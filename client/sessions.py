"""One disposable POSIX PTY and child process per authorized session."""

import asyncio
import base64
import errno
import fcntl
import os
import pty
import select
import signal
import struct
import termios


class PtySession:
    def __init__(self, session_id: str, send, on_exit):
        self.session_id = session_id
        self.send = send
        self.on_exit = on_exit
        self.pid: int | None = None
        self.fd: int | None = None
        self.reader: asyncio.Task | None = None
        self.closed = False

    def start(self) -> None:
        pid, fd = pty.fork()
        if pid == 0:
            environment = {**os.environ, "TERM": "xterm-256color"}
            try:
                os.execve("/bin/bash", ["/bin/bash"], environment)
            except OSError:
                os._exit(127)
        self.pid, self.fd = pid, fd
        self.reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        try:
            while not self.closed:
                fd = self.fd
                readable, _, _ = await asyncio.to_thread(select.select, [fd], [], [], 0.1)
                if not readable or self.closed:
                    continue
                try:
                    chunk = os.read(fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                await self.send({"type": "term_data", "sessionId": self.session_id,
                                 "data": base64.b64encode(chunk).decode("ascii")})
        except asyncio.CancelledError:
            raise
        except (OSError, ConnectionError):
            pass
        finally:
            if not self.closed:
                await self.on_exit(self.session_id)

    def write(self, data: bytes) -> None:
        if self.closed or self.fd is None:
            return
        view = memoryview(data)
        while view:
            try:
                count = os.write(self.fd, view)
            except OSError as exc:
                if exc.errno in (errno.EIO, errno.EBADF):
                    return
                raise
            view = view[count:]

    def resize(self, cols: int, rows: int) -> None:
        if not self.closed and self.fd is not None:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.reader and self.reader is not asyncio.current_task():
            self.reader.cancel()
            try:
                await self.reader
            except asyncio.CancelledError:
                pass
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.pid is None:
            return
        pid = self.pid
        try:
            own_group = os.getpgid(pid) == pid
        except OSError:
            own_group = False

        def signal_child(sig):
            if own_group:
                try:
                    os.killpg(pid, sig)
                except OSError:
                    pass
            try:
                os.kill(pid, sig)
            except OSError:
                pass

        signal_child(signal.SIGTERM)
        await asyncio.sleep(0.25)
        signal_child(signal.SIGKILL)
        try:
            await asyncio.to_thread(os.waitpid, pid, 0)
        except ChildProcessError:
            pass
        self.pid = None
