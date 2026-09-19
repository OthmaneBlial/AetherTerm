"""Read server identity files without following symlinks or weak permissions."""

import errno
import os
from pathlib import Path
import stat


def read_private_text(path: Path, max_bytes: int) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"Identity file must not be a symbolic link: {path}") from exc
        raise
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError(f"Identity file must be a private regular file owned by this user: {path}")
        data = source.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"Identity file is too large: {path}")
    return data.decode("utf-8")
