"""Headless browser smoke test of a real server, agent and PTY on Linux CI."""

import asyncio
import http.client
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

from playwright.async_api import async_playwright, expect

from server.agents import issue_credential
from server.auth import initialize_operator


def stop(process):
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        raise AssertionError(f"Process {process.pid} did not stop after SIGTERM")


async def main():
    with tempfile.TemporaryDirectory(prefix="aetherterm-browser-check-") as temporary:
        directory = Path(temporary)
        operator_file = directory / "operator.json"
        agents_file = directory / "agents.json"
        credential = directory / "browser-agent.token"
        initialize_operator(operator_file, "temporary-browser-password")
        issue_credential(agents_file, "browser-agent", credential)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        environment = {**os.environ, "AETHERTERM_OPERATOR_FILE": str(operator_file),
                       "AETHERTERM_AGENTS_FILE": str(agents_file), "PYTHONUNBUFFERED": "1"}
        executable_dir = Path(sys.prefix) / "bin"
        server_log = (directory / "server.log").open("w+", encoding="utf-8")
        agent_log = (directory / "agent.log").open("w+", encoding="utf-8")
        server = agent = None
        server_command = [str(executable_dir / "aetherterm-server"), "--port", str(port)]
        try:
            server = subprocess.Popen(server_command,
                                      cwd=directory, env=environment, stdout=server_log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
            for _ in range(100):
                try:
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
                    connection.request("GET", "/login")
                    response = connection.getresponse()
                    response.read()
                    connection.close()
                    if response.status == 200:
                        break
                except OSError:
                    await asyncio.sleep(0.1)
            else:
                raise AssertionError("Browser test server did not start")
            agent = subprocess.Popen([str(executable_dir / "aetherterm-agent"), "--host", "127.0.0.1",
                                      "--port", str(port), "--device-id", "browser-agent",
                                      "--token-file", str(credential)], cwd=directory, env=environment,
                                     stdout=agent_log, stderr=subprocess.STDOUT, start_new_session=True)

            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                page = await browser.new_page(viewport={"width": 1280, "height": 800})
                errors = []
                external_requests = []

                async def require_local_asset(route):
                    if not route.request.url.startswith(f"http://127.0.0.1:{port}/"):
                        external_requests.append(route.request.url)
                        await route.abort()
                    else:
                        await route.continue_()

                await page.route("**/*", require_local_asset)
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
                try:
                    await page.goto(f"http://127.0.0.1:{port}/login")
                    await page.get_by_label("Operator password").fill("temporary-browser-password")
                    await page.get_by_role("button", name="Enter console").click()
                    await page.wait_for_url("**/web/")
                    await expect(page.get_by_role("heading", name="Remote workspace.")).to_be_visible()
                    device = page.get_by_role("button", name=re.compile(r"browser-agent, online, open shell"))
                    await device.click(timeout=15000)
                    await expect(page.get_by_text("Shell ready on browser-agent.", exact=False)).to_be_visible()
                    await page.locator(".xterm-helper-textarea").focus()
                    await page.keyboard.type("printf 'BROWSER_OK\\n'")
                    await page.keyboard.press("Enter")
                    await page.get_by_text("BROWSER_OK", exact=True).wait_for(state="attached", timeout=10000)
                    assert not external_requests, f"Web UI requested external assets: {external_requests}"
                    assert not errors, f"Browser console errors before restart: {errors}"

                    outage_started = time.monotonic()
                    await page.context.set_offline(True)
                    await expect(page.locator("#connection-status")).to_have_text("Server offline", timeout=15000)
                    await expect(page.get_by_text("Connection lost. Retrying; previous shells are closed.")).to_be_visible()
                    await expect(page.get_by_role("heading", name="Your next shell starts here.")).to_be_visible()
                    detection_seconds = time.monotonic() - outage_started
                    recovery_started = time.monotonic()
                    await page.context.set_offline(False)
                    await expect(page.locator("#connection-status")).to_have_text("Server connected", timeout=15000)
                    device = page.get_by_role("button", name=re.compile(r"browser-agent, online, open shell"))
                    await device.click()
                    await expect(page.get_by_text("Shell ready on browser-agent.", exact=False)).to_be_visible()
                    await page.locator(".xterm-helper-textarea").focus()
                    await page.keyboard.type("printf 'BROWSER_AFTER_OUTAGE\\n'")
                    await page.keyboard.press("Enter")
                    await page.get_by_text("BROWSER_AFTER_OUTAGE", exact=True).wait_for(state="attached", timeout=10000)
                    print(f"Browser outage: detected in {detection_seconds:.2f}s; "
                          f"reconnected in {time.monotonic() - recovery_started:.2f}s")

                    stop(server)
                    server = subprocess.Popen(server_command, cwd=directory, env=environment,
                                              stdout=server_log, stderr=subprocess.STDOUT, start_new_session=True)
                    for _ in range(100):
                        try:
                            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
                            connection.request("GET", "/login")
                            response = connection.getresponse()
                            response.read()
                            connection.close()
                            if response.status == 200:
                                break
                        except OSError:
                            await asyncio.sleep(0.1)
                    else:
                        raise AssertionError("Restarted server did not start")
                    await expect(page.get_by_role("link", name="Sign in again")).to_be_visible(timeout=20000)
                    await expect(page.get_by_role("heading", name="Your next shell starts here.")).to_be_visible()
                    await page.get_by_role("link", name="Sign in again").click()
                    await page.get_by_label("Operator password").fill("temporary-browser-password")
                    await page.get_by_role("button", name="Enter console").click()
                    device = page.get_by_role("button", name=re.compile(r"browser-agent, online, open shell"))
                    await device.click(timeout=20000)
                    await expect(page.get_by_text("Shell ready on browser-agent.", exact=False)).to_be_visible()
                    await page.locator(".xterm-helper-textarea").focus()
                    await page.keyboard.type("printf 'BROWSER_RETURNED\\n'")
                    await page.keyboard.press("Enter")
                    await page.get_by_text("BROWSER_RETURNED", exact=True).wait_for(state="attached", timeout=10000)
                    await page.keyboard.type("printf 'HISTORY_ARROW_OK\\n'")
                    await page.keyboard.press("Enter")
                    await page.get_by_text("HISTORY_ARROW_OK", exact=True).wait_for(state="attached", timeout=10000)
                    await page.wait_for_function("""() =>
                        (document.querySelector('.xterm-screen').textContent.match(/HISTORY_ARROW_OK/g) || []).length >= 2
                    """, timeout=10000)
                    prior_count = await page.locator(".xterm-screen").evaluate(
                        "element => (element.textContent.match(/HISTORY_ARROW_OK/g) || []).length"
                    )
                    await page.keyboard.press("ArrowUp")
                    await page.keyboard.press("Enter")
                    await page.wait_for_function("""count =>
                        (document.querySelector('.xterm-screen').textContent.match(/HISTORY_ARROW_OK/g) || []).length > count
                    """, arg=prior_count, timeout=10000)
                    await page.keyboard.type("vim --version | head -n 1")
                    await page.keyboard.press("Enter")
                    await page.locator(".xterm-screen").get_by_text("VIM - Vi IMproved", exact=False).first.wait_for(
                        state="attached", timeout=10000)
                    vim_file = directory / "vim-proof.txt"
                    await page.keyboard.type(f"vim -Nu NONE -n {vim_file}")
                    await page.keyboard.press("Enter")
                    await page.wait_for_function("""() =>
                        document.querySelector('.xterm-screen').textContent.includes('vim-proof.txt')
                    """, timeout=10000)
                    await page.wait_for_timeout(400)
                    await page.keyboard.press("i")
                    await page.keyboard.type("VIM_BROWSER_OK")
                    vim_screenshot_dir = os.environ.get("AETHERTERM_SCREENSHOT_DIR")
                    if vim_screenshot_dir:
                        vim_screenshots = Path(vim_screenshot_dir)
                        vim_screenshots.mkdir(parents=True, exist_ok=True)
                        await page.screenshot(path=str(vim_screenshots / "vim.png"), full_page=True)
                    await page.keyboard.press("Escape")
                    await page.wait_for_timeout(100)
                    await page.keyboard.type(":wq")
                    await page.keyboard.press("Enter")
                    for _ in range(100):
                        if vim_file.is_file() and vim_file.read_text(encoding="utf-8").strip() == "VIM_BROWSER_OK":
                            break
                        await asyncio.sleep(0.1)
                    else:
                        print("Vim terminal rows:", repr(await page.locator(".xterm-rows").inner_text()),
                              file=sys.stderr)
                        raise AssertionError("Vim did not save the expected file through the browser PTY")
                    await page.wait_for_timeout(200)
                    await page.keyboard.type(f"cat {vim_file}")
                    await page.keyboard.press("Enter")
                    await page.wait_for_function("""() =>
                        document.querySelector('.xterm-screen').textContent.includes('VIM_BROWSER_OK')
                    """, timeout=10000)
                    await page.keyboard.type("cd /tmp")
                    await page.keyboard.press("Enter")
                    await page.keyboard.type("clear")
                    await page.keyboard.press("Enter")
                    await page.keyboard.type("printf 'Live shell connected\\n'")
                    await page.keyboard.press("Enter")
                    await page.get_by_text("Live shell connected", exact=True).wait_for(state="attached", timeout=10000)
                    await page.keyboard.type("uname -s")
                    await page.keyboard.press("Enter")
                    await page.get_by_text("Linux", exact=True).wait_for(state="attached", timeout=10000)
                    errors.clear()  # Network errors from the deliberate outage are expected.
                    screenshot_dir = os.environ.get("AETHERTERM_SCREENSHOT_DIR")
                    if screenshot_dir:
                        screenshots = Path(screenshot_dir)
                        screenshots.mkdir(parents=True, exist_ok=True)
                        await page.screenshot(path=str(screenshots / "desktop.png"), full_page=True)
                    await page.set_viewport_size({"width": 375, "height": 812})
                    for _ in range(50):
                        widths = await page.evaluate("""() => ({
                          viewport: window.innerWidth,
                          document: document.documentElement.scrollWidth,
                          overflowing: [...document.querySelectorAll('*')]
                            .filter(element => element.getBoundingClientRect().right > window.innerWidth + 1)
                            .slice(0, 8).map(element => ({tag: element.tagName, className: String(element.className),
                                                          right: element.getBoundingClientRect().right}))
                        })""")
                        if widths["document"] <= widths["viewport"]:
                            break
                        await asyncio.sleep(0.1)
                    else:
                        raise AssertionError(f"Mobile horizontal overflow: {widths}")
                    if screenshot_dir:
                        await page.screenshot(path=str(screenshots / "mobile.png"), full_page=True)
                    await page.set_viewport_size({"width": 1280, "height": 800})
                    await page.locator(".xterm-helper-textarea").focus()
                    await page.keyboard.type("cat")
                    await page.keyboard.press("Enter")
                    await page.get_by_text("cat", exact=False).wait_for(state="attached", timeout=10000)
                    await asyncio.sleep(0.2)
                    await page.get_by_role("button", name="Send Ctrl+C").click()
                    await expect(page.get_by_text("Sent Ctrl+C to the active shell.")).to_be_visible()
                    await page.keyboard.type("printf 'AFTER_CTRL_C\\n'")
                    await page.keyboard.press("Enter")
                    await page.get_by_text("AFTER_CTRL_C", exact=True).wait_for(state="attached", timeout=10000)
                    await page.keyboard.type("printf 'Caf\\303\\251 \\346\\274\\242\\345\\255\\227\\n'")
                    await page.keyboard.press("Enter")
                    try:
                        await page.get_by_text("Café 漢字", exact=True).wait_for(state="attached", timeout=10000)
                    except Exception:
                        print("Unicode terminal rows:", repr(await page.locator(".xterm-rows").inner_text()),
                              file=sys.stderr)
                        diagnostic_dir = Path(os.environ.get("AETHERTERM_SCREENSHOT_DIR", directory / "screenshots"))
                        diagnostic_dir.mkdir(parents=True, exist_ok=True)
                        await page.screenshot(path=str(diagnostic_dir / "unicode-failure.png"), full_page=True)
                        raise
                    await expect(page.get_by_role("button", name="Close session")).to_be_visible()
                    await page.get_by_role("button", name="Close session").click()
                    await expect(page.get_by_role("heading", name="Your next shell starts here.")).to_be_visible()
                    await page.get_by_role("button", name="Sign out").click()
                    await expect(page.get_by_role("heading", name="Welcome back.")).to_be_visible()
                    assert not errors, f"Browser console errors: {errors}"
                finally:
                    await browser.close()
        except BaseException:
            server_log.flush()
            agent_log.flush()
            print((directory / "server.log").read_text(encoding="utf-8"), file=sys.stderr)
            print((directory / "agent.log").read_text(encoding="utf-8"), file=sys.stderr)
            raise
        finally:
            try:
                stop(agent)
            finally:
                stop(server)
                server_log.close()
                agent_log.close()
    print("Chromium login, PTY, restart, reauthentication, Unicode output, interrupt, mobile layout and sign-out: PASS")


if __name__ == "__main__":
    asyncio.run(main())
