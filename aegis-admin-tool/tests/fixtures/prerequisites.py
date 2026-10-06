"""Exercise first-run setup through a real terminal, with a local GCP fixture."""
import errno
import os
from pathlib import Path
import pty
import select
import signal
import sys
import time

binary, directory, scenario = sys.argv[1:]
directory = Path(directory)
pid, terminal = pty.fork()
if pid == 0:
    os.environ.update(
        HOME=str(directory), TERM="xterm-256color",
        PATH=str(directory) + os.pathsep + os.environ["PATH"],
        AEGIS_TEST_CLOUD_STATE=str(directory / "cloud.json"),
        BROWSER="/bin/true",
    )
    os.environ.pop("SUDO_USER", None)
    os.execv(binary, [binary, "setup", "--no-enroll", "--image",
                     "ghcr.io/khoek/aegis-api@sha256:" + "a" * 64])

transcript = bytearray()
position = 0
reaped = False

def read():
    if select.select([terminal], [], [], 0.1)[0]:
        try:
            chunk = os.read(terminal, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                return False
            raise
        transcript.extend(chunk)
        return bool(chunk)
    return True

def expect(text):
    global position
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        found = transcript.find(text.encode(), position)
        if found >= 0:
            position = found + len(text)
            return
        if not read():
            break
    raise AssertionError(f"Missing terminal output: {text}\n{transcript.decode(errors='replace')}")

try:
    expect("gcloud auth login")
    expect("Waiting for Google Cloud sign-in")
    if scenario == "interrupt":
        os.kill(pid, signal.SIGINT)
    else:
        (directory / "cloud.signed-in").touch()
        expect("GCP project")
        if scenario == "create":
            os.write(terminal, b"\x1b[B")
        os.write(terminal, b"\r")
        if scenario == "create":
            expect("https://console.cloud.google.com/projectcreate")
            expect("GCP project ID")
            os.write(terminal, b"aegis-new-test\r")
        expect("billing/linkedaccount?project=")
        expect("Waiting for Project billing")
        if scenario == "interrupt-billing":
            os.kill(pid, signal.SIGINT)
            expect("GCP management APIs remain enabled")
        else:
            (directory / "cloud.billing-enabled").touch()
            expect("Custom public endpoint")
            os.write(terminal, b"\r")
            expect("Create or resume this deployment?")
            os.write(terminal, b"n\r")
            expect("Setup declined")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        read()
        completed, status = os.waitpid(pid, os.WNOHANG)
        if completed:
            reaped = True
            assert os.waitstatus_to_exitcode(status) == (130 if scenario.startswith("interrupt") else 1), transcript
            break
    assert reaped, "setup did not terminate"
finally:
    if not reaped:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(terminal)
