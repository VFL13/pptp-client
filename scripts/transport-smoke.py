"""Exercise the compiled client's TCP framing against a local fake PPTP peer.

No administrator rights, credentials, external servers, or network changes.
"""
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time

BINARY = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".build/debug/pptp-client").resolve())


def message(kind, payload):
    return struct.pack("!HHIHH", len(payload) + 12, 1, 0x1A2B3C4D, kind, 0) + payload


def read_exact(peer, length):
    result = b""
    while len(result) < length:
        chunk = peer.recv(length - len(result))
        if not chunk:
            raise AssertionError("unexpected EOF in client message")
        result += chunk
    return result


def run_case(name, mode, expected_code):
    failures = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        port = listener.getsockname()[1]

        def serve():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(3)
                    request = read_exact(peer, 156)
                    assert request[:12] == struct.pack("!HHIHH", 156, 1, 0x1A2B3C4D, 1, 0)
                    body = struct.pack("!HBBIIHH", 0x0100, 1, 0, 3, 3, 1, 1)
                    reply = message(2, body + b"fixture".ljust(64, b"\0") + b"local".ljust(64, b"\0"))
                    if mode == "timeout":
                        assert peer.recv(1) == b""
                        return
                    if mode == "truncated":
                        peer.sendall(reply[:15])
                        return
                    if mode == "invalid":
                        peer.sendall(reply[:4] + b"\0\0\0\0" + reply[8:])
                        return
                    for chunk in [reply[:3], reply[3:11], reply[11:]]:
                        peer.sendall(chunk)
                        time.sleep(0.01)
                    assert read_exact(peer, 16) == message(3, b"\x01\0\0\0")
                    # Coalesced Echo-Request and shutdown reply in one TCP write.
                    peer.sendall(message(5, b"\x11\x22\x33\x44") + message(4, b"\x01\0\0\0"))
                    assert read_exact(peer, 20) == message(6, b"\x11\x22\x33\x44\x01\0\0\0")
            except BaseException as exc:
                failures.append(exc)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        result = subprocess.run([BINARY, "probe", "127.0.0.1", "--port", str(port), "--timeout", "0.3" if mode == "timeout" else "2"],
                                capture_output=True, text=True, timeout=4)
        worker.join(timeout=4)
        assert not worker.is_alive(), name + ": fixture did not exit"
        assert not failures, (name, failures)
        assert result.returncode == expected_code, (name, result.returncode, result.stdout, result.stderr)
        if expected_code == 0:
            assert "Control shutdown: confirmed" in result.stdout
        else:
            assert "PPTP control channel: established" not in result.stdout
        print(name + ": passed")


for case in [("fragmented/coalesced TCP", "valid", 0), ("truncated response", "truncated", 1),
             ("invalid magic cookie", "invalid", 1), ("shared timeout", "timeout", 1)]:
    run_case(*case)
