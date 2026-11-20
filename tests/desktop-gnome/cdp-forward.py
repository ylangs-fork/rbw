#!/usr/bin/env python3
"""Loopback-only raw CDP tunnel via docker exec; does not publish container ports."""
import argparse
import selectors
import socketserver
import subprocess
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("container", help="Owned GNOME test container name")
    parser.add_argument("--port", type=int, default=19222)
    args = parser.parse_args()
    stopping = threading.Event()

    class Forward(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            process = subprocess.Popen(
                ["docker", "exec", "--interactive", "--user", "desktop", args.container,
                 "socat", "STDIO", "TCP:127.0.0.1:9222"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(self.request, selectors.EVENT_READ, "client")
                    selector.register(process.stdout, selectors.EVENT_READ, "browser")
                    while not stopping.is_set():
                        for key, _ in selector.select(timeout=0.5):
                            if key.data == "client":
                                data = self.request.recv(65536)
                                if not data:
                                    return
                                process.stdin.write(data)
                                process.stdin.flush()
                            else:
                                data = process.stdout.read1(65536)
                                if not data:
                                    return
                                self.request.sendall(data)
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            finally:
                for stream in (process.stdin, process.stdout):
                    try:
                        stream.close()
                    except (BrokenPipeError, OSError):
                        pass
                # EOF on socat's stdio normally closes the owned exec on its own.
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = False

    with Server(("127.0.0.1", args.port), Forward) as server:
        print(f"GNOME_CDP_TUNNEL_READY http://127.0.0.1:{args.port}", flush=True)
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            stopping.set()


if __name__ == "__main__":
    main()
