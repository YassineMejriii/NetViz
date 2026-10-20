"""Zero-dependency HTTP + WebSocket server and the capture/broadcast loops."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import select
import socketserver
import threading
import time
from urllib.parse import unquote, urlsplit

from .capture import PcapSource, list_interfaces
from .flows import FlowTable

WEB_DIR = os.path.realpath(os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web"))

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".map": "application/json",
}


class ClientConn:
    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()
        self.queue = []
        self.lock = threading.Lock()
        self.alive = True
        self.paused = False
        self.resync = False

    def push(self, obj) -> None:
        with self.lock:
            if len(self.queue) >= 40:
                self.queue.clear()
                self.resync = True
                return
            self.queue.append(obj)

    def pop(self):
        with self.lock:
            if self.queue:
                return self.queue.pop(0)
        return None

    def clear(self) -> None:
        with self.lock:
            self.queue.clear()

    def send_json(self, obj) -> None:
        try:
            payload = json.dumps(obj, separators=(",", ":")).encode()
        except (TypeError, ValueError):
            return
        self.send_frame(payload, 1)

    def send_frame(self, payload: bytes, opcode: int = 1) -> None:
        if not self.alive:
            return
        length = len(payload)
        head = bytearray([0x80 | opcode])
        if length < 126:
            head.append(length)
        elif length < 65536:
            head.append(126)
            head.extend(length.to_bytes(2, "big"))
        else:
            head.append(127)
            head.extend(length.to_bytes(8, "big"))
        try:
            self.sock.sendall(bytes(head) + payload)
        except OSError:
            self.alive = False

    def extract_frames(self):
        frames = []
        while True:
            if len(self.buf) < 2:
                break
            b0, b1 = self.buf[0], self.buf[1]
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            length = b1 & 0x7F
            pos = 2
            if length == 126:
                if len(self.buf) < 4:
                    break
                length = int.from_bytes(self.buf[2:4], "big")
                pos = 4
            elif length == 127:
                if len(self.buf) < 10:
                    break
                length = int.from_bytes(self.buf[2:10], "big")
                pos = 10
            if length > 1_000_000:
                self.alive = False
                break
            if masked:
                if len(self.buf) < pos + 4:
                    break
                mask = bytes(self.buf[pos:pos + 4])
                pos += 4
            else:
                mask = None
            if len(self.buf) < pos + length:
                break
            payload = bytes(self.buf[pos:pos + length])
            del self.buf[:pos + length]
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            frames.append((opcode, payload))
        return frames

    def on_text(self, payload: bytes, table: FlowTable, info: dict) -> None:
        try:
            message = json.loads(payload.decode("utf-8", "replace"))
        except ValueError:
            return
        if not isinstance(message, dict):
            return
        action = message.get("type")
        if action == "pause":
            self.paused = True
            self.clear()
        elif action == "resume":
            self.paused = False
            self.resync = True
        elif action == "snapshot":
            self.resync = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.buf = bytearray()
        try:
            self.request.settimeout(15)
            head = self._read_until(b"\r\n\r\n", 65536)
            if head is None:
                return
            text = head.decode("latin-1", "replace")
            lines = text.split("\r\n")
            if not lines:
                return
            request_parts = lines[0].split(" ")
            if len(request_parts) < 2:
                return
            method, target = request_parts[0], request_parts[1]
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.strip().lower()] = value.strip()
            self.request.settimeout(None)
            if headers.get("upgrade", "").lower() == "websocket" \
                    and headers.get("sec-websocket-key"):
                self._websocket(headers)
            else:
                self._http(method, target)
        except (OSError, ValueError):
            return

    def _read_until(self, delim: bytes, limit: int):
        while True:
            idx = self.buf.find(delim)
            if idx >= 0:
                head = bytes(self.buf[:idx])
                del self.buf[:idx + len(delim)]
                return head
            if len(self.buf) > limit:
                return None
            try:
                chunk = self.request.recv(8192)
            except OSError:
                return None
            if not chunk:
                return None
            self.buf.extend(chunk)

    # -- plain HTTP -----------------------------------------------------
    def _http(self, method: str, target: str) -> None:
        if method not in ("GET", "HEAD"):
            self._send(405, b"method not allowed")
            return
        path = unquote(urlsplit(target).path)
        if path == "/api/info":
            body = json.dumps({
                "info": self.server.info_snapshot(),
                "interfaces": list_interfaces(),
            }, separators=(",", ":")).encode()
            self._send(200, body, "application/json; charset=utf-8", method)
            return
        if path == "/api/interfaces":
            body = json.dumps(list_interfaces()).encode()
            self._send(200, body, "application/json; charset=utf-8", method)
            return
        if path in ("", "/"):
            path = "/index.html"
        full = os.path.realpath(os.path.join(WEB_DIR, path.lstrip("/")))
        if not full.startswith(WEB_DIR + os.sep):
            self._send(404, b"not found")
            return
        try:
            with open(full, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send(404, b"not found")
            return
        ctype = _MIME.get(os.path.splitext(full)[1].lower(), "application/octet-stream")
        self._send(200, body, ctype, method)

    def _send(self, status: int, body: bytes, ctype: str = "text/plain; charset=utf-8",
              method: str = "GET") -> None:
        reason = {200: "OK", 404: "Not Found", 405: "Method Not Allowed"}.get(status, "OK")
        headers = [
            f"HTTP/1.1 {status} {reason}",
            f"Content-Length: {len(body)}",
            f"Content-Type: {ctype}",
            "Cache-Control: no-store",
            "Connection: close",
            "X-Content-Type-Options: nosniff",
            "Referrer-Policy: no-referrer",
        ]
        try:
            self.request.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
            if method != "HEAD":
                self.request.sendall(body)
        except OSError:
            pass

    # -- websocket ------------------------------------------------------
    def _websocket(self, headers: dict) -> None:
        key = headers["sec-websocket-key"]
        digest = hashlib.sha1((key + _WS_GUID).encode()).digest()
        accept = base64.b64encode(digest).decode()
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        self.request.sendall(response.encode())
        server = self.server

        leftover = bytes(self.buf)
        client = ClientConn(self.request)
        client.buf.extend(leftover)
        self.buf.clear()

        client.push(server.table.snapshot(server.info_snapshot()))
        with server.client_lock:
            server.clients.add(client)

        last_ping = time.time()
        try:
            while client.alive and not server.stop.is_set():
                if client.resync and not client.paused:
                    client.resync = False
                    client.clear()
                    client.push(server.table.snapshot(server.info_snapshot()))
                while True:
                    message = client.pop()
                    if message is None:
                        break
                    client.send_json(message)
                    if not client.alive:
                        break
                if not client.alive:
                    break
                if time.time() - last_ping > 20:
                    client.send_frame(b"", 9)
                    last_ping = time.time()
                try:
                    readable, _, _ = select.select([self.request], [], [], 0.2)
                except (OSError, ValueError):
                    break
                if not readable:
                    continue
                try:
                    chunk = self.request.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                client.buf.extend(chunk)
                if len(client.buf) > 4_000_000:
                    break
                for opcode, payload in client.extract_frames():
                    if opcode == 1:
                        client.on_text(payload, server.table, server.info)
                    elif opcode == 8:
                        client.alive = False
                        break
                    elif opcode == 9:
                        client.send_frame(payload, 10)
        except OSError:
            pass
        finally:
            client.alive = False
            with server.client_lock:
                server.clients.discard(client)


class NetVizServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, table: FlowTable, info: dict):
        super().__init__(addr, Handler)
        self.table = table
        self.info = info
        self.clients: set[ClientConn] = set()
        self.client_lock = threading.Lock()
        self.stop = threading.Event()

    def info_snapshot(self) -> dict:
        data = dict(self.info)
        data["flows"] = len(self.table.flows)
        data.setdefault("notice", None)
        return data


def broadcast_loop(server: NetVizServer) -> None:
    while not server.stop.wait(0.25):
        payload = server.table.tick()
        payload["info"] = server.info_snapshot()
        with server.client_lock:
            clients = list(server.clients)
        for client in clients:
            if client.paused or not client.alive:
                continue
            client.push(payload)


def capture_loop(source, server: NetVizServer) -> None:
    try:
        for pkt in source.packets():
            if server.stop.is_set():
                break
            server.table.ingest(pkt)
    except PermissionError:
        server.info["notice"] = (
            "permission denied on the capture socket - run with CAP_NET_RAW "
            "(sudo) or use --pcap / --demo"
        )
    except OSError as exc:
        detail = exc.strerror or str(exc)
        server.info["notice"] = f"capture error: {detail}"
    except Exception as exc:  # noqa: BLE001 - surface any source failure to the UI
        server.info["notice"] = f"capture stopped: {exc}"
    else:
        if isinstance(source, PcapSource):
            server.info["notice"] = (
                f"replay finished: {server.table.total_packets} packets "
                f"from {os.path.basename(source.path)}"
            )


def serve(source, host: str, port: int, info: dict, max_flows: int = 8000,
          on_ready=None) -> None:
    table = FlowTable(max_flows=max_flows)
    server = NetVizServer((host, port), table, info)
    server.info["started"] = time.time()
    threads = [
        threading.Thread(target=broadcast_loop, args=(server,), daemon=True),
        threading.Thread(target=capture_loop, args=(source, server), daemon=True),
    ]
    for thread in threads:
        thread.start()
    if on_ready is not None:
        on_ready(server)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop.set()
        try:
            source.close()
        except (AttributeError, OSError):
            pass
        server.server_close()
