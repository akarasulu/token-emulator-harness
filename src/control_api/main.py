"""Lightweight control API for the token emulator harness."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from harness import HarnessRegistry, load_config


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _split_path(path: str) -> List[str]:
    return [segment for segment in path.strip("/").split("/") if segment]


@dataclass
class Route:
    method: str
    path: str
    segments: List[str]
    handler: Callable[..., Any]

    def match(self, method: str, path: str) -> Optional[Dict[str, str]]:
        if method.upper() != self.method:
            return None
        req_segments = _split_path(path)
        if len(req_segments) != len(self.segments):
            return None
        params: Dict[str, str] = {}
        for route_seg, req_seg in zip(self.segments, req_segments):
            if route_seg.startswith("{") and route_seg.endswith("}"):
                params[route_seg.strip("{}")] = req_seg
            elif route_seg != req_seg:
                return None
        return params


class MiniApp:
    def __init__(self, title: str = "token-emulator"):
        self.title = title
        self.routes: List[Route] = []

    def route(self, method: str, path: str) -> Callable:
        def decorator(func: Callable):
            self.routes.append(Route(method.upper(), path, _split_path(path), func))
            return func

        return decorator

    def post(self, path: str) -> Callable:
        return self.route("POST", path)

    def get(self, path: str) -> Callable:
        return self.route("GET", path)

    def dispatch(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> "Response":
        for route in self.routes:
            params = route.match(method, path)
            if params is None:
                continue
            kwargs = dict(params)
            if isinstance(payload, dict):
                kwargs.update(payload)
            try:
                result = route.handler(**kwargs)
            except HTTPException as exc:
                return Response({"detail": exc.detail}, status_code=exc.status_code)
            if isinstance(result, Response):
                return result
            body = {} if result is None else result
            return Response(body, status_code=HTTPStatus.OK)
        return Response({"detail": "not found"}, status_code=HTTPStatus.NOT_FOUND)

    def serve(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _read_body(self) -> Optional[Dict[str, Any]]:
                length = int(self.headers.get("Content-Length", 0))
                if not length:
                    return None
                data = self.rfile.read(length)
                return json.loads(data.decode("utf-8"))

            def _respond(self, method: str):
                parsed = urlparse(self.path)
                body = self._read_body()
                result = app.dispatch(method, parsed.path, body)
                self.send_response(result.status_code)
                content_type = result.media_type or "application/json"
                self.send_header("Content-Type", content_type)
                for key, value in result.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                payload = result.body
                if content_type == "application/json":
                    payload = json.dumps(payload).encode("utf-8")
                elif isinstance(payload, str):
                    payload = payload.encode("utf-8")
                self.wfile.write(payload)

            def do_GET(self):  # pylint: disable=invalid-name
                self._respond("GET")

            def do_POST(self):  # pylint: disable=invalid-name
                self._respond("POST")

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                return

        server = ThreadingHTTPServer((host, port), Handler)
        print(f"{self.title} listening on {host}:{port}")  # noqa: T201
        try:
            server.serve_forever()
        except KeyboardInterrupt:  # pragma: no cover
            server.server_close()


@dataclass
class Response:
    body: Any
    status_code: int = HTTPStatus.OK
    media_type: str = "application/json"
    headers: Dict[str, str] = field(default_factory=dict)


class ResponseWrapper:
    def __init__(self, response: Response):
        self.status_code = response.status_code
        self.media_type = response.media_type
        self._body = response.body

    def json(self) -> Any:
        return self._body

    def text(self) -> str:
        if isinstance(self._body, bytes):
            return self._body.decode("utf-8")
        if isinstance(self._body, str):
            return self._body
        return json.dumps(self._body)


class TestClient:
    __test__ = False

    def __init__(self, app: MiniApp):
        self._app = app

    def post(self, path: str, json: Optional[Dict[str, Any]] = None) -> ResponseWrapper:
        result = self._app.dispatch("POST", path, json)
        return ResponseWrapper(result)

    def get(self, path: str) -> ResponseWrapper:
        result = self._app.dispatch("GET", path, None)
        return ResponseWrapper(result)


BASE_DIR = Path(__file__).resolve().parents[2]
OPENAPI_PATH = BASE_DIR / "docs" / "openapi.yaml"
config = load_config()
registry = HarnessRegistry(config)
app = MiniApp()


@app.post("/reset_all")
def reset_all():
    registry.reset_all()
    return {"status": "reset"}


@app.post("/otp/seed")
def issue_seed(type: str = "totp"):
    seed = registry.otp.issue_seed(token_type=type)
    return seed.__dict__


@app.get("/otp/code/{seed_id}")
def current_code(seed_id: str):
    try:
        code = registry.otp.current_code(seed_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"seed_id": seed_id, "code": code}


@app.post("/pkcs11/keys")
def generate_key(label: str):
    key = registry.pkcs11.generate_key(label)
    return key.__dict__


@app.get("/pkcs11/keys")
def list_keys():
    return [key.__dict__ for key in registry.pkcs11.list_keys()]


@app.post("/fido2/register")
def fido_register(user_id: str, rp_id: str):
    cred = registry.fido.register(user_id=user_id, rp_id=rp_id)
    return cred.__dict__


@app.post("/fido2/authenticate")
def fido_authenticate(credential_id: str, challenge: str):
    try:
        result = registry.fido.authenticate(credential_id, challenge)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return result


@app.post("/smartcard/insert")
def smartcard_insert():
    return registry.smartcard.insert_card().__dict__


@app.post("/smartcard/remove")
def smartcard_remove():
    return registry.smartcard.remove_card().__dict__


@app.get("/smartcard/status")
def smartcard_status():
    return registry.smartcard.status().__dict__


@app.post("/mobile/pair")
def mobile_pair(device_id: str):
    return registry.mobile.pair(device_id).__dict__


@app.post("/mobile/assert")
def mobile_assert(device_id: str, challenge: str):
    try:
        return registry.mobile.assert_challenge(device_id, challenge)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/issue_ocra_challenge")
def issue_ocra_challenge():
    return {"challenge": registry.otp.issue_ocra_challenge()}


@app.post("/network_hsm/sign")
def network_hsm_sign(payload: str):
    return registry.network_hsm.sign_payload(payload)


@app.get("/openapi.yaml")
def openapi_spec():
    if not OPENAPI_PATH.exists():
        raise HTTPException(404, "spec not found")
    return Response(OPENAPI_PATH.read_text(encoding="utf-8"), media_type="application/yaml")


@app.get("/docs")
def docs_page():
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Token Emulator Harness API</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; }
    pre { background: #f5f5f5; padding: 1rem; border-radius: 4px; overflow-x: auto; }
    #status { margin-bottom: 1rem; }
  </style>
</head>
<body>
  <h1>Token Emulator Harness API</h1>
  <p>This page renders the OpenAPI specification bundled with the harness.</p>
  <p>Download the raw spec at <a href="/openapi.yaml">/openapi.yaml</a>.</p>
  <div id="status">Loading spec...</div>
  <pre id="spec"></pre>
  <script>
    fetch('/openapi.yaml')
      .then(resp => resp.text())
      .then(text => {
        document.getElementById('status').textContent = 'Loaded spec:';
        document.getElementById('spec').textContent = text;
      })
      .catch(err => {
        document.getElementById('status').textContent = 'Failed to load spec: ' + err;
      });
  </script>
</body>
</html>
""".strip()
    return Response(html, media_type="text/html")


if __name__ == "__main__":  # pragma: no cover
    app.serve()
