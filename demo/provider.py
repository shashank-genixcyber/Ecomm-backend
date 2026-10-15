"""Local HTTPS resource server and OIDC/OAuth issuer for opt-in demos."""
import base64
from datetime import datetime, timezone
import hashlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import ssl
from threading import RLock, Thread
import time
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import jwt

from . import audit
from .assets import certificate_fingerprint
from .issuance import ensure_issuances, token_issuance
from .registry import BY_ID, Consumer


class LocalProvider:
    def __init__(self, root, port=9443, frontend_origin="http://127.0.0.1:5173"):
        self.root = Path(root)
        origin = urlsplit(frontend_origin)
        if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.path not in {"", "/"} or origin.query or origin.fragment or origin.username:
            raise ValueError("The demo frontend must be an HTTP 127.0.0.1 origin.")
        self.frontend_origin = frontend_origin.rstrip("/")
        self.redirect_uri = self.frontend_origin + "/accounts/oidc/shop/login/callback/"
        self.references = json.loads((self.root / "provider.json").read_text())
        self.issuances = ensure_issuances(self.root)
        self.bootstrap = json.loads((self.root / "bootstrap.json").read_text())
        self.issuer_key = serialization.load_pem_private_key((self.root / "issuer.key.pem").read_bytes(), password=None)
        self.codes = {}
        self.approvals = {}
        self.lock = RLock()
        provider = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "EverydayDemo"

            def log_message(self, *args):
                pass  # Request completion is recorded without URL queries.

            def respond(self, status, data=None, *, headers=None, html=None):
                audit.emit("provider.request.completed", path=provider.root / "ecomm-demo.jsonl",
                           http_method=self.command, http_path=urlsplit(self.path).path, http_status=status)
                body = html.encode() if html is not None else json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8" if html is not None else "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            def dispatch(self):
                metadata = {"caller": "anonymous"}
                for name in ("request_id", "run_id"):
                    try:
                        metadata[name] = str(UUID(self.headers.get("X-Demo-" + name.replace("_", "-"), "")))
                    except ValueError:
                        metadata[name] = str(uuid4())
                marker = audit.context.set(metadata)
                try:
                    if self.command == "GET":
                        self.get()
                    else:
                        self.post()
                except audit.AuditUnavailable:
                    # Do not return a successful operation if its audit cannot be written.
                    self.send_error(503, "Demo audit unavailable")
                except (ValueError, KeyError, TypeError, UnicodeError, jwt.PyJWTError):
                    self.respond(400, {"error": "invalid_request"})
                except Exception:
                    audit.emit("provider.error", path=provider.root / "ecomm-demo.jsonl", outcome="failure", error_code="PROVIDER_ERROR")
                    self.respond(500, {"error": "provider_error"})
                finally:
                    audit.context.reset(marker)

            do_GET = dispatch
            do_POST = dispatch

            def read_body(self):
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 65536:
                    raise ValueError("Invalid body size")
                return self.rfile.read(size).decode()

            def get(self):
                parsed = urlsplit(self.path)
                if parsed.path == "/demo-provider/.well-known/openid-configuration":
                    return self.respond(200, {
                        "issuer": provider.url, "authorization_endpoint": provider.frontend_origin + "/demo-provider/authorize",
                        "token_endpoint": provider.url + "/demo-provider/token", "jwks_uri": provider.url + "/demo-provider/jwks",
                        "response_types_supported": ["code"], "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"], "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                        "code_challenge_methods_supported": ["S256"], "scopes_supported": ["openid", "profile", "email"],
                    })
                if parsed.path == "/demo-provider/jwks":
                    key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(provider.issuer_key.public_key()))
                    return self.respond(200, {"keys": [{**key, "kid": "local-issuer-v1", "alg": "RS256", "use": "sig"}]})
                if parsed.path == "/demo-provider/authorize":
                    params = {key: value[0] for key, value in parse_qs(parsed.query).items()}
                    if (params.get("client_id") != "everyday-web" or params.get("redirect_uri") != provider.redirect_uri
                            or params.get("response_type") != "code" or params.get("code_challenge_method") != "S256"
                            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.get("code_challenge", ""))
                            or not 1 <= len(params.get("state", "")) <= 512):
                        return self.respond(400, {"error": "invalid_request"})
                    approval = secrets.token_urlsafe(32)
                    with provider.lock:
                        provider.approvals = {key: value for key, value in provider.approvals.items() if value["expires"] > time.time()}
                        if len(provider.approvals) >= 1000:
                            return self.respond(429, {"error": "too_many_requests"})
                        provider.approvals[approval] = {**params, "expires": time.time() + 120}
                    html = ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                            '<title>Everyday local demo sign-in</title><body><main><h1>Everyday local demo</h1>'
                            '<p>This local provider signs you in as Demo Buyer. No Google or Azure account is needed.</p>'
                            '<form method="post" action="/demo-provider/authorize">'
                            f'<input type="hidden" name="approval" value="{approval}">'
                            '<button type="submit">Continue as Demo Buyer</button></form></main></body></html>')
                    return self.respond(200, html=html, headers={"Set-Cookie": f"demo_approval={approval}; HttpOnly; SameSite=Lax; Path=/demo-provider/; Max-Age=120"})
                self.respond(404, {"error": "not_found"})

            def basic_client(self):
                try:
                    scheme, encoded = self.headers.get("Authorization", "").split(" ", 1)
                    if scheme != "Basic":
                        return None
                    client_id, secret = base64.b64decode(encoded, validate=True).decode().split(":", 1)
                    expected = (provider.bootstrap["web_client_secret"] if client_id == "everyday-web"
                                else provider.references.get(client_id, {}).get("client_secret"))
                    return client_id if expected and secrets.compare_digest(secret, expected) else None
                except (ValueError, UnicodeError):
                    return None

            def post(self):
                path = urlsplit(self.path).path
                if path == "/demo-provider/authorize":
                    params = parse_qs(self.read_body())
                    approval = params.get("approval", [""])[0]
                    cookie = SimpleCookie()
                    cookie.load(self.headers.get("Cookie", ""))
                    token = cookie.get("demo_approval")
                    if not token or not secrets.compare_digest(token.value, approval):
                        return self.respond(403, {"error": "invalid_approval"})
                    if self.headers.get("Origin", provider.frontend_origin) != provider.frontend_origin:
                        return self.respond(403, {"error": "invalid_origin"})
                    with provider.lock:
                        authorization = provider.approvals.pop(approval, None)
                        if not authorization or authorization["expires"] <= time.time():
                            return self.respond(403, {"error": "expired_approval"})
                        code = secrets.token_urlsafe(32)
                        provider.codes = {key: value for key, value in provider.codes.items() if value["expires"] > time.time()}
                        provider.codes[code] = {**authorization, "expires": time.time() + 60}
                    return self.respond(302, {}, headers={"Location": provider.redirect_uri + "?" + urlencode({"code": code, "state": authorization["state"]}),
                                                          "Set-Cookie": "demo_approval=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/demo-provider/"})
                if path == "/demo-provider/token":
                    client_id = self.basic_client()
                    if not client_id:
                        return self.respond(401, {"error": "invalid_client"})
                    params = {key: value[0] for key, value in parse_qs(self.read_body()).items()}
                    now = int(time.time())
                    claims = {"iss": provider.url, "iat": now, "exp": now + 300, "jti": str(uuid4())}
                    if params.get("grant_type") == "authorization_code" and client_id == "everyday-web":
                        with provider.lock:
                            authorization = provider.codes.pop(params.get("code", ""), None)
                        verifier = params.get("code_verifier", "")
                        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                        if (not authorization or authorization["expires"] <= time.time() or params.get("redirect_uri") != provider.redirect_uri
                                or not secrets.compare_digest(challenge, authorization["code_challenge"])):
                            return self.respond(400, {"error": "invalid_grant"})
                        claims.update({"sub": "local-demo-buyer", "aud": client_id, "email": "demo.buyer@example.test",
                                       "email_verified": True, "name": "Demo Buyer", "given_name": "Demo"})
                        id_token = provider.encode(claims)
                        access_token = secrets.token_urlsafe(32)
                        web_consumer = Consumer("everyday-web", "oauth_token", "website-id-token", "login", "issue")
                        for name, value, token_claims in (
                            ("website-id-token", id_token, claims),
                            ("website-access-token", access_token, {**claims, "jti": str(uuid4())}),
                        ):
                            issuance = token_issuance(web_consumer, token_claims, hashlib.sha256(value.encode()).hexdigest(), actual_issuer=provider.url)
                            audit.emit("credential.issued", path=provider.root / "ecomm-demo.jsonl", **issuance,
                                       consumer_id="everyday-web", consumer_name="Everyday Website Login",
                                       api_path="/accounts/oidc/shop/login/callback/", credential_name=name,
                                       credential_type="oauth_token", asset_role="infrastructure", operation="issue", outcome="success")
                        return self.respond(200, {"access_token": access_token, "token_type": "Bearer", "expires_in": 300, "id_token": id_token})
                    reference = provider.references.get(client_id, {})
                    if (params.get("grant_type") != "client_credentials" or reference.get("type") != "oauth_token"
                            or params.get("scope") != reference["scope"]):
                        return self.respond(400, {"error": "invalid_scope"})
                    claims.update({"sub": client_id, "aud": reference["audience"], "scope": reference["scope"]})
                    consumer = BY_ID[client_id]
                    token = provider.encode(claims)
                    issuance = token_issuance(consumer, claims, hashlib.sha256(token.encode()).hexdigest(), actual_issuer=provider.url)
                    fields = {**issuance, "consumer_id": client_id, "consumer_name": consumer.name,
                              "api_path": consumer.api_path, "credential_name": consumer.credential_name,
                              "credential_type": "oauth_token", "asset_role": "business", "operation": "issue", "outcome": "success"}
                    audit.emit("credential.issued", path=provider.root / "ecomm-demo.jsonl", **fields)
                    audit.emit("provider.token.issued", path=provider.root / "ecomm-demo.jsonl", **fields)
                    return self.respond(200, {"access_token": token, "token_type": "Bearer", "expires_in": 300})
                if path.startswith("/targets/"):
                    consumer = BY_ID.get(path.removeprefix("/targets/"))
                    if not consumer:
                        return self.respond(404, {"error": "not_found"})
                    reference = provider.references[consumer.id]
                    data = json.loads(self.read_body())
                    valid = False
                    if consumer.credential_type == "secret":
                        valid = secrets.compare_digest(self.headers.get("X-API-Key", ""), reference["expected_secret"])
                    elif consumer.credential_type == "certificate":
                        peer = self.connection.getpeercert(binary_form=True)
                        valid = bool(peer and certificate_fingerprint(x509.load_der_x509_certificate(peer)) == reference["fingerprint"])
                    elif consumer.credential_type == "key":
                        try:
                            key = serialization.load_pem_public_key(reference["public_key"].encode())
                            key.verify(base64.b64decode(data["signature"], validate=True), canonical(data["payload"]))
                            valid = True
                        except Exception:
                            valid = False
                    else:
                        try:
                            scheme, token = self.headers.get("Authorization", "").split(" ", 1)
                            claims = jwt.decode(token, provider.issuer_key.public_key(), algorithms=["RS256"],
                                                issuer=provider.url, audience=reference["audience"],
                                                options={"require": ["iss", "sub", "aud", "iat", "exp", "jti"]})
                            valid = scheme == "Bearer" and claims["sub"] == consumer.id and claims.get("scope") == reference["scope"]
                        except (ValueError, jwt.PyJWTError):
                            valid = False
                    if consumer.credential_type != "oauth_token":
                        valid = valid and datetime.now(timezone.utc) < datetime.fromisoformat(provider.issuances[consumer.id]["expires_at"])
                    audit.emit("provider.credential.validated", path=provider.root / "ecomm-demo.jsonl",
                               consumer_id=consumer.id, credential_name=consumer.credential_name,
                               credential_type=consumer.credential_type, operation=consumer.operation,
                               outcome="success" if valid else "failure")
                    return self.respond(200 if valid else 403, {"verified": valid, "consumer_id": consumer.id})
                self.respond(404, {"error": "not_found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        self.url = f"https://127.0.0.1:{self.server.server_port}"
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(self.root / "server.pem", self.root / "server.key.pem")
        tls.load_verify_locations(self.root / "ca.pem")
        tls.verify_mode = ssl.CERT_OPTIONAL
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    def encode(self, claims):
        return jwt.encode(claims, self.issuer_key, algorithm="RS256", headers={"kid": "local-issuer-v1"})

    def __enter__(self):
        audit.emit("provider.started", path=self.root / "ecomm-demo.jsonl", outcome="success")
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
