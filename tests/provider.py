"""Test-only OIDC server: real code exchange, PKCE, client authentication, and signed JWTs."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
from threading import Thread
import time
from urllib.parse import parse_qs, urlencode, urlparse

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt


class Provider:
    client_id = "test-client"
    secret = "test-only-client-secret"
    mode = "valid"

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes = {}
        self.token_requests = 0
        self.used_pkce = False
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send_json(self, data, status=200):
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == "/.well-known/openid-configuration":
                    return self.send_json({
                        "issuer": provider.url, "authorization_endpoint": provider.url + "/authorize",
                        "token_endpoint": provider.url + "/token", "jwks_uri": provider.url + "/jwks",
                        "userinfo_endpoint": provider.url + "/userinfo", "response_types_supported": ["code"],
                        "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
                        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                        "code_challenge_methods_supported": ["S256"],
                    })
                if parsed.path == "/jwks":
                    key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(provider.key.public_key()))
                    return self.send_json({"keys": [{**key, "kid": "test-key", "alg": "RS256", "use": "sig"}]})
                if parsed.path == "/authorize":
                    params = {key: value[0] for key, value in parse_qs(parsed.query).items()}
                    if params.get("client_id") != provider.client_id or params.get("response_type") != "code":
                        return self.send_json({"error": "invalid_request"}, 400)
                    code = secrets.token_urlsafe(24)
                    provider.codes[code] = params
                    self.send_response(302)
                    self.send_header("Location", params["redirect_uri"] + "?" + urlencode({"code": code, "state": params["state"]}))
                    self.end_headers()
                    return
                self.send_json({"error": "not_found"}, 404)

            def do_POST(self):
                if self.path != "/token":
                    return self.send_json({"error": "not_found"}, 404)
                provider.token_requests += 1
                expected = "Basic " + base64.b64encode(f"{provider.client_id}:{provider.secret}".encode()).decode()
                if not secrets.compare_digest(self.headers.get("Authorization", ""), expected):
                    return self.send_json({"error": "invalid_client"}, 401)
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                params = {key: value[0] for key, value in parse_qs(body).items()}
                authorization = provider.codes.pop(params.get("code", ""), None)
                if not authorization or params.get("redirect_uri") != authorization["redirect_uri"]:
                    return self.send_json({"error": "invalid_grant"}, 400)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(params.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
                provider.used_pkce = authorization.get("code_challenge_method") == "S256" and secrets.compare_digest(challenge, authorization.get("code_challenge", ""))
                if not provider.used_pkce:
                    return self.send_json({"error": "invalid_grant"}, 400)
                now = int(time.time())
                claims = {
                    "iss": provider.url, "aud": provider.client_id, "sub": "test-buyer",
                    "iat": now, "exp": now + 300, "email": "buyer@example.com",
                    "email_verified": True, "name": "Sam Buyer", "given_name": "Sam",
                }
                if provider.mode == "expired": claims["exp"] = now - 60
                if provider.mode == "wrong_issuer": claims["iss"] = "https://wrong.example.com"
                if provider.mode == "wrong_audience": claims["aud"] = "another-client"
                if provider.mode == "missing_expiry": del claims["exp"]
                if provider.mode == "missing_subject": del claims["sub"]
                key = provider.key
                if provider.mode == "tampered": key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})
                if provider.mode == "unsigned": token = jwt.encode(claims, None, algorithm="none")
                if provider.mode == "malformed": token = "not-a-jwt"
                self.send_json({"access_token": secrets.token_urlsafe(32), "token_type": "Bearer", "expires_in": 300, "id_token": token})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def configure(settings, provider, secret=None):
    settings.OIDC_CLIENT_ID = provider.client_id
    settings.OIDC_CLIENT_SECRET = secret or provider.secret
    settings.OIDC_SERVER_URL = provider.url
    settings.OIDC_PROVIDER_NAME = "Test account"
    settings.SOCIALACCOUNT_PROVIDERS = {"openid_connect": {"OAUTH_PKCE_ENABLED": True, "APPS": [{
        "provider_id": "shop", "name": "Test account", "client_id": provider.client_id,
        "secret": secret or provider.secret, "settings": {
            "server_url": provider.url, "oauth_pkce_enabled": True,
            "fetch_userinfo": False, "token_auth_method": "client_secret_basic",
        },
    }]}}

