# Everyday shop

A small e-commerce demo using **Django + Django REST Framework + django-allauth**, **React + Vite + TypeScript**, and **SQLite**. One backend, one React page, six sample products. OAuth/OIDC login, a persistent browser cart, demo checkout, private order history, and Django admin. Checkout records an order; it does not process payments or ship products.

## Run locally

Requires Python 3.12+ and Node.js 22.12+ (or 20.19+) with pnpm. Run these commands from the project root:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/init_env.py
python manage.py migrate
python manage.py seed
pnpm --dir frontend install
python manage.py runserver 127.0.0.1:8000
```

In another terminal:

```sh
pnpm --dir frontend dev
```

If VS Code reports `pnpm: command not found`, you can run the existing installation with npm. This project includes `.nvmrc` to select Node 22. From the `frontend` directory:

```sh
source ~/.nvm/nvm.sh
nvm use
npm run dev
```

These commands use the dependencies already installed in `frontend/node_modules`. On a fresh checkout, install pnpm with `npm install --global pnpm` after selecting Node 22, then run `pnpm install` in `frontend`. If Node 22 is not installed yet, run `nvm install` from the project root first. Use the same Node version for `npm run build` and browser tests.

Open **http://127.0.0.1:5173**. The Vite proxy sends `/api/`, `/accounts/`, and `/admin/` requests to Django. Browse products and use the cart immediately; ordering requires an OAuth login. There is no demo-login bypass.

## Enable OAuth login

Create a confidential **web application** client with your OIDC provider (Google, Keycloak, or another compatible provider). Register this exact redirect URI:

```text
http://127.0.0.1:5173/accounts/oidc/shop/login/callback/
```

Then edit the generated `.env` and restart Django:

```dotenv
OIDC_SERVER_URL=https://accounts.google.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_PROVIDER_NAME=Google
```

For Keycloak, use your realm URL, e.g. `http://localhost:8080/realms/shop`. The generic allauth provider appends `/.well-known/openid-configuration`. Enable Standard Flow and PKCE S256 on the provider. The app currently uses `client_secret_basic` and accepts RS256 or ES256 ID tokens. Use `127.0.0.1` consistently while developing; `localhost` is a different cookie origin and needs its own registered redirect URI.

The backend manages Authorization Code + PKCE, CSRF-protected login initiation, state verification, server-side code exchange, and explicit JWT signature/issuer/audience/expiry checks. Provider tokens are not persisted or sent to React. The browser receives an HTTP-only Django session cookie; unsafe API requests also require a CSRF token.

`.env` and SQLite files are ignored. `scripts/init_env.py` generates a random Django key and sets file permissions to `0600`, preserving an existing file. SQLite does not need a database password. Use backend environment variables for secrets, never `VITE_*`. Set `DJANGO_DEBUG=false`, an HTTPS provider, appropriate allowed hosts, trusted HTTPS frontend origins, and TLS at your reverse proxy for deployment. This enables secure session/CSRF cookies. Serve the built frontend and Django routes under the same origin; `vite preview` is only a static preview and does not proxy the API.

## Test

```sh
source .venv/bin/activate
pytest tests/test_shop.py tests/test_oauth.py -q
python -m playwright install chromium
pytest tests/test_browser.py -q
pnpm --dir frontend build
```

The tests use isolated databases and a test-only local OIDC server with actual RSA-signed JWTs, authorization codes, client authentication, and PKCE. They never contact your real provider or use your real client credentials. Browser tests start their own Vite server and Django test server; install the frontend dependencies first.

Coverage includes successful login, tampered/expired/unsigned/malformed tokens, issuer/audience validation, missing claims, state tampering, code replay, PKCE mismatch, client-secret rotation, signing-key rotation, CSRF, session expiry/logout, order isolation, price tampering, cart validation, and frontend secret exposure. Live login with Google or your own provider still requires valid credentials in `.env`.

## API

| Method | Path | Access |
| --- | --- | --- |
| GET | `/api/products/` | Public catalog |
| GET | `/api/session/` | Current user and CSRF token; no secrets |
| GET | `/api/orders/` | Signed-in customer's orders |
| POST | `/api/orders/` | Signed-in customer + CSRF |
| POST | `/api/logout/` | Signed-in customer + CSRF |

Create an order with `{"items": [{"product_id": 1, "quantity": 2}]}`. Prices and totals always come from the database. Quantities are limited to 1–20, with up to 50 distinct products per order. The API uses sessions; provider ID/access tokens cannot be used as API bearer credentials.

For admin access, sign in through your provider first, then grant that account staff and superuser status from a local Django shell. Open `/admin/` through Vite. This keeps the app's authentication flow OAuth-only.

```sh
python manage.py shell
```

```python
from django.contrib.auth import get_user_model
user = get_user_model().objects.get(email="your-email@example.com")
user.is_staff = user.is_superuser = True
user.save()
```

SQLite keeps local setup simple. Review the database choice before adding concurrent inventory management or production checkout traffic.
