# Everyday shop

A small e-commerce demo using **Django + Django REST Framework + django-allauth**, **React + Vite + TypeScript**, and **SQLite**. One backend, one React page, six sample products. OAuth/OIDC login, a persistent browser cart, demo checkout, private order history, and Django admin. Checkout records an order; it does not process payments or ship products.

## Self-contained credential demo

This opt-in mode runs **12 distinct consumers** inside Django: three secrets, three mTLS client certificates, three Ed25519 signing keys, and three OAuth access-token families. Each invocation retrieves its credential again and actually authenticates, completes mTLS, verifies a signature, or obtains and uses a fresh access token against a local HTTPS target.

After installing backend and frontend dependencies, run from the backend directory:

```sh
.venv/bin/python scripts/init_demo.py
ECOMM_DEMO_MODE=true .venv/bin/python manage.py run_demo
```

In another terminal:

```sh
ECOMM_DEMO_MODE=true npm --prefix frontend run dev
```

Open **http://127.0.0.1:5173** and select **Sign in → Continue as Demo Buyer**. The local issuer uses the existing Authorization Code + PKCE login flow, with signed ID-token verification and HTTP-only Django session cookies. The browser authorization page is proxied through Vite; backend HTTPS and mTLS use the generated CA without disabling certificate verification or changing the operating system trust store.

The demo panel provides **Run Secrets**, **Run Certificates**, **Run Keys**, **Run OAuth Tokens**, **Run All**, and a Run button for every consumer. It displays names, outcomes, fingerprints, versions, retrieval timestamps and retrieval durations. Demo session/CSRF cookies have separate names so they can coexist with the normal shop on other ports. The same consumers run automatically during shopping:

| Action | Consumers and credential names |
| --- | --- |
| Browse products | `catalog-secret` / `catalog-api-secret`; `catalog-mtls` / `catalog-client-cert`; `catalog-signing` / `catalog-signing-key` |
| Change cart | `inventory-secret` / `inventory-api-secret`; `pricing-mtls` / `pricing-client-cert`; `promotions-oauth` / `promotions-access-token` |
| Checkout | `checkout-secret` / `checkout-api-secret`; `order-signing` / `order-signing-key`; `fulfillment-oauth` / `fulfillment-access-token` |
| View orders | `tracking-mtls` / `tracking-client-cert`; `receipt-signing` / `receipt-signing-key`; `notifications-oauth` / `notifications-access-token` |

A failed dependency blocks that shopping action. Failed cart updates preserve the previous cart; checkout checks complete before an order is created. Cart mutations and checkout are serialized in the UI. Batch runs attempt every selected consumer and report individual failures.

Generated credentials, provider references and a separate SQLite database live in ignored **`.demo/`**. The initializer is idempotent, creates private files with `0600` permissions inside a `0700` directory, and refuses to overwrite incomplete existing data. Restarting reuses the assets. Client certificates expire after 30 days. For a fresh disposable setup, stop the demo and move the entire `.demo` directory aside before initializing again; this also starts a new demo database. Existing `.env`, Azure configuration and the normal shop database are untouched. Demo mode bypasses Azure completely and is enabled by the process environment, not by editing `.env`.

The HTTPS provider binds **127.0.0.1:9443**, Django binds **127.0.0.1:8002**, and Vite uses **127.0.0.1:5173**. To coexist with existing processes, use a separate backend/frontend port pair:

```sh
ECOMM_DEMO_MODE=true ECOMM_DEMO_FRONTEND_ORIGIN=http://127.0.0.1:5175 .venv/bin/python manage.py run_demo --port 8003
ECOMM_DEMO_MODE=true BACKEND_URL=http://127.0.0.1:8003 npm --prefix frontend run dev -- --port 5175
```

Optional process settings: `ECOMM_DEMO_DIR` selects an isolated asset directory (pass the same directory to `scripts/init_demo.py --directory` and Vite); `ECOMM_DEMO_PROVIDER_PORT` selects the provider port and must match in both terminals. `run_demo` disables autoreload and uses one backend process with multiple threads and one shared audit writer. Demo routes and loopback enforcement are active only in demo mode. Supporting CA/server certificates, issuer keys and client/bootstrap secrets are classified as infrastructure in the manifest and excluded from the 12 business-consumer count.

### APIs and shared log

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/demo/services/` | List public consumer definitions |
| POST | `/api/demo/services/{consumer_id}/run/` | Run one consumer; login + CSRF required |
| POST | `/api/demo/run/` | Run all, or pass `credential_type`: `secret`, `certificate`, `key`, `oauth_token`; login + CSRF required |
| POST | `/api/demo/cart/` | Validate and check a proposed cart; anonymous + CSRF supported, including an empty cart |
| POST | `/api/demo/exposure/secret/run/` | Authenticate with a dedicated demo secret and intentionally log its raw value; login + CSRF required |
| POST | `/api/demo/exposure/key/run/` | Sign/verify with a dedicated Ed25519 key and intentionally log its private PEM value; login + CSRF required |

Run responses contain `request_id`, `run_id`, `results`, and `summary.succeeded`/`summary.failed`. Individual failures return HTTP 503 with a fixed error code and correlation IDs. Completed batches return HTTP 200 with per-consumer outcomes. Existing successful catalog/order response shapes are preserved. The session response includes `demo_enabled`.

All backend application logs, request completions, provider events, credential retrievals, uses and failures append to **`.demo/ecomm-demo.jsonl`**. There is one JSON object per line, shared by Django and provider threads. Each credential retrieval/use event identifies the consumer ID/name/API path, credential type/name/version, SHA-256 fingerprint and its basis, UTC `retrieved_at`, measured `retrieval_duration_ms`, operation/destination/outcome, request/run IDs, trigger and caller ID or anonymous. Failed retrievals leave unavailable fingerprints/timestamps null. Query strings, bodies, cookies, authorization headers and raw tokens are excluded. The 12 business consumers exclude raw secrets and private keys. Generic library log records retain source/severity and safe stack locations, rather than potentially sensitive interpolated messages.

The separate **Credential values in logs** panel has **Run Secret Logging API** and **Run Key Logging API** buttons. These two endpoints intentionally append `credential.value.logged` events containing `credential_value`: the secret as UTF-8 text or the private key as PKCS#8 PEM. The event is marked `intentional_value_logging: true`, `credential_value_logged: true`, and `asset_role: log_exposure_demo`. It carries the usual environment, consumer, source, issuance/expiry, TTL, fingerprint, retrieval timing and correlation metadata. JSON escapes the PEM newlines so each event remains one parseable JSONL line. API responses and the frontend show metadata and confirmation only.

Each endpoint creates its own random, disposable credential under `.demo/log-exposure/` on its first invocation, with private directory/file permissions, and reuses it on later calls. The secret uses the simulated Azure Vault label and a 24-hour TTL; the key uses PostgreSQL DB and a 7-day TTL. Issuance is logged once per credential, and an expired, missing or mismatched asset fails the call. Raw-value logging happens only when one of these buttons/endpoints is explicitly run; these two demos are separate from Run All, category controls, automatic shopping checks, and the original 12 consumers.

Every new log record also contains `environment`. Set `ECOMM_DEMO_ENVIRONMENT` to `production`, `testing`, `development` (default), or `staging` in the initializer and backend processes. Input is case-insensitive and logged in lowercase; invalid values are rejected. For example, `ECOMM_DEMO_ENVIRONMENT=staging ECOMM_DEMO_MODE=true .venv/bin/python manage.py run_demo` labels issuance, retrieval, usage, provider, request, and error events as `"environment":"staging"`. This field describes the running demo environment and does not change deployment behavior. Existing log lines remain unchanged.

Fingerprint bases are UTF-8 secret/token bytes (`value_utf8`), certificate DER (`certificate_der`), and public signing-key SPKI DER (`public_key_spki`). Static fingerprints stay stable across runs; service tokens have fresh IDs and fingerprints. Critical credential events are flushed and synced before success is reported. An unavailable audit file prevents startup or fails the operation.

Issuance is recorded separately as **`credential.issued`**. Every record identifies `issuance_id`, `issuance_source`, `issuance_source_type`, `actual_issuer`, `issued_at`, `expires_at`, `ttl_seconds`, and `remaining_ttl_seconds`, along with consumer, credential name/type/version and fingerprint. Retrieval/use events carry the same issuance identity for correlation. TTL is the original lifetime; remaining TTL is a snapshot when the event is recorded (or when displayed in the panel).

The source labels are deliberately **simulated**: `source_simulated: true` is present beside the source and `actual_issuer` identifies the local generator or local OAuth server. `catalog`, `checkout`, `tracking`, and `receipt` static credentials use **Azure Vault** (`vault`); `inventory-secret`, `pricing-mtls`, and `order-signing` use **PostgreSQL DB** (`database`); OAuth tokens use **Google OAuth** (`cloud_broker`). These labels require no external cloud or database connection.

Default lifetimes are **24 hours for secrets**, **7 days for signing keys**, **30 days for certificates** (their actual certificate expiry), and **5 minutes for OAuth tokens** (their actual signed `iat`/`exp`). Expired static credentials are rejected. The panel shows source, issuance/expiry and TTL alongside retrieval metadata. Static issuance records are persisted in `.demo/issuance.json`; repeated retrievals or initializer runs do not manufacture new issuances. Each newly minted OAuth token receives a separate issuance ID. Website login token issuances are marked `asset_role: infrastructure` and excluded from the 12 business-consumer count.

For existing demo directories, rerun the initializer or restart `run_demo`. Missing issuance metadata is backfilled using the original manifest creation time and certificate expiry, with `issuance_time_origin: manifest_backfill` and `historical_record: true`. Existing credential values and fingerprints are preserved. If a file is replaced with unregistered material, its issuance identity is reported as unknown with `issuance_record_status: fingerprint_mismatch`; it is not silently treated as a new issuance. Existing log lines are preserved, and the new records are appended.

```sh
tail -f .demo/ecomm-demo.jsonl
pytest tests/test_demo.py tests/test_demo_browser.py -q
```

The tests generate isolated local assets and providers. No cloud credentials or real provider accounts are used. The normal (non-demo) setup continues below.

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
python manage.py runserver 127.0.0.1:8002
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

When using Azure Key Vault as described below, omit the `OIDC_CLIENT_SECRET` value from `.env`; Django reads it from the vault.

For Keycloak, use your realm URL, e.g. `http://localhost:8080/realms/shop`. The generic allauth provider appends `/.well-known/openid-configuration`. Enable Standard Flow and PKCE S256 on the provider. The app currently uses `client_secret_basic` and accepts RS256 or ES256 ID tokens. Use `127.0.0.1` consistently while developing; `localhost` is a different cookie origin and needs its own registered redirect URI.

The backend manages Authorization Code + PKCE, CSRF-protected login initiation, state verification, server-side code exchange, and explicit JWT signature/issuer/audience/expiry checks. Provider tokens are not persisted or sent to React. The browser receives an HTTP-only Django session cookie; unsafe API requests also require a CSRF token.

`.env` and SQLite files are ignored. `scripts/init_env.py` generates a random Django key and sets file permissions to `0600`, preserving an existing file. SQLite does not need a database password. Use backend environment variables for secrets, never `VITE_*`. Set `DJANGO_DEBUG=false`, an HTTPS provider, appropriate allowed hosts, trusted HTTPS frontend origins, and TLS at your reverse proxy for deployment. This enables secure session/CSRF cookies. Serve the built frontend and Django routes under the same origin; `vite preview` is only a static preview and does not proxy the API.

## Azure Key Vault: application secrets

The only Azure integration reads these two existing objects from **Key Vault → Objects → Secrets** during Django startup:

| Django setting | Default Azure secret name | Value |
| --- | --- | --- |
| `SECRET_KEY` (`DJANGO_SECRET_KEY` in local configuration) | `django-secret-key` | A random Django signing key of at least 50 characters |
| `OIDC_CLIENT_SECRET` | `oidc-client-secret` | The Google/OIDC application's client secret |

Use objects under **Secrets** with raw string values. No tags or JSON payloads are required. The integration only reads these two application settings; it does not store OAuth tokens or create, update or delete anything in Azure.

Configure access in the Azure Portal:

1. Under **Microsoft Entra ID → App registrations**, create/select the application Django will use to access the vault. Copy its **Directory (tenant) ID** and **Application (client) ID**. It does not need a redirect URI.
2. Under that registration's **Certificates & secrets**, create a client secret and copy its **Value**, not its Secret ID. This Azure bootstrap credential is separate from the Google `oidc-client-secret` inside the vault.
3. If the vault uses Azure RBAC, assign **Key Vault Secrets User** to this application's service principal under the vault's **Access control (IAM)**. Read access is sufficient. If the vault uses access policies instead, grant the application **Secrets → Get** under **Access policies**. Your personal portal access does not grant Django access. [Azure secret roles](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide).
4. Ensure the vault's networking allows your Mac to connect, and that both secret versions are enabled and within their validity dates.

Add these server-side values to `e-com_dummy/.env`:

```dotenv
AZURE_KEY_VAULT_URL=https://argus-nhi.vault.azure.net
AZURE_TENANT_ID=<directory-tenant-id>
AZURE_CLIENT_ID=<azure-application-client-id>
AZURE_CLIENT_SECRET=<azure-client-secret-value>
DJANGO_SECRET_KEY_NAME=django-secret-key
OIDC_CLIENT_SECRET_NAME=oidc-client-secret

OIDC_SERVER_URL=https://accounts.google.com
OIDC_CLIENT_ID=<your-google-oauth-client-id>
OIDC_PROVIDER_NAME=Google
```

The last two `*_NAME` settings are optional overrides; their defaults match your vault. Leave `AZURE_KEY_VAULT_URL` empty only when deliberately using the original local `.env` secret values. With a vault URL configured, **both application secrets come exclusively from Azure**, and unavailable, empty, disabled, expired or future-dated secrets prevent startup. Local secret values are ignored in this mode. No Azure CLI or `AZURE_KEY_VAULT_AUTH` setting is needed: the backend uses `ClientSecretCredential` directly. Keep all Azure credentials out of frontend `VITE_*` settings.

```sh
source .venv/bin/activate
pip install -r requirements.txt
python manage.py check
python manage.py runserver 127.0.0.1:8002
```

The current local frontend proxy targets port **8002**. Use that backend port, or set `BACKEND_URL=http://127.0.0.1:8000` when starting the frontend if you prefer port 8000. A successful `manage.py check` with a vault URL verifies that Django can read both secrets without printing their values. Restart Django after replacing a secret version; values stay in server memory for the process lifetime. Changing the Django signing key invalidates existing signed sessions. Use the previous Django key as the vault value if existing sessions should remain valid.

This integration adds no database migration or background worker. Remove obsolete `GOOGLE_API_TESTING_*`, `GOOGLE_API_TEST_ENCRYPTION_KEY`, `VAULT_API_TOKEN_SECRET_NAME`, `VAULT_REFRESH_TOKEN_SECRET_NAME`, `OAUTH_TOKEN_SECRET_PREFIX`, and `AZURE_KEY_VAULT_AUTH` entries from old local configurations; none are used now. Stop any previously started `cleanup_oauth_tokens --watch` process.

## Test

```sh
source .venv/bin/activate
pytest tests/test_shop.py tests/test_oauth.py tests/test_key_vault.py -q
python -m playwright install chromium
pytest tests/test_browser.py -q
pnpm --dir frontend build
```

The tests use isolated databases, a mocked vault, and a test-only local OIDC server with actual RSA-signed JWTs, authorization codes, client authentication, and PKCE. They never contact your real provider/vault or use your real credentials. Vault tests cover settings integration, read-only access, missing configuration, permission/network errors, secret validity and sanitized failures. Browser tests start their own Vite server and Django test server; install the frontend dependencies first.

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
