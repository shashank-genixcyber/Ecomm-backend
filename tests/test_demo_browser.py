"""Browser coverage against the actual local TLS/OIDC provider."""
import json
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect
import pytest

from .test_browser import browser_shop  # noqa: F401
from .test_demo import local_demo, template  # noqa: F401

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def provider(local_demo, settings, monkeypatch):
    settings.SOCIALACCOUNT_ADAPTER = "demo.adapter.DemoSocialAccountAdapter"
    settings.OIDC_PROVIDER_NAME = "Local Demo"
    settings.SOCIALACCOUNT_PROVIDERS = {"openid_connect": {"OAUTH_PKCE_ENABLED": True, "APPS": [{
        "provider_id": "shop", "name": "Local Demo", "client_id": "everyday-web",
        "secret": local_demo.bootstrap["web_client_secret"],
        "settings": {"server_url": local_demo.url + "/demo-provider", "oauth_pkce_enabled": True,
                     "fetch_userinfo": False, "token_auth_method": "client_secret_basic"},
    }]}}
    monkeypatch.setenv("ECOMM_DEMO_MODE", "true")
    monkeypatch.setenv("ECOMM_DEMO_DIR", str(local_demo.root))
    monkeypatch.setenv("ECOMM_DEMO_PROVIDER_PORT", str(local_demo.server.server_port))
    return local_demo


def open_shop(page, provider):
    page.goto("/")
    origin = urlsplit(page.url)
    provider.frontend_origin = f"{origin.scheme}://{origin.netloc}"
    provider.redirect_uri = provider.frontend_origin + "/accounts/oidc/shop/login/callback/"
    expect(page.locator(".product")).to_have_count(6)


def login(page):
    page.get_by_role("button", name="Sign in", exact=True).click()
    page.get_by_role("button", name="Continue as Demo Buyer").click()
    expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible(timeout=15000)


def test_demo_login_all_controls_shopping_and_mobile(browser_shop):
    page, context, provider, _ = browser_shop
    open_shop(page, provider)
    expect(page.locator(".demo-service")).to_have_count(12)
    login(page)
    for label in ("Run Secrets", "Run Certificates", "Run Keys", "Run OAuth Tokens", "Run All"):
        button = page.get_by_role("button", name=label, exact=True)
        with page.expect_response("**/api/demo/run/"):
            button.click()
        expect(button).to_be_enabled()
        expect(page.locator(".demo-run-summary")).to_contain_text("12 succeeded" if label == "Run All" else "3 succeeded")
    expect(page.locator(".demo-outcome.success")).to_have_count(12)
    expect(page.locator(".demo-fingerprint")).to_have_count(12)
    for source in ("Azure Vault", "PostgreSQL DB", "Google OAuth"):
        expect(page.locator(".credential-demo")).to_contain_text(source)
    expect(page.get_by_text("Issued TTL", exact=True)).to_have_count(12)
    with page.expect_response("**/api/demo/services/catalog-secret/run/"):
        page.get_by_role("button", name="Run Catalog Secret", exact=True).click()
    expect(page.locator(".demo-run-summary")).to_contain_text("1 succeeded")
    page.get_by_role("button", name="Add The morning mug to cart").click()
    expect(page.get_by_role("button", name="Open cart, 1 items")).to_be_visible()
    page.get_by_role("button", name="Open cart, 1 items").click()
    page.get_by_role("button", name="Place demo order").click()
    expect(page.locator(".toast")).to_contain_text("placed")
    page.get_by_role("button", name="My orders").click()
    expect(page.get_by_role("dialog")).to_contain_text("The morning mug")
    page.get_by_role("button", name="Close panel").click()
    sensitive = [provider.bootstrap["web_client_secret"], *[reference["expected_secret"] for reference in provider.references.values() if reference["type"] == "secret"]]
    browser_data = page.content() + page.evaluate("JSON.stringify(localStorage)")
    assert all(value not in browser_data for value in sensitive)
    assert next(cookie for cookie in context.cookies() if cookie["name"] == "ecomm_demo_sessionid")["httpOnly"]
    for width in (320, 390, 768, 1440):
        page.set_viewport_size({"width": width, "height": 1000})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), page.evaluate("Array.from(document.querySelectorAll('body *')).map(e => ({tag:e.tagName, cls:e.className, right:e.getBoundingClientRect().right, width:e.getBoundingClientRect().width})).filter(e => e.right > window.innerWidth + 1).slice(0,15)")
    evidence = Path(__file__).resolve().parents[1] / "test-results"
    evidence.mkdir(exist_ok=True)
    page.screenshot(path=str(evidence / "credential-demo-desktop.png"), full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    page.screenshot(path=str(evidence / "credential-demo-mobile.png"), full_page=True)
    events = [json.loads(line) for line in (provider.root / "ecomm-demo.jsonl").read_text().splitlines()]
    assert {event["trigger"] for event in events if event["event_type"] == "credential.used"} >= {"products", "cart", "checkout", "orders", "manual", "manual_batch"}


def test_failed_cart_does_not_commit_browser_state(browser_shop):
    page, _, provider, _ = browser_shop
    open_shop(page, provider)
    (provider.root / "inventory-api-secret.txt").write_text("canary-invalid-inventory")
    page.get_by_role("button", name="Add The morning mug to cart").click()
    expect(page.locator(".toast")).to_contain_text("failed")
    expect(page.get_by_role("button", name="Open cart, 0 items")).to_be_visible()
    assert page.evaluate("localStorage.getItem('everyday-cart')") == "{}"
    assert "canary-invalid-inventory" not in page.content()


def test_explicit_secret_and_key_logging_buttons(browser_shop):
    page, _, provider, _ = browser_shop
    open_shop(page, provider)
    expect(page.locator('.demo-exposure-service')).to_have_count(2)
    login(page)
    for kind, label in (("secret", "Run Secret Logging API"), ("key", "Run Key Logging API")):
        with page.expect_response(f"**/api/demo/exposure/{kind}/run/") as response:
            page.get_by_role("button", name=label, exact=True).click()
        assert response.value.status == 200
        expect(page.locator(f'[data-consumer="log-exposure-{kind}"] .demo-exposure-outcome')).to_have_text("Value written to shared log")
        value = (provider.root / "log-exposure" / kind / "credential.txt").read_text()
        browser_data = page.content() + page.evaluate("JSON.stringify(localStorage)") + response.value.text()
        assert value not in browser_data
        assert json.dumps(value) not in browser_data
    events = [json.loads(line) for line in (provider.root / "ecomm-demo.jsonl").read_text().splitlines()]
    exposed = [event for event in events if event["event_type"] == "credential.value.logged"]
    assert len(exposed) == 2 and {event["credential_type"] for event in exposed} == {"secret", "key"}
    assert all(event["environment"] == "testing" and event["intentional_value_logging"] for event in exposed)
    assert len({event["request_id"] for event in exposed}) == 2
    for width in (320, 390, 1440):
        page.set_viewport_size({"width": width, "height": 1000})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    (provider.root / "log-exposure/secret/credential.txt").write_text("invalid-demo-exposure-secret")
    page.get_by_role("button", name="Run Secret Logging API", exact=True).click()
    expect(page.locator('[data-consumer="log-exposure-secret"] .demo-exposure-outcome')).to_contain_text("Failed")
    expect(page.locator('.demo-error')).to_contain_text("Reference:")


def test_checkout_serializes_cart_mutations_and_handles_html_failure(browser_shop):
    page, _, provider, _ = browser_shop
    open_shop(page, provider)
    login(page)
    page.get_by_role("button", name="Add The morning mug to cart").click()
    expect(page.get_by_role("button", name="Open cart, 1 items")).to_be_visible()
    held = []
    def hold_checkout(route):
        if route.request.method == "POST":
            response = route.fetch(headers=route.request.all_headers())
            assert response.status == 201, response.text()
            held.append((route, response))
        else:
            route.continue_()
    page.route("**/api/orders/", hold_checkout)
    page.get_by_role("button", name="Open cart, 1 items").click()
    page.get_by_role("button", name="Place demo order").click()
    page.get_by_role("button", name="Close panel").click()
    expect(page.get_by_role("button", name="Add Everywhere tote to cart")).to_be_disabled()
    assert len(held) == 1
    held[0][0].fulfill(response=held[0][1])
    expect(page.get_by_role("button", name="Open cart, 0 items")).to_be_visible()
    page.unroute("**/api/orders/", hold_checkout)
    page.get_by_role("button", name="Add The morning mug to cart").click()
    expect(page.get_by_role("button", name="Open cart, 1 items")).to_be_visible()
    page.route("**/api/orders/", lambda route: route.fulfill(status=502, content_type="text/html", body="<html>Gateway error</html>"))
    page.get_by_role("button", name="Open cart, 1 items").click()
    page.get_by_role("button", name="Place demo order").click()
    expect(page.locator(".panel-message")).to_contain_text("We couldn’t complete that request")
    assert "Unexpected token" not in page.locator(".panel-message").inner_text()
