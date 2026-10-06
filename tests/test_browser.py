import os
from pathlib import Path
import shutil
import socket
import subprocess
import time

from django.core.management import call_command
from playwright.sync_api import expect, sync_playwright
import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def browser_shop(live_server, provider, settings):
    call_command("seed", verbosity=0)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    settings.CSRF_TRUSTED_ORIGINS = [origin]
    node = os.getenv("NODE_BINARY") or shutil.which("node")
    assert node, "Install Node.js or set NODE_BINARY to run the browser tests."
    process = subprocess.Popen([
        node, str(ROOT / "frontend/node_modules/vite/bin/vite.js"), "--host", "127.0.0.1", "--port", str(port), "--strictPort",
    ], cwd=ROOT / "frontend", env={**os.environ, "BACKEND_URL": live_server.url}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 30
        while True:
            assert process.poll() is None, "Vite exited; install frontend dependencies before running these tests."
            try:
                if requests.get(origin, timeout=1).status_code == 200:
                    break
            except requests.ConnectionError:
                pass
            assert time.monotonic() < deadline, "Vite did not start in time."
            time.sleep(.1)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(base_url=origin, viewport={"width": 1440, "height": 1000})
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            yield page, context, provider, errors
            assert errors == [], f"Browser errors: {errors}"
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_catalog_search_cart_persistence_and_mobile_layout(browser_shop):
    page, _, _, _ = browser_shop
    page.goto("/")
    expect(page.locator(".product")).to_have_count(6)
    page.get_by_role("button", name="Desk", exact=True).click()
    expect(page.locator(".product")).to_have_count(2)
    page.get_by_role("button", name="All essentials").click()
    page.get_by_role("textbox", name="Search products").fill("mug")
    expect(page.locator(".product")).to_have_count(1)
    page.get_by_role("textbox", name="Search products").fill("")
    page.get_by_role("button", name="Add The morning mug to cart").click()
    page.get_by_role("button", name="Open cart, 1 items").click()
    expect(page.get_by_role("dialog")).to_be_visible()
    page.get_by_role("button", name="Increase The morning mug quantity").click()
    expect(page.locator(".cart-summary")).to_contain_text("₹1,380.00")
    page.get_by_role("button", name="Close panel").click()
    page.reload()
    expect(page.get_by_role("button", name="Open cart, 2 items")).to_be_visible()
    Path(ROOT / "test-results").mkdir(exist_ok=True)
    page.screenshot(path=str(ROOT / "test-results/desktop.png"), full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    expect(page.get_by_role("button", name="My orders")).to_be_visible()
    page.screenshot(path=str(ROOT / "test-results/mobile.png"), full_page=True)
    page.get_by_role("button", name="Open cart, 2 items").click()
    page.get_by_role("button", name="Remove", exact=True).click()
    expect(page.get_by_role("dialog")).to_contain_text("Your bag is empty")
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog")).not_to_be_visible()


def test_oauth_checkout_history_logout_and_secret_exposure(browser_shop):
    page, context, provider, _ = browser_shop
    page.goto("/")
    expect(page.locator(".product")).to_have_count(6)
    page.get_by_role("button", name="Add The morning mug to cart").click()
    page.get_by_role("button", name="Sign in", exact=True).click()
    expect(page.get_by_role("button", name="Sign out")).to_be_visible(timeout=15000)
    assert provider.used_pkce
    assert provider.token_requests == 1
    cookies = context.cookies()
    session = next(cookie for cookie in cookies if cookie["name"] == "sessionid")
    assert session["httpOnly"]
    assert "sessionid" not in page.evaluate("document.cookie")
    assert provider.secret not in page.content()
    assert provider.secret not in page.evaluate("JSON.stringify(localStorage)")
    assert "access_token" not in page.evaluate("JSON.stringify(localStorage)")
    page.get_by_role("button", name="Open cart, 1 items").click()
    page.get_by_role("button", name="Place demo order").click()
    expect(page.get_by_role("status")).to_contain_text("placed")
    expect(page.get_by_role("button", name="Open cart, 0 items")).to_be_visible()
    history = page.request.get("/api/orders/").json()
    assert len(history) == 1
    assert history[0]["total"] == "690.00"
    page.get_by_role("button", name="My orders").click()
    expect(page.get_by_role("dialog")).to_contain_text("The morning mug")
    expect(page.get_by_role("dialog")).to_contain_text("₹690.00")
    page.get_by_role("button", name="Close panel").click()
    page.get_by_role("button", name="Sign out").click()
    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
    assert page.request.get("/api/orders/").status == 403


def test_bad_oauth_token_does_not_create_browser_session(browser_shop):
    page, _, provider, _ = browser_shop
    provider.mode = "tampered"
    page.goto("/")
    expect(page.locator(".product")).to_have_count(6)
    page.get_by_role("button", name="Sign in", exact=True).click()
    page.wait_for_url("**/accounts/oidc/shop/login/callback/**")
    page.wait_for_load_state("domcontentloaded")
    assert page.request.get("/api/session/").json()["user"] is None
    assert page.request.get("/api/orders/").status == 403
