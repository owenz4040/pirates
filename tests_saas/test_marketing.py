"""Tests for public marketing website and pricing displays."""
from __future__ import annotations


def test_landing_page_renders_successfully(client):
    """Test GET / returns 200 OK with core branding and value propositions."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Branding & Header
    assert "COwen" in html
    assert "Multi-Tenant ISP" in html

    # Core Features
    assert "MikroTik" in html
    assert "PPPoE" in html
    assert "Hotspot" in html
    assert "Captive Portal" in html
    assert "M-Pesa" in html
    assert "Paystack" in html

    # Exact Pricing Packages Check
    assert "Starter" in html
    assert "KSh 1,000" in html
    assert "Basic" in html
    assert "KSh 1,500" in html
    assert "Growth" in html
    assert "KSh 3,500" in html
    assert "Business" in html
    assert "KSh 5,000" in html

    # Router Limits
    assert "1 MikroTik Router" in html
    assert "2 MikroTik Routers" in html
    assert "4 MikroTik Routers" in html
    assert "6 MikroTik Routers" in html


def test_pricing_redirect(client):
    """Test GET /pricing redirects to anchor #pricing on homepage."""
    response = client.get("/pricing", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/#pricing"


def test_marketing_navigation_sign_in_and_actions(client):
    """Verifies PART A marketing navigation: Sign In button, Get Started button, and section anchors."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Brand
    assert "COwen" in html
    # Sign In linking to /tenant/login
    assert 'href="/tenant/login"' in html
    assert "Sign In" in html
    # Get Started linking to /#pricing with arrow
    assert 'href="/#pricing"' in html
    assert "Get Started" in html
    # Section anchors
    assert 'href="/#features"' in html
    assert 'href="/#how-it-works"' in html
    assert 'href="/#pricing"' in html
    assert 'href="/#faq"' in html
    # Mobile drawer & toggle
    assert 'id="mobileDrawer"' in html
    assert "toggleMobileNav()" in html

