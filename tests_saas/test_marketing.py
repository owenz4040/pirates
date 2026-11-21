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
