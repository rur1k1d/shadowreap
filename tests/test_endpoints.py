"""Tests for robots.txt + sitemap.xml parsing (no live hosts)."""

from shadowreap.parsers.endpoints import parse_robots, parse_sitemap_xml

ROBOTS = """User-agent: *
Disallow: /admin
Allow: /public
Disallow: /private/*

User-agent: googlebot
Disallow: /everything

Sitemap: https://example.com/sitemap.xml
"""

BOOK_AGENT_ROBOTS = """User-agent: *
Disallow:
"""


def test_parse_robots_all_groups():
    parsed = parse_robots(ROBOTS)
    assert parsed["disallow"] == ["/admin", "/private/*"]
    assert parsed["allow"] == ["/public"]
    assert parsed["sitemap"] == ["https://example.com/sitemap.xml"]


def test_parse_robots_ignores_other_agents():
    # googlebot's Disallow must not leak into "*" handling
    parsed = parse_robots(ROBOTS)
    assert "/everything" not in parsed["disallow"]


def test_parse_robots_empty_disallow():
    parsed = parse_robots(BOOK_AGENT_ROBOTS)
    assert parsed["disallow"] == []


def test_parse_sitemap_xml():
    xml = """<?xml version="1.0"?>
<urlset><url><loc>https://example.com/</loc></url><url><loc>https://example.com/about</loc></url></urlset>
"""
    assert parse_sitemap_xml(xml) == ["https://example.com/", "https://example.com/about"]


def test_parse_sitemap_index():
    xml = """<?xml version="1.0"?>
<sitemapindex><sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap></sitemapindex>
"""
    assert parse_sitemap_xml(xml) == ["https://example.com/sitemap-1.xml"]