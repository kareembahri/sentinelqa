"""Unit tests for HTML analysis: links, metadata and accessibility indicators."""

from worker.scanner.html import parse_html

GOOD_PAGE = b"""<!doctype html>
<html lang="en"><head>
<title>  OWASP   Juice Shop </title>
<meta name="description" content="Probably the most modern and sophisticated insecure web application">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta charset="utf-8">
<link rel="canonical" href="http://juice-shop:3000/">
<link rel="icon" href="favicon.ico">
<link rel="preconnect" href="https://fonts.example">
</head><body>
<a href="/about">About us</a>
<a href="/home"><img src="/logo.png" alt="Home"></a>
<a href="/close" aria-label="Close"><svg></svg></a>
<img src="/decorative.png" alt="">
<label for="email">Email</label><input id="email" type="email">
<label>Password <input type="password"></label>
<input type="search" aria-label="Search">
<input type="hidden" name="csrf">
<button>Log in</button>
<button aria-label="Open menu"></button>
<script src="main.js"></script>
<iframe src="/video"></iframe>
</body></html>"""


def issue_types(body: bytes) -> list[str]:
    return [issue["type"] for issue in parse_html(body).a11y_issues]


def test_good_page_has_no_accessibility_issues() -> None:
    assert issue_types(GOOD_PAGE) == []


def test_title_and_metadata_are_extracted() -> None:
    page = parse_html(GOOD_PAGE)
    assert page.title == "OWASP Juice Shop"  # whitespace collapsed
    assert page.lang == "en"
    assert page.meta["description"].startswith("Probably")
    assert page.meta["viewport"].startswith("width=device-width")
    assert page.meta["canonical"] == "http://juice-shop:3000/"
    assert page.meta["charset"] == "utf-8"


def test_links_and_resources_are_extracted_but_not_hints() -> None:
    urls = [(link.tag, link.url) for link in parse_html(GOOD_PAGE).links]
    assert ("a", "/about") in urls
    assert ("img", "/logo.png") in urls
    assert ("script", "main.js") in urls
    assert ("iframe", "/video") in urls
    assert ("link", "favicon.ico") in urls
    assert ("link", "https://fonts.example") not in urls  # preconnect is a hint, not a resource
    assert ("link", "http://juice-shop:3000/") not in urls  # canonical is recorded as metadata


def test_missing_alt_is_reported_but_empty_alt_is_allowed() -> None:
    page = parse_html(b'<html lang="en"><title>t</title><meta name="viewport" content="x">'
                      b'<img src="/a.png"><img src="/b.png" alt=""></html>')
    issues = page.a11y_issues
    assert [i["type"] for i in issues] == ["missing_alt"]
    assert "/a.png" in issues[0]["element"]
    assert "WCAG 1.1.1" in issues[0]["message"]


def test_unlabelled_form_fields_are_reported() -> None:
    body = (b'<html lang="en"><title>t</title><meta name="viewport" content="x">'
            b'<input type="text" id="name" placeholder="Your name">'  # a placeholder is not a label
            b'<textarea></textarea><select><option>1</option></select>'
            b'<input type="submit" value="Send"></html>')
    assert issue_types(body) == ["missing_label", "missing_label", "missing_label"]


def test_label_for_can_appear_after_the_field() -> None:
    body = (b'<html lang="en"><title>t</title><meta name="viewport" content="x">'
            b'<input id="later"><label for="later">Later</label></html>')
    assert issue_types(body) == []


def test_empty_links_and_buttons_are_reported() -> None:
    body = (b'<html lang="en"><title>t</title><meta name="viewport" content="x">'
            b'<a href="/x"><img src="/i.png" alt=""></a><button><svg></svg></button>'
            b'<a name="anchor-without-href"></a></html>')
    assert issue_types(body) == ["empty_link", "empty_button"]


def test_page_level_issues() -> None:
    assert issue_types(b"<html><body>hi</body></html>") == [
        "missing_title",
        "missing_lang",
        "missing_viewport",
    ]


def test_base_href_is_detected() -> None:
    page = parse_html(b'<html><head><base href="/app/"></head><a href="x">x</a></html>')
    assert page.base_href == "/app/"


def test_charset_from_content_type_is_used() -> None:
    body = '<html lang="fr"><title>Café</title></html>'.encode("latin-1")
    assert parse_html(body, "text/html; charset=ISO-8859-1").title == "Café"


def test_unknown_charset_falls_back_to_utf8() -> None:
    assert parse_html(b"<title>ok</title>", "text/html; charset=not-a-charset").title == "ok"


def test_broken_markup_never_raises() -> None:
    for body in (b"", b"<<<>>>", b"<a href='x'", b"<![if !IE]><p>", b"\x00\xff\xfe<title>x"):
        parse_html(body)


def test_issue_count_and_snippets_are_bounded() -> None:
    body = b'<html lang="en"><title>t</title>' + (b'<img src="/' + b"a" * 500 + b'.png">') * 200
    issues = parse_html(body).a11y_issues
    assert len(issues) == 50
    assert all(len(issue["element"]) <= 120 for issue in issues)
