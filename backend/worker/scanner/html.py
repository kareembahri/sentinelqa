"""HTML page analysis: links, title, metadata and accessibility indicators.

Uses Python's built-in, lenient HTML parser (no extra dependency). It reads the
HTML exactly as the server sent it. Pages that build their content with
JavaScript (single-page apps such as Juice Shop) show only their initial HTML
here; Phase 4 adds a real browser for the rendered page.

The accessibility checks are *indicators* of common WCAG problems found in
markup. They are not a full accessibility audit: contrast, keyboard use and
screen-reader behaviour need a browser and a human.
"""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

# Tag -> attribute that holds a URL worth checking.
LINK_ATTRIBUTES = {
    "a": "href",
    "area": "href",
    "iframe": "src",
    "img": "src",
    "script": "src",
    "link": "href",
}
# <link rel="..."> values that are not fetchable resources of this page.
SKIPPED_LINK_RELS = ("canonical", "alternate", "dns-prefetch", "preconnect")
META_NAMES = frozenset({"description", "robots", "viewport", "generator", "keywords"})
# Input types that do not need a visible label.
UNLABELLED_INPUT_TYPES = frozenset({"hidden", "submit", "button", "reset", "image"})

MAX_ISSUES_PER_PAGE = 50
MAX_LINKS_PER_PAGE = 1000
SNIPPET_LENGTH = 120

ISSUE_MESSAGES = {
    "missing_alt": "Image has no alt attribute (WCAG 1.1.1 Non-text Content)",
    "missing_label": "Form field has no associated label (WCAG 1.3.1, 4.1.2)",
    "empty_link": "Link has no accessible text (WCAG 2.4.4 Link Purpose)",
    "empty_button": "Button has no accessible text (WCAG 4.1.2 Name, Role, Value)",
    "missing_title": "Page has no <title> (WCAG 2.4.2 Page Titled)",
    "missing_lang": "<html> element has no lang attribute (WCAG 3.1.1 Language of Page)",
    "missing_viewport": "No viewport meta tag; the page may not scale on mobile devices",
}


@dataclass(frozen=True)
class ExtractedLink:
    tag: str  # a, area, iframe, img, script, link
    url: str


@dataclass
class PageAnalysis:
    title: str | None
    lang: str | None
    base_href: str | None
    meta: dict[str, str]
    links: list[ExtractedLink]
    a11y_issues: list[dict[str, Any]]


def _snippet(tag: str, attrs: list[tuple[str, str | None]]) -> str:
    parts = [tag] + [f'{name}="{value}"' if value is not None else name for name, value in attrs]
    text = "<" + " ".join(parts) + ">"
    return text if len(text) <= SNIPPET_LENGTH else text[: SNIPPET_LENGTH - 4] + "...>"


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.has_title_tag = False
        self.in_title = False
        self.lang: str | None = None
        self.seen_html_tag = False
        self.base_href: str | None = None
        self.meta: dict[str, str] = {}
        self.links: list[ExtractedLink] = []
        self.issues: list[dict[str, Any]] = []
        self.label_depth = 0
        self.label_for_ids: set[str] = set()
        # (id, snippet, already_labelled) for every form control; resolved at the end
        # because a <label for="..."> may come after the field.
        self.controls: list[tuple[str | None, str, bool]] = []
        # Open <a>/<button> elements whose visible text we are collecting.
        self.text_contexts: list[dict[str, Any]] = []

    def add_issue(self, issue_type: str, element: str) -> None:
        if len(self.issues) < MAX_ISSUES_PER_PAGE:
            self.issues.append(
                {"type": issue_type, "message": ISSUE_MESSAGES[issue_type], "element": element}
            )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: (value or "") for name, value in attrs}
        snippet = _snippet(tag, attrs)

        if tag == "html" and not self.seen_html_tag:
            self.seen_html_tag = True
            self.lang = values.get("lang", "").strip() or None
        elif tag == "title":
            self.has_title_tag = True
            self.in_title = True
        elif tag == "base" and self.base_href is None and values.get("href"):
            self.base_href = values["href"].strip()
        elif tag == "meta":
            name = (values.get("name") or values.get("property") or "").strip().lower()
            if name in META_NAMES:
                self.meta[name] = values.get("content", "")[:500]
            if "charset" in values:
                self.meta["charset"] = values["charset"][:50]

        rel = values.get("rel", "").lower()
        if tag == "link" and "canonical" in rel and values.get("href"):
            self.meta["canonical"] = values["href"][:500]

        attribute = LINK_ATTRIBUTES.get(tag)
        url = values.get(attribute, "").strip() if attribute else ""
        skipped_rel = tag == "link" and any(skip in rel for skip in SKIPPED_LINK_RELS)
        if url and not skipped_rel and len(self.links) < MAX_LINKS_PER_PAGE:
            self.links.append(ExtractedLink(tag=tag, url=url))

        if tag == "img":
            if "alt" not in values:
                self.add_issue("missing_alt", snippet)
            elif values["alt"].strip():
                for context in self.text_contexts:
                    context["text"] += values["alt"]  # an image's alt text names its link

        if tag == "label":
            self.label_depth += 1
            if values.get("for"):
                self.label_for_ids.add(values["for"])

        if tag in ("input", "select", "textarea"):
            input_type = values.get("type", "text").strip().lower()
            if not (tag == "input" and input_type in UNLABELLED_INPUT_TYPES):
                labelled = self.label_depth > 0 or any(
                    values.get(name, "").strip() for name in ("aria-label", "aria-labelledby", "title")
                )
                self.controls.append((values.get("id") or None, snippet, labelled))

        if tag == "button" or (tag == "a" and "href" in values):
            labelled = any(
                values.get(name, "").strip() for name in ("aria-label", "aria-labelledby", "title")
            )
            self.text_contexts.append({"tag": tag, "text": "", "labelled": labelled, "snippet": snippet})

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        elif tag == "label" and self.label_depth:
            self.label_depth -= 1
        elif tag in ("a", "button"):
            for index in range(len(self.text_contexts) - 1, -1, -1):
                if self.text_contexts[index]["tag"] == tag:
                    context = self.text_contexts.pop(index)
                    if not context["text"].strip() and not context["labelled"]:
                        self.add_issue("empty_link" if tag == "a" else "empty_button", context["snippet"])
                    break

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        for context in self.text_contexts:
            if len(context["text"]) < 200:
                context["text"] += data

    def finish(self) -> PageAnalysis:
        for control_id, snippet, labelled in self.controls:
            if not labelled and (control_id is None or control_id not in self.label_for_ids):
                self.add_issue("missing_label", snippet)

        title = " ".join("".join(self.title_parts).split()) or None
        if title is None:
            self.add_issue("missing_title", "<title>" if self.has_title_tag else "<head>")
        if self.seen_html_tag and self.lang is None:
            self.add_issue("missing_lang", "<html>")
        if "viewport" not in self.meta:
            self.add_issue("missing_viewport", "<head>")

        return PageAnalysis(
            title=title[:500] if title else None,
            lang=self.lang,
            base_href=self.base_href,
            meta=self.meta,
            links=self.links,
            a11y_issues=self.issues,
        )


def decode_body(body: bytes, content_type: str) -> str:
    match = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
    encoding = match.group(1) if match else "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:  # unknown charset name sent by the server
        return body.decode("utf-8", errors="replace")


def parse_html(body: bytes, content_type: str = "text/html; charset=utf-8") -> PageAnalysis:
    parser = _PageParser()
    try:
        parser.feed(decode_body(body, content_type))
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup must never crash a scan
        parser.meta["parse_warning"] = "The HTML could not be fully parsed; results may be incomplete"
    return parser.finish()
