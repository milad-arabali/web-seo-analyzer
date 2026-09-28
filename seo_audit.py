#!/usr/bin/env python3
"""Bounded, token-free technical SEO crawler and Persian report generator."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo


USER_AGENT = "WebSEOAnalyzer/1.0 (+technical SEO audit; respectful crawler)"
HTML_TYPES = ("text/html", "application/xhtml+xml")
WORD_RE = re.compile(r"[\w\u0600-\u06ff]{3,}", re.UNICODE)
GENERIC_WORDS = {
    "برای", "این", "های", "است", "شود", "شده", "the", "and", "with", "from",
    "درمان", "خدمات", "صفحه", "خانه", "تماس", "منزل", "تهران", "شمال",
    "جنوب", "شرق", "غرب",
}


def normalize_url(url: str, base: str | None = None) -> str | None:
    try:
        absolute = urllib.parse.urljoin(base or "", url.strip())
        parts = urllib.parse.urlsplit(absolute)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        host = parts.hostname.lower()
        port = parts.port
        netloc = host if not port or (parts.scheme == "http" and port == 80) or (
            parts.scheme == "https" and port == 443
        ) else f"{host}:{port}"
        path = re.sub(r"/{2,}", "/", parts.path or "/")
        return urllib.parse.urlunsplit(
            (parts.scheme.lower(), netloc, path, parts.query, "")
        )
    except (ValueError, UnicodeError):
        return None


def same_site(url: str, root: str) -> bool:
    return urllib.parse.urlsplit(url).hostname == urllib.parse.urlsplit(root).hostname


class PublicURLValidator:
    """Reject local/private targets, including redirect targets."""

    def __init__(self) -> None:
        self._cache: dict[str, bool] = {}

    def validate(self, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Unsupported URL: {url}")
        hostname = parsed.hostname.lower()
        if hostname in {"localhost", "localhost.localdomain"}:
            raise ValueError(f"Private target rejected: {url}")
        if hostname not in self._cache:
            try:
                addresses = {
                    item[4][0] for item in socket.getaddrinfo(hostname, parsed.port or 443)
                }
            except socket.gaierror as exc:
                raise ValueError(f"DNS lookup failed for {hostname}") from exc
            self._cache[hostname] = bool(addresses) and all(
                not (
                    ipaddress.ip_address(address).is_private
                    or ipaddress.ip_address(address).is_loopback
                    or ipaddress.ip_address(address).is_link_local
                    or ipaddress.ip_address(address).is_multicast
                    or ipaddress.ip_address(address).is_reserved
                )
                for address in addresses
            )
        if not self._cache[hostname]:
            raise ValueError(f"Private or unsafe target rejected: {url}")


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, validator: PublicURLValidator) -> None:
        super().__init__()
        self.validator = validator
        self.history: list[tuple[int, str]] = []

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> Any:
        target = urllib.parse.urljoin(req.full_url, newurl)
        self.validator.validate(target)
        self.history.append((code, target))
        return super().redirect_request(req, fp, code, msg, headers, target)


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    content_type: str = ""
    body: bytes = b""
    redirects: list[tuple[int, str]] = field(default_factory=list)
    error: str = ""


class Fetcher:
    def __init__(self, timeout: int, max_bytes: int, retries: int = 1) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.retries = retries
        self.validator = PublicURLValidator()

    def fetch(self, url: str) -> FetchResult:
        result = FetchResult(url, url, 0, error="Request was not attempted")
        for attempt in range(self.retries + 1):
            result = self._fetch_once(url)
            if result.status not in {0, 429, 502, 503, 504}:
                return result
            if attempt < self.retries:
                time.sleep(0.5 * (attempt + 1))
        return result

    def _fetch_once(self, url: str) -> FetchResult:
        try:
            self.validator.validate(url)
            redirects = SafeRedirectHandler(self.validator)
            opener = urllib.request.build_opener(redirects)
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml,text/plain;q=0.8,*/*;q=0.2",
                    "Accept-Encoding": "gzip",
                },
            )
            with opener.open(request, timeout=self.timeout) as response:
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    body = body[: self.max_bytes]
                if response.headers.get("Content-Encoding", "").lower() == "gzip":
                    body = gzip.decompress(body)
                return FetchResult(
                    requested_url=url,
                    final_url=response.geturl(),
                    status=response.status,
                    content_type=response.headers.get_content_type(),
                    body=body,
                    redirects=redirects.history,
                )
        except urllib.error.HTTPError as exc:
            return FetchResult(
                requested_url=url,
                final_url=exc.geturl(),
                status=exc.code,
                content_type=exc.headers.get_content_type() if exc.headers else "",
                redirects=[],
                error=str(exc),
            )
        except Exception as exc:  # Network and parser failures must become report evidence.
            return FetchResult(url, url, 0, error=f"{type(exc).__name__}: {exc}")


def decode_html(body: bytes) -> str:
    prefix = body[:2048].decode("ascii", errors="ignore")
    match = re.search(r"charset=[\"']?\s*([\w.-]+)", prefix, re.I)
    encodings = [match.group(1)] if match else []
    encodings += ["utf-8", "windows-1256", "latin-1"]
    for encoding in encodings:
        try:
            return body.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            pass
    return body.decode("utf-8", errors="replace")


class PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self.h1_parts: list[list[str]] = []
        self.text_parts: list[str] = []
        self.links: set[str] = set()
        self.meta: dict[str, str] = {}
        self.canonical = ""
        self.schema_types: set[str] = set()
        self.lang = ""
        self._in_title = False
        self._h1_depth = 0
        self._ignored_depth = 0
        self._json_ld_depth = 0
        self._json_ld_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "").strip() for key, value in attrs}
        tag = tag.lower()
        if tag == "html":
            self.lang = values.get("lang", "")
        if tag in {"script", "style", "noscript", "svg"}:
            self._ignored_depth += 1
        if tag == "script" and values.get("type", "").lower() == "application/ld+json":
            self._json_ld_depth += 1
            self._json_ld_parts = []
        elif tag == "title":
            self._in_title = True
        elif tag == "h1":
            self._h1_depth += 1
            self.h1_parts.append([])
        elif tag == "a" and values.get("href"):
            target = normalize_url(values["href"], self.base_url)
            if target:
                self.links.add(target)
        elif tag == "meta":
            key = (values.get("name") or values.get("property") or "").lower()
            if key:
                self.meta[key] = values.get("content", "")
        elif tag == "link" and "canonical" in values.get("rel", "").lower().split():
            self.canonical = normalize_url(values.get("href", ""), self.base_url) or ""

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script" and self._json_ld_depth:
            self._extract_schema("".join(self._json_ld_parts))
            self._json_ld_depth -= 1
            self._json_ld_parts = []
        if tag in {"script", "style", "noscript", "svg"} and self._ignored_depth:
            self._ignored_depth -= 1
        elif tag == "title":
            self._in_title = False
        elif tag == "h1" and self._h1_depth:
            self._h1_depth -= 1

    def handle_data(self, data: str) -> None:
        clean = " ".join(data.split())
        if not clean:
            return
        if self._json_ld_depth:
            self._json_ld_parts.append(data)
        if self._in_title:
            self.title_parts.append(clean)
        if self._h1_depth and self.h1_parts:
            self.h1_parts[-1].append(clean)
        if not self._ignored_depth:
            self.text_parts.append(clean)

    def _extract_schema(self, raw: str) -> None:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                schema_type = value.get("@type")
                if isinstance(schema_type, str):
                    self.schema_types.add(schema_type)
                elif isinstance(schema_type, list):
                    self.schema_types.update(str(item) for item in schema_type)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(data)


@dataclass
class Page:
    url: str
    final_url: str
    status: int
    content_type: str
    redirects: list[list[Any]]
    error: str
    title: str = ""
    description: str = ""
    h1: list[str] = field(default_factory=list)
    canonical: str = ""
    robots: str = ""
    lang: str = ""
    word_count: int = 0
    schema_types: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    inlinks: int = 0
    from_sitemap: bool = False


@dataclass
class Issue:
    url: str
    kind: str
    severity: str
    evidence: str
    importance: str
    solution: str
    previous_status: str = "جدید"

    @property
    def key(self) -> str:
        return hashlib.sha256(f"{self.url}|{self.kind}".encode()).hexdigest()[:16]


class SiteCrawler:
    def __init__(self, root: str, config: dict[str, Any], fetcher: Fetcher) -> None:
        normalized = normalize_url(root)
        if not normalized:
            raise ValueError(f"Invalid site URL: {root}")
        self.root = normalized
        self.config = config
        self.fetcher = fetcher
        self.max_pages = int(config.get("max_pages_per_site", 30))
        self.delay = float(config.get("request_delay_seconds", 0.25))
        self.pages: dict[str, Page] = {}
        self.sitemap_urls: set[str] = set()
        self.blocked_urls: set[str] = set()
        self.robots_url = urllib.parse.urljoin(self.root, "/robots.txt")
        self.robots_status = 0
        self.robots_error = ""
        self.sitemap_sources: list[str] = []
        self.robot_parser = urllib.robotparser.RobotFileParser()

    def crawl(self) -> dict[str, Any]:
        self._load_robots()
        self._load_sitemaps()
        queue = deque([self.root])
        queue.extend(sorted(self.sitemap_urls)[: self.max_pages])
        queued = set(queue)
        while queue and len(self.pages) < self.max_pages:
            url = queue.popleft()
            if url in self.pages or not same_site(url, self.root):
                continue
            if not self.robot_parser.can_fetch(USER_AGENT, url):
                self.blocked_urls.add(url)
                continue
            page = self._crawl_page(url)
            self.pages[url] = page
            for link in page.links:
                if same_site(link, self.root) and link not in queued:
                    queued.add(link)
                    queue.append(link)
            if self.delay:
                time.sleep(self.delay)
        self._set_inlinks()
        return {
            "root": self.root,
            "robots": {
                "url": self.robots_url,
                "status": self.robots_status,
                "error": self.robots_error,
            },
            "sitemaps": self.sitemap_sources,
            "sitemap_url_count": len(self.sitemap_urls),
            "blocked_urls": sorted(self.blocked_urls),
            "discovered_url_count": len(queued),
            "crawl_limit": self.max_pages,
            "pages": [asdict(page) for page in self.pages.values()],
        }

    def _load_robots(self) -> None:
        result = self.fetcher.fetch(self.robots_url)
        self.robots_status = result.status
        self.robots_error = result.error
        lines = decode_html(result.body).splitlines() if result.status == 200 else []
        self.robot_parser.set_url(self.robots_url)
        self.robot_parser.parse(lines)
        for line in lines:
            if line.lower().startswith("sitemap:"):
                candidate = normalize_url(line.split(":", 1)[1].strip(), self.root)
                if candidate:
                    self.sitemap_sources.append(candidate)

    def _load_sitemaps(self) -> None:
        if not self.sitemap_sources:
            self.sitemap_sources.append(urllib.parse.urljoin(self.root, "/sitemap.xml"))
        queue = deque(self.sitemap_sources[:10])
        seen: set[str] = set()
        while queue and len(seen) < 10 and len(self.sitemap_urls) < self.max_pages * 10:
            sitemap = queue.popleft()
            if sitemap in seen:
                continue
            seen.add(sitemap)
            result = self.fetcher.fetch(sitemap)
            if result.status != 200 or not result.body:
                continue
            body = result.body
            if sitemap.endswith(".gz"):
                try:
                    body = gzip.decompress(body)
                except gzip.BadGzipFile:
                    continue
            try:
                root = ET.fromstring(body)
            except ET.ParseError:
                continue
            locations = [
                (node.text or "").strip()
                for node in root.iter()
                if node.tag.rsplit("}", 1)[-1].lower() == "loc"
            ]
            if root.tag.rsplit("}", 1)[-1].lower() == "sitemapindex":
                queue.extend(filter(None, (normalize_url(url, self.root) for url in locations)))
            else:
                self.sitemap_urls.update(
                    url for url in (normalize_url(item, self.root) for item in locations)
                    if url and same_site(url, self.root)
                )
        self.sitemap_sources = sorted(seen)

    def _crawl_page(self, url: str) -> Page:
        result = self.fetcher.fetch(url)
        page = Page(
            url=url,
            final_url=result.final_url,
            status=result.status,
            content_type=result.content_type,
            redirects=[[code, target] for code, target in result.redirects],
            error=result.error,
            from_sitemap=url in self.sitemap_urls,
        )
        if result.status == 200 and result.content_type in HTML_TYPES:
            parser = PageParser(result.final_url)
            try:
                parser.feed(decode_html(result.body))
            except Exception as exc:
                page.error = f"HTML parse error: {exc}"
            page.title = " ".join(parser.title_parts).strip()
            page.description = parser.meta.get("description", "").strip()
            page.h1 = [" ".join(parts).strip() for parts in parser.h1_parts if parts]
            page.canonical = parser.canonical
            page.robots = parser.meta.get("robots", "").lower()
            page.lang = parser.lang
            page.word_count = len(WORD_RE.findall(" ".join(parser.text_parts)))
            page.schema_types = sorted(parser.schema_types)
            page.links = sorted(parser.links)
        return page

    def _set_inlinks(self) -> None:
        counts: Counter[str] = Counter()
        for page in self.pages.values():
            counts.update(link for link in page.links if same_site(link, self.root))
        for url, page in self.pages.items():
            page.inlinks = counts[url]


def issue_for_sites(sites: list[dict[str, Any]], thin_words: int) -> list[Issue]:
    issues: list[Issue] = []
    for site in sites:
        root = site["root"]
        robots = site["robots"]
        if robots["status"] != 200:
            issues.append(Issue(
                robots["url"], "robots.txt در دسترس نیست", "زیاد",
                f"HTTP {robots['status'] or 'network error'}؛ {robots['error']}",
                "قواعد Crawl و محل Sitemap ممکن است برای موتور جستجو نامشخص باشد.",
                "فایل robots.txt معتبر با پاسخ 200 ارائه و Sitemap در آن معرفی شود.",
            ))
        if not site["sitemaps"] or site["sitemap_url_count"] == 0:
            issues.append(Issue(
                root, "Sitemap معتبر پیدا نشد", "زیاد",
                "هیچ URL قابل استخراج از Sitemapهای بررسی‌شده وجود نداشت.",
                "کشف و پایش صفحات مهم دشوارتر می‌شود.",
                "XML Sitemap معتبر بسازید، در robots.txt معرفی و در Search Console ثبت کنید.",
            ))
        pages = site["pages"]
        page_by_url = {page["url"]: page for page in pages}
        for page in pages:
            url = page["url"]
            status = page["status"]
            if status == 0:
                issues.append(Issue(
                    url, "امکان بررسی صفحه وجود نداشت", "متوسط",
                    page["error"] or "پاسخ HTTP دریافت نشد.",
                    "این نتیجه خطای قطعی سایت نیست و وضعیت فنی صفحه نامشخص مانده است.",
                    "صفحه از شبکه یا زمان دیگری دوباره بررسی شود؛ فقط در صورت تکرار، DNS، TLS و لاگ سرور بررسی شود.",
                ))
                continue
            if status >= 500:
                issues.append(Issue(
                    url, "خطای سرور", "بحرانی",
                    f"پاسخ قطعی HTTP {status}", "صفحه برای کاربر و خزنده قابل دریافت نیست.",
                    "لاگ سرور و پاسخ endpoint بررسی و خطای 5xx رفع شود.",
                ))
                continue
            if status >= 400:
                issues.append(Issue(
                    url, f"خطای HTTP {status}", "زیاد", f"پاسخ نهایی HTTP {status}",
                    "لینک یا صفحه خطادار Crawl budget و تجربه کاربر را تضعیف می‌کند.",
                    "صفحه را بازیابی یا لینک‌های ورودی را به نزدیک‌ترین مقصد معتبر اصلاح کنید.",
                ))
                continue
            if len(page["redirects"]) > 1:
                issues.append(Issue(
                    url, "زنجیره ریدایرکت", "متوسط",
                    " → ".join(f"{item[0]} {item[1]}" for item in page["redirects"]),
                    "زنجیره ریدایرکت زمان پاسخ و اتلاف Crawl را افزایش می‌دهد.",
                    "لینک‌ها را مستقیماً به URL نهایی و ریدایرکت را تک‌مرحله‌ای کنید.",
                ))
            if page["content_type"] not in HTML_TYPES:
                continue
            if not page["title"]:
                issues.append(Issue(
                    url, "Title ناموجود", "زیاد", "تگ title خالی یا ناموجود است.",
                    "عنوان یکی از سیگنال‌های اصلی موضوع و نمایش نتیجه جستجو است.",
                    "عنوان یکتا، دقیق و متناسب با هدف صفحه اضافه کنید.",
                ))
            elif len(page["title"]) < 20 or len(page["title"]) > 65:
                issues.append(Issue(
                    url, "طول نامناسب Title", "متوسط", f"{len(page['title'])} نویسه",
                    "عنوان بسیار کوتاه یا بلند ممکن است موضوع را ناقص منتقل یا بریده نمایش داده شود.",
                    "عنوان را با حفظ طبیعی‌بودن و تطابق با محتوا بازنویسی کنید.",
                ))
            if not page["description"]:
                issues.append(Issue(
                    url, "Meta Description ناموجود", "متوسط", "متای description یافت نشد.",
                    "توضیح مناسب می‌تواند کیفیت snippet و نرخ کلیک را بهتر کند.",
                    "توضیح یکتا و متناسب با هدف جستجو اضافه کنید.",
                ))
            if len(page["h1"]) != 1:
                issues.append(Issue(
                    url, "تعداد نامناسب H1", "متوسط", f"{len(page['h1'])} تگ H1 یافت شد.",
                    "ساختار عنوان اصلی صفحه برای کاربر و خزنده مبهم می‌شود.",
                    "یک H1 روشن و منطبق با موضوع اصلی صفحه نگه دارید.",
                ))
            if not page["canonical"]:
                issues.append(Issue(
                    url, "Canonical ناموجود", "متوسط", "تگ canonical یافت نشد.",
                    "نسخه ترجیحی URL صریحاً مشخص نشده است.",
                    "Canonical خودارجاعی معتبر برای صفحه ایندکس‌پذیر اضافه کنید.",
                ))
            elif page["canonical"] not in page_by_url and not same_site(page["canonical"], root):
                issues.append(Issue(
                    url, "Canonical برون‌دامنه‌ای", "زیاد", page["canonical"],
                    "ممکن است اعتبار و ایندکس صفحه به دامنه دیگری منتقل شود.",
                    "درستی مقصد را بررسی و در صورت خطا به نسخه اصلی همان صفحه اصلاح کنید.",
                ))
            if "noindex" in page["robots"]:
                issues.append(Issue(
                    url, "صفحه Noindex", "متوسط", page["robots"],
                    "صفحه از ایندکس موتور جستجو حذف می‌شود.",
                    "اگر صفحه باید رتبه بگیرد، noindex را حذف کنید؛ در غیر این صورت آن را مستند نگه دارید.",
                ))
            if page["word_count"] < thin_words:
                issues.append(Issue(
                    url, "محتوای کم‌حجم", "متوسط", f"{page['word_count']} واژه قابل مشاهده",
                    "ممکن است پاسخ صفحه برای هدف جستجو ناکافی باشد؛ حجم به‌تنهایی معیار کیفیت نیست.",
                    "هدف جستجو را بررسی و فقط اطلاعات مفید، پزشکی معتبر و غیرتکراری اضافه کنید.",
                ))
            if not page["schema_types"]:
                issues.append(Issue(
                    url, "Schema شناسایی نشد", "کم", "JSON-LD دارای @type یافت نشد.",
                    "داده ساختاریافته می‌تواند درک موجودیت و خدمت را بهتر کند.",
                    "Schema متناسب و منطبق با محتوای قابل مشاهده اضافه و اعتبارسنجی کنید.",
                ))
            if page["from_sitemap"] and page["inlinks"] == 0 and url != root:
                issues.append(Issue(
                    url, "صفحه یتیم احتمالی", "زیاد",
                    "در Sitemap وجود دارد اما در Crawl محدود هیچ لینک داخلی ورودی یافت نشد.",
                    "صفحه بدون مسیر داخلی مناسب سخت‌تر کشف و کم‌اعتبارتر می‌شود.",
                    "پس از Crawl کامل، از صفحات مرتبط لینک طبیعی به این صفحه اضافه کنید.",
                ))
        for field_name, label in (("title", "Title تکراری"), ("description", "Description تکراری")):
            groups: defaultdict[str, list[str]] = defaultdict(list)
            for page in pages:
                value = page[field_name].strip()
                if value:
                    groups[value].append(page["url"])
            for value, urls in groups.items():
                if len(urls) > 1:
                    for url in urls:
                        issues.append(Issue(
                            url, label, "متوسط",
                            f"مقدار مشترک در {len(urls)} صفحه: {value[:120]}",
                            "متادیتای تکراری تمایز صفحات را کاهش می‌دهد.",
                            "هدف هر صفحه را مشخص و مقدار یکتای دقیق بنویسید.",
                        ))
    return issues


def mark_history(issues: list[Issue], previous: dict[str, Any] | None) -> list[dict[str, str]]:
    old = {item["key"]: item for item in (previous or {}).get("issues", [])}
    current_keys = {issue.key for issue in issues}
    for issue in issues:
        issue.previous_status = "هنوز رفع نشده" if issue.key in old else "جدید"
    return [
        {"key": key, "url": item["url"], "kind": item["kind"], "status": "رفع شده"}
        for key, item in old.items() if key not in current_keys
    ]


def tokens(text: str) -> set[str]:
    return {word.lower() for word in WORD_RE.findall(text) if word.lower() not in GENERIC_WORDS}


def internal_link_suggestions(site: dict[str, Any], limit: int = 10) -> list[dict[str, str]]:
    pages = [page for page in site["pages"] if page["status"] == 200 and page["title"]]
    results: list[dict[str, str]] = []
    for target in sorted(pages, key=lambda item: item["inlinks"]):
        target_tokens = tokens(" ".join([target["title"], *target["h1"]]))
        candidates: list[tuple[int, dict[str, Any]]] = []
        for source in pages:
            if source["url"] == target["url"] or target["url"] in source["links"]:
                continue
            score = len(target_tokens & tokens(" ".join([source["title"], *source["h1"]])))
            if score:
                candidates.append((score, source))
        if candidates:
            source = max(candidates, key=lambda item: item[0])[1]
            results.append({
                "source": source["url"],
                "target": target["url"],
                "anchor": target["h1"][0] if target["h1"] else target["title"],
                "reason": "هم‌پوشانی موضوعی عنوان‌ها؛ محل دقیق باید با بازبینی متن تعیین شود.",
                "priority": "زیاد" if target["inlinks"] == 0 else "متوسط",
            })
        if len(results) >= limit:
            break
    return results


def markdown_report(data: dict[str, Any]) -> str:
    issues = data["issues"]
    severity_counts = Counter(item["severity"] for item in issues)
    competitor_status = (
        f"{len(data.get('competitors', []))} دامنه بررسی شد"
        if data.get("competitors")
        else "اجرا نشد؛ URL رقیب ثبت نشده یا امروز روز بررسی هفتگی نیست"
    )
    lines = [
        '<div dir="rtl" align="right">',
        f"<h1>گزارش SEO آنا درمان — {data['report_date']}</h1>",
        f"<p><strong>زمان گزارش:</strong> {data['generated_at_tehran']}<br>",
        "<strong>ابزار:</strong> خزنده داخلی بدون API پولی</p>",
        "</div>",
        "",
        "## ۱. خلاصه مدیریتی",
        "",
        "| شاخص | نتیجه |",
        "|---|---:|",
        f"| صفحات بررسی‌شده | {len(data['primary_site']['pages'])} |",
        f"| مشکلات بحرانی | {severity_counts['بحرانی']} |",
        f"| مشکلات با اولویت زیاد | {severity_counts['زیاد']} |",
        f"| مشکلات با اولویت متوسط | {severity_counts['متوسط']} |",
        f"| مشکلات با اولویت کم | {severity_counts['کم']} |",
        f"| وضعیت بررسی رقبا | {competitor_status} |",
        "",
        "## ۲. دامنه بررسی و محدودیت داده‌ها",
        "",
        "- گزارش فنی بر اساس پاسخ HTTP و HTML دریافت‌شده در همین اجرا است.",
        "- رتبه واقعی گوگل، حجم جستجو، ترافیک، Authority و دیتابیس بک‌لینک بدون منبع داده خارجی در دسترس نیست.",
        "- PageSpeed/Core Web Vitals و سازگاری واقعی دستگاه‌ها در این خزنده اندازه‌گیری نمی‌شود.",
        f"- سقف Crawl هر دامنه {data['config']['max_pages_per_site']} صفحه است؛ نتیجه، Crawl کامل سایت محسوب نمی‌شود.",
        "",
        "## ۳. وضعیت مشکلات گزارش قبل",
        "",
    ]
    if data["resolved"]:
        lines += ["| URL | مشکل | وضعیت |", "|---|---|---|"]
        lines += [
            f"| {item['url']} | {item['kind']} | رفع شده در Crawl فعلی |"
            for item in data["resolved"]
        ]
    else:
        lines.append("مورد رفع‌شده قابل تأییدی وجود نداشت یا گزارش قبلی موجود نبود.")
    lines += ["", "## ۴. مشکلات بحرانی امروز", ""]
    critical = [item for item in issues if item["severity"] == "بحرانی"]
    lines += (
        [f"- **{item['url']}** — {item['kind']}: {item['evidence']}" for item in critical]
        or ["مشکل بحرانی در دامنه Crawl‌شده مشاهده نشد."]
    )
    lines += [
        "",
        "## ۵. مشکلات SEO تکنیکال",
        "",
        "| شدت | URL | مشکل | شواهد | اهمیت | راه‌حل | نسبت به قبل |",
        "|---|---|---|---|---|---|---|",
    ]
    order = {"بحرانی": 0, "زیاد": 1, "متوسط": 2, "کم": 3}
    for item in sorted(issues, key=lambda value: (order[value["severity"]], value["url"])):
        escaped = {key: str(value).replace("|", "¦").replace("\n", " ") for key, value in item.items()}
        lines.append(
            f"| {escaped['severity']} | {escaped['url']} | {escaped['kind']} | "
            f"{escaped['evidence']} | {escaped['importance']} | {escaped['solution']} | "
            f"{escaped['previous_status']} |"
        )
    lines += ["", "## ۶. پیشنهادهای لینک‌سازی داخلی", ""]
    suggestions = data["internal_link_suggestions"]
    if suggestions:
        lines += [
            "| اولویت | صفحه مبدأ | صفحه مقصد | انکرتکست پیشنهادی | دلیل |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| {item['priority']} | {item['source']} | {item['target']} | "
            f"{item['anchor']} | {item['reason']} |" for item in suggestions
        ]
    else:
        lines.append("در Crawl محدود فعلی پیشنهاد قابل اتکایی استخراج نشد.")
    lines += [
        "",
        "## ۷. کلمات کلیدی صفحات خدمات",
        "",
        "داده رتبه، حجم جستجو و کلمات کلیدی واقعی بدون اتصال به Search Console یا ارائه‌دهنده داده در دسترس نیست. "
        "برای جلوگیری از حدس، این بخش عدد یا رتبه ساختگی ندارد.",
        "",
        "## ۸. شکاف‌های محتوایی",
        "",
        "عنوان صفحات رقیب برای بازبینی انسانی در بخش رقبا آمده است. تشخیص شکاف نیازمند تأیید هدف جستجو و داده کلمه کلیدی است.",
        "",
        "## ۹. تغییرات رقبا",
        "",
    ]
    competitors = data.get("competitors", [])
    if competitors:
        for site in competitors:
            lines.append(f"### {site['root']}")
            lines.append("")
            lines.append(f"- صفحات بررسی‌شده: {len(site['pages'])}")
            for page in site["pages"][:15]:
                if page["title"]:
                    lines.append(f"- [{page['title']}]({page['url']})")
            lines.append("")
    else:
        lines.append(
            "بررسی هفتگی رقبا فقط دوشنبه‌ها انجام می‌شود، یا URL رقیبی در تنظیمات ثبت نشده است."
        )
    lines += [
        "",
        "## ۱۰. فرصت‌های بک‌لینک",
        "",
        "بدون دیتابیس بک‌لینک معتبر، فرصت مشخصی گزارش نشد. Crawl عمومی وب جایگزین معتبری برای دیتابیس بک‌لینک نیست.",
        "",
        "## ۱۱. برنامه پیشنهادی رپورتاژ",
        "",
        "تا زمان تأیید آمادگی فنی و محتوایی صفحه مقصد و دسترسی به داده معتبر رقبا/بک‌لینک، انتشار رپورتاژ توصیه نمی‌شود.",
        "",
        "## ۱۲. اقدامات پیشنهادی به‌ترتیب اولویت",
        "",
    ]
    for index, item in enumerate(
        sorted(issues, key=lambda value: order[value["severity"]])[:15], start=1
    ):
        lines.append(
            f"{index}. **{item['severity']} — {item['url']}**: {item['solution']} "
            f"نتیجه مورد انتظار: رفع «{item['kind']}» پس از بررسی مجدد."
        )
    lines += [
        "",
        "## ۱۳. URLها و منابع بررسی‌شده",
        "",
    ]
    for site in [data["primary_site"], *competitors]:
        lines.append(f"### {site['root']}")
        lines.append("")
        lines += [f"- {page['url']} — HTTP {page['status']}" for page in site["pages"]]
        lines.append("")
    lines.append("")
    return "\n".join(lines)


def load_config(path: Path) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if not config.get("site_url"):
        raise ValueError("site_url is required")
    config.setdefault("competitor_urls", [])
    config.setdefault("timezone", "Asia/Tehran")
    config.setdefault("max_pages_per_site", 30)
    config.setdefault("request_delay_seconds", 0.25)
    config.setdefault("timeout_seconds", 15)
    config.setdefault("network_retries", 1)
    config.setdefault("max_response_bytes", 2_000_000)
    config.setdefault("thin_content_words", 250)
    config.setdefault("competitor_weekday", 0)
    return config


def run(config_path: Path, output_dir: Path, force_competitors: bool = False) -> dict[str, Any]:
    config = load_config(config_path)
    now = datetime.now(ZoneInfo(config["timezone"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    state_path = output_dir / ".seo-state.json"
    legacy_state_path = output_dir / "latest-data.json"
    previous = None
    previous_path = state_path if state_path.exists() else legacy_state_path
    if previous_path.exists():
        try:
            previous = json.loads(previous_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous = None
    fetcher = Fetcher(
        config["timeout_seconds"],
        config["max_response_bytes"],
        int(config["network_retries"]),
    )
    primary = SiteCrawler(config["site_url"], config, fetcher).crawl()
    competitors: list[dict[str, Any]] = []
    if force_competitors or now.weekday() == int(config["competitor_weekday"]):
        for competitor in config["competitor_urls"]:
            competitors.append(SiteCrawler(competitor, config, fetcher).crawl())
    issues = issue_for_sites([primary], int(config["thin_content_words"]))
    resolved = mark_history(issues, previous)
    data = {
        "report_date": now.strftime("%Y-%m-%d"),
        "generated_at_tehran": now.isoformat(timespec="seconds"),
        "config": config,
        "primary_site": primary,
        "competitors": competitors,
        "issues": [{**asdict(issue), "key": issue.key} for issue in issues],
        "resolved": resolved,
        "internal_link_suggestions": internal_link_suggestions(primary),
    }
    report = markdown_report(data)
    dated_report = output_dir / f"{data['report_date']}.md"
    state = {
        "report_date": data["report_date"],
        "issues": [
            {"key": item["key"], "url": item["url"], "kind": item["kind"]}
            for item in data["issues"]
        ],
    }
    state_path.write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    for legacy_path in output_dir.glob("*-data.json"):
        legacy_path.unlink()
    legacy_state_path.unlink(missing_ok=True)
    dated_report.write_text(report, encoding="utf-8")
    (output_dir / "latest.md").write_text(report, encoding="utf-8")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("seo-audit.config.json"))
    parser.add_argument("--output", type=Path, default=Path("seo-reports"))
    parser.add_argument(
        "--include-competitors", action="store_true",
        help="Crawl competitors even when today is not the configured weekly day.",
    )
    args = parser.parse_args()
    try:
        data = run(args.config, args.output, args.include_competitors)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"SEO audit failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Wrote SEO report for {data['report_date']}: "
        f"{len(data['primary_site']['pages'])} pages, {len(data['issues'])} issues"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
