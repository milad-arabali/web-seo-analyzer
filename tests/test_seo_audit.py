import unittest

from seo_audit import (
    PageParser,
    internal_link_suggestions,
    issue_for_sites,
    markdown_report,
    normalize_url,
)


class SEOAuditTests(unittest.TestCase):
    def test_normalize_url_removes_fragment_and_default_port(self):
        self.assertEqual(
            normalize_url("../service/#part", "https://Example.com:443/blog/post"),
            "https://example.com/service/",
        )

    def test_parser_extracts_on_page_signals(self):
        parser = PageParser("https://example.com/page")
        parser.feed(
            """
            <html lang="fa"><head>
              <title>عنوان خدمت</title>
              <meta name="description" content="توضیح صفحه">
              <link rel="canonical" href="/page">
              <script type="application/ld+json">
                {"@context":"https://schema.org","@type":"MedicalWebPage"}
              </script>
            </head><body>
              <h1>خدمت در منزل</h1>
              <a href="/contact#form">تماس</a>
              <p>متن قابل مشاهده صفحه</p>
            </body></html>
            """
        )
        self.assertEqual(" ".join(parser.title_parts), "عنوان خدمت")
        self.assertEqual(parser.meta["description"], "توضیح صفحه")
        self.assertEqual(parser.canonical, "https://example.com/page")
        self.assertEqual(parser.h1_parts, [["خدمت در منزل"]])
        self.assertIn("MedicalWebPage", parser.schema_types)
        self.assertIn("https://example.com/contact", parser.links)

    def test_issue_detection_is_evidence_based(self):
        site = {
            "root": "https://example.com/",
            "robots": {
                "url": "https://example.com/robots.txt",
                "status": 200,
                "error": "",
            },
            "sitemaps": ["https://example.com/sitemap.xml"],
            "sitemap_url_count": 1,
            "pages": [
                {
                    "url": "https://example.com/",
                    "final_url": "https://example.com/",
                    "status": 200,
                    "content_type": "text/html",
                    "redirects": [],
                    "error": "",
                    "title": "",
                    "description": "",
                    "h1": [],
                    "canonical": "",
                    "robots": "",
                    "lang": "fa",
                    "word_count": 20,
                    "schema_types": [],
                    "links": [],
                    "inlinks": 0,
                    "from_sitemap": True,
                }
            ],
        }
        kinds = {issue.kind for issue in issue_for_sites([site], 250)}
        self.assertIn("Title ناموجود", kinds)
        self.assertIn("Meta Description ناموجود", kinds)
        self.assertIn("تعداد نامناسب H1", kinds)
        self.assertIn("محتوای کم‌حجم", kinds)

    def test_network_failure_is_not_claimed_as_server_error(self):
        site = {
            "root": "https://example.com/",
            "robots": {
                "url": "https://example.com/robots.txt",
                "status": 200,
                "error": "",
            },
            "sitemaps": ["https://example.com/sitemap.xml"],
            "sitemap_url_count": 1,
            "pages": [{
                "url": "https://example.com/timeout",
                "status": 0,
                "error": "TimeoutError",
            }],
        }
        issues = issue_for_sites([site], 250)
        self.assertEqual(issues[0].kind, "امکان بررسی صفحه وجود نداشت")
        self.assertEqual(issues[0].severity, "متوسط")

    def test_internal_link_suggestion_requires_topic_overlap(self):
        site = {
            "pages": [
                {
                    "url": "https://example.com/nurse",
                    "status": 200,
                    "title": "پرستار سالمند در منزل",
                    "h1": ["پرستاری سالمند"],
                    "inlinks": 2,
                    "links": [],
                },
                {
                    "url": "https://example.com/elderly-care",
                    "status": 200,
                    "title": "مراقبت سالمند در منزل",
                    "h1": ["مراقبت از سالمند"],
                    "inlinks": 0,
                    "links": [],
                },
            ]
        }
        suggestions = internal_link_suggestions(site)
        self.assertTrue(suggestions)
        self.assertEqual(
            suggestions[0]["target"], "https://example.com/elderly-care"
        )


if __name__ == "__main__":
    unittest.main()
