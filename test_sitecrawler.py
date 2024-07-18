import json
import time
import unittest

from sitecrawler import SiteCrawler, ExtractionRules, do_extract


class TestSiteCrawler(unittest.TestCase):

    def test_valid_link_domains(self):
        crawler = SiteCrawler(name="testing", starting_urls=["https://www.example.com"], allow_starting_url_tld=True,
                              allow_starting_url_hostname=True)
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://www.example.com"))
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://www.example.com/index.html"))
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://www.example.com/foo/index.html"))
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://example.com/index.html"))
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://foo.example.com/index.html"))
        self.assertTrue(crawler.valid_link("https://www.example.com", "http://foo.example.com/index.html"))

        self.assertFalse(crawler.valid_link("https://www.example.com", "https://google.com/index.html"))

        crawler = SiteCrawler(name="testing", starting_urls=["https://www.example.com"],
                              allow_starting_url_tld=False,
                              allow_starting_url_hostname=True)
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://www.example.com/index.html"))
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://example.com/index.html"))
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://foo.example.com/index.html"))
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://google.com/index.html"))

        crawler = SiteCrawler(name="testing", starting_urls=["https://www.example.com"],
                              allow_starting_url_tld=True,
                              allow_starting_url_hostname=False)
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://www.example.com/index.html"))
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://example.com/index.html"))
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://foo.example.com/index.html"))
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://google.com/index.html"))

        crawler = SiteCrawler(name="testing", starting_urls=["https://www.example.com"],
                              allowed_domains=["foo.example.com"],
                              allow_starting_url_tld=False,
                              allow_starting_url_hostname=False)
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://www.example.com/index.html"))
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://example.com/index.html"))
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://foo.example.com/index.html"))
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://google.com/index.html"))

    def test_valid_link_includes_excludes(self):
        crawler = SiteCrawler(name="testing", starting_urls=["https://www.example.com"],
                              allowed_regex=[".html$"],
                              denied_regex=[".css$"],
                              )
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://www.example.com/index.html"))
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://www.example.com/index.css"))

        # test default behavior
        self.assertTrue(crawler.valid_link("https://www.example.com", "https://www.example.com/index.htmlsss"))
        crawler.config.allow_urls_by_default = False
        self.assertFalse(crawler.valid_link("https://www.example.com", "https://www.example.com/index.htmlsss"))

    def test_extract_css(self):
        content = "<html><title>foo</title></html>"
        rules = ExtractionRules.model_validate_json(
            json.dumps({"rules": [{"field_name": "title", "css": "title"}, {"field_name": "desc", "css": "bar"}]}))
        self.assertEqual("foo", do_extract(content, rules)["title"])
        self.assertEqual("", do_extract(content, rules)["desc"])

        content = "<html><title>foo</title><title>bar</title></html>"
        rules = ExtractionRules.model_validate_json(
            json.dumps({"rules": [{"field_name": "title", "css": "title"}, {"field_name": "desc", "css": "bar"}]}))
        self.assertEqual(["foo", "bar"], do_extract(content, rules)["title"])

    def test_extract_regex(self):
        content = "<html><title>foo</title><animal>cat</animal></html>"
        rules = ExtractionRules.model_validate_json(
            json.dumps({"rules": [{"field_name": "title", "regex": "<animal>(.*?)</animal>"}]}))
        self.assertEqual("cat", do_extract(content, rules)["title"])

        rules = ExtractionRules.model_validate_json(
            json.dumps({"rules": [{"field_name": "title", "regex": "<animals>(.*?)</animals>"}]}))
        self.assertEqual("", do_extract(content, rules)["title"])

    def test_cache_expiry(self):
        crawler = SiteCrawler(name="testing", starting_urls=[], cache_ttl_hours=-1, init_collection=False)
        crawler.collection = {"foo": {"type": "content"}}
        self.assertTrue(crawler.is_cached_url("foo"))

        crawler = SiteCrawler(name="testing", starting_urls=[], cache_ttl_hours=0.5, init_collection=False)
        crawler.collection = {"foo": {"type": "content", "crawled": time.time() - 3600}}
        self.assertFalse(crawler.is_cached_url("foo"))


if __name__ == '__main__':
    unittest.main()
