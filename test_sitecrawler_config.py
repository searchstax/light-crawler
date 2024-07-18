import unittest

from sitecrawler import SiteCrawlerConfig, ExtractionRules, SiteCrawler


class TestSiteCrawlerConfig(unittest.TestCase):
    def setUp(self):
        self.config_dict = {
            "name": "custom_test",
            "starting_urls": ["http://example.com"],
            "sitemap_file": None,
            "allowed_domains": ["example.com"],
            "allowed_regex": [".*example.*"],
            "denied_regex": [".*denied.*"],
            "denied_extensions": [".pdf", ".jpg"],
            "is_sitemap": False,
            "is_sitemap_direct": False,
            "if_modified_since_hours": 24,
            "cache_ttl_hours": 48,
            "allow_starting_url_hostname": False,
            "allow_starting_url_tld": True,
            "content_css_selector": "div.content",
            "extraction_rules": {"rules": [{"field_name": "title", "css": "h1"}]},
            "user_agent": "CustomBot/1.0",
            "data_dir": "/custom/data",
            "init_collection": False,
            "debug_html": True
        }

    def test_initialization_with_config_object(self):
        config = SiteCrawlerConfig(**self.config_dict)
        crawler = SiteCrawler(config)
        self._assert_crawler_config(crawler)

    def test_initialization_with_kwargs(self):
        crawler = SiteCrawler(**self.config_dict)
        self._assert_crawler_config(crawler)

    def _assert_crawler_config(self, crawler):
        config = crawler.config
        self.assertEqual(config.name, "custom_test")
        self.assertEqual(config.starting_urls, ["http://example.com"], msg="Different starting_urls")
        self.assertEqual(config.sitemap_file, None)
        self.assertEqual(config.allowed_domains, ["example.com"], msg="Different allowed_domains")
        self.assertEqual(config.allowed_regex, [".*example.*"])
        self.assertIn(".*denied.*", config.denied_regex)
        self.assertEqual(config.denied_extensions, [".pdf", ".jpg"])
        self.assertFalse(config.is_sitemap)
        self.assertFalse(config.is_sitemap_direct)
        self.assertEqual(config.if_modified_since_hours, 24)
        self.assertEqual(config.cache_ttl_hours, 48)
        self.assertFalse(config.allow_starting_url_hostname)
        self.assertTrue(config.allow_starting_url_tld)
        self.assertEqual(config.content_css_selector, "div.content")
        self.assertIsInstance(config.extraction_rules, ExtractionRules)
        self.assertEqual(config.extraction_rules.rules[0].field_name, "title")
        self.assertEqual(config.extraction_rules.rules[0].css, "h1")
        self.assertEqual(config.user_agent, "CustomBot/1.0")
        self.assertEqual(config.data_dir, "/custom/data")
        self.assertFalse(config.init_collection)
        self.assertTrue(config.debug_html)

    def test_string_to_list_conversion(self):
        config = SiteCrawlerConfig(
            name="test",
            starting_urls="http://example.com",
            allowed_domains=["example.com"],
            allowed_regex=[".*example.*"],
            denied_regex=[".*denied.*"],
            denied_extensions=[".pdf", ".jpg"]
        )
        self.assertEqual(config.starting_urls, ["http://example.com"])
        self.assertEqual(config.allowed_domains, ["example.com"])
        self.assertEqual(config.allowed_regex, [".*example.*"])
        # self.assertEqual(config.denied_regex, [".*denied.*"] + list(global_excludes))
        self.assertEqual(config.denied_extensions, [".pdf", ".jpg"])

    def test_extraction_rules_processing(self):
        # Test with string
        config1 = SiteCrawlerConfig(
            name="test1",
            starting_urls=["http://example.com"],
            extraction_rules='{"rules": [{"field_name": "title", "css": "h1"}]}'
        )
        self.assertIsInstance(config1.extraction_rules, ExtractionRules)
        self.assertEqual(config1.extraction_rules.rules[0].field_name, "title")

        # Test with dict
        config2 = SiteCrawlerConfig(
            name="test2",
            starting_urls=["http://example.com"],
            extraction_rules={"rules": [{"field_name": "description", "css": "meta[name='description']"}]}
        )
        self.assertIsInstance(config2.extraction_rules, ExtractionRules)
        self.assertEqual(config2.extraction_rules.rules[0].field_name, "description")

    def test_headers_processing(self):
        config = SiteCrawlerConfig(
            name="test",
            starting_urls=["http://example.com"],
            headers={"Custom-Header": "Value"}
        )
        self.assertEqual(config.headers["Custom-Header"], "Value")
        self.assertEqual(config.headers["User-Agent"], "SiteCrawler/1.0")

        config_custom_ua = SiteCrawlerConfig(
            name="test",
            starting_urls=["http://example.com"],
            headers={"User-Agent": "CustomBot/1.0"}
        )
        self.assertEqual(config_custom_ua.headers["User-Agent"], "CustomBot/1.0")


if __name__ == '__main__':
    unittest.main()
