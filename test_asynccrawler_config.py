import unittest

from pydantic import ValidationError

from asynccrawler import AsyncCrawlerConfig


class TestAsyncCrawlerConfig(unittest.TestCase):

    def test_custom_initialization(self):
        config = AsyncCrawlerConfig(
            starting_urls=["http://example.com", "http://example.org"],
            max_depth=5,
            max_pages=100,
            concurrency=20,
            max_retries=3,
            headers={"User-Agent": "TestBot"},
            proxy_username="user",
            proxy_password="pass",
            proxy_url="http://proxy.com",
            proxy_post_data="data",
            proxy_response_to_html={"key": "value"},
            proxy_base64_decode=True,
            timeout=15,
            max_redirects=5
        )
        self.assertEqual(config.starting_urls, ["http://example.com", "http://example.org"])
        self.assertEqual(config.max_depth, 5)
        self.assertEqual(config.max_pages, 100)
        self.assertEqual(config.concurrency, 20)
        self.assertEqual(config.max_retries, 3)
        self.assertEqual(config.headers, {"User-Agent": "TestBot"})
        self.assertEqual(config.proxy_username, "user")
        self.assertEqual(config.proxy_password, "pass")
        self.assertEqual(config.proxy_url, "http://proxy.com")
        self.assertEqual(config.proxy_post_data, "data")
        self.assertEqual(config.proxy_response_to_html, {"key": "value"})
        self.assertTrue(config.proxy_base64_decode)
        self.assertEqual(config.timeout, 15)
        self.assertEqual(config.max_redirects, 5)

    def test_starting_urls_validation(self):
        with self.assertRaises(ValidationError):
            AsyncCrawlerConfig()  # Missing required field

        with self.assertRaises(ValidationError):
            AsyncCrawlerConfig(starting_urls=[])  # Empty list

        config = AsyncCrawlerConfig(starting_urls="http://example.com")
        self.assertEqual(config.starting_urls, ["http://example.com"])




if __name__ == '__main__':
    unittest.main()
