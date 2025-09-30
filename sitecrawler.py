import asyncio
import json
import logging
import os.path
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Optional, List, Dict
from typing import Set, Tuple, Union

import requests
from celery.result import AsyncResult
from multidict import CIMultiDictProxy, CIMultiDict
from pydantic import Field, field_validator
from tldextract import tldextract
from usp.tree import sitemap_tree_for_homepage

from asynccrawler import AsyncCrawler, AsyncCrawlerConfig
from lmdb_collection import LmdbmDocumentCollection
from siteextractor import do_extraction, ExtractionRules

logger = logging.getLogger('SiteCrawler')


class SiteCrawlerConfig(AsyncCrawlerConfig):
    name: str
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_regex: List[str] = Field(default_factory=list)
    denied_regex: List[str] = Field(default_factory=list)
    denied_extensions: List[str] = Field(default_factory=list)
    allow_urls_by_default: bool = True,
    headers: Dict[str, str] = Field(default_factory=dict)
    sitemap_file: Optional[str] = None
    is_sitemap: bool = False
    is_sitemap_direct: bool = False
    if_modified_since_hours: int = -1
    cache_ttl_hours: float = -1
    allow_starting_url_hostname: bool = True
    allow_starting_url_tld: bool = False
    content_css_selector: Optional[str] = None
    extraction_rules: Union[ExtractionRules, str, dict] = None
    user_agent: str = 'SearchStax SiteCrawler/1.0'
    data_dir: str = "data"
    init_collection: bool = True
    debug_html: bool = False
    global_excludes: Set[str] = {"\\.jpg", "\\.jpeg", "\\.png", "\\.mp4", "\\.webp", "\\.gif", "\\.css", "\\.js"}

    def __init__(self, **data):
        # Process starting_urls before calling super().__init__
        if 'starting_urls' in data and isinstance(data['starting_urls'], str):
            data['starting_urls'] = [data['starting_urls']]

        super().__init__(**data)

        for field in ['denied_regex', 'allowed_regex']:
            value = getattr(self, field)
            if isinstance(value, str):
                setattr(self, field, value.split(","))
        if isinstance(self.allowed_domains, str):
            self.allowed_domains = self.allowed_domains.split(",")
        if isinstance(self.denied_extensions, str):
            self.denied_extensions = self.denied_extensions.split(",")

        if self.user_agent and "User-Agent" not in self.headers:
            self.headers["User-Agent"] = self.user_agent

        self.denied_regex = self.denied_regex + list(self.global_excludes)

    @field_validator('extraction_rules', mode='before')
    @classmethod
    def parse_extraction_rules(cls, v):
        if v is None:
            return ExtractionRules(rules=[])
        if isinstance(v, str):
            return ExtractionRules.model_validate_json(v)
        elif isinstance(v, dict):
            return ExtractionRules.model_validate(v)
        elif isinstance(v, ExtractionRules):
            return v
        else:
            raise ValueError("Invalid extraction_rules format")


class SiteCrawler(AsyncCrawler):
    def __init__(self, config: Optional[SiteCrawlerConfig] = None, **kwargs):
        if config is None and not kwargs:
            raise ValueError("Either config or keyword arguments must be provided")

        if config is None:
            config = SiteCrawlerConfig(**kwargs)
        elif kwargs:
            config_dict = config.model_dump()
            config_dict.update(kwargs)
            config = SiteCrawlerConfig(**config_dict)

        self.config = config
        self._initialize_starting_urls()
        super().__init__(self.config)

        self.stats = Counter()
        self.start_time = time.time()
        self.end_time = -1
        self.duration = -1
        self.celery_task: Optional[AsyncResult] = None

        if self.config.init_collection:
            if not os.path.exists(self.config.data_dir):
                os.makedirs(self.config.data_dir)
            self.collection = LmdbmDocumentCollection(f"{self.config.data_dir}/{self.config.name}.crawl")

    def _initialize_starting_urls(self):
        if self.config.is_sitemap:
            self._process_sitemap_tree()
        elif self.config.is_sitemap_direct:
            self._process_sitemap_direct()
        elif self.config.sitemap_file:
            self._process_sitemap_file()
        else:
            self._process_starting_urls()

    def _process_sitemap_tree(self):
        self.config.max_depth = 1
        leaf_urls = set()
        for s in self.config.starting_urls:
            logger.info("Fetching sitemap for %s", s)
            tree = sitemap_tree_for_homepage(s)
            for page in tree.all_pages():
                leaf_urls.add(page.url)
        self.config.starting_urls = list(leaf_urls)

    def _process_sitemap_direct(self):
        print("Fetching sitemap direct...")
        leaf_urls = set()
        for s in self.config.starting_urls:
            subdomain, tld = self.parse_tld(s)
            if self.config.allow_starting_url_hostname and subdomain not in self.config.allowed_domains:
                self.config.allowed_domains.append(subdomain)
            if self.config.allow_starting_url_tld and tld not in self.config.allowed_domains:
                self.config.allowed_domains.append(tld)

            logger.info("Fetching sitemap for %s", s)
            res = requests.get(s)
            matches = re.findall(r"<loc>(.*?)</loc>", res.text)
            for m in matches:
                if self.valid_link(s, m):
                    leaf_urls.add(m)
        self.config.starting_urls = list(leaf_urls)

    def _process_sitemap_file(self):
        print(f"Loading sitemap from file: {self.config.sitemap_file}")
        leaf_urls = set()
        with open(self.config.sitemap_file) as f:
            s = f.read()
            matches = re.findall(r"<loc>(.*?)</loc>", s)
            for m in matches:
                if self.valid_link(s, m):
                    leaf_urls.add(m)
        for s in leaf_urls:
            print(s)
        self.config.starting_urls = list(leaf_urls)

    def _process_starting_urls(self):
        for s in self.config.starting_urls:
            subdomain, tld = self.parse_tld(s)
            if self.config.allow_starting_url_hostname and subdomain not in self.config.allowed_domains:
                self.config.allowed_domains.append(subdomain)
            if self.config.allow_starting_url_tld and tld not in self.config.allowed_domains:
                self.config.allowed_domains.append(tld)

    def __repr__(self) -> str:
        return f"SiteCrawler(name={self.config.name}, starting_urls={self.config.starting_urls}"

    @staticmethod
    def parse_args(args):
        d = {}
        for arg in args:
            if '=' in arg:
                k, v = arg.lstrip('-').split('=', 1)
                d[k] = v
        return d

    @classmethod
    def from_command_line(cls):
        args = cls.parse_args(sys.argv[1:])

        if 'config' in args:
            config_file = args['config']
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            print("SiteCrawler parameters (from config):", config_data)
            return cls(**config_data)
        else:
            print("SiteCrawler parameters:", args)
            return cls(**args)

    @classmethod
    def from_json(cls, json_str: str, **kwargs) -> 'SiteCrawler':
        return cls(**json.loads(json_str), **kwargs)

    @staticmethod
    def format_duration(seconds):
        if seconds < 1:
            return "less than a second"

        words = ["year", "day", "hour", "minute", "second"]

        if not seconds:
            return "now"
        else:
            m, s = divmod(seconds, 60)
            h, m = divmod(m, 60)
            d, h = divmod(h, 24)
            y, d = divmod(d, 365)

            time = [y, d, h, m, s]

            duration = []

            for x, i in enumerate(time):
                if i == 1:
                    duration.append(f"{i} {words[x]}")
                elif i > 1:
                    duration.append(f"{i} {words[x]}s")

            if len(duration) == 1:
                return duration[0]
            elif len(duration) == 2:
                return f"{duration[0]} and {duration[1]}"
            else:
                return ", ".join(duration[:-1]) + " and " + duration[-1]

    def report(self):
        start_time = datetime.fromtimestamp(self.start_time, timezone.utc).astimezone().strftime(
            "%Y-%m-%d %H:%M:%S.%f%z (%Z)")
        if self.end_time == -1:
            end_time = "still running"
        else:
            end_time = datetime.fromtimestamp(self.end_time, timezone.utc).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S.%f%z (%Z)")
        return {"name": self.config.name, "stats": dict(self.stats), "start_time": start_time, "end_time": end_time,
                "duration": self.format_duration(self.duration)}

    async def _make_request(self, url: str) -> Tuple[str, str, Union[str, bytes], CIMultiDictProxy[str]]:
        """
        The super method is where the actual fetching of the URL takes place.
        This overriden function takes care of handling caching, redirections and updating celery.
        :param url:
        :return:
        """
        self.stats["total"] += 1

        if self.is_cached_url(url):
            self.stats["cached"] += 1
            if self.celery_task:
                self.celery_task.update_state(state='PROGRESS', meta={"name": self.config.name, "stats": self.stats})
            dict = CIMultiDict()
            cached = self.collection[url]
            dict["Last-Modified"] = cached["server_last_modified"]
            return cached["content_type"], url, cached["_content"], CIMultiDictProxy(dict)
        elif self.is_redirected_url(url):
            # logger.debug("Cached[redirected]: " + url)
            self.stats["cached_redirects"] += 1
            actual_url = self.get_redirected_url(url)
            dict = CIMultiDict()
            cached = self.collection[actual_url]
            dict["Last-Modified"] = cached["server_last_modified"]
            return cached["content_type"], actual_url, cached["_content"], CIMultiDictProxy(dict)
        else:
            print(f"Fetching {url}")

        self.stats["fetched"] += 1
        content_type, actual_url, content, headers = await super()._make_request(url)
        if self.celery_task:
            self.celery_task.update_state(state='PROGRESS', meta={"name": self.config.name, "stats": self.stats})
        if url != actual_url:
            self.save_redirect(url, actual_url)
        if self.config.debug_html:
            print(content)
        return content_type, actual_url, content, headers

    def parse_tld(self, url: str) -> tuple[str, str]:
        link_tld = tldextract.extract(url)
        tld = link_tld.domain + "." + link_tld.suffix
        return link_tld.subdomain + "." + tld, tld

    def valid_link(self, source_url: str, link: str):
        """
        Checks if we should follow the link
        :param source_url:
        :param link:
        :return:
        """
        subdomain, tld = self.parse_tld(link)
        if len(self.config.allowed_domains) > 0 and subdomain not in self.config.allowed_domains \
                and tld not in self.config.allowed_domains:
            return False
        if "@" in link:
            return False

        included = False
        for s in self.config.allowed_regex:
            if re.findall(s, link, re.IGNORECASE):
                included = True
                break
        if included:
            return True

        excluded = False
        for s in self.config.denied_regex:
            if re.findall(s, link, re.IGNORECASE):
                excluded = True
                break
        if excluded:
            return False
        for s in self.config.denied_extensions:
            if link.endswith(s):
                excluded = True
                break
        if excluded:
            return False

        return self.config.allow_urls_by_default

    def is_cached_url(self, url):
        is_cached = url in self.collection and self.collection[url]["type"] == "content"
        if is_cached and self.config.cache_ttl_hours > -1:
            is_cache_expired = (self.start_time - self.collection[url]["crawled"]) / 3600 >= self.config.cache_ttl_hours
            return not is_cache_expired
        else:
            return is_cached

    def is_redirected_url(self, url):
        return url in self.collection and self.collection[url]["type"] == "redirect"

    def get_redirected_url(self, url):
        return self.collection[url]["redirected_url"]

    def save_redirect(self, source_url: str, redirected_url: str):
        self.collection.add(source_url, None, type="redirect", redirected_url=redirected_url)

    def log_error_url(self, url, error_code: int, error_message: str):
        self.stats[error_code] += 1
        self.collection.add(url, error_message, type="error", error_code=error_code)
        logging.error(f'{url}, {error_code}, {error_message}')

    def output(self, content_type: str, url: str, links: Set[str], content: Union[str, bytes],
               response_headers: CIMultiDictProxy[str]) -> Optional[Tuple[str, str]]:
        """
        Write the content to the LMDB collection.
        :param content_type:
        :param url:
        :param links:
        :param content:
        :param headers:
        :return:
        """
        try:
            if not self.is_cached_url(url):
                self.stats["new_or_updated"] += 1
                if content_type == "text/html":
                    self.collection.add_html(url, content, type="content", parsed_hash="", crawled=time.time(),
                                             server_last_modified=response_headers.get("Last-Modified"))
                else:
                    self.collection.add_binary(url, content, content_type, type="content", parsed_hash="",
                                               crawled=time.time(),
                                               server_last_modified=response_headers.get("Last-Modified"))
            else:
                # compare the last modified dates
                server_last_modified = response_headers.get("Last-Modified")
                cached = self.collection[url]
                if server_last_modified and cached["server_last_modified"] != server_last_modified:
                    self.stats["new_or_updated"] += 1
                    if content_type == "text/html":
                        self.collection.add_html(url, content, type="content", parsed_hash="", crawled=time.time(),
                                                 server_last_modified=response_headers.get("Last-Modified"))
                    else:
                        self.collection.add_binary(url, content, content_type, type="content", parsed_hash="",
                                                   crawled=time.time(),
                                                   server_last_modified=response_headers.get("Last-Modified"))

        except Exception as e:
            print("Error saving", url, e)
        return None

    def crawl_completed(self):
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time

    def attach_celery_task(self, current_task):
        self.celery_task = current_task


if __name__ == '__main__':
    crawler = SiteCrawler.from_command_line()

    # Run the crawler and perform the extraction
    asyncio.run(crawler.get_results())
    print(crawler.stats)
    do_extraction(crawler.collection, crawler.config.extraction_rules)
