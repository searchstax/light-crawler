import asyncio
import logging
import ssl
from base64 import b64decode
from dataclasses import dataclass
from typing import Set, List, Tuple, Optional, Union
from urllib.parse import urljoin, urldefrag

import aiohttp
import certifi
from aiohttp import ClientConnectionError, ClientPayloadError
from aiohttp import ClientSession, ClientResponseError, ClientTimeout
from aiohttp.client_exceptions import TooManyRedirects
from aiohttp_client_rate_limiter.ClientSession import RateLimitedClientSession
from multidict import CIMultiDictProxy
from pydantic import BaseModel
from selectolax.parser import HTMLParser
from urllib3.util import create_urllib3_context

# from urllib3 import PoolManager

logger = logging.getLogger('AsyncCrawler')


class InvalidContentTypeError(Exception):
    '''
    Exception raised when response content type is not in allowed types
    '''

    def __init__(self, response):
        self.response = response


class AlreadyFetchedError(Exception):
    def __init__(self):
        pass


@dataclass
class TaskQueueMessage:
    source_url: str
    url: str
    depth: int
    retry_count: int


class AsyncCrawlerConfig(BaseModel):
    starting_urls: List[str]
    max_depth: int = -1
    max_pages: int = -1
    concurrency: int = 100
    max_retries: int = 2
    headers: Optional[dict] = None
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None
    proxy_url: Optional[str] = None
    proxy_post_data: Optional[str] = None
    proxy_response_to_html: Optional[dict] = None
    proxy_base64_decode: bool = False
    timeout: int = 30
    max_redirects: int = 10
    max_requests_per_second: int = 1000


class AsyncCrawler:
    '''
    Crawler baseclass that concurrently crawls multiple pages till provided depth
    Built on asyncio
    '''

    html_content_types: Set[str] = {
        'text/html',
        'text/xhtml',
        'application/xhtml+xml',
        'application/xhtml',
        'application/html',
    }

    binary_content_types: Set[str] = {
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/epub+zip',
    }

    def __init__(self, config: AsyncCrawlerConfig):
        self.config = config
        self.crawled_urls: Set[str] = set()
        self.results: List = []
        self.session: Optional[ClientSession] = None
        self.task_queue: Optional[asyncio.Queue] = None

    async def issue_proxy_request(self, url: str):
        logging.debug("Using proxy", self.config.proxy_url)
        auth = None
        if self.config.proxy_username:
            auth = aiohttp.BasicAuth(self.config.proxy_username, self.config.proxy_password)
        if self.config.proxy_post_data:
            if self.config.headers:
                self.config.headers['Content-Type'] = 'application/json'
            else:
                self.config.headers = {'Content-Type': 'application/json'}

            data = self.config.proxy_post_data.replace("$URL", url)
            async with self.session.post(self.config.proxy_url, auth=auth, headers=self.config.headers,
                                         data=data) as response:
                content = await response.json()
                for key in self.config.proxy_response_to_html:
                    content = content[key]
                if self.config.proxy_base64_code:
                    content = b64decode(content).decode("utf8")
                return content, response.headers
        raise Exception("Unsupported proxy type")

    async def _make_request(self, url: str) -> Tuple[
        str, str, Union[str, bytes], CIMultiDictProxy[str, str]]:
        """
        Wrapper on aiohttp to make get requests on a shared session
        :param url: the url to fetch
        :return: tuple of actual url (if redirected) and html
        """

        if not self.session:
            if (self.config.max_requests_per_second > -1):
                self.session = RateLimitedClientSession(
                    max_concur=self.config.concurrency,
                    reqs_per_period=self.config.max_requests_per_second,
                    period_in_secs=1
                )
            else:
                self.session = ClientSession()

        logging.debug(f'Fetching: {url}')
        timeout = ClientTimeout(total=self.config.timeout)

        ctx = create_urllib3_context(ciphers=":HIGH:!DH:!aNULL",
                                     ssl_minimum_version=ssl.TLSVersion.MINIMUM_SUPPORTED)
        ctx.load_verify_locations(cafile=certifi.where())

        if self.config.proxy_url:
            # Use the proxy request method
            html, response_headers = await self.issue_proxy_request(url)
            actual_url = url  # The proxy request does not change the URL
            content_type = "text/html"  # Assuming the content is HTML, modify as needed
            return content_type, actual_url, html, response_headers  # No headers from the proxy request

        async with self.session.get(
                url,
                headers=self.config.headers,
                raise_for_status=True,
                timeout=timeout,
                max_redirects=self.config.max_redirects,
                # verify_ssl=False,
                ssl_context=ctx
        ) as response:

            actual_url = response.url.human_repr()
            if actual_url != url:
                # We were redirected to a new URL
                # check that we haven't already fetched the new URL. If so, let's ignore
                if response.url in self.crawled_urls:
                    raise AlreadyFetchedError()

            if response.content_type in self.html_content_types:
                html = await response.text()
                return "text/html", actual_url, html, response.headers
            elif response.content_type in self.binary_content_types:
                content = await response.read()
                return response.content_type, actual_url, content, response.headers
            else:
                raise InvalidContentTypeError(response)

    def extract_links(self, url: str, html: str) -> Set[str]:
        '''
        Finds all the links in passed html
        '''
        links = set()
        dom = HTMLParser(html)
        for tag in dom.css('a'):
            attrs = tag.attributes
            if 'href' in attrs:
                href = attrs['href']
                if not href or href.startswith('mailto:'):
                    continue
                href = urldefrag(urljoin(url, href))[0]
                links.add(href)
        links = {x for x in links if self.valid_link(url, x)}
        return links

    def valid_link(self, url: str, link: str):
        return True

    def output(self, content_type: str, url: str, links: Set[str], content: Union[str, bytes],
               response_headers: CIMultiDictProxy[str]) -> Optional[Tuple[str, str]]:
        raise NotImplementedError(
            '{}.output callback is not defined'.format(self.__class__.__name__)
        )

    async def crawl_page(self, url: str) -> Tuple[str, str, Set[str], Union[str, bytes], CIMultiDictProxy[str, str]]:
        '''
        Request a webpage and return all relevant data from it
        '''
        content_type, actual_url, content, response_headers = await self._make_request(url)
        if content_type == "text/html":
            links = self.extract_links(actual_url, content)
        else:
            links = None
        return content_type, actual_url, links, content, response_headers

    async def retry_task(self, task):
        '''
        Retries a task if max retries not hit
        '''
        if task.retry_count < self.config.max_retries:
            self.crawled_urls.discard(task.url)
            task_message = TaskQueueMessage(task.source_url, task.url, task.depth, task.retry_count + 1)
            await self.task_queue.put(task_message)
        else:
            logger.error(f'Max retries exceeded for url: {task.url}')

    async def worker(self) -> None:
        '''
        Pops a url from the task queue and crawls the page
        '''
        while True:

            if not self.task_queue:
                break

            task = await self.task_queue.get()
            logger.debug(f'Working on {task.url} at {task.depth}')

            if (self.config.max_depth > -1 and task.depth >= self.config.max_depth):
                self.task_queue.task_done()
                logger.debug('Max depth reached')
                continue

            if (task.url in self.crawled_urls):
                self.task_queue.task_done()
                logger.debug('Already seen URL')
                continue

            if (self.config.max_pages > 0) and (len(self.crawled_urls) > self.config.max_pages):
                self.task_queue.task_done()
                logger.debug('Max pages reached')
                continue

            self.crawled_urls.add(task.url)

            try:
                content_type, url, links, content, response_headers = await self.crawl_page(task.url)
            except InvalidContentTypeError as excp:
                pass
            except AlreadyFetchedError as excp:
                pass
            except TooManyRedirects as excp:
                self.log_error_url(task.url, "too_many_redirects", f'Redirected too many times at url: {task.url}')
            except ClientPayloadError as excp:
                self.log_error_url(task.url, "invalid_encoding", f'Invalid compression or encoding at url: {task.url}')
            except asyncio.TimeoutError as excp:
                self.log_error_url(task.url, "timeout", f'Timeout: {task.url}')
                # await self.retry_task(task)
            except ClientResponseError as excp:
                if excp.status > 499:
                    self.log_error_url(task.url, excp.status, f'Server error at url: {task.url}')
                else:
                    self.log_error_url(task.url, excp.status,
                                       f'Client error with status: {excp.status} at url: {task.url} from {task.source_url}')
            except ClientConnectionError as excp:
                print(excp)
                self.log_error_url(task.url, "connection_error", f'Connection error at url: {task.url}, skipping ....')
                # await self.retry_task(task)
            except Exception as excp:
                self.log_error_url(task.url, "exception", f'Unhandled exception: {type(excp)} {excp}')
            else:
                result = self.output(content_type, url, links, content, response_headers)
                if result:
                    self.results.append(result)

                if links:
                    for link in links.difference(self.crawled_urls):
                        task_message = TaskQueueMessage(url, link, task.depth + 1, 0)
                        await self.task_queue.put(task_message)
            finally:
                self.task_queue.task_done()

    def log_error_url(self, url, error_code: int, error_message: str):
        logger.error(url, error_code, error_message)

    def crawl_completed(self):
        pass

    async def crawl(self) -> None:
        '''
        Starts concurrent workers and kickstarts scraping
        '''
        self.task_queue = asyncio.Queue()
        for url in self.config.starting_urls:
            task_message = TaskQueueMessage(url, url, 0, 0)
            self.task_queue.put_nowait(task_message)
        workers = [asyncio.create_task(self.worker()) for i in range(self.config.concurrency)]

        await self.task_queue.join()

        for worker in workers:
            worker.cancel()

        self.crawl_completed()

        if self.session:
            await self.session.close()

    async def get_results(self) -> List:
        '''
        Run the crawler and return the generated sitemap
        '''
        await self.crawl()
        return self.results
