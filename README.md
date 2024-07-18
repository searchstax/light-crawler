# SiteCrawler

A Python [asyncio](https://docs.python.org/3/library/asyncio.html) website crawler that uses a simple stack:

1. [LMDB](https://lmdb.readthedocs.io/en/release/) for saving downloaded URLs
2. [Celery](https://docs.celeryq.dev/en/stable/index.html) over [Redis](https://redis.io) for work queue management
3. [FastAPI](https://fastapi.tiangolo.com/) provides a thin API wrapper over the crawler 

It was forked from [https://github.com/tapanpandita/aiocrawler](https://github.com/tapanpandita/aiocrawler) (MIT licensed).

It is designed for speed:

- asyncio
- selectolax for fast HTML parsing
- LMDB for high read/write performance
- Unstructured API for file extraction

## Features
- [x] Multiple starting URLs
- [x] Configurable metadata extraction using CSS selectors and regex
- [x] Limit depth of crawl
- [x] Limit number of pages crawled
- [x] Configurable concurrency
- [x] Download sitemaps
- [x] FastAPI API server
- [x] Celery integration
- [x] Dockerized
- [x] Proxy support
- [ ] Scheduling crawls
- [x] Return full downloaded content via /browse API
- [ ] Standard webpage metadata extractors
- [x] Integrate with unstructured to extract text from PDF, docx, pptx etc
- [ ] Javascript rendering/parsing via https://splash.readthedocs.io/en/stable/
- [ ] content_css_selector
- [ ] if_modified_since_hours

## Installation

```bash
git clone https://github.com/superkelvint/sitecrawler
cd sitecrawler
docker compose up --build
```

The FastAPI crawler API server is now available at [http://localhost:8000](http://localhost:8000).
The OpenAPI spec is available at [http://localhost:8000/docs](http://localhost:8000/docs).

## Starting your first crawl

```bash
curl -X POST http://localhost:8000/crawl \
 -H "Content-Type: application/json" \
 -d '{"name": "supermind", "starting_urls": ["https://www.supermind.org/"], "max_pages": 200, "concurrency": 5, "extraction_rules": {"rules": [{"field_name": "title", "regex": "<title>(.*?)</title>"}]}}'
```

This starts a crawl on supermind.org limited to 200 pages with a concurrency of 5.

The above command should return a UUID response like so:

```bash
{"id":"f339cef3-9839-476d-acdf-b61548515a93"} 
```

This is your job id. You can inspect the result of your crawl like so:

```bash
curl http://localhost:8000/crawl/f339cef3-9839-476d-acdf-b61548515a93
```

After the crawl is completed, you should see a response like:

```json
{
  "id": "f339cef3-9839-476d-acdf-b61548515a93",
  "status": "SUCCESS",
  "info": {
    "name": "supermind",
    "stats": {
      "total": 201,
      "cached": 191,
      "cached_redirects": 2,
      "fetched": 8,
      "new_or_updated": 8
    },
    "start_time": "2024-02-12 05:13:38.358572+0000 (UTC)",
    "end_time": "2024-02-12 05:13:41.063751+0000 (UTC)",
    "duration": "2.705178737640381 seconds"
  }
}  
```


## Design choices
This is not a distributed crawler. The entire crawl runs within a single Celery worker in an async fashion. 
It is very fast, especially if you set a high concurrency. 

Hitting a single host from a single crawler node, we can easily hit 50 URLs/s with concurrency of 10.  

The crawl job runs in 2 phases:
1. download all URLs
2. parse and extract

Each phase runs as a separate Celery task. This means it should be possible to have different workers doing different tasks. 

## APIs

<details>
  <summary><code>GET</code> <code><b>/health</b></code> <code>Health Check</code></summary>

### Response
 ```json
{
  "health": "GREEN"
}
```
</details>

<details>
  <summary><code>POST</code> <code><b>/crawl</b></code> <code>Submit a new crawl</code></summary>

### Request Object
| **Name**                        | **Type**        | **Default**     | **Description**                                                                                                                                                                                                        |
| ------------------------------- | --------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **name**                        | string          |                 | Name of the crawl (required)                                                                                                                                                                                           |
| **starting_urls**               | list of strings |                 | Starting URLs (required)                                                                                                                                                                                               |
| **allowed_domains**             | list of strings |                 | Allowed domains. Additive with allow_starting_url_hostname and allow_starting_url_tld.                                                                                                                                 |
| **allowed_regex**               | list of strings |                 | URLs matching with these regexes will be allowed.                                                                                                                                                                      |
| **denied_regex**                | list of strings |                 | URLs matching with these regexes will not be crawled.                                                                                                                                                                  |
| **denied_extensions**           | list of strings |                 | URLs ending with these extensions will not be crawled.                                                                                                                                                                 |
| **is_sitemap**                  | boolean         | false           | If true, all the starting URLs will be treated as sitemaps. The entire sitemaps will be downloaded, all the URLs collected and crawled to a depth of 1. No URLs other than what is in the sitemaps will be downloaded. |
| **max_depth**                   | number          | 300             | Maximum crawler depth. The starting URL is depth of 1.                                                                                                                                                                 |
| **max_pages**                   | number          | -1              | Max number of pages to crawl. -1 means no limit (default)                                                                                                                                                              |
| **concurrency**                 | number          | 10              | Simultaneous crawler connections.                                                                                                                                                                                      |
| **allow_starting_url_hostname** | boolean         | true            | Allow all links with the same hostname as starting URLs.                                                                                                                                                               |
| **allow_starting_url_tld**      | boolean         | false           | Allow all links with the same TLD as starting URLs.                                                                                                                                                                    |
| **user_agent**                  | string          | SiteCrawler/1.0 | Crawler user-agent.                                                                                                                                                                                                    |
| **extraction_rules**            | dictionary      |                 | See ExtractionRules section.                                                                                                                                                                                           |

#### Example
```json
{
  "name": "supermind",
  "starting_urls": [
    "https://www.supermind.org/"
  ],
  "max_pages": 200,
  "concurrency": 5,
  "extraction_rules": {
    "rules": [
      {
        "field_name": "title",
        "regex": "<title>(.*?)</title>"
      },
      {
        "field_name": "description",
        "css": "meta[name=description]",
        "attribute": "content"
      }
    ]
  }
}
```

### Extraction Rules
| **Name**          | **Type** | **Description**                                                                                                    |
| ----------------- | -------- | ------------------------------------------------------------------------------------------------------------------ |
| **field_name**    | string   | Name of the field                                                                                                  |
| **css**           | string   | CSS selector.                                                                                                      |
| **regex**         | string   | Regex. There must be 1 matching group.                                                                             |
| **delimiter**     | string   | Not currently used.                                                                                                |
| **attribute**     | string   | **CSS only**. If specifed, the HTML element attribute it extracted. Otherwise, the element text is used (default). |
| **fixed_value**   | string   | Populate the field with a fixed value. It can be useful if merging data from different sites                       |
| **default_value** | string   | Default value to use if there is no match                                                                          |

There should only be either `css` or `regex` declared. If both are declared, `css` is used. 
### Response
 ```json
{
  "id": "b67dbbbb-84c0-45c5-b467-85eb846c8988"
}
```
</details>

<details>
  <summary><code>GET</code> <code><b>/crawl</b></code> <code>List all active crawl</code></summary>

### Response
 ```json
{
  "jobs": [
    {
      "id": "1fcfba77-03d4-47d1-9b3d-41ca5336c27d",
      "status": "PENDING",
      "info": null
    }
  ]
}
```
</details>

<details>
  <summary><code>GET</code> <code><b>/crawl/{job_id}</b></code> <code>Get details of crawl by its job ID</code></summary>

### Response
 ```json
{
  "id": "b67dbbbb-84c0-45c5-b467-85eb846c8988",
  "status": "SUCCESS",
  "info": {
    "name": "test",
    "stats": {
      "total": 1,
      "cached": 1
    },
    "start_time": "2024-03-18 17:16:52.552218+0000 (UTC)",
    "end_time": "2024-03-18 17:16:52.583229+0000 (UTC)",
    "duration": "less than a second"
  }
}
```
</details>

<details>
  <summary><code>DELETE</code> <code><b>/crawl/{job_id}</b></code> <code>Stop the crawl</code></summary>

### Response
 ```json
{
  "jobs": [
    {
      "id": "1fcfba77-03d4-47d1-9b3d-41ca5336c27d",
      "status": "PENDING",
      "info": null
    }
  ]
}
```
</details>

<details>
  <summary><code>GET</code> <code><b>/browse/{name}</b></code> <code>Get contents of the crawl</code></summary>

### Parameters
| name        | data type | description              |
| ----------- | --------- | ------------------------ |
| page        | int       | Page number              |
| rows        | int       | Number of items per page |
| fullcontent | bool      | Return unparsed content  |

### Response
 ```json
{
  "name": "test_crawl",
  "page": 0,
  "total_pages": 1,
  "num_records": 1,
  "items": [
    {
      "server_last_modified": "Fri, 16 Feb 2024 15:43:40 GMT",
      "_content": "xyz file content",
      "content_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "title": "filename.pptx",
      "description": "",
      "metacategory_ss": "",
      "metaproducts_ss": "",
      "metaindustries_ss": "",
      "ogimage_s": "",
      "h1list": "",
      "h2list": "",
      "h3list": "",
      "h4list": "",
      "uri": "https://...REDACTED.../filename.pptx",
      "path_s": "sites / default / files / 2024-02 / filename.pptx",
      "typeUrl_s": "Sites",
      "id": "07794058-2453-3a03-b292-1278da923e3d"
    }
  ]
}
```
</details>


## Using proxy services
| **Name**                   | **Type**     | **Description**                                         |
|----------------------------|--------------|---------------------------------------------------------|
| **proxy_url**              | string       | Proxy service URL (required)                            |
| **proxy_username**         | string       | Proxy username                                          |
| **proxy_password**         | string       | Proxy password                                          |
| **proxy_post_data**        | string       | The JSON payload. Use $URL to signify the URL to fetch. |
| **proxy_response_to_html** | list[string] | The JSON response path to the HTML.                     |
| **proxy_base64_decode**    | boolean      | Is the HTML response base64 encoded?                    |

Example settings for Zyte Proxy API:
```
  "proxy_username": "[Zyte API Key]",
  "proxy_password": "",
  "proxy_url": "https://api.zyte.com/v1/extract",
  "proxy_post_data": "{\"url\": \"$URL\", \"httpResponseBody\": true}",
  "proxy_response_to_html": ["httpResponseBody"],
  "proxy_base64_decode": true,
```

Example settings for OxyLabs Proxy API:
```
  "proxy_url": "https://realtime.oxylabs.io/v1/queries",
  "proxy_username": "[OxyLabs API username]",
  "proxy_password": "[OxyLabs API password]",
  "proxy_post_data": "{\"source\": \"universal\", \"url\": \"$URL\", \"geo_location\": \"United States\"}",
  "proxy_response_to_html": ["results", 0, "content"],
```

## Using sitecrawler as a library

```python
import asyncio

from sitecrawler import SiteCrawler
from siteextractor import do_extraction

if __name__ == "__main__":
    crawler = SiteCrawler(name="test_crawl", starting_urls=["https://www.supermind.org"], max_pages=10)
    asyncio.run(crawler.get_results())
    print(crawler.stats)
    do_extraction(crawler.collection, crawler.config.extraction_rules)
```

If you prefer, you can also initialize a SiteCrawlerConfig object. 
```python
import asyncio

from sitecrawler import SiteCrawler, SiteCrawlerConfig
from siteextractor import do_extraction

if __name__ == "__main__":
    config = SiteCrawlerConfig(name="test_crawl", starting_urls=["https://www.supermind.org"], max_pages=10)
    crawler = SiteCrawler(config=config)
    asyncio.run(crawler.get_results())
    print(crawler.stats)
    do_extraction(crawler.collection, crawler.config.extraction_rules)

```

## Using sitecrawler from the command-line
```bash
source ./venv/bin/activate
python3 sitecrawler.py --name=supermind --starting_urls="https://www.supermind.org"
```

You can also pass in a --config JSON crawl configuration. e.g. if you have a file crawl_config.json
```json
{
  "name": "supermind",
  "starting_urls": ["https://www.supermind.org"]
}
```

You can do this:
```bash
python3 sitecrawler.py --config=crawl_config.json
```


## Running celery locally

Celery is not needed to run the sitecrawler. You can run it as-is. If you do wish to run Celery locally, 
in a terminal, this is how to start the celery worker:
```bash
source ./venv/bin/activate
celery -A tasks worker --loglevel=INFO
```

You will also need Redis running locally. 

## Contributing

The 4 files of interest are:

- sitecrawler.py: the main crawler logic
- aiocrawler.py: the crawler base class that handles most of the async fetching operations
- main.py: the FastAPI wrapper around the crawler
- tasks.py: submits jobs to celery
