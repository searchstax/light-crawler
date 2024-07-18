import json
import os
import re
import tempfile
import urllib.parse as urlparse
import uuid
from collections import Counter
from typing import Optional, List, Set, Dict, Union

import requests
import xxhash
from lxml.html.clean import Cleaner
from pydantic import BaseModel, Field, PrivateAttr, model_validator
from selectolax.parser import Node, HTMLParser

from lmdb_collection import LmdbmDocumentCollection


class CleanerConfig(BaseModel):
    scripts: bool = True
    javascript: bool = True
    comments: bool = True
    style: bool = True
    inline_style: Optional[bool] = None
    links: bool = True
    meta: bool = True
    page_structure: bool = False
    processing_instructions: bool = True
    embedded: bool = True
    frames: bool = True
    forms: bool = True
    annoying_tags: bool = True
    remove_tags: Optional[List[str]] = None
    allow_tags: Optional[List[str]] = None
    kill_tags: Optional[List[str]] = ['noscript', 'footer', 'header', 'nav', 'button', 'form']
    remove_unknown_tags: bool = True
    safe_attrs_only: bool = True
    add_nofollow: bool = False
    host_whitelist: Set[str] = Field(default_factory=set)
    whitelist_tags: Set[str] = {'embed', 'iframe'}
    tag_link_attrs: Dict[str, Union[str, List[str]]] = {
        'a': 'href',
        'applet': ['code', 'object'],
        'embed': 'src',
        'iframe': 'src',
        'layer': 'src',
        'link': 'href',
        'script': 'src'
    }

    _cached_cleaner: Optional[Cleaner] = PrivateAttr(default=None)

    def get_cleaner(self) -> Cleaner:
        if self._cached_cleaner is None:
            self._cached_cleaner = Cleaner(
                scripts=self.scripts,
                javascript=self.javascript,
                comments=self.comments,
                style=self.style,
                inline_style=self.inline_style,
                links=self.links,
                meta=self.meta,
                page_structure=self.page_structure,
                processing_instructions=self.processing_instructions,
                embedded=self.embedded,
                frames=self.frames,
                forms=self.forms,
                annoying_tags=self.annoying_tags,
                remove_tags=self.remove_tags,
                allow_tags=self.allow_tags,
                kill_tags=self.kill_tags,
                remove_unknown_tags=self.remove_unknown_tags,
                safe_attrs_only=self.safe_attrs_only,
                safe_attrs=self.safe_attrs,
                add_nofollow=self.add_nofollow,
                host_whitelist=self.host_whitelist,
                whitelist_tags=self.whitelist_tags
            )
        return self._cached_cleaner


class ExtractionRule(BaseModel):
    field_name: str
    css: Optional[str] = None
    regex: Optional[str] = None
    delimiter: Optional[str] = None
    attribute: Optional[str] = None
    fixed_value: Optional[str] = None
    default_value: Optional[str] = None

    @model_validator(mode='before')
    @classmethod
    def check_css_or_regex(cls, values):
        css = values.get('css')
        regex = values.get('regex')
        if not css and not regex:
            raise ValueError("Either 'css' or 'regex' must be provided and non-empty")
        if css is not None and not css.strip():
            raise ValueError("'css' must not be empty if provided")
        if regex is not None and not regex.strip():
            raise ValueError("'regex' must not be empty if provided")
        return values


class ExtractionRules(BaseModel):
    rules: list[ExtractionRule]
    cleaner_config: Optional[CleanerConfig] = Field(default_factory=CleanerConfig)
    unstructured_url: Optional[str] = 'http://localhost:8005'

    def compute_hash(self):
        return xxhash.xxh32_intdigest(json.dumps([k.model_dump_json() for k in self.rules]))


def _extract_content(node: Node, rule: ExtractionRule) -> str:
    if rule.attribute:
        return node.attributes[rule.attribute].strip()
    else:
        return node.text().strip()


def do_extract(content: str, rules: ExtractionRules) -> dict:
    if not content:
        return {}
    cleaned_content = rules.cleaner_config.get_cleaner().clean_html(content)
    dom = HTMLParser(cleaned_content)
    result = {}
    for r in rules.rules:
        if r.css:
            results = dom.css(r.css)
            if len(results) == 0:
                if r.default_value:
                    result[r.field_name] = r.default_value
            if len(results) == 1:
                result[r.field_name] = _extract_content(results[0], r)
            elif len(results) > 1:
                result[r.field_name] = [_extract_content(n, r) for n in results]
        elif r.regex:
            matches = re.findall(r.regex, content)
            if len(matches) > 0:
                result[r.field_name] = matches[0].strip()
        elif r.fixed_value:
            result[r.field_name] = r.fixed_value
        if r.field_name not in result:
            result[r.field_name] = ""
    return result


def _extract_binary_content(result, bytestream, unstructured_url):
    headers = {
        'accept': 'application/json'
    }
    a = urlparse.urlparse(result['uri'])
    filename = os.path.basename(a.path)
    files = {
        'files': (filename, bytestream),
        'strategy': (None, 'auto')
    }
    resp = requests.post(f'{unstructured_url}/general/v0/general', headers=headers, files=files)
    if resp.status_code == 200:
        text_blob = ' '.join([line['text'] for line in resp.json()])
        title = resp.json()[0]['metadata']['filename']
        result['_content'] = text_blob
        result['title'] = title
    return result


def do_extraction(collection: LmdbmDocumentCollection, extraction_rules: ExtractionRules):
    if extraction_rules is None or len(extraction_rules.rules) == 0:
        return
    parsed_hash = extraction_rules.compute_hash()

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        temp_filename = temp_file.name
        counter = Counter()
        for k, v in collection.items():
            if collection.is_binary_key(k):
                continue
            else:
                if v["type"] == "content":
                    if v["parsed_hash"] != parsed_hash:
                        result = do_extract(v["_content"], extraction_rules)
                        # Default extraction for Facet on Based on URL
                        result['uri'] = k
                        result['path_s'] = get_path(k)
                        result['typeUrl_s'] = get_type_from_url(k)
                        result['id'] = create_id(k)

                        if v['content_type'] != 'text/html':
                            result = _extract_binary_content(result, collection.get_binary(k),
                                                             extraction_rules.unstructured_url)
                        v.update(result)
                        v["parsed_hash"] = parsed_hash
                        # crawler.collection[k] = v
                        json.dump({"key": k, "value": v}, temp_file)
                        temp_file.write('\n')
                        counter['new_parsed'] += 1
        with open(temp_filename, 'r') as file:
            for line in file:
                try:
                    record = json.loads(line)
                    k = record["key"]
                    v = record["value"]
                    collection[k] = v
                    counter['updated'] += 1
                except:
                    print("Error with " + line)
                    counter['errors'] += 1
        print("Extraction stats", counter)


def create_id(url_string):
    return str(uuid.uuid3(uuid.NAMESPACE_URL, url_string))


def get_path(url_string):
    url_parse = urlparse.urlparse(url_string)
    path_str = url_parse.path.strip('/').replace('/', ' / ')
    if not path_str:
        path_str = url_parse.netloc
    return path_str


def get_type_from_url(url_string):
    url_parse = urlparse.urlparse(url_string)
    pagetype = url_parse.path.strip('/').split('/')[0].title()
    if "-" in pagetype:
        pagetype = " ".join(pagetype.split("-")).title()
    if "_" in pagetype:
        pagetype = " ".join(pagetype.split("_")).title()
    if not pagetype:
        return "Web Page"
    return pagetype
