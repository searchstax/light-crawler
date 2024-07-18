import json
from collections import Counter

from sitecrawler import SiteCrawler

crawler = SiteCrawler.from_command_line()

counter = Counter()
with open(crawler.name + "_export.jsonl", 'w') as f:
    for k, v in crawler.collection.items():
        if v["type"] != "content":
            counter["not_content"] += 1
            continue
        output = {"url": k}
        try:

            for r in crawler.extraction_rules.rules:
                output[r.field_name] = v[r.field_name].replace("&amp;", "&")
            f.write(json.dumps(output))
            f.write("\n")
            counter["success"] += 1
        except:
            counter["error"] += 1
            print("Error with " + k)

print(counter)
