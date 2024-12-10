import pandas as pd
import json
from urllib.parse import urlparse, parse_qs


import hashlib
import base64
import urllib.parse
import zlib
import gzip
import html

from Crypto.Hash import MD4, RIPEMD160  # pycryptodome
import mmh3  # MurmurHash3
import base58  # Base58 encoding
from lzstring import LZString  # LZString compression

def generate_variants(data):
    variants = set()

    # Raw data
    variants.add(data)

    # Hashes
    variants.add(hashlib.new("md4", data.encode()).hexdigest())
    variants.add(hashlib.md5(data.encode()).hexdigest())
    variants.add(hashlib.sha1(data.encode()).hexdigest())
    variants.add(hashlib.sha256(data.encode()).hexdigest())
    variants.add(hashlib.sha224(data.encode()).hexdigest())
    variants.add(hashlib.sha384(data.encode()).hexdigest())
    variants.add(hashlib.sha512(data.encode()).hexdigest())
    variants.add(hashlib.sha3_224(data.encode()).hexdigest())
    variants.add(hashlib.sha3_256(data.encode()).hexdigest())
    variants.add(hashlib.sha3_384(data.encode()).hexdigest())
    variants.add(hashlib.sha3_512(data.encode()).hexdigest())
    variants.add(hashlib.new("whirlpool", data.encode()).hexdigest())
    variants.add(mmh3.hash(data.encode()))
    variants.add(mmh3.hash128(data.encode()))
    variants.add(RIPEMD160.new(data.encode()).hexdigest())

    #encodings
    variants.add(base64.b16encode(data.encode()).decode())
    variants.add(base64.b32encode(data.encode()).decode())
    variants.add(base64.b64encode(data.encode()).decode())
    variants.add(urllib.parse.quote(data))

    # compressiosn
    variants.add(zlib.compress(data.encode()).hex())
    variants.add(gzip.compress(data.encode()).hex())
    variants.add(LZString().compress(data))
    variants.add(zlib.compress(data.encode()).hex())

    return {str(variant) for variant in variants}


file_path = '/Users/pouneh/Downloads/www.joann.com.har'
with open(file_path, 'r') as file:
    har_data = json.load(file)

input_data = {
    "first_name": "pouneh",
    "last_name": "bahrami",
    "email": "pouneh.nb@gmail.com",
    "card_number": "4645992371716565",
    "zip_code": "96787"
}

all_variants = set()
for key, value in input_data.items():
    all_variants.update(generate_variants(value))

exfiltrated_data = []
for entry in har_data.get("log", {}).get("entries", []):
    # Check in request URL
    url = entry.get("request", {}).get("url", "")
    for variant in all_variants:
        if variant in url:
            exfiltrated_data.append({"location": "URL", "data": variant, "url": url})

    # Check query parameters in the URL
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    for param, values in query_params.items():
        for value in values:
            for variant in all_variants:
                if variant in value:
                    exfiltrated_data.append({
                        "location": "Query Parameter",
                        "data": variant,
                        "url": url,
                        "parameter": param
                    })

    # Check in request headers
    for header in entry.get("request", {}).get("headers", []):
        value = header.get("value", "")
        for variant in all_variants:
            if variant in value:
                exfiltrated_data.append({"location": "Header", "data": variant, "url": url})

    # Check in request payloads
    post_data = entry.get("request", {}).get("postData", {}).get("text", "")
    for variant in all_variants:
        if variant in post_data:
            exfiltrated_data.append({"location": "Payload", "data": variant, "url": url})

    # Check in cookies
    cookies = entry.get("request", {}).get("cookies", [])
    for cookie in cookies:
        cookie_value = cookie.get("value", "")
        for variant in all_variants:
            if variant in cookie_value:
                exfiltrated_data.append({"location": "Cookie", "data": variant, "url": url})


exfiltrated_df = pd.DataFrame(exfiltrated_data)
print(exfiltrated_df)
    