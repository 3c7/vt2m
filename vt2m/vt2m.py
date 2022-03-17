import os
from argparse import ArgumentParser
from datetime import datetime
from sys import stderr
from typing import Generator, Union, List, Optional, Dict
from urllib.parse import quote_plus, urlparse

from pymisp import PyMISP, MISPEvent
from vt import Client as VTClient


def query(api_key: str, query: str, limit: Optional[int]) -> List:
    """Queries VT API and yields a list of results."""
    if not limit:
        limit = 100

    with VTClient(apikey=api_key) as vt_client:
        response = vt_client.get(f"/intelligence/search?query={quote_plus(query)}&limit={limit}")
        results = response.json()
        return results.get("data", [])


def process_results(results: Union[Generator, List], event: MISPEvent, comment: Optional[str],
                    disable_output: bool = False):
    """Processes VT results using the specific methods per VT object type."""
    for result in results:
        if result["type"] == "file":
            if not disable_output:
                print("[FILE] ", end='')
            process_file(result["attributes"], event, comment, disable_output)
        elif result["type"] == "url":
            if not disable_output:
                print("[URL] ", end='')
            process_url(result["attributes"], event, comment, disable_output)
        elif result["type"] == "domain":
            raise NotImplementedError("Processing domains is currently not implemented.")
        elif result["type"] == "ip":
            raise NotImplementedError("Processing IPs is currently not implemented.")
        else:
            raise ValueError(f"Unknown entity type: {result['type']}")


def process_file(file: Dict, event: MISPEvent, comment: Optional[str] = None, disable_output: bool = False):
    """Adds files to MISP event as MISP objects."""
    sha256 = file.get("sha256", None)
    if not sha256:
        raise KeyError("VirusTotal file object misses sha256 hash. This should not happen.")
    if not disable_output:
        print(f"Processing {sha256}...")
    f_obj = event.add_object(name="file", comment=comment if comment else "")
    f_obj.add_attribute("md5", simple_value=file["md5"])
    f_obj.add_attribute("sha1", simple_value=file["sha1"])
    f_obj.add_attribute("sha256", simple_value=sha256)

    names = file.get("names", [])
    if len(names) > 0:
        for name in names:
            f_obj.add_attribute("filename", name)

    imp = file.get("pe_info", {}).get("imphash", None)
    if imp:
        f_obj.add_attribute("imphash", simple_value=imp)

    vhash = file.get("vhash", None)
    if vhash:
        f_obj.add_attribute("vhash", simple_value=vhash)

    tlsh = file.get("tlsh", None)
    if tlsh:
        f_obj.add_attribute("tlsh", simple_value=tlsh)

    telfhash = file.get("telfhash", None)
    if telfhash:
        f_obj.add_attribute("telfhash", simple_value=telfhash)

    creation_date = file.get("creation_date", None)
    if creation_date:
        creation_date = datetime.fromtimestamp(creation_date)
        f_obj.add_attribute("compilation-timestamp", type="datetime", value=creation_date)


def process_url(url: Dict, event: MISPEvent, comment: Optional[str] = None, disable_output: bool = False):
    """Adds URLs to MISP event as MISP objects."""
    url_string = url.get("url", None)
    if not url_string:
        raise KeyError("VirusTotal URL object missing the actual URL.")

    if not disable_output:
        print(f"Processing {url_string.replace('http', 'hxxp').replace('.', '[.]')}")
    _, domain, resource_path, _, query_string, _ = urlparse(url_string)
    u_obj = event.add_object(name="url", comment=comment if comment else "")
    u_obj.add_attribute("url", simple_value=url_string)
    u_obj.add_attribute("domain", simple_value=domain, to_ids=False)
    if resource_path:
        u_obj.add_attribute("resource_path", simple_value=resource_path)
    if query_string:
        u_obj.add_attribute("query_string", simple_value=query_string)

    u_obj.add_attribute("first-seen", type="datetime", value=datetime.fromtimestamp(url["first_submission_date"]))
    u_obj.add_attribute("last-seen", type="datetime", value=datetime.fromtimestamp(url["last_submission_date"]))


def cli():
    parser = ArgumentParser("vt2m")
    parser.add_argument("--uuid", "-u", type=str, required=True, help="MISP event uuid")
    parser.add_argument("--url", "-U", type=str, help="MISP URL - can also be given as env MISP_URL")
    parser.add_argument("--key", "-k", type=str, help="MISP API key - can also be given as env MISP_KEY")
    parser.add_argument("--vt-key", "-K", type=str, help="VT API key - can also be given as env VT_KEY")
    parser.add_argument("--comment", "-c", type=str, help="Comment to add to MISP objects")
    parser.add_argument("--limit", "-l", type=int, help="Limit results of VT query - default is 100")
    parser.add_argument("query", type=str, help="VT query")
    args = parser.parse_args()

    url = args.url
    if not url:
        url = os.getenv("MISP_URL", None)

    key = args.key
    if not key:
        key = os.getenv("MISP_KEY", None)

    vtkey = args.vt_key
    if not vtkey:
        vtkey = os.getenv("VT_KEY", None)

    if not url or not key or not vtkey:
        print("URL and key must be given either through param or env.", file=stderr)

    misp = PyMISP(url, key)
    misp.global_pythonify = True
    event = misp.get_event(args.uuid)
    results = query(vtkey, args.query, args.limit)
    process_results(results, event, args.comment)
    misp.update_event(event)
