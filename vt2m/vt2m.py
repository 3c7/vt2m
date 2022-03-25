import os
from argparse import ArgumentParser
from datetime import datetime
from sys import stderr
from typing import Generator, Union, List, Optional, Dict
from urllib.parse import quote_plus, urlparse

from pymisp import PyMISP, MISPEvent, MISPObject
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
                    disable_output: bool = False) -> List[MISPObject]:
    """Processes VT results using the specific methods per VT object type."""
    created_objects = []
    for result in results:
        if result["type"] == "file":
            created_objects.append(process_file(result["attributes"], event, comment, disable_output))
        elif result["type"] == "url":
            created_objects.append(process_url(result["attributes"], event, comment, disable_output))
        elif result["type"] == "domain":
            created_objects.append(process_domain(result, event, comment))
        elif result["type"] == "ip-address":
            print_err("[IP] Processing IP objects is currently not supported.")
            continue
        else:
            print_err(f"[ERR] Unknown entity type: {result['type']}")
            continue
    return created_objects


def process_file(file: Dict, event: MISPEvent, comment: Optional[str] = None,
                 disable_output: bool = False) -> MISPObject:
    """Adds files to MISP event as MISP objects."""
    sha256 = file.get("sha256", None)
    if not sha256:
        raise KeyError("VirusTotal file object misses sha256 hash. This should not happen.")
    if not disable_output:
        print(f"[FILE] Processing {sha256}...")
    f_obj = event.add_object(name="file", comment=comment if comment else "")
    f_obj.add_attribute("md5", simple_value=file["md5"])
    f_obj.add_attribute("sha1", simple_value=file["sha1"])
    f_obj.add_attribute("sha256", simple_value=sha256)

    names = file.get("names", [])
    if len(names) > 0:
        for name in names:
            f_obj.add_attribute("filename", simple_value=name, to_ids=False)

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

    return f_obj


def process_url(url: Dict, event: MISPEvent, comment: Optional[str] = None, disable_output: bool = False):
    """Adds URLs to MISP event as MISP objects."""
    url_string = url.get("url", None)
    if not url_string:
        raise KeyError("VirusTotal URL object missing the actual URL.")

    if not disable_output:
        print(f"[URL] Processing {url_string.replace('http', 'hxxp').replace('.', '[.]')}")
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


def process_domain(domain: Dict, event: MISPEvent, comment: Optional[str] = None,
                   disable_output: bool = False) -> MISPObject:
    """Adds a domain object to a MISP event. Instead of the attributes sub-dictionary, this function needs the complete
    VT object, in order to use the VT id."""
    domain_name = domain.get("id", None)
    if not domain_name:
        raise KeyError("VirusTotal Domain object missing the ID.")

    if not disable_output:
        print(f"[DOMAIN] Processing {domain_name.replace('.', '[.]')}")

    domain = domain["attributes"]

    d_obj = event.add_object(name="domain-ip", comment=comment if comment else "")
    d_obj.add_attribute("domain", simple_value=domain_name)

    for record in domain.get("last_dns_records", []):
        t = record.get("type", None)
        if not t:
            continue

        if t == "NS":
            d_obj.add_attribute("domain", simple_value=record["value"], comment="NS record", to_ids=False)
        elif t == "A" or t == "AAAA":
            d_obj.add_attribute("ip", type="ip-dst", value=record["value"])
        elif t == "MX":
            d_obj.add_attribute("domain", simple_value=record["value"], comment="MX record", to_ids=False)

    return d_obj


def process_relations(api_key: str, objects: List[MISPObject], event: MISPEvent, relations_string: Optional[str],
                      disable_output: bool = False):
    """Creates related objects based on given relation string."""
    # Todo: Add additional relations
    if not relations_string or len(relations_string) == 0:
        return

    if "," in relations_string:
        relations = relations_string.split(",")
    else:
        relations = [relations_string]

    file_relations = ["execution_parents", "bundled_files", "dropped_files"]

    for rel in relations:
        if rel not in file_relations:
            print_err(f"[REL] Relation {rel} not implemented (yet).")
            continue

        for obj in objects:
            r_objs = get_related_objects(api_key, obj, rel, disable_output)
            for r_obj_dict in r_objs:
                if rel in file_relations:
                    try:
                        r_obj = process_file(
                            file=r_obj_dict["attributes"],
                            event=event,
                            comment=f"Added via {rel} relation.",
                            disable_output=True
                        )
                    except KeyError as e:
                        print_err(f"[ERR] File misses key {e}, skipping...")
                        continue
                    if rel == "execution_parents":
                        r_obj.add_reference(obj.uuid, "executes")
                    elif rel == "bundled_files":
                        obj.add_reference(r_obj.uuid, "contains")
                    elif rel == "dropped_files":
                        obj.add_reference(r_obj.uuid, "drops")
                    else:
                        print_err(f"[REL] Could not determine relationship between {obj.uuid} and {r_obj.uuid}. "
                                  f"Adding as generic \"related-to\".")
                        r_obj.add_reference(obj.uuid, "related-to")


def get_related_objects(api_key: str, obj: MISPObject, rel: str, disable_output: bool = False) -> List[Dict]:
    """Gets related objects from VT."""
    if obj.name == "file":
        vt_id = obj.get_attributes_by_relation("sha256")[0].value
    else:
        print_err("[REL] Currently only file objects are supported.")
        return []

    if not disable_output:
        print(f"[REL] Receiving {rel} for {vt_id}...")

    with VTClient(api_key) as client:
        res = client.get(f"/files/{vt_id}/{rel}").json()
    files = []
    for file in res.get("data", []):
        if "error" in file:
            print_err(f"[REL] File {file['id']} not available on VT.")
        else:
            files.append(file)
    return files


def print_err(*args, **kwargs):
    """Wrapper for printing to stderr."""
    print(*args, **kwargs, file=stderr)


def cli():
    parser = ArgumentParser("vt2m")
    parser.add_argument("--uuid", "-u", type=str, required=True, help="MISP event uuid")
    parser.add_argument("--url", "-U", type=str, help="MISP URL - can also be given as env MISP_URL")
    parser.add_argument("--key", "-k", type=str, help="MISP API key - can also be given as env MISP_KEY")
    parser.add_argument("--vt-key", "-K", type=str, help="VT API key - can also be given as env VT_KEY")
    parser.add_argument("--comment", "-c", type=str, help="Comment to add to MISP objects")
    parser.add_argument("--limit", "-l", type=int, help="Limit results of VT query - default is 100")
    parser.add_argument("--relations", "-r", type=str, help="Comma-seperated list of relations to request PER result "
                                                            "(if type fits). This can burn your API credits. "
                                                            "Currently implemented: dropped_files, executing_parents, "
                                                            "bundled_files")
    parser.add_argument("--quiet", "-q", action="store_true", default=False,
                        help="Disable output. Stderr will still be printed.")
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
        print_err("URL and key must be given either through param or env.")

    misp = PyMISP(url, key)
    misp.global_pythonify = True
    event = misp.get_event(args.uuid)
    results = query(vtkey, args.query, args.limit)
    created_objects = process_results(results, event, args.comment, args.quiet)
    process_relations(vtkey, created_objects, event, args.relations, args.quiet)
    misp.update_event(event)
