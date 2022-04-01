from datetime import datetime
from typing import Generator, Union, List, Optional, Dict
from urllib.parse import quote_plus, urlparse

import requests
import typer
from pymisp import MISPEvent, MISPObject
from vt import Client as VTClient


def vt_request(api_key: str, url: str):
    """Use this instead of the VT API client."""
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code > 302:
        print_err("[WARN] Status code received from VT API is > 302.")

    return response.json()


def vt_query(api_key: str, query: str, limit: Optional[int]) -> List:
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

    f_obj = get_object_if_available(event, "file", "sha256", sha256)
    if f_obj:
        return f_obj

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


def process_url(url: Dict, event: MISPEvent, comment: Optional[str] = None, disable_output: bool = False) -> MISPObject:
    """Adds URLs to MISP event as MISP objects."""
    url_string = url.get("url", None)
    if not url_string:
        raise KeyError("VirusTotal URL object missing the actual URL.")

    if not disable_output:
        print(f"[URL] Processing {url_string.replace('http', 'hxxp').replace('.', '[.]')}")

    u_obj = get_object_if_available(event, "url", "url", url_string)
    if u_obj:
        return u_obj

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
    return u_obj


def process_domain(domain: Dict, event: MISPEvent, comment: Optional[str] = None,
                   disable_output: bool = False) -> MISPObject:
    """Adds a domain object to a MISP event. Instead of the attributes sub-dictionary, this function needs the complete
    VT object, in order to use the VT id."""
    domain_name = domain.get("id", None)
    if not domain_name:
        raise KeyError("VirusTotal Domain object missing the ID.")

    if not disable_output:
        print(f"[DOMAIN] Processing {domain_name.replace('.', '[.]')}")

    d_obj = get_object_if_available(event, "domain-ip", "domain", domain_name)
    if d_obj:
        return d_obj

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


def get_object_if_available(event: MISPEvent, object_name: str, attribute_relation: str,
                            value: str) -> Union[MISPObject, None]:
    """Returns an object if it's already available in the MISP event."""
    objects = event.get_objects_by_name(object_name)
    for obj in objects:
        attributes = obj.get_attributes_by_relation(attribute_relation)
        for attribute in attributes:
            if attribute.value == value:
                value = value.replace("http", "hxxp").replace(".", "[.]")
                print_err(f"[{object_name.upper().split('-')[0]}] Object with value {value} already available.")
                return obj
    return None


def process_relations(api_key: str, objects: List[MISPObject], event: MISPEvent, relations_string: Optional[str],
                      detections: Optional[int], disable_output: bool = False):
    """Creates related objects based on given relation string."""
    # Todo: Add additional relations
    if not relations_string or len(relations_string) == 0:
        return

    if "," in relations_string:
        relations = relations_string.split(",")
    else:
        relations = [relations_string]

    file_relations = ["execution_parents", "bundled_files", "dropped_files"]
    url_relations = ["contacted_urls", "embedded_urls", "itw_urls"]
    domain_relations = ["contacted_domains", "embedded_domains", "itw_domains"]

    for rel in relations:
        if rel not in file_relations and rel not in url_relations and rel not in domain_relations:
            print_err(f"[REL] Relation {rel} not implemented (yet).")
            continue

        for obj in objects:
            r_objs = get_related_objects(api_key, obj, rel, disable_output)
            for r_obj_dict in r_objs:
                r_obj_id = r_obj_dict.get("id", "<NO ID GIVEN>").replace(".", "[.]")

                # Check the detection
                stats_malicious = r_obj_dict["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
                if detections and isinstance(detections, int):
                    if not isinstance(stats_malicious, int):
                        print_err("[REL] Detection stats for are not given as integer therefore skipping the "
                                  "check.")
                    else:
                        if stats_malicious < detections:
                            if not disable_output:
                                print(f"[REL] Skipping {r_obj_id} because malicious detections are lower than "
                                      f"{detections}.")
                            continue

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
                elif rel in url_relations:
                    try:
                        r_obj = process_url(
                            url=r_obj_dict["attributes"],
                            event=event,
                            comment=f"Added via {rel} relation.",
                            disable_output=True
                        )
                    except KeyError as e:
                        print_err(f"[ERR] URL misses key {e}, skipping...")
                        continue
                elif rel in domain_relations:
                    try:
                        r_obj = process_domain(
                            domain=r_obj_dict,
                            event=event,
                            comment=f"Added via {rel} relation.",
                            disable_output=True
                        )
                    except KeyError as e:
                        print_err(f"[ERR] URL misses key {e}, skipping...")
                        continue
                else:
                    print_err(f"[ERR] Could not process returned object \"{r_obj_id}\".")
                    continue

                try:
                    if rel == "execution_parents":
                        add_reference(r_obj, obj.uuid, "executes")
                    elif rel == "bundled_files":
                        add_reference(obj, r_obj.uuid, "contains")
                    elif rel == "dropped_files":
                        add_reference(obj, r_obj.uuid, "drops")
                    elif "embedded_" in rel:
                        add_reference(obj, r_obj.uuid, "contains")
                    elif "contacted_" in rel:
                        add_reference(obj, r_obj.uuid, "contacts")
                    elif "itw_" in rel:
                        add_reference(obj, r_obj.uuid, "downloaded-from")
                    else:
                        print_err(f"[REL] Could not determine relationship between {obj.uuid} and {r_obj.uuid}. "
                                  f"Adding as generic \"related-to\".")
                        r_obj.add_reference(obj.uuid, "related-to")
                except AttributeError as ae:
                    print_err(f"[ERR] Related object {r_obj_id} missing an attribute: {ae}")
                    # If the related object is not none, let's dump it to see what's wrong
                    if r_obj:
                        print_err(f"[ERR] Remote object dump:\n{r_obj.to_json()}")
                    continue


def add_reference(obj: MISPObject, to_obj_uuid: str, relationship_type: str):
    """Adds a reference, if not already available."""
    if not reference_available(obj, to_obj_uuid, relationship_type):
        obj.add_reference(to_obj_uuid, relationship_type)
    else:
        print_err(f"[REL] {obj.uuid} --{relationship_type}-> {to_obj_uuid} already available and therefore skipped.")


def reference_available(obj: MISPObject, referenced_uuid: str, relationship_type: str) -> bool:
    """Loops over given relationships and returns true if any relationship references the given uuid and type."""
    for ref in obj.references:
        if ref.referenced_uuid == referenced_uuid and ref.relationship_type == relationship_type:
            return True
    return False


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
        res = client.get(f"/files/{vt_id}/{rel}?limit=40").json()
    if "error" in res:
        print_err(f"[REL] Error during receiving related objects: {res['error']}.")
        return []

    related_objects = []
    for related_object in res.get("data", []):
        if "error" in related_object:
            print_err(f"[REL] File {related_object['id']} not available on VT.")
        else:
            related_objects.append(related_object)
    if not disable_output:
        print(f"[REL] Got {len(related_objects)} {rel} objects.")
    return related_objects


def print_err(s):
    """Wrapper for printing to stderr."""
    if s[:5] == "[ERR]":
        s = typer.style("[ERR]", fg="red") + s[5:]
    elif s[:6] == "[WARN]":
        s = typer.style("[WARN]", fg="yellow") + s[6:]
    print(s, err=True)


def print(*args, **kwargs):
    """Wraps typer.echo for proper console output."""
    typer.echo(*args, **kwargs)


def get_vt_notifications(
        vt_key: str,
        filter: Optional[str] = None,
        limit: int = 10
) -> Dict:
    """Requests notifications from VT API."""
    url = f"https://www.virustotal.com/api/v3/intelligence/hunting_notification_files?limit={limit}"
    if filter:
        url += f"&filter={quote_plus(filter)}"

    data = vt_request(api_key=vt_key, url=url)
    if "error" in data:
        print_err(f"[ERR] Error occured during receiving notifications: {data['error']}")
        return {}
    return data["data"]
