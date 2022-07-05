import json
import re
from datetime import datetime
from typing import Generator, Union, List, Optional, Dict
from urllib.parse import quote_plus, urlparse

import requests
import typer
from pymisp import MISPEvent, MISPObject
from vt import Client as VTClient

from vt2m.lib.output import print, print_err

file_relations = ["execution_parents", "compressed_parents", "bundled_files", "dropped_files"]
url_relations = ["contacted_urls", "embedded_urls", "itw_urls"]
domain_relations = ["contacted_domains", "embedded_domains", "itw_domains"]
ip_relations = ["contacted_ips", "embedded_ips", "itw_ips"]
user_account_relations = ["submissions"]
communication_relations = ["communicating_files"]
all_relations = []
all_relations.extend(file_relations)
all_relations.extend(url_relations)
all_relations.extend(domain_relations)
all_relations.extend(ip_relations)
all_relations.extend(user_account_relations)
all_relations.extend(communication_relations)


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

    response = vt_request(
        api_key=api_key,
        url=f"https://www.virustotal.com/api/v3/intelligence/search?query={quote_plus(query)}&limit={limit}"
    )
    if "error" in response and len(response["error"] > 0):
        print_err(f"Received error from VT API: {response['error']}")
        raise typer.Exit(-1)

    return response["data"]


def process_results(results: Union[Generator, List], event: MISPEvent, comment: Optional[str],
                    disable_output: bool = False, extract_domains: bool = False) -> List[MISPObject]:
    """Processes VT results using the specific methods per VT object type."""
    created_objects = []
    for result in results:
        if result["type"] == "file":
            created_objects.append(
                process_file(
                    file=result["attributes"],
                    event=event,
                    comment=comment,
                    disable_output=disable_output
                )
            )
        elif result["type"] == "url":
            created_objects.append(
                process_url(
                    url=result["attributes"],
                    event=event,
                    comment=comment,
                    disable_output=disable_output,
                    extract_domain=extract_domains
                )
            )
        elif result["type"] == "domain":
            created_objects.append(
                process_domain(
                    domain=result,
                    event=event,
                    comment=comment,
                    disable_output=disable_output
                )
            )
        elif result["type"] == "ip-address":
            created_objects.append(
                process_ip(
                    ip=result,
                    event=event,
                    comment=comment,
                    disable_output=disable_output
                )
            )
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
    fs = file.get("first_submission_date", None)
    if fs:
        f_obj.first_seen = datetime.fromtimestamp(fs)

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


def process_url(url: Dict, event: MISPEvent, comment: Optional[str] = None, disable_output: bool = False,
                extract_domain: bool = False) -> MISPObject:
    """Adds URLs to MISP event as MISP objects."""
    url_string = url.get("url", None)
    if not url_string:
        raise KeyError("VirusTotal URL object missing the actual URL.")

    if not disable_output:
        print(f"[URL] Processing {url_string.replace('http', 'hxxp').replace('.', '[.]')}")

    _, domain, resource_path, _, query_string, _ = urlparse(url_string)
    port = None
    if domain.count(":") == 1:
        ip, port = domain.split(":")
        if 0 < int(port, base=10) < 65536:
            domain = ip
    u_obj = get_object_if_available(event, "url", "url", url_string)
    if u_obj:
        if extract_domain:
            create_domain_from_url(event, domain, u_obj, disable_output)
        return u_obj

    u_obj = event.add_object(name="url", comment=comment if comment else "")
    u_obj.add_attribute("url", simple_value=url_string)
    u_obj.add_attribute("domain", simple_value=domain, to_ids=False)
    if resource_path:
        u_obj.add_attribute("resource_path", simple_value=resource_path)
    if query_string:
        u_obj.add_attribute("query_string", simple_value=query_string)
    if port:
        u_obj.add_attribute("port", simple_value=port)

    u_obj.add_attribute("first-seen", type="datetime", value=datetime.fromtimestamp(url["first_submission_date"]))
    u_obj.add_attribute("last-seen", type="datetime", value=datetime.fromtimestamp(url["last_submission_date"]))

    if extract_domain:
        create_domain_from_url(event, domain, u_obj, disable_output)
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


def process_ip(ip: Dict, event: MISPEvent, comment: Optional[str] = None, disable_output: bool = False) -> MISPObject:
    """Adds a domain-ip object to the MISP event. Instead of the attributes sub-dictionary, this function needs the
    complete VT object, in order to use the VT id. """
    ip_str = ip.get("id", None)
    if not ip_str:
        raise KeyError("VirusTotal IP object missing the ID.")

    if not disable_output:
        print(f"[IP] Processing {ip_str.replace('.', '[.]')}.")

    i_obj = get_object_if_available(event, "domain-ip", "ip", ip_str)
    if i_obj:
        return i_obj

    ip = ip["attributes"]

    i_obj = event.add_object(name="domain-ip", comment=comment if comment else "")
    i_obj.add_attribute("ip", type="ip-dst", value=ip_str)
    i_obj.add_attribute("text", simple_value=f"AS: {ip.get('as_owner', 'not available')}")

    cert = ip.get("last_https_certificate", None)
    if cert:
        cn = cert.get("subject", {}).get("CN", None)
        if cn:
            i_obj.add_attribute("domain", type="domain", value=cn, comment="Certificate Subject Common Name")

        for alt in cert.get("extensions", {}).get("subject_alternative_name", []):
            i_obj.add_attribute("domain", type="domain", value=alt, comment="Certificate Subject Alternative Name")

    return i_obj


def process_submission(submission: Dict, event: MISPEvent, comment: Optional[str] = None,
                       disable_output: bool = False) -> MISPObject:
    """Adds a virustotal-submission object to the given MISP event."""
    s_id = submission.get("source_key")
    if not disable_output:
        print(f"[SUB] Processing submission from submitter {s_id}.")

    s_obj = get_object_if_available(event, "virustotal-submission", "submitter-id", s_id)
    if s_obj:
        return s_obj

    s_obj = event.add_object(name="virustotal-submission", comment=comment if comment else "")
    s_obj.add_attribute("submitter-id", type="text", value=s_id)

    country = submission.get("country", None)
    if country:
        s_obj.add_attribute("country", type="text", value=country)

    city = submission.get("city", None)
    if city:
        s_obj.add_attribute("city", type="text", value=city)

    interface = submission.get("interface", None)
    if interface:
        s_obj.add_attribute("interface", type="text", value=interface)

    upload_date = submission.get("date", None)
    if upload_date:
        upload_date = datetime.fromtimestamp(upload_date)
        s_obj.add_attribute("date", type="datetime", value=upload_date)

    filename = submission.get("filename", None)
    if filename:
        s_obj.add_attribute("filename", type="filename", value=filename)

    return s_obj


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
                      detections: Optional[int], disable_output: bool = False, extract_domains: bool = False,
                      filter=None):
    """Creates related objects based on given relation string."""
    # Todo: Add additional relations
    if not relations_string or len(relations_string) == 0:
        return

    if "," in relations_string:
        relations = relations_string.split(",")
    else:
        relations = [relations_string]

    for rel in relations:
        if rel not in all_relations:
            print_err(f"[REL] Relation {rel} not implemented (yet).")
            continue

        for obj in objects:
            r_objs = get_related_objects(api_key, obj, rel, disable_output)
            filtered = False
            for r_obj_dict in r_objs:
                if filter:
                    filtered = False
                    json_string = json.dumps(r_obj_dict)
                    for f in filter:
                        if f in json_string:
                            if not disable_output:
                                print(f"[FILTER] Filter {f} matched object {r_obj_dict.get('id', '<ID not given>')}, "
                                      f"skipping...")
                            filtered = True
                            break
                if filtered:
                    continue
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
                            disable_output=True,
                            extract_domain=extract_domains
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
                        print_err(f"[ERR] Domain misses key {e}, skipping...")
                        continue
                elif rel in ip_relations:
                    try:
                        r_obj = process_ip(
                            ip=r_obj_dict,
                            event=event,
                            comment=f"Added via {rel} relation.",
                            disable_output=True
                        )
                    except KeyError as e:
                        print_err(f"[ERR] IP misses key {e}, skipping...")
                        continue
                elif rel in user_account_relations:
                    try:
                        r_obj = process_submission(
                            submission=r_obj_dict["attributes"],
                            event=event,
                            comment=f"Added via {rel} relation."
                        )
                    except KeyError as e:
                        print_err(f"[ERR] Submission misses key {e}, skipping...")
                        continue
                elif rel in communication_relations:
                    try:
                        r_obj = process_file(
                            file=r_obj_dict["attributes"],
                            event=event,
                            disable_output=True,
                            comment=f"Added via {rel} relation."
                        )
                    except KeyError as e:
                        print_err(f"[ERR] File misses key {e}, skipping...")
                        continue
                else:
                    print_err(f"[ERR] Could not process returned object \"{r_obj_id}\".")
                    continue

                try:
                    if rel == "execution_parents":
                        add_reference(r_obj, obj.uuid, "executes")
                    elif rel == "compressed_parents":
                        add_reference(r_obj, obj.uuid, "contains")
                    elif rel == "bundled_files":
                        add_reference(obj, r_obj.uuid, "contains")
                    elif rel == "dropped_files":
                        add_reference(obj, r_obj.uuid, "drops")
                    elif "embedded_" in rel:
                        add_reference(obj, r_obj.uuid, "contains")
                    elif "contacted_" in rel:
                        add_reference(obj, r_obj.uuid, "connects-to")
                    elif "itw_" in rel:
                        add_reference(obj, r_obj.uuid, "downloaded-from")
                    elif rel == "submissions":
                        add_reference(r_obj, obj.uuid, "submitted")
                    elif rel == "communicating_files":
                        add_reference(r_obj, obj.uuid, "connects-to")
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
    elif obj.name == "domain-ip":
        vt_id = obj.get_attributes_by_relation("domain")[0].value
    else:
        print_err("[REL] Currently only file and domain objects are supported.")
        return []

    if not disable_output:
        print(f"[REL] Receiving {rel} for {vt_id}...")

    with VTClient(api_key) as client:
        if obj.name == "file":
            res = client.get(f"/files/{vt_id}/{rel}?limit=40").json()
        elif obj.name == "domain-ip":
            res = client.get(f"/domains/{vt_id}/{rel}?limit=40").json()
    if "error" in res:
        print_err(f"[REL] Error during receiving related objects: {res['error']}.")
        return []

    related_objects = []
    for related_object in res.get("data", []):
        if "error" in related_object:
            print_err(f"[REL] Object {related_object['id']} not available on VT.")
        else:
            related_objects.append(related_object)
    if not disable_output:
        print(f"[REL] Got {len(related_objects)} {rel} objects.")
    return related_objects


def get_vt_notifications(
        vt_key: str,
        filter: Optional[str] = None,
        limit: int = 10
) -> List:
    """Requests notifications from VT API. Applies an optional filter."""
    url = f"https://www.virustotal.com/api/v3/intelligence/hunting_notification_files?limit={limit}"
    if filter:
        url += f"&filter={quote_plus(filter)}"

    data = vt_request(api_key=vt_key, url=url)
    if "error" in data:
        print_err(f"[ERR] Error occured during receiving notifications: {data['error']}")
        return []
    return data["data"]


def create_domain_from_url(event: MISPEvent, domain: str, u_obj: MISPObject, disable_output: bool = False):
    """Creates domain object from url object and adds a relation."""
    if domain and len(domain) > 0:
        if re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", domain):
            attribute_type = "ip"
        elif ":" in domain:
            attribute_type = "ip"
        else:
            attribute_type = "domain"

        d_obj = get_object_if_available(event, "domain-ip", attribute_type, domain)
        if not d_obj:
            d_obj = event.add_object(name="domain-ip", comment=f"Extracted {attribute_type}")
            d_obj.add_attribute(attribute_type, simple_value=domain)
        add_reference(u_obj, d_obj.uuid, "contains")
        if not disable_output:
            print(f"[REL] Extracted {attribute_type} from {object_represent_string(u_obj)}.")


def object_represent_string(obj: MISPObject, include_uuid: bool = False) -> str:
    """Returns a string which represents the object."""
    if obj.name == "file":
        repr = obj.get_attributes_by_relation("sha256").pop()
    elif obj.name == "domain-ip":
        repr = obj.get_attributes_by_relation("domain").pop()
        if not repr:
            repr = obj.get_attributes_by_relation("ip").pop()
    elif obj.name == "url":
        repr = obj.get_attributes_by_relation("url").pop()
    else:
        s = f"[ERR] Given object name/type unknown: {obj.name}."
        print_err(s)
        raise TypeError(s)

    if not repr:
        s = f"[ERR] Given object does not include its representative attribute: {obj.to_json()}"
        print_err(s)
        raise KeyError(s)

    defanged = repr.value.replace("http", "hxxp").replace(".", "[.]")

    if include_uuid:
        return defanged + "(" + obj.uuid + ")"

    return defanged


def get_vt_retrohunts(vt_key: str, limit: Optional[int] = 40, filter: Optional[str] = "") -> List[Dict]:
    """Loads available retrohunts from the VT API."""
    url = f"https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs?limit={limit}"
    if filter:
        url += f"&filter={quote_plus(filter)}"

    data = vt_request(api_key=vt_key, url=url)
    if "error" in data:
        print_err(f"[ERR] Error occured during receiving notifications: {data['error']}")
        return []
    return data["data"]


def get_retrohunt_rules(r: Dict) -> List[str]:
    """Extracts rules used within a retrohunt."""
    rules = []
    for line in r.get("attributes", {}).get("rules", "").splitlines():
        line = line.strip()
        if "rule" in line[:4]:
            line = line.split("{")[0]
            line = line.split(":")[0]
            line = line[4:].strip()
            rules.append(line)
    return rules


def get_vt_retrohunt_files(vt_key: str, r_id: str, limit: Optional[int] = 100):
    """Retrieve file objects related to a retrohunt from VT."""
    url = f"https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/{r_id}/matching_files?limit={limit}"

    data = vt_request(api_key=vt_key, url=url)
    if "error" in data:
        print_err(f"[ERR] Error occured during receiving notifications: {data['error']}")
        return []
    return data["data"]
