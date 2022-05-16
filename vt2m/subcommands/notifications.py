import os
from typing import List

import typer
from pymisp import PyMISP

from vt2m.lib.lib import print, print_err, get_vt_notifications, process_results, process_relations
from vt2m.lib.output import print_file_object

app = typer.Typer(help="Query and process VT notifications")


@app.command("list")
def list_notifications(
        vt_key: str = typer.Option(None, help="VT API Key - can also be set via VT_KEY env"),
        filter: str = typer.Option("", help="Filter to be used for filtering notifications"),
        limit: int = typer.Option(10, help="Amount of notifications to grab"),
        sha256: bool = typer.Option(False, "-s", "--sha256", help="Only show sha256 hashes")
):
    """List currently available VirusTotal notifications"""
    if not vt_key:
        vt_key = os.getenv("VT_KEY")

    if not all([vt_key]):
        print_err("[ERR] Not all required parameters were given.")
        raise typer.Abort()

    notifications = get_vt_notifications(
        vt_key=vt_key,
        filter=filter,
        limit=limit
    )

    if len(notifications) == 0:
        print_err("[WARN] No notifications found.")
        raise typer.Exit(1)

    if not sha256:
        print(f"{'Rule':<40}{'Submission Date':<30}SHA256 Hash")

    for notification in notifications:
        if sha256:
            print_file_object(notification, "attributes.sha256")
        else:
            print_file_object(
                notification,
                "context_attributes.rule_name,40",
                "attributes.first_submission_date,30",
                "attributes.sha256"
            )


@app.command("import")
def import_notifications(
        vt_key: str = typer.Option(None, help="VT API Key - can also be set via VT_KEY env"),
        filter: str = typer.Option("", help="Filter to be used for filtering notifications"),
        limit: int = typer.Option(10, help="Amount of notifications to grab"),
        uuid: str = typer.Option(..., "--uuid", "-u", help="MISP event UUID"),
        url: str = typer.Option(None, "--url", "-U", help="MISP URL - can be passed via MISP_URL env"),
        key: str = typer.Option(None, "--key", "-K", help="MISP API Key - can be passed via MISP_KEY env"),
        comment: str = typer.Option("", "--comment", "-c", help="Comment for new MISP objects"),
        relations: str = typer.Option("", "--relations", "-r", help="Relations to resolve via VirusTotal"),
        detections: int = typer.Option(0, "--detections", "-d",
                                       help="Amount of detections a related VirusTotal object must at least have"),
        extract_domains: bool = typer.Option(False, "--extract-domains", "-D",
                                             help="Extract domains from URL objects and add them as related object"),
        relation_filter: List[str] = typer.Option([], "--filter", "-f",
                                                  help="Filtering related objects by matching this string(s) "
                                                       "against json dumps of the objects"),
        quiet: bool = typer.Option(False, "--quiet", "-q", help="Disable output")
):
    """Import files related to notifications"""
    if not url:
        url = os.getenv("MISP_URL", None)

    if not key:
        key = os.getenv("MISP_KEY", None)

    if not vt_key:
        vt_key = os.getenv("VT_KEY", None)

    if not url or not key or not vt_key:
        print_err("[ERR] URL and key must be given either through param or env.")
        raise typer.Exit(-1)

    misp = PyMISP(url, key)
    misp.global_pythonify = True
    event = misp.get_event(uuid)

    files = get_vt_notifications(
        vt_key=vt_key,
        filter=filter,
        limit=limit
    )
    created_objects = process_results(
        results=files,
        event=event,
        comment=comment,
        disable_output=quiet,
        extract_domains=extract_domains
    )
    process_relations(
        api_key=vt_key,
        objects=created_objects,
        event=event,
        relations_string=relations,
        detections=detections,
        disable_output=quiet,
        extract_domains=extract_domains,
        filter=relation_filter
    )
    event.published = False
    misp.update_event(event)
