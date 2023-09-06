import os
from typing import List

import typer
from pymisp import PyMISP
from rich.box import MINIMAL
from rich.console import Console
from rich.table import Table

from vt2m.lib.lib import warning, error, get_vt_notifications, process_results, process_relations
from vt2m.lib.output import add_object_to_table

app = typer.Typer(help="Query and process VT notifications")


@app.command("list")
def list_notifications(
        vt_key: str = typer.Option(None, "-k", "--vt-key", help="VT API Key - can also be set via VT_KEY env"),
        filter: str = typer.Option("", "-f", "--filter", help="Filter to be used for filtering notifications"),
        limit: int = typer.Option(10, "-l", "--limit", help="Amount of notifications to grab"),
        sha256: bool = typer.Option(False, "-s", "--sha256", help="Only show sha256 hashes")
):
    """List currently available VirusTotal notifications"""
    con = Console()
    if not vt_key:
        vt_key = os.getenv("VT_KEY")

    if not all([vt_key]):
        error("Not all required parameters were given.")
        raise typer.Exit(-1)

    notifications = get_vt_notifications(
        vt_key=vt_key,
        filter=filter,
        limit=limit
    )

    if len(notifications) == 0:
        warning("No notifications found.")
        raise typer.Exit(1)

    if sha256:
        for notification in notifications:
            con.print(notification["attributes"]["sha256"])
    else:
        t = Table(box=MINIMAL)
        t.add_column("Rule Name")
        t.add_column("First Seen")
        t.add_column("SHA256")
        for notification in notifications:
            add_object_to_table(
                t, notification,
                "context_attributes.rule_name", "attributes.first_submission_date", "attributes.sha256"
            )
        con.print(t)


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
        quiet: bool = typer.Option(False, "--quiet", "-q", help="Disable output"),
        no_verifiy: bool = typer.Option(False, "--no-verify", help="Disables MISP TLS certificate validation.")
):
    """Import files related to notifications"""
    if not url:
        url = os.getenv("MISP_URL", None)

    if not key:
        key = os.getenv("MISP_KEY", None)

    if not vt_key:
        vt_key = os.getenv("VT_KEY", None)

    if not url or not key or not vt_key:
        error("URL and key must be given either through param or env.")
        raise typer.Exit(-1)

    misp = PyMISP(url, key, ssl=not no_verifiy)
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
