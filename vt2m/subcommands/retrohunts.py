import os
from typing import List

import typer
from pymisp import PyMISP
from rich.box import MINIMAL
from rich.console import Console
from rich.table import Table

from vt2m.lib.lib import (
    get_vt_retrohunts,
    get_vt_retrohunt_files,
    process_results,
    process_relations
)
from vt2m.lib.output import warning, error, add_object_to_table

app = typer.Typer(help="Query for retrohunt results.")


@app.command("list")
def list_retrohunts(
        vt_key: str = typer.Option(None, "-k", "--vt-key", help="VT API Key - can also be set via VT_KEY env"),
        filter: str = typer.Option("", "-f", "--filter", help="Filter to be used for filtering retrohunts"),
        limit: int = typer.Option(10, "-l", "--limit", help="Amount of retrohunts to grab"),
        rules: bool = typer.Option(False, "-r", "--rules", help="Include rules.")
):
    """Lists available retrohunts"""
    con = Console()
    if not vt_key:
        vt_key = os.getenv("VT_KEY", None)

    if not vt_key:
        error("VirusTotal key must be given.")
        raise typer.Exit(-1)

    retrohunts = get_vt_retrohunts(
        vt_key=vt_key,
        limit=limit,
        filter=filter
    )
    if len(retrohunts) == 0:
        warning("No retrohunts found.")
        raise typer.Exit(-1)

    t = Table(box=MINIMAL)
    t.add_column("ID")
    t.add_column("Status")
    t.add_column("Finished Date")
    if rules:
        t.add_column("Rules")
    t.add_column("# Matches")
    for item in retrohunts:
        if not rules:
            add_object_to_table(
                t, item, "id", "attributes.status", "attributes.finish_date", "attributes.num_matches"
            )
        else:
            add_object_to_table(
                t, item, "id", "attributes.status", "attributes.finish_date", "attributes.rules",
                "attributes.num_matches"
            )
    con.print(t)


@app.command("import")
def import_retrohunt(
        rid: str = typer.Argument(..., help="Retrohunt ID"),
        vt_key: str = typer.Option(None, help="VT API Key - can also be set via VT_KEY env"),
        uuid: str = typer.Option(..., "--uuid", "-u", help="MISP event UUID"),
        url: str = typer.Option(None, "--url", "-U", help="MISP URL - can be passed via MISP_URL env"),
        key: str = typer.Option(None, "--key", "-K", help="MISP API Key - can be passed via MISP_KEY env"),
        comment: str = typer.Option("", "--comment", "-c", help="Comment for new MISP objects"),
        limit: int = typer.Option(100, "--limit", "-l", help="Limit of VirusTotal objects to receive"),
        relations: str = typer.Option("", "--relations", "-r", help="Relations to resolve via VirusTotal"),
        detections: int = typer.Option(0, "--detections", "-d",
                                       help="Amount of detections a related VirusTotal object must at least have"),
        extract_domains: bool = typer.Option(False, "--extract-domains", "-D",
                                             help="Extract domains from URL objects and add them as related object"),
        filter: List[str] = typer.Option([], "--filter", "-f",
                                         help="Filtering related objects by matching this string(s) "
                                              "against json dumps of the objects"),
        quiet: bool = typer.Option(False, "--quiet", "-q", help="Disable output")
):
    """Imports results of a retrohunt into a MISP event"""
    if not url:
        url = os.getenv("MISP_URL", None)

    if not key:
        key = os.getenv("MISP_KEY", None)

    if not vt_key:
        vt_key = os.getenv("VT_KEY", None)

    if not rid:
        error("Retrohunt ID must be given.")
        raise typer.Exit(-1)

    if not url or not key or not vt_key:
        error("URL and key must be given either through param or env.")
        raise typer.Exit(-1)

    misp = PyMISP(url, key)
    misp.global_pythonify = True
    event = misp.get_event(uuid)

    files = get_vt_retrohunt_files(
        vt_key=vt_key,
        r_id=rid,
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
        filter=filter
    )
    event.published = False
    misp.update_event(event)
