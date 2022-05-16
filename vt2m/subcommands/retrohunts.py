import os
from typing import List

import typer
from pymisp import PyMISP

from vt2m.lib.lib import (
    get_vt_retrohunts,
    get_retrohunt_rules,
    get_vt_retrohunt_files,
    process_results,
    process_relations
)
from vt2m.lib.output import print, print_err, print_file_object

app = typer.Typer(help="Query for retrohunt results.")


@app.command("list")
def list_retrohunts(
        vt_key: str = typer.Option(None, help="VT API Key - can also be set via VT_KEY env"),
        limit: int = typer.Option(40, help="Limit of retrohunts to return"),
        filter: str = typer.Option("", help="Text filter to apply"),
        rules: bool = typer.Option(False, help="Show rules")
):
    """Lists available retrohunts"""
    if not vt_key:
        vt_key = os.getenv("VT_KEY", None)

    if not vt_key:
        print_err("[ERR] VirusTotal key must be given.")
        raise typer.Exit(-1)

    retrohunts = get_vt_retrohunts(
        vt_key=vt_key,
        limit=limit,
        filter=filter
    )
    if len(retrohunts) == 0:
        print_err("No retrohunts found.")
        raise typer.Exit(-1)

    print(f"{'ID':<25}{'Status':<15}{'Finished Date':<25}Matches")
    for item in retrohunts:
        print_file_object(item, "id,25", "attributes.status,15", "attributes.finish_date,25", "attributes.num_matches")
        if rules:
            print("Rules: ", nl=False)
            print(", ".join(get_retrohunt_rules(item)))


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
        print_err("[ERR] Retrohunt ID must be given.")
        raise typer.Exit(-1)

    if not url or not key or not vt_key:
        print_err("[ERR] URL and key must be given either through param or env.")
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
