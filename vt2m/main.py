import os
from typing import List

import typer
from pymisp import PyMISP
from typer import Typer, Option, Argument

from vt2m.lib import lib
from vt2m.lib.output import debug, info, warning, error
from vt2m.subcommands import notifications, retrohunts
from rich.logging import RichHandler
from logging import basicConfig
app = Typer()
state = {
    "verbose": False,
    "quiet": False
}


@app.command()
def query(
        query: str = Argument(..., help="VirusTotal Query"),
        uuid: str = Option(..., "--uuid", "-u", help="MISP event UUID"),
        url: str = Option(None, "--url", "-U", help="MISP URL - can be passed via MISP_URL env"),
        key: str = Option(None, "--key", "-K", help="MISP API Key - can be passed via MISP_KEY env"),
        vt_key: str = Option(None, "--vt-key", "-k", help="VirusTotal API Key - can be passed via VT_KEY env"),
        comment: str = Option("", "--comment", "-c", help="Comment for new MISP objects."),
        limit: int = Option(100, "--limit", "-l", help="Limit of VirusTotal objects to receive"),
        limit_relations: int = Option(
            40,
            "--limit-relations",
            "-L",
            help="Limit the amount of related objects. Note that this is for every relation queries."),
        relations: str = Option(
            "",
            "--relations",
            "-r",
            help=f"Relations to resolve via VirusTotal, available relations are: {', '.join(lib.all_relations)}"
        ),
        detections: int = Option(0, "--detections", "-d",
                                 help="Amount of detections a related VirusTotal object must at least have"),
        extract_domains: bool = Option(False, "--extract-domains", "-D",
                                       help="Extract domains from URL objects and add them as related object."),
        include_api_submissions: bool = Option(
            False, "-A", "--include-api", help="Include submission via api for submissions relation."
        ),
        filter: List[str] = Option(
            [],
            "--filter",
            "-f",
            help="Filtering related objects by matching this string(s) against json dumps of the objects."
        ),
        pivot: str = Option(
            None,
            "-p",
            "--pivot",
            help="Pivot from the given query before resolving relationships. This must be a valid VT file relation "
                 f"({', '.join(lib.file_relations)})."
        ),
        pivot_limit: int = Option(40, "-P", "--pivot-limit", help="Limit the amount of files returned by a pivot."),
        pivot_comment: str = Option(None, "-C", "--pivot-comment", help="Comment to add to the initial pivot object."),
        pivot_relationship: str = Option(
            "related-to",
            "--pivot-relationship",
            help="MISP relationship type for the relation between the initial pivot object and the results."
        ),
        no_verfiy: bool = Option(False, "--no-verify", help="Disables MISP TLS certificate validation.")
):
    """
    Query VT for files and add them to a MISP event
    """
    if not url:
        url = os.getenv("MISP_URL", None)

    if not key:
        key = os.getenv("MISP_KEY", None)

    if not vt_key:
        vt_key = os.getenv("VT_KEY", None)

    if not url or not key or not vt_key:
        error("URL and key must be given either through param or env.")

    if pivot and pivot not in lib.file_relations:
        error("Pivot relationship is not valid or not implemented.")

    misp = PyMISP(url, key, ssl=not no_verfiy)
    misp.global_pythonify = True
    event = misp.get_event(uuid)
    results = lib.vt_query(
        api_key=vt_key,
        query=query,
        limit=limit
    )

    pivot_object = None
    if pivot:
        pivot_results = []
        for r in results:
            pivot_results.extend(
                lib.pivot_from_hash(
                    api_key=vt_key,
                    sha256_hash=r["attributes"]["sha256"],
                    rel=pivot,
                    limit=pivot_limit,
                    disable_output=state["quiet"]
                )
            )
        if len(pivot_results) == 0:
            error("[PIV] No files returned.")
            raise typer.Exit(-1)
        else:
            pivot_object = lib.process_results(
                results=results,
                event=event,
                comment=pivot_comment,
                disable_output=state["quiet"],
                extract_domains=False
            )[0]
            results = pivot_results

    created_objects = lib.process_results(
        results=results,
        event=event,
        comment=comment,
        disable_output=state["quiet"],
        extract_domains=extract_domains
    )
    lib.process_relations(
        api_key=vt_key,
        objects=created_objects,
        event=event,
        relations_string=relations,
        detections=detections,
        disable_output=state["quiet"],
        extract_domains=extract_domains,
        limit=limit_relations,
        filter=filter,
        include_api_submissions=include_api_submissions
    )
    if pivot and pivot_object:
        for obj in created_objects:
            lib.add_reference(pivot_object, obj.uuid, pivot_relationship)
    event.published = False
    misp.update_event(event)


@app.callback()
def callback(
        quiet: bool = Option(False, "-q", "--quiet", help="No output except stderr"),
        verbose: bool = Option(False, "-v", "--verbose", help="Use verbose logging")
):
    basicConfig(
        level="DEBUG" if verbose else "INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
    )
    state["quiet"] = quiet


app.add_typer(notifications.app, name="notifications")
app.add_typer(notifications.app, name="no")
app.add_typer(retrohunts.app, name="retrohunts")
app.add_typer(retrohunts.app, name="re")

if __name__ == "__main__":
    app()
