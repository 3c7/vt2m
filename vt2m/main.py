import os

import typer
from pymisp import PyMISP
from typer import Typer, Option, Argument

from vt2m.lib import lib
from vt2m.subcommands import notifications

app = Typer()
state = {
    "verbose": False,
    "quiet": False
}


@app.command()
def query(
        query: str = Argument(..., help="VirusTotal Query"),
        uuid: str = Option(..., help="MISP event UUID"),
        url: str = Option(None, help="MISP URL - can be passed via MISP_URL env"),
        key: str = Option(None, help="MISP API Key - can be passed via MISP_KEY env"),
        vt_key: str = Option(None, help="VirusTotal API Key - can be passed via VT_KEY env"),
        comment: str = Option("", help="Comment for new MISP objects."),
        limit: int = Option(100, help="Limit of VirusTotal objects to receive"),
        relations: str = Option("", help="Relations to resolve via VirusTotal"),
        detections: int = Option(0, help="Amount of detections a related VirusTotal object must at least have")
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
        typer.echo("URL and key must be given either through param or env.", err=True)

    misp = PyMISP(url, key)
    misp.global_pythonify = True
    event = misp.get_event(uuid)
    results = lib.vt_query(
        api_key=vt_key,
        query=query,
        limit=limit
    )
    created_objects = lib.process_results(
        results=results,
        event=event,
        comment=comment,
        disable_output=state["quiet"]
    )
    lib.process_relations(
        api_key=vt_key,
        objects=created_objects,
        event=event,
        relations_string=relations,
        detections=detections,
        disable_output=state["quiet"]
    )
    event.published = False
    misp.update_event(event)


@app.callback()
def callback(quiet: bool = Option(False, is_flag=True, help="No output except stderr")):
    state["quiet"] = quiet


app.add_typer(notifications.app, name="notifications")

if __name__ == "__main__":
    app()
