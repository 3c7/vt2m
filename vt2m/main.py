import os
from typing import List

from pymisp import PyMISP
from typer import Typer, Option, Argument

from vt2m.lib import lib
from vt2m.lib.output import print_err
from vt2m.subcommands import notifications, retrohunts

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
        relations: str = Option("", "--relations", "-r", help=f"Relations to resolve via VirusTotal, available "
                                                              f"relations are: {', '.join(lib.all_relations)}"),
        detections: int = Option(0, "--detections", "-d",
                                 help="Amount of detections a related VirusTotal object must at least have"),
        extract_domains: bool = Option(False, "--extract-domains", "-D",
                                       help="Extract domains from URL objects and add them as related object."),
        filter: List[str] = Option([], "--filter", "-f", help="Filtering related objects by matching this string(s) "
                                                              "against json dumps of the objects.")
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
        print_err("[ERR] URL and key must be given either through param or env.")

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
        filter=filter
    )
    event.published = False
    misp.update_event(event)


@app.callback()
def callback(quiet: bool = Option(False, is_flag=True, help="No output except stderr")):
    state["quiet"] = quiet


app.add_typer(notifications.app, name="notifications")
app.add_typer(notifications.app, name="no")
app.add_typer(retrohunts.app, name="retrohunts")
app.add_typer(retrohunts.app, name="re")

if __name__ == "__main__":
    app()
