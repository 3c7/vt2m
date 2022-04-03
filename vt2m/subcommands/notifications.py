import os

import typer

from vt2m.lib.lib import print, print_err, get_vt_notifications
from vt2m.lib.output import print_file_object

app = typer.Typer(help="Query and process VT notifications")


@app.command("list")
def list_notifications(
        vt_key: str = typer.Option(None, help="VT API Key - can also be set via VT_KEY env"),
        filter: str = typer.Option("", help="Filter to be used for filtering notifications"),
        limit: int = typer.Option(10, help="Amount of notifications to grab"),
        sha256: bool = typer.Option(False, "-s", "--sha256", help="Only show sha256 hashes")
):
    """
    List currently available VirusTotal notifications and filter them using --filter.
    """
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
