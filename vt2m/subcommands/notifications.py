import typer
import os
from datetime import datetime

from vt2m.lib.lib import print, print_err, get_vt_notifications

app = typer.Typer(help="Query and process VT notifications")


@app.command("list")
def list_notifications(
        vt_key: str = typer.Option(None, help="VT API Key - can also be set via VT_KEY env"),
        filter: str = typer.Option("", help="Filter to be used for filtering notifications"),
        limit: int = typer.Option(10, help="Amount of notifications to grab")
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
    print(f"{'Rule':<40} | {'Submission Date':<30} | SHA256 Hash")
    for notification in notifications:
        rule = notification.get("context_attributes", {}).get("rule_name", None)
        date = notification.get("context_attributes", {}).get("notification_date", None)
        sha256 = notification.get("attributes", {}).get("sha256", None)
        if date:
            date = datetime.fromtimestamp(date)
        print(f"{rule:<40} | {date.isoformat():<30} | {sha256}")
