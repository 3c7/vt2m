from datetime import datetime
from logging import getLogger
from typing import Dict

from rich.table import Table

LOGGER = getLogger("vt2m")


def debug(*args, **kwargs) -> None:
    """Wrapper for Logger.debug."""
    LOGGER.debug(*args, **kwargs)


def info(*args, **kwargs) -> None:
    """Wrapper for Logger.info."""
    LOGGER.info(*args, **kwargs)


def print(*args, **kwargs) -> None:
    """Shadows python print method in order to use typer.echo instead."""
    LOGGER.info(*args, **kwargs)


def warning(*args, **kwargs) -> None:
    """Wrapper for Logger.warning"""
    LOGGER.warning(*args, **kwargs)


def error(*args, **kwargs):
    """Wrapper for Logger.error"""
    LOGGER.error(*args, **kwargs)


def add_object_to_table(t: Table, obj: Dict, *attributes) -> None:
    row = []
    for attrib in attributes:
        keys = attrib.split(".")
        tmp = obj
        for idx, key in enumerate(keys):
            try:
                if idx == len(keys) - 1 and "date" in key:
                    try:
                        tmp = datetime.fromtimestamp(tmp[key]).isoformat()
                    except:
                        tmp = tmp[key]
                        warning(f"Could not parse {tmp} ({key}) as date.")
                else:
                    tmp = tmp[key]
            except KeyError as ke:
                tmp = f"<{ke} not found>"
        if isinstance(tmp, list):
            tmp = ", ".join(tmp)
        row.append(str(tmp))
    t.add_row(*row)


def print_file_object(obj: Dict, *attributes: str) -> None:
    """Print file object with given attributes. Attributes are given in a list of strings which can end with a reserved
    length passed to the format string, e.g., `attributes.sha256,40`."""
    for idx, attrib in enumerate(attributes):
        tmp = obj
        keys = attrib.split(".")
        if "," in keys[-1]:
            keys[-1], length = keys[-1].split(",", maxsplit=1)
        else:
            length = None

        try:
            for idx2, key in enumerate(keys):
                if idx2 == len(keys) - 1 and "date" in key:
                    try:
                        tmp = datetime.fromtimestamp(tmp[key]).isoformat()
                    except:
                        warning(f"[WARN] Tried to parse {keys} as date, but was not successful.")
                        tmp = [key]
                else:
                    tmp = tmp[key]
        except KeyError:
            tmp = "<Not found>"
        if idx + 1 < len(attributes) and len(attributes) > 1:
            if length:
                print(f"{tmp:<{length}}", nl=False)
            else:
                print(tmp + " ", nl=False)
        else:
            if length:
                print(f"{tmp:<{length}}")
            else:
                print(tmp)
