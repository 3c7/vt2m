from datetime import datetime
from typing import Dict

import typer


def print(*args, **kwargs) -> None:
    """Shadows python print method in order to use typer.echo instead."""
    typer.echo(*args, **kwargs)


def print_err(s):
    """Wrapper for printing to stderr."""
    if s[:5] == "[ERR]":
        s = typer.style("[ERR]", fg="red") + s[5:]
    elif s[:6] == "[WARN]":
        s = typer.style("[WARN]", fg="yellow") + s[6:]
    print(s, err=True)


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
                        print_err(f"[WARN] Tried to parse {keys} as date, but was not successful.")
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
