# VirusTotal Query 2 MISP (vtq2misp)

While there are multiple Python projects which implement the object creation based on single VirusTotal objects, this
project aims to enable users to directly convert VirusTotal search queries to MISP objects.
**This is work in progress.** Future release will implement handling URLs, Domain and IP objects, too. Right now, only
file objects are implemented.

## Installation

```
pip install vtq2misp  # (not yet)
```

## Usage

If you use the script frequently, passing the arguments as environment variables (`MISP_URL`, `MISP_KEY`, `VT_KEY`)
can be useful to save some time. 

```
usage: v2m [-h] --uuid UUID [--url URL] [--key KEY] [--vt-key VT_KEY] [--comment COMMENT] query

positional arguments:
  query                 VT query

optional arguments:
  -h, --help            show this help message and exit
  --uuid UUID, -u UUID  MISP event uuid
  --url URL, -U URL     MISP URL - can also be given as env MISP_URL
  --key KEY, -k KEY     MISP API key - can also be given as env MISP_KEY
  --vt-key VT_KEY, -K VT_KEY
                        VT API key - can also be given as env VT_KEY
  --comment COMMENT, -c COMMENT
                        Comment to add to MISP objects
```
