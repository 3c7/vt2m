# VirusTotal Query to MISP Objects (vt2m)

While there are multiple Python projects which implement the object creation based on single VirusTotal objects, this
project aims to enable users to directly convert VirusTotal search queries to MISP objects.
**This is work in progress.** Future release will implement handling URLs, Domain and IP objects, too. Right now, only
file objects - as a base for queries - are implemented. These file objects can have related IPs, domains and URLs,
though.

## Installation

```
pip install vt2m
```

## Usage

If you use the script frequently, passing the arguments as environment variables (`MISP_URL`, `MISP_KEY`, `VT_KEY`)
can be useful to save some time. For example, this can be achieved through creating a shell script which passes the
environment variables and executes the command with spaces in front, so it does not show up in the shell history.
Something like this:

```bash
#!/usr/bin/env bash

SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
IFS=$SAVEIFS
    MISP_URL="https://my.misp.host.local" MISP_KEY="MyMISPApiKey1234567890" VT_KEY="MyVTApiKey1234567890" /path/to/venv/bin/vt2m "$@"
IFS=$SAVEIFS
```

Changing the IFS is a must, so spaces are not seen as a field seperator.

Overall, `vt2m` supports three commands:

- VirusTotal Intelligence Search via `query`
- Accessing Live Hunting notifications via `notifications` (or `no`)
- Accessing Retrohunt results via `retrohunts` (or `re`)

### VirusTotal Ingelligence Search: `query`

```
Usage: vt2m query [OPTIONS] QUERY

  Query VT for files and add them to a MISP event

Arguments:
  QUERY  VirusTotal Query  [required]

Options:
  -u, --uuid TEXT                MISP event UUID  [required]
  -U, --url TEXT                 MISP URL - can be passed via MISP_URL env
  -K, --key TEXT                 MISP API Key - can be passed via MISP_KEY env
  -k, --vt-key TEXT              VirusTotal API Key - can be passed via VT_KEY
                                 env
  -c, --comment TEXT             Comment for new MISP objects.
  -l, --limit INTEGER            Limit of VirusTotal objects to receive
                                 [default: 100]
  -L, --limit-relations INTEGER  Limit the amount of related objects. Note
                                 that this is for every relation queries.
                                 [default: 40]
  -r, --relations TEXT           Relations to resolve via VirusTotal,
                                 available relations are: execution_parents,
                                 compressed_parents, bundled_files,
                                 dropped_files, contacted_urls, embedded_urls,
                                 itw_urls, contacted_domains,
                                 embedded_domains, itw_domains, contacted_ips,
                                 embedded_ips, itw_ips, submissions,
                                 communicating_files
  -d, --detections INTEGER       Amount of detections a related VirusTotal
                                 object must at least have  [default: 0]
  -D, --extract-domains          Extract domains from URL objects and add them
                                 as related object.
  -f, --filter TEXT              Filtering related objects by matching this
                                 string(s) against json dumps of the objects.
  -p, --pivot TEXT               Pivot from the given query before resolving
                                 relationships. This must be a valid VT file
                                 relation (execution_parents,
                                 compressed_parents, bundled_files,
                                 dropped_files).
  -P, --pivot-limit INTEGER      Limit the amount of files returned by a
                                 pivot.  [default: 40]
  -C, --pivot-comment TEXT       Comment to add to the initial pivot object.
  --pivot-relationship TEXT      MISP relationship type for the relation
                                 between the initial pivot object and the
                                 results.  [default: related-to]
  --help                         Show this message and exit.
```

The `query` command supports ingesting files from a VT search, but additional also requesting specific related files or
infrastructure indicators (via `--relations`) and an initial pivot off the files (via `--pivot`). The latter means that,
e.g., you're able to search for files that are commonly dropped or contained within the samples you're actually
searching for and use the "parent" files as your regular result set, enrichting them with additional relationships etc.

Via `--relations` VirusTotal relations can be resolved and added as MISP objects with the specific relations, e.g. the
following graph was created using vt2m:
![MISP Graph](.github/screenshots/graph.png)
*Graph created
via `vt2m --uuid <UUID> --limit 5 --relations dropped_files,execution_parents "behaviour_processes:\"ping -n 70\""`*

### VirusTotal Livehunt notifications: `notifications`

```
Usage: vt2m notifications [OPTIONS] COMMAND [ARGS]...

  Query and process VT notifications

Options:
  --help  Show this message and exit.

Commands:
  import  Import files related to notifications
  list    List currently available VirusTotal notifications
```

The command allows to list and to import livehunt results via two subcommands.

### VirusTotal Retrohunt results: `retrohunts`

```
Usage: vt2m retrohunts [OPTIONS] COMMAND [ARGS]...

  Query for retrohunt results.

Options:
  --help  Show this message and exit.

Commands:
  import  Imports results of a retrohunt into a MISP event
  list    Lists available retrohunts
```

The command allows to list and to import retrohunt results via two subcommands.

## Examples

### Query for hashes

In order to just ingest files you already found via VirusTotal search, you can query for the file hashes in order to
save VirusTotal queries. This way the command only counts towards regular API calls.

`vt2m query --uuid <MISP Event UUID> "<hash 1> <hash 2> <hash 3> ... <hash n>"`

Of course, the same way you're able to include related objects, e.g. contacted URLs, the according domains and dropped
files during execution.

`vt2m query --uuid <MISP Event UUID> --relations contacted_urls,dropped_files --extract-domains "<hash 1> <hash 2> <hash 3> ... <hash n>"`

### Query using VirusTotal Intelligence Searches

Similar as above, you can directly use VirusTotal search queries for ingesting indicators into MISP events:

`vt2m query --uuid <MISP Event UUID> --relations contacted_urls,dropped_files --extract-domains "imphash:<imphash>"`

### Pivot before query

Sometimes it's necessary to pivot before receiving the actual files. This is useful, if files drop a common file during
execution, or archives have a common file bundled. This can be done this way:

`vt2m query --uuid <MISP Event UUID> --relations contacted_domains,bundled_files --detections 3 --pivot compressed_parents --pivot-comment "RC4 Key" --pivot-limit 20 --pivot-relationship contained-within 99c9440a84cdc428ce140de901452eb334faec49f1f6258acdde1ddcbb34376e`

As this command introduces some parameters that might be not self-explanatory, here is a small breakdown of them:

| Parameter                              | Description                                                                         |
|----------------------------------------|-------------------------------------------------------------------------------------|
| `--uuid`                               | The UUID of the MISP event which will be the ingestion target                       |
| `--relations`                          | VirusTotal relations to query for                                                   |
| `--detections 3`                       | Filter for related objects with at least 3 AV detections                            |
| `--pivot compressed_parents`           | Enable pivot mode and pivot via the relation given                                  |
| `--pivot-comment`                      | Comment to add to the MISP object pivoted from                                      |
| `--pivot-limit 20`                     | Limit the pivot to 20 objects                                                       |
| `--pivot-relationship contaned-within` | MISP relationship between the pivoted object and the results, default is related-to |

The above query is resulting in the following MISP graph:

![MISP graph of the pivot example](.github/screenshots/graph2.png)