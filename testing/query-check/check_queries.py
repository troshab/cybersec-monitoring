#!/usr/bin/env python3
"""Push production-shaped fixtures and check repository LogQL using only stdlib."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def dashboard_queries(root):
    def panels(items):
        for panel in items:
            yield panel
            yield from panels(panel.get("panels", []))

    for path in sorted((root / "server/monitoring-stack/grafana/dashboards").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        for panel in panels(data.get("panels", [])):
            for target in panel.get("targets", []):
                datasource = target.get("datasource", panel.get("datasource", {}))
                if "loki" in str(datasource).lower() and target.get("expr"):
                    yield {"file": path.relative_to(root).as_posix(),
                           "name": f"{panel.get('id')}: {panel.get('title')} / {target.get('refId')}",
                           "expr": target["expr"]}


def alert_queries(root):
    # This deliberately handles only the scalar YAML forms used by provisioning.
    # Unknown forms fail closed rather than silently omitting a security rule.
    folder = root / "server/monitoring-stack/grafana/provisioning/alerting"
    for path in sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")]):
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        name = datasource = ""
        for index, line in enumerate(lines):
            uid = re.match(r"\s*- uid:\s*(.+)", line)
            if uid:
                name = uid[1].strip("\"'")
            source = re.match(r"\s*datasourceUid:\s*(.+)", line)
            if source:
                datasource = source[1].strip("\"'")
            expression = re.match(r"(\s*)expr:\s*(.*)", line)
            if not expression or datasource != "loki":
                continue
            raw = expression[2].strip()
            if raw.startswith("'") and raw.endswith("'"):
                expr = raw[1:-1].replace("''", "'")
            elif raw.startswith('"') and raw.endswith('"'):
                expr = json.loads(raw)
            elif raw in ("|", "|-", ">", ">-"):
                parts = []
                for following in lines[index + 1:]:
                    if following.strip() and len(following) - len(following.lstrip()) <= len(expression[1]):
                        break
                    parts.append(following.strip())
                expr = " ".join(parts)
            elif raw and not raw.startswith(("{", "[", "&", "*", "!")):
                expr = raw
            else:
                raise ValueError(f"Unsupported YAML expression at {path}:{index + 1}")
            yield {"file": path.relative_to(root).as_posix(), "name": name, "expr": expr}


def extra_queries(path):
    text = path.read_text(encoding="utf-8-sig")
    if text.lstrip().startswith("["):
        values = json.loads(text)
        for index, value in enumerate(values, 1):
            row = {"expr": value} if isinstance(value, str) else dict(value)
            yield {"file": str(path), "name": row.get("name", str(index)), "expr": row["expr"]}
    else:
        for index, line in enumerate(text.splitlines(), 1):
            if line.strip() and not line.lstrip().startswith("#"):
                yield {"file": str(path), "name": str(index), "expr": line.strip()}


def expand_variables(expr, variables):
    def replace(match):
        name = next(value for value in match.groups() if value is not None)
        name = name.split(":", 1)[0]
        if name not in variables:
            raise ValueError(f"Unresolved Grafana variable: {name}")
        return variables[name]
    return re.sub(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z_0-9]*)", replace, expr)


def request(url, data=None):
    encoded = None if data is None else json.dumps(data, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=encoded,
                                 headers={"Content-Type": "application/json"} if encoded else {})
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read()
        return json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"HTTP {error.code}: {error.read().decode(errors='replace')}") from error


def push_samples(url, directory, now):
    streams = {}
    count = 0
    for path in sorted(directory.glob("*.jsonl")):
        for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            row = json.loads(text)
            labels, line = row["labels"], row["line"]
            if labels.get("job") != path.stem or not isinstance(line, str):
                raise ValueError(f"Invalid fixture {path}:{number}")
            if labels["job"].startswith("windows_"):
                event = json.loads(line)
                if type(event.get("event_id")) is not int or not isinstance(event.get("event_data", ""), str):
                    raise ValueError(f"Not an Alloy Windows event: {path}:{number}")
                forbidden = {"image", "commandLine", "destinationIp", "destinationPort", "user", "source_ip", "logon_type"}
                if forbidden.intersection(event):
                    raise ValueError(f"Non-production top-level event fields: {path}:{number}")
            key = tuple(sorted(labels.items()))
            stream = streams.setdefault(key, {"stream": labels, "values": []})
            stamp = str(now - 30_000_000_000 + count * 1000)
            stream["values"].append([stamp, line])
            count += 1
    if not count:
        raise ValueError(f"No samples found in {directory}")
    request(url + "/loki/api/v1/push", {"streams": list(streams.values())})
    return count


def check_query(url, row, variables, now):
    result = dict(row)
    try:
        concrete = expand_variables(row["expr"], variables)
        result["concrete"] = concrete
        params = urllib.parse.urlencode({"query": concrete, "start": str(now - 60_000_000_000),
                                         "end": str(now), "step": "15", "limit": "1000"})
        payload = request(url + "/loki/api/v1/query_range?" + params)
        if payload.get("status") != "success":
            raise RuntimeError(json.dumps(payload))
        data = payload["data"]
        result["result_type"] = data["resultType"]
        rows = data["result"]
        # Empty formatted lines and runtime parser errors are not successful data.
        if data["resultType"] == "streams":
            if any(item["stream"].get("__error__") for item in rows):
                raise RuntimeError("LogQL pipeline returned __error__ labels")
            present = any(value[1] for item in rows for value in item.get("values", []))
        else:
            present = bool(rows)
        result.update(status="ok" if present else "empty", series=len(rows))
    except (ValueError, KeyError, TypeError, RuntimeError, urllib.error.URLError, TimeoutError) as error:
        result.update(status="error", error=str(error))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loki-url", default=os.environ.get("LOKI_URL"))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--samples", type=Path, default=HERE / "samples")
    parser.add_argument("--extra", action="append", type=Path, default=[])
    parser.add_argument("--var", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--require-nonempty", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if not args.loki_url:
        parser.error("Set LOKI_URL or pass --loki-url (use a disposable Loki only)")
    variables = {"__range": "5m", "__interval": "1m", "__auto": "1m", "__rate_interval": "5m",
                 "__range_s": "300", "__range_ms": "300000", "host": ".+", "hostname": ".+",
                 "instance": ".+", "job": ".+"}
    for option in args.var:
        if "=" not in option:
            parser.error("--var requires NAME=VALUE")
        name, value = option.split("=", 1)
        variables[name.lstrip("$")] = value
    rows = [*dashboard_queries(args.root), *alert_queries(args.root)]
    for path in args.extra:
        rows.extend(extra_queries(path))
    if not rows:
        parser.error("No LogQL expressions found")
    url = args.loki_url.rstrip("/")
    now = time.time_ns()
    sample_count = push_samples(url, args.samples, now)
    results = []
    for row in rows:
        result = check_query(url, row, variables, now)
        results.append(result)
        print(f"{result['status']}: {row['file']} :: {row['name']}")
        if result["status"] == "error":
            print(result["error"])
    counts = {state: sum(row["status"] == state for row in results) for state in ("ok", "empty", "error")}
    report = {"samples": sample_count, "total": len(results), **counts, "results": results}
    if args.report:
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"total={len(results)} ok={counts['ok']} empty={counts['empty']} error={counts['error']}")
    return int(bool(counts["error"] or (args.require_nonempty and counts["empty"])))


if __name__ == "__main__":
    sys.exit(main())
