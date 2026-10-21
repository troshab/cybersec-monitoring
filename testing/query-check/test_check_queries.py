import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_queries as checker


class QueryRegressionTests(unittest.TestCase):
    def test_extracts_all_dashboard_and_alert_logql(self):
        dashboards = list(checker.dashboard_queries(checker.ROOT))
        alerts = list(checker.alert_queries(checker.ROOT))
        self.assertEqual(len(dashboards), 76)
        self.assertEqual(len(alerts), 14)
        self.assertTrue(any(row["name"] == "ad-object-modified-5136" for row in alerts))
        self.assertFalse(any("<EventID>" in row["expr"] for row in dashboards + alerts))

    def test_expands_variables_but_preserves_logql_templates(self):
        expr = '{host=~"${host:regex}"} | line_format "{{.message}}" [$__range]'
        self.assertEqual(checker.expand_variables(expr, {"host": "LAB-DC01", "__range": "5m"}),
                         '{host=~"LAB-DC01"} | line_format "{{.message}}" [5m]')
        with self.assertRaisesRegex(ValueError, "Unresolved Grafana variable"):
            checker.expand_variables("$missing", {})

    def test_push_preserves_exact_alloy_lines_without_added_fields(self):
        with patch.object(checker, "request") as request:
            total = checker.push_samples("http://test", checker.HERE / "samples", 1_800_000_000_000_000_000)
        payload = request.call_args.args[1]
        submitted = [line for stream in payload["streams"] for _, line in stream["values"]]
        fixture_lines = [json.loads(line)["line"] for path in (checker.HERE / "samples").glob("*.jsonl")
                         for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertCountEqual(submitted, fixture_lines)
        self.assertEqual(total, len(fixture_lines))
        for stream in payload["streams"]:
            if stream["stream"]["job"].startswith("windows_"):
                self.assertNotIn("event_id", stream["stream"])
                for _, line in stream["values"]:
                    self.assertIs(type(json.loads(line)["event_id"]), int)

    def test_journal_fixtures_are_message_only(self):
        path = checker.HERE / "samples/systemd-journal.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(row["line"].startswith("Failed password") for row in rows))
        self.assertTrue(any(row["line"].startswith("Accepted publickey") for row in rows))
        self.assertTrue(any(row["line"].startswith("(root) CMD") for row in rows))
        for row in rows:
            self.assertEqual(row["labels"], {"job": "systemd-journal",
                                             "instance": "monitoring-server", "source": "journal"})
            self.assertNotRegex(row["line"], r"^[A-Za-z_-]+\[\d+\]:")

    def test_extra_files_accept_plain_lines_and_named_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "extra.txt"
            path.write_text('# comment\n{job="auth"}\n', encoding="utf-8")
            self.assertEqual(list(checker.extra_queries(path))[0]["expr"], '{job="auth"}')
            path.write_text(json.dumps([{"name": "test", "expr": '{job="auth"}'}]), encoding="utf-8")
            self.assertEqual(list(checker.extra_queries(path))[0]["name"], "test")

    def test_stream_parser_errors_and_blank_formats_are_not_ok(self):
        row = {"expr": '{job="auth"}'}
        with patch.object(checker, "request", return_value={"status": "success", "data": {
                "resultType": "streams", "result": [{"stream": {"__error__": "JSONParserErr"},
                                                       "values": [["1", "bad"]]}]}}):
            self.assertEqual(checker.check_query("http://test", row, {}, 1)["status"], "error")
        with patch.object(checker, "request", return_value={"status": "success", "data": {
                "resultType": "streams", "result": [{"stream": {}, "values": [["1", ""]]}]}}):
            self.assertEqual(checker.check_query("http://test", row, {}, 1)["status"], "empty")


if __name__ == "__main__":
    unittest.main()
