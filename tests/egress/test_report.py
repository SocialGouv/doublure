"""Tests de report.py — écrits AVANT l'implémentation (test-first).

Fixtures 100 % synthétiques : aucun hôte réel de l'infrastructure de jo.
Exécution : python3 tests/egress/test_report.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import report  # noqa: E402


def flow(**kw) -> dict:
    base = {
        "kind": "http",
        "host": "api.anthropic.com",
        "port": 443,
        "method": "POST",
        "path": "/v1/messages",
        "bytes_out": 100,
        "bytes_in": 200,
        "status": 200,
        "content_type": "application/json",
        "ts": 1.0,
    }
    base.update(kw)
    return base


KNOWN = {
    "api.anthropic.com": "Trafic modèle (canal 1)",
    "*.sentry.io": "Crash reporting",
    "*.claude.ai": "Services compte Claude",
}


def write_jsonl(dirpath: Path, flows: list[dict]) -> Path:
    p = dirpath / "flows.jsonl"
    p.write_text("".join(json.dumps(f) + "\n" for f in flows), encoding="utf-8")
    return p


class LoadFlowsTest(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = write_jsonl(Path(d), [flow(), flow(host="o1.ingest.sentry.io")])
            flows = report.load_flows(p)
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[1]["host"], "o1.ingest.sentry.io")

    def test_malformed_line_raises(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "flows.jsonl"
            p.write_text('{"kind": "http"}\npas du json\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                report.load_flows(p)


class AggregateTest(unittest.TestCase):
    def test_sums_and_counts(self):
        agg = report.aggregate(
            [
                flow(bytes_out=100, bytes_in=10),
                flow(bytes_out=50, bytes_in=5),
                flow(host="API.ANTHROPIC.COM", bytes_out=1, bytes_in=1),
            ]
        )
        self.assertEqual(list(agg), ["api.anthropic.com"])  # hôte normalisé
        a = agg["api.anthropic.com"]
        self.assertEqual(a["http"], 3)
        self.assertEqual(a["bytes_out"], 151)
        self.assertEqual(a["bytes_in"], 16)

    def test_kinds_separated(self):
        agg = report.aggregate(
            [
                flow(kind="connect", host="cdn.claude.ai", bytes_out=0, bytes_in=0),
                flow(kind="error", host="cdn.claude.ai", error="tls refusée"),
            ]
        )
        a = agg["cdn.claude.ai"]
        self.assertEqual(a["http"], 0)
        self.assertEqual(a["connect"], 1)
        self.assertEqual(a["errors"], 1)

    def test_model_paths_counted(self):
        agg = report.aggregate(
            [flow(path="/v1/messages"), flow(path="/v1/messages"), flow(path="/v1/messages/count_tokens")]
        )
        paths = agg["api.anthropic.com"]["paths"]
        self.assertEqual(paths["/v1/messages"], 2)
        self.assertEqual(paths["/v1/messages/count_tokens"], 1)


class JustifyTest(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(report.justify("api.anthropic.com", KNOWN), "Trafic modèle (canal 1)")

    def test_wildcard_match(self):
        self.assertEqual(report.justify("o123.ingest.sentry.io", KNOWN), "Crash reporting")

    def test_wildcard_does_not_match_bare_domain(self):
        # "*.sentry.io" ne couvre PAS "sentry.io" : une entrée exacte est requise.
        self.assertIsNone(report.justify("sentry.io", KNOWN))

    def test_unknown_host(self):
        self.assertIsNone(report.justify("unexpected.example.net", KNOWN))

    def test_case_insensitive(self):
        self.assertEqual(report.justify("API.Anthropic.Com", KNOWN), "Trafic modèle (canal 1)")


class BuildReportTest(unittest.TestCase):
    def build(self, flows, known=KNOWN, session_rc=0):
        agg = report.aggregate(flows)
        return report.build_report(
            agg, known, session_rc=session_rc, flow_count=len(flows), generated="2026-08-01T00:00:00"
        )

    def test_all_justified_exit_0(self):
        md, rc = self.build([flow(), flow(host="o1.ingest.sentry.io")])
        self.assertEqual(rc, 0)
        self.assertNotIn("NON JUSTIFIÉE", md)
        self.assertIn("api.anthropic.com", md)

    def test_unjustified_host_exit_1(self):
        md, rc = self.build([flow(), flow(host="unexpected.example.net")])
        self.assertEqual(rc, 1)
        self.assertIn("NON JUSTIFIÉE", md)
        self.assertIn("unexpected.example.net", md)

    def test_empty_capture_exit_1(self):
        # Capture vide ≠ absence d'egress : fail-closed.
        md, rc = self.build([])
        self.assertEqual(rc, 1)
        self.assertIn("aucun flux", md.lower())

    def test_failed_session_exit_1(self):
        md, rc = self.build([flow()], session_rc=3)
        self.assertEqual(rc, 1)
        self.assertIn("échec", md.lower())

    def test_model_ratio(self):
        md, rc = self.build([flow(bytes_out=300), flow(host="o1.ingest.sentry.io", bytes_out=100)])
        self.assertEqual(rc, 0)
        self.assertIn("75.0", md)  # 300 / 400 octets sortants vers le modèle

    def test_connect_only_section(self):
        md, rc = self.build(
            [flow(), flow(kind="connect", host="cdn.claude.ai", bytes_out=0, bytes_in=0)]
        )
        self.assertEqual(rc, 0)  # hôte justifié par *.claude.ai
        self.assertIn("non déchiffr", md.lower())
        self.assertIn("cdn.claude.ai", md)


class MainCliTest(unittest.TestCase):
    def test_main_writes_report_and_returns_code(self):
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            flows_p = write_jsonl(dp, [flow(), flow(host="unexpected.example.net")])
            known_p = dp / "known.json"
            known_p.write_text(json.dumps(KNOWN), encoding="utf-8")
            out_p = dp / "report.md"
            rc = report.main(
                [str(flows_p), "--known", str(known_p), "--out", str(out_p), "--session-rc", "0"]
            )
            self.assertEqual(rc, 1)
            md = out_p.read_text(encoding="utf-8")
            self.assertIn("unexpected.example.net", md)
            self.assertIn("NON JUSTIFIÉE", md)

    def test_main_ok(self):
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            flows_p = write_jsonl(dp, [flow()])
            known_p = dp / "known.json"
            known_p.write_text(json.dumps(KNOWN), encoding="utf-8")
            out_p = dp / "report.md"
            rc = report.main([str(flows_p), "--known", str(known_p), "--out", str(out_p)])
            self.assertEqual(rc, 0)
            self.assertTrue(out_p.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
