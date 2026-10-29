# -*- coding: utf-8 -*-
"""
Validation tests for the Sigma rules.

How it works:
  1. Each rule is parsed and converted by pySigma's SQLite backend — the real Sigma
     toolchain, not a re-implementation of Sigma's matching logic.
  2. The sample events in sample_events.json are loaded into an in-memory SQLite
     table called `logs` (the table the backend's queries read).
  3. The generated query is run, and the set of events it matches must equal the
     set marked `"expect": true` — positives must match, benign events must not.

What this does NOT show: that the rules behave the same in a production SIEM, or
against real captured telemetry. See ../README.md for the full status.

    pip install -r requirements.txt
    pytest
"""
import json
import os
import re
import sqlite3

import pytest
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.dirname(HERE)

with open(os.path.join(HERE, "sample_events.json"), encoding="utf-8") as f:
    SAMPLES = {k: v for k, v in json.load(f).items() if not k.startswith("_")}


def load_rule(filename):
    with open(os.path.join(RULES_DIR, filename), encoding="utf-8") as f:
        return SigmaCollection.from_yaml(f.read())


def _regexp(pattern, value):
    # SQLite calls REGEXP(pattern, value) for `value REGEXP pattern`.
    return value is not None and re.search(pattern, value) is not None


def run_rule(filename, events):
    """Convert `filename` with the SQLite backend, run it over `events`, and return
    the names of the events it matched."""
    queries = sqliteBackend().convert(load_rule(filename))
    assert len(queries) == 1, "expected one query per rule"

    columns = sorted({col for e in events for col in e["fields"]} | {"_name"})
    db = sqlite3.connect(":memory:")
    db.create_function("REGEXP", 2, _regexp)
    db.execute(f"CREATE TABLE logs ({', '.join(columns)})")
    for e in events:
        row = dict(e["fields"], _name=e["name"])
        db.execute(
            f"INSERT INTO logs ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
            list(row.values()),
        )
    cur = db.execute(queries[0])
    names_idx = [d[0] for d in cur.description].index("_name")
    return {r[names_idx] for r in cur.fetchall()}


# ---------------------------------------------------------------------------
# 1. Every rule in the folder parses and converts (schema-level check).
# ---------------------------------------------------------------------------
ALL_RULES = sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".yml"))


@pytest.mark.parametrize("filename", ALL_RULES)
def test_rule_parses_and_converts(filename):
    collection = load_rule(filename)
    assert not collection.errors, collection.errors
    assert sqliteBackend().convert(collection)


# ---------------------------------------------------------------------------
# 2. The validated rules match exactly the expected sample events.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("filename", sorted(SAMPLES))
def test_rule_matches_positives_and_ignores_benign(filename):
    events = SAMPLES[filename]
    expected = {e["name"] for e in events if e["expect"]}
    matched = run_rule(filename, events)

    missed = expected - matched
    false_positives = matched - expected
    assert not missed, f"rule missed expected events: {sorted(missed)}"
    assert not false_positives, f"rule matched benign events: {sorted(false_positives)}"


def test_each_validated_rule_has_positive_and_benign_cases():
    for filename, events in SAMPLES.items():
        assert any(e["expect"] for e in events), f"{filename}: no positive case"
        assert any(not e["expect"] for e in events), f"{filename}: no benign case"
