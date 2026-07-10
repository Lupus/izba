"""Unit tests for the Actor loop, caps, and runner entrypoint (no model, no KVM).

Everything here runs with a FakeModel and a stub ``izba`` binary, so it needs
neither an API key nor KVM.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_journeys  # noqa: E402
from model import FakeModel  # noqa: E402


def _load_collector():
    """Import the (dash-named, out-of-tree) collect-trajectories.py script so the
    end-to-end tally can be asserted against the REAL collector, not a re-impl.

    Path is resolved from this file (cwd-independent). Returns None if the script
    is absent (odd checkout) so the dependent test self-skips instead of erroring."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(repo_root, ".claude", "skills", "llm-dogfooding",
                        "scripts", "collect-trajectories.py")
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location("collect_trajectories", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_stub_izba(d):
    """A stub `izba` that succeeds for known subcommands and 'fails' for bogus ones."""
    stub = os.path.join(d, "izba")
    with open(stub, "w") as f:
        f.write(
            "#!/bin/sh\n"
            'if [ "$1" = "__reconcile" ]; then echo \'{"violations":[],"sandboxes":[]}\'; exit 0; fi\n'
            'if [ "$1" = "bogus-subcommand" ]; then echo "error: unrecognized subcommand" 1>&2; exit 2; fi\n'
            'if [ "$1" = "panicky" ]; then echo "thread \'main\' panicked at x.rs:1" 1>&2; exit 101; fi\n'
            "echo ok\n"
            "exit 0\n"
        )
    os.chmod(stub, 0o755)
    return stub


def _journeys_file(d, journeys):
    p = os.path.join(d, "journeys.json")
    with open(p, "w") as f:
        json.dump({"feature": "test-feature", "journeys": journeys}, f)
    return p


class ShardSelectionTests(unittest.TestCase):
    def test_shard_selects_modulo(self):
        js = [{"journey_id": f"j{i}", "rationale": "", "source": {},
               "steps": []} for i in range(5)]
        sel = run_journeys.select_shard(js, shard=0, shards=2)
        self.assertEqual([j["journey_id"] for j in sel], ["j0", "j2", "j4"])
        sel = run_journeys.select_shard(js, shard=1, shards=2)
        self.assertEqual([j["journey_id"] for j in sel], ["j1", "j3"])

    def test_select_cli_journeys_excludes_gui(self):
        js = [{"journey_id": "c1"},
              {"journey_id": "g1", "modality": "gui"},
              {"journey_id": "c2", "modality": "cli"}]
        self.assertEqual(
            [j["journey_id"] for j in run_journeys.select_cli_journeys(js)],
            ["c1", "c2"])

    def test_main_excludes_gui_journeys_from_cli_shards(self):
        # A CLI shard must never run a modality:"gui" journey as CLI — in the
        # gui-skeleton dispatch the model typed shell commands at GUI intents.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [
                {"journey_id": "cli-j", "rationale": "r",
                 "source": {"kind": "spec", "ref": "x"},
                 "steps": [{"intent": "do", "expect": "works"}]},
                {"journey_id": "gui-j", "modality": "gui", "rationale": "r",
                 "source": {"kind": "spec", "ref": "x"},
                 "steps": [{"intent": "click it", "expect": "works"}]},
            ])
            out = os.path.join(d, "traj.json")
            script = [{"command": "izba ls"}, {"done": True}]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script)])
            self.assertEqual(rc, 0)
            with open(out) as f:
                bundle = json.load(f)
            self.assertEqual([r["journey_id"] for r in bundle["results"]],
                             ["cli-j"])


class RunnerTests(unittest.TestCase):
    def test_failing_command_produces_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "panics",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "do a panicky thing", "expect": "no panic"}],
            }])
            out = os.path.join(d, "traj.json")
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba panicky"}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)  # report-only
            with open(out) as _f:
                bundle = json.load(_f)
            self.assertEqual(bundle["shard"], 0)
            self.assertEqual(bundle["feature"], "test-feature")
            res = bundle["results"][0]
            self.assertTrue(any(c["kind"] == "implicit" for c in res["candidates"]),
                            res["candidates"])

    def test_step_cap_halts_runaway_loop(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "runaway",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "loop forever", "expect": "bounded"}],
            }])
            out = os.path.join(d, "traj.json")
            # A model that NEVER says done and issues a fresh unique command each time.
            script = [{"command": f"izba run-{i}"} for i in range(1000)]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "5", "--action-timeout-s", "10",
                "--max-turns", "1000", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            with open(out) as _f:
                bundle = json.load(_f)
            actions = bundle["results"][0]["actions"]
            self.assertLessEqual(len(actions), 5, f"step cap not enforced: {len(actions)}")

    def test_loop_dedup_short_circuits_repeat_command(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "dedup",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "repeat", "expect": "bounded"}],
            }])
            out = os.path.join(d, "traj.json")
            # Same command over and over; dedup must stop the journey.
            script = [{"command": "izba ls"} for _ in range(50)]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "50", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            with open(out) as _f:
                bundle = json.load(_f)
            actions = bundle["results"][0]["actions"]
            # The repeat is detected after the first run -> at most one real action.
            self.assertLessEqual(len(actions), 1, f"dedup failed: {len(actions)}")

    def test_max_turns_caps_actions(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "turns",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "x", "expect": "y"}],
            }])
            out = os.path.join(d, "traj.json")
            script = [{"command": f"izba run-{i}"} for i in range(1000)]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "100", "--action-timeout-s", "10",
                "--max-turns", "3", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            with open(out) as _f:
                bundle = json.load(_f)
            actions = bundle["results"][0]["actions"]
            self.assertLessEqual(len(actions), 3, f"max-turns not enforced: {len(actions)}")

    def test_infra_error_does_not_raise(self):
        # Point at a non-existent izba binary; the run must still complete and
        # write a bundle (report-only) instead of raising. A binary that
        # doesn't exist means EVERY reconcile snapshot errors, so this is now
        # honestly surfaced as a catastrophic infra failure (exit 3) rather
        # than a silent rc=0 that hid a dead reconciler.
        with tempfile.TemporaryDirectory() as d:
            jf = _journeys_file(d, [{
                "journey_id": "infra",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "x", "expect": "y"}],
            }])
            out = os.path.join(d, "traj.json")
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", os.path.join(d, "does-not-exist"),
                "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba ls"}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "5",
                "--max-turns", "5", "--max-usd", "5",
            ])
            self.assertEqual(rc, run_journeys.EXIT_CATASTROPHIC_INFRA)
            self.assertTrue(os.path.exists(out))
            with open(out) as f:
                res = json.load(f)["results"][0]
            infra = [c for c in res["candidates"] if c["kind"] == "infra"]
            self.assertTrue(any("reconciler unusable" in c["detail"] for c in infra),
                            res["candidates"])


class FakeModelTests(unittest.TestCase):
    def test_pops_scripted_replies_in_order(self):
        m = FakeModel([{"command": "izba ls"}, {"done": True}])
        self.assertEqual(m.next_command({}, {}, [])["command"], "izba ls")
        self.assertTrue(m.next_command({}, {}, []).get("done"))

    def test_exhausted_script_signals_done(self):
        m = FakeModel([])
        self.assertTrue(m.next_command({}, {}, []).get("done"))

    def test_fake_model_cost_is_zero(self):
        m = FakeModel([{"command": "izba ls"}])
        m.next_command({}, {}, [])
        self.assertEqual(m.last_cost_usd, 0.0)


class HarnessImprovementTests(unittest.TestCase):
    def test_journey_data_dir_is_per_journey_and_sanitized(self):
        a = run_journeys._journey_data_dir("/base", "lifecycle-happy-path")
        b = run_journeys._journey_data_dir("/base", "clean-data-dir")
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("/base/"))
        seg = os.path.basename(run_journeys._journey_data_dir("/base", "weird id/with..x"))
        self.assertNotIn(" ", seg)
        self.assertNotIn("/", seg)

    def test_journey_data_dir_resists_path_traversal(self):
        # ".." must not escape base; it sanitizes to a safe segment under base.
        trav = os.path.normpath(run_journeys._journey_data_dir("/base", ".."))
        self.assertEqual(os.path.dirname(trav), "/base")
        self.assertNotEqual(os.path.basename(trav), "..")

    def test_journey_data_dir_tolerates_none_id(self):
        self.assertTrue(run_journeys._journey_data_dir("/base", None).startswith("/base/"))

    def test_journey_data_dir_component_is_short(self):
        # Long ids must not blow the AF_UNIX sun_path budget (izba#71): the
        # per-journey component stays bounded (<=16 prefix + '-' + 8 hash).
        seg = os.path.basename(run_journeys._journey_data_dir("/base", "x" * 200))
        self.assertLessEqual(len(seg), 25)

    def test_null_journey_id_does_not_break_report_only(self):
        with tempfile.TemporaryDirectory() as d:
            izba = _write_stub_izba(d)
            journeys = {"feature": "n", "journeys": [
                {"journey_id": None, "rationale": "",
                 "source": {"kind": "x", "ref": "y"},
                 "steps": [{"intent": "ls", "expect": "ok"}]},
            ]}
            jpath = os.path.join(d, "journeys.json")
            with open(jpath, "w") as f:
                json.dump(journeys, f)
            out = os.path.join(d, "traj.json")
            rc = run_journeys.main([
                "--journeys", jpath, "--shard", "0", "--shards", "1",
                "--izba-bin", izba, "--data-dir", os.path.join(d, "data"),
                "--out", out, "--fake-model",
                json.dumps([{"command": "izba ls"}, {"done": True}]),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(out))  # report-only: bundle written

    def test_journey_data_dir_distinguishes_punctuation_only_ids(self):
        # ids that sanitize identically must NOT share a dir (hash suffix).
        self.assertNotEqual(
            run_journeys._journey_data_dir("/base", "a b"),
            run_journeys._journey_data_dir("/base", "a-b"),
        )

    def test_gather_cli_help_captures_stub_help(self):
        with tempfile.TemporaryDirectory() as d:
            izba = _write_stub_izba(d)
            help_text = run_journeys.gather_cli_help(izba)
            self.assertIn("izba --help", help_text)
            self.assertIn("ok", help_text)

    def test_gather_cli_help_returns_empty_on_bad_binary(self):
        self.assertEqual(run_journeys.gather_cli_help("/no/such/izba-binary"), "")

    def test_parse_subcommands_extracts_names_skipping_help(self):
        top = ("Usage: izba <COMMAND>\n\n"
               "Commands:\n"
               "  volume   Manage volumes\n"
               "  ls       List sandboxes\n"
               "  help     Print help\n\n"
               "Options:\n"
               "  -h, --help  Print help\n")
        self.assertEqual(run_journeys._parse_subcommands(top), ["volume", "ls"])

    def test_parse_subcommands_empty_on_no_commands_section(self):
        self.assertEqual(run_journeys._parse_subcommands("just some text\nok"), [])

    def test_parse_subcommands_ignores_indented_commands_header(self):
        # An indented "Commands:" (e.g. quoted in a description) is NOT a real
        # clap header and must not open a block (header invariant: non-indented).
        text = ("Some description mentioning Commands: below\n"
                "    Commands:\n"
                "      not-a-real-cmd  oops\n")
        self.assertEqual(run_journeys._parse_subcommands(text), [])

    def test_gather_cli_help_recurses_into_subcommands(self):
        # A stub that emits a clap-style nested `volume` namespace; the gather
        # must discover `volume` AND recurse into `volume attach` (the exact verb
        # the M3 run never saw).
        with tempfile.TemporaryDirectory() as d:
            izba = os.path.join(d, "izba")
            with open(izba, "w") as f:
                f.write(
                    "#!/bin/sh\n"
                    'if [ "$1" = "--help" ]; then\n'
                    "  printf 'Usage: izba <COMMAND>\\n\\nCommands:\\n"
                    "  volume   Manage volumes\\n  help     Print help\\n\\n"
                    "Options:\\n  -h\\n'\n"
                    "  exit 0\n"
                    "fi\n"
                    'if [ "$1" = "volume" ] && [ "$2" = "--help" ]; then\n'
                    "  printf 'Manage volumes\\n\\nUsage: izba volume <COMMAND>\\n\\n"
                    "Commands:\\n  attach   Attach a volume\\n  help     Print help\\n'\n"
                    "  exit 0\n"
                    "fi\n"
                    'if [ "$1" = "volume" ] && [ "$2" = "attach" ] && [ "$3" = "--help" ]; then\n'
                    "  printf 'Attach a volume\\n\\nUsage: izba volume attach <NAME> <[VNAME:]GUEST_PATH:SIZE>\\n'\n"
                    "  exit 0\n"
                    "fi\n"
                    "echo ok\n"
                )
            os.chmod(izba, 0o755)
            help_text = run_journeys.gather_cli_help(izba)
            self.assertIn("$ izba volume --help", help_text)
            self.assertIn("$ izba volume attach --help", help_text)
            self.assertIn("GUEST_PATH:SIZE", help_text)

    def test_system_content_seeds_help_and_warns_against_inventing(self):
        from model import SYSTEM_PROMPT, _system_content
        self.assertEqual(_system_content(""), SYSTEM_PROMPT)
        self.assertEqual(_system_content("", "", ""), SYSTEM_PROMPT)
        seeded = _system_content("$ izba --help\nCommands: create, run, exec")
        self.assertIn("create, run, exec", seeded)
        self.assertIn("do NOT invent", seeded)

    def test_system_content_layers_readme_and_context_pack(self):
        from model import _system_content
        s = _system_content(
            "$ izba --help\nCommands: create, run",
            readme="# izba\nRun `izba policy enforce NAME on` to turn the firewall on.",
            context_pack="The guest is ubuntu:24.04 with no curl preinstalled.",
        )
        self.assertIn("=== run notes (your environment) ===", s)
        self.assertIn("ubuntu:24.04", s)
        self.assertIn("=== README (product documentation) ===", s)
        self.assertIn("policy enforce", s)
        self.assertIn("=== izba help ===", s)
        # run notes precede the README, which precedes the raw help.
        self.assertLess(s.index("run notes"), s.index("README (product"))
        self.assertLess(s.index("README (product"), s.index("izba help"))

    def test_read_optional_missing_file_is_empty(self):
        self.assertEqual(run_journeys._read_optional("/no/such/readme.md"), "")
        self.assertEqual(run_journeys._read_optional(""), "")

    def test_main_isolates_data_dir_per_journey(self):
        with tempfile.TemporaryDirectory() as d:
            izba = _write_stub_izba(d)
            journeys = {"feature": "iso", "journeys": [
                {"journey_id": "j-one", "rationale": "",
                 "source": {"kind": "x", "ref": "y"},
                 "steps": [{"intent": "ls", "expect": "ok"}]},
                {"journey_id": "j-two", "rationale": "",
                 "source": {"kind": "x", "ref": "y"},
                 "steps": [{"intent": "ls", "expect": "ok"}]},
            ]}
            jpath = os.path.join(d, "journeys.json")
            with open(jpath, "w") as f:
                json.dump(journeys, f)
            data_dir = os.path.join(d, "data")
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jpath, "--shard", "0", "--shards", "1",
                "--izba-bin", izba, "--data-dir", data_dir, "--out", out,
                "--fake-model", json.dumps([{"command": "izba ls"}, {"done": True}]),
            ])
            self.assertTrue(os.path.isdir(run_journeys._journey_data_dir(data_dir, "j-one")))
            self.assertTrue(os.path.isdir(run_journeys._journey_data_dir(data_dir, "j-two")))


class SeedFilesTests(unittest.TestCase):
    def test_write_seed_files_writes_nested_and_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            wd = os.path.join(d, "proj")
            os.makedirs(wd)
            run_journeys._write_seed_files(wd, {
                "izba.yml": "version: 1\n",
                "sub/dir/f.txt": "hi",
                "../escape.txt": "bad",        # rejected (traversal)
                "/abs.txt": "bad",             # rejected (absolute)
                "": "bad",                     # rejected (empty key)
            })
            # Valid entries materialized, including a nested path.
            with open(os.path.join(wd, "izba.yml")) as _f:
                self.assertEqual(_f.read(), "version: 1\n")
            self.assertTrue(os.path.isfile(os.path.join(wd, "sub", "dir", "f.txt")))
            # Traversal / absolute rejected: nothing escaped the workdir.
            self.assertFalse(os.path.exists(os.path.join(d, "escape.txt")))
            self.assertFalse(os.path.exists("/abs.txt"))

    def test_write_seed_files_report_only_on_non_dict(self):
        # None / non-dict is a no-op, never raises (report-only).
        with tempfile.TemporaryDirectory() as d:
            run_journeys._write_seed_files(d, None)
            run_journeys._write_seed_files(d, "not-a-dict")


def _write_decisive_stub_izba(d):
    """Like _write_stub_izba but used for the decisive-grading integration test.

    Reuses the exact same contract: `__reconcile` -> empty snapshot,
    `bogus-subcommand` -> exit 2 (the setup step's non-zero exit), any other
    subcommand -> exit 0 (the core step's success). cd/file ops need no stubbing —
    run_action runs a real shell, so only `izba` itself is intercepted here."""
    return _write_stub_izba(d)


class DecisiveGradingTests(unittest.TestCase):
    def test_setup_noise_is_not_decisive_and_core_step_governs(self):
        # Replays the #111 masking scenario: a non-core SETUP step that exits
        # non-zero (would have buried the journey under the old harness) followed
        # by a core:true step that succeeds. The setup step's functional candidate
        # must be tagged decisive:false, and there must be NO decisive functional
        # candidate — so the collector will tally the journey positive.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_decisive_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "review-gate",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "review-gate §"},
                # A seeded valid-looking manifest: the journey starts at the gate.
                "seed_files": {"izba.yml": "version: 1\nservices: {}\n"},
                "steps": [
                    {"intent": "prepare", "expect": "the setup succeeds",
                     "core": False},
                    {"intent": "assert the gate", "expect": "the listing succeeds",
                     "core": True},
                ],
            }])
            out = os.path.join(d, "traj.json")
            # step 0: failing setup action, then done; step 1: succeeding action, done.
            script = [
                {"command": "izba bogus-subcommand"}, {"done": True},
                {"command": "izba ls"}, {"done": True},
            ]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            with open(out) as _f:
                bundle = json.load(_f)
            res = bundle["results"][0]
            funcs = [c for c in res["candidates"] if c["kind"] == "functional"]
            # Exactly the setup-step functional candidate, tagged non-decisive.
            self.assertTrue(funcs, "expected a setup-step functional candidate")
            self.assertTrue(any(c.get("decisive") is False for c in funcs), funcs)
            # No decisive functional candidate => nothing flips the journey.
            self.assertFalse(any(c.get("decisive") for c in funcs), funcs)
            # The seed file was materialized into the journey's workdir.
            jdir = run_journeys._journey_data_dir(d, "review-gate")
            self.assertTrue(os.path.isfile(os.path.join(jdir, "proj", "izba.yml")))

    # A realistic minimal izba.yml (the #122 required fields) — seeded so a deep
    # review-gate journey starts AT the gate instead of dying on manifest
    # authoring. The stub izba doesn't parse it; this documents the real shape.
    SEEDED_MANIFEST = (
        "apiVersion: izba.dev/v1alpha1\n"
        "kind: Sandbox\n"
        "metadata:\n  name: gate-demo\n"
        "spec:\n"
        "  image: ubuntu:24.04\n"
        "  resources: {cpus: 2, memory: 2Gi}\n"
        "  rootDisk: {size: 8Gi}\n"
        "  egress: {enforce: true, allow: [{host: github.com}]}\n"
    )

    def test_collector_tallies_masking_journey_positive(self):
        # THE #111 acceptance proof, end-to-end: the masking scenario run through
        # main() AND the real collector comes out POSITIVE — the non-zero setup
        # exit no longer buries a satisfied core assertion — with the setup
        # candidate demoted to SOFT (not a flipping negative). Old harness: 0
        # positive. New harness: 1 positive.
        collector = _load_collector()
        if collector is None:
            self.skipTest("collect-trajectories.py not found in this checkout")
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            arts = os.path.join(d, "arts")
            os.makedirs(arts)
            jf = _journeys_file(d, [{
                "journey_id": "review-gate",
                "rationale": "the review-gate refuses a stale token",
                "source": {"kind": "spec", "ref": "review-gate §7"},
                "seed_files": {"izba.yml": self.SEEDED_MANIFEST},
                "steps": [
                    {"intent": "prepare the sandbox", "expect": "setup succeeds",
                     "core": False},
                    {"intent": "assert the gate holds", "expect": "listing succeeds",
                     "core": True},
                ],
            }])
            # The collector globs traj-*.json (dash) — name the bundle so it matches.
            out = os.path.join(arts, "traj-0.json")
            script = [
                {"command": "izba bogus-subcommand"}, {"done": True},  # setup fails
                {"command": "izba ls"}, {"done": True},                # core succeeds
            ]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            data = collector.collect(arts)
            self.assertEqual(data["totals"]["positive_journeys"], 1, data["totals"])
            self.assertEqual(data["negatives"], [], data["negatives"])
            # The setup-step non-zero exit survives as a SOFT functional candidate.
            self.assertTrue(
                any(s.get("kind") == "functional" for s in data["soft"]),
                data["soft"])


class InfraCandidateTests(unittest.TestCase):
    def _run(self, d, fake_script, n_journeys=1):
        stub = _write_stub_izba(d)
        journeys = [{
            "journey_id": f"j{i}", "rationale": "r",
            "source": {"kind": "spec", "ref": "x"},
            "steps": [{"intent": "do", "expect": "works"}],
        } for i in range(n_journeys)]
        jf = _journeys_file(d, journeys)
        out = os.path.join(d, "traj.json")
        rc = run_journeys.main([
            "--journeys", jf, "--shard", "0", "--shards", "1",
            "--izba-bin", stub, "--data-dir", d, "--out", out,
            "--fake-model", json.dumps(fake_script),
            "--step-cap", "25", "--action-timeout-s", "10",
            "--max-turns", "10", "--max-usd", "5",
        ])
        with open(out) as f:
            return rc, json.load(f)

    def test_model_error_reply_emits_flipping_infra_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            rc, bundle = self._run(d, [{"error": "openrouter request failed"}])
            cands = bundle["results"][0]["candidates"]
            infra = [c for c in cands if c["kind"] == "infra"]
            self.assertTrue(infra, cands)
            self.assertIn("openrouter request failed", infra[0]["detail"])
            # single journey, degraded -> catastrophic exit
            self.assertEqual(rc, 3)

    def test_infra_journey_not_positive_in_collector(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            _, bundle = self._run(d, [{"error": "dead key"}])
            bdir = os.path.join(d, "bundles")
            os.makedirs(bdir)
            with open(os.path.join(bdir, "traj-0.json"), "w") as f:
                json.dump(bundle, f)
            data = collector.collect(bdir)
            self.assertEqual(data["totals"]["positive_journeys"], 0)

    def test_catastrophic_exit_only_above_half(self):
        # 1 of 3 journeys degraded (error on first journey's first turn; the
        # FakeModel script then supplies clean done-runs for the other two).
        with tempfile.TemporaryDirectory() as d:
            script = [{"error": "blip"},               # j0: degraded
                      {"command": "izba ls"}, {"done": True},   # j1: fine
                      {"command": "izba ls"}, {"done": True}]   # j2: fine
            rc, bundle = self._run(d, script, n_journeys=3)
            self.assertEqual(rc, 0)  # 1/3 <= 0.5 -> report-only

    def test_exactly_half_degraded_is_not_catastrophic(self):
        # Pin the boundary: exactly 2 of 4 journeys degraded is 0.5, and 0.5 is
        # NOT > CATASTROPHIC_DEGRADED_FRACTION (0.5) -> report-only rc 0. Kills
        # a `>` -> `>=` mutation in the catastrophic check. Each {"error"} reply
        # ends that journey's only step, so the two error replies degrade j0
        # and j1; the clean command/done pairs serve j2 and j3.
        with tempfile.TemporaryDirectory() as d:
            script = [{"error": "blip"},                       # j0: degraded
                      {"error": "blip2"},                      # j1: degraded
                      {"command": "izba ls"}, {"done": True},  # j2: fine
                      {"command": "izba ls"}, {"done": True}]  # j3: fine
            rc, bundle = self._run(d, script, n_journeys=4)
            degraded = [r["journey_id"] for r in bundle["results"]
                        if not r["actions"]
                        or any(c["kind"] == "infra" for c in r["candidates"])]
            self.assertEqual(degraded, ["j0", "j1"])  # exactly half
            self.assertEqual(rc, 0)  # 2/4 == 0.5 is NOT > 0.5 -> report-only

    def test_model_exception_emits_infra_candidate(self):
        class ExplodingModel:
            last_cost_usd = 0.0
            def next_command(self, *a):
                raise RuntimeError("kaboom")
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            journey = {"journey_id": "boom", "rationale": "r",
                       "source": {"kind": "spec", "ref": "x"},
                       "steps": [{"intent": "do", "expect": "works"}]}
            budget = {"usd": 0.0}
            res = run_journeys.run_journey(
                ExplodingModel(), journey, stub, d,
                max_turns=5, step_cap=5, action_timeout_s=5,
                latency_budget_ms=1000, budget=budget, max_usd=5)
            self.assertTrue(any(c["kind"] == "infra" for c in res["candidates"]))


class UnreachedDecisiveTests(unittest.TestCase):
    def _journey(self):
        return {
            "journey_id": "deep", "rationale": "r",
            "source": {"kind": "spec", "ref": "spec §9"},
            "steps": [
                {"intent": "setup", "expect": "ok"},
                {"intent": "the real assertion", "expect": "guard refuses",
                 "core": True},
            ],
        }

    def test_budget_burned_in_setup_flags_unreached_core(self):
        # Model does setup actions then goes silent (done) without ever
        # reaching step 2 — max-turns trips inside step 1.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [self._journey()])
            out = os.path.join(d, "traj.json")
            script = [{"command": f"izba ls-{i}"} for i in range(10)]
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "3", "--max-usd", "5",
            ])
            with open(out) as f:
                res = json.load(f)["results"][0]
            unreached = [c for c in res["candidates"]
                         if c["kind"] == "unreached_decisive"]
            self.assertEqual(len(unreached), 1, res["candidates"])
            self.assertIn("the real assertion", unreached[0]["detail"])

    def test_unreached_journey_not_positive_in_collector(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [self._journey()])
            out = os.path.join(d, "bundles", "traj-0.json")
            os.makedirs(os.path.dirname(out))
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(
                    [{"command": "izba setup-thing"}] * 5),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "2", "--max-usd", "5",
            ])
            data = collector.collect(os.path.dirname(out))
            self.assertEqual(data["totals"]["positive_journeys"], 0)

    def test_entered_decisive_step_with_zero_actions_flags_unreached(self):
        # The decisive step IS entered (step 1 finishes cleanly, no cap trips),
        # but the Actor immediately replies done without running a single
        # command — the step produced zero actions, so its assertion was never
        # exercised. Must flag exactly like the never-entered case.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [self._journey()])
            out = os.path.join(d, "traj.json")
            script = [{"command": "izba ls"}, {"done": True},  # step 0 does work then finishes
                      {"done": True}]  # step 1 (core) entered, zero actions
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5",
            ])
            with open(out) as f:
                res = json.load(f)["results"][0]
            unreached = [c for c in res["candidates"]
                         if c["kind"] == "unreached_decisive"]
            self.assertEqual(len(unreached), 1, res["candidates"])
            self.assertIn("decisive step 1", unreached[0]["detail"])
            self.assertIn("the real assertion", unreached[0]["detail"])

    def test_reached_decisive_step_emits_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [self._journey()])
            out = os.path.join(d, "traj.json")
            script = [{"command": "izba ls"}, {"done": True},        # step 1
                      {"command": "izba bogus-subcommand"}, {"done": True}]  # step 2 (nonzero = refusal ok)
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5",
            ])
            with open(out) as f:
                res = json.load(f)["results"][0]
            self.assertFalse([c for c in res["candidates"]
                              if c["kind"] == "unreached_decisive"],
                             res["candidates"])


class ReconcileViolationTests(unittest.TestCase):
    def _stub_with_violations(self, d):
        stub = os.path.join(d, "izba")
        with open(stub, "w") as f:
            f.write(
                "#!/bin/sh\n"
                'if [ "$1" = "__reconcile" ]; then\n'
                '  echo \'{"violations":[{"kind":"orphan-relay","name":"web"}],"sandboxes":[]}\'\n'
                "  exit 0\nfi\n"
                "echo ok\nexit 0\n")
        os.chmod(stub, 0o755)
        return stub

    def test_nonempty_violations_emit_flipping_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            stub = self._stub_with_violations(d)
            jf = _journeys_file(d, [{
                "journey_id": "viol", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "do", "expect": "ok"}]}])
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba ls"}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5"])
            with open(out) as f:
                res = json.load(f)["results"][0]
            rv = [c for c in res["candidates"] if c["kind"] == "reconcile_violation"]
            self.assertTrue(rv, res["candidates"])
            self.assertIn("orphan-relay", rv[0]["detail"])

    def test_all_snapshots_failed_emits_infra(self):
        with tempfile.TemporaryDirectory() as d:
            stub = os.path.join(d, "izba")
            with open(stub, "w") as f:
                f.write("#!/bin/sh\n"
                        'if [ "$1" = "__reconcile" ]; then exit 7; fi\n'
                        "echo ok\nexit 0\n")
            os.chmod(stub, 0o755)
            jf = _journeys_file(d, [{
                "journey_id": "deadrec", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "do", "expect": "ok"}]}])
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba ls"}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5"])
            with open(out) as f:
                res = json.load(f)["results"][0]
            infra = [c for c in res["candidates"] if c["kind"] == "infra"]
            self.assertTrue(any("reconciler unusable" in c["detail"] for c in infra),
                            res["candidates"])


class InformationalReconcileTest(unittest.TestCase):
    def _action(self, violations):
        from oracles import Action
        return Action(intent="", command="izba rm x", exit_code=0,
                      stdout_tail="", stderr_tail="", latency_ms=1,
                      reconcile={"violations": violations, "sandboxes": []})

    def test_informational_only_violations_do_not_flip(self):
        import run_journeys as rj
        a = self._action([{"kind": "orphan_volume",
                           "detail": "informational: named volume 'x' is "
                                     "unreferenced (persistent volumes survive rm)"}])
        cands = rj._collect_candidates(a, "izba rm x", 0, None, 30000, {}, {}, "j1")
        self.assertFalse(
            [c for c in cands if c["kind"] == "reconcile_violation"],
            f"informational items must not flip: {cands}")

    def test_mixed_violations_flip_and_count_only_real_ones(self):
        import run_journeys as rj
        a = self._action([
            {"kind": "orphan_volume", "detail": "informational: named volume 'x'"},
            {"kind": "list_mismatch", "detail": "daemon lists a ghost sandbox"},
        ])
        cands = [c for c in rj._collect_candidates(
            a, "izba ls", 0, None, 30000, {}, {}, "j1")
            if c["kind"] == "reconcile_violation"]
        self.assertEqual(len(cands), 1)
        self.assertIn("1 violation(s)", cands[0]["detail"])
        self.assertNotIn("informational", cands[0]["detail"])


class ExpectCmdReTests(unittest.TestCase):
    def _run(self, d, step, script):
        stub = _write_stub_izba(d)
        jf = _journeys_file(d, [{
            "journey_id": "anchor", "rationale": "r",
            "source": {"kind": "spec", "ref": "x"},
            "steps": [step]}])
        out = os.path.join(d, "traj.json")
        run_journeys.main([
            "--journeys", jf, "--shard", "0", "--shards", "1",
            "--izba-bin", stub, "--data-dir", d, "--out", out,
            "--fake-model", json.dumps(script),
            "--step-cap", "25", "--action-timeout-s", "10",
            "--max-turns", "10", "--max-usd", "5"])
        with open(out) as f:
            return json.load(f)["results"][0]

    def test_grades_matching_action_not_trailing_verify(self):
        # The refusal (bogus-subcommand, exit 2) is followed by a passing
        # `izba ls` verify. expect_exit=nonzero must be graded against the
        # promote-like command, so NO candidate fires.
        step = {"intent": "try the guarded op", "expect": "must be refused",
                "expect_exit": "nonzero", "core": True,
                "expect_cmd_re": r"bogus-subcommand"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [
                {"command": "izba bogus-subcommand"},
                {"command": "izba ls"},
                {"done": True}])
            func = [c for c in res["candidates"] if c["kind"] == "functional"]
            self.assertEqual(func, [], func)

    def test_without_anchor_trailing_verify_false_fires(self):
        # Same trajectory WITHOUT expect_cmd_re: the final action (ls, exit 0)
        # is graded against nonzero -> false candidate. Locks in the motivation.
        step = {"intent": "try the guarded op", "expect": "must be refused",
                "expect_exit": "nonzero", "core": True}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [
                {"command": "izba bogus-subcommand"},
                {"command": "izba ls"},
                {"done": True}])
            func = [c for c in res["candidates"] if c["kind"] == "functional"]
            self.assertEqual(len(func), 1)
            self.assertEqual(func[0].get("graded_cmd"), "izba ls")

    def test_mid_step_match_pins_action_index(self):
        # The anchored action is NOT the step's last: two distinct verifies
        # follow it (varied because loop-dedup is per (journey_id, command)).
        # expect_exit=0 against the anchored bogus-subcommand (exit 2) fires
        # exactly one candidate, whose graded_cmd AND trajectory_ref must
        # point at action 0 — not the trailing verifies.
        step = {"intent": "run the op then verify", "expect": "op succeeds",
                "expect_exit": 0, "core": True,
                "expect_cmd_re": r"bogus-subcommand"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [
                {"command": "izba bogus-subcommand"},
                {"command": "izba ls"},
                {"command": "izba ls --json"},
                {"done": True}])
            func = [c for c in res["candidates"] if c["kind"] == "functional"]
            self.assertEqual(len(func), 1, func)
            self.assertEqual(func[0].get("graded_cmd"), "izba bogus-subcommand")
            self.assertEqual(func[0]["trajectory_ref"]["action_index"], 0)

    def test_bad_regex_falls_back_to_last_action(self):
        step = {"intent": "x", "expect": "works", "core": True,
                "expect_cmd_re": "["}  # invalid regex
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba ls"}, {"done": True}])
            # ls exits 0 and expect describes success -> no candidate; and no crash.
            self.assertEqual([c for c in res["candidates"]
                              if c["kind"] == "functional"], [])


class BundleSchemaTests(unittest.TestCase):
    def test_full_run_bundle_validates(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "ok", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "list", "expect": "works", "core": True,
                           "expect_cmd_re": "ls"}]},
                {"journey_id": "err", "rationale": "r",
                 "source": {"kind": "spec", "ref": "x"},
                 "steps": [{"intent": "boom", "expect": "works"}]}])
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([
                    {"command": "izba ls"}, {"done": True},   # journey ok
                    {"error": "transport down"}]),            # journey err
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5"])
            schema_path = os.path.join(os.path.dirname(
                os.path.abspath(run_journeys.__file__)),
                "schema", "trajectory.schema.json")
            with open(schema_path) as f:
                schema = json.load(f)
            with open(out) as f:
                bundle = json.load(f)
            jsonschema.validate(bundle, schema)  # raises on mismatch


class CollectorBucketsTests(unittest.TestCase):
    def _mk_bundle(self, d, fname, results):
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, fname), "w") as f:
            json.dump({"shard": 0, "feature": "t", "results": results}, f)

    def test_gui_bundles_are_collected_with_modality(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            self._mk_bundle(d, "traj-0.json", [
                {"journey_id": "cli-j", "actions": [], "candidates": []}])
            self._mk_bundle(d, "gui-traj-0.json", [
                {"journey_id": "gui-j", "actions": [], "candidates": []}])
            data = collector.collect(d)
            self.assertEqual(data["totals"]["journeys"], 2)
            mods = {p["journey_id"]: p["modality"] for p in data["positives"]}
            # NOTE: zero-action journeys stop being positive once Task 3's
            # unreached candidates are in real bundles; these synthetic results
            # have no candidates, so they still land in positives here.
            self.assertEqual(mods, {"cli-j": "cli", "gui-j": "gui"})

    def test_infra_and_unreached_buckets(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            self._mk_bundle(d, "traj-0.json", [
                {"journey_id": "dead", "actions": [], "candidates": [
                    {"kind": "infra", "detail": "x", "violated_expectation": "",
                     "source": "", "trajectory_ref": {"journey_id": "dead",
                                                      "action_index": -1}}]},
                {"journey_id": "shallow", "actions": [], "candidates": [
                    {"kind": "unreached_decisive", "detail": "y",
                     "violated_expectation": "", "source": "",
                     "trajectory_ref": {"journey_id": "shallow",
                                        "action_index": -1}}]}])
            data = collector.collect(d)
            self.assertEqual(data["totals"]["positive_journeys"], 0)
            self.assertEqual(data["totals"]["infra_journeys"], 1)
            self.assertEqual(data["totals"]["unreached_journeys"], 1)
            self.assertEqual([u["journey_id"] for u in data["unreached"]],
                             ["shallow"])

    def test_by_kind_split_by_modality(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            self._mk_bundle(d, "traj-0.json", [
                {"journey_id": "cli-dead", "actions": [], "candidates": [
                    {"kind": "infra", "detail": "x", "violated_expectation": "",
                     "source": "", "trajectory_ref": {"journey_id": "cli-dead",
                                                      "action_index": -1}}]}])
            self._mk_bundle(d, "gui-traj-0.json", [
                {"journey_id": "gui-err", "actions": [], "candidates": [
                    {"kind": "console", "detail": "boom",
                     "violated_expectation": "", "source": "",
                     "trajectory_ref": {"journey_id": "gui-err",
                                        "action_index": 0}}]}])
            data = collector.collect(d)
            self.assertEqual(data["totals"]["by_kind"],
                             {"infra": 1, "console": 1})
            self.assertEqual(data["totals"]["by_kind_by_modality"],
                             {"cli": {"infra": 1}, "gui": {"console": 1}})


if __name__ == "__main__":
    unittest.main()


class CrashedJourneyHonestyTests(unittest.TestCase):
    def test_crashed_journey_carries_infra_candidate(self):
        # A journey that crashes at the run_journey level must not read as
        # positive: the outer handler records a flipping infra candidate
        # (parity with the GUI runner's crash path).
        class ExplodingOnJourneyModel:
            last_cost_usd = 0.0
            def next_command(self, *a):
                raise KeyboardInterrupt  # not caught by inner report-only guards
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "boom", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "do", "expect": "ok"}]}])
            out = os.path.join(d, "traj.json")
            import run_journeys as rj
            # Route build_model to the exploding model via --fake-model then
            # monkeypatch FakeModel's next_command to raise BaseException-free:
            # simplest robust route — patch run_journey itself to raise.
            orig = rj.run_journey
            def boom(*a, **k):
                raise RuntimeError("kaboom-at-journey-level")
            rj.run_journey = boom
            try:
                rc = rj.main([
                    "--journeys", jf, "--shard", "0", "--shards", "1",
                    "--izba-bin", stub, "--data-dir", d, "--out", out,
                    "--fake-model", json.dumps([{"done": True}]),
                    "--step-cap", "5", "--action-timeout-s", "5",
                    "--max-turns", "5", "--max-usd", "5"])
            finally:
                rj.run_journey = orig
            self.assertEqual(rc, 3)  # 1/1 degraded -> catastrophic
            with open(out) as f:
                res = json.load(f)["results"][0]
            infra = [c for c in res["candidates"] if c["kind"] == "infra"]
            self.assertTrue(any("journey crashed" in c["detail"] for c in infra),
                            res["candidates"])
