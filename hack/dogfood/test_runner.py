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


class SeedSurvivalTests(unittest.TestCase):
    """DEEP-H0: a seeded precondition the Actor overwrote must be an explicit,
    auditable signal — never a silent grade of the Actor's own substitute.

    The deep tier's dominant fact was that the CLI Actor `cat >`-overwrote the
    seeded fixture in 11 of 11 journeys (its first act, every time), so the
    oracles graded a file the journey compiler never authored. Telling the Actor
    about the seed would breach the fair-test boundary (seeds are invisible to
    it by contract), so the harness instead OBSERVES the fixture and says so."""

    SEED = "enforce: true\nallow:\n  - seeded.example\n"

    def _run(self, d, command, *, seed_files=None, steps=None):
        stub = _write_stub_izba(d)
        jf = _journeys_file(d, [{
            "journey_id": "seeded",
            "rationale": "r",
            "source": {"kind": "spec", "ref": "x"},
            "seed_files": seed_files if seed_files is not None
            else {"policy.yaml": self.SEED},
            "steps": steps or [{"intent": "use the policy file that is already "
                                          "in your working directory",
                                "expect": "it works"}],
        }])
        out = os.path.join(d, "traj.json")
        self.rc = run_journeys.main([
            "--journeys", jf, "--shard", "0", "--shards", "1",
            "--izba-bin", stub, "--data-dir", d, "--out", out,
            "--fake-model", json.dumps(command),
        ])
        with open(out) as f:
            return json.load(f)

    # The machine-readable marker the Phase-3 skeptic greps for. Pinned as a
    # literal here on purpose: it is the wording a human reads in the bundle.
    MARKER = "seeded precondition"

    @classmethod
    def _seed_candidates(cls, result):
        return [c for c in result["candidates"]
                if cls.MARKER in c.get("detail", "")]

    def test_actor_overwriting_a_seeded_file_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = self._run(d, [
                {"command": "cat > policy.yaml <<'EOF'\nenforce: true\n"
                            "allow:\n  - invented.example\nEOF"},
                {"done": True},
            ])
            result = bundle["results"][0]
            found = self._seed_candidates(result)
            self.assertTrue(found, f"the clobbered seed must be reported: "
                                   f"{result['candidates']}")
            c = found[0]
            self.assertEqual(c["kind"], "infra")  # flipping: nothing was verified
            self.assertIn("seed", c["source"],
                          "provenance must point at the seeding mechanism")
            self.assertIn("policy.yaml", c["detail"])
            self.assertIn("cat > policy.yaml", c["detail"],
                          "the detail must name the action that clobbered it")
            self.assertEqual(c["trajectory_ref"]["action_index"], 0)

    def test_clobbered_seed_journey_is_not_positive_in_collector(self):
        collector = _load_collector()
        if collector is None:
            self.skipTest("collector script not present")
        with tempfile.TemporaryDirectory() as d:
            bundle = self._run(d, [
                {"command": "printf 'mine\\n' > policy.yaml"}, {"done": True},
            ])
            bdir = os.path.join(d, "bundles")
            os.makedirs(bdir)
            with open(os.path.join(bdir, "traj-0.json"), "w") as f:
                json.dump(bundle, f)
            data = collector.collect(bdir)
            self.assertEqual(data["totals"]["positive_journeys"], 0,
                             "a journey whose precondition was destroyed "
                             "verified nothing")

    def test_deleting_a_seeded_file_is_flagged_too(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = self._run(d, [{"command": "rm -f policy.yaml"},
                                   {"done": True}])
            found = self._seed_candidates(bundle["results"][0])
            self.assertTrue(found)
            self.assertIn("policy.yaml", found[0]["detail"])

    def test_all_journeys_clobbering_their_seed_is_catastrophic(self):
        # The flip has teeth: a clobbered precondition is an `infra` candidate,
        # so the journey counts as DEGRADED — and a run in which every journey
        # destroyed its fixture (the 2026-08 deep tier: 11 of 11) measured
        # nothing and must fail the job, not report a tidy green.
        with tempfile.TemporaryDirectory() as d:
            self._run(d, [{"command": "printf 'mine\\n' > policy.yaml"},
                          {"done": True}])
            self.assertEqual(self.rc, run_journeys.EXIT_CATASTROPHIC_INFRA)

    def test_untouched_seed_run_stays_green(self):
        with tempfile.TemporaryDirectory() as d:
            self._run(d, [{"command": "cat policy.yaml"}, {"done": True}])
            self.assertEqual(self.rc, 0)

    def test_untouched_seed_is_silent(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = self._run(d, [{"command": "cat policy.yaml"},
                                   {"done": True}])
            result = bundle["results"][0]
            self.assertEqual(self._seed_candidates(result), [],
                             "a surviving fixture must produce no signal")
            self.assertIn("seeded.example", result["actions"][0]["stdout_tail"])

    def test_reported_once_per_seed_not_once_per_later_action(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = self._run(d, [
                {"command": "printf 'mine\\n' > policy.yaml"},
                {"command": "cat policy.yaml"},
                {"command": "cat policy.yaml"},
                {"done": True},
            ])
            self.assertEqual(len(self._seed_candidates(bundle["results"][0])), 1)

    def test_step_level_reseed_reestablishes_the_fixture(self):
        # A step-level seed_files re-authors the file mid-journey: the drift
        # fixture is a NEW precondition, so a clobber of the ORIGINAL before it
        # is reported once, and the re-seeded content is tracked from there.
        with tempfile.TemporaryDirectory() as d:
            bundle = self._run(
                d,
                [{"command": "printf 'mine\\n' > policy.yaml"}, {"done": True},
                 {"command": "cat policy.yaml"}, {"done": True}],
                steps=[
                    {"intent": "step 0", "expect": "x"},
                    {"intent": "step 1", "expect": "y",
                     "seed_files": {"policy.yaml": "enforce: false\n"}},
                ])
            result = bundle["results"][0]
            found = self._seed_candidates(result)
            self.assertEqual(len(found), 1, found)
            self.assertEqual(found[0]["trajectory_ref"]["action_index"], 0)
            self.assertIn("enforce: false", result["actions"][1]["stdout_tail"],
                          "the step-level seed must land over the Actor's file")


class SeedFilesTests(unittest.TestCase):
    def test_write_seeds_writes_nested_and_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            wd = os.path.join(d, "proj")
            os.makedirs(wd)
            run_journeys._write_seeds(wd, {
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

    def test_write_seeds_report_only_on_non_dict(self):
        # None / non-dict is a no-op, never raises (report-only).
        with tempfile.TemporaryDirectory() as d:
            run_journeys._write_seeds(d, None)
            run_journeys._write_seeds(d, "not-a-dict")


class StepSeedFilesTests(unittest.TestCase):
    def test_step_seed_files_land_before_that_step_not_earlier(self):
        # A two-step journey: step 0 has no seed_files, step 1 does. The seed
        # must be ABSENT while step 0 runs and PRESENT (with the declared
        # content) when step 1's action runs — mid-journey drift, the Task 10
        # GUI-manifest primitive.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            manifest = "spec:\n  image: alpine\n"
            jf = _journeys_file(d, [{
                "journey_id": "mid-drift",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [
                    {"intent": "look before the drift", "expect": "no file yet"},
                    {"intent": "look after the drift", "expect": "file present",
                     "seed_files": {"izba.yml": manifest}},
                ],
            }])
            out = os.path.join(d, "traj.json")
            script = [
                {"command": "cat izba.yml 2>&1 || echo MISSING"}, {"done": True},
                {"command": "cat izba.yml"}, {"done": True},
            ]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
            ])
            self.assertEqual(rc, 0)
            with open(out) as f:
                bundle = json.load(f)
            actions = bundle["results"][0]["actions"]
            # Exactly the two Actor commands — the seed write is not itself an
            # action (so it can never be graded as the step's command).
            self.assertEqual(len(actions), 2)
            self.assertIn("MISSING", actions[0]["stdout_tail"],
                          "izba.yml must not exist before step 1 seeds it")
            self.assertEqual(actions[1]["stdout_tail"], manifest,
                             "izba.yml must be seeded before step 1's action runs")
            # The file also lands on disk in the journey's workdir.
            jdir = run_journeys._journey_data_dir(d, "mid-drift")
            with open(os.path.join(jdir, "proj", "izba.yml")) as f:
                self.assertEqual(f.read(), manifest)

    def test_step_seed_files_do_not_override_journey_level_for_other_steps(self):
        # Journey-level seed_files ("before step 0") and step-level seed_files
        # on a later step coexist: the journey-level file must still be there
        # for step 0, and the step-level file only appears starting its step.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "layered-seeds",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "seed_files": {"base.txt": "base\n"},
                "steps": [
                    {"intent": "step0", "expect": "base file present"},
                    {"intent": "step1", "expect": "drift file present",
                     "seed_files": {"drift.txt": "drift\n"}},
                ],
            }])
            out = os.path.join(d, "traj.json")
            script = [
                {"command": "cat base.txt; test -f drift.txt && echo HAS_DRIFT || echo NO_DRIFT"},
                {"done": True},
                {"command": "cat drift.txt"}, {"done": True},
            ]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
            ])
            self.assertEqual(rc, 0)
            with open(out) as f:
                bundle = json.load(f)
            actions = bundle["results"][0]["actions"]
            self.assertIn("base\n", actions[0]["stdout_tail"])
            self.assertIn("NO_DRIFT", actions[0]["stdout_tail"])
            self.assertEqual(actions[1]["stdout_tail"], "drift\n")


class ProductCommandGradingTest(unittest.TestCase):
    def _produced(self):
        # The izba command failed as expected (exit 2), then the model wrote a
        # file with a heredoc as the step's FINAL action (exit 0).
        return [
            {"command": "izba promote .", "exit_code": 2},
            {"command": "cat > izba.yml <<EOF\nfoo\nEOF", "exit_code": 0},
        ]

    def test_grades_last_izba_action_not_trailing_heredoc(self):
        import run_journeys as rj
        step = {"intent": "promote must refuse", "expect": "",
                "expect_exit": "nonzero"}
        cands = rj._grade_step_functional(
            step, self._produced(), {}, "j1", True, action_index=1)
        self.assertFalse(
            cands, f"the izba action (exit 2) satisfies expect_exit=nonzero, "
                   f"but the heredoc was graded: {cands}")

    def test_falls_back_to_final_action_without_any_izba_command(self):
        import run_journeys as rj
        produced = [{"command": "ls -la", "exit_code": 0},
                    {"command": "cat notes.txt", "exit_code": 1}]
        step = {"intent": "x", "expect": "the listing succeeds"}
        cands = rj._grade_step_functional(step, produced, {}, "j1", False,
                                          action_index=1)
        self.assertTrue(cands, "final action (exit 1) vs success expectation "
                               "must still produce a candidate")
        self.assertEqual(cands[0]["graded_cmd"], "cat notes.txt")

    def test_expect_cmd_re_still_wins_over_izba_heuristic(self):
        import run_journeys as rj
        produced = [{"command": "izba diff .", "exit_code": 0},
                    {"command": "izba promote .", "exit_code": 2},
                    {"command": "echo done", "exit_code": 0}]
        step = {"intent": "x", "expect": "", "expect_exit": 0,
                "expect_cmd_re": r"izba diff"}
        cands = rj._grade_step_functional(step, produced, {}, "j1", True,
                                          action_index=2)
        self.assertFalse(cands, f"expect_cmd_re selects `izba diff` (exit 0), "
                                f"which matches expect_exit=0: {cands}")


def _write_decisive_stub_izba(d):
    """Like _write_stub_izba but used for the decisive-grading integration test.

    Reuses the exact same contract: `__reconcile` -> empty snapshot,
    `bogus-subcommand` -> exit 2 (the setup step's non-zero exit), any other
    subcommand -> exit 0 (the core step's success). cd/file ops need no stubbing —
    run_action runs a real shell, so only `izba` itself is intercepted here."""
    return _write_stub_izba(d)


class RefusalNotReversedByRetryTests(unittest.TestCase):
    """DEEP-H1: an assertion the product SATISFIED, then followed by something
    else, must not be graded on the something else.

    `expect_cmd_re` selects the LAST matching action, which is right for "the
    Actor retried until it got it right" and wrong for "the refusal fired, then
    the Actor deliberately took the escape hatch the error message advertised".
    In `deep-command-line-grants-skip-the-review-gate` the refusal fired at
    action[6] EXACTLY as asserted and was scored against action[7]'s legitimate
    `--force` retry, turning a kept promise into two flipping candidates."""

    REFUSAL = ("izba: error: no reviewed diff — run `izba diff` first "
               "(or --force)")

    def _produced(self):
        return [
            {"command": "izba promote pin21", "exit_code": 1,
             "stderr_tail": self.REFUSAL, "stdout_tail": ""},
            {"command": "izba promote pin21 --force", "exit_code": 0,
             "stderr_tail": "WARNING: --force: promoting changes that were "
                            "never reviewed", "stdout_tail": "promoted pin21"},
        ]

    def _step(self):
        return {"intent": "promote without reviewing first",
                "expect": "izba refuses to promote an unreviewed diff",
                "expect_exit": "nonzero",
                "expect_stderr_re": "no reviewed diff",
                "expect_cmd_re": r"izba promote"}

    def test_refusal_satisfied_then_force_retry_is_not_a_candidate(self):
        import run_journeys as rj
        cands = rj._grade_step_functional(
            self._step(), self._produced(), {}, "pin21", True, action_index=1)
        self.assertFalse(
            cands, f"the refusal fired at action[0] exactly as asserted; the "
                   f"deliberate --force retry must not invert it: {cands}")

    def test_the_satisfying_action_is_recorded_as_an_auditable_credit(self):
        import run_journeys as rj
        credits = []
        rj._grade_step_functional(
            self._step(), self._produced(), {}, "pin21", True, action_index=1,
            step_index=2, credits=credits)
        self.assertEqual(len(credits), 1, credits)
        self.assertEqual(credits[0]["step_index"], 2)
        self.assertEqual(credits[0]["action_index"], 0)
        self.assertEqual(credits[0]["graded_cmd"], "izba promote pin21")

    def test_retry_until_right_still_grades_the_successful_retry(self):
        # The common case last-match exists for: the Actor got it wrong, then
        # got it right. Unchanged — no candidate, and no rescue needed.
        import run_journeys as rj
        produced = [{"command": "izba diff web", "exit_code": 2,
                     "stderr_tail": "no such sandbox", "stdout_tail": ""},
                    {"command": "izba diff webapp", "exit_code": 0,
                     "stderr_tail": "", "stdout_tail": "no changes"}]
        step = {"intent": "review the diff", "expect": "the diff renders",
                "expect_exit": 0, "expect_cmd_re": r"izba diff"}
        credits = []
        cands = rj._grade_step_functional(step, produced, {}, "j1", True,
                                          action_index=1, credits=credits)
        self.assertFalse(cands, cands)
        self.assertFalse(credits, "the LAST match already satisfied it; "
                                  "nothing to rescue and nothing to claim")

    def test_no_match_satisfies_still_flips_on_the_last_match(self):
        # Strictness preserved: when NO eligible action satisfied the
        # assertion, the verdict is still a candidate graded on the last match.
        import run_journeys as rj
        produced = [{"command": "izba promote a", "exit_code": 0,
                     "stderr_tail": "", "stdout_tail": ""},
                    {"command": "izba promote b", "exit_code": 0,
                     "stderr_tail": "", "stdout_tail": ""}]
        step = {"intent": "x", "expect": "izba refuses",
                "expect_exit": "nonzero", "expect_cmd_re": r"izba promote"}
        cands = rj._grade_step_functional(step, produced, {}, "j1", True,
                                          action_index=1)
        self.assertTrue(cands)
        self.assertEqual(cands[0]["graded_cmd"], "izba promote b")

    def test_rescue_also_applies_without_expect_cmd_re(self):
        # The same "satisfied, then the Actor did something else" shape with no
        # expect_cmd_re: the default target is the LAST product invocation.
        import run_journeys as rj
        produced = [{"command": "izba promote pin21", "exit_code": 1,
                     "stderr_tail": self.REFUSAL, "stdout_tail": ""},
                    {"command": "izba promote pin21 --force", "exit_code": 0,
                     "stderr_tail": "", "stdout_tail": ""}]
        step = {"intent": "x", "expect": "izba refuses",
                "expect_exit": "nonzero"}
        cands = rj._grade_step_functional(step, produced, {}, "j1", True,
                                          action_index=1)
        self.assertFalse(cands, cands)

    def test_a_success_expecting_step_is_never_rescued(self):
        # The rescue is scoped to a step that asserts a REFUSAL (a guard that
        # fires once has kept its promise; what the Actor does next is its own
        # business). A SUCCESS-expecting step keeps last-match authority: an
        # earlier success must never absolve a later failure, or the harness
        # would start hiding real bugs behind the Actor's first lucky attempt.
        import run_journeys as rj
        produced = [{"command": "izba start web", "exit_code": 0,
                     "stderr_tail": "", "stdout_tail": "started"},
                    {"command": "izba start web2", "exit_code": 1,
                     "stderr_tail": "izba: error: boot failed",
                     "stdout_tail": ""}]
        step = {"intent": "start a sandbox", "expect": "the sandbox starts",
                "expect_exit": 0, "expect_cmd_re": r"izba start"}
        credits = []
        cands = rj._grade_step_functional(step, produced, {}, "j1", True,
                                          action_index=1, credits=credits)
        self.assertTrue(cands, "the later failure is real signal")
        self.assertEqual(cands[0]["graded_cmd"], "izba start web2")
        self.assertFalse(credits)

    def test_a_stream_assertion_on_a_refusal_step_is_rescued_too(self):
        # Both halves of the assertion are re-graded on the rescued action, so
        # a step is only rescued by an action that satisfied it IN FULL.
        import run_journeys as rj
        step = {"intent": "x", "expect": "the refusal names the remedy",
                "expect_exit": "nonzero",
                "expect_stderr_re": r"run `izba diff` first",
                "expect_cmd_re": r"izba promote"}
        cands = rj._grade_step_functional(step, self._produced(), {}, "j1",
                                          True, action_index=1)
        self.assertFalse(cands, cands)

    def test_partial_satisfaction_does_not_rescue(self):
        # action[0] refuses (exit 1) but WITHOUT the asserted stderr; the step
        # must still flip — a rescue needs every declared assertion satisfied.
        import run_journeys as rj
        produced = [{"command": "izba promote pin21", "exit_code": 1,
                     "stderr_tail": "izba: error: something else entirely",
                     "stdout_tail": ""},
                    {"command": "izba promote pin21 --force", "exit_code": 0,
                     "stderr_tail": "", "stdout_tail": ""}]
        cands = rj._grade_step_functional(self._step(), produced, {}, "j1",
                                          True, action_index=1)
        self.assertTrue(cands)
        self.assertEqual(cands[0]["graded_cmd"], "izba promote pin21 --force")

    def test_credit_lands_in_the_bundle(self):
        # End to end through main(): the rescue is visible to the Phase-3
        # skeptic in `decisive_credits`, never a silent regrade.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "refusal",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "the gate must refuse",
                           "expect": "izba refuses", "core": True,
                           "expect_exit": "nonzero",
                           "expect_cmd_re": r"izba"}],
            }])
            out = os.path.join(d, "traj.json")
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([
                    {"command": "izba bogus-subcommand"},   # exit 2: the refusal
                    {"command": "izba ls"},                 # exit 0: the retry
                    {"done": True}]),
            ])
            self.assertEqual(rc, 0)
            with open(out) as f:
                result = json.load(f)["results"][0]
            self.assertFalse([c for c in result["candidates"]
                              if c["kind"] == "functional"],
                             result["candidates"])
            credits = result["decisive_credits"]
            self.assertEqual(len(credits), 1, credits)
            self.assertEqual(credits[0]["action_index"], 0)
            self.assertEqual(credits[0]["graded_cmd"], "izba bogus-subcommand")


class UnmatchedExpectCmdReTests(unittest.TestCase):
    """H2 (run-2 smoke skeptic): an `expect_cmd_re` that matched NOTHING in the
    step means the decisive command was never run — a materially different fact
    from "it ran and failed", and it must not be reported as the latter.

    In `smoke-find-the-surface-that-answers-bypass` the step declared
    `expect_cmd_re: "izba policy show"` and the Actor never ran it inside that
    step, so the old fallback graded the step's LAST action —
    `izba policy allow audit-me pinned.vendor.example` — against
    `expect_stdout_re 'pinning passthrough'`, fabricating a functional red on a
    command the assertion was never about. The honest kind already exists:
    `unreached_decisive`."""

    def _step(self, **kw):
        step = {"intent": "find izba's answer to 'is anything bypassing my "
                          "firewall?'",
                "expect": "izba names the one port that is exempt",
                "expect_cmd_re": r"izba policy show",
                "expect_exit": 0,
                "expect_stdout_re": "pinning passthrough"}
        step.update(kw)
        return step

    def _produced(self):
        return [
            {"command": "izba exec audit-me -- apk add curl", "exit_code": 0,
             "stdout_tail": "OK: 13 MiB in 24 packages", "stderr_tail": ""},
            {"command": "izba policy allow audit-me pinned.vendor.example",
             "exit_code": 0,
             "stdout_tail": "allowed pinned.vendor.example [80, 443] "
                            "access: read-write",
             "stderr_tail": ""},
        ]

    def test_no_functional_candidate_on_an_unrelated_command(self):
        import run_journeys as rj
        cands = rj._grade_step_functional(
            self._step(), self._produced(), {}, "bypass", True,
            action_index=1, step_index=1)
        self.assertFalse(
            [c for c in cands if c["kind"] == "functional"],
            f"`izba policy allow` was never the command under test: {cands}")

    def test_it_flips_unreached_decisive_instead(self):
        import run_journeys as rj
        cands = rj._grade_step_functional(
            self._step(), self._produced(), {}, "bypass", True,
            action_index=1, step_index=1)
        self.assertEqual([c["kind"] for c in cands], ["unreached_decisive"],
                         cands)
        self.assertIn("izba policy show", cands[0]["detail"])
        self.assertTrue(cands[0]["decisive"])

    def test_it_names_no_graded_cmd(self):
        # Nothing was graded, so the bundle must not point the skeptic at a
        # command as though it had been.
        import run_journeys as rj
        cands = rj._grade_step_functional(
            self._step(), self._produced(), {}, "bypass", True,
            action_index=1, step_index=1)
        self.assertIsNone(cands[0].get("graded_cmd"))

    def test_a_non_decisive_step_grades_nothing_at_all(self):
        # A non-decisive step's verdict never governs the journey, and the
        # fabricated grade is exactly what this fix removes: emit nothing
        # rather than an `unreached_decisive` that would newly FLIP the run.
        import run_journeys as rj
        self.assertEqual(
            rj._grade_step_functional(self._step(), self._produced(), {},
                                      "bypass", False, action_index=1,
                                      step_index=1),
            [])

    def test_a_matching_action_is_still_graded_normally(self):
        # Regression guard: when the declared command DID run, nothing changes.
        import run_journeys as rj
        produced = self._produced() + [
            {"command": "izba policy show audit-me", "exit_code": 0,
             "stdout_tail": "pinned.vendor.example [80, 443]\n"
                            "  :443 protocol: tcp — pinning passthrough",
             "stderr_tail": ""}]
        self.assertEqual(
            rj._grade_step_functional(self._step(), produced, {}, "bypass",
                                      True, action_index=2, step_index=1),
            [])

    def test_the_flip_reaches_the_bundle(self):
        # End to end: the journey tallies UNREACHED, not flipped, so the
        # Phase-3 skeptic is not handed a fabricated product finding.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "anchor", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "run the audit surface",
                           "expect": "it answers", "core": True,
                           "expect_cmd_re": r"izba policy show",
                           "expect_stdout_re": "pinning passthrough"}],
            }])
            out = os.path.join(d, "traj.json")
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba ls"},
                                            {"done": True}])])
            self.assertEqual(rc, 0)
            with open(out) as f:
                result = json.load(f)["results"][0]
            kinds = [c["kind"] for c in result["candidates"]]
            self.assertIn("unreached_decisive", kinds, result["candidates"])
            self.assertNotIn("functional", kinds, result["candidates"])


class ReobservationDoesNotInvertAPassTests(unittest.TestCase):
    """H3 (run-2 smoke skeptic): a step whose decisive assertion was satisfied
    must not be retroactively failed by a later RE-OBSERVATION whose different
    answer the journey itself caused.

    In `smoke-manifest-can-carry-the-firewall` the Actor ran `izba diff
    mani-egress` (matched `expect_stdout_re "(?s)state: repo ahead.*egress"` —
    the promise kept), then `izba promote mani-egress`, then the SAME `izba
    diff mani-egress`, whose honest `state: in sync` was graded as the step's
    result. Last-match is still the rule; the rescue is narrow — the earlier
    action must be the byte-identical command, must satisfy EVERY declared
    assertion, and something must have run in between."""

    DIFF_AHEAD = ("state: repo ahead (promotable)\n"
                  "showing: managed (current) -> izba.yml (proposed)\n"
                  "  egress:  [live]\n"
                  "    from (managed):\n      enforce: false\n"
                  "    to (izba.yml):\n"
                  "      enforce: true\n      allow:\n"
                  "      - api.vendor.example\n")

    def _step(self):
        return {"intent": "show how the project file differs from the "
                          "sandbox, before anything is applied",
                "expect": "izba reports the project file is ahead and lists "
                          "the firewall settings as a pending change",
                "expect_cmd_re": r"izba diff",
                "expect_exit": 0,
                "expect_stdout_re": r"(?s)state: repo ahead.*egress"}

    def _produced(self):
        return [
            {"command": "izba diff mani-egress", "exit_code": 0,
             "stdout_tail": self.DIFF_AHEAD, "stderr_tail": ""},
            {"command": "izba promote mani-egress", "exit_code": 0,
             "stdout_tail": "promoted mani-egress", "stderr_tail": ""},
            {"command": "izba diff mani-egress", "exit_code": 0,
             "stdout_tail": "state: in sync\n", "stderr_tail": ""},
        ]

    def test_the_satisfied_step_is_not_flipped(self):
        import run_journeys as rj
        cands = rj._grade_step_functional(
            self._step(), self._produced(), {}, "mani", True, action_index=2,
            step_index=2)
        self.assertFalse(cands, f"action[0] satisfied the assertion in full; "
                                f"action[2] merely re-asked after the promote "
                                f"the journey itself performed: {cands}")

    def test_the_rescue_is_recorded_as_an_auditable_credit(self):
        import run_journeys as rj
        credits = []
        rj._grade_step_functional(
            self._step(), self._produced(), {}, "mani", True, action_index=2,
            step_index=2, credits=credits)
        self.assertEqual(len(credits), 1, credits)
        self.assertEqual(credits[0]["step_index"], 2)
        self.assertEqual(credits[0]["action_index"], 0)
        self.assertEqual(credits[0]["graded_cmd"], "izba diff mani-egress")
        self.assertEqual(credits[0]["rescue"], "re-observation")

    def test_the_later_disagreement_is_never_buried(self):
        # The rescue may not silently discard the later, failing observation:
        # a skeptic auditing the green must see WHAT diverged, or "an earlier
        # hit passed the step" becomes unfalsifiable from the bundle alone.
        import run_journeys as rj
        credits = []
        rj._grade_step_functional(
            self._step(), self._produced(), {}, "mani", True, action_index=2,
            step_index=2, credits=credits)
        sup = credits[0]["superseded_by"]
        self.assertEqual(sup["action_index"], 2)
        self.assertEqual(sup["graded_cmd"], "izba diff mani-egress")
        self.assertTrue(sup["candidates"], sup)
        self.assertIn("state: in sync", sup["candidates"][0]["detail"])

    def test_a_different_later_command_is_not_a_reobservation(self):
        # The narrowing that keeps last-match honest: `izba diff other` is a
        # NEW question, not the same one re-asked, so its failure is real
        # signal and the step still flips.
        import run_journeys as rj
        produced = self._produced()[:2] + [
            {"command": "izba diff other-sandbox", "exit_code": 1,
             "stdout_tail": "", "stderr_tail": "izba: error: no such sandbox"}]
        credits = []
        cands = rj._grade_step_functional(
            self._step(), produced, {}, "mani", True, action_index=2,
            step_index=2, credits=credits)
        self.assertTrue(cands, "a different command's failure is real signal")
        self.assertEqual(cands[0]["graded_cmd"], "izba diff other-sandbox")
        self.assertFalse(credits)

    def test_back_to_back_disagreement_still_flips(self):
        # Nothing ran in between, so the world had no chance to move on: the
        # same command answering differently twice in a row is instability,
        # and last-match keeps its authority.
        import run_journeys as rj
        produced = [self._produced()[0], self._produced()[2]]
        cands = rj._grade_step_functional(
            self._step(), produced, {}, "mani", True, action_index=1,
            step_index=2)
        self.assertTrue(cands, "adjacent re-runs disagreeing is a finding")
        self.assertEqual(cands[0]["trajectory_ref"]["action_index"], 1)


    # --- the shape the smoke run actually produced -----------------------
    # The Actor ran `izba diff` (the pass) and `izba promote` while still
    # inside the PREVIOUS step, so the decisive step's own actions contain
    # only the second, `in sync` diff. The rescue must reach it: the harness
    # already credits a decisive step from an earlier STEP's action
    # (`_grade_decisive_from_observed`), and the same fact is no less true
    # when the step did produce actions of its own.

    def _journey_actions(self):
        return [
            {"command": "izba run -d --name mani-egress .", "exit_code": 0,
             "stdout_tail": "", "stderr_tail": ""},
            {"command": "cat > izba.yml <<'EOF'\nspec:\nEOF\n",
             "exit_code": 0, "stdout_tail": "", "stderr_tail": ""},
            {"command": "izba diff mani-egress", "exit_code": 0,
             "stdout_tail": self.DIFF_AHEAD, "stderr_tail": ""},
            {"command": "izba promote mani-egress", "exit_code": 0,
             "stdout_tail": "promoted mani-egress", "stderr_tail": ""},
            {"command": "izba diff mani-egress", "exit_code": 0,
             "stdout_tail": "state: in sync\n", "stderr_tail": ""},
        ]

    def test_a_pass_under_the_previous_step_still_rescues(self):
        import run_journeys as rj
        acts = self._journey_actions()
        credits = []
        cands = rj._grade_step_functional(
            self._step(), acts[4:], {}, "mani", True, action_index=4,
            step_index=2, credits=credits, actions=acts)
        self.assertFalse(cands, f"action[2] printed the promised diff; the "
                                f"promote the journey itself ran is why "
                                f"action[4] says `in sync`: {cands}")
        self.assertEqual(credits[0]["action_index"], 2)
        self.assertEqual(credits[0]["rescue"], "re-observation")
        self.assertEqual(credits[0]["superseded_by"]["action_index"], 4)

    def test_a_predrift_reobservation_cannot_rescue(self):
        # The established state boundary: a step-level `seed_files` injection
        # means an action recorded before it observed PRE-drift state, so it
        # can never satisfy an assertion about the post-drift world. Same
        # discipline `_grade_decisive_from_observed` already enforces.
        import run_journeys as rj
        acts = self._journey_actions()
        credits = []
        cands = rj._grade_step_functional(
            self._step(), acts[4:], {}, "mani", True, action_index=4,
            step_index=2, credits=credits, actions=acts, min_action_index=4)
        self.assertTrue(cands, "the only satisfying observation is pre-drift")
        self.assertEqual(cands[0]["trajectory_ref"]["action_index"], 4)
        self.assertFalse(credits)

    def test_a_cross_step_rescue_still_needs_the_same_command(self):
        import run_journeys as rj
        acts = self._journey_actions()
        acts[2] = dict(acts[2], command="izba diff --json mani-egress")
        cands = rj._grade_step_functional(
            self._step(), acts[4:], {}, "mani", True, action_index=4,
            step_index=2, actions=acts)
        self.assertTrue(cands, "a different invocation is a different "
                               "question, not the same one re-asked")

    def test_partial_satisfaction_does_not_rescue(self):
        # The earlier action printed the right thing but exited non-zero:
        # a rescue needs EVERY declared assertion, exactly as on a refusal step.
        import run_journeys as rj
        produced = self._produced()
        produced[0] = dict(produced[0], exit_code=1)
        cands = rj._grade_step_functional(
            self._step(), produced, {}, "mani", True, action_index=2,
            step_index=2)
        self.assertTrue(cands, cands)
        self.assertEqual(cands[0]["graded_cmd"], "izba diff mani-egress")
        self.assertEqual(cands[0]["trajectory_ref"]["action_index"], 2)


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


class DecisiveByObservedCommandTest(unittest.TestCase):
    def test_decisive_satisfied_under_earlier_step_is_not_unreached(self):
        import run_journeys as rj
        from model import FakeModel
        # Step 0's model turn runs the DECISIVE command (a real izba-shaped
        # invocation, via the stub izba on PATH) and then the model goes done
        # for the rest; step 1 (core) produces no actions.
        model = FakeModel([
            {"command": "izba ls"},  # a real product invocation for step 0
            {"done": True},          # step 0 ends
            {"done": True},          # step 1 produces nothing
        ])
        journey = {"journey_id": "early-decisive",
                   "steps": [
                       {"intent": "explore", "expect": ""},
                       {"intent": "verify drift shows", "expect": "",
                        "core": True, "expect_exit": 0,
                        "expect_cmd_re": r"izba ls"}]}
        with tempfile.TemporaryDirectory() as td:
            stub = _write_decisive_stub_izba(td)
            res = rj.run_journey(
                model, journey, izba_bin=stub, data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertNotIn(
            "unreached_decisive", kinds,
            f"decisive assertion was exercised under step 0: {res['candidates']}")
        # The credit itself must be recorded in the bundle so the Phase-3
        # skeptic can audit it (Greptile P2: a silent pass left no artifact).
        self.assertEqual(
            res["decisive_credits"],
            [{"step_index": 1, "action_index": 0, "graded_cmd": "izba ls"}])

    def test_predrift_action_does_not_credit_decisive_step(self):
        # Reproduces the observed false-green: step 0 runs a baseline command,
        # step 1 injects mid-journey drift via step-level seed_files, and step
        # 2 (core) is decisive with an expect_cmd_re that matches ONLY step
        # 0's pre-drift action. The Actor never reaches step 2 (zero actions).
        # The old, position-blind scan credited step 2 from step 0's action
        # anyway; a step-level seed_files is a state boundary and must refuse
        # to credit anything recorded before it.
        import run_journeys as rj
        from model import FakeModel
        model = FakeModel([
            {"command": "izba policy show"},  # step 0: baseline, pre-drift
            {"done": True},                   # step 0 ends
            {"done": True},                   # step 1: seed_files, zero actions
            {"done": True},                   # step 2 (core): zero actions
        ])
        journey = {"journey_id": "predrift-not-credited",
                   "steps": [
                       {"intent": "baseline", "expect": ""},
                       {"intent": "inject drift", "expect": "",
                        "seed_files": {"izba.yml": "version: 1\n"}},
                       {"intent": "verify post-drift state", "expect": "",
                        "core": True, "expect_exit": 0,
                        "expect_cmd_re": r"izba policy show"}]}
        with tempfile.TemporaryDirectory() as td:
            stub = _write_decisive_stub_izba(td)
            res = rj.run_journey(
                model, journey, izba_bin=stub, data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertIn(
            "unreached_decisive", kinds,
            f"pre-drift action must not credit the decisive step: {res['candidates']}")
        self.assertEqual(res["decisive_credits"], [],
                          "the only match is pre-drift; nothing should be credited")

    def test_postdrift_action_still_credits_decisive_step(self):
        # The watermark is positional, not a blanket refusal for any step that
        # happens to carry seed_files: an action recorded AFTER the step-level
        # seed_files injection (even within that same step) still legitimately
        # satisfies a later decisive step's expect_cmd_re.
        import run_journeys as rj
        from model import FakeModel
        model = FakeModel([
            {"done": True},                   # step 0: no actions, no drift
            {"command": "izba policy show"},  # step 1: seed_files, then a post-drift action
            {"done": True},                   # step 1 ends
            {"done": True},                   # step 2 (core): zero actions
        ])
        journey = {"journey_id": "postdrift-credited",
                   "steps": [
                       {"intent": "baseline", "expect": ""},
                       {"intent": "inject drift then observe", "expect": "",
                        "seed_files": {"izba.yml": "version: 1\n"}},
                       {"intent": "verify post-drift state", "expect": "",
                        "core": True, "expect_exit": 0,
                        "expect_cmd_re": r"izba policy show"}]}
        with tempfile.TemporaryDirectory() as td:
            stub = _write_decisive_stub_izba(td)
            res = rj.run_journey(
                model, journey, izba_bin=stub, data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertNotIn(
            "unreached_decisive", kinds,
            f"post-drift action should credit the decisive step: {res['candidates']}")
        self.assertEqual(
            res["decisive_credits"],
            [{"step_index": 2, "action_index": 0,
              "graded_cmd": "izba policy show"}])

    def test_watermark_refusal_log_is_truthful_when_a_predrift_match_exists(self):
        # A genuine pre-drift match: action 0 (below the watermark) DOES
        # match the pattern, action 1 (at/after the watermark) does not. The
        # refusal log's "only matched pre-drift action(s)" claim is accurate
        # here.
        import io
        import contextlib
        import run_journeys as rj
        actions = [{"command": "izba policy show", "exit_code": 0},
                   {"command": "izba ls", "exit_code": 0}]
        step = {"expect_cmd_re": r"izba policy show", "expect_exit": 0,
                "expect": ""}
        journey = {"journey_id": "j"}
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            graded = rj._grade_decisive_from_observed(
                step, actions, journey, "j", min_action_index=1)
        self.assertIsNone(graded)
        self.assertIn("only matched pre-drift action(s)", buf.getvalue())

    def test_watermark_refusal_log_is_truthful_when_nothing_matched_at_all(self):
        # Greptile finding: no action anywhere (before OR after the
        # watermark) matches the pattern — the old log unconditionally
        # claimed "only matched pre-drift action(s)" the moment the scan
        # crossed the watermark, which is FALSE here: nothing ever matched.
        import io
        import contextlib
        import run_journeys as rj
        actions = [{"command": "izba ls", "exit_code": 0},
                   {"command": "izba diff", "exit_code": 0}]
        step = {"expect_cmd_re": r"izba policy show", "expect_exit": 0,
                "expect": ""}
        journey = {"journey_id": "j"}
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            graded = rj._grade_decisive_from_observed(
                step, actions, journey, "j", min_action_index=1)
        self.assertIsNone(graded)
        self.assertNotIn(
            "only matched pre-drift action(s)", buf.getvalue(),
            f"no action anywhere matched; the log must not claim a "
            f"pre-drift match existed: {buf.getvalue()!r}")

    def test_empty_seed_files_dict_still_moves_the_watermark(self):
        # Greptile finding: the schema declares no minProperties, so
        # `seed_files: {}` is legal — an author might write it as a no-op
        # placeholder. It still establishes the pre-drift boundary: this is
        # a deliberate fail-closed pin (declaring the key at all is the
        # signal, not whether _write_seeds actually materialized a file).
        import run_journeys as rj
        from model import FakeModel
        model = FakeModel([
            {"command": "izba policy show"},  # step 0: pre-boundary baseline
            {"done": True},
            {"done": True},                   # step 1: seed_files={}, zero actions
            {"done": True},                   # step 2 (core): zero actions
        ])
        journey = {"journey_id": "empty-seed-dict-watermark",
                   "steps": [
                       {"intent": "baseline", "expect": ""},
                       {"intent": "declare an empty drift boundary", "expect": "",
                        "seed_files": {}},
                       {"intent": "verify post-drift state", "expect": "",
                        "core": True, "expect_exit": 0,
                        "expect_cmd_re": r"izba policy show"}]}
        with tempfile.TemporaryDirectory() as td:
            stub = _write_decisive_stub_izba(td)
            res = rj.run_journey(
                model, journey, izba_bin=stub, data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertIn("unreached_decisive", kinds, res["candidates"])
        self.assertEqual(res["decisive_credits"], [])

    def test_fully_rejected_seed_files_dict_still_moves_the_watermark(self):
        # Same pin, but the single entry is one _write_seeds rejects outright
        # (an absolute path fails the traversal guard) — no file is ever
        # written to disk, yet declaring the key still moves the watermark.
        import run_journeys as rj
        from model import FakeModel
        model = FakeModel([
            {"command": "izba policy show"},  # step 0: pre-boundary baseline
            {"done": True},
            {"done": True},                   # step 1: seed_files all-rejected
            {"done": True},                   # step 2 (core): zero actions
        ])
        journey = {"journey_id": "rejected-seed-dict-watermark",
                   "steps": [
                       {"intent": "baseline", "expect": ""},
                       {"intent": "declare a rejected drift boundary", "expect": "",
                        "seed_files": {"/etc/evil": "nope\n"}},
                       {"intent": "verify post-drift state", "expect": "",
                        "core": True, "expect_exit": 0,
                        "expect_cmd_re": r"izba policy show"}]}
        with tempfile.TemporaryDirectory() as td:
            stub = _write_decisive_stub_izba(td)
            res = rj.run_journey(
                model, journey, izba_bin=stub, data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertIn("unreached_decisive", kinds, res["candidates"])
        self.assertEqual(res["decisive_credits"], [])
        # And confirm the rejected entry really never landed on disk.
        jdir = run_journeys._journey_data_dir(td, "rejected-seed-dict-watermark")
        self.assertFalse(os.path.exists(os.path.join(jdir, "proj", "etc", "evil")))

    def test_non_product_command_does_not_credit_unreached_decisive(self):
        # Greptile P1: a broad-but-valid expect_cmd_re (e.g. bare `izba`) must
        # NOT be satisfied by a non-product command like `echo izba diff
        # looks-good` from an earlier step — only an actual izba invocation in
        # command position can credit an unreached decisive step.
        import run_journeys as rj
        from model import FakeModel
        model = FakeModel([
            {"command": "echo izba diff looks-good"},  # prose, not a product call
            {"done": True},   # step 0 ends
            {"done": True},   # step 1 (core) produces nothing
        ])
        journey = {"journey_id": "echo-not-credited",
                   "steps": [
                       {"intent": "explore", "expect": ""},
                       {"intent": "verify drift shows", "expect": "",
                        "core": True, "expect_exit": 0,
                        "expect_cmd_re": r"izba"}]}
        with tempfile.TemporaryDirectory() as td:
            res = rj.run_journey(
                model, journey, izba_bin="/bin/false", data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertIn(
            "unreached_decisive", kinds,
            f"echo izba ... must not credit the decisive step: {res['candidates']}")
        self.assertEqual(res["decisive_credits"], [],
                          "no izba invocation was observed; nothing should be credited")

    def test_decisive_without_match_still_flags_unreached(self):
        import run_journeys as rj
        from model import FakeModel
        model = FakeModel([{"command": "true"}, {"done": True}, {"done": True}])
        journey = {"journey_id": "never-reached",
                   "steps": [
                       {"intent": "explore", "expect": ""},
                       {"intent": "verify", "expect": "", "core": True,
                        "expect_cmd_re": r"izba promote"}]}
        with tempfile.TemporaryDirectory() as td:
            res = rj.run_journey(
                model, journey, izba_bin="/bin/false", data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertIn("unreached_decisive", kinds)
        # No credit was made (nothing matched) — the audit trail stays empty.
        self.assertEqual(res["decisive_credits"], [])

    def test_degenerate_expect_cmd_re_does_not_credit_unreached_decisive(self):
        # A decisive step declaring `expect_cmd_re: ".*"` matches EVERY action
        # (including the empty string) — crediting it against an earlier,
        # unrelated action would be a false green. It must still flag
        # unreached_decisive, even though earlier steps produced actions.
        import run_journeys as rj
        from model import FakeModel
        model = FakeModel([{"command": "true"}, {"done": True}, {"done": True}])
        journey = {"journey_id": "degenerate-regex",
                   "steps": [
                       {"intent": "explore", "expect": ""},
                       {"intent": "verify", "expect": "", "core": True,
                        "expect_cmd_re": ".*"}]}
        with tempfile.TemporaryDirectory() as td:
            res = rj.run_journey(
                model, journey, izba_bin="/bin/false", data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertIn(
            "unreached_decisive", kinds,
            f"degenerate expect_cmd_re must not be credited: {res['candidates']}")


class CreditCmdRegexTest(unittest.TestCase):
    """Direct unit coverage of `_CREDIT_CMD_RE` (Greptile P1): it must accept
    `izba` in COMMAND POSITION (start of a shell segment, optionally after env
    assignments) and reject `izba` appearing merely as an argument/word/filename."""

    def test_matches_izba_in_command_position(self):
        import run_journeys as rj
        for cmd in [
            "izba diff .",
            "cd x && izba diff",
            "FOO=1 izba run",
            "izba ls | grep x",
            "(izba status)",
        ]:
            self.assertTrue(rj._CREDIT_CMD_RE.search(cmd), cmd)

    def test_rejects_izba_as_mere_argument_or_filename(self):
        import run_journeys as rj
        for cmd in [
            "echo izba",
            "cat izba.yml",
            "grep izba log.txt",
            "./izba run",
        ]:
            self.assertFalse(rj._CREDIT_CMD_RE.search(cmd), cmd)


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

    def test_without_anchor_a_satisfied_refusal_is_credited_not_flipped(self):
        # Same trajectory WITHOUT expect_cmd_re. This USED to grade the final
        # action (ls, exit 0) against nonzero and fire a false candidate — the
        # motivation for expect_cmd_re, and the same defect DEEP-H1 fixes at
        # the root: the refusal DID fire at action[0], so the step passes and
        # the rescue is recorded for audit. `expect_cmd_re` still matters for
        # success-expecting steps (never rescued) and for pinning which action
        # a candidate points at.
        step = {"intent": "try the guarded op", "expect": "must be refused",
                "expect_exit": "nonzero", "core": True}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [
                {"command": "izba bogus-subcommand"},
                {"command": "izba ls"},
                {"done": True}])
            func = [c for c in res["candidates"] if c["kind"] == "functional"]
            self.assertEqual(func, [], func)
            self.assertEqual(
                [(c["step_index"], c["action_index"], c["graded_cmd"])
                 for c in res["decisive_credits"]],
                [(0, 0, "izba bogus-subcommand")])

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


class StarvationTallyTest(unittest.TestCase):
    def test_repeated_model_failures_yield_one_infra_candidate(self):
        # Two steps; the model errors on BOTH turns -> previously 2 per-reply
        # infra candidates, now ONE tally candidate for the journey.
        model = FakeModel([{"error": "unparseable model reply: 'x'"},
                           {"error": "unparseable model reply: 'y'"}])
        journey = {"journey_id": "starved-j",
                   "steps": [{"intent": "a", "expect": ""},
                             {"intent": "b", "expect": ""}]}
        with tempfile.TemporaryDirectory() as td:
            res = run_journeys.run_journey(
                model, journey, izba_bin="/bin/false", data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=5,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        infra = [c for c in res["candidates"] if c.get("kind") == "infra"]
        self.assertEqual(
            len(infra), 1,
            f"starvation must coalesce to ONE infra candidate: {infra}")
        self.assertIn("2 failed turn(s)", infra[0]["detail"])
        self.assertIn("unparseable", infra[0]["detail"])
        # Degradation semantics unchanged: the journey still counts degraded.
        self.assertEqual(run_journeys.count_degraded([res]), 1)


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


def _write_echoing_stub_izba(d):
    """A stub `izba` that ECHOES its arguments, so a test can assert on WHAT a
    command printed (the expect_stdout_re surface) rather than only on its exit
    code. `__reconcile` keeps the empty-snapshot contract."""
    stub = os.path.join(d, "izba")
    with open(stub, "w") as f:
        f.write(
            "#!/bin/sh\n"
            'if [ "$1" = "__reconcile" ]; then echo \'{"violations":[],"sandboxes":[]}\'; exit 0; fi\n'
            'if [ "$1" = "bogus-subcommand" ]; then echo "error: unrecognized subcommand" 1>&2; exit 2; fi\n'
            'echo "izba-said: $*"\n'
            "exit 0\n"
        )
    os.chmod(stub, 0o755)
    return stub


class ExpectStdoutReTests(unittest.TestCase):
    """Defect 3: `expect_exit` grades the exit code and `expect_cmd_re` selects
    WHICH action is graded — neither can assert WHAT the command printed. A
    decisive step meaning "the audit log shows this flow was spliced opaquely,
    not terminated at L7" was graded purely on `izba netlog` exiting 0, which
    is true whichever way the flow actually went."""

    def _run(self, d, step, script, journey_extra=None):
        stub = _write_echoing_stub_izba(d)
        journey = {"journey_id": "stdout-anchor", "rationale": "r",
                   "source": {"kind": "spec", "ref": "x"},
                   "steps": [step]}
        journey.update(journey_extra or {})
        jf = _journeys_file(d, [journey])
        out = os.path.join(d, "traj.json")
        run_journeys.main([
            "--journeys", jf, "--shard", "0", "--shards", "1",
            "--izba-bin", stub, "--data-dir", d, "--out", out,
            "--fake-model", json.dumps(script),
            "--step-cap", "25", "--action-timeout-s", "10",
            "--max-turns", "10", "--max-usd", "5"])
        with open(out) as f:
            return json.load(f)["results"][0]

    def test_stdout_mismatch_flips_the_decisive_step(self):
        step = {"intent": "read the audit log", "expect": "the flow is spliced",
                "core": True, "expect_stdout_re": r"passthrough"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba netlog demo"},
                                      {"done": True}])
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertTrue(func[0].get("decisive"), func[0])
        self.assertEqual(func[0].get("graded_cmd"), "izba netlog demo")
        self.assertIn("passthrough", func[0]["detail"])

    def test_stdout_match_passes(self):
        step = {"intent": "read the audit log", "expect": "the flow is spliced",
                "core": True, "expect_stdout_re": r"izba-said: netlog"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba netlog demo"},
                                      {"done": True}])
        self.assertEqual([c for c in res["candidates"]
                          if c["kind"] == "functional"], [])

    def test_composes_with_expect_exit(self):
        # The exit-code half HOLDS (0) and the stdout half does not: the step
        # must still grade negative — both declared assertions must hold.
        step = {"intent": "read the audit log", "expect": "the flow is spliced",
                "core": True, "expect_exit": 0,
                "expect_stdout_re": r"terminated at L7"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba netlog demo"},
                                      {"done": True}])
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertIn("terminated at L7", func[0]["detail"])

    def test_graded_against_the_expect_cmd_re_selected_action(self):
        # Same selection rule as expect_exit: the LAST action matching
        # expect_cmd_re, not the step's trailing verify (whose stdout WOULD
        # have matched — so a runner grading the wrong action passes here).
        step = {"intent": "read the audit log then peek", "expect": "spliced",
                "core": True, "expect_cmd_re": r"izba netlog",
                "expect_stdout_re": r"izba-said: ls"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba netlog demo"},
                                      {"command": "izba ls"},
                                      {"done": True}])
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertEqual(func[0].get("graded_cmd"), "izba netlog demo")

    def test_unparseable_regex_degrades_to_infra_never_silent(self):
        step = {"intent": "read the audit log", "expect": "spliced",
                "core": True, "expect_stdout_re": "["}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba netlog demo"},
                                      {"done": True}])
        self.assertTrue([c for c in res["candidates"] if c["kind"] == "infra"],
                        res["candidates"])

    def test_credit_from_an_earlier_action_still_grades_stdout(self):
        # H3 credit path: a decisive step the Actor never reached may be
        # credited from an earlier action via expect_cmd_re. That credit must
        # not skip the stdout assertion — otherwise the very false-green this
        # hook closes reopens on the credit path.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_echoing_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "stdout-credit", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [
                    {"intent": "look at the log", "expect": ""},
                    {"intent": "assert the splice", "expect": "spliced",
                     "core": True, "expect_cmd_re": r"izba netlog",
                     "expect_stdout_re": r"passthrough"}]}])
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba netlog demo"},
                                            {"done": True}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5"])
            with open(out) as f:
                res = json.load(f)["results"][0]
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertTrue(func[0].get("decisive"), func[0])


def _write_reconcile_stub_izba(d, sandboxes="[]", reconcile_exit=0):
    """A stub `izba` whose `__reconcile` reports a chosen sandbox list (or
    FAILS, when ``reconcile_exit`` is non-zero — the no-evidence path). Every
    other subcommand echoes and exits 0, so state grading is what the test is
    measuring, not the exit code."""
    stub = os.path.join(d, "izba")
    with open(stub, "w") as f:
        f.write(
            "#!/bin/sh\n"
            'if [ "$1" = "__reconcile" ]; then\n'
            f'  if [ {reconcile_exit} -ne 0 ]; then echo "boom" 1>&2; exit {reconcile_exit}; fi\n'
            f'  echo \'{{"violations":[],"sandboxes":{sandboxes}}}\'; exit 0\n'
            "fi\n"
            'echo "izba-said: $*"\n'
            "exit 0\n"
        )
    os.chmod(stub, 0o755)
    return stub


def _write_mutable_state_stub_izba(d):
    """A stub `izba` with REAL state: `create` plants a marker, `rm` removes
    it, and `__reconcile` reports the sandbox iff the marker exists — so a
    journey's daemon truth genuinely differs between step 0 and step 1."""
    stub = os.path.join(d, "izba")
    marker = os.path.join(d, "created")
    with open(stub, "w") as f:
        f.write(
            "#!/bin/sh\n"
            'if [ "$1" = "__reconcile" ]; then\n'
            f'  if [ -f {marker} ]; then\n'
            '    echo \'{"violations":[],"sandboxes":[{"name":"web","status_disk":"running"}]}\'\n'
            "  else\n"
            '    echo \'{"violations":[],"sandboxes":[]}\'\n'
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            f'if [ "$1" = "create" ]; then : > {marker}; echo created; exit 0; fi\n'
            f'if [ "$1" = "rm" ]; then rm -f {marker}; echo removed; exit 0; fi\n'
            'echo "izba-said: $*"\n'
            "exit 0\n"
        )
    os.chmod(stub, 0o755)
    return stub


class MidJourneyExpectStateTests(unittest.TestCase):
    """DEEP-H2: an `expect_state` about a MID-JOURNEY moment must be graded at
    that moment.

    `_grade_decisive_state_hooks` ran once, against the end-of-journey
    `capture_state_evidence` snapshot. In
    `deep-command-line-grants-skip-the-review-gate` step 1's assertion was
    satisfied at action[3]/[4] and then legitimately undone by the journey's
    OWN step 2 — so the oracle reported a divergence for a promise that was
    kept. Grading a step against a snapshot taken after later steps changed
    the world is grading the wrong fixture, which is exactly the class of
    harness lie this instrument keeps having to close."""

    def _journey(self, steps):
        return {"journey_id": "mid-state", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"}, "steps": steps}

    def _run(self, d, steps, script):
        return run_journeys.run_journey(
            FakeModel(script), self._journey(steps),
            izba_bin=_write_mutable_state_stub_izba(d), data_dir=d,
            max_turns=12, step_cap=25, action_timeout_s=10,
            latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=5.0)

    STEPS = [
        {"intent": "create the sandbox", "expect": "it exists", "core": True,
         "expect_state": {"sandboxes_exact": ["web"]}},
        {"intent": "then tidy up", "expect": "it is gone"},
    ]
    SCRIPT = [{"command": "izba create web"}, {"done": True},
              {"command": "izba rm web --force"}, {"done": True}]

    def test_step_assertion_is_graded_at_its_own_step_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, self.STEPS, self.SCRIPT)
        self.assertEqual([c for c in res["candidates"]
                          if c["kind"] in ("functional", "infra",
                                           "unreached_decisive")],
                         [], "step 0's assertion held AT step 0; a later step "
                             "legitimately undoing it is not a product bug")
        credits = [c for c in res["decisive_credits"]
                   if "expect_state" in (c.get("graded_cmd") or "")]
        self.assertEqual(len(credits), 1, res["decisive_credits"])

    def test_the_step_boundary_snapshot_is_in_the_bundle(self):
        # A credit graded against evidence nobody can see is not auditable:
        # the snapshot the grade was drawn from ships with the journey.
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, self.STEPS, self.SCRIPT)
        steps_ev = res["state_evidence_steps"]
        self.assertIn("0", steps_ev, steps_ev)
        self.assertEqual(steps_ev["0"]["sandboxes"], ["web"])
        # ... and the end-of-journey snapshot still tells the other truth.
        self.assertEqual(res["state_evidence"]["sandboxes"], [])

    def test_a_bundle_carrying_step_snapshots_validates(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        with tempfile.TemporaryDirectory() as d:
            stub = _write_mutable_state_stub_izba(d)
            jf = _journeys_file(d, [self._journey(self.STEPS)])
            out = os.path.join(d, "traj.json")
            run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(self.SCRIPT)])
            with open(out) as f:
                bundle = json.load(f)
            self.assertIn("state_evidence_steps", bundle["results"][0])
            schema_path = os.path.join(os.path.dirname(
                os.path.abspath(run_journeys.__file__)),
                "schema", "trajectory.schema.json")
            with open(schema_path) as f:
                jsonschema.validate(bundle, json.load(f))

    def test_a_genuinely_wrong_step_state_still_flips(self):
        # Strictness preserved: when the assertion was false AT ITS OWN step,
        # the decisive functional candidate still fires.
        steps = [dict(self.STEPS[0]), dict(self.STEPS[1])]
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, steps,
                            [{"command": "izba ls"}, {"done": True},
                             {"command": "izba ls --json"}, {"done": True}])
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertIn("expect_state", func[0]["detail"])

    def test_final_step_still_grades_on_the_end_of_journey_snapshot(self):
        # No behavior change (and no extra capture) for the common shape: the
        # decisive step is the last one.
        steps = [{"intent": "create", "expect": "ok"},
                 {"intent": "and it is there", "expect": "it exists",
                  "core": True,
                  "expect_state": {"sandboxes_exact": ["web"]}}]
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, steps,
                            [{"command": "izba ls"}, {"done": True},
                             {"command": "izba create web"}, {"done": True}])
        self.assertEqual([c for c in res["candidates"]
                          if c["kind"] in ("functional", "infra",
                                           "unreached_decisive")], [],
                         res["candidates"])
        self.assertEqual(res.get("state_evidence_steps", {}), {},
                         "the last step needs no extra snapshot")


class CliExpectStateTests(unittest.TestCase):
    """Defect 2: the journey schema puts `expect_state` on `step`
    unconditionally and the GUI runner grades it, but the CLI runner never
    read it — declaring it on a CLI journey validated against the schema and
    was then silently discarded, leaving the decisive step graded on an exit
    code alone."""

    def _run(self, d, stub, step, script=None):
        # run_journey directly (not main): the data dir is then exactly ``d``,
        # so a test can plant the managed policy.yaml the assertion reads.
        journey = {"journey_id": "state-hook", "rationale": "r",
                   "source": {"kind": "spec", "ref": "x"},
                   "steps": [step]}
        model = FakeModel(script or [{"command": "izba ls"}, {"done": True}])
        return run_journeys.run_journey(
            model, journey, izba_bin=stub, data_dir=d,
            max_turns=10, step_cap=25, action_timeout_s=10,
            latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=5.0)

    def test_failing_expect_state_flips_the_decisive_step(self):
        # The command exits 0 (the only thing the old runner graded) but the
        # asserted daemon truth is false: the journey must grade NEGATIVE.
        step = {"intent": "create the sandbox", "expect": "it exists",
                "core": True,
                "expect_state": {"sandbox": "demo", "exists": True}}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, _write_reconcile_stub_izba(d), step)
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertTrue(func[0].get("decisive"), func[0])
        self.assertIn("expect_state", func[0]["detail"])

    def test_holding_expect_state_records_an_auditable_credit(self):
        step = {"intent": "leave nothing behind", "expect": "no sandboxes",
                "core": True, "expect_state": {"sandboxes_exact": []}}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, _write_reconcile_stub_izba(d), step)
        self.assertEqual([c for c in res["candidates"]
                          if c["kind"] in ("functional", "infra",
                                           "unreached_decisive")], [])
        credits = [c for c in res["decisive_credits"]
                   if "expect_state" in (c.get("graded_cmd") or "")]
        self.assertEqual(len(credits), 1, res["decisive_credits"])
        self.assertEqual(credits[0]["step_index"], 0)

    def test_unverifiable_expect_state_degrades_to_infra(self):
        step = {"intent": "create the sandbox", "expect": "it exists",
                "core": True,
                "expect_state": {"sandbox": "demo", "exists": False}}
        with tempfile.TemporaryDirectory() as d:
            stub = _write_reconcile_stub_izba(d, reconcile_exit=1)
            res = self._run(d, stub, step)
        infra = [c for c in res["candidates"]
                 if c["kind"] == "infra" and "expect_state" in c["detail"]]
        self.assertEqual(len(infra), 1, res["candidates"])
        self.assertEqual([c for c in res["candidates"]
                          if c["kind"] == "functional"], [])

    def test_malformed_expect_state_is_never_silently_dropped(self):
        # A declared-but-ungradable hook (no assertion key at all) must flip,
        # not pass: silence is the one option that is not acceptable.
        step = {"intent": "do the thing", "expect": "it worked", "core": True,
                "expect_state": {"sandbox": "demo"}}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, _write_reconcile_stub_izba(d), step)
        self.assertTrue([c for c in res["candidates"]
                         if c["kind"] == "unreached_decisive"],
                        res["candidates"])
        self.assertEqual(res["decisive_credits"], [])

    def test_policy_vocabulary_is_graded_from_the_managed_policy_yaml(self):
        # The `expect_state.policy` sub-assertion (the saved-policy oracle)
        # must work on a CLI journey too — reusing the ONE implementation,
        # not a second fold of the inspectability rule.
        import oracles
        if oracles._yaml is None:
            self.skipTest("PyYAML unavailable")  # the capture degrades to infra
        with tempfile.TemporaryDirectory() as d:
            stub = _write_reconcile_stub_izba(
                d, sandboxes='[{"name":"pin-demo","status_disk":"running"}]')
            pol_dir = os.path.join(d, "sandboxes", "pin-demo")
            os.makedirs(pol_dir, exist_ok=True)
            with open(os.path.join(pol_dir, "policy.yaml"), "w") as f:
                f.write("enforce: true\n"
                        "allow:\n"
                        "  - host: pinned.vendor.com\n"
                        "    ports:\n"
                        "      - port: 443\n"
                        "        protocol: tcp\n")
            held = {"intent": "check the hatch", "expect": "still pinned",
                    "core": True,
                    "expect_state": {"sandbox": "pin-demo",
                                     "policy": {"host": "pinned.vendor.com",
                                                "port": {"number": 443,
                                                         "pinned": True}}}}
            res_ok = self._run(d, stub, held)
            self.assertTrue([c for c in res_ok["decisive_credits"]
                             if "expect_state" in (c.get("graded_cmd") or "")],
                            res_ok)
            self.assertEqual([c for c in res_ok["candidates"]
                              if c["kind"] == "functional"], [])
        with tempfile.TemporaryDirectory() as d2:
            stub = _write_reconcile_stub_izba(
                d2, sandboxes='[{"name":"pin-demo","status_disk":"running"}]')
            pol_dir = os.path.join(d2, "sandboxes", "pin-demo")
            os.makedirs(pol_dir, exist_ok=True)
            with open(os.path.join(pol_dir, "policy.yaml"), "w") as f:
                f.write("allow:\n  - host: pinned.vendor.com\n")
            broken = {"intent": "check the hatch", "expect": "still pinned",
                      "core": True,
                      "expect_state": {"sandbox": "pin-demo",
                                       "policy": {"host": "pinned.vendor.com",
                                                  "port": {"number": 443,
                                                           "pinned": True}}}}
            res_bad = self._run(d2, stub, broken)
        func = [c for c in res_bad["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res_bad["candidates"])
        self.assertIn("443", func[0]["detail"])


class UnreachedDecisiveHookHonestyTests(unittest.TestCase):
    """F1: a decisive step the Actor NEVER REACHED must not have its
    `expect_state` graded as a PRODUCT finding.

    `zero_actions` only covers journey-wide inaction. A 2-step journey whose
    Actor spends its budget on step 0 leaves step 1 (core) unreached — and the
    hook grader still emitted 'diverges from daemon truth', a fabricated
    product bug that lands in the Phase-3 skeptic's triage indistinguishable
    from a real one. Manufacturing false signal in the final report is worse
    than missing an assertion."""

    def _journey(self, steps):
        return {"journey_id": "unreached-hook", "rationale": "r",
                "source": {"kind": "spec", "ref": "x"}, "steps": steps}

    def test_unreached_decisive_step_emits_only_the_unreached_flip(self):
        steps = [
            {"intent": "do the setup", "expect": "ok"},
            {"intent": "then verify", "expect": "the sandbox exists",
             "core": True,
             "expect_state": {"sandbox": "demo", "exists": True}},
        ]
        # One turn of budget: step 0 consumes it, so step 1 never acts.
        model = FakeModel([{"command": "izba ls"}])
        with tempfile.TemporaryDirectory() as d:
            res = run_journeys.run_journey(
                model, self._journey(steps),
                izba_bin=_write_reconcile_stub_izba(d), data_dir=d,
                max_turns=1, step_cap=25, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=5.0)
        decisive_cands = [c for c in res["candidates"]
                          if c["kind"] in ("functional", "unreached_decisive",
                                           "infra")]
        self.assertEqual([c["kind"] for c in decisive_cands],
                         ["unreached_decisive"], res["candidates"])
        self.assertEqual(res["decisive_credits"], [], res["decisive_credits"])

    def test_reached_and_failing_decisive_step_still_flips_functional(self):
        # The other half: a step the Actor DID act in keeps grading exactly as
        # before — this fix narrows fabrication, never the real flip.
        steps = [{"intent": "create it", "expect": "the sandbox exists",
                  "core": True,
                  "expect_state": {"sandbox": "demo", "exists": True}}]
        model = FakeModel([{"command": "izba create demo"}, {"done": True}])
        with tempfile.TemporaryDirectory() as d:
            res = run_journeys.run_journey(
                model, self._journey(steps),
                izba_bin=_write_reconcile_stub_izba(d), data_dir=d,
                max_turns=10, step_cap=25, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=5.0)
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertTrue(func[0].get("decisive"))
        self.assertIn("expect_state", func[0]["detail"])


class NonDecisiveHookHonestyTests(unittest.TestCase):
    """F4: `expect_state` declared on a NON-decisive step was silently
    discarded — the journey validated, the author got an oracle they never
    got. Silence is the thing being eliminated: it degrades LOUDLY instead."""

    def test_expect_state_on_a_non_decisive_step_is_not_silent(self):
        steps = [
            {"intent": "check state early", "expect": "ok",
             "expect_state": {"sandbox": "demo", "exists": True}},
            {"intent": "the real assertion", "expect": "ok", "core": True,
             "expect_state": {"sandboxes_exact": []}},
        ]
        journey = {"journey_id": "nondecisive-hook", "rationale": "r",
                   "source": {"kind": "spec", "ref": "x"}, "steps": steps}
        model = FakeModel([{"command": "izba ls"}, {"done": True},
                           {"command": "izba ls"}, {"done": True}])
        with tempfile.TemporaryDirectory() as d:
            res = run_journeys.run_journey(
                model, journey, izba_bin=_write_reconcile_stub_izba(d),
                data_dir=d, max_turns=10, step_cap=25, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=5.0)
        loud = [c for c in res["candidates"]
                if c["kind"] == "infra" and "non-decisive" in c["detail"]]
        self.assertEqual(len(loud), 1, res["candidates"])
        self.assertIn("0", loud[0]["detail"])  # names the step


class JourneyIdPathLeakTests(unittest.TestCase):
    """F6: the first 16 chars of `journey_id` reached the Actor through its
    cwd / data-dir path (`deep-dormant-exc` literally carries the answer).
    The fair-test boundary means NO fragment of the id is Actor-visible."""

    IDS = ("deep-dormant-exception-is-not-live",
           "gui-cannot-activate-a-dormant-exception",
           "smoke-docs-bare-port-is-inspected")

    def test_data_dir_component_is_opaque(self):
        import re as _re
        for jid in self.IDS:
            seg = os.path.basename(run_journeys._journey_data_dir("/base", jid))
            self.assertRegex(seg, r"^j-[0-9a-f]+$", seg)
            for n in range(4, len(jid) + 1):
                for i in range(len(jid) - n + 1):
                    self.assertNotIn(jid[i:i + n], seg,
                                     f"{jid[i:i+n]!r} leaked into {seg!r}")
            self.assertLessEqual(len(seg), 25)  # SUN_LEN budget (izba#71)


def run_journeys_tail(text):
    """The recorded tail exactly as `run_action` would store it."""
    from oracles import _tail
    return _tail(text)


class StdoutReTruncationHonestyTests(unittest.TestCase):
    """F5 (grader half): when `expect_stdout_re` misses on a TRUNCATED tail,
    the candidate must say so — otherwise 'the product printed the wrong
    thing' and 'the harness threw away the line' read identically."""

    def test_detail_names_the_truncation(self):
        from oracles import TAIL_BYTES
        step = {"intent": "read the log", "expect": "spliced",
                "expect_stdout_re": "OPAQUE-SPLICE"}
        action = {"command": "izba netlog demo",
                  "stdout_tail": run_journeys_tail("X" * (TAIL_BYTES + 10)),
                  "exit_code": 0}
        found = run_journeys._stream_candidates(
            step, action, "src", {"journey_id": "j", "action_index": 0}, "j")
        self.assertEqual(len(found), 1)
        self.assertIn("truncat", found[0].detail.lower())

    def test_detail_is_unchanged_on_an_untruncated_tail(self):
        step = {"expect_stdout_re": "OPAQUE-SPLICE", "expect": "spliced"}
        action = {"command": "izba netlog demo", "stdout_tail": "nope\n",
                  "exit_code": 0}
        found = run_journeys._stream_candidates(
            step, action, "src", {"journey_id": "j", "action_index": 0}, "j")
        self.assertEqual(len(found), 1)
        self.assertNotIn("truncat", found[0].detail.lower())


def _write_stderr_stub_izba(d):
    """A stub `izba` whose `promote` writes its decisive line to STDERR — the
    real shape: `izba promote`'s `WARNING: weakens egress` (PromoteEvent::Warn
    → eprintln!) and the `no reviewed diff` bail both go to stderr, where
    expect_stdout_re structurally cannot see them."""
    stub = os.path.join(d, "izba")
    with open(stub, "w") as f:
        f.write(
            "#!/bin/sh\n"
            'if [ "$1" = "__reconcile" ]; then echo \'{"violations":[],"sandboxes":[]}\'; exit 0; fi\n'
            'if [ "$1" = "promote" ]; then\n'
            '  echo "WARNING: weakens egress" 1>&2\n'
            '  echo "Promoted 1 change(s)."\n'
            "  exit 0\n"
            "fi\n"
            'echo "izba-said: $*"\n'
            "exit 0\n"
        )
    os.chmod(stub, 0o755)
    return stub


class ExpectStderrReTests(unittest.TestCase):
    """The security-posture assertion of the whole passthrough campaign —
    `izba promote`'s `WARNING: weakens egress` — is written to STDERR, so
    `expect_stdout_re` cannot see it and that half of the review-gate
    assertion rested on the skeptic reading prose. `expect_stderr_re` is its
    symmetric twin: same action selection, same composition, same credit-path
    enforcement, same truncation honesty, same invisibility to the Actor."""

    def _run(self, d, step, script, stub=None):
        journey = {"journey_id": "stderr-anchor", "rationale": "r",
                   "source": {"kind": "spec", "ref": "x"},
                   "steps": [step] if isinstance(step, dict) else step}
        jf = _journeys_file(d, [journey])
        out = os.path.join(d, "traj.json")
        run_journeys.main([
            "--journeys", jf, "--shard", "0", "--shards", "1",
            "--izba-bin", stub or _write_stderr_stub_izba(d),
            "--data-dir", d, "--out", out,
            "--fake-model", json.dumps(script),
            "--step-cap", "25", "--action-timeout-s", "10",
            "--max-turns", "10", "--max-usd", "5"])
        with open(out) as f:
            return json.load(f)["results"][0]

    def test_stderr_match_passes(self):
        step = {"intent": "promote the change", "expect": "the gate warns",
                "core": True, "expect_stderr_re": r"WARNING: weakens egress"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba promote ."},
                                      {"done": True}])
        self.assertEqual([c for c in res["candidates"]
                          if c["kind"] == "functional"], [], res["candidates"])

    def test_stderr_mismatch_flips_the_decisive_step(self):
        step = {"intent": "promote the change", "expect": "the gate warns",
                "core": True, "expect_stderr_re": r"weakens INGRESS"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba promote ."},
                                      {"done": True}])
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertTrue(func[0].get("decisive"), func[0])
        self.assertEqual(func[0].get("graded_cmd"), "izba promote .")
        self.assertIn("expect_stderr_re", func[0]["detail"])
        self.assertIn("stderr", func[0]["detail"])

    def test_composes_with_stdout_and_exit(self):
        # All three declared: stdout + exit hold, stderr does not ⇒ the step
        # still flips, on the stderr half alone.
        step = {"intent": "promote the change", "expect": "the gate warns",
                "core": True, "expect_exit": 0,
                "expect_stdout_re": r"Promoted 1 change",
                "expect_stderr_re": r"weakens INGRESS"}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba promote ."},
                                      {"done": True}])
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertIn("expect_stderr_re", func[0]["detail"])

    def test_enforced_on_the_credit_path(self):
        # H3: a decisive step credited from an EARLIER action must still prove
        # what that action printed on stderr — otherwise the false green just
        # reopens there.
        steps = [
            {"intent": "promote the change", "expect": "warned"},
            {"intent": "confirm the warning", "expect": "the gate warned",
             "core": True, "expect_cmd_re": r"izba promote",
             "expect_stderr_re": r"weakens INGRESS"},
        ]
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, steps, [{"command": "izba promote ."},
                                       {"done": True}, {"done": True}])
        func = [c for c in res["candidates"] if c["kind"] == "functional"]
        self.assertEqual(len(func), 1, res["candidates"])
        self.assertIn("expect_stderr_re", func[0]["detail"])
        self.assertTrue(func[0].get("decisive"))

    def test_invalid_regex_degrades_to_infra(self):
        step = {"intent": "promote the change", "expect": "the gate warns",
                "core": True, "expect_stderr_re": r"("}
        with tempfile.TemporaryDirectory() as d:
            res = self._run(d, step, [{"command": "izba promote ."},
                                      {"done": True}])
        infra = [c for c in res["candidates"]
                 if c["kind"] == "infra" and "expect_stderr_re" in c["detail"]]
        self.assertEqual(len(infra), 1, res["candidates"])

    def test_truncated_stderr_is_named_in_the_detail(self):
        from oracles import TAIL_BYTES, _tail
        step = {"expect_stderr_re": "MISSING-TOKEN", "expect": "warned"}
        action = {"command": "izba promote .", "exit_code": 0,
                  "stdout_tail": "", "stderr_tail": _tail("Y" * (TAIL_BYTES + 9))}
        found = run_journeys._stream_candidates(
            step, action, "src", {"journey_id": "j", "action_index": 0}, "j")
        self.assertEqual(len(found), 1)
        self.assertIn("truncat", found[0].detail.lower())

    def test_one_parameterised_implementation_not_two(self):
        # A second copy of this rule is the specific mistake this codebase has
        # paid for: stdout and stderr are one grader over a stream table.
        self.assertFalse(hasattr(run_journeys, "_stderr_candidates"))
        self.assertEqual(
            sorted(h[0] for h in run_journeys._STREAM_HOOKS),
            ["expect_stderr_re", "expect_stdout_re"])
