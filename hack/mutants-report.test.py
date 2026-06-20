# hack/mutants-report.test.py
import os, tempfile, subprocess, sys, importlib.util, json

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("mr", os.path.join(HERE, "mutants-report.py"))
mr = importlib.util.module_from_spec(spec); spec.loader.exec_module(mr)

def _outdir(tmp, name, missed_lines, total_mutants=None):
    d = os.path.join(tmp, name, "mutants.out")
    os.makedirs(d)
    with open(os.path.join(d, "missed.txt"), "w") as f:
        f.write("\n".join(missed_lines) + ("\n" if missed_lines else ""))
    if total_mutants is not None:
        with open(os.path.join(d, "outcomes.json"), "w") as f:
            json.dump({"total_mutants": total_mutants}, f)
    return d

def test_read_missed_parses_lines():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", ["crates/izba-proto/src/codec.rs:21:12: replace > with >= in write_frame"])
        got = mr.read_missed(d)
        assert len(got) == 1
        m = got[0]
        assert m.path == "crates/izba-proto/src/codec.rs"
        assert m.line == 21 and m.col == 12
        assert "replace > with >=" in m.desc
        assert len(m.id_hash) == 12

def test_merge_dedups_across_dirs_and_sorts():
    with tempfile.TemporaryDirectory() as t:
        line_a = "crates/izba-proto/src/codec.rs:21:12: replace > with >= in write_frame"
        line_b = "crates/izba-proto/src/dns.rs:35:36: replace | with ^ in servfail"
        d1 = _outdir(t, "s1", [line_a, line_b])
        d2 = _outdir(t, "s2", [line_a])          # duplicate of line_a
        merged = mr.merge([d1, d2])
        assert len(merged) == 2                   # deduped
        assert merged[0].path.endswith("codec.rs")  # sorted: codec before dns
        assert merged[1].path.endswith("dns.rs")

def test_render_markdown_groups_by_file_with_checkboxes():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", ["crates/izba-proto/src/codec.rs:21:12: replace > with >= in write_frame"])
        md = mr.render_markdown(mr.merge([d]))
        assert "crates/izba-proto/src/codec.rs" in md
        assert "- [ ]" in md
        assert "21:12" in md

def test_gate_mode_exit_1_on_survivors():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", ["crates/izba-proto/src/codec.rs:21:12: replace > with >= in write_frame"])
        r = subprocess.run([sys.executable, os.path.join(HERE, "mutants-report.py"),
                            "--mode", "gate", os.path.dirname(d)], capture_output=True, text=True)
        assert r.returncode == 1
        assert "codec.rs" in r.stdout

def test_gate_mode_exit_0_when_clean():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", [])   # no survivors
        r = subprocess.run([sys.executable, os.path.join(HERE, "mutants-report.py"),
                            "--mode", "gate", os.path.dirname(d)], capture_output=True, text=True)
        assert r.returncode == 0

def test_full_mode_writes_json_and_md():
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", ["crates/izba-proto/src/dns.rs:35:36: replace | with ^ in servfail"])
        jp = os.path.join(t, "r.json"); wp = os.path.join(t, "w.md")
        r = subprocess.run([sys.executable, os.path.join(HERE, "mutants-report.py"),
                            "--mode", "full", "--json-out", jp, "--md-out", wp, os.path.dirname(d)],
                           capture_output=True, text=True)
        assert r.returncode == 0
        data = json.load(open(jp))
        assert data["survivors"][0]["path"].endswith("dns.rs")
        assert "id_hash" in data["survivors"][0]
        assert "dns.rs" in open(wp).read()

def test_full_mode_sums_tested_count_across_shards():
    with tempfile.TemporaryDirectory() as t:
        d1 = _outdir(t, "s1", ["crates/a/src/x.rs:1:1: replace + with -"], total_mutants=12)
        d2 = _outdir(t, "s2", [], total_mutants=13)
        jp = os.path.join(t, "r.json"); wp = os.path.join(t, "w.md")
        r = subprocess.run([sys.executable, os.path.join(HERE, "mutants-report.py"),
                            "--mode", "full", "--json-out", jp, "--md-out", wp,
                            os.path.dirname(d1), os.path.dirname(d2)], capture_output=True, text=True)
        assert r.returncode == 0
        data = json.load(open(jp))
        assert data["tested"] == 25            # 12 + 13 summed from outcomes.json
        assert "25" in open(wp).read()         # surfaced in the markdown header

def test_issue_summary_is_compact_and_per_file():
    # Many survivors across many files must still fit GitHub's 65536-char issue cap.
    lines = []
    for fi in range(200):
        for li in range(20):
            lines.append(f"crates/c{fi}/src/f{fi}.rs:{li+1}:5: replace + with - in func{li}")
    with tempfile.TemporaryDirectory() as t:
        d = _outdir(t, "s1", lines, total_mutants=5000)
        ip = os.path.join(t, "issue.md")
        r = subprocess.run([sys.executable, os.path.join(HERE, "mutants-report.py"),
                            "--mode", "full", "--issue-out", ip, os.path.dirname(d)],
                           capture_output=True, text=True)
        assert r.returncode == 0
        body = open(ip).read()
        assert len(body) < 65536, f"issue body too long: {len(body)}"
        assert "4000" in body            # total survivor count surfaced (200*20)
        assert "mutants-report.json" in body  # points to the artifact for detail

if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    sys.exit(1 if failed else 0)
