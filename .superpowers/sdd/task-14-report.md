### Task 14 Report: Docs + coverage exclusions

**Status:** Done — commit `a503952` "docs(dogfood): document the GUI modality + exclude bridge glue from coverage"

---

#### grep -c check

```
grep -c '^sonar.coverage.exclusions' sonar-project.properties
1
```

Result: **1** — exactly one key. Pass.

---

#### File-by-file changes

**1. `.claude/skills/llm-dogfooding/references/methodology.md`**
- Replaced the 4-line `## Extending to the UI` stub (Playwright-MCP + differential-oracle placeholder) with the full 18-line `## The GUI modality (Tauri app)` section from the brief verbatim: driver (agent-browser `--json`), real backend (WS sidecar + `bin/headless`), oracles (`ui_daemon_diff`/`console`/`silent_failure`/`dom_expect`), run instructions, deferred tauri-driver cross-engine smoke note.

**2. `.claude/skills/llm-dogfooding/SKILL.md`**
- Appended one table row to the "Quick reference" table, after the existing `Why & deeper method` row:
  `| Drive the GUI swarm (Tauri app) | hack/dogfood/gui/run_gui_journeys.py (agent-browser + bin/headless bridge); modality:"gui" journeys |`

**3. `sonar-project.properties`**
- Appended `,app/src-tauri/src/bin/headless.rs,app/dogfood/real-bridge.js` to the end of the single existing `sonar.coverage.exclusions=` value. No second key added; the note above the line ("must appear EXACTLY ONCE") remains accurate.

---

#### Files changed

- `.claude/skills/llm-dogfooding/references/methodology.md`
- `.claude/skills/llm-dogfooding/SKILL.md`
- `sonar-project.properties`

---

#### Concerns

None. The `.claude/` directory is in `.gitignore` but the skill files are already tracked; `git add -f` was used to stage them through the ignore rule (standard practice for this repo's tracked skill files).

---

## Final-review fix wave

**Status:** Done — 4 fixes applied; 80 tests pass (78 baseline + 2 new).

### Fix 1 — `screenshot_ref` + dead loop removal (`run_gui_journeys.py`)

- Removed the dead inner loop `for c in end_found: c.trajectory_ref = dict(final_ref)` that appeared inside the `try` block after `driver.screenshot(shot)` — it was overwritten by the identical `for c in end_found:` loop immediately below.
- After a successful `driver.screenshot(shot)`, the last action now gets `actions[-1]["screenshot_ref"] = os.path.join(os.path.basename(artifact_dir), f"{journey_id}.png")`.
- New test `test_run_gui_journey_screenshot_ref_recorded_on_last_action` in `test_run_gui_journeys.py`: runs a `ui_daemon_diff`-producing journey with `artifact_dir=str(tmp_path/…)` and asserts `driver.shots` contains the full path and `res["actions"][-1]["screenshot_ref"]` equals the expected relative path.

### Fix 2 — `dogfood-app-guide.md` at repo root

Created `dogfood-app-guide.md` (end-user onboarding tone, ~55 lines). Covers: sandbox list, create, start/stop, open shell, SSH access, firewall/egress policy, remove, daemon status indicator. No source file names, component names, `data-testid`s, IPC commands, or Rust/React internals. Matches the length/tone of the committed `dogfood-context.md`.

### Fix 3 — `ui_daemon_diff_oracle` word-boundary match (`gui_oracles.py`)

Changed `str(name).lower() not in hay` to `not re.search(r'\b' + re.escape(str(name).lower()) + r'\b', hay)`, consistent with `dom_expect_oracle`. New regression test `test_ui_daemon_diff_word_boundary_run_not_suppressed_by_running` in `test_gui_oracles.py` asserts that a sandbox named `"run"` is still flagged when the UI only shows `"running"` (substring match would falsely pass it).

### Fix 4 — cleanups

- `run_gui_journeys.py`: hoisted `from oracles import Action as _A` from inside the inner loop to the module-level `from oracles import (...)` block.
- `driver.py`: removed unused `field` from `from dataclasses import dataclass, field` → `from dataclasses import dataclass`. Also extended `FakeDriver.screenshot()` to append `path` to `self.shots: List[str]` (previously a no-op; needed by Fix 1's test).

### Test command and output

```
python3 -m pytest hack/dogfood -q
```

```
................................................................................
........
80 passed in 4.26s
```
