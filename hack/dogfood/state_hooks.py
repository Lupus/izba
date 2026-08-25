# hack/dogfood/state_hooks.py
"""The shared decisive-hook vocabulary: ONE implementation of the
``expect_state`` rule, imported by BOTH runners.

``expect_state`` is a single rule with three parts — the schema vocabulary and
its validity normalization (:func:`step_decisive_hooks` + the ``valid_*``
predicates), the oracle that grades it (``gui_oracles.expect_state_oracle``),
and the instrument-honesty fold that turns a verdict into candidates/credits
(:func:`apply_hook_verdict`). A second implementation of ANY of them is a
second fold of one rule, which is how this repo once shipped a live
no-certificate-verification bypass (CLAUDE.md, M5 P1).

This module exists so both runners can share those parts WITHOUT the CLI
runner reaching into the GUI runner's privates: ``run_gui_journeys`` imports
``run_journeys`` at module scope, so the reverse edge had to be a lazy import
of underscore-prefixed names — a shared rule with two homes, one rename away
from silently becoming two. The dependency now points one way: both runners
import this module, and this module imports NEITHER (nor anything that does),
so no cycle exists and no lazy-import workaround is needed.

The oracle half (``expect_state_oracle``) deliberately stays in
``gui.gui_oracles`` beside the other state-evidence graders it shares parsing
helpers with; it is a PUBLIC name, so importing it crosses no privacy
boundary.

Instrument-honesty contract, identical on both sides: ``matched`` ⇒ an
auditable ``decisive_credits`` entry; ``mismatch`` ⇒ the oracle's
``functional`` candidate(s) tagged ``decisive``; ``no_evidence`` ⇒ a flipping
``infra`` candidate. Never a silent pass."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

# The `no_evidence` explanation both runners hand the skeptic when an
# expect_state assertion could not be graded. One string, one meaning.
STATE_NO_EVIDENCE_DETAIL = (
    "expect_state: daemon state evidence unavailable (reconcile snapshot "
    "errored/absent, no usable `izba volume ls` capture for a volume "
    "assertion, no usable port_ls/ports_persisted capture for a port "
    "assertion, no usable managed policy.yaml capture — PyYAML unavailable "
    "/ file absent / unparseable — for a policy assertion, or a policy "
    "assertion whose host has mixed-access wildcard duplicates the product "
    "deliberately keeps independent, which no single-entry assertion can "
    "state), assertion unverifiable")


def normalize_policy_host(host: str) -> str:
    """The product's policy-host identity: trim, strip trailing dot(s), ASCII
    lowercase (izba-core ``daemon/egress/config.rs::normalize_policy_host``).

    Every comparison of a journey-declared host against a `policy.yaml` entry
    goes through this, so the harness keys hosts exactly the way the product
    keys them — a `.strip().lower()` lookalike silently misses
    ``vendor.com.``."""
    return host.strip().rstrip(".").lower()


def is_wildcard_host(host: str) -> bool:
    """Is this allow-entry host a wildcard pattern (``*.x`` / ``**.x``)?
    Mirrors izba-core's ``is_wildcard_host``: the two fold semantics differ
    (exact = last-wins, wildcard = union), so the classification must not
    drift."""
    return host.startswith("*.") or host.startswith("**.")


# Provenance for a hook-grader degradation. The model transport had nothing to
# do with it, and both fields are read by the Phase-3 skeptic as provenance —
# misattributing them sends it looking at the wrong subsystem.
HOOK_GRADER_SOURCE = "harness: decisive-hook grader"
HOOK_GRADER_EXPECTATION = "a declared decisive hook must be gradable"


def infra_candidate(journey_id: str, detail: str, *,
                    source: str = "harness: model transport",
                    violated_expectation: str =
                    "model/API must produce a next command") -> Dict[str, Any]:
    """Flipping infra candidate — the harness/driver plumbing failed, so the
    journey verified nothing (and must not tally positive).

    ``source``/``violated_expectation`` default to the MODEL-TRANSPORT
    provenance the original callers (model starvation, sidecar/daemon spawn
    failure) need; every other emitter passes its own. The skeptic reads both
    fields, so a hook-grader degradation labelled "model/API must produce a
    next command" points it at the wrong subsystem entirely."""
    return {
        "kind": "infra",
        "detail": detail,
        "violated_expectation": violated_expectation,
        "source": source,
        "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
    }



# --- Seed-file survival (DEEP-H0) -------------------------------------------
#
# `seed_files` is a PRECONDITION the journey compiler authors and the Actor is
# never told about (the fair-test boundary: an Actor that knew the fixture was
# planted would be reading the answer sheet). A cheap Actor therefore quite
# reasonably decides to author its own `policy.yaml`/`izba.yml` — and in the
# 2026-08 deep tier it did exactly that in 11 of 11 CLI journeys, so the
# oracles graded a file the compiler never wrote while the bundle said nothing.
#
# The harness cannot tell the Actor about the seed and must not silently
# re-plant it behind the Actor's back (that would hand the Actor a shell whose
# writes spontaneously revert). What it CAN do is watch the fixture and say so:
# a seeded path that is no longer on disk as seeded means the journey's
# precondition is gone, i.e. the evidence the assertions needed is unavailable
# — which the instrument-honesty contract already spells `infra`, flipping, so
# the journey cannot tally positive.
SEED_CLOBBER_SOURCE = "harness: seed_files precondition"
SEED_CLOBBER_EXPECTATION = (
    "a seeded precondition must still be on disk, byte-for-byte as seeded, "
    "when the journey's assertions are graded")
# The literal a bundle reader (and the Phase-3 skeptic) greps for.
SEED_CLOBBER_MARKER = "seeded precondition"


def seed_digest(content: str) -> str:
    """Content identity for a seeded file: sha256 of its UTF-8 bytes.

    Compared against the same digest of what is on disk later, so "the Actor
    rewrote it with identical bytes" is correctly NOT a clobber."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def clobbered_seed_candidate(journey_id: str, relpath: str, *,
                             action_index: int, command: str, origin: str,
                             disposition: str) -> Dict[str, Any]:
    """The flipping `infra` candidate for a seeded fixture that did not survive.

    Names WHICH fixture, WHERE it came from (journey-level vs a step's drift
    injection), and the exact action that ended it — so the skeptic can tell
    "the product ate the file" from "the Actor wrote its own", and can never
    mistake a graded substitute for the authored precondition. Report-once per
    seeding: a later re-seed re-arms it."""
    candidate = infra_candidate(
        journey_id,
        f"{SEED_CLOBBER_MARKER} {relpath!r} ({origin}) was {disposition} by "
        f"action[{action_index}] ({command[:160]!r}) — the rest of the journey "
        f"ran against the Actor's own file, so every assertion downstream "
        f"graded a fixture the journey never authored",
        source=SEED_CLOBBER_SOURCE,
        violated_expectation=SEED_CLOBBER_EXPECTATION,
    )
    # Unlike the model-transport infra candidates, this one IS tied to a single
    # action, so the ref reproduces it directly instead of pointing at nothing.
    candidate["trajectory_ref"]["action_index"] = action_index
    return candidate


def surviving_seed_disposition(path: str, digest: str) -> str:
    """Empty string if the seeded file is still exactly as seeded, else WHAT
    happened to it: ``REMOVED`` / ``OVERWRITTEN`` / ``UNREADABLE (...)``.

    Unreadable is deliberately reported rather than swallowed: an oracle that
    cannot see the fixture is in the same position as one whose fixture was
    replaced."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            current = f.read()
    except FileNotFoundError:
        return "REMOVED"
    except OSError as e:
        return f"UNREADABLE ({e.__class__.__name__})"
    return "" if seed_digest(current) == digest else "OVERWRITTEN"


def valid_volume_spec(vspec: Any) -> bool:
    """True iff ``vspec`` is a schema-shaped ``expect_state.volume`` object:
    a dict with a non-empty ``name`` and at least one of
    ``exists``/``attached_to`` declared."""
    return (isinstance(vspec, dict) and bool(vspec.get("name"))
            and ("exists" in vspec or "attached_to" in vspec))


def valid_port_spec(pspec: Any) -> bool:
    """True iff ``pspec`` is a schema-shaped ``expect_state.port`` object: a
    dict with an integer ``host`` (bool rejected — Python bools are ints) and
    at least one of ``exists``/``persistent`` declared."""
    return (isinstance(pspec, dict)
            and isinstance(pspec.get("host"), int)
            and not isinstance(pspec.get("host"), bool)
            and ("exists" in pspec or "persistent" in pspec))


POLICY_ACCESS_VERBS = ("read", "read-write")


def valid_policy_spec(pspec: Any) -> bool:
    """True iff ``pspec`` is a schema-shaped ``expect_state.policy`` object:
    a dict declaring at least one of ``present``/``access``/``port``/
    ``enforcing``; a non-empty ``host`` anchor whenever a host-scoped key
    (present/access/port) is declared (``enforcing`` is file-level and needs
    none); booleans where booleans belong; a known access verb; and a
    ``port`` carrying BOTH an integer ``number`` (bool rejected — Python
    bools are ints) and a boolean ``pinned``. A half-formed policy assertion
    must fall through to the unreached_decisive flip, never grade."""
    if not isinstance(pspec, dict):
        return False
    scoped = [k for k in ("present", "access", "port") if k in pspec]
    if not scoped and "enforcing" not in pspec:
        return False
    host = pspec.get("host")
    if scoped and not (isinstance(host, str) and host):
        return False
    if "enforcing" in pspec and not isinstance(pspec["enforcing"], bool):
        return False
    if "present" in pspec and not isinstance(pspec["present"], bool):
        return False
    if "access" in pspec and pspec["access"] not in POLICY_ACCESS_VERBS:
        return False
    if "port" in pspec:
        port = pspec["port"]
        if not isinstance(port, dict):
            return False
        if not isinstance(port.get("number"), int) or isinstance(
                port.get("number"), bool):
            return False
        if not isinstance(port.get("pinned"), bool):
            return False
        if port["pinned"] and is_wildcard_host(normalize_policy_host(host)):
            # `protocol: tcp` on a WILDCARD host is a product parse error
            # (DP-3: matching an SNI against a wildcard would fork the
            # semantics that live in egress.rego), so no loadable policy.yaml
            # can ever satisfy this. Grading it would manufacture a
            # permanent, unsatisfiable product finding; refuse it as a
            # malformed assertion instead (⇒ unreached_decisive, an
            # instrument problem, which is what it is).
            return False
    return True


def valid_sandboxes_exact(v: Any) -> bool:
    """True iff ``v`` is a schema-shaped ``expect_state.sandboxes_exact``
    value: a list — possibly EMPTY (asserts no sandboxes exist at all) — of
    non-empty strings."""
    return (isinstance(v, list)
            and all(isinstance(n, str) and n for n in v))


def state_hook_label(state_hook: Dict[str, Any]) -> str:
    """Human label for an expect_state hook's target — the named sandbox for
    per-sandbox assertions, the daemon set for a pure sandboxes_exact spec."""
    name = state_hook.get("sandbox")
    return (f"sandbox {name!r}" if name
            else "the daemon sandbox set (sandboxes_exact)")


def step_declares_hook(step: Dict[str, Any]) -> bool:
    """True iff the step DECLARES a decisive hook key at all — deliberately
    keyed on raw presence, not on validity: a malformed hook (which
    ``step_decisive_hooks`` normalizes to absent) is still a declared
    assertion and must reach the grader, where it flips ``unreached_decisive``
    rather than being silently skipped."""
    return isinstance(step, dict) and ("expect_text" in step
                                       or "expect_state" in step)


def step_decisive_hooks(step: Dict[str, Any]) -> tuple:
    """The (expect_text, expect_state) declarative hooks a step carries, with
    malformed values normalized to absent (``None``): a hook the schema would
    reject (non-str/empty expect_text; expect_state carrying a per-sandbox
    assertion — ``exists``/``status``/``volume``/``port``/``policy`` —
    without a ``sandbox`` target, without at least one assertion among those
    plus ``sandboxes_exact``, or with a half-formed ``volume``/``port``/
    ``policy``/``sandboxes_exact`` value — a declared assertion must never be
    silently dropped) is NOT gradable and must fall through to the
    unreached_decisive flip — never a silent pass on a half-formed
    assertion."""
    text = step.get("expect_text")
    if not (isinstance(text, str) and text):
        text = None
    state = step.get("expect_state")
    if not isinstance(state, dict):
        state = None
    else:
        per_sandbox = [k for k in ("exists", "status", "volume", "port",
                                   "policy")
                       if k in state]
        if per_sandbox and not state.get("sandbox"):
            state = None  # per-sandbox assertions need a sandbox target
        elif not per_sandbox and "sandboxes_exact" not in state:
            state = None  # no assertion declared at all
        elif "volume" in state and not valid_volume_spec(state.get("volume")):
            state = None
        elif "port" in state and not valid_port_spec(state.get("port")):
            state = None
        elif "policy" in state and not valid_policy_spec(state.get("policy")):
            state = None
        elif ("sandboxes_exact" in state
              and not valid_sandboxes_exact(state.get("sandboxes_exact"))):
            state = None
    return text, state


def apply_hook_verdict(verdict: str, found: List[Any], *, hook: str,
                        no_evidence_detail: str, journey_id: str,
                        step_idx: int, candidates: List[Dict[str, Any]],
                        decisive_credits: List[Dict[str, Any]]) -> None:
    """Fold one hook oracle's ``(verdict, candidates)`` into the journey per
    the instrument-honesty contract: ``matched`` ⇒ an auditable
    decisive_credits entry (the skeptic must see the decisive assertion WAS
    checked, mirroring the manifest_truth credit shape); ``mismatch`` ⇒ the
    oracle's ``functional`` candidate(s) tagged ``decisive`` (the collector's
    flip contract); ``no_evidence`` ⇒ a flipping ``infra`` candidate
    (couldn't verify — harness degradation, not a product bug, and NEVER a
    silent pass)."""
    if verdict == "matched":
        decisive_credits.append({
            "step_index": step_idx, "action_index": -1,
            "graded_cmd": f"{hook} (matched)",
        })
        return
    if verdict == "no_evidence":
        candidates.append(infra_candidate(
            journey_id, f"{no_evidence_detail} (core decisive step {step_idx})",
            source=HOOK_GRADER_SOURCE,
            violated_expectation=HOOK_GRADER_EXPECTATION))
        return
    for c in found:
        cd = c.to_dict()
        cd["decisive"] = True
        candidates.append(cd)


def step_was_entered(step_idx: int, step_actions: Dict[int, int]) -> bool:
    """Did the Actor produce at least one action INSIDE this step?

    The single definition of "reached", shared by both runners so they cannot
    drift apart again. `step_actions` maps step index -> the number of actions
    that step produced (CLI: shell commands; GUI: browser actions); a step the
    run never opened has no entry at all, which is zero.

    Why it is load-bearing: grading a decisive step the Actor never entered
    emits "diverges from daemon truth" about an assertion nobody exercised —
    the harness FABRICATING a product finding, which reaches Phase-3 triage
    indistinguishable from a real one. Both runners refuse.

    What each runner does with a NOT-entered decisive step is deliberately
    identical in shape but surface-specific in evidence: it may still be
    graded if OBSERVED evidence already satisfies its declared assertion —
    the CLI's `_grade_decisive_from_observed` (an earlier action matching
    `expect_cmd_re`, post-watermark), the GUI's final-capture `expect_text`
    fallback. Otherwise the step yields `unentered_step_candidate` ALONE: no
    functional flip, and no credit either (a credit from an unreached step is
    what the watermark discipline forbids)."""
    return (step_actions or {}).get(step_idx, 0) > 0


def unentered_step_candidate(journey_id: str, step: Dict[str, Any],
                             step_idx: int, source: str) -> Dict[str, Any]:
    """The flip for a decisive step the Actor never entered — one wording,
    both runners, so a bundle reader sees one convention."""
    return {
        "kind": "unreached_decisive",
        "detail": (f"decisive step {step_idx} "
                   f"({step.get('intent', '')[:80]!r}) produced no actions — "
                   f"its assertion was never exercised"),
        "violated_expectation": (step.get("expect", "")
                                 or "decisive step must be exercised"),
        "source": source,
        "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
    }


ZERO_ACTION_REASON = ("actor performed no actions; decisive assertion "
                       "never exercised")


def zero_action_unreached(journey_id: str, step: Dict[str, Any],
                           source: str, hook_desc: str) -> Dict[str, Any]:
    """The Fix-4 reclassification candidate: a decisive hook that FAILED on a
    journey whose Actor never acted is an unreached/engagement failure (the
    swarm never attempted the interaction), NOT a product-functional flip —
    'absent from every capture' over an untouched screen reads as a product
    failure but proves nothing about the product."""
    return {
        "kind": "unreached_decisive",
        "detail": f"{ZERO_ACTION_REASON} ({hook_desc})",
        "violated_expectation": step.get("expect", "") or hook_desc,
        "source": source,
        "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
    }


