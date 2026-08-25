# hack/dogfood/test_state_hooks.py
"""The shared `expect_state` hook vocabulary — ONE implementation, imported by
both runners (R5). The CLI runner must not reach into the GUI runner's
privates: the dependency direction was backwards, and a shared rule with two
homes is one rename away from becoming two rules."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))


def test_state_hooks_exports_the_shared_vocabulary():
    import state_hooks
    for name in ("step_decisive_hooks", "state_hook_label",
                 "apply_hook_verdict", "zero_action_unreached",
                 "infra_candidate", "valid_policy_spec"):
        assert hasattr(state_hooks, name), name


def test_both_runners_use_the_same_hook_objects():
    import gui.run_gui_journeys as rgj
    import run_journeys
    import state_hooks
    assert rgj._step_decisive_hooks is state_hooks.step_decisive_hooks
    assert rgj._apply_hook_verdict is state_hooks.apply_hook_verdict
    assert rgj._state_hook_label is state_hooks.state_hook_label
    assert rgj._zero_action_unreached is state_hooks.zero_action_unreached
    assert run_journeys._step_decisive_hooks is state_hooks.step_decisive_hooks
    assert run_journeys._apply_hook_verdict is state_hooks.apply_hook_verdict


def test_cli_runner_does_not_import_gui_runner_privates():
    with open(os.path.join(HERE, "run_journeys.py"), encoding="utf-8") as f:
        src = f.read()
    assert "from gui.run_gui_journeys import" not in src
    assert "import gui.run_gui_journeys" not in src


def test_state_hooks_imports_no_runner():
    # The shared module must sit BELOW both runners or the cycle returns.
    with open(os.path.join(HERE, "state_hooks.py"), encoding="utf-8") as f:
        src = f.read()
    for banned in ("run_journeys", "run_gui_journeys"):
        assert f"import {banned}" not in src, banned


def test_valid_policy_spec_rejects_a_pinned_wildcard():
    # `protocol: tcp` on a wildcard host is a product PARSE ERROR (DP-3), so
    # a policy.yaml can never contain one: asserting it is an instrument bug,
    # not a product finding. Refuse it as malformed (⇒ unreached_decisive)
    # rather than manufacturing a functional flip that can never be satisfied.
    from state_hooks import valid_policy_spec
    assert not valid_policy_spec(
        {"host": "*.v.com", "port": {"number": 443, "pinned": True}})
    assert valid_policy_spec(
        {"host": "*.v.com", "port": {"number": 443, "pinned": False}})
    assert valid_policy_spec(
        {"host": "exact.v.com", "port": {"number": 443, "pinned": True}})
