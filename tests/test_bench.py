"""D27 - benchmark profiles. Lite must be byte-identical to before; Pro must match
the Scale grader's own conventions (image tag, repo path, entrypoint, output shape)."""

from __future__ import annotations

import json

import pytest

from dfc import bench, container, sample
from dfc.solver import system_prompt_for, _build_user_prompt
from dfc.policy import ARM0, ARM1


# --------------------------------------------------------------------------
# Lite is unchanged
# --------------------------------------------------------------------------

def test_lite_image_matches_previous_convention():
    assert bench.LITE.image_for({"instance_id": "astropy__astropy-12907"}) == \
        "swebench/sweb.eval.x86_64.astropy_1776_astropy-12907:latest"
    assert bench.LITE.image_for({"instance_id": "astropy__astropy-12907"}) == \
        container.image_for("astropy__astropy-12907")


def test_lite_container_defaults_are_the_old_ones():
    assert bench.LITE.repo_dir == "/testbed"
    assert bench.LITE.docker_run_extra() == []
    assert bench.LITE.docker_run_cmd() == ["sleep", "infinity"]


def test_lite_prompts_are_byte_identical():
    """The prompt substitution must be a no-op for Lite or the August condition
    changes retroactively."""
    for arm in (ARM0, ARM1):
        assert system_prompt_for(arm) == system_prompt_for(arm, "/testbed")
    inst = {"problem_statement": "x", "hints_text": ""}
    assert _build_user_prompt(inst, False) == _build_user_prompt(inst, False, "/testbed")
    assert "/testbed" in _build_user_prompt(inst, False)


def test_lite_normalize_keeps_swebench_columns():
    row = {"instance_id": "django__django-1", "problem_statement": "p", "patch": "d",
           "test_patch": "t", "FAIL_TO_PASS": '["a::b"]', "PASS_TO_PASS": '["c::d", "e::f"]'}
    n = bench.LITE.normalize(row)
    assert n["repo"] == "django"
    assert n["fail_to_pass"] == ["a::b"] and n["pass_to_pass"] == ["c::d", "e::f"]


# --------------------------------------------------------------------------
# Pro
# --------------------------------------------------------------------------

QUTE = "instance_qutebrowser__qutebrowser-f91ace96223cac8161c16dd061907e138fe85111-v059c6fdc75567943479b23ebca7c07b5e9a7f34c"


def test_pro_image_tag_matches_scale_helper():
    """Same function as helper_code/image_uri.py - including the 128-character
    truncation Docker Hub imposes, which the qutebrowser tags hit - so the container
    we solve in is the image the grader evaluates in."""
    tag = bench.pro_image_tag(QUTE, "qutebrowser/qutebrowser")
    assert len(tag) == 128 and tag.startswith("qutebrowser.qutebrowser-qutebrowser__qutebrowser-f91ace")
    assert bench.pro_image_tag("instance_NodeBB__NodeBB-abc-vnan", "NodeBB/NodeBB") == \
        "nodebb.nodebb-NodeBB__NodeBB-abc"
    assert bench.PRO.image_for({"instance_id": QUTE, "repo": "qutebrowser/qutebrowser"}) == \
        "jefzda/sweap-images:" + tag


def test_pro_image_tag_agrees_with_scale_repo_when_present():
    import sys
    if not (bench.PRO_ROOT / "helper_code" / "image_uri.py").exists():
        pytest.skip("Scale repo not cloned")
    sys.path.insert(0, str(bench.PRO_ROOT))
    from helper_code.image_uri import get_dockerhub_image_uri
    for uid, repo in [(QUTE, "qutebrowser/qutebrowser"),
                      ("instance_NodeBB__NodeBB-abc-vnan", "NodeBB/NodeBB"),
                      ("instance_element-hq__element-web-abc-vnan", "element-hq/element-web"),
                      ("instance_internetarchive__openlibrary-abc-vdef", "internetarchive/openlibrary")]:
        assert bench.PRO.image_for({"instance_id": uid, "repo": repo}) == \
            get_dockerhub_image_uri(uid, "jefzda", repo)


def test_pro_prefers_dataset_dockerhub_tag_when_present():
    assert bench.PRO.image_for({"instance_id": QUTE, "repo": "x/y", "dockerhub_tag": "given"}) == \
        "jefzda/sweap-images:given"


def test_pro_container_overrides_bash_entrypoint():
    """Pro images set ENTRYPOINT ["/bin/bash"]; `docker run img sleep infinity` would
    run `bash sleep infinity`."""
    assert bench.PRO.repo_dir == "/app"
    assert bench.PRO.docker_run_extra() == ["--entrypoint", "sleep"]
    assert bench.PRO.docker_run_cmd() == ["infinity"]


def test_pro_prompts_name_app():
    for arm in (ARM0, ARM1):
        p = system_prompt_for(arm, "/app")
        assert "/app" in p and "/testbed" not in p
    u = _build_user_prompt({"problem_statement": "x", "hints_text": ""}, False, "/app")
    assert "/app" in u and "/testbed" not in u


@pytest.mark.parametrize("row", [
    {"instance_id": QUTE, "repo": "qutebrowser/qutebrowser", "FAIL_TO_PASS": ["t::a"],
     "PASS_TO_PASS": ["t::b"]},
    {"instance_id": QUTE, "repo": "qutebrowser/qutebrowser", "fail_to_pass": '["t::a"]',
     "pass_to_pass": "['t::b']"},
])
def test_pro_normalize_accepts_both_export_shapes(row):
    n = bench.PRO.normalize(row)
    assert n["fail_to_pass"] == ["t::a"] and n["pass_to_pass"] == ["t::b"]
    assert n["repo"] == "qutebrowser/qutebrowser"


def test_pro_default_repo_filter_is_the_pytest_pair():
    assert bench.PRO.repos == ("internetarchive/openlibrary", "qutebrowser/qutebrowser")
    assert bench.PRO.keep({"repo": "qutebrowser/qutebrowser"})
    assert not bench.PRO.keep({"repo": "ansible/ansible"})
    assert not bench.PRO.keep({"repo": "flipt-io/flipt"})


def test_pro_repo_filter_can_be_widened():
    b = bench.get("pro", bench.PRO_PYTHON_REPOS)
    assert b.keep({"repo": "ansible/ansible"})


def test_stratified_uses_repo_field_when_present():
    rows = [{"instance_id": f"instance_a__a-{i}", "repo": "org/alpha"} for i in range(5)] + \
           [{"instance_id": f"instance_b__b-{i}", "repo": "org/beta"} for i in range(5)]
    picked = sample.stratified(rows, 4, seed=1)
    assert sorted(r["repo"] for r in picked) == ["org/alpha", "org/alpha", "org/beta", "org/beta"]


# --------------------------------------------------------------------------
# Pro grader output -> report
# --------------------------------------------------------------------------

INST = {"fail_to_pass": ["t::f1", "t::f2"], "pass_to_pass": ["t::p1", "t::p2"]}


def _out(passed, failed=()):
    return {"tests": [{"name": n, "status": "PASSED"} for n in passed]
                     + [{"name": n, "status": "FAILED"} for n in failed]}


def test_pro_report_resolved_when_every_named_test_passes():
    r = bench.pro_report(_out(["t::f1", "t::f2", "t::p1", "t::p2", "t::extra"]), "", INST)
    assert r["resolved"] and r["patch_successfully_applied"]
    assert r["tests_status"]["FAIL_TO_PASS"]["failure"] == []


def test_pro_report_missing_test_counts_as_failure():
    """Same rule as the Lite parser and as Scale's own `(f2p | p2p) <= passed`."""
    r = bench.pro_report(_out(["t::f1", "t::p1", "t::p2"]), "", INST)
    assert not r["resolved"]
    assert r["tests_status"]["FAIL_TO_PASS"]["failure"] == ["t::f2"]


def test_pro_report_p2p_regression():
    r = bench.pro_report(_out(["t::f1", "t::f2", "t::p1"], failed=["t::p2"]), "", INST)
    assert r["tests_status"]["PASS_TO_PASS"]["failure"] == ["t::p2"]


def test_pro_report_detects_failed_apply_from_stderr():
    """The Pro entryscript has no `set -e`: a patch that does not apply still runs the
    tests on the base commit and would read as 'applied, unfixed'."""
    stderr = "Checking patch qutebrowser/utils/log.py...\nerror: patch failed: qutebrowser/utils/log.py:12\n"
    r = bench.pro_report(_out([]), stderr, INST)
    assert r["patch_successfully_applied"] is False and not r["resolved"]


def test_pro_report_clean_apply_stderr_is_fine():
    stderr = "Checking patch a.py...\nApplied patch a.py cleanly.\n"
    assert bench.pro_report(_out(["t::f1", "t::f2", "t::p1", "t::p2"]), stderr, INST)["patch_successfully_applied"]


def test_pro_report_none_when_no_output():
    assert bench.pro_report(None, "", INST) is None


def test_noop_patch_survives_pro_binary_strip():
    """Scale's grader strips binary hunks; the envcheck no-op must not be one."""
    from dfc.run import NOOP_PATCH
    assert "Binary files" not in NOOP_PATCH and "GIT binary patch" not in NOOP_PATCH


def test_real_pro_rows_normalize(tmp_path):
    """Smoke test against the Scale repo's own export when it is present."""
    path = bench.PRO_ROOT / "helper_code" / "sweap_eval_full_v2.jsonl"
    if not path.exists():
        pytest.skip("Scale repo not cloned")
    with path.open() as fh:
        rows = [bench.PRO.normalize(json.loads(l)) for _, l in zip(range(40), fh)]
    for r in rows:
        assert r["fail_to_pass"] and isinstance(r["fail_to_pass"], list)
        assert r["base_commit"] and r["repo"].count("/") == 1
        assert bench.PRO.image_for(r).startswith("jefzda/sweap-images:")
