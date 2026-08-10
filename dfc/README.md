# `dfc/` — the policed-primitives pipeline

Phase 1 of the build order in `DFC_STATUS_AND_BUILD_PLAN.md` §8.
Design decisions that the plan left open are recorded in `../DECISIONS.md`.

## Layout

| Module | Job |
|---|---|
| `model.py` | Vocabulary: verbs, the two label lattices, targets, actions, decisions, the flow-log record |
| `policy.py` | **Enforcement table** — what the restriction *is*. Primitive set, restricted-awk and scoped-`sed -i` predicates, curl form splitting, infra allowlist, arm configs |
| `canon.py` | **Canonicalization table** — the 56 CSV rules, ported with `csv_row` provenance. Proposes rewrites; does not decide admissibility (D1) |
| `classifier.py` | Shell string → flow edges, via tree-sitter-bash. Handles pipes, redirects, subshells, command substitution, heredocs |
| `hook.py` | The `PreToolUse` gate. allow / allow+`updatedInput` / deny, and writes the flow log |
| `flowlog.py` | Append-only JSONL log and the §7 metrics |
| `cli.py` | `classify`, `summarize`, `mine` |

## Why tree-sitter-bash and not bashlex

The plan named `bashlex` first. It cannot parse heredocs at all — it raises
`ParsingError: here-document at line 0 delimited by end-of-file` on
`tee f <<'EOF' … EOF`, which §8 Phase 2 mandates for *every* write. tree-sitter-bash
parses them natively, isolates `heredoc_body` as data, and exposes `root_node.has_error`
so malformed input can fail closed under enforcement and open under observation.

## Usage

```bash
pip install -r ../requirements.txt

# classify one command
python -m dfc.cli classify 'grep pat f > out' --arm arm1

# the whole gate, as Claude Code calls it
echo '{"tool_name":"Bash","tool_input":{"command":"cat setup.py"}}' | python -m dfc.hook

# metrics off a run
python -m dfc.cli summarize runs/arm1/flow_log.jsonl

# §7 coverage over an existing trajectory corpus, weighted by invocation frequency
python -m dfc.cli mine ../SWE-bench_Pro-os/traj --arm arm1
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DFC_ARM` | `arm1` | `arm0` (observe-only), `arm1` (primitives), `arm2` (+ scoped `sed -i`) |
| `DFC_FLOW_LOG` | `./flow_log.jsonl` | Append-only flow log |
| `DFC_INSTANCE_ID` | — | SWE-bench instance under test |
| `DFC_STRICT` | `1` | `0` makes an internal classifier error fail open even under enforcement |

## The three outcomes

Report these separately (D2). Collapsing them loses the result.

| Outcome | Meaning |
|---|---|
| `passthrough` | already canonical |
| `rewritten` | folded onto the primitive set, silently. Sizes the **translation layer** |
| `denied` | no admissible rewrite exists. This is the **restriction**, and the only thing that counts as an escape attempt |
| `observed` | Arm 0: classified and logged, never gated |

## Phase 2 wiring

1. Copy `settings.template.json` to `../.claude/settings.json`.
2. Construct the SDK session with `setting_sources=["project"]` — it does not load
   filesystem settings otherwise (§10).
3. Set `disallowed_tools` for every built-in file tool. `allowed_tools` does **not**
   restrict anything under `permission_mode="bypassPermissions"`.
4. Set `continueOnBlock: true` so a denial returns to the model as a tool error it can
   adapt to. Without it, one reflexive `awk` ends the turn and kills a viable
   trajectory — which would confound the cost measurement badly.
