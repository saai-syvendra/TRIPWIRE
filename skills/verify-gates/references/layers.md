# Claim layers, verdicts and how to try to refute each

## Contents

- Verdicts and reason codes
- L1: existence
- L2: value and operator
- L3: guarding and exclusivity
- L4: combination
- L5: behaviour
- L6: interpretation

## Verdicts and reason codes

| verdict | when |
|---|---|
| `verified` | the cited code positively shows what the claim says |
| `refuted` | the cited code contradicts the claim |
| `unanchored` | the claim cannot be tied to bytes in the package |
| `cannot_tell` | the claim is tied to code, but that code does not decide it |

Reason codes: `no_anchor`, `sample_missing`, `anchor_hash_mismatch`, `recipe_failed`, `parse_failed` (why a claim is unanchored); `value_unchecked`, `value_redacted` (the record redacted the value as personal data or a secret), `operator_unchecked`, `encoded_unchecked`, `budget_exceeded`, `dynamic_dispatch`, `lang_unsupported`, `unresolved_binding`, `bundle_unresolved`, `name_only_link`, `witness_gap`, `incomplete_cfg` (why it cannot be told); `not_a_test`, `api_mismatch`, `value_mismatch`, `operator_mismatch`, `outside_region`, `broken_hop`, `no_sink`, `sink_kind_mismatch`, `expression_mismatch` (why it is refuted); `checker_error` (a fault in the checker, never a finding); `judgement` for an interpretation verdict; `other` with evidence when nothing fits.

The deterministic checker never overclaims. It says `verified` only when the code positively proves the claim, `refuted` only when the code positively contradicts it, and `cannot_tell` (with a reason naming what it could not resolve) whenever its analysis is incomplete: an unresolved binding, a require or bundle module it could not follow (`bundle_unresolved`), a call tied to a definition only by a shared name (`name_only_link`; add a `bind` hop or a resolved binding to prove such a path), a witness hop it could not confirm (`witness_gap`), a control-flow construct it does not model (`incomplete_cfg`), or a name computed by a call behind obfuscation (`encoded_unchecked`). It refutes an API only when it resolves the site to a *different* known API; a value only when the operand is a different constant; an operator only when the code's operator is the *opposite polarity* of the claim (a same-polarity different operator, e.g. `exists` where the claim says `truthy`, or `regex` where it says `includes`, is `cannot_tell`, not a contradiction); a region only when the guards provably control the opposite edge or the region runs regardless of every guard on a fully modelled function. Names are resolved to canonical fully-qualified forms (import aliases, destructuring renames, `(0, x.m)`, bundle module ids) before matching; a built-in prototype method (`String.startsWith`) matches on its method name.

## L1: existence

The claim: at every cited site, the code tests the named API. Try to refute it: is the cited node a decision (a comparison, a negation, an existence or lookup call, or something in the condition of a branch, loop, ternary, switch, short-circuit or try body), or a value that a gate's decision reads through a variable or a one-line helper? Does it use the API, directly or through a variable bound to it in the same scope? A variable assigned more than once before the test (a fallback: `let t = env.NPM_TOKEN; if (!t) t = readRc();`) may hold any of its values. A variable of the same name in another function is not the same binding. When the API lists alternatives (`a / b`), each site must use one of them.

Absence is only evidence where the code can be read. A site the analyst decoded by hand (`value_recovered` `decoded` or `partial`) that still sits on the encoded bytes, rather than in a derivation, and a site whose names are computed by a call (`process.env[dec('...')]`, `s[_0x4fb9(0x52b)]('ru')`, what string tables and ciphers leave behind) cannot contradict a claim: when the API, value or operator is not visible there, the verdict is `cannot_tell` with `encoded_unchecked`, never `refuted`. Once the analyst registers the decode (a `decode_spec` derivation, rebuilt by running the registered decoder over the package bytes and checked against `output_sha256`), the site sits in readable code and is checked like any other.

A condition with a `probe` claims more: the test reaches (through variables, awaits, accessors such as the output or exit status, or the parameters of a callback) a call of `probe.callee` that runs exactly `probe.target` (a command line, `*` standing for an interpolated part) or reads that path. A call of the same function with another command refutes it.

## L2: value and operator

The claim: the compared value is what the code compares against, and the operator is written in positive form, the form that must be true to reach the guarded code. Count the negations between the test and the decision (including those in a variable's value when the decision reads the variable), and remember that an early exit runs the guarded code when its test is false: `if (t.startsWith(D)) exit()` guards code where `not_startswith D` holds, so `startswith` there is refuted. The negated forms are `!=`, `not_in`, `not_startswith`, `not_includes`, `not_regex`, `falsy` and `not_exists`. `x["m"](...)` reads like `x.m(...)`. A value assembled from pieces (a path joined from a home folder and a name) counts when every piece is in the code. `exists`/`not_exists` with no value asks whether something was there: a probe's output compared unequal to empty, an exit status equal to 0, an error that is absent, a value unequal to null.

## L3: guarding and exclusivity

The claim: the branch's sink is reached from the code the guards control. A guard's site is its decision statement or that decision's test expression; a guard cited on the test is read as the enclosing decision of its kind (and refused when there is none). The claimed side of an early exit with no else block is the rest of the enclosing block after it. A guard with `via` calls extends that side: when the exit ends the process, each cited call must run the function holding the previous step (the guard first), and the rest of the block after each call is on the guard's side too. Every region of the branch must lie on the claimed side of at least one guard, and every guard must control at least one region. For the `else` branch each guard's claimed side is its other side, except a guard whose conditions the branch lists in `else.requires`: that guard encloses both branches and keeps its side (`if X { if Y {A} else {B} }`: B is on X's then side and Y's else side). The sink is a call. Walk the witness: the first hop must sit inside a branch region; a call must reach the definition that follows it; the next hop must sit inside that definition; the last step reaches the sink. A `bind` hop does not move along the path: it cites where a function or object is stored under a name (an object key, an assignment or declaration, a call argument), must sit in code already reached, and lets a later call under that name reach the stored definition; a method called on a bound object must belong to the bound class. An empty witness claims the sink sits in the region itself. A payload marked `unresolved` gives the hops the analyst could trace: check those, then try to follow the rest; the claim is verified only when you can. Exclusivity asks whether the sink can also be reached without passing the gate (another caller of the same function, an export, a timer).

## L4: combination

The claim: the expression joins the conditions the way the code does. Guards over the same region nest and join with and; alternatives in one test, or separate decisions each leading to its own copy of the code (each its own region), join with or. A decision on a variable or helper is read through what the variable holds. A presence check in front of a test of the same value (`x !== undefined && x.startsWith(p)`) is part of that test, not another condition. `min_conditions` must equal the smallest set of conditions that satisfies the combination.

## L5: behaviour

The claim: each behaviour of the branch rests on a sink that can do it: network for exfiltration and downloads, process creation for spawning, file writes for persistence and dropped files, file deletion for destruction. The sink's kind follows its binding (a destructured or named import of a process or network module, a client library) and, when the sink calls the package's own wrapper function or method, what that wrapper reaches. A wrapper is found by its binding, else by its name; a name defined more than three times in the file (generated code, minified bundles) is ambiguous and is not followed, so such a sink's kind stays open. Each claim may visit a fixed number of syntax nodes; one that needs more is `cannot_tell` with `budget_exceeded`. Recon and defense evasion need reading of the code around the sink.

## L6: interpretation

These are judgement calls; decide them from the code and the claim's fields alone.
- `category`: which environment property the condition reads.
- `polarity`: `activate` (runs on a target) or `evade` (backs off when it spots analysis, CI or a sandbox).
- `effect`: `enables`, `selects` (a different payload per branch) or `modifies` (the same behaviour, acting on a different target the environment decides: the host data goes to, the victim artifact taken, the account used). A test that only changes where the payload is stored or how it starts (a destination folder, a temp path, a shell) is plumbing, not a gate.
- `purpose`: `portability`, `targeting`, `anti_analysis`, `data_availability` or `unclear`.
- `drop`: the analyst left this test out of the record for the stated `reason_code`. Give `verified` when the cited test really is not part of an environment gate for that reason (library code, not environmental, dead branch, not run at install, log text only, a duplicate, a re-entry guard), `refuted` when it is a gate the record misses (say which behaviour it decides), `cannot_tell` when the code shown does not decide it.
Give `verified` when the label fits the code, `refuted` with the label you would give in the evidence, `cannot_tell` when the code shown does not decide it.
