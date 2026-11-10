# TRIPWIRE: definitions and rules

Dynamic scanners install a package in one sandbox and watch what it does. Many malicious packages check their surroundings first: if the OS is wrong, a CI variable is missing or the hostname looks like a sandbox, the payload does not run and the package looks clean. TRIPWIRE records those checks in real packages: what each one tests, the value, how conditions combine and what sits behind it.

## Scope: install time only

Only code that runs because the package was installed. npm: `preinstall`/`install`/`postinstall` and everything they reach, the implicit `node-gyp rebuild`, and `prepare` (flagged, since it only runs for git or local installs). PyPI: `setup.py` in an sdist and what it imports, custom `cmdclass`, in-tree build backends. Import-time code, CLI commands, wheels and non-packages are skipped with a one-line skip record so they still count in the denominators.

## Definitions

- **Condition:** one deliberate environmental test, written in the form that must be true to reach the guarded code (e.g. `os == win32`).
- **Gate:** one or more conditions that decide *which behaviour runs*. Early exits count. If flipping it only changes log text, it is not a gate.
- **Requirement:** something the payload just needs (C2 reachable, `bash` or `curl` present). Not a gate, but an analysis environment must provide it.
- **Target artifact:** a check that the thing to steal exists (`.env`, Discord folder, wallet extension). A gate, because an analysis environment can plant decoys. A fresh sandbox looks nothing like a developer's machine.
- **Manifest gate:** a package's own `os`/`cpu`/`libc` fields. npm won't install it at all on a mismatch.
- **Polarity:** *activate* (runs on a target) or *evade* (backs off when it spots analysis).
- **Effect:** *enables*, *selects* (a different payload per branch), or *modifies* (the same behaviour, acting on a different target the environment decides: an exfil host, a victim artifact, an account). A check that only changes where the payload is stored or how it starts is plumbing, not a gate.
- **min_conditions:** the smallest number of conditions that must hold together to reach the payload.
- **In scope:** a machine-environment condition an analysis environment can set. Dependency-tree, consuming-app and server-response gates are recorded but out of scope.
- **Release date (`released_at`):** when the analysed version was published. Taken from the npm or PyPI registry (`released_at_source: registry`), else from a dated dataset archive name (`dataset`), else `null`. Removed malicious versions often have no registry entry.
- **Analysis type:** who produced a record: `ai` (Claude through the gate-analysis skill, with `model_name`) or `tool` (a skip or member record `prepare.py` writes with no judgement).

## Reading the data

- Registries delete malicious versions fast, so prevalence numbers are lower bounds.
- Many payloads need a C2 or second stage that is long dead. The gate still opens; the payload cannot finish.
- Obfuscation hides conditions. Unrecovered code is flagged, never counted as "no gate".
- Datasets are full of near-identical campaign packages. Note the family so they can be clustered.
- A handful of packages says nothing about prevalence. Only the aggregated dataset with denominators does.

## Ground rules

Static analysis only: nothing from a package is installed, run, imported or eval'd, and no URL in it is visited. Indicators are defanged. No personal data about maintainers. Samples never get committed.
