# npm packages

Install mechanics, JavaScript idioms and extractor limits for npm. Read after Step 1 for any npm package.

## Contents

- Install hooks and `runs_on`
- Hook commands
- Delegated tools
- Manifest gate
- Dependency tree and never-reached code
- Commands never to run
- JavaScript idioms
- Extractor limits
- Bundles

## Install hooks and `runs_on`

- `preinstall`, `install`, `postinstall` run on every install from the registry: `runs_on: always`.
- `preprepare`, `prepare`, `postprepare` run only for git or local-folder installs: `runs_on: git_or_local_install_only`. Record them; they matter less for registry installs.
- A `binding.gyp` with no `install`/`preinstall` script makes npm run `node-gyp rebuild` implicitly. The tool records it as hook `node_gyp_implicit`, launch style `native_build`.
- `prepack`, `prepublish*`, `test`, `start` and other scripts do not run on install unless a hook calls them (`npm run x`).
- Install-time env vars npm sets (category `package_manager`): `npm_config_*`, `npm_lifecycle_event`, `npm_lifecycle_script`, `npm_package_*`, `npm_execpath`, `INIT_CWD`; Bun adds `BUN_INSTALL`, Yarn `YARN_*`/`npm_config_user_agent`. A check on these usually tells real installs from scanners that run the script directly. Credentials users set themselves (`NPM_TOKEN`, `GITHUB_TOKEN`, cloud keys) are not installer variables: use `env_var`, or `target_artifact` when the check is that the credential exists.
- Hooks run with the package root as working directory, so relative paths in hook code resolve from there.

## Hook commands

The tool parses hook strings with `parse_command` and follows: `npm run`/`yarn`/`pnpm`/`bun run` script chains, `node <file>`, `node -e`/`-r`/`--require`/`--import`, `bun <file>`, `sh -c`/`bash <file>`, `cmd /c`, `start /b`, `powershell` (flags `-enc` as `decoded_eval`), and `curl|sh` style pipes (`shell_pipe`, `download_then_exec`).

Yours to read:
- Shell conditionals in the hook string (`[ "$(uname)" = Linux ] && node a.js`, `test -f x || …`). The tool lists them in `notes`. Each is a condition whose site is a text anchor on the test inside `package.json` (`cite.py scratch/<key> package.json --line N --text '<the test>'`); its guard is the same span with kind `short_circuit` or `if`.
- Silencers: `|| true`, `|| exit 0`, `2>/dev/null`, `>nul` set `silent_failure`.
- `npx <pkg>` and unknown executables run code from a dependency or the system: out of scope as code, in scope as a command.
- Hooks that install further packages (`npm i x`) are noted; the installed package is dependency tree.

## Delegated tools

`node-gyp`, `prebuild-install`, `node-pre-gyp`, `cmake-js`, `prebuildify`, `husky` and a dependency's `bin` are delegated commands: record the command, not the dependency's code. A `binding.gyp` itself can run shell actions; read it when present.

## Manifest gate

`package.json` `os`, `cpu` and `libc` make npm refuse the install on a mismatch, so no hook runs. Values may be negated with `!` (`"!win32"`). The tool prefills the gate with hook `resolve`, api `package.json#os` (or `#cpu`, `#libc`). `engines` is advisory unless `engine-strict` is set, so it is not a gate.

## Dependency tree and never-reached code

Not install-time code of this package:
- `bin` commands, `main`/`module`/`exports` (run when invoked or loaded), unless a hook runs them.
- `dependencies` with git/http/file specs and `optionalDependencies` platform picks: noted as dependency tree.

A hook file can still launch a `bin` file or a sibling script by path. `hints.not_chained` flags such files when they are named literally.

## Commands never to run

`npm install`/`ci`/`run`/`pack` on the package, `yarn`, `pnpm`, `bun`, `npx`, `node` (including `node -e`, `node --check`), and any formatter, linter or bundler that loads package files through node (prettier, js-beautify, eslint, webpack). Reformat with Python or tree-sitter on a scratch copy instead.

## JavaScript idioms

Early exits: `process.exit()`, `return` at top level of a function, `throw`, `process.kill(process.pid)`. Positive form: `if (os.platform() !== 'win32') process.exit()` becomes `os == win32`.

Process launch: `child_process.exec/execSync/spawn/spawnSync/execFile/fork`, often destructured (`const { spawn } = require('child_process')`) or aliased; `shelljs.exec`, `execa`, `cross-spawn`; Bun's `Bun.spawn`, `Bun.spawnSync` and the `Bun.$` template shell; Deno's `Deno.Command`. `detached: true` with `.unref()` is `detached_child`: the payload outlives the install.

Indirect execution of a package file: `fork(path)`, `spawn(process.execPath, [path])`, `spawn('node', [path])`, a runtime held in a variable (`spawn(runtime, [path])`), a downloaded runtime running a bundled file, `require(path)` with a computed path, `import()`.

Dynamic evaluation: `eval`, `Function(...)`/`new Function`, `vm.runIn*Context`, `vm.Script`, `require` of a file written at runtime, `Buffer.from(x, 'base64')` feeding any of these. Never run them; decode their input as data.

Silent failure: `try {} catch {}` with an empty or exit-0 handler, `.catch(() => {})`, `process.on('uncaughtException', …)`, `process.exit(0)` in error paths.

Credential and target lookups worth checking as `target_artifact`: `.npmrc` (`_authToken`), `~/.ssh`, browser and wallet profile paths, `gh auth token`, cloud CLI config folders, env vars matching token prefixes (`ghp_`, `gho_`, `npm_`). A credential variable (`NPM_TOKEN`, `GITHUB_TOKEN`, `NODE_AUTH_TOKEN`) is `env_var`, never `package_manager`, whatever its prefix.

`api` names: `process.platform`, `os.platform()`, `process.env.CI`, `fs.existsSync`, `child_process.execSync`, `Bun.$`.

Probes (`probe` on a condition):
- `execSync('id -u').toString().trim() === '0'`: api `child_process.execSync`, operator `==`, value `0`, probe `{"kind": "exec", "callee": "child_process.execSync", "target": "id -u", "accessor": "stdout"}`.
- `execSync('ps aux').toString().includes('agent')`: operator `includes`, value `agent`, target `ps aux`.
- `spawnSync('sudo', ['-n', 'true']).status === 0`, ``(await $`sudo -n true`.nothrow()).exitCode === 0``: operator `exists`, value `null`, accessor `returncode`, target `sudo -n true` (argv joined with spaces).
- `exec('which docker', (err) => { if (!err) ... })`: site `!err`, operator `exists`, accessor `error`.
- A try body that runs `execSync('systemd-detect-virt')`: operator `exists`, accessor `throws`.
- `fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8').includes('_authToken')`: category `target_artifact`, api `fs.readFileSync`, operator `includes`, value `_authToken`, probe `{"kind": "file", "callee": "fs.readFileSync", "target": "~/.npmrc", "accessor": "content"}`.

Evade tests before an early exit, as obfuscator.io output leaves them after decoding: `if (N6()) process["exit"](0)` with `function N6() { const a = b; return t !== void 0 && t["startsWith"]('ghp_decoy'); }` is a condition on the `startsWith` call, operator `not_startswith`, value `ghp_decoy`, guard `early_exit` with `arm: else` on the `if`. Bracket members (`x["m"]()`) read like dot members, the `t !== void 0 &&` presence check is part of the test, and the `const a = b;` alias line does not stop the helper counting as one-line. A value read with a default (`(process.env.LANG || '')["startsWith"]('ru')`) is a test of that value.

Inherited checks (`"inherited": true`): a compromised or typosquatted copy of a real package keeps that package's own install script, for example a native addon's `install.js` that tests `process.platform` or `process.versions.node` to choose a prebuilt binary, or the real package's `engines` check. Flag those conditions; the attacker's added code (a new hook, an injected block in the copied script) never is. The cluster key never hashes `package.json`, so copies that only differ in name and version already group as one campaign.

Tests through variables and helpers: in `const isWin = os.platform() === 'win32'; if (isWin)` the site is `os.platform() === 'win32'` and the guard is the `if`. In `const token = process.env.NPM_TOKEN || readNpmrc(); if (token)` cite `process.env.NPM_TOKEN` and the test inside `readNpmrc` as two conditions joined with `||`, both on the `if` guard.

## Extractor limits

- `else if` chains: each branch carries only its own test.
- Calls through object properties (`obj.run()` where `obj` is built at runtime), dynamic `require`, and callbacks other than named functions are not followed. Write these paths with `bind` hops, or mark them `unresolved` (SKILL.md, payload).
- The node runtime detection only follows `fork(x)`, `spawn('node', [x])`, `spawn(process.execPath, [x])` and `exec('node x')` with literal paths. Anything else that starts a package file shows up, at best, in `hints.not_chained`.
- Bun and Deno process APIs are not sinks in the table, so `launches_processes` misses files that only use them, and their gates may lack sink hints. Read such files fully.
- Template-literal commands with substitutions are only partly recovered (`<?>` in values).
- Very large single-line files parse, but candidates from library code are common; see the large-code reference.

## Bundles

How to split common formats into units before applying the coverage tiers (see the large-code reference for the tiers themselves):
- **webpack:** a module table object `{ <id>: (module, exports, require) => {…} }` or an array of functions; the entry is the trailing call that requires the entry id. Each module is a unit; follow `require(<id>)` references from the entry to find package-written modules.
- **esbuild / rollup:** helper wrappers like `__commonJS`, `__esm`, `__toESM` (often renamed to one-letter names) around each module; ES module imports and top-level code at the end are the package's own code. Comment paths (`// node_modules/x/index.js`) survive in unminified output and name the library.
- **ncc / browserify:** similar module tables keyed by number.
- **obfuscator.io style:** a string array function, a rotation IIFE that shuffles it until a checksum expression matches, and a decoder function `name(index)` that maps `index - offset` (sometimes with base64 or RC4). Decoy branches use constant string comparisons (`if ('abc' === 'xyz')`). Decoding procedure is in the large-code reference.
