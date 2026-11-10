# PyPI packages

Install mechanics, Python idioms and extractor limits for PyPI. Read after Step 1 for any PyPI package.

## Contents

- What runs at install
- `runs_on`
- Manifest and dependency tree
- Commands never to run
- Python idioms
- Extractor limits
- Packed and compiled code

## What runs at install

- **Wheels** (`.whl`) install by copying files; no package code runs. The tool sends them to Step 2 (`no_install_code` at most). A `.pth` file in a wheel runs at every interpreter start after install; that is load time, not install time (`import_time_only` if malicious).
- **sdists** are built by pip through the build backend in `pyproject.toml` (`build-system.build-backend`), or through setuptools when there is no `pyproject.toml` or the backend is setuptools. Under setuptools, `setup.py` runs as a module, so its top-level code runs on every build step, including metadata generation. Hook `setup_py`.
- **cmdclass overrides** in `setup(cmdclass={...})`: the tool records each as hook `cmdclass` with the overriding class's `run` method as entry. Setuptools' wheel build runs the `install` command into a staging directory, so an `install` override runs on a normal pip install of an sdist, as do `build`, `build_py`, `build_ext`, `egg_info` and `bdist_wheel` overrides. `develop` runs only on legacy editable installs. `sdist` and `upload` overrides run only when the author builds or publishes.
- **In-tree build backends** (`build-system.backend-path`): the backend module runs during the build. Hook `build_backend`.
- A different backend (hatchling, flit, poetry-core, maturin, …) does not run `setup.py`; the tool notes this. Their plugins and build hooks configured in `pyproject.toml` can still run package code; read the configuration.

## `runs_on`

The tools write `always` for `setup_py`, `cmdclass` and `build_backend` hooks. Change it only with a reason in `execution.notes` (for example a `develop`-only override). The schema value `sdist_build_only` has no agreed meaning yet; do not use it, write a note instead.

## Manifest and dependency tree

- `setup_requires`, `build-system.requires` and `install_requires` pull in other packages: dependency tree, noted as one-liners.
- `Requires-Python` makes pip skip an incompatible version; it is not recorded as a gate for now (open question), mention it in a note if it is unusual.
- Install-time variables (category `package_manager`) are those pip or the build frontend set, for example `PIP_*` configuration variables or a virtualenv marker; check what the code actually compares against.

## Commands never to run

`pip install`, `pip download` and `pip wheel` on the package (both download and wheel build sdist metadata, which runs `setup.py`), `python setup.py <anything>`, `python -m build`, `uv pip`/`uv build`, `poetry`, `pdm`, `hatch`, `tox`, `python -c "import pkg"`, and `python` on any package file.

## Python idioms

Early exits: `sys.exit()`, `exit()`, `os._exit()`, `raise`, `return` in the hook function. Positive form: `if os.name != 'nt': sys.exit()` becomes `os == win32`.

Process launch: `subprocess.run/call/Popen/check_output`, `os.system`, `os.popen`, `os.startfile`, `os.exec*`, `os.spawn*`, `pty.spawn`, `multiprocessing` targets. A list starting with `sys.executable` runs Python on the next element.

Indirect execution of a package file: `exec(open(path).read())`, `runpy.run_path`, `execfile`, `subprocess` with `python <file>` or `[sys.executable, <file>]`, `importlib.import_module` or `__import__` with a computed name.

Dynamic evaluation and deserialisation: `exec`, `eval`, `compile`, `__import__`, `importlib`, `marshal.loads`, `pickle.loads`, `types.CodeType`, usually fed by `base64.b64decode`, `zlib.decompress`, `codecs.decode(..., 'rot13')` or `bytes.fromhex`. Decode the input as data; never run it.

Silent failure: bare `except: pass`, `except Exception: pass`, `contextlib.suppress(Exception)`.

Credential and target lookups worth checking as `target_artifact`: `.pypirc`, `.netrc`, `~/.ssh`, browser and wallet profile paths, cloud CLI config folders, env vars that hold tokens.

Version reads (`open('pkg/__init__.py').read()` to find `__version__`) are ordinary build plumbing, not gates.

Inherited checks (`"inherited": true`): typosquats often copy the real project's `setup.py` and add a payload to it. The copied guards stay conditions, flagged as inherited: requests' interpreter check (`if CURRENT_PYTHON < REQUIRED_PYTHON: ... sys.exit(1)`, category `runtime_version`, operator `>=`, value the required version such as `3.7`), a `platform.system()` branch that picks the real project's build options, or `if sys.argv[-1] == 'publish'` (not environmental; drop it). The injected block is the attacker's own, never inherited. The cluster key masks the literal values of `setup()`'s descriptive arguments (`name`, `version`, `description`, `long_description`, `author*`, `maintainer*`, `url`, `download_url`, `keywords`, `classifiers`, `license`, `project_urls`, `platforms`; a string, number, list or dict of literals, or a bare name), so copies that differ only there group as one campaign; a computed value (`open('README.md').read()`, `about['__version__']`, an f-string) is code and still hashed.

Probes in Python: `subprocess.run(['sudo', '-n', 'true']).returncode == 0` is api `subprocess.run`, operator `exists`, probe `{"kind": "exec", "callee": "subprocess.run", "target": "sudo -n true", "accessor": "returncode"}`; `'root' in subprocess.check_output(['id'])` is operator `includes`, value `root`, accessor `stdout`; a try body that opens `/.dockerenv` is api `open`, operator `exists`, value `/.dockerenv`.

## Extractor limits

- `elif` branches carry only their own test.
- Calls through `getattr`, dictionaries of functions, or classes built at runtime are not followed. Write these paths with `bind` hops (`self.sender = HttpSender()`, `{'send': post}`, a function passed as an argument), or mark them `unresolved` (SKILL.md, payload). An early exit on an excluded value (`if locale.startswith('ru'): sys.exit()`) is operator `not_startswith`.
- The cmdclass entry is the class's own `run`; behaviour inherited through `super().run()` from setuptools is not package code.
- Local-file execution is followed only for literal paths: `exec(open('x').read())`, `runpy.run_path('x')`, `execfile('x')`, and `subprocess`/`os.system` with a literal `python x`. Anything else that starts a package file shows up, at best, in `hints.not_chained`.
- f-strings with substitutions give `partial` values (`<?>`).

## Packed and compiled code

- **pyarmor:** encrypted bytecode with a runtime loader; the tool marks it unrecovered. Without a static way to recover it, it stays unread.
- **marshal'd code objects** (`exec(marshal.loads(b'...'))`): the bytes are compiled bytecode. Loading them is deserialisation (hard rule 2), so never call `marshal.loads`; strings visible in the raw bytes may be listed as data, the logic stays unread.
- **Compiled extensions** (`.so`, `.pyd`) or `.pyc`-only modules reached at build time: list strings and imports as data, but treat logic as unread.
- Large vendored packages inside an sdist follow the coverage tiers in the large-code reference.
