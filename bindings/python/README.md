# dstu-core (Python bindings)

**Provisional — not yet published to PyPI, not independently audited.** See the root project's
`docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and per-construction status.
Full documentation (installation, examples, the complete API) lands in `docs/bindings-strategy.md`
T-49's later steps — this is scaffolding (step 1), not the finished binding.

## Building locally

This crate is its own Cargo workspace, separate from the repo root (`docs/DECISIONS.md` D-119) —
build/test it from inside this directory, not from the repo root.

`pyo3` needs a real Python interpreter to link against at build time. Plain `python`/`python3` may
not be enough to find one — on Windows in particular, those names can resolve to non-functional
Microsoft Store alias stubs instead of a real install. If `cargo build`/`maturin develop` fails to
find (or finds the wrong) Python, point it at one explicitly:

```sh
export PYO3_PYTHON=/path/to/a/real/python3   # POSIX
$env:PYO3_PYTHON = "C:\path\to\python.exe"   # PowerShell
```

Then, from a virtualenv with `maturin` installed:

```sh
python -m venv .venv
source .venv/bin/activate        # or .venv\Scripts\activate on Windows
pip install maturin
maturin develop
python -c "import dstu_core; dstu_core.selftest()"
```

`maturin develop` builds the Rust extension and installs it into the active virtualenv as an
editable package. `dstu_core.selftest()` re-runs `dstu_core::selftest::run()` (`docs/TASKS.md`
T-161) against the exact compiled build and raises `RuntimeError` if anything official-vector-level
is wrong — the first thing to run after any build to confirm it actually works, not just compiled.
