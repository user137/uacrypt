//! `cargo xtask asm-check` (T-292, `docs/DECISIONS.md` D-229): builds `dstu-core`'s release asm
//! with D-225's recipe and fails if a constant-time fix of D-223/D-225/D-227 comes undone.
//!
//! Hard rules, no exceptions: no riscv32 64-bit carry compare shape (D-226) in any function of
//! the limb-arithmetic modules or any `OUTLINED_FUNCTION_*` body, and no `__multi3`/`__muldi3`
//! call anywhere in the crate (D-227's `hazmat::limb` has no barrier, so this is its only guard).
//! Then every symbol in [`ZERO_JUMPS`] must have no conditional or indirect jump in that target
//! and `opt-level`. Symbols that keep public jumps (loop counters, `Option` tags) are not counted
//! (owner, 2026-09-26): a count would only say "something changed" and would need a re-read after
//! every rustc release. A failure after a rustc bump names the version change ([`AUDITED_RUSTC`]):
//! read the asm; a row may only be dropped once its new jump has been read and is public.
use std::path::{Path, PathBuf};
use std::process::Command;

const AUDITED_RUSTC: &str = "1.97.1";

const X86_64: &str = "x86_64-unknown-linux-gnu";
const AARCH64: &str = "aarch64-unknown-none";
const THUMB: &str = "thumbv7em-none-eabihf";
const RISCV32: &str = "riscv32imc-unknown-none-elf";

/// D-227: the 32-bit targets also at `s`/`z`, where the outliner and `__multi3` calls appear.
const CELLS: [(&str, Arch, &str); 8] = [
    (X86_64, Arch::X86_64, "3"),
    (AARCH64, Arch::Aarch64, "3"),
    (THUMB, Arch::Thumb, "3"),
    (THUMB, Arch::Thumb, "s"),
    (THUMB, Arch::Thumb, "z"),
    (RISCV32, Arch::Riscv32, "3"),
    (RISCV32, Arch::Riscv32, "s"),
    (RISCV32, Arch::Riscv32, "z"),
];

/// `(target, opt-level, spec)`: symbols with secret data and no jump at all at rustc
/// [`AUDITED_RUSTC`] (D-225/D-227), plus the summed outlined bodies ([`OUTLINED`]) where they have
/// none. A spec is `::`-separated idents, see [`symbol_matches`].
const ZERO_JUMPS: &[(&str, &str, &str)] = &[
    (X86_64, "3", "gf2m163::FieldElement::square"),
    (X86_64, "3", "gf2m257::FieldElement::square"),
    (X86_64, "3", "scalar::Scalar::Add::add"),
    (X86_64, "3", "fp256::FieldElement::add"),
    (X86_64, "3", "fp512::FieldElement::add"),
    (X86_64, "3", "fp512::FieldElement::sub"),
    (X86_64, "3", "fp256::FieldElement::square"),
    (X86_64, "3", "fp256::FieldElement::invert"),
    (X86_64, "3", "fp256::FieldElement::sqrt"),
    (X86_64, "3", "fp256::FieldElement::euler_criterion"),
    (X86_64, "3", "fp512::FieldElement::square"),
    (X86_64, "3", "fp512::FieldElement::invert"),
    (X86_64, "3", "fp512::FieldElement::sqrt"),
    (X86_64, "3", "fp512::FieldElement::euler_criterion"),
    (X86_64, "3", "curve256::ProjectivePoint::add"),
    (X86_64, "3", "curve512::ProjectivePoint::add"),
    (AARCH64, "3", "gf2m163::FieldElement::square"),
    (AARCH64, "3", "gf2m257::FieldElement::square"),
    (AARCH64, "3", "scalar::Scalar::Add::add"),
    (AARCH64, "3", "scalar257::Scalar::Add::add"),
    (AARCH64, "3", "fp256::FieldElement::add"),
    (AARCH64, "3", "fp512::FieldElement::add"),
    (AARCH64, "3", "fp512::FieldElement::sub"),
    (AARCH64, "3", "fp256::FieldElement::square"),
    (AARCH64, "3", "fp256::FieldElement::invert"),
    (AARCH64, "3", "fp256::FieldElement::sqrt"),
    (AARCH64, "3", "fp256::FieldElement::euler_criterion"),
    (AARCH64, "3", "fp512::FieldElement::square"),
    (AARCH64, "3", "fp512::FieldElement::invert"),
    (AARCH64, "3", "fp512::FieldElement::sqrt"),
    (AARCH64, "3", "fp512::FieldElement::euler_criterion"),
    (AARCH64, "3", "curve256::ProjectivePoint::add"),
    (AARCH64, "3", "curve512::ProjectivePoint::add"),
    (THUMB, "3", "gf2m163::FieldElement::square"),
    (THUMB, "3", "gf2m257::FieldElement::square"),
    (THUMB, "3", "scalar::Scalar::Add::add"),
    (THUMB, "3", "fp256::FieldElement::add"),
    (THUMB, "3", "fp512::FieldElement::add"),
    (THUMB, "3", "fp512::FieldElement::sub"),
    (THUMB, "3", "fp256::FieldElement::square"),
    (THUMB, "3", "fp256::FieldElement::invert"),
    (THUMB, "3", "fp256::FieldElement::sqrt"),
    (THUMB, "3", "fp256::FieldElement::euler_criterion"),
    (THUMB, "3", "fp512::FieldElement::square"),
    (THUMB, "3", "fp512::FieldElement::invert"),
    (THUMB, "3", "fp512::FieldElement::sqrt"),
    (THUMB, "3", "fp512::FieldElement::euler_criterion"),
    (THUMB, "3", "curve256::ProjectivePoint::add"),
    (THUMB, "3", "curve512::ProjectivePoint::add"),
    (THUMB, "s", "fp256::FieldElement::square"),
    (THUMB, "s", "fp256::FieldElement::invert"),
    (THUMB, "s", "fp256::FieldElement::euler_criterion"),
    (THUMB, "s", "fp512::FieldElement::square"),
    (THUMB, "s", "fp512::FieldElement::invert"),
    (THUMB, "s", "fp512::FieldElement::euler_criterion"),
    (THUMB, "s", "curve256::ProjectivePoint::to_affine"),
    (THUMB, "s", "curve512::ProjectivePoint::to_affine"),
    (THUMB, "z", "gf2m163::FieldElement::invert"),
    (THUMB, "z", "gf2m257::FieldElement::invert"),
    (THUMB, "z", "fp256::FieldElement::square"),
    (THUMB, "z", "fp256::FieldElement::invert"),
    (THUMB, "z", "fp256::FieldElement::sqrt"),
    (THUMB, "z", "fp256::FieldElement::euler_criterion"),
    (THUMB, "z", "fp512::FieldElement::square"),
    (THUMB, "z", "fp512::FieldElement::invert"),
    (THUMB, "z", "fp512::FieldElement::sqrt"),
    (THUMB, "z", "fp512::FieldElement::euler_criterion"),
    (THUMB, "z", "curve256::ProjectivePoint::add"),
    (THUMB, "z", "curve256::ProjectivePoint::to_affine"),
    (THUMB, "z", "curve512::ProjectivePoint::add"),
    (THUMB, "z", "curve512::ProjectivePoint::to_affine"),
    (THUMB, "z", "limb::mac"),
    (RISCV32, "3", "gf2m163::FieldElement::square"),
    (RISCV32, "3", "gf2m257::FieldElement::square"),
    (RISCV32, "3", "scalar::Scalar::Add::add"),
    (RISCV32, "3", "fp256::FieldElement::add"),
    (RISCV32, "3", "fp512::FieldElement::add"),
    (RISCV32, "3", "fp512::FieldElement::sub"),
    (RISCV32, "3", "fp256::FieldElement::square"),
    (RISCV32, "3", "fp256::FieldElement::invert"),
    (RISCV32, "3", "fp256::FieldElement::sqrt"),
    (RISCV32, "3", "fp256::FieldElement::euler_criterion"),
    (RISCV32, "3", "fp512::FieldElement::square"),
    (RISCV32, "3", "fp512::FieldElement::invert"),
    (RISCV32, "3", "fp512::FieldElement::sqrt"),
    (RISCV32, "3", "fp512::FieldElement::euler_criterion"),
    (RISCV32, "3", "curve256::ProjectivePoint::add"),
    (RISCV32, "3", "curve512::ProjectivePoint::add"),
    (RISCV32, "s", "fp256::FieldElement::square"),
    (RISCV32, "s", "fp256::FieldElement::invert"),
    (RISCV32, "s", "fp256::FieldElement::euler_criterion"),
    (RISCV32, "s", "fp512::FieldElement::square"),
    (RISCV32, "s", "fp512::FieldElement::invert"),
    (RISCV32, "s", "fp512::FieldElement::euler_criterion"),
    (RISCV32, "s", "curve256::ProjectivePoint::to_affine"),
    (RISCV32, "s", "curve512::ProjectivePoint::to_affine"),
    (RISCV32, "z", "gf2m163::FieldElement::invert"),
    (RISCV32, "z", "gf2m257::FieldElement::invert"),
    (RISCV32, "z", "fp256::FieldElement::square"),
    (RISCV32, "z", "fp256::FieldElement::invert"),
    (RISCV32, "z", "fp256::FieldElement::sqrt"),
    (RISCV32, "z", "fp256::FieldElement::euler_criterion"),
    (RISCV32, "z", "fp512::FieldElement::square"),
    (RISCV32, "z", "fp512::FieldElement::invert"),
    (RISCV32, "z", "fp512::FieldElement::sqrt"),
    (RISCV32, "z", "fp512::FieldElement::euler_criterion"),
    (RISCV32, "z", "curve256::ProjectivePoint::add"),
    (RISCV32, "z", "curve256::ProjectivePoint::to_affine"),
    (RISCV32, "z", "curve512::ProjectivePoint::add"),
    (RISCV32, "z", "curve512::ProjectivePoint::to_affine"),
    (RISCV32, "z", "limb::mac"),
    (RISCV32, "z", "OUTLINED_FUNCTION_*"),
];

const OUTLINED: &str = "OUTLINED_FUNCTION_*";

/// [`find_one`] for a spec, or the summed outlined bodies for [`OUTLINED`].
fn row_jumps(arch: Arch, functions: &[Function], spec: &str) -> Result<u32, String> {
    if spec != OUTLINED {
        return jumps(arch, find_one(functions, spec)?);
    }
    let outlined: Vec<&Function> = functions.iter().filter(|f| f.is_outlined()).collect();
    if outlined.is_empty() {
        return Err(format!("'{spec}': no symbol"));
    }
    outlined.into_iter().map(|f| jumps(arch, f)).sum()
}

pub(crate) fn run() -> bool {
    let installed = match output("rustup", &["target", "list", "--installed"]) {
        Ok(list) => list,
        Err(e) => {
            return crate::skip(&format!(
                "xtask: asm-check: rustup not usable ({e}) - skipping"
            ))
        }
    };
    for (target, _, _) in CELLS {
        if !installed.lines().any(|t| t.trim() == target) {
            return crate::skip(&format!(
                "xtask: asm-check: target {target} not installed - skipping.\n  install with: \
                 rustup target add {X86_64} {AARCH64} {THUMB} {RISCV32}"
            ));
        }
    }
    let rustc = match output("rustc", &["-V"]) {
        Ok(v) => v.split_whitespace().nth(1).unwrap_or_default().to_owned(),
        Err(e) => {
            eprintln!("xtask: asm-check: rustc -V failed: {e}");
            return false;
        }
    };

    let mut failures = Vec::new();
    for (target, arch, opt) in CELLS {
        let result = build(target, opt).and_then(|path| {
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
        });
        match result {
            Ok(asm) => failures.extend(
                check_cell(&asm, target, arch, opt)
                    .into_iter()
                    .map(|f| format!("{target} {opt}: {f}")),
            ),
            Err(e) => failures.push(format!("{target} {opt}: {e}")),
        }
    }
    if failures.is_empty() {
        println!(
            "asm-check: {} zero-jump rows and the hard rules hold (rustc {rustc})",
            ZERO_JUMPS.len()
        );
        return true;
    }
    for failure in &failures {
        eprintln!("asm-check: {failure}");
    }
    if rustc != AUDITED_RUSTC {
        eprintln!(
            "asm-check: rustc changed from {AUDITED_RUSTC} to {rustc}: read the failing symbols' \
             asm before changing a row (D-229)"
        );
    }
    false
}

fn output(base: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(crate::command_for(base))
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// D-225's recipe. Each `opt-level` has its own target dir so the eight builds stay cached. A
/// fresh build does not rewrite the `.s`, so deleting it would lose it; instead the `.s` is the one
/// with the newest `libdstu_core-<hash>.rlib`'s hash (same rustc invocation, and this target dir
/// only ever sees these `RUSTFLAGS`), so a leftover from an older rustc is never read.
fn build(target: &str, opt: &str) -> Result<PathBuf, String> {
    let dir = PathBuf::from("target")
        .join("asm-check")
        .join(format!("opt-{opt}"));
    let deps = dir.join(target).join("release").join("deps");
    println!("+ cargo build --release -p dstu-core --lib --no-default-features --target {target} (opt-level {opt}, --emit=asm)");
    let ok = Command::new(crate::command_for("cargo"))
        .args([
            "build",
            "--release",
            "-p",
            "dstu-core",
            "--lib",
            "--no-default-features",
        ])
        .args(["--target", target])
        .env("CARGO_TARGET_DIR", &dir)
        .env("CARGO_PROFILE_RELEASE_OPT_LEVEL", opt)
        .env("RUSTFLAGS", "--emit=asm -C debuginfo=0")
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        return Err("cargo build failed".to_owned());
    }
    let hash = newest_rlib_hash(&deps)
        .ok_or_else(|| format!("no libdstu_core-*.rlib in {}", deps.display()))?;
    let asm = deps.join(format!("dstu_core-{hash}.s"));
    if asm.is_file() {
        Ok(asm)
    } else {
        Err(format!(
            "{} missing (built without --emit=asm?)",
            asm.display()
        ))
    }
}

fn newest_rlib_hash(deps: &Path) -> Option<String> {
    std::fs::read_dir(deps)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let hash = name
                .strip_prefix("libdstu_core-")?
                .strip_suffix(".rlib")?
                .to_owned();
            Some((e.metadata().ok()?.modified().ok()?, hash))
        })
        .max()
        .map(|(_, hash)| hash)
}

fn check_cell(asm: &str, target: &str, arch: Arch, opt: &str) -> Vec<String> {
    let functions = match parse(asm, arch) {
        Ok(functions) => functions,
        Err(e) => return vec![e],
    };
    let mut failures = Vec::new();
    // Fail closed across the whole crate, not only the audited symbols.
    for function in &functions {
        if let Err(e) = jumps(arch, function) {
            failures.push(e);
        }
    }
    let rows = ZERO_JUMPS
        .iter()
        .filter(|(t, o, _)| *t == target && *o == opt);
    for (_, _, spec) in rows {
        match row_jumps(arch, &functions, spec) {
            Ok(0) => {}
            Ok(found) => failures.push(format!("{spec}: {found} jumps, expected none")),
            Err(e) => failures.push(e),
        }
    }
    for function in &functions {
        if arch == Arch::Riscv32 && in_carry_scope(function) && carry_shapes(function) > 0 {
            failures.push(format!(
                "{}: riscv32 64-bit carry compare shape (D-226)",
                function.name
            ));
        }
        if mul_calls(function) > 0 {
            failures.push(format!("{}: __multi3/__muldi3 call (D-227)", function.name));
        }
    }
    failures
}

/// The carry shape also matches a public `RangeInclusive` step (`bgeu` + `sltu`, `kalyna_kw`), so
/// that rule covers every function of the limb-arithmetic modules and every outlined body, which
/// takes in what `limb` is inlined into (`invert`, `pow_mod`, `to_affine`, ...). The
/// `__multi3`/`__muldi3` rule has no such false match and covers the whole crate.
fn in_carry_scope(function: &Function) -> bool {
    function.is_outlined()
        || ["8dstu9041", "8dstu4145", "9gf2m_wide", "4limb"]
            .iter()
            .any(|module| function.name.contains(module))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arch {
    X86_64,
    Aarch64,
    Thumb,
    Riscv32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Conditional,
    Indirect,
    Plain,
    NotBranch,
}

#[derive(Debug)]
struct Insn<'a> {
    mnemonic: &'a str,
    operands: &'a str,
}

#[derive(Debug)]
struct Function<'a> {
    name: &'a str,
    insns: Vec<Insn<'a>>,
}

impl Function<'_> {
    fn is_outlined(&self) -> bool {
        self.name.starts_with("OUTLINED_FUNCTION_")
    }
}

/// `#` would also cut thumb/aarch64 immediates (`#8`), so each arch strips only its own comment.
fn strip_comment(arch: Arch, line: &str) -> &str {
    let marker = match arch {
        Arch::X86_64 | Arch::Riscv32 => "#",
        Arch::Aarch64 => "//",
        Arch::Thumb => "@",
    };
    line.split_once(marker).map_or(line, |(code, _)| code)
}

/// A body runs from its `.type`-declared label to the next `.Lfunc_end`, so local `.LBB` labels
/// and data between functions never start or end one.
fn parse(asm: &str, arch: Arch) -> Result<Vec<Function<'_>>, String> {
    let mut declared = std::collections::HashSet::new();
    let mut functions = Vec::new();
    let mut current: Option<Function> = None;
    for raw in asm.lines() {
        let line = strip_comment(arch, raw).trim();
        if let Some(rest) = line.strip_prefix(".type") {
            if let Some((name, "@function" | "%function")) = rest.trim().split_once(',') {
                declared.insert(name.trim());
            }
        } else if line.starts_with(".Lfunc_end") {
            functions.extend(current.take());
        } else if let Some(label) = line.strip_suffix(':') {
            if declared.contains(label) {
                if let Some(open) = &current {
                    return Err(format!(
                        "'{}' has no .Lfunc_end before '{label}'",
                        open.name
                    ));
                }
                current = Some(Function {
                    name: label,
                    insns: Vec::new(),
                });
            }
        } else if !line.is_empty() && !line.starts_with('.') {
            if let Some(function) = current.as_mut() {
                let (mnemonic, operands) =
                    line.split_once(char::is_whitespace).unwrap_or((line, ""));
                function.insns.push(Insn {
                    mnemonic,
                    operands: operands.trim(),
                });
            }
        }
    }
    match current {
        Some(open) => Err(format!("'{}' has no .Lfunc_end", open.name)),
        None => Ok(functions),
    }
}

const X86_CONDITIONS: [&str; 30] = [
    "o", "no", "b", "nb", "ae", "nae", "c", "nc", "e", "z", "ne", "nz", "be", "na", "a", "nbe",
    "s", "ns", "p", "pe", "np", "po", "l", "nge", "ge", "nl", "le", "ng", "g", "nle",
];
const ARM_CONDITIONS: [&str; 16] = [
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
];

/// Fails closed: a mnemonic that looks like a branch but is not listed here is an error, so a
/// new instruction form (a toolchain bump, a new target feature) cannot pass as a non-branch.
fn classify(arch: Arch, insn: &Insn, outlined: bool) -> Result<Kind, String> {
    let m = insn.mnemonic;
    let ops = insn.operands;
    let kind = match arch {
        Arch::X86_64 => match m {
            "jmp" | "jmpq" if ops.starts_with('*') && !ops.ends_with("@GOTPCREL(%rip)") => {
                Some(Kind::Indirect)
            }
            "jmp" | "jmpq" | "call" | "callq" | "ret" | "retq" => Some(Kind::Plain),
            "jrcxz" | "jecxz" | "loop" | "loope" | "loopne" => Some(Kind::Conditional),
            _ if m
                .strip_prefix('j')
                .is_some_and(|cc| X86_CONDITIONS.contains(&cc)) =>
            {
                Some(Kind::Conditional)
            }
            _ if m.starts_with('j') || m.starts_with("loop") => None,
            _ => Some(Kind::NotBranch),
        },
        Arch::Aarch64 => match m {
            "b" | "bl" | "blr" | "ret" => Some(Kind::Plain),
            "br" => Some(Kind::Indirect),
            "cbz" | "cbnz" | "tbz" | "tbnz" => Some(Kind::Conditional),
            "bic" | "bics" | "bfi" | "bfxil" | "bfm" | "bfc" | "bsl" | "bit" | "bif" | "tbl"
            | "tbx" => Some(Kind::NotBranch),
            _ if m
                .strip_prefix("b.")
                .is_some_and(|cc| ARM_CONDITIONS.contains(&cc)) =>
            {
                Some(Kind::Conditional)
            }
            _ if m.starts_with('b') || m.starts_with("cb") || m.starts_with("tb") => None,
            _ if m.starts_with("ret") => None,
            _ => Some(Kind::NotBranch),
        },
        Arch::Thumb => classify_thumb(m.trim_end_matches(".w").trim_end_matches(".n"), ops),
        Arch::Riscv32 => match m {
            "j" | "c.j" | "jal" | "c.jal" | "call" | "tail" | "ret" | "jalr" | "c.jalr" => {
                Some(Kind::Plain)
            }
            "jr" | "c.jr" if ops == "ra" || (outlined && ops == "t0") => Some(Kind::Plain),
            "jr" | "c.jr" => Some(Kind::Indirect),
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "beqz" | "bnez" | "blez" | "bgez"
            | "bltz" | "bgtz" | "bgt" | "ble" | "bgtu" | "bleu" | "c.beqz" | "c.bnez" => {
                Some(Kind::Conditional)
            }
            _ if m.starts_with('b') || m.starts_with('j') || m.starts_with("c.b") => None,
            _ if m.starts_with("c.j") => None,
            _ => Some(Kind::NotBranch),
        },
    };
    kind.ok_or_else(|| format!("unclassified branch-like instruction '{m} {ops}'"))
}

/// Condition suffixes are checked before `bl`, so `bls`/`blt`/`ble`/`blo` are `b` + condition.
/// Within an IT block the suffix is mandatory (UAL), so `bxne lr`/`popne {pc}` carry it.
fn classify_thumb(m: &str, ops: &str) -> Option<Kind> {
    let has_condition = |base: &str| {
        m.strip_prefix(base)
            .is_some_and(|cc| ARM_CONDITIONS.contains(&cc))
    };
    let writes_pc = ops == "pc"
        || ops.starts_with("pc,")
        || ops
            .split_once('{')
            .is_some_and(|(_, list)| list.split([',', '}']).any(|r| r.trim() == "pc"));
    match m {
        "b" | "bl" | "blx" => Some(Kind::Plain),
        "bx" if ops == "lr" => Some(Kind::Plain),
        "bx" | "tbb" | "tbh" => Some(Kind::Indirect),
        "cbz" | "cbnz" => Some(Kind::Conditional),
        "bic" | "bics" | "bfi" | "bfc" | "bkpt" => Some(Kind::NotBranch),
        _ if ["b", "bl", "blx", "bx"].iter().any(|b| has_condition(b)) => Some(Kind::Conditional),
        _ if m.starts_with('b') || m.starts_with("cb") || m.starts_with("tb") => None,
        _ if writes_pc
            && ["pop", "ldm", "ldr", "mov", "add"]
                .iter()
                .any(|b| has_condition(b)) =>
        {
            Some(Kind::Conditional)
        }
        "pop" | "ldm" if writes_pc => Some(Kind::Plain),
        _ if writes_pc => Some(Kind::Indirect),
        _ => Some(Kind::NotBranch),
    }
}

/// Conditional and indirect jumps both count: a jump table is data-dependent control flow too.
/// Calls do not: `callq *%rbx`/`blx r6` reuse a constant target held in a register.
fn jumps(arch: Arch, function: &Function) -> Result<u32, String> {
    let mut count = 0;
    for insn in &function.insns {
        let kind = classify(arch, insn, function.is_outlined())
            .map_err(|e| format!("{}: {e}", function.name))?;
        if matches!(kind, Kind::Conditional | Kind::Indirect) {
            count += 1;
        }
    }
    Ok(count)
}

/// D-226's riscv32 lowering of a 64-bit carry compare: a branch on two registers (the high
/// halves), then `sltu` on the same pair (the low-half compare), in either order.
fn carry_shapes(function: &Function) -> u32 {
    let registers =
        |ops: &str| -> Vec<String> { ops.split(',').map(|r| r.trim().to_owned()).collect() };
    let mut count = 0;
    for pair in function.insns.windows(2) {
        let [branch, next] = pair else { continue };
        let is_two_register_branch = matches!(
            branch.mnemonic,
            "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" | "bgt" | "ble" | "bgtu" | "bleu"
        );
        if !is_two_register_branch || next.mnemonic != "sltu" {
            continue;
        }
        let b = registers(branch.operands);
        let s = registers(next.operands);
        if b.len() == 3
            && s.len() == 3
            && ((b[0] == s[1] && b[1] == s[2]) || (b[0] == s[2] && b[1] == s[1]))
        {
            count += 1;
        }
    }
    count
}

fn mul_calls(function: &Function) -> u32 {
    let count = function
        .insns
        .iter()
        .filter(|i| i.operands.contains("__multi3") || i.operands.contains("__muldi3"))
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// A spec is `::`-separated idents, found in order as v0 length-prefixed idents (`5fp256`), the
/// last one ending the symbol. No demangler (owner, T-292), and no digit-boundary rule either:
/// `8dstu90415fp256` shows an ident can end in a digit. A false match is caught by
/// [`find_one`]'s exactly-once rule.
fn symbol_matches(name: &str, spec: &str) -> bool {
    let segments: Vec<&str> = spec.split("::").collect();
    let mut from = 0;
    for (i, segment) in segments.iter().enumerate() {
        let token = format!("{}{segment}", segment.len());
        let found = if i + 1 == segments.len() {
            name[from..]
                .ends_with(&token)
                .then(|| name.len() - token.len())
        } else {
            name[from..].find(&token).map(|at| from + at)
        };
        match found {
            Some(at) => from = at + token.len(),
            None => return false,
        }
    }
    true
}

fn find_one<'f, 'a>(functions: &'f [Function<'a>], spec: &str) -> Result<&'f Function<'a>, String> {
    let mut matches = functions.iter().filter(|f| symbol_matches(f.name, spec));
    match (matches.next(), matches.count()) {
        (Some(function), 0) => Ok(function),
        (Some(_), more) => Err(format!("'{spec}' matches {} symbols", more + 1)),
        (None, _) => Err(format!(
            "'{spec}': no symbol (inlined or renamed? re-read the asm)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        carry_shapes, classify, find_one, in_carry_scope, jumps, mul_calls, parse, symbol_matches,
        Arch, Function, Insn, Kind,
    };

    fn kind(arch: Arch, line: &str) -> Kind {
        kind_in(arch, line, false)
    }

    fn kind_in(arch: Arch, line: &str, outlined: bool) -> Kind {
        let (mnemonic, operands) = line.split_once('\t').unwrap_or((line, ""));
        classify(arch, &Insn { mnemonic, operands }, outlined).unwrap()
    }

    fn unknown(arch: Arch, line: &str) -> bool {
        let (mnemonic, operands) = line.split_once('\t').unwrap_or((line, ""));
        classify(arch, &Insn { mnemonic, operands }, false).is_err()
    }

    const RISCV: &str = "\t.type\tfoo,@function\n\
        foo:\n\
        \taddi\ta0, a0, 1 # comment with beq in it\n\
        .LBB0_1:\n\
        \tbeq\ta1, a2, .LBB0_3\n\
        \tsltu\ta0, a1, a2\n\
        \tbeq\ta3, a4, .LBB0_3\n\
        \tsltu\ta0, a4, a3\n\
        \tbne\ta5, a6, .LBB0_1\n\
        \tsltu\ta0, a5, a7\n\
        \tcall\t__multi3\n\
        \tret\n\
        .Lfunc_end0:\n\
        \t.type\tbar,@function\n\
        bar:\n\
        \tj\t.LBB1_1\n\
        \ttail\t__muldi3\n\
        .Lfunc_end1:\n\
        \t.type\tOUTLINED_FUNCTION_0,@function\n\
        OUTLINED_FUNCTION_0:\n\
        \tjr\tt0\n\
        .Lfunc_end2:\n";

    #[test]
    fn parse_splits_at_type_labels_and_func_end() {
        let fns = parse(RISCV, Arch::Riscv32).unwrap();
        let names: Vec<_> = fns.iter().map(|f| f.name).collect();
        assert_eq!(names, ["foo", "bar", "OUTLINED_FUNCTION_0"]);
        assert_eq!(fns[0].insns.len(), 9);
        assert_eq!(fns[0].insns[0].operands, "a0, a0, 1");
    }

    #[test]
    fn parse_rejects_an_unterminated_function() {
        let asm = "\t.type\tfoo,@function\nfoo:\n\tret\n\t.type\tbar,@function\nbar:\n\tret\n";
        assert!(parse(asm, Arch::Riscv32).is_err());
    }

    #[test]
    fn parse_strips_each_arch_comment_but_not_immediates() {
        let thumb = "\t.type\tf,%function\nf:\n\tadds\tr0, #8 @ bne here\n.Lfunc_end0:\n";
        assert_eq!(
            parse(thumb, Arch::Thumb).unwrap()[0].insns[0].operands,
            "r0, #8"
        );
        let a64 = "\t.type\tf,@function\nf:\n\tadd\tx0, x0, #8 // b.ne\n.Lfunc_end0:\n";
        assert_eq!(
            parse(a64, Arch::Aarch64).unwrap()[0].insns[0].operands,
            "x0, x0, #8"
        );
    }

    #[test]
    fn riscv_counts_every_b_form_and_register_jumps() {
        for line in [
            "beq\ta0, a1, .L",
            "bnez\ta0, .L",
            "blez\ta0, .L",
            "bgtz\ta0, .L",
            "bltu\ta0, a1, .L",
            "c.beqz\ta0, .L",
        ] {
            assert_eq!(kind(Arch::Riscv32, line), Kind::Conditional, "{line}");
        }
        for line in [
            "j\t.L",
            "call\tfoo",
            "call\tt0, OUTLINED_FUNCTION_1",
            "tail\tfoo",
            "ret",
            "jr\tra",
            "jalr\ts3",
        ] {
            assert_eq!(kind(Arch::Riscv32, line), Kind::Plain, "{line}");
        }
        assert_eq!(kind(Arch::Riscv32, "jr\ta5"), Kind::Indirect);
        assert_eq!(kind(Arch::Riscv32, "jr\tt0"), Kind::Indirect);
        assert_eq!(kind_in(Arch::Riscv32, "jr\tt0", true), Kind::Plain);
        assert_eq!(kind(Arch::Riscv32, "sltu\ta0, a1, a2"), Kind::NotBranch);
        assert!(unknown(Arch::Riscv32, "bset\ta0, a0, a1"));
        assert!(unknown(Arch::Riscv32, "jx\ta0"));
    }

    #[test]
    fn thumb_separates_conditions_from_link_and_bit_ops() {
        for line in [
            "bne\t.L",
            "bls.w\t.L",
            "blt\t.L",
            "ble\t.L",
            "blo\t.L",
            "bcc\t.L",
            "cbz\tr0, .L",
            "bleq\tfoo",
            "blxne\tr3",
            "bxne\tlr",
            "bxlo\tr3",
            "popne\t{r4, pc}",
            "popeq.w\t{r4, r5, pc}",
            "ldmne\tsp!, {r4, pc}",
        ] {
            assert_eq!(kind(Arch::Thumb, line), Kind::Conditional, "{line}");
        }
        for line in [
            "b\t.L",
            "b.w\t.L",
            "bl\tfoo",
            "blx\tr3",
            "bx\tlr",
            "pop\t{r4, pc}",
            "pop.w\t{r4, r5, r6, pc}",
        ] {
            assert_eq!(kind(Arch::Thumb, line), Kind::Plain, "{line}");
        }
        for line in [
            "tbb\t[pc, r1]",
            "tbh\t[pc, r1, lsl #1]",
            "bx\tr3",
            "ldr\tpc, [r0]",
            "mov\tpc, r2",
        ] {
            assert_eq!(kind(Arch::Thumb, line), Kind::Indirect, "{line}");
        }
        for line in [
            "bic\tr0, r1",
            "bic.w\tr0, r1, #3",
            "bics\tr0, r1",
            "bfi\tr0, r1, #0, #8",
            "pop\t{r4, r5}",
            "ldm.w\tr0, {r1, r2}",
            "ldr\tr0, [pc, #4]",
        ] {
            assert_eq!(kind(Arch::Thumb, line), Kind::NotBranch, "{line}");
        }
        assert!(unknown(Arch::Thumb, "bxj\tr0"));
    }

    #[test]
    fn aarch64_separates_branches_from_neon_and_bit_ops() {
        for line in ["b.ne\t.L", "b.hs\t.L", "cbz\tx0, .L", "tbnz\tw0, #3, .L"] {
            assert_eq!(kind(Arch::Aarch64, line), Kind::Conditional, "{line}");
        }
        for line in ["b\t.L", "bl\tfoo", "blr\tx9", "ret"] {
            assert_eq!(kind(Arch::Aarch64, line), Kind::Plain, "{line}");
        }
        assert_eq!(kind(Arch::Aarch64, "br\tx3"), Kind::Indirect);
        for line in [
            "bic\tx0, x1, x2",
            "bfxil\tx0, x1, #0, #8",
            "tbl\tv0.16b, {v1.16b}, v2.16b",
        ] {
            assert_eq!(kind(Arch::Aarch64, line), Kind::NotBranch, "{line}");
        }
        assert!(unknown(Arch::Aarch64, "braa\tx0, x1"));
    }

    #[test]
    fn x86_64_separates_indirect_jumps_from_calls() {
        for line in ["jae\t.L", "jne\t.L", "js\t.L", "jrcxz\t.L"] {
            assert_eq!(kind(Arch::X86_64, line), Kind::Conditional, "{line}");
        }
        for line in [
            "jmp\t.L",
            "callq\tfoo",
            "callq\t*%rbx",
            "jmpq\t*memcpy@GOTPCREL(%rip)",
            "retq",
        ] {
            assert_eq!(kind(Arch::X86_64, line), Kind::Plain, "{line}");
        }
        assert_eq!(kind(Arch::X86_64, "jmpq\t*%rax"), Kind::Indirect);
        assert_eq!(kind(Arch::X86_64, "btq\t%rcx, %rbp"), Kind::NotBranch);
        assert!(unknown(Arch::X86_64, "jfoo\t.L"));
    }

    #[test]
    fn jumps_count_conditional_and_indirect_only() {
        let fns = parse(RISCV, Arch::Riscv32).unwrap();
        assert_eq!(jumps(Arch::Riscv32, &fns[0]).unwrap(), 3);
        assert_eq!(jumps(Arch::Riscv32, &fns[1]).unwrap(), 0);
        assert_eq!(jumps(Arch::Riscv32, &fns[2]).unwrap(), 0);
    }

    #[test]
    fn carry_shape_is_a_register_compare_branch_then_sltu_on_the_same_pair() {
        let fns = parse(RISCV, Arch::Riscv32).unwrap();
        // Same pair, either order; `bne a5, a6` + `sltu a0, a5, a7` is not the shape.
        assert_eq!(carry_shapes(&fns[0]), 2);
        assert_eq!(carry_shapes(&fns[1]), 0);
    }

    #[test]
    fn carry_scope_is_the_limb_modules_and_outlined_bodies_only() {
        let named = |name| Function {
            name,
            insns: Vec::new(),
        };
        assert!(in_carry_scope(&named(FP_ADD)));
        assert!(in_carry_scope(&named(
            "_RNvNtNtC9dstu_core6hazmat4limb3mac"
        )));
        assert!(in_carry_scope(&named("OUTLINED_FUNCTION_7")));
        let kw = "_RNvMNtNtC9dstu_core6hazmat9kalyna_kwNtB5_15Kalyna128_128Kw16wrap_with_cipher";
        assert!(!in_carry_scope(&named(kw)));
    }

    #[test]
    fn mul_calls_find_multi3_and_muldi3() {
        let fns = parse(RISCV, Arch::Riscv32).unwrap();
        assert_eq!(mul_calls(&fns[0]), 1);
        assert_eq!(mul_calls(&fns[1]), 1);
        assert_eq!(mul_calls(&fns[2]), 0);
    }

    const FP_ADD: &str =
        "_RNvMNtNtNtCs8uJ8nHuXZ6v_9dstu_core6hazmat8dstu90415fp256NtB2_12FieldElement3add";
    const POINT_ADD: &str = "_RNvXs_NtNtNtCs8uJ8nHuXZ6v_9dstu_core6hazmat8dstu41458curve163NtB4_\
        5PointNtNtNtCs57AslucmIUK_4core3ops5arith3Add3add";
    const PROJ_ADD: &str =
        "_RNvMs_NtNtNtCs8uJ8nHuXZ6v_9dstu_core6hazmat8dstu90418curve256NtB4_15ProjectivePoint3add";

    #[test]
    fn symbol_spec_matches_ordered_length_prefixed_idents() {
        assert!(symbol_matches(FP_ADD, "fp256::FieldElement::add"));
        assert!(!symbol_matches(FP_ADD, "fp512::FieldElement::add"));
        assert!(!symbol_matches(FP_ADD, "FieldElement::fp256::add"));
        assert!(symbol_matches(POINT_ADD, "curve163::Point::Add::add"));
        assert!(!symbol_matches(PROJ_ADD, "curve256::Point::add"));
        assert!(symbol_matches(PROJ_ADD, "curve256::ProjectivePoint::add"));
    }

    #[test]
    fn symbol_spec_needs_the_last_ident_at_the_end() {
        assert!(!symbol_matches(FP_ADD, "fp256::FieldElement"));
        assert!(!symbol_matches(PROJ_ADD, "curve256::ProjectivePoint::ad"));
    }

    #[test]
    fn symbol_spec_does_not_match_a_longer_module_name() {
        let name = "_RNvNtNtC9dstu_core6hazmat9scalar2578multiply";
        assert!(!symbol_matches(name, "scalar::multiply"));
        assert!(symbol_matches(name, "scalar257::multiply"));
    }

    #[test]
    fn find_one_rejects_a_missing_or_ambiguous_symbol() {
        // A length prefix can end inside another number (`16scalarxxxxxxxxxx` holds `6scalar`),
        // so a spec can match a wrong symbol; exactly-once turns that into an error.
        let asm = "\t.type\t_RNv6scalar8multiply,@function\n_RNv6scalar8multiply:\n\tret\n\
            .Lfunc_end0:\n\t.type\t_RNv16scalarxxxxxxxxxx8multiply,@function\n\
            _RNv16scalarxxxxxxxxxx8multiply:\n\tret\n.Lfunc_end1:\n";
        let fns = parse(asm, Arch::Riscv32).unwrap();
        assert!(find_one(&fns, "scalar::multiply")
            .unwrap_err()
            .contains("2 symbols"));
        assert!(find_one(&fns, "scalar::add")
            .unwrap_err()
            .contains("no symbol"));
        assert_eq!(
            find_one(&fns[..1], "scalar::multiply").unwrap().name,
            fns[0].name
        );
    }
}
