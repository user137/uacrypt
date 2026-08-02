#![cfg(feature = "selftest")]

use dstu_core::selftest;

/// `docs/TASKS.md` T-161 / `docs/DECISIONS.md` D-117: `run()` re-checks the live compiled build
/// against the same official vectors this crate's own oracle-verified test suite already uses.
/// Written before `dstu_core::selftest` existed - test-first, per this project's standing rule.
#[test]
fn run_reports_success_on_the_real_build() {
    let result = selftest::run();
    assert!(
        result.is_ok(),
        "selftest::run() must pass against this crate's own compiled implementation, got {:?}",
        result.err()
    );
}
