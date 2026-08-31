/* T-216 part 2: CI-only regression backstop for the double-free UB contract documented on every
 * dstu_*_free function (docs/DECISIONS.md, include/dstu_core.h). This is NOT part of the normal
 * `test_capi.c` harness on purpose: a deliberate double-free is genuinely undefined behavior, and
 * under AddressSanitizer specifically it aborts the process with a nonzero exit rather than
 * returning cleanly - that doesn't fit test_capi.c's CHECK()/failures-counter shape, and linking
 * this into the same main() would break the existing `capi` CI job (which runs on all three OSes,
 * none of which build this crate's C harness with ASan).
 *
 * Expected result when built with -fsanitize=address and run: the process aborts with an
 * AddressSanitizer error and a nonzero exit code - that IS success for this program; a clean exit 0
 * means ASan failed to catch a real double-free and is the actual test failure. The specific
 * diagnostic ASan emits is NOT guaranteed to say "double-free": the second dstu_auth_key_free's
 * Box::from_raw re-drops the (already-dropped) key, whose Drop impl writes zeroize() bytes into
 * now-freed memory - ASan reports that as heap-use-after-free before the call ever reaches the
 * allocator's free(). Either diagnostic (or a literal double-free one, if the zeroize-on-drop write
 * doesn't happen to touch a poisoned page first) is a correct catch of this same underlying misuse -
 * see the CI job's own grep for the exact set of diagnostics treated as success.
 * Never build/run this without ASan - without it, a double-free's behavior is simply undefined
 * (silent heap corruption, a crash somewhere unrelated, or no visible symptom at all), which proves
 * nothing either way. See `.github/workflows/rust.yml`'s `capi-double-free-asan` job (Linux-only)
 * for the actual invocation - this file is not compiled by `cargo xtask capi`.
 */

#include "dstu_core.h"

#include <stdio.h>

int main(void) {
  DstuAuthKey *key = NULL;
  if (dstu_auth_key_generate(&key) != DSTU_OK) {
    fprintf(stderr, "setup failed: dstu_auth_key_generate\n");
    return 2; /* a setup failure, not evidence about the double-free contract either way */
  }

  dstu_auth_key_free(key);
  dstu_auth_key_free(key); /* deliberate double-free - ASan must abort the process here */

  fprintf(stderr, "UNEXPECTED: double-free was not caught - ASan is not working as intended\n");
  return 0;
}
