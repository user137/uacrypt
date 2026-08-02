//! Shared Python exception type for this extension - `docs/cross-language-style-guide.md`'s
//! "errors are an explicit, typed result" principle, Python form (a custom `Exception` subclass).
//! One exception type across every `crypto_*` wrapper, not one per module: every failure raised
//! here already carries a specific message from the wrapped `dstu_core` error type's own
//! `Display` impl, so a caller who needs to distinguish cases matches on that message - the same
//! shape `RuntimeError`/`ValueError` already have in the stdlib rather than a bespoke class per
//! function.

use pyo3::create_exception;
use pyo3::exceptions::PyException;

create_exception!(
    _dstu_core,
    DstuError,
    PyException,
    "Raised for any dstu_core crypto operation failure (authentication/tamper rejection, OS \
     CSPRNG failure, malformed input, etc.) - see the raised message for the specific cause."
);
