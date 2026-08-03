// Package dstu is a Go binding for dstu-core (Ukrainian DSTU cryptographic standards - Kalyna,
// Kupyna, Strumok, DSTU 4145), via cgo over crates/dstu-core-capi's C ABI (T-158).
//
// Pre-release and provisional - see docs/SECURITY.md and docs/DECISIONS.md in the project
// repository for the full threat model and per-construction status.
package dstu

// #cgo CFLAGS: -I${SRCDIR}/../../../crates/dstu-core-capi/include
// #cgo LDFLAGS: -L${SRCDIR}/../../../target/release
// #cgo windows LDFLAGS: -Wl,-Bstatic -ldstu_core_capi -Wl,-Bdynamic -lws2_32 -luserenv -lntdll
// #cgo linux LDFLAGS: -Wl,-Bstatic -ldstu_core_capi -Wl,-Bdynamic -lpthread -ldl -lm
// #cgo darwin LDFLAGS: -ldstu_core_capi
// #include "dstu_core.h"
import "C"

// Selftest re-verifies one official test vector per primitive (Kalyna, Kupyna, Strumok,
// DSTU 4145) against the live compiled build. Returns an error if any check fails.
func Selftest() error {
	return statusError(C.dstu_selftest())
}
