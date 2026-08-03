package dstu

// #include "dstu_core.h"
import "C"

import "fmt"

// Error is returned for any DstuStatus other than DSTU_OK.
type Error struct {
	Code C.DstuStatus
}

func (e *Error) Error() string {
	return fmt.Sprintf("dstu: status %d", int(e.Code))
}

func statusError(status C.DstuStatus) error {
	return &Error{Code: status}
}
