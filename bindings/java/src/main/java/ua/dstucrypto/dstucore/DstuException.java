package ua.dstucrypto.dstucore;

/**
 * Raised for any dstu_core crypto operation failure (authentication/tamper rejection, OS CSPRNG
 * failure, malformed input, etc.) - see the message for the specific cause. Unchecked, matching
 * the rest of this project's bindings (Python's {@code DstuError}, C#'s {@code DstuException}):
 * a caller who wants to distinguish cases matches on the message, not a bespoke subclass per
 * failure kind.
 */
public final class DstuException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public DstuException(String message) {
        super(message);
    }
}
