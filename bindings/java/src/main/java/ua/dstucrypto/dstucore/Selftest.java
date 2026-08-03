package ua.dstucrypto.dstucore;

/**
 * Re-runs dstu_core's official-vector self-check against this exact compiled native build.
 */
public final class Selftest {
    static {
        NativeLoader.ensureLoaded();
    }

    private Selftest() {
    }

    /**
     * Throws {@link DstuException} naming which primitive(s) failed, if any.
     */
    public static native void run();
}
