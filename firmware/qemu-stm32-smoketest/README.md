# qemu-stm32-smoketest

Runs `dstu-core`'s `no_std`/no-`alloc` build on a QEMU-emulated STM32 (Cortex-M4F, the
`netduinoplus2` machine) and checks the exact official Kalyna-128/128 and Kupyna-256 DSTU vectors
already used by the host test suite. See `docs/DECISIONS.md` D-156 for why this board and no
others (ESP32 has no real board in mainline QEMU - see D-156 for the full survey).

**Not real-hardware validation** - see `docs/TASKS.md` T-55/T-56 (still open) and `CLAUDE.md`'s
Phase 4 notes. This only proves the emulated instruction semantics produce the right bytes, not
real silicon timing or side-channel behavior.

## Run it

Requires `qemu-system-arm` (Debian/Ubuntu: `apt install qemu-system-arm qemu-system-misc`) and the
`thumbv7em-none-eabihf` target (`rustup target add thumbv7em-none-eabihf`).

```
cargo xtask qemu-stm32
```

or directly from this directory: `cargo run --release`. Exit code 0 = both vectors passed; nonzero
= a real mismatch (see the printed `PASS:`/`FAIL:` semihosting output).
