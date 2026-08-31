using Xunit;

// MemoryLeakTests' Linux-only VmRSS-delta assertion (T-213) measures process-wide memory growth
// around its own loop - it has no way to distinguish its own growth from unrelated concurrent
// activity elsewhere in the process. xUnit parallelizes different test classes by default (up to
// processor-count threads), and this project later added ThreadSafetyTests/GcStressTests (T-218/
// T-219), both real multi-threaded CPU/allocation churn (Parallel.For across up to 16 workers,
// repeated blocking GC.Collect passes) - exactly the kind of concurrent noise the class's own doc
// comment already flagged VmRSS as too sensitive to ("GC/JIT/working-set churn dominates the
// actual, small, per-handle leak signal"). Confirmed empirically: adding those two test classes
// made MemoryLeakTests fail in CI (Linux only, where it actually runs) with 64MB "growth" against
// an 8MB threshold - not a real leak, real cross-test contamination from parallel execution.
// Disabling parallelization here (this test suite runs in well under a minute either way) removes
// the whole failure class rather than just re-tuning a threshold around today's noise level.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
