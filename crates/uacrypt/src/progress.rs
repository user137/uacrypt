//! The progress line on stderr for a long `--in` read (T-261, `docs/DECISIONS.md` D-218). Shown
//! only when stderr is a terminal and the input is large; no flag, never a failure of the command.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// Inputs smaller than this never show a line; stdin shows its byte counter once this much is read.
pub(crate) const THRESHOLD: u64 = 64 * 1024 * 1024;

/// At most 10 redraws a second.
const REDRAW_EVERY: Duration = Duration::from_millis(100);

/// Wraps `inner` so reading it draws a progress line on stderr, when [`wanted`]; otherwise returns
/// `inner` unchanged, so a piped stderr costs nothing and gets nothing.
pub(crate) fn wrap(inner: Box<dyn Read>, total: Option<u64>) -> Box<dyn Read> {
    use std::io::IsTerminal;
    if !wanted(std::io::stderr().is_terminal(), total) {
        return inner;
    }
    Box::new(ProgressReader {
        inner,
        progress: Progress::new(std::io::stderr(), total),
    })
}

/// `total` is the input's size when known (a regular file), `None` for stdin or a pipe.
fn wanted(stderr_is_terminal: bool, total: Option<u64>) -> bool {
    stderr_is_terminal && total.is_none_or(|total| total >= THRESHOLD)
}

struct ProgressReader<R, W: Write> {
    inner: R,
    progress: Progress<W>,
}

impl<R: Read, W: Write> Read for ProgressReader<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.progress
            .advance(u64::try_from(n).unwrap_or(u64::MAX), Instant::now());
        Ok(n)
    }
}

/// The line itself; [`Drop`] clears it, so it is gone before the command prints anything else -
/// its result, or its error.
struct Progress<W: Write> {
    sink: W,
    total: Option<u64>,
    done: u64,
    last_draw: Option<Instant>,
    /// Columns of the widest line drawn so far; 0 = nothing on screen.
    width: usize,
}

impl<W: Write> Progress<W> {
    fn new(sink: W, total: Option<u64>) -> Self {
        Self {
            sink,
            total,
            done: 0,
            last_draw: None,
            width: 0,
        }
    }

    fn advance(&mut self, n: u64, now: Instant) {
        self.done = self.done.saturating_add(n);
        if self.total.is_none() && self.done < THRESHOLD {
            return;
        }
        if self
            .last_draw
            .is_some_and(|last| now.saturating_duration_since(last) < REDRAW_EVERY)
        {
            return;
        }
        self.last_draw = Some(now);
        let line = line(self.done, self.total);
        let pad = self.width.saturating_sub(line.len());
        self.width = self.width.max(line.len());
        self.draw(&format!("\r{line}{:pad$}", ""));
    }

    fn clear(&mut self) {
        if self.width > 0 {
            let width = self.width;
            self.width = 0;
            self.draw(&format!("\r{:width$}\r", ""));
        }
    }

    /// One write per redraw; a failing stderr is ignored - progress never fails the command.
    fn draw(&mut self, text: &str) {
        let _ = self.sink.write_all(text.as_bytes());
        let _ = self.sink.flush();
    }
}

impl<W: Write> Drop for Progress<W> {
    fn drop(&mut self) {
        self.clear();
    }
}

fn line(done: u64, total: Option<u64>) -> String {
    match total {
        Some(total) => {
            let percent = (u128::from(done.min(total)) * 100)
                .checked_div(u128::from(total))
                .unwrap_or(100);
            format!("uacrypt: {} / {} ({percent}%)", size(done), size(total))
        }
        None => format!("uacrypt: {} read", size(done)),
    }
}

/// Binary units with one decimal, truncated (never shows more than was read).
fn size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut unit: u64 = 1024;
    let mut i = 0;
    while i + 1 < UNITS.len() && bytes / unit >= 1024 {
        unit *= 1024;
        i += 1;
    }
    let tenths = u128::from(bytes) * 10 / u128::from(unit);
    format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn text(sink: &[u8]) -> String {
        String::from_utf8(sink.to_vec()).unwrap()
    }

    #[test]
    fn shown_only_on_a_terminal_and_for_a_large_or_unknown_input() {
        assert!(wanted(true, Some(THRESHOLD)));
        assert!(wanted(true, None));
        assert!(!wanted(true, Some(THRESHOLD - 1)));
        assert!(!wanted(true, Some(0)));
        assert!(!wanted(false, Some(THRESHOLD)));
        assert!(!wanted(false, None));
    }

    #[test]
    fn sizes_read_in_binary_units() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1024), "1.0 KiB");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(64 * MIB), "64.0 MiB");
        assert_eq!(size(1024 * MIB - 1), "1023.9 MiB");
        assert_eq!(size(1024 * MIB), "1.0 GiB");
        assert_eq!(size(1024 * 1024 * MIB), "1.0 TiB");
        assert_eq!(size(u64::MAX), "16777215.9 TiB");
    }

    #[test]
    fn line_shows_percent_for_a_known_size_and_a_counter_otherwise() {
        assert_eq!(
            line(100 * MIB, Some(400 * MIB)),
            "uacrypt: 100.0 MiB / 400.0 MiB (25%)"
        );
        assert_eq!(line(100 * MIB, None), "uacrypt: 100.0 MiB read");
    }

    #[test]
    fn percent_is_clamped_when_the_file_grows_while_read() {
        assert_eq!(
            line(500 * MIB, Some(400 * MIB)),
            "uacrypt: 500.0 MiB / 400.0 MiB (100%)"
        );
        assert!(line(u64::MAX, Some(u64::MAX)).ends_with("(100%)"));
        assert_eq!(line(0, Some(0)), "uacrypt: 0 B / 0 B (100%)");
    }

    #[test]
    fn line_fits_a_narrow_terminal() {
        let widest = line(1024 * 1024 * MIB - 1, Some(1024 * 1024 * MIB - 1));
        assert!(widest.len() <= 40, "{widest}");
    }

    #[test]
    fn known_size_draws_at_once_and_clears_on_drop() {
        let mut sink = Vec::new();
        let start = Instant::now();
        {
            let mut p = Progress::new(&mut sink, Some(400 * MIB));
            p.advance(100 * MIB, start);
        }
        let drawn = "\ruacrypt: 100.0 MiB / 400.0 MiB (25%)";
        let cleared = format!("\r{}\r", " ".repeat(drawn.len() - 1));
        assert_eq!(text(&sink), format!("{drawn}{cleared}"));
    }

    #[test]
    fn stdin_counter_waits_for_the_threshold() {
        let mut sink = Vec::new();
        let start = Instant::now();
        {
            let mut p = Progress::new(&mut sink, None);
            p.advance(THRESHOLD - 1, start);
            assert_eq!(p.width, 0);
            p.advance(1, start + REDRAW_EVERY);
        }
        assert!(text(&sink).starts_with("\ruacrypt: 64.0 MiB read"));
    }

    #[test]
    fn nothing_drawn_means_nothing_cleared() {
        let mut sink = Vec::new();
        {
            let mut p = Progress::new(&mut sink, None);
            p.advance(MIB, Instant::now());
        }
        assert!(sink.is_empty());
    }

    #[test]
    fn at_most_ten_redraws_a_second() {
        let mut sink = Vec::new();
        let start = Instant::now();
        {
            let mut p = Progress::new(&mut sink, Some(THRESHOLD));
            for ms in 0..1000 {
                p.advance(1, start + Duration::from_millis(ms));
            }
        }
        let redraws = text(&sink).matches("uacrypt:").count();
        assert_eq!(redraws, 10);
    }

    #[test]
    fn redraw_within_the_interval_is_skipped() {
        let mut sink = Vec::new();
        let start = Instant::now();
        let mut p = Progress::new(&mut sink, Some(THRESHOLD));
        p.advance(1, start);
        p.advance(
            1,
            (start + REDRAW_EVERY)
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        );
        p.advance(1, start + REDRAW_EVERY);
        drop(p);
        assert_eq!(text(&sink).matches("uacrypt:").count(), 2);
    }

    #[test]
    fn a_shorter_line_overwrites_the_longer_one_fully() {
        let mut sink = Vec::new();
        let start = Instant::now();
        {
            let mut p = Progress::new(&mut sink, None);
            p.advance(1024 * MIB - 1, start); // "1023.9 MiB read"
            p.advance(1, start + REDRAW_EVERY); // "1.0 GiB read", 3 columns shorter
        }
        let out = text(&sink);
        assert!(out.contains("\ruacrypt: 1.0 GiB read   \r"), "{out:?}");
        let widest = "uacrypt: 1023.9 MiB read".len();
        assert!(
            out.ends_with(&format!("\r{}\r", " ".repeat(widest))),
            "{out:?}"
        );
    }

    struct FailingSink;

    impl Write for FailingSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("stderr closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("stderr closed"))
        }
    }

    #[test]
    fn a_failing_stderr_never_fails_the_read() {
        let data = vec![7u8; 3000];
        let mut reader = ProgressReader {
            inner: data.as_slice(),
            progress: Progress::new(FailingSink, Some(0)),
        };
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn reader_passes_bytes_through_and_counts_them() {
        let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let mut sink = Vec::new();
        let mut reader = ProgressReader {
            inner: data.as_slice(),
            progress: Progress::new(&mut sink, None),
        };
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
        assert_eq!(reader.progress.done, 10_000);
    }

    struct BrokenInput;

    impl Read for BrokenInput {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk gone"))
        }
    }

    #[test]
    fn read_errors_pass_through_and_the_line_is_still_cleared() {
        let mut sink = Vec::new();
        {
            let mut progress = Progress::new(&mut sink, Some(THRESHOLD));
            progress.advance(1, Instant::now());
            let mut reader = ProgressReader {
                inner: BrokenInput,
                progress,
            };
            let err = reader.read(&mut [0u8; 16]).unwrap_err();
            assert_eq!(err.to_string(), "disk gone");
        }
        assert!(text(&sink).ends_with('\r'));
    }
}
