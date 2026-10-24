//! `uacrypt man` (T-264, `docs/DECISIONS.md` D-257): the `uacrypt(1)` page in roff, built from
//! [`super::TOP_LEVEL_HELP`] and every [`super::COMMANDS`] entry's `--help` text, so it says
//! exactly what `--help` says; the [`super::HAZMAT_COMMANDS`] get a section of their own (T-317).
//! Deterministic: no date, only the crate version.

use super::{
    is_help_flag, print_command_help, write_stdout, CliError, COMMANDS, HAZMAT_COMMANDS,
    TOP_LEVEL_HELP,
};
use core::fmt::Write as _;

/// `uacrypt man`: prints the page.
///
/// # Errors
///
/// [`CliError::UnexpectedArgument`] for any argument other than `--help`, [`CliError::Io`] if
/// stdout fails.
pub(crate) fn run_man_command(rest: &[String]) -> Result<(), CliError> {
    if rest.iter().any(|a| is_help_flag(a)) {
        print_command_help("man");
        return Ok(());
    }
    if let Some(extra) = rest.first() {
        return Err(CliError::UnexpectedArgument(extra.clone()));
    }
    write_stdout(&page())
}

/// Escapes help text for roff no-fill mode: `\` as `\e`, `-` as `\-` (a minus, so flags copy
/// and paste), any non-ASCII character as `\[uXXXX]`, and a line starting with `.` or `'` (a
/// request otherwise) behind `\&`.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    for line in text.lines() {
        if line.starts_with(['.', '\'']) {
            out.push_str("\\&");
        }
        for ch in line.chars() {
            match ch {
                '\\' => out.push_str("\\e"),
                '-' => out.push_str("\\-"),
                c if c.is_ascii() => out.push(c),
                c => {
                    let _ = write!(out, "\\[u{:04X}]", u32::from(c));
                }
            }
        }
        out.push('\n');
    }
    out
}

pub(crate) fn page() -> String {
    let (title, overview) = TOP_LEVEL_HELP
        .split_once('\n')
        .unwrap_or((TOP_LEVEL_HELP, ""));
    let summary = title.strip_prefix("uacrypt - ").unwrap_or(title);
    let mut s = format!(
        ".TH UACRYPT 1 \"\" \"uacrypt {}\" \"User Commands\"\n.SH NAME\nuacrypt \\- {}",
        env!("CARGO_PKG_VERSION"),
        escape(summary)
    );
    s.push_str(".SH DESCRIPTION\n.nf\n");
    s.push_str(&escape(overview.trim_start_matches('\n')));
    s.push_str(".fi\n.SH COMMANDS\n");
    for c in COMMANDS {
        let _ = write!(
            s,
            ".SS {}\n.nf\n{}.fi\n",
            escape(c.name).trim_end(),
            escape(c.help)
        );
    }
    s.push_str(".SH LOW-LEVEL COMMANDS (uacrypt hazmat)\n");
    for c in HAZMAT_COMMANDS {
        let _ = write!(
            s,
            ".SS hazmat {}\n.nf\n{}.fi\n",
            escape(c.name).trim_end(),
            escape(c.help)
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{escape, page};
    use crate::{COMMANDS, HAZMAT_COMMANDS};

    #[test]
    fn page_has_a_title_and_one_section_per_command() {
        let text = page();
        assert!(text.starts_with(".TH UACRYPT 1 \"\" \"uacrypt "));
        assert!(text.contains("\n.SH NAME\nuacrypt \\- a CLI over dstu\\-core"));
        let sections: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix(".SS "))
            .collect();
        let names: Vec<String> = COMMANDS
            .iter()
            .map(|c| c.name.replace('-', "\\-"))
            .chain(
                HAZMAT_COMMANDS
                    .iter()
                    .map(|c| format!("hazmat {}", c.name.replace('-', "\\-"))),
            )
            .collect();
        assert_eq!(sections, names);
        let (everyday, hazmat) = text
            .split_once("\n.SH LOW-LEVEL COMMANDS (uacrypt hazmat)\n")
            .expect("hazmat section");
        for c in HAZMAT_COMMANDS {
            let name = c.name.replace('-', "\\-");
            assert!(!everyday.contains(&format!(".SS {name}\n")), "{name}");
            assert!(hazmat.contains(&format!(".SS hazmat {name}\n")), "{name}");
        }
    }

    #[test]
    fn only_the_page_s_own_requests_start_a_line_with_a_dot_or_quote() {
        let requests = [".TH ", ".SH ", ".SS ", ".nf", ".fi"];
        for line in page().lines() {
            assert!(!line.starts_with('\''), "unescaped line: {line}");
            if line.starts_with('.') {
                assert!(
                    requests.iter().any(|r| line.starts_with(r)),
                    "unescaped line: {line}"
                );
            }
        }
    }

    #[test]
    fn escape_neutralises_requests_backslashes_minus_and_non_ascii() {
        assert_eq!(escape(".TH evil\n"), "\\&.TH evil\n");
        assert_eq!(escape("'br\n"), "\\&'br\n");
        assert_eq!(escape("a\\b --in\n"), "a\\eb \\-\\-in\n");
        assert_eq!(
            escape("l(p) \u{2014} \u{0457}\n"),
            "l(p) \\[u2014] \\[u0457]\n"
        );
        assert_eq!(escape(""), "");
    }

    #[test]
    fn page_is_ascii_and_deterministic() {
        let text = page();
        assert!(text.is_ascii());
        assert_eq!(text, page());
    }
}
