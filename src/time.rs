//! Shutdown time specs — FreeBSD shutdown(8) syntax.
//!
//!   `now` — immediately; `+N` — N minutes from now; `hh:mm` — absolute,
//!   24-hour clock.
//!
//! Absolute times must lie in the future, as in FreeBSD: silently rolling
//! to the next day would fire a shutdown nobody scheduled.

/// Parses a time spec into seconds from now.
///
/// `now_secs_of_day` is the local time of day in seconds, supplied by the
/// caller so the arithmetic stays testable off-Windows.
pub fn parse(spec: &str, now_secs_of_day: u32) -> Result<u32, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("now") {
        return Ok(0);
    }
    if let Some(mins) = spec.strip_prefix('+') {
        let m: u32 = mins
            .parse()
            .map_err(|_| format!("{spec}: invalid time specification"))?;
        return Ok(m.saturating_mul(60));
    }
    if let Some((h, m)) = spec.split_once(':') {
        let (h, m): (u32, u32) = match (h.parse(), m.parse()) {
            (Ok(h), Ok(m)) if h < 24 && m < 60 => (h, m),
            _ => return Err(format!("{spec}: invalid time specification")),
        };
        let target = h * 3600 + m * 60;
        let delta = target as i64 - now_secs_of_day as i64;
        if delta < 0 {
            return Err(format!("{spec}: that time has already passed"));
        }
        return Ok(delta as u32);
    }
    Err(format!("{spec}: invalid time specification"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u32 = 10 * 3600 + 30 * 60; // 10:30

    #[test]
    fn now_is_zero() {
        assert_eq!(parse("now", NOW).unwrap(), 0);
        assert_eq!(parse("NOW", NOW).unwrap(), 0);
    }

    #[test]
    fn relative_minutes() {
        assert_eq!(parse("+5", NOW).unwrap(), 300);
        assert_eq!(parse("+0", NOW).unwrap(), 0);
        assert!(parse("+x", NOW).is_err());
        assert!(parse("+", NOW).is_err());
    }

    #[test]
    fn absolute_clock_time() {
        assert_eq!(parse("11:00", NOW).unwrap(), 1800);
        assert_eq!(parse("10:30", NOW).unwrap(), 0);
    }

    #[test]
    fn past_times_are_rejected() {
        assert!(parse("09:00", NOW).is_err());
        assert!(parse("10:29", NOW).is_err());
    }

    #[test]
    fn malformed_specs_are_rejected() {
        assert!(parse("24:00", NOW).is_err());
        assert!(parse("12:60", NOW).is_err());
        assert!(parse("soon", NOW).is_err());
        assert!(parse("", NOW).is_err());
    }
}
