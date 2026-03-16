use chrono::Utc;
use crate::error::CoreError;
use super::filter::*;

/// Parse a query string into a `Query`.
///
/// Supported syntax:
/// - `field=value`           — exact match
/// - `field!=value`          — negated exact match
/// - `field=prefix*`         — prefix wildcard
/// - `field=*suffix`         — suffix wildcard
/// - `field=*contains*`      — contains wildcard
/// - `field=*`               — field exists
/// - `AND` (keyword)         — implicit between terms, explicit also accepted
/// - `earliest=-24h`         — relative time (units: m, h, d, w)
/// - `earliest=2024-01-01T00:00:00Z` — absolute time
/// - `latest=...`            — same for upper bound
///
/// Unknown field names are silently skipped to allow forward compatibility.
pub fn parse_query(input: &str) -> Result<Query, CoreError> {
    let mut query = Query::default();
    let input = input.trim();
    if input.is_empty() {
        return Ok(query);
    }

    let tokens = tokenize(input);

    for token in &tokens {
        // Skip AND/OR conjunctions (we treat everything as AND for now)
        if token.eq_ignore_ascii_case("AND") || token.eq_ignore_ascii_case("OR") {
            continue;
        }
        // Time tokens
        if token.starts_with("earliest=") || token.starts_with("latest=") {
            parse_time_token(token, &mut query)?;
            continue;
        }
        // Field filter tokens
        if let Some(filter) = parse_filter_token(token)? {
            query.filters.push(filter);
        }
    }

    Ok(query)
}

/// Tokenize on whitespace, respecting double-quoted strings.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                // Quotes delimit but are not included in the token
            }
            ' ' | '\t' | '\n' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Parse a token like `field=value` or `field!=value` into a FieldFilter.
/// Returns `Ok(None)` for tokens that don't look like filters (skipped silently).
fn parse_filter_token(token: &str) -> Result<Option<FieldFilter>, CoreError> {
    // Must check `!=` before `=` so we don't split on the `=` inside `!=`
    if let Some(pos) = token.find("!=") {
        let field_str = &token[..pos];
        let value_str = &token[pos + 2..];
        let field = match FieldName::from_str(field_str) {
            Some(f) => f,
            None => return Ok(None), // unknown field — skip
        };
        return Ok(Some(FieldFilter {
            field,
            mode: parse_match_mode(value_str),
            negated: true,
        }));
    }

    if let Some(pos) = token.find('=') {
        let field_str = &token[..pos];
        let value_str = &token[pos + 1..];
        let field = match FieldName::from_str(field_str) {
            Some(f) => f,
            None => return Ok(None), // unknown field — skip
        };
        return Ok(Some(FieldFilter {
            field,
            mode: parse_match_mode(value_str),
            negated: false,
        }));
    }

    // Not a filter token — skip
    Ok(None)
}

fn parse_match_mode(value: &str) -> MatchMode {
    if value == "*" {
        return MatchMode::Exists;
    }
    let starts_star = value.starts_with('*');
    let ends_star = value.ends_with('*') && value.len() > 1;

    match (starts_star, ends_star) {
        (true, true) if value.len() > 2 => {
            MatchMode::Contains(value[1..value.len() - 1].to_lowercase())
        }
        (true, true) => {
            // Edge case: "**" — treat as Exists
            MatchMode::Exists
        }
        (false, true) => MatchMode::Prefix(value[..value.len() - 1].to_lowercase()),
        (true, false) => MatchMode::Suffix(value[1..].to_lowercase()),
        (false, false) => MatchMode::Exact(value.to_string()),
    }
}

fn parse_time_token(token: &str, query: &mut Query) -> Result<(), CoreError> {
    let (key, value) = token
        .split_once('=')
        .ok_or_else(|| CoreError::Query(format!("Invalid time token: {token}")))?;
    let is_earliest = key == "earliest";
    let ts_ms = parse_time_value(value)?;

    let tr = query.time_range.get_or_insert(TimeRange {
        start_ms: i64::MIN,
        end_ms: i64::MAX,
    });
    if is_earliest {
        tr.start_ms = ts_ms;
    } else {
        tr.end_ms = ts_ms;
    }
    Ok(())
}

fn parse_time_value(value: &str) -> Result<i64, CoreError> {
    if value.eq_ignore_ascii_case("now") {
        return Ok(Utc::now().timestamp_millis());
    }

    // Relative: -24h, -7d, -30m, -2w
    if let Some(rest) = value.strip_prefix('-') {
        if rest.is_empty() {
            return Err(CoreError::Query(format!("Empty relative time: {value}")));
        }
        let unit_char = rest.chars().last().unwrap();
        let num_str = &rest[..rest.len() - unit_char.len_utf8()];
        let n: i64 = num_str
            .parse()
            .map_err(|_| CoreError::Query(format!("Invalid number in time: {value}")))?;
        let millis = match unit_char {
            'm' => n * 60 * 1_000,
            'h' => n * 3_600 * 1_000,
            'd' => n * 86_400 * 1_000,
            'w' => n * 7 * 86_400 * 1_000,
            _ => return Err(CoreError::Query(format!("Unknown time unit '{unit_char}' in: {value}"))),
        };
        return Ok(Utc::now().timestamp_millis() - millis);
    }

    // Absolute ISO 8601
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.timestamp_millis())
        .map_err(|e| CoreError::Query(format!("Invalid time '{value}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_query() {
        let q = parse_query("").unwrap();
        assert!(q.is_empty());
    }

    #[test]
    fn test_exact_filter() {
        let q = parse_query("eventName=ConsoleLogin").unwrap();
        assert_eq!(q.filters.len(), 1);
        assert_eq!(q.filters[0].field, FieldName::EventName);
        assert!(!q.filters[0].negated);
        assert!(matches!(&q.filters[0].mode, MatchMode::Exact(v) if v == "ConsoleLogin"));
    }

    #[test]
    fn test_negated_filter() {
        let q = parse_query("errorCode!=AccessDenied").unwrap();
        assert_eq!(q.filters.len(), 1);
        assert!(q.filters[0].negated);
    }

    #[test]
    fn test_wildcard_prefix() {
        let q = parse_query("eventName=Create*").unwrap();
        assert!(matches!(&q.filters[0].mode, MatchMode::Prefix(p) if p == "create"));
    }

    #[test]
    fn test_multiple_filters() {
        let q = parse_query("eventName=ConsoleLogin AND awsRegion=us-east-1").unwrap();
        assert_eq!(q.filters.len(), 2);
    }

    #[test]
    fn test_relative_time() {
        let q = parse_query("eventName=CreateUser earliest=-24h").unwrap();
        assert_eq!(q.filters.len(), 1);
        assert!(q.time_range.is_some());
        let tr = q.time_range.unwrap();
        assert!(tr.start_ms > 0);
        assert_eq!(tr.end_ms, i64::MAX);
    }

    #[test]
    fn test_unknown_field_skipped() {
        let q = parse_query("unknownField=value eventName=CreateUser").unwrap();
        assert_eq!(q.filters.len(), 1);
        assert_eq!(q.filters[0].field, FieldName::EventName);
    }
}
