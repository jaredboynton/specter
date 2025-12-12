use chrono::Utc;

fn parse_cookie_date(date_str: &str) -> Option<chrono::DateTime<Utc>> {
    const FORMATS: &[&str] = &[
        "%a, %d %b %Y %H:%M:%S GMT", // RFC 1123
        "%A, %d-%b-%y %H:%M:%S GMT", // RFC 850
        "%a %b %e %H:%M:%S %Y",      // ANSI C asctime()
    ];

    for fmt in FORMATS {
        if let Ok(dt) = chrono::DateTime::parse_from_str(date_str, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    None
}

fn main() {
    let s1 = "Sun, 06 Nov 1994 08:49:37 GMT";
    println!("Testing '{}': {:?}", s1, parse_cookie_date(s1));
}
