/// Известные пробники: (хост, путь, тело ответа).
///
/// Хост сравнивается в нижнем регистре, query-строка отбрасывается.
pub static PROBES: &[(&str, &str, &str)] = &[
    (
        "www.msftconnecttest.com",
        "/connecttest.txt",
        "Microsoft Connect Test",
    ),
    (
        "ipv6.msftconnecttest.com",
        "/connecttest.txt",
        "Microsoft Connect Test",
    ),
    ("www.msftncsi.com", "/ncsi.txt", "Microsoft NCSI"),
    ("dns.msftncsi.com", "/ncsi.txt", "Microsoft NCSI"),
    (
        "captive.apple.com",
        "/hotspot-detect.html",
        "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ),
    (
        "captive.apple.com",
        "/",
        "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ),
    (
        "www.apple.com",
        "/library/test/success.html",
        "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ),
    ("detectportal.firefox.com", "/success.txt", "success\n"),
    (
        "detectportal.firefox.com",
        "/canonical.html",
        "<meta http-equiv=\"refresh\" content=\"0; url=https://support.mozilla.org/kb/captive-portal\"/>\n",
    ),
    (
        "nmcheck.gnome.org",
        "/check_network_status.txt",
        "NetworkManager is online\n",
    ),
    ("networkcheck.kde.org", "/", "OK"),
    ("connectivity-check.ubuntu.com", "/", ""),
];

/// Найти тело ответа для пробника.
pub fn probe_body(host: &str, path: &str) -> Option<&'static str> {
    // Хост: убираем порт и квадратные скобки (IPv6), приводим к нижнему регистру.
    let host = host
        .trim()
        .to_ascii_lowercase()
        .split(':')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();

    // Путь: без query-строки, пустой -> "/".
    let path = path.split('?').next().unwrap_or("/");
    let path = if path.is_empty() { "/" } else { path };
    PROBES
        .iter()
        .find(|(h, p, _)| *h == host && *p == path)
        .map(|(_, _, body)| *body)
}
