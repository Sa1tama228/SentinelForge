from __future__ import annotations

import re


def technologies_from_banner(banner: str) -> list[str]:
    text = banner or ""
    low = text.lower()
    tech: list[str] = []
    _add_header_product(tech, text, "server")
    _add_header_product(tech, text, "x-powered-by")
    if "x-generator:" in low:
        _add_header_product(tech, text, "x-generator")
    for pattern, name in (
        (r"wp-content|wordpress", "WordPress"),
        (r"joomla", "Joomla"),
        (r"drupal", "Drupal"),
        (r"laravel", "Laravel"),
        (r"django", "Django"),
        (r"express", "Express"),
        (r"phpmyadmin", "phpMyAdmin"),
        (r"apache2 ubuntu default page", "Apache Ubuntu default page"),
    ):
        if re.search(pattern, low):
            tech.append(name)
    for cookie in re.findall(r"set-cookie:\s*([^=\r\n;]+)", text, flags=re.I):
        if cookie.lower().startswith("phpsessid"):
            tech.append("PHP session")
        elif "jsessionid" in cookie.lower():
            tech.append("Java servlet session")
    return sorted(dict.fromkeys(t.strip() for t in tech if t.strip()))


def _add_header_product(out: list[str], text: str, header: str) -> None:
    match = re.search(rf"^{re.escape(header)}:\s*([^\r\n]+)", text, flags=re.I | re.M)
    if match:
        out.append(match.group(1).strip())
