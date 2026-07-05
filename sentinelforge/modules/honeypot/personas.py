"""Honeypot personas and response presets.

Personas keep the low-interaction services coherent: the HTTP banner, page
body, SSH banner, and FTP replies should look like they came from the same
kind of host.
"""
from __future__ import annotations

from copy import deepcopy

PRESETS: dict[str, dict] = {
    "apache_ubuntu": {
        "label": "Apache on Ubuntu",
        "summary": "Default Ubuntu web host with OpenSSH and vsFTPd.",
        "http_server_header": "Apache/2.4.58 (Ubuntu)",
        "http_status": "200 OK",
        "http_content_type": "text/html; charset=utf-8",
        "http_extra_headers": {
            "X-Powered-By": "PHP/8.1.2",
            "X-Generator": "WordPress 6.4.3",
        },
        "http_body": (
            "<!doctype html><html><head><title>Apache2 Ubuntu Default Page: It works</title></head>"
            "<body><h1>It works!</h1><p>This is the default welcome page for Apache2.</p></body></html>"
        ),
        "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "ftp_banner": "220 (vsFTPd 3.0.5)",
        "ftp_user_reply": "331 Please specify the password.",
        "ftp_pass_reply": "530 Login incorrect.",
        "telnet_banner": "Ubuntu 22.04 LTS",
        "telnet_fail_reply": "Login incorrect",
        "smtp_banner": "220 mail.local ESMTP Postfix",
        "smtp_relay_denied": "554 5.7.1 Relay access denied",
        "tags": ["linux", "ubuntu", "apache", "php"],
    },
    "nginx_debian": {
        "label": "nginx on Debian",
        "summary": "Minimal Debian reverse proxy or static web host.",
        "http_server_header": "nginx/1.22.1",
        "http_status": "200 OK",
        "http_content_type": "text/html",
        "http_extra_headers": {
            "X-Accel-Version": "0.01",
        },
        "http_body": (
            "<!doctype html><html><head><title>Welcome to nginx!</title></head>"
            "<body><h1>Welcome to nginx!</h1><p>If you see this page, nginx is working.</p></body></html>"
        ),
        "ssh_banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "ftp_banner": "220 ProFTPD Server (Debian) [::ffff:127.0.0.1]",
        "ftp_user_reply": "331 Password required",
        "ftp_pass_reply": "530 Login incorrect.",
        "telnet_banner": "Debian GNU/Linux 12",
        "telnet_fail_reply": "Login incorrect",
        "smtp_banner": "220 mx.local ESMTP Exim 4.96",
        "smtp_relay_denied": "550 relay not permitted",
        "tags": ["linux", "debian", "nginx", "proxy"],
    },
    "iis_windows": {
        "label": "IIS on Windows",
        "summary": "Windows Server host with IIS-style HTTP responses.",
        "http_server_header": "Microsoft-IIS/10.0",
        "http_status": "200 OK",
        "http_content_type": "text/html",
        "http_extra_headers": {
            "X-Powered-By": "ASP.NET",
            "X-AspNet-Version": "4.0.30319",
        },
        "http_body": (
            "<!doctype html><html><head><title>IIS Windows Server</title></head>"
            "<body><h1>IIS Windows Server</h1></body></html>"
        ),
        "ssh_banner": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "ftp_banner": "220 Microsoft FTP Service",
        "ftp_user_reply": "331 Password required",
        "ftp_pass_reply": "530 User cannot log in.",
        "telnet_banner": "Microsoft Telnet Service",
        "telnet_fail_reply": "Access denied",
        "smtp_banner": "220 mail.local Microsoft ESMTP MAIL Service ready",
        "smtp_relay_denied": "550 5.7.1 Unable to relay",
        "tags": ["windows", "iis", "aspnet"],
    },
    "tomcat_admin": {
        "label": "Tomcat Admin",
        "summary": "Java application server with exposed manager-looking surface.",
        "http_server_header": "Apache-Coyote/1.1",
        "http_status": "200 OK",
        "http_content_type": "text/html;charset=UTF-8",
        "http_extra_headers": {},
        "http_body": (
            "<!doctype html><html><head><title>Apache Tomcat/9.0.31</title></head>"
            "<body><h1>Apache Tomcat/9.0.31</h1><p>Manager App</p></body></html>"
        ),
        "ssh_banner": "SSH-2.0-OpenSSH_8.4",
        "ftp_banner": "220 FileZilla Server 0.9.60 beta",
        "ftp_user_reply": "331 Password required for user",
        "ftp_pass_reply": "530 Login or password incorrect!",
        "telnet_banner": "CentOS Linux 7",
        "telnet_fail_reply": "Login incorrect",
        "smtp_banner": "220 app.local ESMTP Sendmail",
        "smtp_relay_denied": "550 5.7.1 Relaying denied",
        "tags": ["linux", "java", "tomcat"],
    },
    "edge_router": {
        "label": "Edge Router",
        "summary": "Small office router or network appliance.",
        "http_server_header": "Boa/0.94.14rc21",
        "http_status": "401 Unauthorized",
        "http_content_type": "text/html",
        "http_extra_headers": {
            "WWW-Authenticate": 'Basic realm="Router"',
        },
        "http_body": (
            "<html><head><title>401 Unauthorized</title></head>"
            "<body><h1>401 Unauthorized</h1></body></html>"
        ),
        "ssh_banner": "SSH-2.0-dropbear_2019.78",
        "ftp_banner": "220 BusyBox ftpd (1.31.1) ready",
        "ftp_user_reply": "331 Please specify the password.",
        "ftp_pass_reply": "530 Login incorrect.",
        "telnet_banner": "OpenWrt login:",
        "telnet_fail_reply": "Login incorrect",
        "smtp_banner": "220 router.local ESMTP",
        "smtp_relay_denied": "554 Relay access denied",
        "tags": ["network", "router", "embedded"],
    },
}


def preset_options() -> list[tuple[str, str]]:
    return [(key, value["label"]) for key, value in PRESETS.items()]


def get_preset(key: str) -> dict:
    return deepcopy(PRESETS[key])


def apply_to_honeypot_config(honeypot_cfg: dict, key: str) -> dict:
    preset = get_preset(key)
    honeypot_cfg["persona"] = key
    for field in (
        "http_server_header",
        "http_status",
        "http_content_type",
        "http_extra_headers",
        "http_body",
        "ssh_banner",
        "ftp_banner",
        "ftp_user_reply",
        "ftp_pass_reply",
        "telnet_banner",
        "telnet_fail_reply",
        "smtp_banner",
        "smtp_relay_denied",
    ):
        honeypot_cfg[field] = preset[field]
    honeypot_cfg["persona_tags"] = preset.get("tags", [])
    return honeypot_cfg
