from __future__ import annotations

HTTP_PORTS = {80, 8000, 8080, 8081, 8888}
HTTPS_PORTS = {443, 8443, 9443}
WEB_PORTS = HTTP_PORTS | HTTPS_PORTS

# Well-known ports (FALLBACK when banner evidence are weak)
_PORT_SERVICE = {
      20: "ftp-data",
      21: "ftp",
      22: "ssh",
      23: "telnet",
      25: "smtp",
      53: "dns",
      67: "dhcp",
      68: "dhcp",
      69: "tftp",
      80: "http",
      88: "kerberos",
      110: "pop3",
      111: "rpcbind",
      123: "ntp",
      135: "msrpc",
      137: "netbios-ns",
      138: "netbios-dgm",
      139: "netbios-ssn",
      143: "imap",
      161: "snmp",
      162: "snmptrap",
      389: "ldap",
      443: "https",
      445: "smb",
      464: "kerberos-kpasswd",
      465: "smtps",
      500: "ike",
      514: "syslog",
      587: "smtp-submission",
      631: "ipp",
      636: "ldaps",
      993: "imaps",
      995: "pop3s",
      1433: "mssql",
      1521: "oracle",
      2049: "nfs",
      2375: "docker",
      2376: "docker-tls",
      3000: "http-alt",
      3306: "mysql",
      3389: "rdp",
      5000: "http-alt",
      5432: "postgresql",
      5601: "kibana",
      5672: "amqp",
      5900: "vnc",
      5985: "winrm",
      5986: "winrm-https",
      6379: "redis",
      8000: "http-alt",
      8080: "http-proxy",
      8081: "http-alt",
      8443: "https-alt",
      8888: "http-alt",
      9000: "http-alt",
      9200: "elasticsearch",
      9300: "elasticsearch-transport",
      9443: "https-alt",
      11211: "memcached",
      15672: "rabbitmq-management",
      27017: "mongodb",
  }

def looks_like_https_port(port: int) -> bool:
    return port in HTTPS_PORTS or str(port).endswith("443")


def looks_like_web_port(port: int) -> bool:
    return port in WEB_PORTS or looks_like_https_port(port)
