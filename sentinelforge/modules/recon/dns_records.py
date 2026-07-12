from __future__ import annotations

import dns.resolver


def resolve(domain: str, resolvers: list[str] | None = None) -> dict:
    """Return a dict of record-type -> list of strings for ``domain``."""
    out: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    if resolvers:
        resolver.nameservers = resolvers
    resolver.lifetime = 5.0

    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        try:
            answers = resolver.resolve(domain, rtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue
        vals: list[str] = []
        for r in answers:
            if rtype == "MX":
                vals.append(f"{r.preference} {r.exchange}")
            else:
                vals.append(str(r).strip('"'))
        if vals:
            out[rtype] = vals
    out["posture"] = _mail_posture(domain, out.get("TXT", []), resolver)
    return out


def _mail_posture(domain: str, root_txt: list[str], resolver: dns.resolver.Resolver) -> dict:
    spf = [value for value in root_txt if value.lower().startswith("v=spf1")]
    dmarc: list[str] = []
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
    except Exception:
        answers = []
    for answer in answers:
        value = str(answer).strip('"')
        if value.lower().startswith("v=dmarc1"):
            dmarc.append(value)
    return {
        "spf_present": bool(spf),
        "dmarc_present": bool(dmarc),
        "spf": spf[:3],
        "dmarc": dmarc[:3],
    }
