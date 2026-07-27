"""Domain-level email deliverability check.

We look up whether an email's *domain* can receive mail at all (MX record, or
an A/AAAA fallback per RFC 5321). This blocks signups to dead/fake domains
before we ever send a verification email — the main cause of the bounce flood
that hurts sender reputation. It does NOT verify the individual mailbox exists
(SMTP probing is unreliable and looks like spammer reconnaissance).

Contract: fail *open*. Return True on "deliverable", False only on a definitive
"this domain does not exist / cannot receive mail", and None when DNS itself
was inconclusive (timeout, no nameservers) — callers should allow signup on
None so a transient DNS blip never blocks a legitimate user.
"""
from __future__ import annotations

import dns.resolver
from dns.exception import DNSException

_DNS_TIMEOUT = 5.0


def domain_can_receive_mail(domain: str) -> bool | None:
    """See module docstring. True / False / None (inconclusive)."""
    domain = (domain or "").strip().rstrip(".").lower()
    if not domain or "." not in domain:
        return False

    resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT
    resolver.lifetime = _DNS_TIMEOUT

    # 1. MX record — the normal way a domain accepts mail.
    try:
        if len(resolver.resolve(domain, "MX")) > 0:
            return True
    except dns.resolver.NXDOMAIN:
        return False                     # domain doesn't exist at all
    except dns.resolver.NoAnswer:
        pass                             # exists but no MX — try A/AAAA below
    except (dns.resolver.NoNameservers, DNSException):
        return None                      # inconclusive — fail open

    # 2. A/AAAA fallback: RFC 5321 allows delivery to the host itself.
    for rtype in ("A", "AAAA"):
        try:
            if len(resolver.resolve(domain, rtype)) > 0:
                return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.NoNameservers, DNSException):
            return None

    # Domain resolves for queries but has no MX and no address record.
    return False


def email_domain(email: str) -> str:
    """Extract the lowercased domain from an email address ('' if malformed)."""
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip().lower()
