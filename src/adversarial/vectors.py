"""Injection vector definitions — log fields attackers can control via network traffic."""

from dataclasses import dataclass


@dataclass
class InjectionVector:
    """A SIEM log field that originates from attacker-controlled network data."""

    name: str
    log_field: str
    network_source: str
    siem_sources: list[str]
    realism: str  # high, medium, low
    max_payload_length: int  # typical field length limit
    notes: str = ""


INJECTION_VECTORS = [
    InjectionVector(
        name="HTTP User-Agent",
        log_field="http.user_agent",
        network_source="HTTP request header",
        siem_sources=["Suricata", "Zeek", "WAF", "Web proxy"],
        realism="high",
        max_payload_length=8192,
        notes="RFC 2616: no max length. Validated by [Neaves2025] — full payload logged by SIEM.",
    ),
    InjectionVector(
        name="HTTP Referer",
        log_field="http.referer",
        network_source="HTTP request header",
        siem_sources=["Suricata", "Zeek", "WAF"],
        realism="high",
        max_payload_length=2048,
        notes="Often logged verbatim; URL-encoded payloads may survive",
    ),
    InjectionVector(
        name="DNS Query Name",
        log_field="dns.query",
        network_source="DNS query",
        siem_sources=["Zeek", "Suricata", "DNS server logs"],
        realism="high",
        max_payload_length=253,
        notes="Limited to valid DNS label characters; subdomain chaining possible",
    ),
    InjectionVector(
        name="SMB/NetBIOS Hostname",
        log_field="source.hostname",
        network_source="SMB negotiation / NetBIOS",
        siem_sources=["Windows Event Log", "Zeek"],
        realism="medium",
        max_payload_length=63,
        notes="Short field; payload must be concise",
    ),
    InjectionVector(
        name="SNMP Community String",
        log_field="snmp.community",
        network_source="SNMP request",
        siem_sources=["Network monitoring", "Suricata"],
        realism="medium",
        max_payload_length=255,
        notes="Rarely sanitized; may contain arbitrary text",
    ),
    InjectionVector(
        name="Email Subject",
        log_field="email.subject",
        network_source="SMTP envelope",
        siem_sources=["Mail gateway", "Exchange logs"],
        realism="high",
        max_payload_length=998,
        notes="Rich text field with high payload capacity",
    ),
    InjectionVector(
        name="TLS Certificate CN",
        log_field="tls.server.cn",
        network_source="TLS handshake (server certificate)",
        siem_sources=["Zeek", "TLS inspection appliance"],
        realism="medium",
        max_payload_length=64,
        notes="Attacker needs to control the server certificate",
    ),
    InjectionVector(
        name="TLS Certificate SAN",
        log_field="tls.server.san",
        network_source="TLS handshake (server certificate)",
        siem_sources=["Zeek", "TLS inspection appliance"],
        realism="medium",
        max_payload_length=256,
        notes="Multiple SANs allow longer combined payloads",
    ),
    InjectionVector(
        name="SSH Server Banner",
        log_field="ssh.banner",
        network_source="SSH protocol negotiation",
        siem_sources=["Zeek", "auth logs"],
        realism="high",
        max_payload_length=255,
        notes="Server banner is fully attacker-controlled; logged by most tools",
    ),
    InjectionVector(
        name="Windows Event Username",
        log_field="winlog.event_data.TargetUserName",
        network_source="SMB/NTLM authentication attempt",
        siem_sources=["Windows Event Log", "SIEM (Event 4625)"],
        realism="high",
        max_payload_length=240,
        notes="Validated by [Neaves2025]: 120+ chars in username + 120+ in domain. "
        "MSRC declined to service. Combined username+domain = ~240 char payload.",
    ),
    InjectionVector(
        name="SSH Username",
        log_field="source.user",
        network_source="SSH authentication attempt",
        siem_sources=["sshd/PAM logs", "auth.log", "SIEM"],
        realism="high",
        max_payload_length=256,
        notes="Validated by [Neaves2025]. Username field logged verbatim by PAM/sshd.",
    ),
    InjectionVector(
        name="LDAP Bind DN",
        log_field="ldap.bind_dn",
        network_source="LDAP bind request",
        siem_sources=["AD logs", "LDAP server logs"],
        realism="low",
        max_payload_length=256,
        notes="Requires attacker to initiate LDAP connection; less common vector",
    ),
]
