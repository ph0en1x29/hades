# HADES — Threat Model: SIEM Pipeline Injection

## Core Insight

SIEM systems are faithful loggers. They don't sanitize or filter incoming data — they record it exactly as received. This creates a direct channel from attacker-controlled network traffic to the LLM's input.

## The Attack Flow

1. **Attacker crafts network traffic** containing prompt injection payloads
   - HTTP User-Agent headers
   - DNS TXT records / DNS queries
   - TLS certificate Common Name (CN) fields
   - SSH usernames
   - Windows Event Log fields
   - URL paths
   - Hostnames
   - Authentication fields

2. **Network traffic hits the target organization's infrastructure**

3. **SIEM system logs the traffic verbatim** — payload is preserved in log fields

4. **Alert normalizer includes the payload** in the structured alert sent to the LLM

5. **LLM triage model reads the poisoned alert** — cannot distinguish injected instructions from legitimate data

6. **Wrong security decision** — real attack classified as benign, escalations suppressed, reasoning corrupted

## What makes this different from normal prompt injection?

In normal prompt injection, a user directly interacts with an AI chatbot and tries to trick it. In SIEM pipeline injection:

- The attacker **never directly touches the model**
- The payload travels through the organization's **own legitimate data pipeline**
- The SIEM system **faithfully preserves** the malicious content
- The LLM sees the injection as **part of the security data** it's analyzing
- There is **no user in the loop** to catch the manipulation in real-time

## Injection Vectors (12 total)

The framework implements 12 specific network traffic fields where payloads can be embedded:

| Vector | Example | Payload Capacity |
|--------|---------|-----------------|
| HTTP User-Agent | Browser identification string | High — hundreds of characters common |
| DNS TXT Record | Arbitrary text in DNS responses | Medium — 255 bytes per record |
| TLS Certificate CN | Server identity in certificates | Medium — up to 64 characters |
| HTTP Headers (custom) | X-* headers in requests | High — no standard limit |
| URL Path | Path component of HTTP requests | Medium — varies by server |
| Hostname | Server/client hostname fields | Low — 253 characters max |
| SSH Username | Authentication username field | Low — typically <32 characters |
| Windows Event fields | Various event log fields | Varies by event type |
| Authentication tokens | Token/cookie values | High — can be large |
| SMTP headers | Email header fields | High — relatively unconstrained |
| Process command line | Command arguments in logs | High — can be very long |
| Registry values | Windows registry data in logs | Medium — varies |

## Attack Classes (5 total)

Each injection attempts one of these outcomes:

1. **Misclassification** — Make the LLM classify a real attack as benign (most dangerous)
2. **Confidence Manipulation** — Make the LLM assign wrong confidence scores (subtle)
3. **Reasoning Corruption** — Corrupt the LLM's analytical reasoning chain
4. **Attention Hijacking** — Redirect the LLM's focus away from malicious indicators
5. **Escalation Suppression** — Prevent the LLM from escalating high-severity alerts

## Encoding Strategies (9 total)

Payloads can be encoded to bypass defenses:

1. **Plaintext** — Direct injection, no encoding
2. **Base64** — Standard encoding, LLMs can decode
3. **Homoglyph substitution** — Replace characters with similar-looking Unicode characters
4. **Zero-width characters** — Insert invisible Unicode characters to break keyword matching
5. **Leetspeak** — Replace letters with numbers (e→3, a→4, etc.)
6. **ROT13** — Simple letter rotation cipher
7. **URL encoding** — Percent-encoded characters
8. **HTML entities** — HTML character references
9. **Mixed encoding** — Combination of multiple strategies

## Real-World Validation

This is not theoretical:

- **Neaves (2025)** — Successfully injected payloads through HTTP User-Agent headers, SSH usernames, and Windows Event Log fields in production SIEM environments. Caused LLM assistants to falsify source IPs, hide attack indicators, and fabricate decoy events.
- **Unit 42 (2026)** — Reported 22 distinct indirect prompt injection techniques observed in production telemetry.
- **Carlini et al.** — Demonstrated >90% bypass rates against aligned LLMs.
- **LevelBlue** — Achieved 100% injection success in SOC assistant testing.

## Key Pre-GPU Finding: Payload Survival

From the E3 experiment (already complete, no GPU needed):

- **40% of attack classes survive ALL 11 SIEM normalization rules** — meaning the SIEM's own processing doesn't remove the payloads
- **Homoglyph and zero-width encodings bypass keyword-based defenses** while remaining readable by LLMs
- **Best layered defense achieves only 60% indicator removal** on plaintext payloads
- **Conclusion:** Input sanitization alone is insufficient. Output validation (behavioral invariants) is essential.
