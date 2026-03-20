# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Karstflow, please report it
responsibly. **Do not open a public issue.**

Send a detailed report to: **boogvar@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours. Critical issues will
be addressed as a priority.

## Scope

This policy covers the Karstflow validator codebase, including:
- Consensus logic (Tower BFT, fork choice)
- Cryptographic operations (Ed25519, SHA-256, BLS12-381)
- Network protocols (QUIC, gossip, turbine, repair)
- sBPF virtual machine and program execution
- RPC server and WebSocket endpoints
- Account storage and snapshot handling

## Out of Scope

- Third-party dependencies (report upstream)
- Social engineering attacks
- Denial of service via rate limiting (expected behavior)
