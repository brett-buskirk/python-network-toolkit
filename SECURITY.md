# Security & Responsible Use

The Python Network Toolkit is an **educational** collection of networking utilities — packet capture,
raw TCP/UDP, a TCP proxy, SSH client/server/reverse-shell, and related tools. It exists to demonstrate
how the wire works and to serve as a portfolio reference. Several tools are inherently **dual-use**:
the same packet sniffer that teaches you TCP also captures traffic, and the SSH tools open real
sessions.

## Authorized use only

Use these tools **only** on systems and networks that you own or have **explicit, written permission**
to test. Packet capture, scanning, and remote-session tools can be illegal to run against
infrastructure you don't control — in many jurisdictions, regardless of intent.

- ✅ Your own machines, home lab, or a network you administer.
- ✅ An engagement where you have documented authorization (pentest, CTF, coursework).
- ❌ Any third-party system, network, or service without permission.

You are responsible for how you use this software. The authors provide it for learning and authorized
testing, and accept no liability for misuse (see the [LICENSE](LICENSE)).

## Scope of the tools

Everything here is a diagnostic or learning utility. The project deliberately does **not** ship
capabilities whose only purpose is attack, evasion, or covert persistence with no legitimate
diagnostic value. New tools added to the suite are held to the same line.

## Reporting a vulnerability

If you find a security issue **in this toolkit itself** (not a general networking question), please
report it privately rather than opening a public issue:

- Use GitHub's **[private vulnerability reporting](https://github.com/brett-buskirk/python-network-toolkit/security/advisories/new)**, or
- email **brett@brett-buskirk.dev**.

Please include steps to reproduce and the affected tool. We'll acknowledge and respond as promptly as
we reasonably can.
