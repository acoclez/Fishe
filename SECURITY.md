# Security policy

## Supported versions

Fixes go into a new release. Only the latest release is supported.

## Reporting a vulnerability

Report it privately, through GitHub:
[Security → Report a vulnerability](https://github.com/acoclez/Fishe/security/advisories/new).
Please do not open a public issue for something that can be exploited.

A useful report says:

- the Fishe version and the Windows version;
- whether Fishe was running as administrator;
- what an attacker needs (a host on the same network, a web page open in a
  browser, a local account) and what they gain;
- the steps, or a packet capture, that reproduce it.

Fishe is maintained by one person. Reports are read and answered as soon as
time allows.

## Scope

Fishe reads packets that other hosts send, and can run as administrator, so
these matter most:

- **Packet parsing.** A packet that crashes Fishe, makes it use unbounded
  memory, or puts text other than a host name into the window, an export or
  an agent's tool result.
- **The MCP server.** Reaching it without the token, from another machine or
  from a web page, or using a tool above the access level that was chosen.
  The measures in place are listed in [docs/mcp.md](docs/mcp.md#security).
- **Files.** An export or a recording written anywhere other than the place
  the user chose, or an exported file that runs something when opened.
- **Releases.** Anything that would let the published installers differ from
  the source at their tag.

Not in scope:

- Npcap, the capture driver Fishe depends on: report to the
  [Npcap project](https://npcap.com).
- An attacker who already controls the user's Windows account. The archive
  and the MCP token are stored in the user profile and are readable there.
- The installers not being code-signed. This is known and stated in the
  README.
