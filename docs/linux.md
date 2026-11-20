# Fishe on Linux

Fishe runs on Linux with the same interface and the same measurements as
on Windows. This page says what a Linux user has to do, what is implemented
differently underneath, and what is not available.

## Installing

Packages are attached to each release: a `.deb` (Debian 12 and later,
Ubuntu 22.04 and later) and an `.rpm` (Fedora and relatives). They depend
on libpcap and WebKitGTK 4.1, which the package manager installs.

```sh
sudo apt install ./Fishe_<version>_amd64.deb      # Debian, Ubuntu
sudo dnf install ./Fishe-<version>-1.x86_64.rpm   # Fedora
```

There is no AppImage: see [the capture permission](#the-capture-permission).

## The capture permission

Reading packets from a network interface takes a capability, `CAP_NET_RAW`,
that root has and ordinary programs do not. Fishe never raises its own
rights and does not ask for a password. On first start the Live page shows
the one command that grants the capability to the installed program:

```sh
sudo setcap cap_net_raw=ep /usr/bin/fishe
```

Close Fishe and start it again: a program's capabilities are read when it
starts, so there is no "check again" as there is for Npcap on Windows.

| | |
|---|---|
| What it grants | Opening a capture, and the raw ICMP socket ping and traceroute use. Nothing else: no `CAP_NET_ADMIN`, no file access, no root |
| To whom | This file only. Every user who can run `/usr/bin/fishe` can then capture with it, as with a `dumpcap` set up for Wireshark |
| The window's content | The WebKit processes that draw the interface are started without the capability (checked: their effective set is empty) |
| After an update | The package manager replaces the file, and the capability goes with the old one: the prompt comes back and the command is run once more |
| To take it back | `sudo setcap -r /usr/bin/fishe` |
| Instead | Start Fishe as root. Not recommended for a desktop program |

An AppImage is mounted read-only each time it starts, in a place where a
capability cannot be set, so it could only capture as root. That is why
none is built.

`npcap.rs` makes the check at startup (it reads the effective capabilities
from `/proc/self/status`), and every capture, scan and probe goes through
it, as on Windows.

## What differs underneath

| Piece | Windows | Linux |
|---|---|---|
| Capture | Npcap, installed by the user | libpcap, a dependency of the package |
| Interface names | `\Device\NPF_{GUID}` with a description | `eth0`, `wlp3s0`; libpcap rarely has a description. `any` and the USB, Bluetooth, D-Bus and netfilter sources libpcap lists are left out |
| Which program owns a connection | IP Helper socket tables | `/proc/net` socket lists and `/proc/<pid>/fd` ([process-mode.md](process-mode.md#on-linux)) |
| Exact attribution of short-lived connections | ETW, as administrator | not available |
| Ping and traceroute | Windows ICMP API | A raw ICMP socket; replies are matched to the probe by the identifier and sequence number routers quote back (`route/icmp.rs`) |
| Gateways, neighbours, adapters | IP Helper | The kernel's routing socket, rtnetlink (`route/netlink.rs`): what `ip route`, `ip neigh`, `ip addr` print |
| LAN scan | ARP through Npcap | ARP through libpcap, on the interfaces rtnetlink reports with an IPv4 address and a gateway |
| Opening a folder or the logs | Explorer | `xdg-open` |
| Data folder | `%APPDATA%\com.fishe.app` | `$XDG_DATA_HOME/com.fishe.app`, by default `~/.local/share/com.fishe.app` |
| Window | WebView2 | WebKitGTK 4.1 |

## Limits

- **Other users' programs.** Without root, `/proc` only shows which
  sockets belong to programs running as you. Traffic of system services
  and of other users is counted, and listed as *Unattributed*.
- **Short-lived programs.** A program that opens a connection and exits
  between two ticks can be missed or shown by its PID alone; there is no
  equivalent of ETW to catch it.
- **IPv6 link-local targets** (`fe80::…`) cannot be pinged or traced: the
  probe has no interface to send them on.
- **Policy routing.** Only default routes of the main routing table count
  as gateways; a VPN client that puts its route in a table of its own is
  not shown as one.

## Building

Rust (stable), Node.js 22.17 or later, and these packages (Debian and
Ubuntu names):

```sh
sudo apt install build-essential pkg-config libpcap-dev libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev
npm install
npm run tauri dev        # or: npm run tauri build
```

`npm run tauri build` writes the `.deb` and the `.rpm` to
`src-tauri/target/release/bundle/` (`src-tauri/tauri.linux.conf.json`
chooses them). A development build needs the capability too, and each
rebuild writes a new file without it: run
`sudo setcap cap_net_raw=ep src-tauri/target/debug/fishe` after a build.
Interface work does not need it: `npm run dev` opens the browser preview,
which simulates the backend ([frontend.md](frontend.md)).

## What was verified

Linux support was developed on a Windows PC and checked in Docker
containers (`scripts/linux-check.ps1`, see
[development.md](development.md#linux)), which see a virtual network of
their own. That proves the code paths, not every desktop.

| Checked in a container (Debian 12) | How |
|---|---|
| The whole workspace builds; clippy clean; unit tests of both crates | `scripts/linux-check.ps1 -App` |
| Live capture, counting, TCP quality, per-program attribution | live tests, as root and as an ordinary user with the capability |
| ICMP echo, "time exceeded" from a router, ping statistics | live tests, same two ways; without the capability the probe reports the missing permission |
| Default gateway, neighbour table, adapter list from rtnetlink | live tests against the container's own tables |
| ARP sweep finds the gateway | live test |
| The window on WebKitGTK: all pages, a live session with real traffic, a LAN scan, a traceroute from the map | the built program on a virtual display, screenshots |
| The permission prompt, and the app working after the `setcap` command | the installed `.deb`, as an ordinary user |
| The `.deb` installs with its dependencies; the `.rpm` is built | `scripts/linux-check.ps1 -App -Package` |

| Not verified | Why |
|---|---|
| A real desktop session (GNOME, KDE; Wayland and X11), system fonts, HiDPI | no Linux desktop at hand |
| Wi-Fi interfaces, several adapters, a real LAN with many devices | a container has one virtual Ethernet interface |
| A route of several hops | Docker's network answers for the destination after its own gateway |
| Installing the `.rpm` on Fedora | built, not installed |
| IPv6 probes beyond loopback | the container network is IPv4 only |
