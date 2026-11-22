<#
.SYNOPSIS
  Checks Fishe on Linux from a Windows PC, in a Docker container.

.DESCRIPTION
  Without a switch: rustfmt, clippy (warnings are errors) and the unit
  tests of crates/fishe-core on Debian with libpcap. The repository is
  mounted read-only; the Linux build output and the crate registry live in
  Docker volumes (fishe-target, fishe-cargo), so nothing lands in the
  repository.

  -Live also runs the live tests of the core as root in the container: they
  open its network interface, send a few UDP datagrams and one TCP
  connection to 1.1.1.1, ping and trace, sweep the container's network with
  ARP, read the kernel's routing tables, and run a whole all-traffic session
  through to its security report. The container only sees its own
  traffic, never this PC's or the LAN's.

  -App checks the whole workspace instead, window included: the source is
  copied into a volume (fishe-work, which keeps its own node_modules), then
  npm ci, the Svelte check, the frontend tests, clippy and the tests of
  both crates, and the app binary on WebKitGTK. The image is larger (about
  2.5 GB).

  -Package (with -App) also bundles the .deb and .rpm from that debug build
  and installs the .deb in the container, to check the packaging.

  Needs Docker Desktop running. Remove everything it made with:
    docker volume rm fishe-target fishe-cargo fishe-work
    docker image rm fishe-linux-dev fishe-linux-app

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/linux-check.ps1 -Live

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/linux-check.ps1 -App
#>
param([switch]$Live, [switch]$App, [switch]$Package)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

if ($App) {
  docker build -q -t fishe-linux-app -f "$PSScriptRoot\linux\app.Dockerfile" "$PSScriptRoot\linux" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "docker build failed (is Docker Desktop running?)" }
  $steps = @(
    # node_modules, the build output and the Npcap SDK stay behind: they are Windows'.
    "rsync -a --delete --exclude node_modules --exclude /src-tauri/target --exclude /build --exclude /.svelte-kit --exclude /vendor --exclude /.git --exclude /.idea /src/ /work/",
    "npm ci",
    "npm run check",
    "npm test",
    "npm run build",
    "cargo fmt --all --check",
    "cargo clippy --workspace --all-targets --locked -- -D warnings",
    "cargo test --workspace --locked",
    "npm run tauri build -- --debug --no-bundle"
  )
  if ($Package) {
    $steps += "npm run tauri build -- --debug"
    $steps += "apt-get update -qq && apt-get install -y -qq /target/debug/bundle/deb/*.deb && dpkg -s fishe | grep -E '^(Version|Depends)' && ls -l /usr/bin/fishe /target/debug/bundle/rpm/*.rpm"
  }
  docker run --rm -v "${root}:/src:ro" -v fishe-cargo:/usr/local/cargo/registry -v fishe-target:/target -v fishe-work:/work fishe-linux-app bash -c ($steps -join " && ")
  exit $LASTEXITCODE
}

docker build -q -t fishe-linux-dev "$PSScriptRoot\linux" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "docker build failed (is Docker Desktop running?)" }

$steps = @(
  "cargo fmt --all --check",
  "cargo clippy -p fishe-core --all-targets --locked -- -D warnings",
  "cargo test -p fishe-core --locked"
)
if ($Live) {
  # One at a time: several share a target address and would count each other's packets.
  $names = @(
    "monitor::engine::live_tests::live_capture_sees_outgoing_udp",
    "monitor::engine::live_tests::live_tcp_quality_matches_ping",
    "monitor::engine::live_tests::live_process_mode_attributes_own_traffic",
    "monitor::engine::live_tests::live_all_traffic_labels_programs",
    "route::icmp::tests::loopback_answers_directly",
    "route::ping::tests::loopback_ping_and_limits",
    "route::trace::tests::traces_loopback_in_one_hop",
    "lan::arp::tests::live_sweep",
    "ops::tests::live_security_report"
  )
  foreach ($t in $names) {
    $steps += "timeout 120 cargo test -p fishe-core --locked -- --ignored --exact $t"
  }
}
docker run --rm -v "${root}:/src:ro" -v fishe-cargo:/usr/local/cargo/registry -v fishe-target:/target fishe-linux-dev bash -c ($steps -join " && ")
exit $LASTEXITCODE
