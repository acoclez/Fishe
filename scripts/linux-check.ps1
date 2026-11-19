<#
.SYNOPSIS
  Checks Fishe's core crate on Linux from a Windows PC, in a Docker container.

.DESCRIPTION
  Runs rustfmt, clippy (warnings are errors) and the unit tests of
  crates/fishe-core on Debian with libpcap. The repository is mounted
  read-only; the Linux build output and the crate registry live in two Docker
  volumes (fishe-target, fishe-cargo), so nothing lands in the repository.

  -Live also runs the live tests: they open the container's network
  interface, send a few UDP datagrams and one TCP connection to 1.1.1.1, and
  check that the capture saw and measured them, and that the packets were
  attributed to the test's own process. The container only sees its
  own traffic, never this PC's or the LAN's.

  Needs Docker Desktop running. Remove the caches with:
    docker volume rm fishe-target fishe-cargo; docker image rm fishe-linux-dev

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/linux-check.ps1 -Live
#>
param([switch]$Live)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

docker build -q -t fishe-linux-dev "$PSScriptRoot\linux" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "docker build failed (is Docker Desktop running?)" }

$steps = @(
  "cargo fmt --all --check",
  "cargo clippy -p fishe-core --all-targets --locked -- -D warnings",
  "cargo test -p fishe-core --locked"
)
if ($Live) {
  # One at a time: they share the same target address and would count each other's packets.
  $names = "live_capture_sees_outgoing_udp", "live_tcp_quality_matches_ping", "live_process_mode_attributes_own_traffic", "live_all_traffic_labels_programs"
  foreach ($t in $names | ForEach-Object { "monitor::engine::live_tests::$_" }) {
    $steps += "timeout 120 cargo test -p fishe-core --locked -- --ignored --exact $t"
  }
}
docker run --rm -v "${root}:/src:ro" -v fishe-cargo:/usr/local/cargo/registry -v fishe-target:/target fishe-linux-dev bash -c ($steps -join " && ")
exit $LASTEXITCODE
