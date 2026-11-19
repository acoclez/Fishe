# Connection quality

How *good* a connection is, not just how busy: **round-trip time (RTT)**,
**jitter** and **retransmissions**, measured passively from the TCP traffic
Fishe already captures, plus an optional **continuous ping** for traffic TCP
can't time (UDP games, voice, QUIC).

## Where it shows

| Place | What |
|---|---|
| **Connection quality** card (below the traffic chart) | Round trip, jitter, retransmitted ↑ / ↓, an RTT chart over the chart window, the **Ping** button and the ping figures |
| Endpoints table, **RTT** column | Each endpoint's smoothed TCP RTT, ⟳ *n*% when ≥ 1% of what we sent was retransmitted, **◉** to ping it; a running ping replaces the value (tag *ping*) |
| Recordings | RTT per tick (chart in the replay, `rtt_ms` in the samples CSV), quality per endpoint (RTT column) and for the whole recording |

The card describes:

| Situation | Subject | Round trip | Jitter | Retransmitted |
|---|---|---|---|---|
| Host mode | the target | smoothed | yes | last 10 s |
| An endpoint focused (process / all mode) | that endpoint | smoothed | yes | this session |
| Otherwise (process / all mode) | all connections | average of the last 10 s | — (mixing peers makes it meaningless) | last 10 s |

Program focus (all-traffic mode) keeps the all-connections figures: quality
is measured per connection, not per program.

Colours: values stay neutral when good, turn amber, then red.

| | good | fair | poor |
|---|---|---|---|
| Round trip | < 80 ms | < 150 ms | ≥ 150 ms |
| Jitter | < 10 ms | < 30 ms | ≥ 30 ms |
| Retransmitted / lost | < 1% | < 3% | ≥ 3% |

## Passive TCP analysis

Every capture worker follows the TCP flows it sees (`monitor/quality.rs`),
in capture order, from the headers it already reads (192-byte snap length is
plenty; the payload length comes from the IP header).

**RTT samples**

| Sample | From → to |
|---|---|
| Connection we open | our SYN → their SYN-ACK |
| Connection they open | our SYN-ACK → their ACK |
| Data we send | our segment → the first ACK that covers it (the newest covered segment is timed, the one most likely to have triggered the ACK) |

Karn's rule: a retransmitted segment never gives a sample, and neither does
anything outstanding when a retransmission happens (its ACK would measure
the loss recovery, not the path). Samples over 10 s are discarded.

*Smoothed RTT* uses TCP's gain (1/8). *Jitter* is the RFC 3550 estimator:
the smoothed absolute difference between consecutive samples (gain 1/16).

**Retransmissions** are counted in payload bytes, per direction:

- **↑ sent**: data we had already sent (its sequence range is below the
  highest one sent). Usually loss on the way out, or a lost ACK.
- **↓ received**: data we had already received. Usually our ACK was lost,
  or the sender recovered a segment that never reached us.

Keep-alive probes (≤ 1 byte just below the edge) are not counted. The
percentage is retransmitted bytes ÷ all payload bytes in that direction.

**Attribution.** In process mode a packet's owner may not be known yet
(see [process-mode.md](process-mode.md)); its flow is tracked anyway, so the
handshake is still timed, and the measurements wait on the flow until a
packet of it is counted, or are dropped if it belongs to another program.

**Limits**

- Only TCP. UDP traffic (game servers, voice, QUIC / HTTP 3) has no
  sequence numbers to time: use **Ping**.
- A download gives few RTT samples (we mostly send ACKs, which aren't
  timed); uploads and request/response traffic give many.
- RTT includes the remote host's ACK delay; delayed ACKs (up to ~40–200 ms)
  can inflate single samples, which the minimum and the smoothing absorb.
- Large-send offload: Windows hands the NIC large segments; Fishe reads
  their length from the frame when the IP header says 0. Timing is per
  large segment.
- Loopback flows (both ends local) are not analysed.

## Ping

**Ping** (card) or **◉** (endpoint row) sends one ICMP echo per second to
that address through the Windows ICMP API (no admin), until stopped, for at
most 30 minutes, at most 4 addresses at once. A reply later than 1 s counts
as lost.

| Figure | |
|---|---|
| last | latest reply, or *lost* |
| avg | mean of the replies among the last 60 probes |
| min / max | over the whole ping |
| jitter | RFC 3550, between consecutive replies |
| loss | lost share of the last 60 probes |

Pings show as dots in the RTT chart, lost probes as red ticks on its axis.
Pings live in the backend: they survive switching views and sessions, and
stopped ones stay listed until **Clear**.

Reading it:

- **No replies at all** usually means the host ignores ping (common for
  game and voice servers); its traffic can still be fine.
- **Ping rising while you download or upload** (with TCP RTT steady) is
  queueing delay in your router or modem, "bufferbloat". For example, a
  ping of 24 ms can rise to 66 ms during a 10 MB download.
- ICMP may be answered by your router for some addresses (some ISP boxes
  answer for 1.1.1.1 themselves), giving a lower ping than the real path.

## Code map

| File | Role |
|---|---|
| `net/parse.rs` | `parse_tcp`: TCP seq/ack/flags/payload length |
| `monitor/quality.rs` | `FlowTracker` (per worker), `QualityDelta`, `RttStats`, `SessionQuality`, `EndpointQualityAcc` |
| `monitor/engine.rs` | tracking in workers; resolution of held packets settles flows; `Sample.quality` |
| `monitor/endpoints.rs` | per-endpoint quality, `EndpointRow.quality` |
| `route/ping.rs` | `PingBook`: continuous ping threads |
| `archive/*` | schema v3: `samples.rtt_ms`, `endpoints.quality_json`, summary `quality` |
| `src/lib/pages/live/QualityCard.svelte`, `src/lib/components/QualityChart.svelte` | card and chart |
| `src/lib/stores/pings.svelte.ts`, `src/lib/utils/quality.ts` | ping store; grades and formatting |
