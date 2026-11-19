# Busyness detection

Fishe answers *"is traffic to this host getting busier?"* rather than *"is it
fast?"*. 2 MB/s is quiet for a video CDN and a storm for a game server, so
fixed thresholds don't work. Instead, `BusyDetector`
(`crates/fishe-core/src/monitor/gauge.rs`) learns what's normal for the target and
measures the current traffic against it.

## Algorithm

Every tick (Δt ≈ 0.25 s) the detector receives the total rate *r* (inbound +
outbound, bytes/s):

```
smoothed      ← EWMA(smoothed, r, τ = smoothingSecs)                      fast: 0.6 s
ln(baseline)  ← EWMA(ln(baseline), ln(smoothed), τ = riseSecs  if smoothed > baseline
                                                     fallSecs  otherwise)  slow
                (only while smoothed ≥ idleFloorBps; frozen when idle)
ratio         = smoothed / max(baseline, baselineFloorBps)
```

with `EWMA(prev, x, τ) = prev + (1 − e^(−Δt/τ)) · (x − prev)`, which is
frame-rate independent.

During the first `warmupSecs` the baseline is the plain running mean, so the
first few seconds give a sensible reference.

### Why the log domain

Traffic spans orders of magnitude, so the baseline should move by *factors*.
This came out of a real capture. With a linear average, one 5-second download
at ~100× the normal rate pulled "normal" from ~100 kb/s to ~3 Mb/s, and every
moderate burst in the following minute then read as *calm*. Averaging
`ln(rate)` moves the baseline by about 1.5× for the same burst (test
`short_burst_does_not_inflate_baseline`).

### Why freeze while idle

If a host goes silent for a minute, the silence shouldn't become the new
"normal", or its next ordinary exchange would register as a spike. The
baseline only adapts while traffic is above `idleFloorBps`
(test `baseline_frozen_while_idle`).

### Levels

| Level | Condition | UI |
|---|---|---|
| **Idle** | `smoothed < idleFloorBps` | gray, flat line icon |
| **Calm** | `ratio < busyRatio` | sea blue, single wave |
| **Busy** | `busyRatio ≤ ratio < spikeRatio` | amber, double wave |
| **Spike** | `ratio ≥ spikeRatio` | red, lightning bolt, pulsing |

**Hysteresis:** stepping *up* is immediate; stepping *down* requires the ratio
to fall below 80% of the threshold that triggered the current level. That
stops the badge flickering when the ratio hovers around a boundary.

### Why the baseline rises slower than it falls

- **Slow rise** (τ = 60 s by default): a burst stays visible as a burst
  instead of instantly becoming "the new normal".
- **Faster fall** (τ = 20 s): when a heavy period ends, the reference relaxes
  so the next increase is noticed.
- **Sustained** heavier traffic *does* become normal after a few minutes.
  That is intended: the gauge measures change, not volume. The absolute rate
  is always shown on the dial and in the tiles.

### Baseline floor

`baselineFloorBps` (2 kB/s) stops a near-silent connection from producing
"spikes" out of a handful of packets: 300 B/s → 1.5 kB/s is 5×, but it is
still compared against 2 kB/s and stays calm.

## Defaults and presets

| Parameter | Default | Sensitive | Balanced | Relaxed |
|---|---|---|---|---|
| `busyRatio` | 2.0 | 1.5 | 2.0 | 3.0 |
| `spikeRatio` | 5.0 | 3.0 | 5.0 | 8.0 |
| `baselineRiseSecs` | 60 | 120 | 60 | 30 |
| `baselineFallSecs` | 20 | | | |
| `smoothingSecs` | 0.6 | | | |
| `idleFloorBps` | 256 | | | |
| `baselineFloorBps` | 2048 | | | |
| `warmupSecs` | 5 | | | |

Presets are chosen in the UI (Settings page → Measurement → Sensitivity) and sent with `start_monitor`.
Any field may be overridden; the backend clamps unsafe values
(`GaugeConfig::sanitized`, e.g. `spikeRatio` is forced above `busyRatio`).

## How it shows up in the UI

- **Dial colour:** the value arc and needle take the level's colour.
- **Zones on the dial:** an outer ring marks where *busy* (amber) and *spike*
  (red) begin for the **current** baseline, and a white notch marks the
  baseline itself. The zones slide as the baseline adapts, so the needle
  entering the red ring *is* a spike.
- **"1.8× normal"** next to the level badge is the live `ratio`.
- **Chart:** the dashed line is the baseline; the strip under the time axis
  colours each tick by level, giving a timeline of when traffic got busier.

## Tests

`cargo test monitor::gauge` covers: silence → idle, steady → calm (ratio≈1),
a 20× jump → spike within 2 s, 3× → busy, sustained load becoming calm, the
floor suppressing tiny spikes, hysteresis, config sanitising, short bursts not inflating the baseline, and the idle freeze.
