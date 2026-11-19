//! "How busy is it?": the busyness detector.
//!
//! Absolute throughput alone doesn't say whether traffic *got busier*: 2 MB/s
//! is quiet for a video stream and a storm for a game server. The detector
//! therefore compares a fast-moving average of the current rate with a
//! slow-moving **baseline** that learns what's normal for this target.
//!
//! ```text
//!   smoothed     = EWMA(rate, τ = smoothing_secs)                  fast, follows the action
//!   ln(baseline) = EWMA(ln(baseline), ln(smoothed), τ = rise|fall) slow, multiplicative
//!   ratio        = smoothed / max(baseline, baseline_floor_bps)
//! ```
//!
//! The baseline adapts in the **log domain**: traffic spans orders of
//! magnitude, so it should move by *factors*. A linear average would let a
//! single 5-second burst at 100× drag "normal" up by ~8×, hiding every
//! moderate burst for the next minute; in log space the same burst moves it
//! by ~1.4×. The baseline is also **frozen while idle**, so a silent pause
//! doesn't make the next ordinary exchange look like a spike.
//!
//! | level   | condition                                   |
//! |---------|---------------------------------------------|
//! | `idle`  | smoothed < `idle_floor_bps`                 |
//! | `calm`  | ratio < `busy_ratio`                        |
//! | `busy`  | `busy_ratio` ≤ ratio < `spike_ratio`        |
//! | `spike` | ratio ≥ `spike_ratio`                       |
//!
//! Levels only step *down* once the ratio drops 20% below the threshold
//! that triggered them (hysteresis), so the UI doesn't flicker at a border.
//! During the first `warmup_secs` the baseline is the plain running mean,
//! which gives a sensible starting point.

use serde::{Deserialize, Serialize};

/// Busyness level shown by the UI. Ordered: idle < calm < busy < spike.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, specta::Type,
)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Idle = 0,
    Calm,
    Busy,
    Spike,
}

impl Level {
    /// Compact storage form (0..=3), used by the archive.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Level::Idle,
            1 => Level::Calm,
            2 => Level::Busy,
            _ => Level::Spike,
        }
    }
}

/// Tunables for [`BusyDetector`]. All rates are in bytes per second.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct GaugeConfig {
    /// ratio at which traffic counts as busy.
    pub busy_ratio: f64,
    /// ratio at which traffic counts as a spike.
    pub spike_ratio: f64,
    /// Below this smoothed rate the link is considered idle.
    pub idle_floor_bps: f64,
    /// Minimum baseline used in the ratio, so a near-silent baseline
    /// doesn't turn a single packet into a "spike".
    pub baseline_floor_bps: f64,
    /// Time constant of the fast average.
    pub smoothing_secs: f64,
    /// Time constant while the baseline climbs (slow → spikes stand out).
    pub baseline_rise_secs: f64,
    /// Time constant while the baseline drops.
    pub baseline_fall_secs: f64,
    /// Period during which the baseline is a plain running mean.
    pub warmup_secs: f64,
}

impl Default for GaugeConfig {
    fn default() -> Self {
        GaugeConfig {
            busy_ratio: 2.0,
            spike_ratio: 5.0,
            idle_floor_bps: 256.0,
            baseline_floor_bps: 2048.0,
            smoothing_secs: 0.6,
            baseline_rise_secs: 60.0,
            baseline_fall_secs: 20.0,
            warmup_secs: 5.0,
        }
    }
}

/// Per-field overrides of [`GaugeConfig`], as a `StartRequest` sends them;
/// fields left out keep their default.
#[derive(Debug, Clone, Copy, Default, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct GaugeOverrides {
    pub busy_ratio: Option<f64>,
    pub spike_ratio: Option<f64>,
    pub idle_floor_bps: Option<f64>,
    pub baseline_floor_bps: Option<f64>,
    pub smoothing_secs: Option<f64>,
    pub baseline_rise_secs: Option<f64>,
    pub baseline_fall_secs: Option<f64>,
    pub warmup_secs: Option<f64>,
}

impl GaugeOverrides {
    /// `base` with every given field replaced.
    pub fn apply(self, base: GaugeConfig) -> GaugeConfig {
        GaugeConfig {
            busy_ratio: self.busy_ratio.unwrap_or(base.busy_ratio),
            spike_ratio: self.spike_ratio.unwrap_or(base.spike_ratio),
            idle_floor_bps: self.idle_floor_bps.unwrap_or(base.idle_floor_bps),
            baseline_floor_bps: self.baseline_floor_bps.unwrap_or(base.baseline_floor_bps),
            smoothing_secs: self.smoothing_secs.unwrap_or(base.smoothing_secs),
            baseline_rise_secs: self.baseline_rise_secs.unwrap_or(base.baseline_rise_secs),
            baseline_fall_secs: self.baseline_fall_secs.unwrap_or(base.baseline_fall_secs),
            warmup_secs: self.warmup_secs.unwrap_or(base.warmup_secs),
        }
    }
}

impl GaugeConfig {
    /// Clamp user-provided values into a safe range.
    pub fn sanitized(mut self) -> Self {
        let d = GaugeConfig::default();
        let pos = |v: f64, fallback: f64| {
            if v.is_finite() && v > 0.0 {
                v
            } else {
                fallback
            }
        };
        self.busy_ratio = pos(self.busy_ratio, d.busy_ratio).max(1.05);
        self.spike_ratio = pos(self.spike_ratio, d.spike_ratio).max(self.busy_ratio * 1.05);
        self.idle_floor_bps = pos(self.idle_floor_bps, d.idle_floor_bps);
        self.baseline_floor_bps = pos(self.baseline_floor_bps, d.baseline_floor_bps);
        self.smoothing_secs = pos(self.smoothing_secs, d.smoothing_secs).clamp(0.1, 30.0);
        self.baseline_rise_secs =
            pos(self.baseline_rise_secs, d.baseline_rise_secs).clamp(1.0, 3600.0);
        self.baseline_fall_secs =
            pos(self.baseline_fall_secs, d.baseline_fall_secs).clamp(1.0, 3600.0);
        self.warmup_secs = if self.warmup_secs.is_finite() {
            self.warmup_secs.clamp(0.0, 120.0)
        } else {
            d.warmup_secs
        };
        self
    }
}

/// Output of one detector step.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reading {
    pub smoothed_bps: f64,
    pub baseline_bps: f64,
    pub ratio: f64,
    pub level: Level,
}

/// Stateful busyness detector; feed it one rate per tick.
#[derive(Debug, Clone)]
pub struct BusyDetector {
    cfg: GaugeConfig,
    smoothed: f64,
    baseline: f64,
    elapsed: f64,
    warm_sum: f64,
    warm_ticks: u32,
    level: Level,
    primed: bool,
}

impl BusyDetector {
    pub fn new(cfg: GaugeConfig) -> Self {
        BusyDetector {
            cfg: cfg.sanitized(),
            smoothed: 0.0,
            baseline: 0.0,
            elapsed: 0.0,
            warm_sum: 0.0,
            warm_ticks: 0,
            level: Level::Idle,
            primed: false,
        }
    }

    /// Advance by `dt_secs` with the instantaneous `rate_bps` over that period.
    pub fn update(&mut self, rate_bps: f64, dt_secs: f64) -> Reading {
        let rate = if rate_bps.is_finite() {
            rate_bps.max(0.0)
        } else {
            0.0
        };
        let dt = dt_secs.max(1e-3);
        self.elapsed += dt;

        if self.primed {
            self.smoothed = ewma(self.smoothed, rate, dt, self.cfg.smoothing_secs);
        } else {
            self.smoothed = rate;
            self.primed = true;
        }

        if self.elapsed <= self.cfg.warmup_secs {
            self.warm_sum += rate;
            self.warm_ticks += 1;
            self.baseline = self.warm_sum / f64::from(self.warm_ticks);
        } else if self.smoothed >= self.cfg.idle_floor_bps {
            let tau = if self.smoothed > self.baseline {
                self.cfg.baseline_rise_secs
            } else {
                self.cfg.baseline_fall_secs
            };
            let floor = self.cfg.idle_floor_bps;
            let log_base = ewma(
                self.baseline.max(floor).ln(),
                self.smoothed.max(floor).ln(),
                dt,
                tau,
            );
            self.baseline = log_base.exp();
        }

        let ratio = self.smoothed / self.baseline.max(self.cfg.baseline_floor_bps);
        self.level = self.next_level(ratio);

        Reading {
            smoothed_bps: self.smoothed,
            baseline_bps: self.baseline,
            ratio,
            level: self.level,
        }
    }

    fn next_level(&self, ratio: f64) -> Level {
        const HYSTERESIS: f64 = 0.8;
        let c = &self.cfg;

        let raw = if self.smoothed < c.idle_floor_bps {
            Level::Idle
        } else if ratio >= c.spike_ratio {
            Level::Spike
        } else if ratio >= c.busy_ratio {
            Level::Busy
        } else {
            Level::Calm
        };

        // Stepping up (or to idle) is immediate; stepping down needs margin.
        if raw >= self.level || raw == Level::Idle {
            return raw;
        }
        match self.level {
            Level::Spike if ratio >= c.spike_ratio * HYSTERESIS => Level::Spike,
            Level::Spike | Level::Busy if ratio >= c.busy_ratio * HYSTERESIS => Level::Busy,
            _ => raw,
        }
    }
}

/// Exponentially-weighted moving average with time constant `tau` seconds.
fn ewma(prev: f64, sample: f64, dt: f64, tau: f64) -> f64 {
    let alpha = 1.0 - (-dt / tau).exp();
    prev + alpha * (sample - prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DT: f64 = 0.25;

    fn run(det: &mut BusyDetector, rate: f64, secs: f64) -> Reading {
        let mut last = det.update(rate, DT);
        for _ in 1..(secs / DT) as usize {
            last = det.update(rate, DT);
        }
        last
    }

    #[test]
    fn silence_is_idle() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        assert_eq!(run(&mut d, 0.0, 10.0).level, Level::Idle);
    }

    #[test]
    fn steady_traffic_is_calm() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        let r = run(&mut d, 50_000.0, 30.0);
        assert_eq!(r.level, Level::Calm);
        assert!((r.ratio - 1.0).abs() < 0.05, "ratio {}", r.ratio);
    }

    #[test]
    fn sudden_jump_becomes_spike_quickly() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        run(&mut d, 50_000.0, 30.0);
        let r = run(&mut d, 1_000_000.0, 2.0);
        assert_eq!(r.level, Level::Spike, "{r:?}");
    }

    #[test]
    fn moderate_increase_is_busy() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        run(&mut d, 50_000.0, 30.0);
        let r = run(&mut d, 150_000.0, 4.0);
        assert_eq!(r.level, Level::Busy, "{r:?}");
    }

    #[test]
    fn sustained_load_becomes_new_normal() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        run(&mut d, 50_000.0, 30.0);
        let r = run(&mut d, 500_000.0, 300.0);
        assert_eq!(r.level, Level::Calm, "{r:?}");
    }

    #[test]
    fn baseline_floor_prevents_tiny_spikes() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        run(&mut d, 300.0, 30.0);
        // 1.5 KB/s is 5x the baseline, but under the 2 KB/s floor.
        let r = run(&mut d, 1_500.0, 5.0);
        assert_ne!(r.level, Level::Spike, "{r:?}");
    }

    #[test]
    fn hysteresis_holds_spike_near_threshold() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        run(&mut d, 50_000.0, 30.0);
        run(&mut d, 1_000_000.0, 2.0);
        // Force a ratio just below the spike threshold but above 80% of it.
        let base = d.baseline.max(d.cfg.baseline_floor_bps);
        d.smoothed = base * 4.5;
        assert_eq!(d.next_level(4.5), Level::Spike);
        assert_eq!(d.next_level(3.0), Level::Busy);
    }

    #[test]
    fn sanitize_fixes_inverted_thresholds() {
        let c = GaugeConfig {
            busy_ratio: 6.0,
            spike_ratio: 3.0,
            ..Default::default()
        }
        .sanitized();
        assert!(c.spike_ratio > c.busy_ratio);
        let c = GaugeConfig {
            smoothing_secs: f64::NAN,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.smoothing_secs, GaugeConfig::default().smoothing_secs);
    }

    /// Regression from a real capture: a 5 s download at ~100× used to
    /// drag the (linear) baseline up so far that later bursts read as calm.
    #[test]
    fn short_burst_does_not_inflate_baseline() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        run(&mut d, 50_000.0, 30.0);
        run(&mut d, 5_000_000.0, 5.0);
        run(&mut d, 50_000.0, 5.0);
        // A linear EWMA ends up near 450 kB/s here.
        assert!(
            d.baseline < 100_000.0,
            "baseline inflated to {}",
            d.baseline
        );
        let r = run(&mut d, 200_000.0, 4.0);
        assert_eq!(r.level, Level::Busy, "{r:?}");
    }

    #[test]
    fn baseline_frozen_while_idle() {
        let mut d = BusyDetector::new(GaugeConfig::default());
        run(&mut d, 50_000.0, 30.0);
        let before = d.baseline;
        assert_eq!(run(&mut d, 0.0, 60.0).level, Level::Idle);
        // It drifts only while the smoothed rate decays to idle (~3 s), then freezes.
        assert!(d.baseline > before * 0.5, "{before} -> {}", d.baseline);
        let frozen = d.baseline;
        run(&mut d, 0.0, 60.0);
        assert_eq!(d.baseline, frozen);
        let r = run(&mut d, 50_000.0, 3.0);
        assert_eq!(r.level, Level::Calm, "{r:?}");
    }
}
