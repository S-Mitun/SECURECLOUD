/**
 * SecureCloud 2.0 - Synthetic Military Security Base Breach Alarm Sound Engine
 * Synthesizes an authentic 3-second dual-tone oscillating base breach klaxon/alarm using Web Audio API.
 * Automatically halts audio playback precisely after 3.0 seconds.
 */

class AudioAlertSystem {
  constructor() {
    this.audioCtx = null;
    this.isMuted = false;
    this.isPlaying = false;
    this.stopTimeout = null;
  }

  init() {
    if (!this.audioCtx) {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.audioCtx = new AudioContext();
      }
    }
    if (this.audioCtx && this.audioCtx.state === 'suspended') {
      this.audioCtx.resume();
    }
  }

  toggleMute() {
    this.isMuted = !this.isMuted;
    if (this.isMuted && this.isPlaying) {
      this.stopAlarm();
    }
    return this.isMuted;
  }

  stopAlarm() {
    if (this.audioCtx) {
      try {
        // Suspend/close context or stop active nodes
        if (this.audioCtx.state === 'running') {
          this.audioCtx.suspend();
        }
      } catch (e) {}
    }
    this.isPlaying = false;
    if (this.stopTimeout) {
      clearTimeout(this.stopTimeout);
      this.stopTimeout = null;
    }
  }

  /**
   * Plays a high-urgency 3-second military security base breach alarm.
   * Features rapid frequency-swept klaxon pulses that stop automatically after 3 seconds.
   */
  playCriticalAlert() {
    if (this.isMuted) return;
    this.init();
    if (!this.audioCtx) return;

    // Reset if currently playing
    if (this.isPlaying) {
      this.stopAlarm();
      this.init();
    }
    this.isPlaying = true;

    try {
      const now = this.audioCtx.currentTime;
      const totalDuration = 3.0; // Exactly 3.0 seconds

      const masterGain = this.audioCtx.createGain();
      masterGain.gain.setValueAtTime(0.3, now);
      masterGain.gain.setValueAtTime(0.3, now + 2.85);
      masterGain.gain.exponentialRampToValueAtTime(0.0001, now + totalDuration);
      masterGain.connect(this.audioCtx.destination);

      // Create 3 cycles of dual-tone military base breach sweeps
      // Cycle 1: 0.0s - 0.9s | Cycle 2: 1.0s - 1.9s | Cycle 3: 2.0s - 2.9s
      const cycles = [
        { start: now + 0.0, end: now + 0.88 },
        { start: now + 0.98, end: now + 1.86 },
        { start: now + 1.96, end: now + 2.85 }
      ];

      cycles.forEach(c => {
        // Primary Carrier: Oscillates between 750Hz and 1250Hz (Klaxon Sweep)
        const osc1 = this.audioCtx.createOscillator();
        const gain1 = this.audioCtx.createGain();
        osc1.type = 'sawtooth';
        osc1.frequency.setValueAtTime(750, c.start);
        osc1.frequency.linearRampToValueAtTime(1250, c.start + (c.end - c.start) * 0.5);
        osc1.frequency.linearRampToValueAtTime(800, c.end);

        gain1.gain.setValueAtTime(0.01, c.start);
        gain1.gain.linearRampToValueAtTime(0.35, c.start + 0.05);
        gain1.gain.setValueAtTime(0.35, c.end - 0.05);
        gain1.gain.exponentialRampToValueAtTime(0.001, c.end);

        osc1.connect(gain1);
        gain1.connect(masterGain);
        osc1.start(c.start);
        osc1.stop(c.end);

        // Secondary Harmonic Sub-Tone: 450Hz square for military base resonance
        const osc2 = this.audioCtx.createOscillator();
        const gain2 = this.audioCtx.createGain();
        osc2.type = 'square';
        osc2.frequency.setValueAtTime(450, c.start);
        osc2.frequency.linearRampToValueAtTime(650, c.start + (c.end - c.start) * 0.5);
        osc2.frequency.linearRampToValueAtTime(450, c.end);

        gain2.gain.setValueAtTime(0.01, c.start);
        gain2.gain.linearRampToValueAtTime(0.18, c.start + 0.05);
        gain2.gain.setValueAtTime(0.18, c.end - 0.05);
        gain2.gain.exponentialRampToValueAtTime(0.001, c.end);

        osc2.connect(gain2);
        gain2.connect(masterGain);
        osc2.start(c.start);
        osc2.stop(c.end);
      });

      // Strict Automatic Stop after 3.0 seconds
      this.stopTimeout = setTimeout(() => {
        this.isPlaying = false;
      }, 3050);

    } catch (e) {
      console.warn("Military Base Breach Alarm Audio error:", e);
      this.isPlaying = false;
    }
  }
}

window.audioAlertSystem = new AudioAlertSystem();
