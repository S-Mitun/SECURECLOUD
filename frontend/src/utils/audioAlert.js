/**
 * SecureCloud - Synthetic Military Security Base Breach Alarm Sound Engine
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
   */
  playCriticalAlert() {
    if (this.isMuted) return;
    this.init();
    if (!this.audioCtx) return;

    if (this.isPlaying) {
      this.stopAlarm();
    }

    try {
      if (this.audioCtx.state === 'suspended') {
        this.audioCtx.resume();
      }

      this.isPlaying = true;
      const now = this.audioCtx.currentTime;

      // Master Gain
      const masterGain = this.audioCtx.createGain();
      masterGain.gain.setValueAtTime(0.3, now);
      masterGain.connect(this.audioCtx.destination);

      // Primary Siren Oscillator (Sweeping Sawtooth 650Hz to 1150Hz)
      const osc1 = this.audioCtx.createOscillator();
      osc1.type = 'sawtooth';

      // Sweep frequency over 3 seconds (3 cycles of 1 second each)
      for (let i = 0; i < 3; i++) {
        const cycleStart = now + i * 1.0;
        osc1.frequency.setValueAtTime(650, cycleStart);
        osc1.frequency.linearRampToValueAtTime(1150, cycleStart + 0.5);
        osc1.frequency.linearRampToValueAtTime(650, cycleStart + 1.0);
      }

      // Secondary Warning Square Sub-harmonic (440Hz / 880Hz alert tone)
      const osc2 = this.audioCtx.createOscillator();
      const gain2 = this.audioCtx.createGain();
      osc2.type = 'square';
      gain2.gain.setValueAtTime(0.12, now);

      for (let i = 0; i < 3; i++) {
        const cycleStart = now + i * 1.0;
        osc2.frequency.setValueAtTime(440, cycleStart);
        osc2.frequency.setValueAtTime(880, cycleStart + 0.5);
      }

      osc1.connect(masterGain);
      osc2.connect(gain2);
      gain2.connect(masterGain);

      osc1.start(now);
      osc2.start(now);

      // Schedule exact 3.0-second automatic shutoff
      osc1.stop(now + 3.0);
      osc2.stop(now + 3.0);

      this.stopTimeout = setTimeout(() => {
        this.isPlaying = false;
      }, 3000);
    } catch (e) {
      console.warn("Audio Context playback prevented by browser autoplay policy until user interaction:", e);
      this.isPlaying = false;
    }
  }
}

export const audioAlertSystem = new AudioAlertSystem();
