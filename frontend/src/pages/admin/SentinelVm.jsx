import React, { useEffect, useRef, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { 
  ShieldAlert, ShieldCheck, Zap, AlertTriangle, CheckCircle2, 
  RefreshCw, Volume2, VolumeX, Activity, Share2, Bug, FileText, Lock, Radio, Mic, MicOff
} from 'lucide-react';

export function SentinelVm() {
  const { telemetry, sentinelState, triggerCriticalAlert, dismissCriticalAlert, showToast, isAudioMuted, toggleAudioMute } = useApp();
  const canvasRef = useRef(null);

  const [activePhase, setActivePhase] = useState('NORMAL');
  const [phaseLoading, setPhaseLoading] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(true);
  const [waveformHistory, setWaveformHistory] = useState({
    scanVelocity: Array(45).fill(25),
    threatScore: Array(45).fill(15),
    activeShares: Array(45).fill(20)
  });

  // Auto-sync Sentinel phase when changed globally across application
  useEffect(() => {
    if (sentinelState?.phase) {
      const p = sentinelState.phase.toUpperCase();
      if (p.includes('PHASE 1') || p.includes('NORMAL')) setActivePhase('NORMAL');
      else if (p.includes('PHASE 2') || p.includes('LOAD')) setActivePhase('LOAD');
      else if (p.includes('PHASE 3') || p.includes('ALERT') || p.includes('94')) setActivePhase('ALERT_TRIGGER');
      else if (p.includes('PHASE 4') || p.includes('ACKNOWLEDGE') || p.includes('CONTAINMENT')) setActivePhase('ACKNOWLEDGE');
      else if (p.includes('PHASE 5') || p.includes('RESOLVE')) setActivePhase('RESOLVE');
    }
  }, [sentinelState]);

  // Text-to-Speech synthesizer for SOC Sentinel Voice Announcements
  const speakVoice = (text) => {
    if (!voiceEnabled || isAudioMuted) return;
    try {
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel(); // Cancel previous speech
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1.05;
        utterance.pitch = 1.0;
        utterance.volume = 0.9;
        window.speechSynthesis.speak(utterance);
      }
    } catch (e) {
      console.warn("Speech synthesis notice:", e);
    }
  };

  const handleSimulatePhase = async (phase) => {
    setPhaseLoading(true);
    try {
      const res = await adminApi.simulateSentinelPhase(phase);
      setActivePhase(phase);

      if (phase === 'NORMAL' || phase === 'PHASE_1') {
        showToast('Sentinel switched to Phase 1: Normal Operations', 'success');
        speakVoice('Sentinel telemetry online. Normal operations baseline.');
      } else if (phase === 'LOAD' || phase === 'PHASE_2') {
        showToast('Sentinel switched to Phase 2: Batch Upload Spike', 'info');
        speakVoice('Batch file upload surge detected. Workload increasing.');
      } else if (phase === 'ALERT_TRIGGER' || phase === 'PHASE_3') {
        showToast('Sentinel switched to Phase 3: Malware Ingress Triggered', 'error');
        // 1. Trigger the 3-second military base breach alarm sound and sequential voice
        triggerCriticalAlert({
          filename: 'sentinel-payload-trojan.exe',
          threat_score: 94.8,
          verdict: 'MALWARE_INTRUSION_CRITICAL'
        });
      } else if (phase === 'ACKNOWLEDGE' || phase === 'PHASE_4') {
        dismissCriticalAlert();
        showToast('Incident acknowledged by Operator.', 'info');
        speakVoice('Incident acknowledged by Security Operator. Investigation in progress.');
      } else if (phase === 'RESOLVE' || phase === 'PHASE_5') {
        dismissCriticalAlert();
        showToast('Threat quarantined and neutralized!', 'success');
        speakVoice('Threat isolated to Quarantine Vault. Sentinel VM telemetry normalized.');
      }
    } catch (err) {
      showToast(err.message || 'Phase simulation failed.', 'error');
    } finally {
      setPhaseLoading(false);
    }
  };

  const tickRef = useRef(0);

  // Continuous deterministic harmonic telemetry waveform animation loop (Zero Fake Random)
  useEffect(() => {
    const interval = setInterval(() => {
      tickRef.current += 1;
      const t = tickRef.current;
      const wave1 = Math.sin(t * 0.25);
      const wave2 = Math.cos(t * 0.18);

      setWaveformHistory((prev) => {
        let baseVelocity = 25;
        let baseThreat = 15;
        let baseShares = 20;

        if (activePhase === 'LOAD') {
          baseVelocity = 70 + wave1 * 10;
          baseThreat = 32 + wave2 * 6;
          baseShares = 42 + wave1 * 8;
        } else if (activePhase === 'ALERT_TRIGGER') {
          baseVelocity = 90 + wave1 * 6;
          baseThreat = 94 + wave2 * 4;
          baseShares = 60 + wave1 * 8;
        } else if (activePhase === 'ACKNOWLEDGE') {
          baseVelocity = 52 + wave1 * 6;
          baseThreat = 48 + wave2 * 5;
          baseShares = 38 + wave1 * 5;
        } else if (activePhase === 'RESOLVE') {
          baseVelocity = 28 + wave1 * 4;
          baseThreat = 10 + Math.abs(wave2) * 3;
          baseShares = 22 + wave1 * 4;
        } else {
          baseVelocity = 24 + wave1 * 4;
          baseThreat = 14 + wave2 * 3;
          baseShares = 20 + wave1 * 3;
        }

        return {
          scanVelocity: [...prev.scanVelocity.slice(1), Math.round(baseVelocity)],
          threatScore: [...prev.threatScore.slice(1), Math.round(baseThreat)],
          activeShares: [...prev.activeShares.slice(1), Math.round(baseShares)]
        };
      });
    }, 400);

    return () => clearInterval(interval);
  }, [activePhase]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;

    // Clear Background
    ctx.fillStyle = '#070d19';
    ctx.fillRect(0, 0, width, height);

    // Draw Grid Lines
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let y = 0; y <= height; y += height / 4) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    const drawLine = (data, color) => {
      ctx.strokeStyle = color;
      ctx.lineWidth = 2.5;
      ctx.beginPath();

      const step = width / (data.length - 1);
      data.forEach((val, i) => {
        const x = i * step;
        const y = height - (val / 100) * height;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    };

    drawLine(waveformHistory.scanVelocity, '#38bdf8'); // Sky Blue: Virus Scan Velocity
    drawLine(waveformHistory.threatScore, '#ef4444');   // Red: Threat Score Radar
    drawLine(waveformHistory.activeShares, '#10b981');  // Green: Active Shared Endpoints
  }, [waveformHistory]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-sky-500/40 bg-gradient-to-r from-slate-900 via-sky-950/20 to-slate-900 shadow-2xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-sky-950/90 border border-sky-500/50 text-sky-400">
              <ShieldAlert className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
                Sentinel Threat & File Security Operations
                <span className="px-2 py-0.5 bg-sky-950 border border-sky-500/40 text-sky-300 text-[10px] rounded font-mono">
                  LIVE TELEMETRY
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Real-time LightGBM virus scan velocity, active shared links expiration streams, and malware quarantine radar with audio dispatch.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Voice Synthesis Toggle */}
            <button
              onClick={() => {
                const next = !voiceEnabled;
                setVoiceEnabled(next);
                showToast(next ? 'Sentinel Voice Announcements Enabled' : 'Voice Announcements Muted', 'info');
              }}
              className={`p-2 rounded-lg border text-xs font-semibold flex items-center gap-1.5 transition ${
                voiceEnabled
                  ? 'bg-sky-950/80 text-sky-300 border-sky-500/40'
                  : 'bg-slate-900 text-slate-500 border-slate-800'
              }`}
              title="Toggle SOC Sentinel Voice Announcements"
            >
              {voiceEnabled ? <Mic className="w-4 h-4 text-sky-400" /> : <MicOff className="w-4 h-4" />}
              <span>Voice: {voiceEnabled ? 'ON' : 'OFF'}</span>
            </button>

            {/* Siren Alarm Toggle */}
            <button
              onClick={toggleAudioMute}
              className={`p-2 rounded-lg border text-xs font-semibold flex items-center gap-1.5 transition ${
                isAudioMuted
                  ? 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                  : 'bg-red-950/80 text-red-300 border-red-500/40 hover:bg-red-900'
              }`}
            >
              {isAudioMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4 text-red-400 animate-pulse" />}
              <span>{isAudioMuted ? 'Muted' : '3s Alarm Active'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Live Waveform Canvas */}
      <div className="glass-card p-6 border border-slate-800 shadow-2xl space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-sky-400 animate-pulse" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Live Threat Scan Velocity & Shared Link Stream (Oscilloscope)
            </h3>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-sky-400">
              <span className="w-2.5 h-2.5 rounded-full bg-sky-400"></span> Virus Scan Velocity
            </span>
            <span className="flex items-center gap-1.5 text-red-400">
              <span className="w-2.5 h-2.5 rounded-full bg-red-400"></span> Threat Score Radar
            </span>
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span> Active Shared Links
            </span>
          </div>
        </div>

        <div className="sentinel-waveform-canvas overflow-hidden rounded-xl border border-slate-800 p-2 shadow-inner">
          <canvas
            ref={canvasRef}
            width={900}
            height={200}
            className="w-full h-48 block"
          />
        </div>
      </div>

      {/* Threat Phase Simulator Buttons (Phases 1 through 5) */}
      <div className="glass-card p-6 border border-slate-800 shadow-2xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
            Sentinel SOC Workload & Threat Simulation Controls
          </h3>
          <span className="text-xs font-mono text-sky-400">
            Active Status: <strong className="text-white uppercase">{activePhase}</strong>
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
          {/* Phase 1 */}
          <button
            onClick={() => handleSimulatePhase('NORMAL')}
            disabled={phaseLoading}
            className={`p-3.5 border rounded-xl text-left transition ${
              activePhase === 'NORMAL'
                ? 'bg-emerald-950/80 border-emerald-500 text-white shadow-lg'
                : 'bg-slate-900 hover:bg-slate-800 border-slate-800 text-slate-300'
            }`}
          >
            <div className="text-[10px] text-emerald-400 font-mono font-bold">PHASE 1</div>
            <div className="text-xs font-bold text-white mt-1">Normal Stream</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Low threat volume (32%)</div>
          </button>

          {/* Phase 2 */}
          <button
            onClick={() => handleSimulatePhase('LOAD')}
            disabled={phaseLoading}
            className={`p-3.5 border rounded-xl text-left transition ${
              activePhase === 'LOAD'
                ? 'bg-amber-950/80 border-amber-500 text-white shadow-lg'
                : 'bg-slate-900 hover:bg-slate-800 border-slate-800 text-slate-300'
            }`}
          >
            <div className="text-[10px] text-amber-400 font-mono font-bold">PHASE 2</div>
            <div className="text-xs font-bold text-white mt-1">Batch File Load</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Scanning surge (68%)</div>
          </button>

          {/* Phase 3 */}
          <button
            onClick={() => handleSimulatePhase('ALERT_TRIGGER')}
            disabled={phaseLoading}
            className={`p-3.5 border rounded-xl text-left transition ${
              activePhase === 'ALERT_TRIGGER'
                ? 'bg-red-950 border-red-500 text-white shadow-lg animate-pulse'
                : 'bg-slate-900 hover:bg-red-950 border-slate-800 text-slate-300'
            }`}
          >
            <div className="text-[10px] text-red-400 font-mono font-bold">PHASE 3</div>
            <div className="text-xs font-bold text-red-300 mt-1">Malware Trigger</div>
            <div className="text-[10px] text-slate-400 mt-0.5">3s Siren Alert (94%)</div>
          </button>

          {/* Phase 4 */}
          <button
            onClick={() => handleSimulatePhase('ACKNOWLEDGE')}
            disabled={phaseLoading}
            className={`p-3.5 border rounded-xl text-left transition ${
              activePhase === 'ACKNOWLEDGE'
                ? 'bg-sky-950/80 border-sky-500 text-white shadow-lg'
                : 'bg-slate-900 hover:bg-slate-800 border-slate-800 text-slate-300'
            }`}
          >
            <div className="text-[10px] text-sky-400 font-mono font-bold">PHASE 4</div>
            <div className="text-xs font-bold text-white mt-1">Acknowledge Incident</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Operator confirmed (55%)</div>
          </button>

          {/* Phase 5 */}
          <button
            onClick={() => handleSimulatePhase('RESOLVE')}
            disabled={phaseLoading}
            className={`p-3.5 border rounded-xl text-left transition ${
              activePhase === 'RESOLVE'
                ? 'bg-emerald-950/80 border-emerald-500 text-white shadow-lg'
                : 'bg-slate-900 hover:bg-slate-800 border-slate-800 text-slate-300'
            }`}
          >
            <div className="text-[10px] text-emerald-400 font-mono font-bold">PHASE 5</div>
            <div className="text-xs font-bold text-white mt-1">Quarantine & Resolve</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Threat neutralized (30%)</div>
          </button>
        </div>
      </div>
    </div>
  );
}
