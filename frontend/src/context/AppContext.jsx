import React, { createContext, useContext, useState, useEffect } from 'react';
import { audioAlertSystem } from '../utils/audioAlert';
import { adminApi } from '../api/adminApi';
import { useAuth } from './AuthContext';

const AppContext = createContext(null);

export function AppProvider({ children }) {
  const { user, isAdmin } = useAuth();
  const [toasts, setToasts] = useState([]);
  const [activeModal, setActiveModal] = useState(null);
  const [modalData, setModalData] = useState(null);
  const [criticalAlert, setCriticalAlert] = useState(null);
  const [isAudioMuted, setIsAudioMuted] = useState(false);
  const [fileScanStates, setFileScanStates] = useState({});
  const [telemetry, setTelemetry] = useState(null);
  const [sentinelState, setSentinelState] = useState(null);

  // Toast System
  const showToast = (message, type = 'info') => {
    const id = Date.now() + Math.random().toString(36).substring(2, 6);
    setToasts((prev) => [...prev, { id, message, type }]);

    setTimeout(() => {
      removeToast(id);
    }, 4500);
  };

  const removeToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  // Modal Manager
  const openModal = (modalName, data = null) => {
    setActiveModal(modalName);
    setModalData(data);
  };

  const closeModal = () => {
    setActiveModal(null);
    setModalData(null);
  };

  // Global Synthesized Voice Announcement (Web Speech API)
  const speakVoice = (text) => {
    if (isAudioMuted) return;
    try {
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel();
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1.05;
        utterance.pitch = 1.0;
        utterance.volume = 0.95;
        window.speechSynthesis.speak(utterance);
      }
    } catch (e) {
      console.warn("Speech synthesis notice:", e);
    }
  };

  // Critical Base Breach Alert Trigger (Phase 3 Malware Trigger + Siren + Voice)
  const triggerCriticalAlert = async (threatData) => {
    setCriticalAlert(threatData);
    if (!isAudioMuted) {
      audioAlertSystem.playCriticalAlert();
    }
    
    // Global Synthesized Voice alert - starts strictly AFTER the 3.0-second military siren alarm completes
    setTimeout(() => {
      speakVoice(`Critical alert! Malicious payload detected in ${threatData?.filename || 'file'}. Sentinel VM Phase 3 intrusion containment active.`);
    }, 3150);

    // Simultaneously switch Sentinel VM to Phase 3
    try {
      const res = await adminApi.simulateSentinelPhase('ALERT_TRIGGER');
      if (res && res.sentinel_state) {
        setSentinelState(res.sentinel_state);
      }
    } catch (err) {
      console.warn("Sentinel VM Phase 3 transition notice:", err);
    }
  };

  // Acknowledge Threat Incident -> Transitions Sentinel VM from Phase 3 to Phase 4
  const dismissCriticalAlert = async () => {
    setCriticalAlert(null);
    audioAlertSystem.stopAlarm();

    // Voice announcement for Phase 4 transition
    speakVoice('Threat incident acknowledged by Security Operator. Sentinel VM transitioned to Phase 4 active containment protocol.');
    showToast('Threat incident acknowledged. Sentinel VM shifted from Phase 3 to Phase 4 (Active Containment).', 'info');

    // Simultaneously switch Sentinel VM to Phase 4
    try {
      const res = await adminApi.simulateSentinelPhase('ACKNOWLEDGE');
      if (res && res.sentinel_state) {
        setSentinelState(res.sentinel_state);
      }
    } catch (err) {
      console.warn("Sentinel VM Phase 4 transition notice:", err);
    }
  };

  const toggleAudioMute = () => {
    const muted = audioAlertSystem.toggleMute();
    setIsAudioMuted(muted);
    if (muted && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
    return muted;
  };

  // Live Multi-Stage File Scanning System
  const updateFileScanProgress = (fileId, scanState) => {
    setFileScanStates((prev) => ({
      ...prev,
      [fileId]: scanState
    }));
  };

  // Live Telemetry Poller (Only active for ADMIN role)
  useEffect(() => {
    let interval = null;
    if (isAdmin) {
      const fetchTelemetry = async () => {
        try {
          const res = await adminApi.getTelemetry();
          setTelemetry({
            cpu_percent: res.cpu_percent,
            ram_percent: res.ram_percent,
            ram_used_gb: res.ram_used_gb,
            disk_percent: res.disk_percent,
            net_in_mb: res.net_in_mb
          });
          if (res.sentinel) {
            setSentinelState(res.sentinel);
          }
        } catch {}
      };

      fetchTelemetry();
      interval = setInterval(fetchTelemetry, 2500);
    } else {
      setTelemetry(null);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isAdmin]);

  const value = {
    toasts,
    showToast,
    removeToast,
    activeModal,
    modalData,
    openModal,
    closeModal,
    criticalAlert,
    triggerCriticalAlert,
    dismissCriticalAlert,
    acknowledgeCriticalAlert: dismissCriticalAlert,
    speakVoice,
    isAudioMuted,
    toggleAudioMute,
    fileScanStates,
    updateFileScanProgress,
    telemetry,
    sentinelState,
    setSentinelState
  };

  return (
    <AppContext.Provider value={value}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
}
