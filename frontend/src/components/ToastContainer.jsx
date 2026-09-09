import React from 'react';
import { useApp } from '../context/AppContext';
import { CheckCircle2, AlertTriangle, AlertCircle, Info, X } from 'lucide-react';

export function ToastContainer() {
  const { toasts, removeToast } = useApp();

  if (!toasts.length) return null;

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {toasts.map((toast) => {
        let bgClass = 'bg-slate-900 border-slate-700 text-slate-200';
        let Icon = Info;
        let iconColor = 'text-sky-400';

        if (toast.type === 'success') {
          bgClass = 'bg-emerald-950/95 border-emerald-500/50 text-emerald-100';
          Icon = CheckCircle2;
          iconColor = 'text-emerald-400';
        } else if (toast.type === 'error') {
          bgClass = 'bg-red-950/95 border-red-500/50 text-red-100';
          Icon = AlertCircle;
          iconColor = 'text-red-400';
        } else if (toast.type === 'warning') {
          bgClass = 'bg-amber-950/95 border-amber-500/50 text-amber-100';
          Icon = AlertTriangle;
          iconColor = 'text-amber-400';
        }

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto p-3.5 rounded-xl border shadow-xl flex items-start gap-3 backdrop-blur transform transition duration-300 animate-slide-in ${bgClass}`}
          >
            <Icon className={`w-5 h-5 ${iconColor} shrink-0 mt-0.5`} />
            <div className="flex-1 text-xs sm:text-sm font-medium break-words">
              {toast.message}
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="text-slate-400 hover:text-white p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
