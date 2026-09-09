import React from 'react';
import { HardDrive } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

export function QuotaBar({ 
  usedFormatted, 
  quotaFormatted, 
  usedBytes, 
  quotaBytes,
  files = null 
}) {
  const { user } = useAuth();

  // If files array passed, calculate live storage
  let calculatedUsedBytes = usedBytes;
  if (calculatedUsedBytes === undefined || calculatedUsedBytes === null) {
    if (files && Array.isArray(files) && files.length > 0) {
      calculatedUsedBytes = files.reduce((acc, f) => acc + (f.file_size || f.size || 0), 0);
    } else if (user?.used_quota_bytes !== undefined && user?.used_quota_bytes !== null) {
      calculatedUsedBytes = user.used_quota_bytes;
    } else {
      calculatedUsedBytes = 0;
    }
  }

  const effectiveQuotaBytes = quotaBytes ?? user?.quota_bytes ?? 10737418240; // 10 GB default
  const effectiveUsedFormatted = usedFormatted ?? (calculatedUsedBytes > 0 ? formatBytes(calculatedUsedBytes) : (user?.used_quota_formatted || '0 B'));
  const effectiveQuotaFormatted = quotaFormatted ?? user?.quota_formatted ?? formatBytes(effectiveQuotaBytes);

  const percent = effectiveQuotaBytes > 0 
    ? Math.min(100, Math.max(0, ((calculatedUsedBytes / effectiveQuotaBytes) * 100))) 
    : 0;
  
  const displayPercent = percent < 0.1 && percent > 0 ? '<0.1' : percent.toFixed(1);

  let barColor = 'bg-sky-500';
  if (percent > 90) barColor = 'bg-red-500';
  else if (percent > 75) barColor = 'bg-amber-500';

  return (
    <div className="glass-card p-4">
      <div className="flex items-center justify-between text-xs font-semibold mb-2">
        <span className="flex items-center gap-1.5 text-slate-300">
          <HardDrive className="w-4 h-4 text-sky-400" /> Storage Quota
        </span>
        <span className="font-mono text-slate-300">
          {effectiveUsedFormatted} / {effectiveQuotaFormatted} ({displayPercent}%)
        </span>
      </div>
      <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
        <div
          className={`h-full ${barColor} transition-all duration-500 rounded-full`}
          style={{ width: `${Math.max(calculatedUsedBytes > 0 ? 1 : 0, percent)}%` }}
        />
      </div>
    </div>
  );
}
