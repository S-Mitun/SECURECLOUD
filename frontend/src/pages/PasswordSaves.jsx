import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { fileApi } from '../api/fileApi';
import { 
  KeyRound, Eye, EyeOff, Copy, Check, ShieldCheck, RefreshCw, Lock, ShieldAlert
} from 'lucide-react';

export function PasswordSaves() {
  const { showToast } = useApp();
  const [savedKeys, setSavedKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [visibleKeys, setVisibleKeys] = useState({});
  const [copiedId, setCopiedId] = useState(null);

  const loadSavedPasswords = async () => {
    setLoading(true);
    try {
      const data = await fileApi.listSavedPasswords();
      setSavedKeys(Array.isArray(data) ? data : (data.saved_passwords || []));
    } catch (err) {
      showToast(err.message || 'Failed to load saved confidential keys.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSavedPasswords();
  }, []);

  const toggleKeyVisibility = (id) => {
    setVisibleKeys((prev) => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const copyKey = (id, pin) => {
    navigator.clipboard.writeText(pin);
    setCopiedId(id);
    showToast('Decryption PIN copied to clipboard!', 'success');
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-emerald-500/40 bg-gradient-to-r from-slate-900 via-emerald-950/20 to-slate-900">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-emerald-950/90 border border-emerald-500/50 text-emerald-400">
              <KeyRound className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
                Confidential Password Saves & Recovery Keys
                <span className="px-2 py-0.5 bg-emerald-950 border border-emerald-500/50 text-emerald-300 text-[10px] rounded font-mono">
                  KEY VAULT
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                History of all your encrypted confidential files and their stored decryption PINs/keys.
              </p>
            </div>
          </div>
          <button
            onClick={loadSavedPasswords}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Keys
          </button>
        </div>
      </div>

      {/* Keys Table */}
      <div className="glass-card overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Encrypted File</th>
                <th>Encryption Standard</th>
                <th>Decryption PIN / Key</th>
                <th>Created Date (IST)</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="5" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-emerald-400" />
                    DECRYPTING KEY RECOVERY VAULT...
                  </td>
                </tr>
              ) : savedKeys.length > 0 ? (
                savedKeys.map((item) => {
                  const isVisible = !!visibleKeys[item.id];
                  const isCopied = copiedId === item.id;
                  const pin = item.saved_pin || item.pin || '••••••';

                  return (
                    <tr key={item.id}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
                            <Lock className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="font-bold text-white text-xs sm:text-sm">
                              {item.filename || 'Confidential Document'}
                            </div>
                            <div className="text-[10px] text-slate-500 font-mono">
                              File ID: {item.file_id?.substring(0, 16) || item.id?.substring(0, 16)}...
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="font-mono text-xs text-emerald-300">
                        AES-256-GCM (PBKDF2)
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs px-2.5 py-1 bg-slate-900 border border-slate-700 rounded-lg text-white tracking-widest min-w-[90px] text-center">
                            {isVisible ? pin : '••••••••'}
                          </span>
                          <button
                            onClick={() => toggleKeyVisibility(item.id)}
                            title={isVisible ? 'Hide Key' : 'Show Key'}
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white rounded-lg transition"
                          >
                            {isVisible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </td>
                      <td className="font-mono text-xs text-slate-400">
                        {item.created_at ? (item.created_at.includes('IST') ? item.created_at : `${item.created_at} IST`) : 'Recently'}
                      </td>
                      <td className="text-right">
                        <button
                          onClick={() => copyKey(item.id, pin)}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-emerald-950 text-slate-300 hover:text-emerald-300 border border-slate-700 hover:border-emerald-500/40 rounded-lg text-xs font-semibold flex items-center gap-1.5 ml-auto transition"
                        >
                          {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>{isCopied ? 'Copied!' : 'Copy Key'}</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="5" className="text-center py-12 text-slate-500 text-xs">
                    No confidential keys saved in your recovery vault yet. When encrypting a file, ensure "Save PIN to my Recovery Vault" is checked.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
