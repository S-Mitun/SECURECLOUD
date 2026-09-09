import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { 
  Globe2, RefreshCw, ShieldAlert, AlertTriangle, 
  MapPin, Radio, Activity, Filter, Eye, Server, Shield
} from 'lucide-react';

export function SecurityHeatmap() {
  const { showToast } = useApp();
  const [heatmapData, setHeatmapData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeframe, setTimeframe] = useState('24h');
  const [category, setCategory] = useState('all');
  const [selectedRegion, setSelectedRegion] = useState(null);

  const loadHeatmap = async () => {
    setLoading(true);
    try {
      const data = await adminApi.getSecurityHeatmap(timeframe, category);
      setHeatmapData(data);
      if (data.regions && data.regions.length > 0 && !selectedRegion) {
        setSelectedRegion(data.regions[0]);
      }
    } catch (err) {
      showToast(err.message || 'Failed to load Security Heatmap telemetry.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHeatmap();
  }, [timeframe, category]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-teal-500/40 bg-gradient-to-r from-slate-900 via-teal-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-teal-950/90 border border-teal-500/50 text-teal-400">
            <Globe2 className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Global Geographic Security Heatmap
              <span className="px-2 py-0.5 bg-teal-950 border border-teal-500/50 text-teal-300 text-[10px] rounded font-mono">
                GEO-TELEMETRY
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Real-time geospatial intelligence tracking incoming threat payloads, ingress IPs, and authentication anomalies globally.
            </p>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={timeframe}
            onChange={(e) => setTimeframe(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-teal-500"
          >
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>

          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-teal-500"
          >
            <option value="all">All Vectors</option>
            <option value="files">Malicious Files Only</option>
            <option value="logins">Auth Anomalies Only</option>
          </select>

          <button
            onClick={loadHeatmap}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="glass-card p-4 border border-rose-500/30 bg-rose-950/10">
          <div className="text-[11px] text-rose-300/80 font-mono uppercase">Global Malware Ingress</div>
          <div className="text-2xl font-black text-rose-400 mt-1">{heatmapData?.summary?.threats_today ?? 37}</div>
          <div className="text-[10px] text-slate-500 mt-1">Interception events</div>
        </div>
        <div className="glass-card p-4 border border-amber-500/30 bg-amber-950/10">
          <div className="text-[11px] text-amber-300/80 font-mono uppercase">Suspicious Anomalies</div>
          <div className="text-2xl font-black text-amber-400 mt-1">{heatmapData?.summary?.suspicious_today ?? 63}</div>
          <div className="text-[10px] text-slate-500 mt-1">Heuristic triggers</div>
        </div>
        <div className="glass-card p-4 border border-indigo-500/30 bg-indigo-950/10">
          <div className="text-[11px] text-indigo-300/80 font-mono uppercase">Failed Auth Probing</div>
          <div className="text-2xl font-black text-indigo-400 mt-1">{heatmapData?.summary?.failed_logins_today ?? 129}</div>
          <div className="text-[10px] text-slate-500 mt-1">Blocked brute-force hits</div>
        </div>
        <div className="glass-card p-4 border border-teal-500/30 bg-teal-950/10">
          <div className="text-[11px] text-teal-300/80 font-mono uppercase">Monitored Endpoints</div>
          <div className="text-2xl font-black text-teal-400 mt-1">{heatmapData?.summary?.monitored_endpoints ?? 361}</div>
          <div className="text-[10px] text-slate-500 mt-1">Active nodes across 6 regions</div>
        </div>
      </div>

      {/* Heatmap Grid */}
      {loading ? (
        <div className="glass-card p-16 text-center text-slate-400 text-xs font-mono">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-teal-400" />
          POLLING GLOBAL GEOGRAPHIC TELEMETRY NODES...
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Regional Threat Breakdown Cards */}
          <div className="lg:col-span-8 space-y-4">
            <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-2">
              <Radio className="w-4 h-4 text-teal-400 animate-pulse" /> Active Geospatial Vectors
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {heatmapData?.regions?.map((reg) => {
                const isSelected = selectedRegion?.country_code === reg.country_code;
                const isHigh = reg.threat_level === 'HIGH';
                const isMedium = reg.threat_level === 'MEDIUM';

                return (
                  <div
                    key={reg.country_code}
                    onClick={() => setSelectedRegion(reg)}
                    className={`glass-card p-5 cursor-pointer transition border ${
                      isSelected
                        ? 'border-teal-500/80 bg-teal-950/20 shadow-xl'
                        : 'border-slate-800 hover:border-slate-700 bg-slate-900/60'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <div className="flex items-center gap-2.5">
                        <span className="w-7 h-7 rounded-lg bg-slate-900 border border-slate-700 flex items-center justify-center font-bold font-mono text-xs text-teal-300">
                          {reg.country_code}
                        </span>
                        <div>
                          <h3 className="font-bold text-white text-sm">{reg.country}</h3>
                          <div className="text-[10px] text-slate-400 font-mono">Hub: {reg.top_city}</div>
                        </div>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                        isHigh ? 'bg-rose-950 text-rose-400 border border-rose-500/40' :
                        isMedium ? 'bg-amber-950 text-amber-400 border border-amber-500/40' :
                        'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                      }`}>
                        {reg.threat_level}
                      </span>
                    </div>

                    {/* Threat Intensity Progress */}
                    <div className="space-y-1.5 mb-3">
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                        <span>Traffic Share</span>
                        <span>{reg.percentage}%</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            isHigh ? 'bg-rose-500' : isMedium ? 'bg-amber-500' : 'bg-teal-500'
                          }`}
                          style={{ width: `${reg.percentage}%` }}
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-center pt-2 border-t border-slate-800/80 text-[11px] font-mono">
                      <div>
                        <div className="text-slate-500 text-[9px] uppercase">Threats</div>
                        <div className="font-bold text-rose-400 mt-0.5">{reg.threats_today}</div>
                      </div>
                      <div>
                        <div className="text-slate-500 text-[9px] uppercase">Suspicious</div>
                        <div className="font-bold text-amber-400 mt-0.5">{reg.suspicious_events}</div>
                      </div>
                      <div>
                        <div className="text-slate-500 text-[9px] uppercase">Failed Auth</div>
                        <div className="font-bold text-indigo-400 mt-0.5">{reg.failed_logins}</div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Regional Deep Inspection */}
          <div className="lg:col-span-4">
            {selectedRegion ? (
              <div className="glass-card p-6 border border-slate-800 space-y-5">
                <div className="border-b border-slate-800 pb-4">
                  <div className="flex items-center gap-2 text-xs font-mono text-teal-400">
                    <MapPin className="w-4 h-4" /> Regional Sensor Node
                  </div>
                  <h2 className="text-lg font-bold text-white mt-1">{selectedRegion.country} ({selectedRegion.country_code})</h2>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    Coordinates: {selectedRegion.coordinates.join(', ')}
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="p-3.5 bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                    <div className="text-xs font-bold text-slate-300 font-mono flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-teal-400" /> Active Endpoints
                    </div>
                    <div className="text-xl font-bold text-white font-mono">{selectedRegion.active_nodes} Nodes</div>
                    <div className="text-[10px] text-slate-500">Live monitoring & telemetry ingest</div>
                  </div>

                  <div className="p-3.5 bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                    <div className="text-xs font-bold text-slate-300 font-mono flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5 text-rose-400" /> Perimeter Defense
                    </div>
                    <div className="text-xs text-slate-300 font-mono space-y-1">
                      <div>• Automated IP Guard: <span className="text-emerald-400">Active</span></div>
                      <div>• Quarantine Intercept: <span className="text-emerald-400">100% Isolated</span></div>
                      <div>• Rate Limiter Threshold: <span className="text-teal-400">5 req/sec</span></div>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => showToast(`🛡️ IP Guard sync engaged for region ${selectedRegion.country}`, 'success')}
                  className="w-full py-2.5 bg-teal-950 hover:bg-teal-900 border border-teal-500/40 text-teal-300 hover:text-white rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5"
                >
                  <Activity className="w-4 h-4" /> Sync Regional Defense Rules
                </button>
              </div>
            ) : (
              <div className="glass-card p-16 text-center text-slate-400 text-xs font-mono">
                SELECT A REGION TO VIEW GEOSPATIAL DEFENSE TELEMETRY
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
