import React from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { ToastContainer } from './components/ToastContainer';
import { ProtectedRoute } from './components/ProtectedRoute';

// Public & User Pages
import { Login } from './pages/Login';
import { MyFiles } from './pages/MyFiles';
import { ConfidentialVault } from './pages/ConfidentialVault';
import { PasswordSaves } from './pages/PasswordSaves';
import { SharedLinks } from './pages/SharedLinks';
import { RecycleBin } from './pages/RecycleBin';
import { UserActivity } from './pages/UserActivity';
import { PublicShareView } from './pages/PublicShareView';

// Admin SOC Pages
import { AdminDashboard } from './pages/admin/AdminDashboard';
import { AdminFileUpload } from './pages/admin/AdminFileUpload';
import { SentinelVm } from './pages/admin/SentinelVm';
import { UserWiseFiles } from './pages/admin/UserWiseFiles';
import { UsersManagement } from './pages/admin/UsersManagement';
import { ThreatCorrelation } from './pages/admin/ThreatCorrelation';
import { UserRiskProfiling } from './pages/admin/UserRiskProfiling';
import { QuarantineVault } from './pages/admin/QuarantineVault';
import { IpGuard } from './pages/admin/IpGuard';
import { SessionsManagement } from './pages/admin/SessionsManagement';
import { AuditLogs } from './pages/admin/AuditLogs';
import { VerifiedArtifacts } from './pages/admin/VerifiedArtifacts';

export default function App() {
  const location = useLocation();
  const isPublicShare = location.pathname.startsWith('/public-share');

  return (
    <div className="min-h-screen bg-[#070a12] text-slate-100 flex flex-col font-sans">
      {!isPublicShare && <Navbar />}
      <main className={`flex-1 ${isPublicShare ? 'p-0 m-0 pb-0 flex flex-col' : 'pb-10'}`}>
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/public-share/:id" element={<PublicShareView />} />

          {/* User Protected Routes */}
          <Route element={<ProtectedRoute requireAdmin={false} />}>
            <Route path="/" element={<Navigate to="/my-files" replace />} />
            <Route path="/dashboard" element={<Navigate to="/my-files" replace />} />
            <Route path="/my-files" element={<MyFiles />} />
            <Route path="/confidential" element={<ConfidentialVault />} />
            <Route path="/password-saves" element={<PasswordSaves />} />
            <Route path="/shares" element={<SharedLinks />} />
            <Route path="/shared-links" element={<SharedLinks />} />
            <Route path="/recycle-bin" element={<RecycleBin />} />
            <Route path="/activity" element={<UserActivity />} />
          </Route>

          {/* Admin Protected Routes */}
          <Route element={<ProtectedRoute requireAdmin={true} />}>
            <Route path="/admin" element={<AdminDashboard />} />
            <Route path="/admin/sentinel" element={<SentinelVm />} />
            <Route path="/admin/telemetry" element={<SentinelVm />} />
            <Route path="/admin/upload" element={<AdminFileUpload />} />
            <Route path="/admin/upload-files" element={<AdminFileUpload />} />
            <Route path="/admin/ingestion" element={<AdminFileUpload />} />
            <Route path="/admin/user-wise-files" element={<UserWiseFiles />} />
            <Route path="/admin/users" element={<UsersManagement />} />
            <Route path="/admin/correlation" element={<ThreatCorrelation />} />
            <Route path="/admin/policies" element={<Navigate to="/admin/correlation" replace />} />
            <Route path="/admin/risk-profiling" element={<UserRiskProfiling />} />
            <Route path="/admin/quarantine" element={<QuarantineVault />} />
            <Route path="/admin/threats" element={<Navigate to="/admin/quarantine" replace />} />
            <Route path="/admin/threat-center" element={<Navigate to="/admin/quarantine" replace />} />
            <Route path="/admin/files" element={<Navigate to="/admin/user-wise-files" replace />} />
            <Route path="/admin/verified-artifacts" element={<VerifiedArtifacts />} />
            <Route path="/admin/ip-guard" element={<IpGuard />} />
            <Route path="/admin/sessions" element={<SessionsManagement />} />
            <Route path="/admin/audit-logs" element={<AuditLogs />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </main>

      <ToastContainer />
    </div>
  );
}
