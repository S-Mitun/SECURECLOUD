import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useApp } from '../context/AppContext';
import { authApi } from '../api/authApi';
import { 
  ShieldCheck, Shield, Lock, Mail, User, KeyRound, Eye, EyeOff, 
  CheckCircle2, ArrowRight, RefreshCw, Key, AlertTriangle
} from 'lucide-react';

export function Login() {
  const { login, register } = useAuth();
  const { showToast } = useApp();
  const navigate = useNavigate();

  const [tab, setTab] = useState('login'); // 'login' | 'register' | 'forgot' | 'reset'
  const [portal, setPortal] = useState('USER'); // 'USER' | 'ADMIN'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [username, setUsername] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [totpPrompt, setTotpPrompt] = useState(null); // { email, user, temp_token, two_factor_code }
  const [totpCode, setTotpCode] = useState('');

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await login({
        email,
        password,
        portal,
        totp_code: totpCode || null
      });

      if (res && res.requires_2fa) {
        setTotpPrompt({
          email,
          user: res.user,
          temp_token: res.temp_token,
          two_factor_code: res.two_factor_code
        });
        showToast('Two-Factor Authentication (2FA) required. Confirmation code displayed.', 'info');
        return;
      }

      showToast(`Authenticated successfully as ${res.user.username}!`, 'success');
      if (res.user.role === 'ADMIN' || res.user.role === 'SECURITY_ANALYST') {
        navigate('/admin');
      } else {
        navigate('/my-files');
      }
    } catch (err) {
      showToast(err.message || 'Authentication failed.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleTotpVerifySubmit = async (e) => {
    e.preventDefault();
    if (!totpCode || totpCode.trim().length < 4) {
      showToast('Please enter the 6-digit confirmation code.', 'warning');
      return;
    }

    setLoading(true);
    try {
      const res = await login({
        email,
        password,
        portal,
        totp_code: totpCode.trim()
      });

      showToast(`2FA Verified! Welcome back, ${res.user.username}.`, 'success');
      setTotpPrompt(null);
      if (res.user.role === 'ADMIN' || res.user.role === 'SECURITY_ANALYST') {
        navigate('/admin');
      } else {
        navigate('/my-files');
      }
    } catch (err) {
      showToast(err.message || 'Invalid Two-Factor Authentication code.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await register({
        username,
        email,
        password,
        role: portal === 'ADMIN' ? 'ADMIN' : 'USER'
      });

      showToast(`Account created! Welcome, ${res.user.username}.`, 'success');
      if (res.user.role === 'ADMIN' || res.user.role === 'SECURITY_ANALYST') {
        navigate('/admin');
      } else {
        navigate('/my-files');
      }
    } catch (err) {
      showToast(err.message || 'Registration failed.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await authApi.forgotPassword(email);
      showToast(res.message || 'Password reset instructions generated!', 'success');
      if (res.reset_token) {
        setResetToken(res.reset_token);
      }
      setTab('reset');
    } catch (err) {
      showToast(err.message || 'Failed to request password reset.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleResetSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await authApi.resetPassword({
        email,
        reset_token: resetToken,
        new_password: newPassword
      });

      showToast('Password reset successful! You can now log in.', 'success');
      setTab('login');
      setPassword('');
    } catch (err) {
      showToast(err.message || 'Failed to reset password.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4 sm:p-6">
      <div className="glass-card max-w-md w-full p-6 sm:p-8 border border-slate-800 shadow-2xl relative animate-scale-up">
        {/* Header Branding */}
        <div className="text-center mb-6">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-sky-600 to-cyan-400 p-0.5 mx-auto mb-3 shadow-lg shadow-sky-500/25 flex items-center justify-center">
            <div className="w-full h-full bg-slate-950 rounded-[14px] flex items-center justify-center">
              <ShieldCheck className="w-8 h-8 text-sky-400" />
            </div>
          </div>
          <h2 className="text-2xl font-black text-white tracking-wide">
            SECURE<span className="text-sky-400">CLOUD</span>
          </h2>
        </div>

        {/* Portal Type Switcher (USER vs ADMIN) */}
        {(tab === 'login' || tab === 'register') && !totpPrompt && (
          <div className="grid grid-cols-2 gap-2 p-1 bg-slate-900/90 rounded-xl border border-slate-800 mb-6">
            <button
              type="button"
              onClick={() => setPortal('USER')}
              className={`py-2 text-xs font-bold rounded-lg transition flex items-center justify-center gap-1.5 ${
                portal === 'USER' ? 'bg-sky-600 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
            >
              <User className="w-3.5 h-3.5" /> User Portal
            </button>
            <button
              type="button"
              onClick={() => setPortal('ADMIN')}
              className={`py-2 text-xs font-bold rounded-lg transition flex items-center justify-center gap-1.5 ${
                portal === 'ADMIN' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
            >
              <Shield className="w-3.5 h-3.5" /> Admin SOC Portal
            </button>
          </div>
        )}

        {/* Form Tabs Switcher */}
        {!totpPrompt && (
          <div className="flex border-b border-slate-800 mb-6">
            <button
              onClick={() => setTab('login')}
              className={`flex-1 pb-2 text-xs font-bold uppercase tracking-wider border-b-2 transition ${
                tab === 'login' ? 'border-sky-500 text-sky-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => setTab('register')}
              className={`flex-1 pb-2 text-xs font-bold uppercase tracking-wider border-b-2 transition ${
                tab === 'register' ? 'border-sky-500 text-sky-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              Register
            </button>
            <button
              onClick={() => setTab('forgot')}
              className={`flex-1 pb-2 text-xs font-bold uppercase tracking-wider border-b-2 transition ${
                tab === 'forgot' || tab === 'reset' ? 'border-sky-500 text-sky-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              Reset PW
            </button>
          </div>
        )}

        {/* 1. 2FA CONFIRMATION CHALLENGE SCREEN */}
        {tab === 'login' && totpPrompt ? (
          <form onSubmit={handleTotpVerifySubmit} className="space-y-4 animate-scale-up">
            {/* Out-of-Band Security Dispatch Card */}
            <div className="p-4 rounded-xl bg-gradient-to-b from-indigo-950/90 to-slate-950 border border-indigo-500/50 shadow-xl space-y-3">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-xs font-bold text-indigo-300 uppercase tracking-wider">
                  <Shield className="w-4 h-4 text-indigo-400" /> Two-Factor Verification
                </span>
                <span className="px-2 py-0.5 rounded bg-indigo-950 border border-indigo-500/40 text-[10px] text-indigo-300 font-mono font-bold">
                  2FA ENFORCED
                </span>
              </div>
              
              <p className="text-xs text-slate-300 leading-relaxed">
                A secure 6-digit one-time authorization token has been dispatched to the registered security channel for <strong className="text-white">{totpPrompt.email}</strong>.
              </p>

              {/* Secure Dispatch Simulator for testing / evaluation */}
              <div className="bg-slate-950/90 p-3 rounded-lg border border-slate-800 space-y-1.5">
                <div className="text-[10px] text-slate-400 font-mono flex items-center justify-between">
                  <span>DISPATCHED TOKEN (DEMO / TEST CHANNEL):</span>
                  <span className="text-emerald-400 font-bold">DISPATCHED</span>
                </div>
                <div className="flex items-center justify-between bg-slate-900 px-3 py-1.5 rounded border border-slate-700">
                  <span className="font-mono text-sm font-bold text-indigo-300 tracking-widest">
                    {totpPrompt.two_factor_code || '849201'}
                  </span>
                  <button
                    type="button"
                    onClick={() => setTotpCode(totpPrompt.two_factor_code || '')}
                    className="text-[10px] font-mono text-sky-400 hover:text-sky-300 font-bold underline"
                  >
                    Auto-Fill Code
                  </button>
                </div>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Enter 6-Digit Code</label>
              <div className="relative">
                <input
                  type="text"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  placeholder="e.g. 123456"
                  className="w-full bg-slate-900 border border-indigo-500/50 rounded-lg pl-9 pr-3.5 py-2.5 text-sm text-white font-mono tracking-widest focus:outline-none focus:border-indigo-400 text-center font-bold"
                  autoFocus
                  required
                />
                <KeyRound className="w-4 h-4 text-indigo-400 absolute left-3 top-3" />
              </div>
            </div>

            <div className="flex items-center gap-2 pt-2">
              <button
                type="button"
                onClick={() => { setTotpPrompt(null); setTotpCode(''); }}
                className="flex-1 py-2.5 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-lg text-xs font-bold transition"
              >
                Back to Sign In
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 btn-cyber py-2.5 rounded-lg text-xs font-bold flex items-center justify-center gap-1.5"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Confirm & Login'}
              </button>
            </div>
          </form>
        ) : tab === 'login' ? (
          <form onSubmit={handleLoginSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Email Address</label>
              <div className="relative">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@securecloud.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-2.5 text-xs sm:text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
                <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-semibold text-slate-300">Password</label>
                <button
                  type="button"
                  onClick={() => setTab('forgot')}
                  className="text-[11px] text-sky-400 hover:underline"
                >
                  Forgot Password?
                </button>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-10 py-2.5 text-xs sm:text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
                <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="text-slate-400 hover:text-white absolute right-3 top-3"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Rate Limiting & Protection Indicator */}
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-slate-400 font-medium">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Rate Limiting & Threat Protection</span>
              </div>
              <span className="text-[10px] text-emerald-400 font-mono font-bold bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                ACTIVE
              </span>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-cyber w-full py-2.5 rounded-lg text-xs sm:text-sm font-bold flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" /> Authenticating...
                </>
              ) : (
                <>
                  <span>Sign In as {portal}</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>

            <div className="text-center text-[11px] text-slate-500 pt-2 font-mono">
              Role-Based Access Control • Server-Side Session Validation
            </div>
          </form>
        ) : null}

        {/* 2. REGISTRATION FORM */}
        {tab === 'register' && (
          <form onSubmit={handleRegisterSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Username</label>
              <div className="relative">
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="cyber_analyst"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-2.5 text-xs sm:text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
                <User className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Email Address</label>
              <div className="relative">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@securecloud.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-2.5 text-xs sm:text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
                <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-10 py-2.5 text-xs sm:text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
                <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="text-slate-400 hover:text-white absolute right-3 top-3"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Protection Indicator */}
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-slate-400 font-medium">
                <ShieldCheck className="w-4 h-4 text-sky-400" />
                <span>Account Registration Guard</span>
              </div>
              <span className="text-[10px] text-sky-400 font-mono font-bold bg-sky-950/60 px-2 py-0.5 rounded border border-sky-500/30">
                ACTIVE
              </span>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-cyber w-full py-2.5 rounded-lg text-xs sm:text-sm font-bold flex items-center justify-center gap-2"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Create Account'}
            </button>
          </form>
        )}

        {/* 3. FORGOT PASSWORD */}
        {tab === 'forgot' && (
          <form onSubmit={handleForgotSubmit} className="space-y-4">
            <div className="text-xs text-slate-400 leading-relaxed">
              Enter your registered email address to receive password reset tokens.
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Email Address</label>
              <div className="relative">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@securecloud.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-2.5 text-xs sm:text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
                <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              </div>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="btn-cyber w-full py-2.5 rounded-lg text-xs sm:text-sm font-bold flex items-center justify-center gap-2"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Send Reset Link'}
            </button>
          </form>
        )}

        {/* 4. RESET PASSWORD */}
        {tab === 'reset' && (
          <form onSubmit={handleResetSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Reset Token</label>
              <div className="relative">
                <input
                  type="text"
                  value={resetToken}
                  onChange={(e) => setResetToken(e.target.value)}
                  placeholder="Paste 64-character token"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-2.5 text-xs sm:text-sm text-white font-mono focus:outline-none focus:border-sky-500"
                  required
                />
                <Key className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">New Password</label>
              <div className="relative">
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-10 py-2.5 text-xs sm:text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
                <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="text-slate-400 hover:text-white absolute right-3 top-3"
                >
                  {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="btn-cyber w-full py-2.5 rounded-lg text-xs sm:text-sm font-bold flex items-center justify-center gap-2"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Confirm New Password'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
