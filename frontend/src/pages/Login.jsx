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
  const [adminSecurityCode, setAdminSecurityCode] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showAdminPin, setShowAdminPin] = useState(false);
  const [captchaChecked, setCaptchaChecked] = useState(false);
  const [loading, setLoading] = useState(false);
  const [totpPrompt, setTotpPrompt] = useState(null); // { email, user, temp_token, two_factor_code }
  const [totpCode, setTotpCode] = useState('');

  // Forgot Admin Dual Auth Key state
  const [showForgotKeyModal, setShowForgotKeyModal] = useState(false);
  const [forgotKeyPassword, setForgotKeyPassword] = useState('');
  const [showForgotKeyPassword, setShowForgotKeyPassword] = useState(false);
  const [retrievedKey, setRetrievedKey] = useState(null);
  const [retrieveLoading, setRetrieveLoading] = useState(false);

  const handleRetrieveKeySubmit = async (e) => {
    e.preventDefault();
    if (!email.trim()) {
      showToast('Please enter your Administrator email in the sign-in form first.', 'warning');
      return;
    }
    if (!forgotKeyPassword.trim()) {
      showToast('Please enter your account password.', 'warning');
      return;
    }

    setRetrieveLoading(true);
    try {
      const res = await authApi.retrieveAdminKey({
        email: email.trim(),
        password: forgotKeyPassword.trim()
      });
      setRetrievedKey(res.admin_security_code);
      showToast('Admin Dual Auth Key verified!', 'success');
    } catch (err) {
      showToast(err.message || 'Incorrect password. Verification failed.', 'error');
    } finally {
      setRetrieveLoading(false);
    }
  };

  const handleApplyRetrievedKey = () => {
    if (retrievedKey) {
      setAdminSecurityCode(retrievedKey);
      setShowForgotKeyModal(false);
      setForgotKeyPassword('');
      setRetrievedKey(null);
      showToast('Dual Auth Key auto-filled into login form!', 'success');
    }
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    if (!captchaChecked) {
      showToast('Please check the "I\'m not a robot" security verification.', 'warning');
      return;
    }
    const effectiveAdminCode = portal === 'ADMIN' ? (adminSecurityCode.trim() || '994422') : null;

    setLoading(true);
    try {
      const res = await login({
        email,
        password,
        portal,
        mock_captcha_verified: captchaChecked,
        totp_code: totpCode || null,
        admin_security_code: effectiveAdminCode
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
      if (res.user.role === 'ADMIN') {
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
        mock_captcha_verified: true,
        totp_code: totpCode.trim(),
        admin_security_code: portal === 'ADMIN' ? adminSecurityCode : null
      });

      showToast(`2FA Verified! Welcome back, ${res.user.username}.`, 'success');
      setTotpPrompt(null);
      if (res.user.role === 'ADMIN') {
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
    if (!captchaChecked) {
      showToast('Please complete the verification checkbox.', 'warning');
      return;
    }

    setLoading(true);
    try {
      const res = await register({
        username,
        email,
        password,
        role: portal === 'ADMIN' ? 'ADMIN' : 'USER',
        admin_security_code: portal === 'ADMIN' ? (adminSecurityCode || '994422') : undefined
      });

      showToast(`Account created! Welcome, ${res.user.username}.`, 'success');
      if (res.user.role === 'ADMIN') {
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

            {/* Admin Dual Auth Key for Admin Portal */}
            {portal === 'ADMIN' && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-semibold text-cyan-300">
                    Admin Dual Auth Key <span className="text-slate-400 font-normal font-mono text-[10px]">(Default: 994422)</span>
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setShowForgotKeyModal(true);
                      setRetrievedKey(null);
                      setForgotKeyPassword('');
                    }}
                    className="text-[11px] text-cyan-400 hover:underline font-mono"
                  >
                    Forgot Auth Key?
                  </button>
                </div>
                <div className="relative">
                  <input
                    type={showAdminPin ? 'text' : 'password'}
                    maxLength={32}
                    value={adminSecurityCode}
                    onChange={(e) => setAdminSecurityCode(e.target.value)}
                    placeholder="Enter Admin Dual Auth Key (Default: 994422)..."
                    className="w-full bg-slate-900 border border-cyan-500/50 rounded-lg pl-9 pr-10 py-2.5 text-xs sm:text-sm text-cyan-200 font-mono tracking-wider focus:outline-none focus:border-cyan-400"
                  />
                  <KeyRound className="w-4 h-4 text-cyan-400 absolute left-3 top-3" />
                  <button
                    type="button"
                    onClick={() => setShowAdminPin(!showAdminPin)}
                    className="text-slate-400 hover:text-white absolute right-3 top-3"
                    title={showAdminPin ? 'Hide Key' : 'Show Key'}
                  >
                    {showAdminPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            )}

            {/* CAPTCHA / I'm not a robot checkbox */}
            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center justify-between">
              <label className="flex items-center gap-2.5 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={captchaChecked}
                  onChange={(e) => setCaptchaChecked(e.target.checked)}
                  className="w-4 h-4 rounded bg-slate-800 border-slate-700 text-sky-500 focus:ring-0"
                />
                <span className="text-xs text-slate-200 font-medium">I'm not a robot</span>
              </label>
              <div className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5 text-sky-400" /> reCAPTCHA v2
              </div>
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
              Default Admin: admin@securecloud.com / AdminPass123! (Dual Auth Key: 994422)
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

            {portal === 'ADMIN' && (
              <div>
                <label className="block text-xs font-semibold text-cyan-300 mb-1.5 flex items-center justify-between">
                  <span>Set Admin Dual-Auth Password / Key</span>
                  <span className="text-[10px] text-cyan-400 font-mono font-normal">Permanent Key (Set Once)</span>
                </label>
                <div className="relative">
                  <input
                    type={showAdminPin ? 'text' : 'password'}
                    maxLength={32}
                    value={adminSecurityCode}
                    onChange={(e) => setAdminSecurityCode(e.target.value)}
                    placeholder="Enter user-defined Dual Auth password..."
                    className="w-full bg-slate-900 border border-cyan-500/50 rounded-lg pl-9 pr-10 py-2.5 text-xs sm:text-sm text-cyan-200 font-mono tracking-wider focus:outline-none focus:border-cyan-400"
                    required
                  />
                  <KeyRound className="w-4 h-4 text-cyan-400 absolute left-3 top-3" />
                  <button
                    type="button"
                    onClick={() => setShowAdminPin(!showAdminPin)}
                    className="text-slate-400 hover:text-white absolute right-3 top-3"
                    title={showAdminPin ? 'Hide PIN' : 'Show PIN'}
                  >
                    {showAdminPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-[10px] text-slate-400 mt-1">
                  🔒 Fixed identification key for your admin account. Stored permanently and cannot be changed or reset later.
                </p>
              </div>
            )}

            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center justify-between">
              <label className="flex items-center gap-2.5 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={captchaChecked}
                  onChange={(e) => setCaptchaChecked(e.target.checked)}
                  className="w-4 h-4 rounded bg-slate-800 border-slate-700 text-sky-500 focus:ring-0"
                />
                <span className="text-xs text-slate-200 font-medium">I'm not a robot</span>
              </label>
              <div className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5 text-sky-400" /> reCAPTCHA v2
              </div>
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

      {/* Forgot Admin Dual Auth Key Modal */}
      {showForgotKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-card max-w-md w-full border border-cyan-500/50 bg-slate-950 shadow-2xl p-6 relative space-y-4 animate-scale-up">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5 text-cyan-300 font-bold text-sm">
                <KeyRound className="w-5 h-5 text-cyan-400" />
                <span>Retrieve Admin Dual-Auth Key</span>
              </div>
              <button
                type="button"
                onClick={() => { setShowForgotKeyModal(false); setRetrievedKey(null); setShowForgotKeyPassword(false); }}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              To securely retrieve and view your administrator account's fixed Dual Auth Key, enter your account password below:
            </p>

            <form onSubmit={handleRetrieveKeySubmit} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Admin Email Address</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@securecloud.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Account Password</label>
                <div className="relative">
                  <input
                    type={showForgotKeyPassword ? 'text' : 'password'}
                    value={forgotKeyPassword}
                    onChange={(e) => setForgotKeyPassword(e.target.value)}
                    placeholder="Enter your account password..."
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-3 pr-10 py-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowForgotKeyPassword(!showForgotKeyPassword)}
                    className="text-slate-400 hover:text-white absolute right-3 top-2.5"
                    title={showForgotKeyPassword ? 'Hide password' : 'Show password'}
                  >
                    {showForgotKeyPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {retrievedKey && (
                <div className="p-3 bg-cyan-950/60 border border-cyan-500/40 rounded-xl space-y-2">
                  <div className="text-[10px] text-cyan-400 font-mono font-bold uppercase">Your Fixed Dual-Auth Key:</div>
                  <div className="flex items-center justify-between bg-slate-950 p-2.5 rounded-lg border border-cyan-500/50">
                    <span className="text-base font-black font-mono tracking-widest text-cyan-300">
                      {retrievedKey}
                    </span>
                    <button
                      type="button"
                      onClick={handleApplyRetrievedKey}
                      className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-bold font-mono transition"
                    >
                      Auto-Fill Key
                    </button>
                  </div>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => { setShowForgotKeyModal(false); setRetrievedKey(null); setShowForgotKeyPassword(false); }}
                  className="px-3 py-2 bg-slate-900 hover:bg-slate-800 text-slate-400 rounded-lg text-xs font-mono"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={retrieveLoading}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-lg text-xs font-mono flex items-center gap-1.5 shadow"
                >
                  {retrieveLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
                  <span>Verify & View Key</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
