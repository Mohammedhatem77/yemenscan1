/**
 * YemenScan Cyber-Themed Login & Authentication Page.
 *
 * Theme Palette:
 * - Background: #0f172a (Deep Slate)
 * - Primary Cyan Accent: #06b6d4 (Cyan-500)
 * - Emerald Security Accent: #10b981 (Emerald-500)
 * - Text: #f8fafc / #94a3b8
 */

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  Shield,
  Lock,
  User as UserIcon,
  Mail,
  Eye,
  EyeOff,
  AlertCircle,
  Loader2,
  CheckCircle2,
  KeyRound,
  Terminal,
} from 'lucide-react';

export const Login: React.FC = () => {
  const { login, register } = useAuth();

  // Mode: 'login' or 'register'
  const [isRegisterMode, setIsRegisterMode] = useState<boolean>(false);

  // Form states
  const [usernameOrEmail, setUsernameOrEmail] = useState<string>('');
  const [username, setUsername] = useState<string>('');
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);

  // Feedback states
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const formatError = (err: any): string => {
    if (!err) return 'حدث خطأ غير متوقع';
    if (err.response?.status === 401) {
      return 'بيانات الاعتماد غير صحيحة (اسم المستخدم أو كلمة المرور خاطئة)';
    }
    const detail = err.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((item: any) => {
          if (typeof item === 'string') return item;
          if (item?.msg) return item.msg.replace('Value error, ', '');
          return JSON.stringify(item);
        })
        .join(' | ');
    }
    if (detail && typeof detail === 'object') {
      return detail.msg || detail.message || JSON.stringify(detail);
    }
    return err.response?.data?.message || err.message || 'تعذر الاتصال بالخادم';
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (isRegisterMode) {
      if (!username.trim() || !email.trim() || !password) {
        setError('يرجى ملء كافة الحقول المطلوبة');
        return;
      }
      if (password.length < 8) {
        setError('كلمة المرور يجب أن تكون 8 خانات على الأقل وتحتوي حروفاً وأرقاماً');
        return;
      }

      setIsSubmitting(true);
      try {
        await register({
          username: username.trim(),
          email: email.trim(),
          password,
        });
        setSuccessMsg('تم إنشاء الحساب بنجاح! جاري تسجيل الدخول...');
      } catch (err: any) {
        setError(formatError(err));
      } finally {
        setIsSubmitting(false);
      }
    } else {
      if (!usernameOrEmail.trim() || !password) {
        setError('يرجى إدخال اسم المستخدم أو البريد الإلكتروني وكلمة المرور');
        return;
      }

      setIsSubmitting(true);
      try {
        await login({
          username_or_email: usernameOrEmail.trim(),
          password,
        });
      } catch (err: any) {
        setError(formatError(err));
      } finally {
        setIsSubmitting(false);
      }
    }
  };

  return (
    <div
      dir="rtl"
      className="min-h-screen bg-[#0f172a] text-slate-100 flex flex-col justify-center items-center p-4 relative overflow-hidden font-sans select-none"
    >
      {/* Background Cybernetic Glow Grid Effects */}
      <div className="absolute inset-0 bg-[radial-gradient(#06b6d4_1px,transparent_1px)] [background-size:24px_24px] opacity-15 pointer-events-none" />
      <div className="absolute top-1/4 -left-32 w-96 h-96 bg-[#06b6d4]/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 -right-32 w-96 h-96 bg-[#10b981]/10 rounded-full blur-3xl pointer-events-none" />

      {/* Main Container Card */}
      <div className="relative w-full max-w-md bg-slate-900/90 border border-slate-800 rounded-2xl shadow-2xl shadow-black/80 backdrop-blur-xl p-8 z-10">
        {/* Glowing Top Border Accent */}
        <div className="absolute top-0 left-8 right-8 h-[2px] bg-gradient-to-r from-transparent via-[#06b6d4] to-transparent opacity-80" />

        {/* Brand Header */}
        <div className="flex flex-col items-center mb-6">
          <div className="relative mb-3 flex items-center justify-center">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-emerald-500/10 border border-cyan-500/40 flex items-center justify-center text-[#06b6d4] shadow-lg shadow-cyan-500/20">
              <Shield className="w-8 h-8 text-[#06b6d4]" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-[#10b981] border-2 border-[#0f172a] flex items-center justify-center">
              <Lock className="w-2.5 h-2.5 text-[#0f172a]" />
            </div>
          </div>

          <h1 className="text-2xl font-black tracking-wide text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400">
            YEMENSCAN
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono tracking-tight">
            بوابة المصادقة والأمان السحابي (v2.0)
          </p>
        </div>

        {/* Tab Switcher (Login vs Register) */}
        <div className="grid grid-cols-2 bg-slate-950/80 p-1 rounded-xl mb-6 border border-slate-800/80">
          <button
            type="button"
            onClick={() => {
              setIsRegisterMode(false);
              setError(null);
            }}
            className={`py-2 text-xs font-bold rounded-lg transition-all duration-200 ${
              !isRegisterMode
                ? 'bg-[#06b6d4]/15 text-[#06b6d4] border border-[#06b6d4]/30 shadow-sm shadow-[#06b6d4]/10'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            تسجيل الدخول
          </button>
          <button
            type="button"
            onClick={() => {
              setIsRegisterMode(true);
              setError(null);
            }}
            className={`py-2 text-xs font-bold rounded-lg transition-all duration-200 ${
              isRegisterMode
                ? 'bg-[#10b981]/15 text-[#10b981] border border-[#10b981]/30 shadow-sm shadow-[#10b981]/10'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            حساب جديد
          </button>
        </div>

        {/* Feedback Alert Messages */}
        {error && (
          <div className="mb-5 p-3.5 bg-rose-950/40 border border-rose-500/40 rounded-xl text-rose-300 text-xs flex items-start gap-2.5 animate-fadeIn">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1 font-mono leading-relaxed">{error}</div>
          </div>
        )}

        {successMsg && (
          <div className="mb-5 p-3.5 bg-emerald-950/40 border border-emerald-500/40 rounded-xl text-emerald-300 text-xs flex items-start gap-2.5 animate-fadeIn">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="flex-1 font-mono leading-relaxed">{successMsg}</div>
          </div>
        )}

        {/* Auth Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegisterMode ? (
            <>
              {/* Username Input */}
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1.5">
                  اسم المستخدم (Username)
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="مثال: sec_analyst"
                    required
                    disabled={isSubmitting}
                    className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-4 py-2.5 pr-10 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#06b6d4] focus:ring-1 focus:ring-[#06b6d4] transition-all font-mono"
                  />
                  <UserIcon className="w-4 h-4 text-slate-400 absolute right-3.5 top-3" />
                </div>
              </div>

              {/* Email Input */}
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1.5">
                  البريد الإلكتروني (Email)
                </label>
                <div className="relative">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@domain.com"
                    required
                    disabled={isSubmitting}
                    className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-4 py-2.5 pr-10 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#06b6d4] focus:ring-1 focus:ring-[#06b6d4] transition-all font-mono"
                  />
                  <Mail className="w-4 h-4 text-slate-400 absolute right-3.5 top-3" />
                </div>
              </div>
            </>
          ) : (
            /* Login Identifier (Username or Email) */
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5">
                اسم المستخدم أو البريد الإلكتروني
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={usernameOrEmail}
                  onChange={(e) => setUsernameOrEmail(e.target.value)}
                  placeholder="admin أو user@yemenscan.ye"
                  required
                  autoFocus
                  disabled={isSubmitting}
                  className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-4 py-2.5 pr-10 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#06b6d4] focus:ring-1 focus:ring-[#06b6d4] transition-all font-mono"
                />
                <UserIcon className="w-4 h-4 text-slate-400 absolute right-3.5 top-3" />
              </div>
            </div>
          )}

          {/* Password Input with Visibility Toggle */}
          <div>
            <div className="flex justify-between items-center mb-1.5">
              <label className="text-xs font-mono text-slate-300">
                كلمة المرور (Password)
              </label>
            </div>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                disabled={isSubmitting}
                className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-4 py-2.5 pr-10 pl-10 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-[#06b6d4] focus:ring-1 focus:ring-[#06b6d4] transition-all font-mono"
              />
              <Lock className="w-4 h-4 text-slate-400 absolute right-3.5 top-3" />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex={-1}
                className="absolute left-3 top-2.5 p-0.5 text-slate-400 hover:text-slate-200 transition-colors"
                title={showPassword ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور'}
              >
                {showPassword ? (
                  <EyeOff className="w-4 h-4 text-[#06b6d4]" />
                ) : (
                  <Eye className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>

          {/* Submit Action Button */}
          <button
            type="submit"
            disabled={isSubmitting}
            className={`w-full py-3 px-4 rounded-xl font-bold text-xs flex items-center justify-center gap-2 transition-all duration-200 mt-2 shadow-lg ${
              isRegisterMode
                ? 'bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-emerald-950/50'
                : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-cyan-950/50'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-white" />
                <span>جاري التحقق من الهوية...</span>
              </>
            ) : isRegisterMode ? (
              <>
                <CheckCircle2 className="w-4 h-4" />
                <span>إنشاء الحساب (دور: Analyst)</span>
              </>
            ) : (
              <>
                <KeyRound className="w-4 h-4" />
                <span>تسجيل الدخول للمنظومة</span>
              </>
            )}
          </button>
        </form>

        {/* Security & Cryptography Badges Footer */}
        <div className="mt-8 pt-5 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500 font-mono">
          <div className="flex items-center gap-1 text-slate-400">
            <Terminal className="w-3.5 h-3.5 text-cyan-500" />
            <span>Argon2id + HS256</span>
          </div>
          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-emerald-400 font-semibold">
            RBAC Isolated
          </span>
        </div>
      </div>
    </div>
  );
};
