/**
 * YemenScan ProtectedRoute Component.
 *
 * Enforces:
 * 1. Authentication Check: Blocks unauthenticated users, rendering Login screen or redirect.
 * 2. RBAC Enforcement: Verifies user role against allowedRoles before rendering restricted views.
 * 3. Cybernetic Loading State: Displays security verification animation while loading credentials.
 */

import React, { ReactNode } from 'react';
import { useAuth } from '../context/AuthContext';
import { UserRole } from '../types/auth';
import { ShieldAlert, Loader2 } from 'lucide-react';
import { Login } from '../pages/Login';

interface ProtectedRouteProps {
  children: ReactNode;
  allowedRoles?: UserRole[];
  fallback?: ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  allowedRoles,
  fallback,
}) => {
  const { user, isAuthenticated, isLoading, hasRole, logout } = useAuth();

  // 1. Loading State while checking JWT & user profile
  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#0f172a] flex flex-col items-center justify-center text-slate-200">
        <div className="relative flex items-center justify-center mb-4">
          <div className="w-16 h-16 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin" />
          <Loader2 className="w-6 h-6 text-emerald-400 absolute animate-pulse" />
        </div>
        <p className="text-sm font-mono tracking-wider text-cyan-400 uppercase">
          جاري التحقق من الجلسة الأمنية...
        </p>
        <p className="text-xs text-slate-500 mt-1 font-mono">
          Verifying JWT Credentials & Role Permissions
        </p>
      </div>
    );
  }

  // 2. Authentication Check: Show Login page if not authenticated
  if (!isAuthenticated || !user) {
    if (fallback) {
      return <>{fallback}</>;
    }
    return <Login />;
  }

  // 3. RBAC Role Check: Block users lacking required role
  if (allowedRoles && allowedRoles.length > 0 && !hasRole(allowedRoles)) {
    return (
      <div className="min-h-screen bg-[#0f172a] flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-slate-900/90 border border-rose-500/40 rounded-xl p-8 shadow-2xl shadow-rose-950/30 backdrop-blur-sm text-center">
          <div className="w-16 h-16 mx-auto mb-5 rounded-full bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-8 h-8" />
          </div>

          <h2 className="text-xl font-bold text-slate-100 mb-2">
            تم رفض الوصول (403 Forbidden)
          </h2>
          <p className="text-sm text-slate-400 mb-6 leading-relaxed">
            حسابك الحالي بصلاحية{' '}
            <span className="font-mono px-2 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-500/30 text-xs">
              {user.role}
            </span>{' '}
            لا يملك الصلاحيات الكافية للوصول إلى هذا القسم.
          </p>

          <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800 text-xs text-slate-400 font-mono mb-6 text-right">
            <div>المستخدم: <span className="text-slate-200">{user.username}</span></div>
            <div>الصلاحيات المطلوبة: <span className="text-cyan-400">{allowedRoles.join(', ')}</span></div>
          </div>

          <div className="flex gap-3 justify-center">
            <button
              onClick={logout}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors border border-slate-700"
            >
              تسجيل الخروج
            </button>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-rose-600/80 hover:bg-rose-500 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5"
            >
              إعادة المحاولة
            </button>
          </div>
        </div>
      </div>
    );
  }

  // 4. Authorized: Render content
  return <>{children}</>;
};
