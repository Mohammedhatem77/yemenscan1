/**
 * YemenScan Centralized Authentication Context & Axios Interceptors.
 *
 * Implements:
 * - JWT storage and user session management.
 * - Axios Request Interceptor: Automatically injects Authorization: Bearer <token>.
 * - Axios Response Interceptor: Intercepts 401 Unauthorized errors and safely redirects to Login.
 * - RBAC helper utilities (userRole, hasRole, isAuthenticated).
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  ReactNode,
} from 'react';
import axios, { AxiosInstance, InternalAxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import {
  User,
  UserRole,
  LoginCredentials,
  RegisterData,
  TokenResponse,
  AuthContextType,
} from '../types/auth';

// Storage keys
const ACCESS_TOKEN_KEY = 'yemenscan_access_token';
const REFRESH_TOKEN_KEY = 'yemenscan_refresh_token';
const USER_KEY = 'yemenscan_user';

const API_BASE_URL = import.meta.env?.VITE_API_URL || '';

/**
 * Pre-configured Axios instance for all YemenScan API requests.
 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    try {
      const savedUser = localStorage.getItem(USER_KEY);
      return savedUser ? JSON.parse(savedUser) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);

  /**
   * Log out current session and flush tokens from persistent storage.
   */
  const logout = useCallback(() => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setUser(null);
    setToken(null);
    // Notify window for navigation synchronization
    window.dispatchEvent(new Event('auth:logout'));
  }, []);

  /**
   * Axios Request Interceptor:
   * Appends 'Authorization: Bearer <token>' to every outgoing request.
   */
  useEffect(() => {
    const requestInterceptor = apiClient.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        const storedToken = localStorage.getItem(ACCESS_TOKEN_KEY);
        if (storedToken && config.headers) {
          config.headers.Authorization = `Bearer ${storedToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    /**
     * Axios Response Interceptor:
     * Catches 401 Unauthorized and invalidates the session, redirecting to login.
     */
    const responseInterceptor = apiClient.interceptors.response.use(
      (response: AxiosResponse) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

        if (error.response?.status === 401 && !originalRequest?._retry) {
          const requestUrl = originalRequest.url || '';
          // Avoid interception loop on login or refresh endpoint
          if (!requestUrl.includes('/api/auth/login') && !requestUrl.includes('/api/auth/register')) {
            const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);

            // Attempt seamless token renewal if refresh token is present
            if (refreshToken && !requestUrl.includes('/api/auth/refresh')) {
              originalRequest._retry = true;
              try {
                const refreshResponse = await axios.post<TokenResponse>(
                  `${API_BASE_URL}/api/auth/refresh`,
                  { refresh_token: refreshToken }
                );

                const { access_token, refresh_token: newRefresh, user: updatedUser } = refreshResponse.data;
                localStorage.setItem(ACCESS_TOKEN_KEY, access_token);
                if (newRefresh) {
                  localStorage.setItem(REFRESH_TOKEN_KEY, newRefresh);
                }
                localStorage.setItem(USER_KEY, JSON.stringify(updatedUser));
                setToken(access_token);
                setUser(updatedUser);

                if (originalRequest.headers) {
                  originalRequest.headers.Authorization = `Bearer ${access_token}`;
                }
                return apiClient(originalRequest);
              } catch (refreshErr) {
                // Refresh token expired or revoked -> force logout
                logout();
                return Promise.reject(refreshErr);
              }
            } else {
              logout();
            }
          }
        }
        return Promise.reject(error);
      }
    );

    return () => {
      apiClient.interceptors.request.eject(requestInterceptor);
      apiClient.interceptors.response.eject(responseInterceptor);
    };
  }, [logout]);

  /**
   * Initializes auth state on application startup by verifying token via /api/auth/me.
   */
  useEffect(() => {
    const initializeAuth = async () => {
      const storedToken = localStorage.getItem(ACCESS_TOKEN_KEY);
      if (!storedToken) {
        setIsLoading(false);
        return;
      }

      try {
        const response = await apiClient.get<User>('/api/auth/me');
        setUser(response.data);
        localStorage.setItem(USER_KEY, JSON.stringify(response.data));
      } catch (err) {
        console.warn('Session verification failed, logging out:', err);
        logout();
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, [logout]);

  /**
   * Login action.
   */
  const login = useCallback(async (credentials: LoginCredentials) => {
    setIsLoading(true);
    try {
      const response = await axios.post<TokenResponse>(
        `${API_BASE_URL}/api/auth/login`,
        credentials
      );

      const { access_token, refresh_token, user: loggedUser } = response.data;

      localStorage.setItem(ACCESS_TOKEN_KEY, access_token);
      localStorage.setItem(REFRESH_TOKEN_KEY, refresh_token);
      localStorage.setItem(USER_KEY, JSON.stringify(loggedUser));

      setToken(access_token);
      setUser(loggedUser);
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Registration action.
   */
  const register = useCallback(async (data: RegisterData) => {
    setIsLoading(true);
    try {
      await axios.post(`${API_BASE_URL}/api/auth/register`, data);
      // Automatically log in after registration
      await login({
        username_or_email: data.username,
        password: data.password,
      });
    } finally {
      setIsLoading(false);
    }
  }, [login]);

  /**
   * RBAC Role validation helper.
   */
  const hasRole = useCallback(
    (allowedRoles: UserRole[]): boolean => {
      if (!user) return false;
      return allowedRoles.includes(user.role);
    },
    [user]
  );

  const value = useMemo<AuthContextType>(
    () => ({
      user,
      token,
      isAuthenticated: !!user && !!token,
      isLoading,
      userRole: user ? user.role : null,
      login,
      register,
      logout,
      hasRole,
    }),
    [user, token, isLoading, login, register, logout, hasRole]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

/**
 * Custom hook for consuming Authentication & RBAC context.
 */
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
