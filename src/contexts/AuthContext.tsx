import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { signInWithPopup, signOut } from 'firebase/auth';
import { StaffUser } from '../shared/types.ts';
import { apiRequest, getStoredToken, setStoredToken } from '../lib/api.ts';
import { auth, googleAuthProvider, syncFirebaseUserProfile } from '../lib/firebase.ts';

export interface ToastItem {
  id: string;
  title: string;
  description?: string;
  type: 'success' | 'error' | 'info' | 'warning';
}

interface AuthContextValue {
  user: StaffUser | null;
  loading: boolean;
  toasts: ToastItem[];
  addToast: (toast: Omit<ToastItem, 'id'>) => void;
  dismissToast: (id: string) => void;
  loginWithCredentials: (
    identifier: string,
    password: string
  ) => Promise<{ requires2FA?: boolean; challengeToken?: string; userHint?: { fullName: string; loginId: string; role: string } }>;
  complete2FA: (challengeToken: string, code: string) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<StaffUser | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    (toast: Omit<ToastItem, 'id'>) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => [...prev, { ...toast, id }]);
      setTimeout(() => {
        dismissToast(id);
      }, 4500);
    },
    [dismissToast]
  );

  const refreshUser = useCallback(async () => {
    try {
      const data = await apiRequest<{ user: StaffUser }>('/api/auth/me');
      setUser(data.user);
    } catch {
      setUser(null);
      setStoredToken(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const token = getStoredToken();
    if (token) {
      refreshUser();
    } else {
      // Check httpOnly cookie session
      apiRequest<{ user: StaffUser }>('/api/auth/me')
        .then((res) => setUser(res.user))
        .catch(() => setUser(null))
        .finally(() => setLoading(false));
    }
  }, [refreshUser]);

  const loginWithCredentials = async (identifier: string, password: string) => {
    const res = await apiRequest<{
      requires2FA?: boolean;
      challengeToken?: string;
      userHint?: { fullName: string; loginId: string; role: string };
      token?: string;
      user?: StaffUser;
    }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ identifier, password }),
    });

    if (res.requires2FA && res.challengeToken) {
      return {
        requires2FA: true,
        challengeToken: res.challengeToken,
        userHint: res.userHint,
      };
    }

    if (res.token && res.user) {
      setStoredToken(res.token);
      setUser(res.user);
      addToast({
        title: `Welcome back, ${res.user.fullName}`,
        description: `Signed in as ${res.user.role.replace('_', ' ')} (${res.user.loginId})`,
        type: 'success',
      });
    }
    return {};
  };

  const complete2FA = async (challengeToken: string, code: string) => {
    const res = await apiRequest<{ token: string; user: StaffUser }>('/api/auth/verify-2fa', {
      method: 'POST',
      body: JSON.stringify({ challengeToken, code }),
    });
    setStoredToken(res.token);
    setUser(res.user);
    addToast({
      title: '2FA Verified',
      description: `Signed in as ${res.user.fullName}`,
      type: 'success',
    });
  };

  const loginWithGoogle = async () => {
    const result = await signInWithPopup(auth, googleAuthProvider);
    const idToken = await result.user.getIdToken();
    const res = await apiRequest<{ token: string; user: StaffUser }>('/api/auth/google', {
      method: 'POST',
      body: JSON.stringify({ idToken }),
    });
    setStoredToken(res.token);
    setUser(res.user);
    // Best-effort sync to Firestore profile when Google-authenticated
    syncFirebaseUserProfile({
      uid: result.user.uid,
      email: res.user.email,
      fullName: res.user.fullName,
      role: res.user.role,
      department: res.user.department,
    }).catch((err) => {
      console.warn('Firestore profile sync skipped:', err);
    });
    addToast({
      title: `Signed in with Google`,
      description: `${res.user.fullName} · ${res.user.role.replace('_', ' ')}`,
      type: 'success',
    });
  };

  const logout = async () => {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {
      // Proceed with local cleanup
    }
    try {
      if (auth.currentUser) {
        await signOut(auth);
      }
    } catch {
      // Ignore Firebase signout error
    }
    setStoredToken(null);
    setUser(null);
    addToast({ title: 'Signed out securely', type: 'info' });
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        toasts,
        addToast,
        dismissToast,
        loginWithCredentials,
        complete2FA,
        loginWithGoogle,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
