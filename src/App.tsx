import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ErrorBoundary } from './components/ErrorBoundary.tsx';
import { ToastViewport } from './components/ui/Primitives.tsx';
import { AuthProvider, useAuth } from './contexts/AuthContext.tsx';
import AuditLogsPage from './pages/AuditLogsPage.tsx';
import CandidateDetailPage from './pages/CandidateDetailPage.tsx';
import CandidateOnboardingPage from './pages/CandidateOnboardingPage.tsx';
import CandidatesPage from './pages/CandidatesPage.tsx';
import DashboardPage from './pages/DashboardPage.tsx';
import DocumentVerificationPage from './pages/DocumentVerificationPage.tsx';
import EmployeesPage from './pages/EmployeesPage.tsx';
import LoginPage from './pages/LoginPage.tsx';
import NotificationsPage from './pages/NotificationsPage.tsx';
import { AccountSecurityPage, SystemConfigPage } from './pages/SettingsPage.tsx';
import TeamManagementPage from './pages/TeamManagementPage.tsx';
import { StaffRole } from './shared/types.ts';

function RequireStaff({
  children,
  roles,
}: {
  children: React.ReactNode;
  roles?: StaffRole[];
}) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="text-sm font-medium text-slate-600">Loading 9HR India Portal...</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (roles && !roles.includes(user.role)) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

function AppRoutes() {
  const { user, toasts, dismissToast } = useAuth();

  return (
    <>
      <Routes>
        {/* Public Token-Gated Candidate Onboarding Portal */}
        <Route path="/onboard/:token" element={<CandidateOnboardingPage />} />

        {/* Staff Login */}
        <Route
          path="/login"
          element={user ? <Navigate to="/dashboard" replace /> : <LoginPage />}
        />

        {/* Protected Staff Routes */}
        <Route
          path="/dashboard"
          element={
            <RequireStaff>
              <DashboardPage />
            </RequireStaff>
          }
        />
        <Route
          path="/candidates"
          element={
            <RequireStaff>
              <CandidatesPage />
            </RequireStaff>
          }
        />
        <Route
          path="/candidates/:id"
          element={
            <RequireStaff>
              <CandidateDetailPage />
            </RequireStaff>
          }
        />
        <Route
          path="/documents"
          element={
            <RequireStaff>
              <DocumentVerificationPage />
            </RequireStaff>
          }
        />
        <Route
          path="/employees"
          element={
            <RequireStaff>
              <EmployeesPage />
            </RequireStaff>
          }
        />
        <Route
          path="/notifications"
          element={
            <RequireStaff>
              <NotificationsPage />
            </RequireStaff>
          }
        />
        <Route
          path="/team"
          element={
            <RequireStaff roles={['SUPER_ADMIN', 'ADMIN']}>
              <TeamManagementPage />
            </RequireStaff>
          }
        />
        <Route
          path="/audit-logs"
          element={
            <RequireStaff roles={['SUPER_ADMIN', 'ADMIN']}>
              <AuditLogsPage />
            </RequireStaff>
          }
        />
        <Route
          path="/settings"
          element={
            <RequireStaff>
              <AccountSecurityPage />
            </RequireStaff>
          }
        />
        <Route
          path="/system-config"
          element={
            <RequireStaff roles={['SUPER_ADMIN']}>
              <SystemConfigPage />
            </RequireStaff>
          }
        />

        {/* Default & Catch-all */}
        <Route path="/" element={<Navigate to={user ? '/dashboard' : '/login'} replace />} />
        <Route path="*" element={<Navigate to={user ? '/dashboard' : '/login'} replace />} />
      </Routes>
      <ToastViewport toasts={toasts} onDismiss={dismissToast} />
    </>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
