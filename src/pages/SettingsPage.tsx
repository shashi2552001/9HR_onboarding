import React, { useEffect, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { KeyRound, RefreshCw, ShieldCheck, Sliders } from 'lucide-react';
import { AppLayout } from '../components/Layout.tsx';
import { ConfirmDialog } from '../components/ui/Primitives.tsx';
import { useAuth } from '../contexts/AuthContext.tsx';
import { apiRequest } from '../lib/api.ts';
import { SystemConfig } from '../shared/types.ts';

export function AccountSecurityPage() {
  const { user, refreshUser, addToast } = useAuth();

  // Password Change
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [pwdBusy, setPwdBusy] = useState(false);

  // 2FA Setup
  const [qrData, setQrData] = useState<{ secret: string; otpauthUrl: string } | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [tfaBusy, setTfaBusy] = useState(false);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwdBusy(true);
    try {
      await apiRequest('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setCurrentPassword('');
      setNewPassword('');
      addToast({ title: 'Password Updated', type: 'success' });
      await refreshUser();
    } catch (err) {
      addToast({
        title: 'Password Change Failed',
        description: err instanceof Error ? err.message : 'Error',
        type: 'error',
      });
    } finally {
      setPwdBusy(false);
    }
  };

  const handleStart2FA = async () => {
    setTfaBusy(true);
    try {
      const res = await apiRequest<{ secret: string; otpauthUrl: string }>('/api/auth/2fa/setup', {
        method: 'POST',
      });
      setQrData(res);
    } catch (err) {
      addToast({
        title: '2FA Setup Failed',
        description: err instanceof Error ? err.message : 'Error',
        type: 'error',
      });
    } finally {
      setTfaBusy(false);
    }
  };

  const handleEnable2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    setTfaBusy(true);
    try {
      await apiRequest('/api/auth/2fa/enable', {
        method: 'POST',
        body: JSON.stringify({ code: totpCode }),
      });
      setQrData(null);
      setTotpCode('');
      addToast({ title: 'Two-Factor Authentication Enabled', type: 'success' });
      await refreshUser();
    } catch (err) {
      addToast({
        title: 'Verification Failed',
        description: err instanceof Error ? err.message : 'Invalid code',
        type: 'error',
      });
    } finally {
      setTfaBusy(false);
    }
  };

  const handleDisable2FA = async () => {
    setTfaBusy(true);
    try {
      await apiRequest('/api/auth/2fa/disable', { method: 'POST' });
      addToast({ title: 'Two-Factor Authentication Disabled', type: 'info' });
      await refreshUser();
    } finally {
      setTfaBusy(false);
    }
  };

  return (
    <AppLayout
      title="Account & 2FA Security"
      breadcrumb={`${user?.loginId || ''} · Security Preferences`}
    >
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Change Password */}
        <div className="bg-white border border-slate-200 rounded-xl p-6">
          <div className="flex items-center gap-2.5 mb-4">
            <KeyRound className="w-4 h-4 text-slate-700" />
            <h2 className="text-base font-bold text-slate-900">Change Password</h2>
          </div>
          <form onSubmit={handleChangePassword} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Current Password
              </label>
              <input
                type="password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                New Password (min 8 characters)
              </label>
              <input
                type="password"
                required
                minLength={8}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <button
              type="submit"
              disabled={pwdBusy}
              className="px-4 py-2 text-sm font-semibold text-white bg-[#0B192C] hover:bg-[#132946] rounded-lg cursor-pointer"
            >
              {pwdBusy ? 'Updating...' : 'Update Password'}
            </button>
          </form>
        </div>

        {/* Two-Factor Auth */}
        <div className="bg-white border border-slate-200 rounded-xl p-6">
          <div className="flex items-center justify-between gap-2 mb-4">
            <div className="flex items-center gap-2.5">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              <h2 className="text-base font-bold text-slate-900">Two-Factor Authentication (TOTP)</h2>
            </div>
            <span
              className={`text-xs font-semibold ${
                user?.twoFactorEnabled ? 'text-emerald-700' : 'text-slate-500'
              }`}
            >
              {user?.twoFactorEnabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>

          {user?.twoFactorEnabled ? (
            <div className="space-y-4">
              <p className="text-sm text-slate-600">
                Your account is protected with TOTP 6-digit authenticator verification at sign-in.
              </p>
              <button
                type="button"
                disabled={tfaBusy}
                onClick={handleDisable2FA}
                className="px-4 py-2 text-sm font-semibold text-red-700 bg-red-50 border border-red-200 hover:bg-red-100 rounded-lg cursor-pointer"
              >
                Disable 2FA
              </button>
            </div>
          ) : qrData ? (
            <form onSubmit={handleEnable2FA} className="space-y-4">
              <p className="text-xs text-slate-600">
                Scan this QR code in Google Authenticator, Microsoft Authenticator, or Authy, then enter the 6-digit code.
              </p>
              <div className="p-4 bg-white border border-slate-200 rounded-lg w-fit">
                <QRCodeSVG value={qrData.otpauthUrl} size={150} />
              </div>
              <p className="text-xs font-mono text-slate-600 break-all">
                Manual Key: <strong>{qrData.secret}</strong>
              </p>
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  required
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="6-digit code"
                  className="w-40 px-3 py-2 font-mono text-center border border-slate-300 rounded-lg"
                />
                <button
                  type="submit"
                  disabled={tfaBusy || totpCode.length !== 6}
                  className="px-4 py-2 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg cursor-pointer"
                >
                  Verify & Activate
                </button>
              </div>
            </form>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-slate-600">
                Add an extra verification step using any standard TOTP authenticator app.
              </p>
              <button
                type="button"
                disabled={tfaBusy}
                onClick={handleStart2FA}
                className="px-4 py-2 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg cursor-pointer"
              >
                Set Up 2FA Authenticator
              </button>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}

export function SystemConfigPage() {
  const { addToast } = useAuth();
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [expiryHours, setExpiryHours] = useState(72);
  const [departmentsText, setDepartmentsText] = useState('');
  const [demoMode, setDemoMode] = useState(true);
  const [busy, setBusy] = useState(false);
  const [resetConfirm, setResetConfirm] = useState(false);

  useEffect(() => {
    apiRequest<{ config: SystemConfig }>('/api/config')
      .then((res) => {
        setConfig(res.config);
        setExpiryHours(res.config.defaultLinkExpiryHours);
        setDepartmentsText(res.config.departments.join('\n'));
        setDemoMode(res.config.demoModeEnabled);
      })
      .catch(() => {});
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const departments = departmentsText
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await apiRequest<{ config: SystemConfig }>('/api/config', {
        method: 'PATCH',
        body: JSON.stringify({
          defaultLinkExpiryHours: expiryHours,
          departments,
          demoModeEnabled: demoMode,
        }),
      });
      setConfig(res.config);
      addToast({ title: 'System configuration saved', type: 'success' });
    } catch (err) {
      addToast({
        title: 'Save failed',
        description: err instanceof Error ? err.message : 'Error',
        type: 'error',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleResetDemo = async () => {
    setBusy(true);
    try {
      await apiRequest('/api/demo/reset', { method: 'POST' });
      addToast({
        title: 'Demo dataset restored',
        description: 'Live employee and candidate records were preserved.',
        type: 'success',
      });
      setResetConfirm(false);
    } catch (err) {
      addToast({
        title: 'Reset failed',
        description: err instanceof Error ? err.message : 'Error',
        type: 'error',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <AppLayout
      title="System Configuration"
      breadcrumb="Super Admin · Portal Policies & Demo Environment"
    >
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-5">
            <Sliders className="w-4 h-4 text-slate-700" />
            <h2 className="text-base font-bold text-slate-900">Onboarding Policy Settings</h2>
          </div>

          <form onSubmit={handleSave} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Default Onboarding Link Expiry (Hours)
              </label>
              <input
                type="number"
                min={1}
                max={720}
                value={expiryHours}
                onChange={(e) => setExpiryHours(Number(e.target.value))}
                className="w-48 px-3 py-2 text-sm font-mono border border-slate-300 rounded-lg"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Active Departments (One per line)
              </label>
              <textarea
                rows={6}
                value={departmentsText}
                onChange={(e) => setDepartmentsText(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>

            <label className="flex items-center gap-2.5 text-sm text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={demoMode}
                onChange={(e) => setDemoMode(e.target.checked)}
                className="rounded border-slate-300 text-emerald-600"
              />
              <span>Enable Controlled Demonstration Dataset</span>
            </label>

            <button
              type="submit"
              disabled={busy}
              className="px-4 py-2 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg cursor-pointer"
            >
              {busy ? 'Saving...' : 'Save Configuration'}
            </button>
          </form>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-5 h-fit">
          <div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">Environment Diagnostics</h3>
            <p className="text-xs text-slate-500">
              SMTP Relay: <strong>{config?.smtpConfigured ? 'Configured' : 'Manual Share Mode'}</strong>
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Max Upload Size: <strong>{config?.maxUploadSizeMb ?? 5} MB</strong> (PDF, JPG, PNG)
            </p>
          </div>
          <div className="pt-4 border-t border-slate-100">
            <h3 className="text-sm font-bold text-slate-900 mb-1">Restore Demo Dataset</h3>
            <p className="text-xs text-slate-500 mb-3">
              Resets sample demo candidates and demo employees without affecting live records.
            </p>
            <button
              type="button"
              onClick={() => setResetConfirm(true)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Reset Demo Data
            </button>
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={resetConfirm}
        onClose={() => setResetConfirm(false)}
        onConfirm={handleResetDemo}
        loading={busy}
        title="Restore Demo Dataset"
        message="Sample demo candidates and demo employees will be restored to their default showcase state. Any live candidates or employees you registered will remain untouched."
        confirmLabel="Restore Demo Data"
      />
    </AppLayout>
  );
}
