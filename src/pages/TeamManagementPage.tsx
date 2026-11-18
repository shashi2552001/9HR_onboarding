import React, { useCallback, useEffect, useState } from 'react';
import { Check, Copy, KeyRound, Plus, ShieldOff, UserCheck } from 'lucide-react';
import { AppLayout } from '../components/Layout.tsx';
import { Modal, TableSkeleton } from '../components/ui/Primitives.tsx';
import { useAuth } from '../contexts/AuthContext.tsx';
import { apiRequest } from '../lib/api.ts';
import { StaffRole, StaffUser } from '../shared/types.ts';

export default function TeamManagementPage() {
  const { user, addToast } = useAuth();
  const [users, setUsers] = useState<StaffUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({
    fullName: '',
    email: '',
    role: 'HR' as StaffRole,
    department: 'Human Resources',
    loginId: '',
    password: '',
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [issuedCreds, setIssuedCreds] = useState<{
    loginId: string;
    email: string;
    temporaryPassword: string;
  } | null>(null);
  const [copied, setCopied] = useState(false);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiRequest<{ users: StaffUser[] }>('/api/staff');
      setUsers(res.users);
    } catch (err) {
      addToast({
        title: 'Access Error',
        description: err instanceof Error ? err.message : 'Unable to load staff.',
        type: 'error',
      });
    } finally {
      setLoading(false);
    }
  }, [addToast]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const payload = {
        fullName: form.fullName,
        email: form.email,
        role: form.role,
        department: form.department,
        ...(form.loginId.trim() ? { loginId: form.loginId.trim() } : {}),
        ...(form.password.trim() ? { password: form.password } : {}),
      };
      const res = await apiRequest<{
        user: StaffUser;
        temporaryCredentials: {
          loginId: string;
          email: string;
          temporaryPassword: string;
        };
      }>('/api/staff', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      setCreateOpen(false);
      setForm({
        fullName: '',
        email: '',
        role: 'HR',
        department: 'Human Resources',
        loginId: '',
        password: '',
      });
      setIssuedCreds(res.temporaryCredentials);
      addToast({ title: `Created ${res.user.loginId}`, type: 'success' });
      loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create staff account.');
    } finally {
      setBusy(false);
    }
  };

  const handleToggleActive = async (target: StaffUser) => {
    try {
      await apiRequest(`/api/staff/${target.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ isActive: !target.isActive }),
      });
      addToast({
        title: target.isActive ? 'Account Deactivated' : 'Account Activated',
        type: 'info',
      });
      loadUsers();
    } catch (err) {
      addToast({
        title: 'Action failed',
        description: err instanceof Error ? err.message : 'Error',
        type: 'error',
      });
    }
  };

  const handleResetPassword = async (target: StaffUser) => {
    try {
      const res = await apiRequest<{ user: StaffUser; temporaryPassword?: string }>(
        `/api/staff/${target.id}`,
        {
          method: 'PATCH',
          body: JSON.stringify({ resetPassword: true }),
        }
      );
      if (res.temporaryPassword) {
        setIssuedCreds({
          loginId: res.user.loginId,
          email: res.user.email,
          temporaryPassword: res.temporaryPassword,
        });
      }
      addToast({ title: `Temporary password regenerated for ${target.loginId}`, type: 'success' });
    } catch (err) {
      addToast({
        title: 'Reset failed',
        description: err instanceof Error ? err.message : 'Error',
        type: 'error',
      });
    }
  };

  const handleReset2FA = async (target: StaffUser) => {
    try {
      await apiRequest(`/api/staff/${target.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ reset2FA: true }),
      });
      addToast({ title: `2FA reset for ${target.loginId}`, type: 'info' });
      loadUsers();
    } catch (err) {
      addToast({
        title: '2FA reset failed',
        description: err instanceof Error ? err.message : 'Error',
        type: 'error',
      });
    }
  };

  return (
    <AppLayout
      title="Team & Role Management"
      breadcrumb="9HR India Pvt. Ltd. · Staff Accounts & Temporary Credentials"
      primaryAction={
        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs sm:text-sm font-semibold rounded-lg cursor-pointer whitespace-nowrap"
        >
          <Plus className="w-4 h-4" />
          Add Staff Account
        </button>
      }
    >
      {loading ? (
        <TableSkeleton rows={5} />
      ) : (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-600">
                  <th className="py-3 px-4">Login ID</th>
                  <th className="py-3 px-4">Staff Member</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Department</th>
                  <th className="py-3 px-4">2FA</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-sm">
                {users.map((u) => {
                  const canManage =
                    user?.role === 'SUPER_ADMIN' || (user?.role === 'ADMIN' && u.role === 'HR');
                  return (
                    <tr key={u.id} className="hover:bg-slate-50/70">
                      <td className="py-3 px-4 font-mono text-xs font-bold text-slate-800 whitespace-nowrap">
                        {u.loginId}
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-900">{u.fullName}</div>
                        <div className="text-xs text-slate-500">{u.email}</div>
                      </td>
                      <td className="py-3 px-4 text-xs font-semibold text-slate-700">
                        {u.role.replace('_', ' ')}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-600">{u.department}</td>
                      <td className="py-3 px-4 text-xs">
                        <span className={u.twoFactorEnabled ? 'text-emerald-700 font-semibold' : 'text-slate-400'}>
                          {u.twoFactorEnabled ? 'Enabled' : 'Off'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-xs">
                        <span className={u.isActive ? 'text-emerald-700 font-semibold' : 'text-red-600 font-semibold'}>
                          {u.isActive ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        {canManage && u.id !== user?.id ? (
                          <div className="inline-flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => handleResetPassword(u)}
                              title="Issue new temporary password"
                              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 border border-slate-200 rounded hover:bg-slate-50 cursor-pointer"
                            >
                              <KeyRound className="w-3 h-3" />
                              Temp Password
                            </button>
                            {u.twoFactorEnabled && (
                              <button
                                type="button"
                                onClick={() => handleReset2FA(u)}
                                title="Reset 2FA"
                                className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-amber-700 border border-amber-200 rounded hover:bg-amber-50 cursor-pointer"
                              >
                                <ShieldOff className="w-3 h-3" />
                                Reset 2FA
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => handleToggleActive(u)}
                              className={`px-2.5 py-1 text-xs font-semibold rounded border cursor-pointer ${
                                u.isActive
                                  ? 'text-red-700 border-red-200 hover:bg-red-50'
                                  : 'text-emerald-700 border-emerald-200 hover:bg-emerald-50'
                              }`}
                            >
                              {u.isActive ? 'Deactivate' : 'Activate'}
                            </button>
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400">
                            {u.id === user?.id ? 'Current User' : 'Restricted'}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create Staff Modal */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Create Staff Account"
        subtitle="Generates a unique Login ID and temporary password hashed with bcrypt."
      >
        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700">
            {error}
          </div>
        )}
        <form onSubmit={handleCreate} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="sm:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">Full Name *</label>
              <input
                type="text"
                required
                value={form.fullName}
                onChange={(e) => setForm({ ...form, fullName: e.target.value })}
                placeholder="e.g., Neha Kapoor"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Corporate Email *</label>
              <input
                type="email"
                required
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                placeholder="neha.kapoor@9hrindia.com"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Role *</label>
              <select
                value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value as StaffRole })}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg bg-white"
              >
                <option value="HR">HR / Recruiter</option>
                {user?.role === 'SUPER_ADMIN' && <option value="ADMIN">Admin</option>}
                {user?.role === 'SUPER_ADMIN' && <option value="SUPER_ADMIN">Super Admin</option>}
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Department *</label>
              <input
                type="text"
                required
                value={form.department}
                onChange={(e) => setForm({ ...form, department: e.target.value })}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Custom Login ID (optional)
              </label>
              <input
                type="text"
                value={form.loginId}
                onChange={(e) => setForm({ ...form, loginId: e.target.value })}
                placeholder="Auto-generated if blank"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono"
              />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Temporary Password (optional — auto-generated if left blank)
              </label>
              <input
                type="text"
                minLength={8}
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                placeholder="Leave blank to generate secure temporary password"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-200">
            <button
              type="button"
              onClick={() => setCreateOpen(false)}
              className="px-4 py-2 text-sm font-medium text-slate-700 border border-slate-300 rounded-lg cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="px-4 py-2 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg cursor-pointer"
            >
              {busy ? 'Creating...' : 'Create Account'}
            </button>
          </div>
        </form>
      </Modal>

      {/* One-Time Temporary Credentials Display Modal */}
      <Modal
        open={Boolean(issuedCreds)}
        onClose={() => {
          setIssuedCreds(null);
          setCopied(false);
        }}
        title="Temporary Login Credentials Issued"
        subtitle="Share these credentials securely. Passwords are stored hashed and cannot be viewed again."
      >
        {issuedCreds && (
          <div className="space-y-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg font-mono text-xs space-y-2">
              <p>
                <span className="text-slate-500">Login ID:</span>{' '}
                <strong className="text-slate-900">{issuedCreds.loginId}</strong>
              </p>
              <p>
                <span className="text-slate-500">Email:</span>{' '}
                <strong className="text-slate-900">{issuedCreds.email}</strong>
              </p>
              <p>
                <span className="text-slate-500">Temporary Password:</span>{' '}
                <strong className="text-emerald-700">{issuedCreds.temporaryPassword}</strong>
              </p>
            </div>
            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={async () => {
                  const text = `9HR India Portal Login\nLogin ID: ${issuedCreds.loginId}\nEmail: ${issuedCreds.email}\nTemporary Password: ${issuedCreds.temporaryPassword}`;
                  await navigator.clipboard.writeText(text);
                  setCopied(true);
                  addToast({ title: 'Credentials copied', type: 'success' });
                }}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-white bg-[#0B192C] rounded-lg cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy Credentials'}
              </button>
              <button
                type="button"
                onClick={() => setIssuedCreds(null)}
                className="px-4 py-2 text-xs font-semibold text-white bg-emerald-600 rounded-lg cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>
    </AppLayout>
  );
}
