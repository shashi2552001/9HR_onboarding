import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  ArrowRight,
  BarChart3,
  Box,
  CheckCircle2,
  Clock,
  FileCheck2,
  FileClock,
  Plus,
  ShieldCheck,
  UserPlus,
  Users,
  XCircle,
} from 'lucide-react';
import { AppLayout } from '../components/Layout.tsx';
import { Pipeline3DScene } from '../components/three/Pipeline3DScene.tsx';
import { StatusIndicator, TableSkeleton } from '../components/ui/Primitives.tsx';
import { useAuth } from '../contexts/AuthContext.tsx';
import { apiRequest } from '../lib/api.ts';
import { AnalyticsSummary, Candidate } from '../shared/types.ts';

const PIE_COLORS = [
  '#0B192C',
  '#059669',
  '#0284C7',
  '#D97706',
  '#64748B',
  '#10B981',
  '#DC2626',
  '#334155',
];

export default function DashboardPage() {
  const { user } = useAuth();
  const [scope, setScope] = useState<'all' | 'live' | 'demo'>('all');
  const [viewMode, setViewMode] = useState<'3d' | '2d'>('3d');
  const [analytics, setAnalytics] = useState<AnalyticsSummary | null>(null);
  const [recentCandidates, setRecentCandidates] = useState<Candidate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    Promise.all([
      apiRequest<AnalyticsSummary>(`/api/analytics?scope=${scope}`),
      apiRequest<{ items: Candidate[] }>(`/api/candidates?scope=${scope}&pageSize=6`),
    ])
      .then(([analyticsData, candData]) => {
        if (!active) return;
        setAnalytics(analyticsData);
        setRecentCandidates(candData.items);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Failed to load dashboard metrics.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [scope]);

  const kpiCards = analytics
    ? [
        {
          label: 'Total Candidates',
          value: analytics.kpis.totalCandidates,
          icon: <Users className="w-4 h-4 text-slate-600" />,
          tone: 'text-slate-900',
        },
        {
          label: 'New Applications',
          value: analytics.kpis.newApplications,
          icon: <UserPlus className="w-4 h-4 text-sky-600" />,
          tone: 'text-sky-700',
        },
        {
          label: 'Pending Onboarding',
          value: analytics.kpis.pendingOnboarding,
          icon: <Clock className="w-4 h-4 text-amber-600" />,
          tone: 'text-amber-700',
        },
        {
          label: 'Documents Pending',
          value: analytics.kpis.documentsPending,
          icon: <FileClock className="w-4 h-4 text-amber-600" />,
          tone: 'text-amber-700',
        },
        {
          label: 'Documents Verified',
          value: analytics.kpis.documentsVerified,
          icon: <FileCheck2 className="w-4 h-4 text-emerald-600" />,
          tone: 'text-emerald-700',
        },
        {
          label: 'Onboarding Completed',
          value: analytics.kpis.onboardingCompleted,
          icon: <CheckCircle2 className="w-4 h-4 text-emerald-600" />,
          tone: 'text-emerald-700',
        },
        {
          label: 'Rejected Applications',
          value: analytics.kpis.rejectedApplications,
          icon: <XCircle className="w-4 h-4 text-red-600" />,
          tone: 'text-red-700',
        },
      ]
    : [];

  return (
    <AppLayout
      title="Onboarding Dashboard"
      breadcrumb="9HR India Pvt. Ltd. · Overview & Analytics"
      primaryAction={
        <Link
          to="/candidates?new=1"
          className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs sm:text-sm font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0"
        >
          <Plus className="w-4 h-4" />
          Register Candidate
        </Link>
      }
    >
      {/* Scope & View Mode Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1 p-1 bg-slate-200/70 rounded-lg">
            {(['all', 'live', 'demo'] as const).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setScope(s)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                  scope === s
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {s === 'all' ? 'All Records' : s === 'live' ? 'Live Records Only' : 'Demo Records'}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 p-1 bg-slate-200/70 rounded-lg">
            <button
              type="button"
              onClick={() => setViewMode('3d')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                viewMode === '3d'
                  ? 'bg-[#0B192C] text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Box className="w-3.5 h-3.5" />
              3D Pipeline &amp; Authority
            </button>
            <button
              type="button"
              onClick={() => setViewMode('2d')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                viewMode === '2d'
                  ? 'bg-[#0B192C] text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              2D Analytics Charts
            </button>
          </div>
        </div>

        <div className="inline-flex items-center gap-2 text-xs text-slate-600 bg-white border border-slate-200 px-3 py-1.5 rounded-lg">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
          <span>
            Authority:{' '}
            <strong className="text-slate-900">
              {user?.role === 'SUPER_ADMIN'
                ? 'Super Admin (Full System, Config & Approvals)'
                : user?.role === 'ADMIN'
                  ? 'Admin (HR Management, Approvals & Employee Conversion)'
                  : 'HR / Recruiter (Candidate Intake, Links & Document Review)'}
            </strong>
          </span>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-sm text-red-700">
          {error}
        </div>
      )}

      {loading || !analytics ? (
        <div className="space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-7 gap-4">
            {Array.from({ length: 7 }).map((_, i) => (
              <div key={i} className="bg-white border border-slate-200 rounded-xl p-4 h-24 animate-pulse" />
            ))}
          </div>
          <TableSkeleton rows={5} />
        </div>
      ) : (
        <div className="space-y-6">
          {/* 7 Required KPI Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-7 gap-4">
            {kpiCards.map((k) => (
              <div
                key={k.label}
                className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between gap-2 mb-3">
                  <span className="text-xs font-medium text-slate-500 leading-snug">
                    {k.label}
                  </span>
                  {k.icon}
                </div>
                <span className={`font-mono text-2xl font-bold tabular-nums ${k.tone}`}>
                  {k.value}
                </span>
              </div>
            ))}
          </div>

          {/* Spatial 3D Pipeline OR 2D Analytics Charts */}
          {viewMode === '3d' ? (
            <Pipeline3DScene analytics={analytics} userRole={user?.role} />
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* 1. Monthly Onboarding Statistics */}
            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-sm font-bold text-slate-900">
                    Monthly Onboarding Statistics
                  </h2>
                  <p className="text-xs text-slate-500">
                    Registered candidates vs. completed onboardings (6-month trend)
                  </p>
                </div>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={analytics.monthlyStats}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                    <XAxis dataKey="month" tick={{ fontSize: 12, fill: '#64748B' }} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: '#64748B' }} />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="registered"
                      name="Registered"
                      stroke="#0B192C"
                      fill="#0B192C"
                      fillOpacity={0.12}
                      strokeWidth={2}
                    />
                    <Area
                      type="monotone"
                      dataKey="completed"
                      name="Completed"
                      stroke="#059669"
                      fill="#059669"
                      fillOpacity={0.18}
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* 2. Department-wise Candidates */}
            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <div className="mb-4">
                <h2 className="text-sm font-bold text-slate-900">
                  Department-wise Candidates
                </h2>
                <p className="text-xs text-slate-500">
                  Active pipeline and completed hires across departments
                </p>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={analytics.departmentStats}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                    <XAxis
                      dataKey="department"
                      tick={{ fontSize: 11, fill: '#64748B' }}
                      interval={0}
                      angle={-15}
                      textAnchor="end"
                      height={50}
                    />
                    <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: '#64748B' }} />
                    <Tooltip />
                    <Bar dataKey="count" name="Total Candidates" fill="#0B192C" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="completed" name="Completed" fill="#059669" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* 3. Application Status Distribution */}
            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <div className="mb-4">
                <h2 className="text-sm font-bold text-slate-900">
                  Application Status Distribution
                </h2>
                <p className="text-xs text-slate-500">
                  Current breakdown across all onboarding lifecycle stages
                </p>
              </div>
              <div className="h-64 grid sm:grid-cols-2 items-center gap-4">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={analytics.statusDistribution}
                      dataKey="count"
                      nameKey="status"
                      innerRadius={52}
                      outerRadius={84}
                      paddingAngle={2}
                    >
                      {analytics.statusDistribution.map((entry, idx) => (
                        <Cell
                          key={entry.status}
                          fill={PIE_COLORS[idx % PIE_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
                <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                  {analytics.statusDistribution.map((item, idx) => (
                    <div
                      key={item.status}
                      className="flex items-center justify-between text-xs py-1 border-b border-slate-100 last:border-0"
                    >
                      <span className="flex items-center gap-2 text-slate-700 truncate">
                        <span
                          className="w-2.5 h-2.5 rounded-sm shrink-0"
                          style={{ backgroundColor: PIE_COLORS[idx % PIE_COLORS.length] }}
                        />
                        <span className="truncate">{item.status}</span>
                      </span>
                      <span className="font-mono font-semibold tabular-nums text-slate-900">
                        {item.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* 4. Recruitment Conversion Rate */}
            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <div className="mb-4">
                <h2 className="text-sm font-bold text-slate-900">
                  Recruitment Conversion Rate
                </h2>
                <p className="text-xs text-slate-500">
                  Stage-by-stage completion funnel from registration to employee record
                </p>
              </div>
              <div className="space-y-3.5 pt-2">
                {analytics.conversionFunnel.map((step) => (
                  <div key={step.stage}>
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <span className="font-semibold text-slate-800">{step.stage}</span>
                      <span className="font-mono tabular-nums text-slate-600">
                        {step.count} candidates · {step.rate}%
                      </span>
                    </div>
                    <div className="w-full h-2.5 bg-slate-100 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-emerald-600 rounded-full transition-all"
                        style={{ width: `${step.rate}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
            </div>
          )}

          {/* Recent Applications Table */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-bold text-slate-900">Recent Onboarding Pipeline</h2>
                <p className="text-xs text-slate-500">
                  Latest candidates requiring review, verification, or conversion
                </p>
              </div>
              <Link
                to="/candidates"
                className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-800 whitespace-nowrap"
              >
                View All Candidates
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-600">
                    <th className="py-3 px-4">Candidate ID</th>
                    <th className="py-3 px-4">Candidate Name</th>
                    <th className="py-3 px-4">Position · Department</th>
                    <th className="py-3 px-4">Joining Date</th>
                    <th className="py-3 px-4 text-right">Completion</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-sm">
                  {recentCandidates.map((c) => (
                    <tr key={c.id} className="hover:bg-slate-50/70 transition-colors">
                      <td className="py-3 px-4 font-mono text-xs text-slate-600 whitespace-nowrap">
                        {c.candidateCode}
                        {c.isDemo && (
                          <span className="ml-1.5 text-[11px] font-sans text-slate-400">
                            · Demo
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-medium text-slate-900">
                        <div>{c.fullName}</div>
                        <div className="text-xs text-slate-500">{c.email}</div>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-700">
                        <div className="font-medium text-slate-900">{c.position}</div>
                        <div className="text-slate-500">{c.department}</div>
                      </td>
                      <td className="py-3 px-4 font-mono text-xs tabular-nums text-slate-600 whitespace-nowrap">
                        {c.joiningDate}
                      </td>
                      <td className="py-3 px-4 text-right font-mono text-xs font-semibold tabular-nums text-slate-900">
                        {c.completionPct}%
                      </td>
                      <td className="py-3 px-4">
                        <StatusIndicator status={c.status} />
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link
                          to={`/candidates/${c.id}`}
                          className="text-xs font-semibold text-emerald-700 hover:text-emerald-800 whitespace-nowrap"
                        >
                          Review
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </AppLayout>
  );
}
