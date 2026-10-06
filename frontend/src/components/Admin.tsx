import { Ban, FileText, History, Settings2, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import {
  fetchActivity,
  fetchAdminStatus,
  fetchBans,
  fetchReports,
  fmtT,
  postPassword,
  postSetup,
  postUnban,
  relT,
  type ActivityEntry,
  type AdminStatus,
  type BanEntry,
  type ReportEntry,
} from '../lib/api';
import { Badge, Card, Empty, Skeleton } from './ui';

type Tab = 'bans' | 'reports' | 'activity' | 'settings';

export default function Admin() {
  const [status, setStatus] = useState<AdminStatus | null>(null);
  const [tab, setTab] = useState<Tab>('bans');
  const [err, setErr] = useState('');

  useEffect(() => {
    let live = true;
    fetchAdminStatus()
      .then((s) => live && setStatus(s))
      .catch((e) => live && setErr(e.message));
    return () => {
      live = false;
    };
  }, []);

  if (err) return <div className="rounded-xl border border-[#f85149]/50 bg-[#f85149]/10 p-3 text-sm text-[#ff9d97]">Admin failed: {err}</div>;
  if (!status) return <Skeleton className="h-64" />;

  return (
    <div className="space-y-4">
      {status.setup_needed && <SetupCard onDone={() => window.location.reload()} />}
      <div className="flex flex-wrap gap-1.5">
        {(
          [
            ['bans', 'Bans', <Ban key="b" size={14} />],
            ['reports', 'Reports', <FileText key="r" size={14} />],
            ['activity', 'Activity', <History key="a" size={14} />],
            ['settings', 'Settings', <Settings2 key="s" size={14} />],
          ] as [Tab, string, React.ReactNode][]
        ).map(([id, label, icon]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`inline-flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-sm ring-1 ring-inset transition-all ${
              tab === id
                ? 'bg-[#58a6ff]/20 text-white ring-[#58a6ff]/50'
                : 'bg-white/[.02] text-[#8b98ad] ring-white/10 hover:bg-white/5 hover:text-white'
            }`}
          >
            {icon}
            {label}
          </button>
        ))}
      </div>
      {tab === 'bans' && <BansTab />}
      {tab === 'reports' && <ReportsTab />}
      {tab === 'activity' && <ActivityTab />}
      {tab === 'settings' && <SettingsTab status={status} />}
    </div>
  );
}

function BansTab() {
  const [rows, setRows] = useState<BanEntry[] | null>(null);
  const [err, setErr] = useState('');
  const load = useCallback(() => {
    fetchBans()
      .then(setRows)
      .catch((e) => setErr(e.message));
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  if (err) return <div className="text-sm text-[#ff9d97]">{err}</div>;
  if (!rows) return <Skeleton className="h-48" />;
  return (
    <Card title={`Active bans (${rows.length})`} icon={<Ban size={15} className="text-[#f85149]" />}>
      {rows.length === 0 && <Empty>No active bans. Ban an IP from the attacker modal.</Empty>}
      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[620px] text-sm">
            <thead>
              <tr className="text-left text-xs text-[#8b98ad]">
                <th className="pb-2 pr-3 font-medium">IP</th>
                <th className="pb-2 pr-3 font-medium">Source</th>
                <th className="pb-2 pr-3 font-medium">Reason</th>
                <th className="pb-2 pr-3 font-medium">Expires</th>
                <th className="pb-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((b) => (
                <tr key={b.ip} className="border-t border-[#1e2a3f]">
                  <td className="py-1.5 pr-3 font-mono text-[#a5d6ff]">{b.ip}</td>
                  <td className="py-1.5 pr-3">
                    <Badge tone={b.source === 'auto' ? 'warn' : 'info'}>{b.source}</Badge>
                  </td>
                  <td className="py-1.5 pr-3 text-[#8b98ad]">{b.reason || '—'}</td>
                  <td className="py-1.5 pr-3 text-xs text-[#8b98ad]">{b.expires ? fmtT(b.expires) : '—'}</td>
                  <td className="py-1.5">
                    <button
                      onClick={() => postUnban(b.ip).then(load).catch((e) => setErr(e.message))}
                      className="rounded-lg bg-white/5 px-2.5 py-1 text-xs ring-1 ring-inset ring-white/10 hover:bg-white/10"
                    >
                      Unban
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function ReportsTab() {
  const [rows, setRows] = useState<ReportEntry[] | null>(null);
  useEffect(() => {
    fetchReports().then(setRows).catch(() => setRows([]));
  }, []);
  if (!rows) return <Skeleton className="h-48" />;
  return (
    <Card title={`Abuse reports (${rows.length})`} icon={<FileText size={15} className="text-[#58a6ff]" />}>
      {rows.length === 0 && <Empty>No reports yet. High-risk IPs report once per throttle window.</Empty>}
      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-sm">
            <thead>
              <tr className="text-left text-xs text-[#8b98ad]">
                <th className="pb-2 pr-3 font-medium">IP</th>
                <th className="pb-2 pr-3 font-medium">Provider</th>
                <th className="pb-2 pr-3 font-medium">Time</th>
                <th className="pb-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={`${r.ip}-${r.provider}-${i}`} className="border-t border-[#1e2a3f]">
                  <td className="py-1.5 pr-3 font-mono">{r.ip}</td>
                  <td className="py-1.5 pr-3">{r.provider}</td>
                  <td className="py-1.5 pr-3 text-xs text-[#8b98ad]">{fmtT(r.ts)}</td>
                  <td className="py-1.5">
                    <Badge tone={r.status === 'sent' ? 'ok' : 'warn'}>{r.status}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function ActivityTab() {
  const [rows, setRows] = useState<ActivityEntry[] | null>(null);
  useEffect(() => {
    fetchActivity().then(setRows).catch(() => setRows([]));
  }, []);
  if (!rows) return <Skeleton className="h-48" />;
  return (
    <Card title={`Activity (${rows.length})`} icon={<History size={15} className="text-[#3fb950]" />}>
      {rows.length === 0 && <Empty>No admin activity yet.</Empty>}
      <div className="max-h-[480px] space-y-1 overflow-y-auto">
        {rows.map((a, i) => (
          <div key={i} className="flex flex-wrap items-center gap-2 rounded-lg bg-black/30 px-2.5 py-1.5 text-xs">
            <span className="text-[#8b98ad]">{relT(a.ts)}</span>
            <Badge tone="dim">{a.action}</Badge>
            {a.ip && <span className="font-mono text-[#a5d6ff]">{a.ip}</span>}
            <span className="text-[#8b98ad]">
              {a.actor} · {a.detail}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}

function SettingsTab({ status }: { status: AdminStatus }) {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Card title="Enforcement" icon={<ShieldCheck size={15} className="text-[#3fb950]" />}>
        <dl className="space-y-1.5 text-sm">
          {[
            ['Bans', status.ban_enabled ? 'on' : 'off'],
            ['Auto-ban', status.ban_auto ? `on (${status.ban_threshold} fails / ${status.ban_window}s)` : 'off'],
            ['Jail', status.ban_jail],
            ['Reports', status.report_enabled ? `on (${status.report_provider}, ${status.report_throttle_days}d throttle)` : 'off'],
            ['Auth mode', status.auth_mode],
          ].map(([k, v]) => (
            <div key={k} className="flex gap-2">
              <dt className="w-24 shrink-0 text-[#8b98ad]">{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
        <p className="mt-3 text-xs text-[#8b98ad]">
          Change values with env vars (BAN_*, REPORT_*, see .env.example). Restart central to apply.
        </p>
      </Card>
      <PasswordCard />
    </div>
  );
}

function PasswordCard() {
  const [oldPw, setOldPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [msg, setMsg] = useState('');
  return (
    <Card title="Change admin password" icon={<Settings2 size={15} className="text-[#58a6ff]" />}>
      <div className="space-y-2">
        <input
          type="password"
          value={oldPw}
          onChange={(e) => setOldPw(e.target.value)}
          placeholder="old password"
          className="w-full rounded-xl border border-[#1e2a3f] bg-black/30 px-3 py-2 text-sm outline-none focus:border-[#58a6ff]/60"
        />
        <input
          type="password"
          value={newPw}
          onChange={(e) => setNewPw(e.target.value)}
          placeholder="new password (min 8)"
          className="w-full rounded-xl border border-[#1e2a3f] bg-black/30 px-3 py-2 text-sm outline-none focus:border-[#58a6ff]/60"
        />
        <button
          onClick={() =>
            postPassword(oldPw, newPw)
              .then(() => setMsg('Password changed.'))
              .catch((e) => setMsg(`Failed: ${e.message}`))
          }
          className="rounded-xl bg-[#58a6ff]/20 px-3 py-1.5 text-sm text-white ring-1 ring-inset ring-[#58a6ff]/50 hover:bg-[#58a6ff]/30"
        >
          Change
        </button>
        {msg && <p className="text-xs text-[#8b98ad]">{msg}</p>}
        <p className="text-xs text-[#8b98ad]">File-based setup only. Env credential wins when set.</p>
      </div>
    </Card>
  );
}

function SetupCard({ onDone }: { onDone: () => void }) {
  const [token, setToken] = useState('');
  const [user, setUser] = useState('admin');
  const [pw, setPw] = useState('');
  const [msg, setMsg] = useState('');
  return (
    <div className="rounded-xl border border-[#d29922]/50 bg-[#d29922]/10 p-4">
      <h3 className="mb-1 text-sm font-bold text-[#e8b93e]">First setup needed — create the admin login</h3>
      <p className="mb-3 text-xs text-[#8b98ad]">
        No local credential is set. Enter the one-time token from the central log (or ADMIN_SETUP_TOKEN), pick a user and a password.
      </p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="setup token"
          className="rounded-xl border border-[#1e2a3f] bg-black/30 px-3 py-2 text-sm outline-none focus:border-[#58a6ff]/60"
        />
        <input
          value={user}
          onChange={(e) => setUser(e.target.value)}
          placeholder="admin user"
          className="rounded-xl border border-[#1e2a3f] bg-black/30 px-3 py-2 text-sm outline-none focus:border-[#58a6ff]/60"
        />
        <input
          type="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          placeholder="password (min 8)"
          className="rounded-xl border border-[#1e2a3f] bg-black/30 px-3 py-2 text-sm outline-none focus:border-[#58a6ff]/60"
        />
      </div>
      <div className="mt-2 flex items-center gap-2">
        <button
          onClick={() =>
            postSetup(token, user, pw)
              .then(onDone)
              .catch((e) => setMsg(`Failed: ${e.message}`))
          }
          className="rounded-xl bg-[#58a6ff]/20 px-3 py-1.5 text-sm text-white ring-1 ring-inset ring-[#58a6ff]/50 hover:bg-[#58a6ff]/30"
        >
          Create admin
        </button>
        {msg && <span className="text-xs text-[#ff9d97]">{msg}</span>}
      </div>
    </div>
  );
}
