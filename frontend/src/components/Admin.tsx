import { Ban, FileText, History, Settings2, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import {
  fetchActivity,
  fetchAdminStatus,
  fetchBans,
  fetchEnforcement,
  fetchReports,
  fmtT,
  postEnforcement,
  postPassword,
  postSetup,
  postUnban,
  relT,
  type ActivityEntry,
  type AdminStatus,
  type BanEntry,
  type ReportEntry,
} from '../lib/api';
import { maskIp, useMask } from './Mask';
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
  const { masked } = useMask();
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
          <table className="w-full min-w-[760px] text-sm">
            <thead>
              <tr className="text-left text-xs text-[#8b98ad]">
                <th className="pb-2 pr-3 font-medium">IP</th>
                <th className="pb-2 pr-3 font-medium">Source</th>
                <th className="pb-2 pr-3 font-medium">Reason</th>
                <th className="pb-2 pr-3 font-medium">Created</th>
                <th className="pb-2 pr-3 font-medium">Expires</th>
                <th className="pb-2 pr-3 font-medium">Block</th>
                <th className="pb-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((b) => (
                <tr key={b.ip} className="border-t border-[#1e2a3f]">
                  <td className="py-1.5 pr-3 font-mono text-[#a5d6ff]">{maskIp(b.ip, masked)}</td>
                  <td className="py-1.5 pr-3">
                    <Badge tone={b.source === 'auto' ? 'warn' : 'info'}>{b.source}</Badge>
                  </td>
                  <td className="py-1.5 pr-3 text-[#8b98ad]">{b.reason || '—'}</td>
                  <td className="py-1.5 pr-3 text-xs text-[#8b98ad]">{b.created ? fmtT(b.created) : '—'}</td>
                  <td className="py-1.5 pr-3 text-xs text-[#8b98ad]" title="Ban record becomes inactive at this time. Firewall block needs BAN_ENABLED=1 plus fail2ban.">
                    {b.expires ? `${fmtT(b.expires)} · ${relT(b.expires)}` : '—'}
                  </td>
                  <td className="py-1.5 pr-3">
                    {b.fail2ban_ok ? <Badge tone="ok">firewall</Badge> : <Badge tone="dim" title="DB plus banlist only. Set BAN_ENABLED=1 with fail2ban to drop packets.">monitor</Badge>}
                  </td>
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
      <p className="mt-3 text-xs text-[#8b98ad]">
        Expires means the ban record turns inactive at that time. Sentinel alone never drops packets.
        Real block needs BAN_ENABLED=1 plus fail2ban on the host. Banned IPs can still show in logs when block is off.
      </p>
    </Card>
  );
}

function ReportsTab() {
  const [rows, setRows] = useState<ReportEntry[] | null>(null);
  const { masked } = useMask();
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
                  <td className="py-1.5 pr-3 font-mono">{maskIp(r.ip, masked)}</td>
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
  const { masked } = useMask();
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
            {a.ip && <span className="font-mono text-[#a5d6ff]">{maskIp(a.ip, masked)}</span>}
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
  const [vals, setVals] = useState<Record<string, string | number | boolean>>({
    ban_enabled: status.ban_enabled,
    ban_jail: status.ban_jail,
    ban_time: status.ban_time ?? 86400,
    ban_auto: status.ban_auto,
    ban_threshold: status.ban_threshold,
    ban_window: status.ban_window,
    ban_auto_time: status.ban_auto_time ?? 86400,
    report_enabled: status.report_enabled,
    report_provider: status.report_provider,
    report_throttle_days: status.report_throttle_days,
    report_min_risk: status.report_min_risk ?? 60,
    report_min_hits: status.report_min_hits ?? 20,
    whitelist_ips: status.whitelist_ips ?? '',
    trusted_ips: status.trusted_ips ?? '',
    trusted_users: status.trusted_users ?? '',
    self_public_ips: status.self_public_ips ?? '',
    abusers_min_hits: status.abusers_min_hits ?? 5,
    abusers_min_score: status.abusers_min_score ?? 25,
    abusers_public: status.abusers_public ?? false,
  });
  const [locked, setLocked] = useState<Record<string, boolean>>(status.enforce_locked ?? {});
  const [sources, setSources] = useState<Record<string, string>>(status.enforce_sources ?? {});
  const [msg, setMsg] = useState('');
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    fetchEnforcement().then((c) => {
      setVals({ ...c.values });
      setLocked(c.locked);
      setSources(c.sources);
    }).catch(() => { /* status values stay */ });
  }, []);
  const set = (k: string, v: string | number | boolean) => setVals((p) => ({ ...p, [k]: v }));
  const save = () => {
    setSaving(true);
    setMsg('');
    postEnforcement(vals)
      .then((r) => {
        setVals({ ...r.config.values });
        setLocked(r.config.locked);
        setSources(r.config.sources);
        const n = Object.keys(r.updated || {}).length;
        const skip = Object.keys(r.skipped || {}).length;
        setMsg(n ? `Saved ${n} setting${n === 1 ? '' : 's'}. Applies now, no restart.` : skip ? `Skipped: env locked (${Object.keys(r.skipped).join(', ')}).` : 'No change.');
      })
      .catch((e) => setMsg(`Failed: ${e.message}`))
      .finally(() => setSaving(false));
  };
  const row = (key: string, label: string, hint: string, input: React.ReactNode) => (
    <div className="flex flex-col gap-1 rounded-xl bg-black/20 px-3 py-2 ring-1 ring-inset ring-white/5">
      <div className="flex items-center gap-2">
        <span className="text-sm">{label}</span>
        {locked[key] ? <Badge tone="warn" title="Set by env var. Edit .env to change.">env</Badge>
          : sources[key] === 'db' ? <Badge tone="info">custom</Badge> : <Badge tone="dim">default</Badge>}
      </div>
      {input}
      <span className="text-[11px] text-[#5b6b82]">{hint}{locked[key] ? ' Locked by env.' : ''}</span>
    </div>
  );
  const num = (key: string, min: number, max: number) => (
    <input type="number" min={min} max={max} disabled={!!locked[key]} value={Number(vals[key] ?? 0)}
      onChange={(e) => set(key, Number(e.target.value))}
      className="w-full rounded-lg border border-[#1e2a3f] bg-black/30 px-2 py-1.5 text-sm outline-none focus:border-[#58a6ff]/60 disabled:opacity-50" />
  );
  const toggle = (key: string) => (
    <button disabled={!!locked[key]} onClick={() => set(key, !vals[key])}
      className={`w-11 rounded-full p-1 transition-colors disabled:opacity-50 ${vals[key] ? 'bg-[#3fb950]/60' : 'bg-white/10'}`}>
      <span className={`block h-4 w-4 rounded-full bg-white transition-transform ${vals[key] ? 'translate-x-5' : ''}`} />
    </button>
  );
  const csv = (key: string, placeholder: string) => (
    <textarea rows={2} disabled={!!locked[key]} value={String(vals[key] ?? '')}
      onChange={(e) => set(key, e.target.value)} placeholder={placeholder}
      className="w-full rounded-lg border border-[#1e2a3f] bg-black/30 px-2 py-1.5 font-mono text-xs outline-none focus:border-[#58a6ff]/60 disabled:opacity-50" />
  );
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Card title="Enforcement and fail2ban" icon={<ShieldCheck size={15} className="text-[#3fb950]" />}
        action={<button onClick={save} disabled={saving} className="rounded-xl bg-[#58a6ff]/20 px-3 py-1.5 text-xs font-medium text-white ring-1 ring-inset ring-[#58a6ff]/50 hover:bg-[#58a6ff]/30 disabled:opacity-50">{saving ? 'Saving…' : 'Save'}</button>}>
        <div className="space-y-2">
          {row('ban_enabled', 'Bans', 'Write bans to DB plus banlist. Firewall needs fail2ban. See docs/FAIL2BAN.md.', toggle('ban_enabled'))}
          {row('ban_jail', 'Jail', 'fail2ban jail name, e.g. sshd.', (
            <input value={String(vals.ban_jail ?? '')} disabled={!!locked.ban_jail} onChange={(e) => set('ban_jail', e.target.value)}
              className="w-full rounded-lg border border-[#1e2a3f] bg-black/30 px-2 py-1.5 text-sm outline-none focus:border-[#58a6ff]/60 disabled:opacity-50" />
          ))}
          {row('ban_time', 'Ban time (s)', 'Manual ban life, 300 to 2592000.', num('ban_time', 300, 2592000))}
          {row('ban_auto', 'Auto-ban', 'Auto block hammering IPs each 60s.', toggle('ban_auto'))}
          {row('ban_threshold', 'Threshold', 'Fails to trigger auto-ban, 3 to 10000.', num('ban_threshold', 3, 10000))}
          {row('ban_window', 'Window (s)', 'Count fails inside this time, 60 to 604800.', num('ban_window', 60, 604800))}
          {row('ban_auto_time', 'Auto-ban time (s)', 'Auto-ban life, 300 to 2592000.', num('ban_auto_time', 300, 2592000))}
          {row('report_enabled', 'Reports', 'Send high-risk IPs to provider.', toggle('report_enabled'))}
          {row('report_provider', 'Provider', 'abuseipdb, webhook, or all.', (
            <select value={String(vals.report_provider ?? 'abuseipdb')} disabled={!!locked.report_provider}
              onChange={(e) => set('report_provider', e.target.value)}
              className="w-full rounded-lg border border-[#1e2a3f] bg-black/30 px-2 py-1.5 text-sm outline-none focus:border-[#58a6ff]/60 disabled:opacity-50">
              {['abuseipdb', 'webhook', 'all'].map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          ))}
          {row('report_throttle_days', 'Throttle (days)', 'One report per IP per window, 1 to 90.', num('report_throttle_days', 1, 90))}
          {row('report_min_risk', 'Min risk', 'Report only at or above this score, 0 to 100.', num('report_min_risk', 0, 100))}
          {row('report_min_hits', 'Min hits', 'Report only at or above this count.', num('report_min_hits', 2, 100000))}
          <div className="text-xs text-[#8b98ad]">Auth mode: {status.auth_mode}. Env var set locks a field. DB values apply now. Fail2ban setup: docs/FAIL2BAN.md.</div>
          {msg && <p className="text-xs text-[#a5d6ff]">{msg}</p>}
        </div>
      </Card>
      <div className="space-y-4">
        <Card title="Allow lists and detection" icon={<ShieldCheck size={15} className="text-[#58a6ff]" />}
          action={<button onClick={save} disabled={saving} className="rounded-xl bg-[#58a6ff]/20 px-3 py-1.5 text-xs font-medium text-white ring-1 ring-inset ring-[#58a6ff]/50 hover:bg-[#58a6ff]/30 disabled:opacity-50">{saving ? 'Saving…' : 'Save'}</button>}>
          <div className="space-y-2">
            {row('whitelist_ips', 'Whitelist IPs', 'Never list or ban these IPs. Comma separated.', csv('whitelist_ips', '1.2.3.4, 5.6.7.8'))}
            {row('trusted_ips', 'Trusted IPs', 'Accepted logins from other IPs flag as suspicious.', csv('trusted_ips', '1.2.3.4, 5.6.7.8'))}
            {row('trusted_users', 'Trusted users', 'Accepted logins for other users flag as suspicious.', csv('trusted_users', 'ubuntu, deploy'))}
            {row('self_public_ips', 'Self public IPs', 'Your NAT egress IPs to exclude from stats.', csv('self_public_ips', '1.2.3.4'))}
            {row('abusers_min_hits', 'Abusers min hits', 'Public list needs this many fails, 2 to 100000.', num('abusers_min_hits', 2, 100000))}
            {row('abusers_min_score', 'Abusers min score', 'Public list needs this risk score, 0 to 100.', num('abusers_min_score', 0, 100))}
            {row('abusers_public', 'Public abusers feed', 'Open /api/abusers plus /abusers without login. Still safe fields only.', toggle('abusers_public'))}
            {msg && <p className="text-xs text-[#a5d6ff]">{msg}</p>}
          </div>
        </Card>
        <PasswordCard />
      </div>
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
