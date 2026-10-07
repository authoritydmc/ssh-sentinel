import {
  Activity, AlertTriangle, CheckCircle2, ChevronLeft, Crosshair, Eye, GitBranch, Globe2,
  LayoutDashboard, ListOrdered, Map as MapIcon, Pause, Play, Radio, Search,
  Server, ShieldAlert, ShieldCheck, ShieldHalf, Users,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Suspense, lazy } from 'react';
const Admin = lazy(() => import('./components/Admin'));
const TrendChart = lazy(() => import('./components/charts').then(m => ({ default: m.TrendChart })));
const RegionChart = lazy(() => import('./components/charts').then(m => ({ default: m.RegionChart })));
const AuthDonut = lazy(() => import('./components/charts').then(m => ({ default: m.AuthDonut })));
const WorldMap = lazy(() => import('./components/charts').then(m => ({ default: m.WorldMap })));
import { Badge, Card, Empty, MetricCard, Skeleton } from './components/ui';
const AttackerModal = lazy(() => import('./components/AttackerModal'));
const VersionModal = lazy(() => import('./components/VersionModal'));
import { eventTone, } from './components/ui';
import { REPO_URL, TZ, fetchAuth, fetchSelf, fetchSummary, fetchTail, fmtClock, fmtT, relT, type AuthInfo, type Host, type SelfInfo, type Summary } from './lib/api';
import { MaskProvider, maskHost, maskIp, maskLine, maskLoginIp, maskUser, useMask } from './components/Mask';
import { EyeOff } from 'lucide-react';
import { clsx } from 'clsx';

type View = 'overview' | 'attackers' | 'events' | 'admin';

function useSummary(host: string) {
  const [data, setData] = useState<Summary | null>(null);
  const [err, setErr] = useState('');
  const [updated, setUpdated] = useState(0);
  const [switching, setSwitching] = useState(false);
  useEffect(() => {
    let live = true;
    // Show a subtle switching state so scope changes never look frozen.
    setSwitching(true);
    const load = () => fetchSummary(host)
      .then((d) => { if (live) { setData(d); setErr(''); setUpdated(Date.now()); setSwitching(false); } })
      .catch((e) => { if (live) { setErr(e.message); setSwitching(false); } });
    load();
    const t = setInterval(load, 60000);
    return () => { live = false; clearInterval(t); };
  }, [host]);
  return { data, err, updated, switching };
}

const NAV: { id: View; label: string; icon: React.ReactNode }[] = [
  { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={17} /> },
  { id: 'attackers', label: 'Attackers', icon: <Crosshair size={17} /> },
  { id: 'events', label: 'Live events', icon: <Activity size={17} /> },
  { id: 'admin', label: 'Admin', icon: <ShieldHalf size={17} /> },
];

export default function App() {
  return (<MaskProvider><Shell /></MaskProvider>);
}

function Shell() {
  const { masked, toggle } = useMask();
  const [host, setHost] = useState('all');
  const { data, err, updated, switching } = useSummary(host);
  const [view, setView] = useState<View>('overview');
  const [collapsed, setCollapsed] = useState(false);
  const [modalIp, setModalIp] = useState<string | null>(null);
  const [versionOpen, setVersionOpen] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [auth, setAuth] = useState<AuthInfo | null>(null);
  useEffect(() => {
    let live = true;
    fetchAuth().then((a) => { if (live) setAuth(a); }).catch(() => { /* banner covers it */ });
    return () => { live = false; };
  }, []);
  const [self, setSelf] = useState<SelfInfo | null>(null);
  const [selfHide, setSelfHide] = useState(false);
  useEffect(() => {
    let live = true;
    fetchSelf().then((s) => { if (live) setSelf(s); }).catch(() => { /* optional check */ });
    return () => { live = false; };
  }, []);

  const stats = useMemo(() => {
    if (!data) return null;
    const peak = data.timeline.reduce((a, t) => (t[1] > a[1] ? t : a), [0, 0, 0] as [number, number, number]);
    const bycc: Record<string, { hits: number; country: string; flag: string }> = {};
    const byuser: Record<string, number> = {};
    data.top.forEach((t) => {
      const k = t.cc || '?';
      bycc[k] = bycc[k] ?? { hits: 0, country: t.country || k, flag: t.flag || '' };
      bycc[k].hits += t.hits;
      if (t.country) bycc[k].country = t.country;
      if (t.flag) bycc[k].flag = t.flag;
      byuser[t.user] = (byuser[t.user] || 0) + t.hits;
    });
    const topEntry = Object.entries(bycc).sort((a, b) => b[1].hits - a[1].hits)[0] ?? ['?', { hits: 0, country: '?', flag: '' }];
    const topcc = { cc: topEntry[0], hits: topEntry[1].hits, country: topEntry[1].country, flag: topEntry[1].flag };
    const topuser = Object.entries(byuser).sort((a, b) => b[1] - a[1])[0] ?? ['?', 0];
    const okTotal = data.timeline.reduce((a, t) => a + (t[2] || 0), 0);
    return { peak, topcc, topuser, okTotal };
  }, [data]);

  const regions = useMemo(() => {
    if (!data) return [];
    const m: Record<string, { cc: string; country: string; flag: string; hits: number; ips: number }> = {};
    data.top.forEach((t) => {
      const k = t.cc || '?';
      m[k] = m[k] ?? { cc: k, country: t.country || k, flag: t.flag || '', hits: 0, ips: 0 };
      m[k].hits += t.hits;
      m[k].ips += 1;
      if (t.country) m[k].country = t.country;
      if (t.flag) m[k].flag = t.flag;
    });
    return Object.values(m).sort((a, b) => b.hits - a.hits);
  }, [data]);

  const pins = useMemo(() => (data?.top ?? [])
    .filter((t) => t.lat != null && t.lon != null)
    .map((t) => ({
      lat: t.lat as number, lon: t.lon as number, hits: t.hits,
      label: maskIp(t.ip, masked), ip: t.ip,
      cc: t.cc || '?', country: t.country || '', city: t.city || '',
      flag: t.flag || '', org: t.org || '',
    })), [data, masked]);

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className={clsx(
        'fixed inset-y-0 left-0 z-40 flex flex-col border-r border-[#1e2a3f] bg-[#0c1322]/90 backdrop-blur-xl transition-all md:static',
        collapsed ? 'w-16' : 'w-60', mobileNav ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
      )}>
        <div className="flex items-center gap-2.5 border-b border-[#1e2a3f] p-4">
          <img src={`${import.meta.env.BASE_URL}logo.svg`} alt="SSH Sentinel logo"
            className="h-9 w-9 shrink-0 rounded-xl shadow-lg shadow-[#f85149]/25" />
          {!collapsed && <div><div className="text-sm font-bold tracking-tight">SSH Sentinel</div>
            <div className="flex items-center gap-1 text-[11px] text-[#3fb950]"><span className="live-dot inline-block h-1.5 w-1.5 rounded-full bg-[#3fb950]" />live · {TZ}</div></div>}
        </div>
        <nav className="flex-1 space-y-1 p-3">
          {NAV.map((n) => (
            <button key={n.id} onClick={() => { setView(n.id); setMobileNav(false); }}
              title={n.label}
              className={clsx('flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all',
                view === n.id ? 'bg-[#58a6ff]/15 text-white ring-1 ring-inset ring-[#58a6ff]/40' : 'text-[#8b98ad] hover:bg-white/5 hover:text-white')}>
              {n.icon}{!collapsed && <span className="font-medium">{n.label}</span>}
            </button>
          ))}
        </nav>
        <div className="space-y-1 border-t border-[#1e2a3f] p-3">
          <a href={REPO_URL} target="_blank" rel="noreferrer" title={`ssh-sentinel on GitHub${auth?.version ? ` · v${auth.version}` : ''}`}
            className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-[#8b98ad] transition-all hover:bg-white/5 hover:text-white">
            <GitBranch size={17} className="shrink-0" />
            {!collapsed && <span className="font-medium">GitHub</span>}
            {!collapsed && auth?.version && <span className="ml-auto rounded-full bg-white/5 px-2 py-0.5 text-[11px] ring-1 ring-inset ring-white/10">v{auth.version}</span>}
          </a>
          <button onClick={() => setCollapsed(!collapsed)} className="hidden w-full items-center gap-2 rounded-lg px-2 py-1.5 text-xs text-[#8b98ad] hover:text-white md:flex">
            <ChevronLeft size={15} className={clsx('transition-transform', collapsed && 'rotate-180')} />{!collapsed && 'Collapse'}
          </button>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-h-screen min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b border-[#1e2a3f] bg-[#0a0f1c]/85 backdrop-blur-xl">
          <div className="flex flex-col gap-3 px-4 py-3 md:px-6 lg:flex-row lg:items-center">
            <div className="flex items-center gap-3">
              <button className="rounded-lg p-2 hover:bg-white/10 md:hidden" onClick={() => setMobileNav(!mobileNav)} aria-label="Menu">
                <ListOrdered size={18} />
              </button>
              <div>
                <h1 className="flex items-center gap-2 text-lg font-bold tracking-tight">
                  SSH Security Operations
                  {switching && <span className="rounded-full bg-[#58a6ff]/15 px-2 py-0.5 text-[11px] font-medium text-[#a5d6ff] ring-1 ring-inset ring-[#58a6ff]/40">switching…</span>}
                </h1>
                <p className="text-xs text-[#8b98ad]">
                  <ScopeLabel host={host} hosts={data?.hosts ?? []} data={data} />
                </p>
              </div>
            </div>
            <div className="flex flex-col gap-2 lg:ml-auto lg:items-end">
              <HostScopeBar hosts={data?.hosts ?? []} active={host} onChange={setHost} />
              <div className="flex items-center gap-2 text-xs text-[#8b98ad]">
                <button
                  onClick={toggle}
                  title={masked ? 'Masks on: IPs, users, hosts hidden (click to reveal)' : 'Masks off: click for screenshot-safe mode'}
                  className={masked
                    ? 'inline-flex items-center gap-1 rounded-lg bg-[#d29922]/20 px-2 py-0.5 text-[#e8b93e] ring-1 ring-inset ring-[#d29922]/50 hover:bg-[#d29922]/30'
                    : 'inline-flex items-center gap-1 rounded-lg bg-white/5 px-2 py-0.5 hover:bg-white/10 hover:text-white'}
                >
                  {masked ? <EyeOff size={13} /> : <Eye size={13} />}
                  {masked ? 'masked' : 'mask'}
                </button>
                <Eye size={13} />{updated ? `updated ${fmtClock(updated)}` : '…'}
              </div>
            </div>
          </div>
        </header>

        <main className="flex-1 space-y-4 p-4 md:p-6">
          {self && self.listed && !selfHide && (
            <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[#f85149]/50 bg-[#f85149]/10 p-3 text-sm text-[#ff9d97]">
              <ShieldAlert size={15} />
              <span>Your IP <b className="font-mono">{maskIp(self.ip, masked)}</b> is on the attacker list ({self.hits} fails, risk {self.risk}/{self.band}). If this is you, contact the admin to whitelist you via <code className="rounded bg-white/5 px-1">WHITELIST_IPS</code>.</span>
              <button onClick={() => setSelfHide(true)} className="ml-auto rounded-lg bg-white/5 px-2.5 py-1 text-xs text-white ring-1 ring-inset ring-white/10 hover:bg-white/10">Dismiss</button>
            </div>
          )}
          {err && err.includes('401') && (
            <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[#d29922]/50 bg-[#d29922]/10 p-3 text-sm text-[#e8b93e]">
              <ShieldAlert size={15} />
              <span>Login required — {auth?.login === 'forward' ? 'your SSO proxy must pass X-Forwarded-User.' : auth?.login === 'oidc' ? 'sign in with your identity provider.' : 'sign in with the browser prompt (local login), then reload.'}</span>
              {auth?.login === 'oidc' && (
                <button onClick={() => { window.location.href = 'oidc/login'; }} className="rounded-lg bg-[#58a6ff]/20 px-2.5 py-1 text-xs font-medium text-white ring-1 ring-inset ring-[#58a6ff]/50 hover:bg-[#58a6ff]/30">Sign in with SSO</button>
              )}
              <button onClick={() => window.location.reload()} className="ml-auto rounded-lg bg-white/5 px-2.5 py-1 text-xs text-white ring-1 ring-inset ring-white/10 hover:bg-white/10">Reload</button>
            </div>
          )}
          {err && !err.includes('401') && <div className="rounded-xl border border-[#f85149]/50 bg-[#f85149]/10 p-3 text-sm text-[#ff9d97]">Backend unreachable: {err}</div>}
          {auth?.setup_needed && (
            <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[#d29922]/50 bg-[#d29922]/10 p-3 text-sm text-[#e8b93e]">
              <ShieldAlert size={15} />
              <span>First setup needed — open <b>Admin</b> to create the admin login with the one-time token.</span>
              <button onClick={() => setView('admin')} className="ml-auto rounded-lg bg-[#58a6ff]/20 px-2.5 py-1 text-xs font-medium text-white ring-1 ring-inset ring-[#58a6ff]/50 hover:bg-[#58a6ff]/30">Open Admin</button>
            </div>
          )}

          {view === 'overview' && (
            <>
              {!data ? <OverviewSkeleton /> : (
                <>
                  <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                    <MetricCard icon={<AlertTriangle size={16} />} label="Failed attempts" value={data.total.toLocaleString()} sub={`+${data.excluded_self.toLocaleString()} self excluded`} tone="bad" />
                    <MetricCard icon={<Globe2 size={16} />} label="Attacker IPs" value={data.ips} sub={`${data.geo_cached} geo-located`} tone="acc" />
                    <MetricCard icon={<CheckCircle2 size={16} />} label="Successful logins" value={data.logins.length} sub={(data.suspicious_count ?? 0) > 0 ? `${data.suspicious_count} SUSPICIOUS — review` : 'last 60 in range · usernames masked'} tone={(data.suspicious_count ?? 0) > 0 ? 'bad' : 'ok'} />
                    <MetricCard icon={<Activity size={16} />} label="Peak hour" value={`${stats!.peak[1]}/h`} sub="48h window" tone="warn" />
                    <MetricCard icon={<MapIcon size={16} />} label="Top origin" value={`${stats!.topcc.flag ? `${stats!.topcc.flag} ` : ''}${stats!.topcc.cc}`} sub={`${stats!.topcc.country} · ${stats!.topcc.hits} hits`} tone="acc" />
                    <MetricCard icon={<Users size={16} />} label="Most wanted" value={maskUser(stats!.topuser[0], masked)} sub={`${stats!.topuser[1]} tries`} tone="bad" />
                  </div>
                  {!data.trusted_configured && (
                    <div className="flex items-center gap-2 rounded-xl border border-[#e8b93e]/30 bg-[#e8b93e]/10 px-3 py-2 text-xs text-[#e8b93e]">
                      <ShieldAlert size={13} />
                      <span>Compromise detection is basic: only <b>fail-then-accept</b> is flagged. Set <code>TRUSTED_IPS</code>/<code>TRUSTED_USERS</code> on central to also flag unknown-IP/user accepts.</span>
                    </div>
                  )}
                  <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                    <Card title="SSH activity trends" icon={<Activity size={15} className="text-[#f85149]" />} className="xl:col-span-2"
                      action={<span className="flex gap-3 text-xs text-[#8b98ad]"><i className="mr-1 inline-block h-2 w-2 rounded-full bg-[#f85149]" />failed<i className="mr-1 inline-block h-2 w-2 rounded-full bg-[#3fb950]" />accepted</span>}>
                      <Suspense fallback={<Skeleton className="h-60" />}><TrendChart timeline={data.timeline} /></Suspense>
                    </Card>
                    <Card title="Auth outcomes" icon={<ShieldCheck size={15} className="text-[#3fb950]" />}>
                      <Suspense fallback={<Skeleton className="h-48" />}><AuthDonut fail={data.total} ok={stats!.okTotal} /></Suspense>
                      <div className="mt-1 grid grid-cols-2 gap-2 text-center text-xs">
                        <div className="rounded-lg bg-[#f85149]/10 p-2"><div className="text-lg font-bold text-[#ff9d97]">{data.total.toLocaleString()}</div>failed</div>
                        <div className="rounded-lg bg-[#3fb950]/10 p-2"><div className="text-lg font-bold text-[#7ee787]">{stats!.okTotal.toLocaleString()}</div>accepted</div>
                      </div>
                    </Card>
                  </div>
                  <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                    <Card title="World attack map" icon={<Globe2 size={15} className="text-[#58a6ff]" />} className="xl:col-span-2">
                      <Suspense fallback={<Skeleton className="h-56" />}><WorldMap pins={pins} total={data.total} /></Suspense>
                    </Card>
                    <Card title="Top attacking regions" icon={<MapIcon size={15} className="text-[#f0883e]" />}>
                      <Suspense fallback={<Skeleton className="h-48" />}><RegionChart rows={regions} /></Suspense>
                    </Card>
                  </div>
                  {(data.suspicious_count ?? 0) > 0 && <SuspiciousBanner logins={data.logins} onIp={setModalIp} />}
                  <Card title="Top attackers" icon={<Crosshair size={15} className="text-[#f85149]" />}
                    action={<button onClick={() => setView('attackers')} className="text-xs text-[#58a6ff] hover:underline">view all →</button>}>
                    <AttackerTable rows={data.top.slice(0, 8)} onIp={setModalIp} />
                  </Card>
                  <Card title="Recent logins (Accepted — usernames masked)" icon={<CheckCircle2 size={15} className="text-[#3fb950]" />}>
                    <LoginTable logins={data.logins} onIp={setModalIp} />
                  </Card>
                </>
              )}
            </>
          )}

          {view === 'attackers' && (
            <Card title="All attackers" icon={<Crosshair size={15} className="text-[#f85149]" />}
              action={!data ? undefined : (
                <button onClick={() => {
                  const csv = 'ip,hits,user,country,city,org,asn\n' + data.top.map((t) =>
                    [t.ip, t.hits, t.user, t.cc, `"${(t.city || '').replace(/"/g, "'")}"`,
                     `"${(t.org || '').replace(/"/g, "'")}"`, `"${((t as { asn?: string }).asn || '').replace(/"/g, "'")}"`].join(',')).join('\n');
                  const a = document.createElement('a');
                  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
                  a.download = 'ssh-attackers.csv'; a.click();
                }} className="text-xs text-[#58a6ff] hover:underline">CSV ↓</button>
              )}>
              {!data ? <Skeleton className="h-64" /> : <AttackerTable rows={data.top} onIp={setModalIp} full />}
            </Card>
          )}

          {view === 'events' && <EventFeed host={host} />}

          {view === 'admin' && (
            <Suspense fallback={<Skeleton className="h-64" />}>
              <Admin />
            </Suspense>
          )}
          {host !== 'all' && (
            <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[#58a6ff]/30 bg-[#58a6ff]/10 px-3 py-2 text-xs text-[#a5d6ff]">
              <Server size={13} />
              <span>Viewing <b>{maskHost(host, masked)}</b> only — metrics, attackers and events are filtered to this host.</span>
              <button onClick={() => setHost('all')} className="ml-auto rounded-lg bg-[#58a6ff]/20 px-2.5 py-1 font-medium text-white ring-1 ring-inset ring-[#58a6ff]/50 hover:bg-[#58a6ff]/30">
                Back to fleet
              </button>
            </div>
          )}
        </main>

        <footer className="sticky bottom-0 z-20 flex flex-wrap gap-x-5 gap-y-1 border-t border-[#1e2a3f] bg-[#0a0f1c]/92 px-4 py-2.5 text-xs text-[#8b98ad] backdrop-blur-xl md:px-6">
          <span><i className="live-dot mr-1.5 inline-block h-2 w-2 rounded-full bg-[#3fb950]" />live</span>
          <span title={auth ? `auth mode: ${auth.mode} (login: ${auth.login})${auth.user ? ` · ${auth.user}` : ''}` : 'auth mode: …'}>
            {auth && auth.safe ? '🔒' : '🔓'} {auth?.mode ?? '…'}
          </span>
          <span>scope: <b className="text-white">{host === 'all' ? `fleet (${data?.hosts?.length ?? '…'})` : maskHost(host, masked)}</b></span>
          <span>geo cache: <b className="text-white">{data?.geo_cached ?? '…'}</b></span>
          <span>self excluded: <b className="text-white">{data?.excluded_self ?? '…'}</b></span>
          <span className="hidden sm:inline">auto-refresh 60s</span>
          <a href={REPO_URL} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-white" title="ssh-sentinel on GitHub">
            <GitBranch size={12} /> repo
          </a>
          <button onClick={() => setVersionOpen(true)} title="About: version and changelog" className="inline-flex items-center gap-1 hover:text-white">
            {auth?.version ? `v${auth.version}` : 'version…'}
          </button>
          {auth?.abusers_public && (
            <a href="abusers" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-white" title="Public attacker leaderboard">
              <ShieldAlert size={12} /> abusers
            </a>
          )}
          <span className="ml-auto">times in {TZ}</span>
        </footer>
      </div>
      {modalIp && <Suspense fallback={null}><AttackerModal ip={modalIp} host={host} onClose={() => setModalIp(null)} /></Suspense>}
      {versionOpen && <Suspense fallback={null}><VersionModal onClose={() => setVersionOpen(false)} /></Suspense>}
    </div>
  );
}

function ScopeLabel({ host, hosts, data }: { host: string; hosts: Host[]; data: Summary | null }) {
  const { masked } = useMask();
  const total = data ? `${data.total.toLocaleString()} attempts · ${data.ips} IPs` : 'connecting…';
  if (host === 'all') {
    const n = hosts.length;
    return (
      <span>
        Fleet view · {n > 0 ? `${n} host${n === 1 ? '' : 's'} merged` : 'all hosts'} · live from{' '}
        <code className="rounded bg-white/5 px-1">/var/log/auth.log</code> · {total}
      </span>
    );
  }
  const h = hosts.find((x) => x.id === host);
  return (
    <span>
      Host <b className="text-white">{maskHost(host, masked)}</b>
      {h?.local ? ' · main (central)' : ' · agent'} ·{' '}
      {h && !h.online ? <span className="text-[#e8b93e]">offline · last seen {relT(h.last_seen * 1000)}</span> : total}
    </span>
  );
}

function HostScopeBar({ hosts, active, onChange }: { hosts: Host[]; active: string; onChange: (h: string) => void }) {
  const { masked } = useMask();
  // UX: always show Fleet + central/main + every agent. Never hide the main host.
  // Sorted: central first, then online agents, then offline.
  const sorted = useMemo(() => {
    const arr = [...hosts];
    arr.sort((a, b) => {
      if (a.local !== b.local) return a.local ? -1 : 1;
      if (a.online !== b.online) return a.online ? -1 : 1;
      return a.id.localeCompare(b.id);
    });
    return arr;
  }, [hosts]);

  if (hosts.length === 0) {
    return <div className="flex items-center gap-1.5 text-xs text-[#5b6b82]"><Server size={13} /> discovering fleet…</div>;
  }

  const pill = (isActive: boolean) =>
    clsx(
      'inline-flex items-center gap-1.5 rounded-xl px-2.5 py-1.5 text-xs font-medium transition-all ring-1 ring-inset',
      isActive
        ? 'bg-[#58a6ff]/20 text-white ring-[#58a6ff]/50'
        : 'bg-white/[.02] text-[#8b98ad] ring-white/10 hover:bg-white/5 hover:text-white',
    );

  return (
    <div className="flex flex-wrap items-center gap-1.5" role="tablist" aria-label="Host scope">
      <span className="mr-0.5 inline-flex items-center gap-1 text-[11px] uppercase tracking-wide text-[#5b6b82]">
        <Server size={12} /> scope
      </span>
      <button
        role="tab"
        aria-selected={active === 'all'}
        onClick={() => onChange('all')}
        title={`Merged view of all ${hosts.length} host${hosts.length === 1 ? '' : 's'}`}
        className={pill(active === 'all')}
      >
        Fleet · {hosts.length}
      </button>
      {sorted.map((h) => {
        const isActive = active === h.id;
        const tip = h.local
          ? `Main host (central) · ${h.online ? 'online' : 'offline'}`
          : `Agent · ${h.online ? 'online' : `offline · last seen ${relT(h.last_seen * 1000)}`}${h.lines ? ` · ${h.lines.toLocaleString()} lines` : ''}`;
        return (
          <button
            key={h.id}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(isActive ? 'all' : h.id)}
            title={tip}
            className={pill(isActive)}
          >
            <i className={clsx('h-1.5 w-1.5 rounded-full', h.online ? 'bg-[#3fb950] live-dot' : 'bg-[#5b6b82]')} />
            {maskHost(h.id, masked)}
            {h.local && (
              <span className="rounded-full bg-[#3fb950]/15 px-1.5 py-px text-[10px] font-semibold text-[#7ee787] ring-1 ring-inset ring-[#3fb950]/40">
                main
              </span>
            )}
            {!h.online && !h.local && <span className="text-[10px] text-[#5b6b82]">offline</span>}
          </button>
        );
      })}
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-24" />)}</div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3"><Skeleton className="h-72 xl:col-span-2" /><Skeleton className="h-72" /></div>
    </>
  );
}

export function AttackerTable({ rows, onIp, full }: { rows: Summary['top']; onIp: (ip: string) => void; full?: boolean }) {
  const [q, setQ] = useState('');
  const { masked } = useMask();
  const filtered = rows.filter((t) => !q || t.ip.includes(q) || t.user.toLowerCase().includes(q.toLowerCase()) || (t.country || '').toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      {full && (
        <div className="relative mb-3">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8b98ad]" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter by IP, user, country…"
            className="w-full rounded-xl border border-[#1e2a3f] bg-black/30 py-2 pl-9 pr-3 text-sm outline-none placeholder:text-[#5b6b82] focus:border-[#58a6ff]/60" />
        </div>
      )}
      <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[640px] text-sm">
          <thead><tr className="text-left text-xs text-[#8b98ad]">
            <th className="pb-2 pr-3 font-medium"></th><th className="pb-2 pr-3 font-medium">User</th><th className="pb-2 pr-3 font-medium">IP</th>
            <th className="pb-2 pr-3 font-medium">Hits</th><th className="pb-2 pr-3 font-medium">Origin</th><th className="pb-2 pr-3 font-medium">ASN</th><th className="pb-2 font-medium">Recon</th>
          </tr></thead>
          <tbody>
            {filtered.map((t) => (
              <tr key={`${t.user}@${t.ip}`} onClick={() => onIp(t.ip)} className="cursor-pointer border-t border-[#1e2a3f] transition-colors hover:bg-[#58a6ff]/5">
                <td className="py-2 pr-3">{t.cc ? <img src={`https://flagcdn.com/w40/${t.cc.toLowerCase()}.png`} width={22} className="rounded-[3px]" loading="lazy" alt={t.cc} /> : <span>🌐</span>}</td>
                <td className="py-2 pr-3 font-mono">{maskUser(t.user, masked)}</td>
                <td className="py-2 pr-3 font-mono text-[#a5d6ff]">{maskIp(t.ip, masked)}</td>
                <td className="py-2 pr-3 font-bold">{t.hits}</td>
                <td className="py-2 pr-3 text-[#8b98ad]">{[t.city, t.country].filter(Boolean).join(', ') || t.cc || '—'}</td>
                <td className="py-2 pr-3 font-mono text-xs text-[#8b98ad]">{((t as { asn?: string }).asn || '').replace(/^AS\d+\s*/, '') || (t as { asn?: string }).asn || '—'}</td>
                <td className="py-2">{t.recon.count ? <Badge tone="info">🔍 {t.recon.count}</Badge> : <span className="text-[#5b6b82]">…</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && <Empty>No attackers match.</Empty>}
      </div>
    </>
  );
}

// Parse a log line's leading timestamp (ISO-8601 or classic syslog) to epoch ms.
function lineTime(ln: string): number | null {
  let m = ln.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)/);
  if (m) {
    // Date.parse only handles millisecond fractions — truncate microseconds.
    const t = Date.parse(m[1].replace(/(\.\d{3})\d+/, '$1'));
    if (!Number.isNaN(t)) return t;
  }
  m = ln.match(/^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})/);
  if (m) {
    const months: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    const mi = months[m[1]];
    if (mi !== undefined) {
      const now = new Date();
      let d = new Date(now.getFullYear(), mi, parseInt(m[2], 10), parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10));
      if (d.getTime() > now.getTime() + 86400000) d = new Date(now.getFullYear() - 1, mi, parseInt(m[2], 10), parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10));
      return d.getTime();
    }
  }
  return null;
}

function EventFeed({ host }: { host: string }) {
  const [lines, setLines] = useState<string[]>([]);
  const [q, setQ] = useState('');
  const [paused, setPaused] = useState(false);
  const [newestFirst, setNewestFirst] = useState(true);
  const { masked } = useMask();
  useEffect(() => {
    let live = true;
    const load = async () => {
      if (paused) return;
      try {
        const l = await fetchTail(q, 200, host);
        if (live) setLines(newestFirst ? [...l].reverse() : l);
      } catch { /* keep stale */ }
    };
    load();
    const t = setInterval(load, 15000);
    return () => { live = false; clearInterval(t); };
  }, [q, paused, newestFirst, host]);
  return (
    <Card title="Live event feed" icon={<Radio size={15} className="text-[#f85149]" />}
      action={<button onClick={() => setPaused(!paused)} className="inline-flex items-center gap-1.5 rounded-lg bg-white/5 px-2.5 py-1 text-xs ring-1 ring-inset ring-white/10 hover:bg-white/10">
        {paused ? <><Play size={12} /> resume</> : <><Pause size={12} /> pause</>}
      </button>}>
      <div className="mb-3 flex flex-wrap gap-2">
        <div className="relative min-w-52 flex-1">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8b98ad]" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter, e.g. Accepted or an IP…"
            className="w-full rounded-xl border border-[#1e2a3f] bg-black/30 py-2 pl-9 pr-3 text-sm outline-none placeholder:text-[#5b6b82] focus:border-[#58a6ff]/60" />
        </div>
        <button onClick={() => setNewestFirst(!newestFirst)} className="rounded-xl bg-white/5 px-3 text-xs ring-1 ring-inset ring-white/10 hover:bg-white/10">
          {newestFirst ? '↓ newest first' : '↑ oldest first'}
        </button>
        <span className="self-center text-xs text-[#8b98ad]">{lines.length} lines</span>
      </div>
      <div className="scroll-thin max-h-[560px] space-y-1 overflow-y-auto rounded-xl bg-black/40 p-2 font-mono text-xs leading-relaxed">
        {lines.map((ln, i) => {
          const t = eventTone(ln);
          const ts = lineTime(ln);
          const sev = t === 'bad' ? <Badge tone="bad">attack</Badge> : t === 'ok' ? <Badge tone="ok">auth</Badge> : t === 'info' ? <Badge tone="info">system</Badge> : <Badge tone="dim">log</Badge>;
          return (
            <div key={i} title={ts ? new Date(ts).toLocaleString() : 'no parseable timestamp'} className="flex cursor-default items-start gap-2 rounded px-2 py-1 hover:bg-white/5">
              <span className="mt-0.5 shrink-0">{sev}</span>
              {ts && <span className="mt-0.5 shrink-0 text-[#8b98ad]">{relT(ts)}</span>}
              <span className="break-all text-[#c4cfdf]">{maskLine(ln, masked)}</span>
            </div>
          );
        })}
        {lines.length === 0 && <Empty>No matching lines.</Empty>}
      </div>
      <p className="mt-2 text-xs text-[#8b98ad]">sshd-only feed (sudo/CRON hidden) · auto-refresh 15s · times in {TZ} · {fmtT(Date.now())}</p>
    </Card>
  );
}

function SuspiciousBanner({ logins, onIp }: { logins: Summary['logins']; onIp: (ip: string) => void }) {
  const { masked, toggle } = useMask();
  const bad = logins.filter((l) => l.suspicious).slice(-10).reverse();
  const sig = useMemo(
    () => JSON.stringify(bad.map((l) => [l.user_display || l.user, l.ip, l.ts, l.reason])),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [JSON.stringify(logins)],
  );
  const [open, setOpen] = useState<boolean | null>(null);
  const [cleared, setCleared] = useState(false);
  useEffect(() => {
    let seen = '', gone = '';
    try {
      seen = localStorage.getItem('sentinel-susp-seen') || '';
      gone = localStorage.getItem('sentinel-susp-gone') || '';
    } catch { /* private mode */ }
    setCleared(gone === sig);
    setOpen(sig !== seen && gone !== sig);
    try {
      localStorage.setItem('sentinel-susp-seen', sig);
    } catch { /* private mode */ }
  }, [sig]);
  if (bad.length === 0 || open === null) return null;
  const clear = () => {
    try {
      localStorage.setItem('sentinel-susp-gone', sig);
    } catch { /* private mode */ }
    setCleared(true);
    setOpen(false);
  };
  const review = () => {
    try {
      localStorage.removeItem('sentinel-susp-gone');
    } catch { /* private mode */ }
    setCleared(false);
    setOpen(true);
  };
  if (!open) {
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[#f85149]/30 bg-[#f85149]/5 px-3 py-2 text-xs text-[#8b98ad]">
        <ShieldAlert size={13} className="text-[#ff9d97]" />
        <span>{bad.length} suspicious Accepted login{bad.length === 1 ? '' : 's'}{cleared ? ' cleared' : ''} — no change since last view</span>
        <span className="ml-auto flex gap-1.5">
          {masked && (
            <button onClick={toggle} className="rounded-lg bg-white/5 px-2.5 py-1 ring-1 ring-inset ring-white/10 hover:bg-white/10">Reveal</button>
          )}
          <button onClick={review} className="rounded-lg bg-[#f85149]/15 px-2.5 py-1 font-medium text-[#ff9d97] ring-1 ring-inset ring-[#f85149]/40 hover:bg-[#f85149]/25">
            {cleared ? 'Review anyway' : 'Expand'}
          </button>
        </span>
      </div>
    );
  }
  return (
    <div className="rounded-xl border border-[#f85149]/50 bg-[#f85149]/10 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-sm font-bold text-[#ff9d97]">
        <ShieldAlert size={16} /> {bad.length} suspicious Accepted login{bad.length === 1 ? '' : 's'} — possible compromise{masked ? ', masked for screenshots' : ', full IP/user shown'}
        <span className="ml-auto flex gap-1.5 font-normal">
          <button onClick={() => setOpen(false)} className="rounded-lg bg-white/5 px-2.5 py-1 text-xs text-white ring-1 ring-inset ring-white/10 hover:bg-white/10">Minimize</button>
          <button onClick={clear} className="rounded-lg bg-white/5 px-2.5 py-1 text-xs text-white ring-1 ring-inset ring-white/10 hover:bg-white/10">Clear</button>
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-sm">
          <tbody>
            {bad.map((l, i) => (
              <tr key={i} className="border-t border-[#f85149]/20">
                <td className="py-1.5 pr-3"><Badge tone="bad">{l.reason || 'suspicious'}</Badge></td>
                <td className="py-1.5 pr-3 font-mono text-white">{maskUser(l.user_display || l.user, masked)}</td>
                <td className="py-1.5 pr-3 font-mono"><button onClick={() => onIp(l.ip)} className="text-[#a5d6ff] hover:underline">{maskLoginIp(l.ip, masked)}</button></td>
                <td className="py-1.5 text-xs text-[#8b98ad]">{l.ts ? fmtT(l.ts) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function LoginTable({ logins, onIp }: { logins: Summary['logins']; onIp: (ip: string) => void }) {
  const { masked } = useMask();
  const rows = [...logins].reverse().slice(0, 10);
  if (rows.length === 0) return <Empty>No successful logins in range.</Empty>;
  return (
    <div className="scroll-thin overflow-x-auto">
      <table className="w-full min-w-[560px] text-sm">
        <thead><tr className="text-left text-xs text-[#8b98ad]">
          <th className="pb-2 pr-3 font-medium">User (masked)</th><th className="pb-2 pr-3 font-medium">IP</th>
          <th className="pb-2 pr-3 font-medium">Time</th><th className="pb-2 font-medium">Verdict</th>
        </tr></thead>
        <tbody>
          {rows.map((l, i) => (
            <tr key={i} className="border-t border-[#1e2a3f]">
              <td className="py-1.5 pr-3 font-mono">{maskUser(l.user_display || l.user, masked)}</td>
              <td className="py-1.5 pr-3 font-mono"><button onClick={() => onIp(l.ip)} className="text-[#a5d6ff] hover:underline">{maskLoginIp(l.ip, masked)}</button></td>
              <td className="py-1.5 pr-3 text-xs text-[#8b98ad]">{l.ts ? fmtT(l.ts) : '—'}</td>
              <td className="py-1.5">{l.suspicious ? <Badge tone="bad">⚠ {l.reason}</Badge> : <Badge tone="ok">trusted</Badge>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
