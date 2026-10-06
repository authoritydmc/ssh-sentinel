import {
  Activity, AlertTriangle, CheckCircle2, ChevronLeft, Crosshair, Eye, Globe2,
  LayoutDashboard, ListOrdered, Map as MapIcon, Pause, Play, Radio, Search,
  ShieldAlert, ShieldCheck, Users,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Suspense, lazy } from 'react';
const TrendChart = lazy(() => import('./components/charts').then(m => ({ default: m.TrendChart })));
const RegionChart = lazy(() => import('./components/charts').then(m => ({ default: m.RegionChart })));
const AuthDonut = lazy(() => import('./components/charts').then(m => ({ default: m.AuthDonut })));
const WorldMap = lazy(() => import('./components/charts').then(m => ({ default: m.WorldMap })));
import { Badge, Card, Empty, MetricCard, Skeleton } from './components/ui';
const AttackerModal = lazy(() => import('./components/AttackerModal'));
import { eventTone, } from './components/ui';
import { TZ, fetchSummary, fetchTail, fmtClock, fmtT, relT, type Summary } from './lib/api';
import { clsx } from 'clsx';

type View = 'overview' | 'attackers' | 'events';

function useSummary() {
  const [data, setData] = useState<Summary | null>(null);
  const [err, setErr] = useState('');
  const [updated, setUpdated] = useState(0);
  useEffect(() => {
    let live = true;
    const load = () => fetchSummary()
      .then((d) => { if (live) { setData(d); setErr(''); setUpdated(Date.now()); } })
      .catch((e) => { if (live) setErr(e.message); });
    load();
    const t = setInterval(load, 60000);
    return () => { live = false; clearInterval(t); };
  }, []);
  return { data, err, updated };
}

const NAV: { id: View; label: string; icon: React.ReactNode }[] = [
  { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={17} /> },
  { id: 'attackers', label: 'Attackers', icon: <Crosshair size={17} /> },
  { id: 'events', label: 'Live events', icon: <Activity size={17} /> },
];

export default function App() {
  const { data, err, updated } = useSummary();
  const [view, setView] = useState<View>('overview');
  const [collapsed, setCollapsed] = useState(false);
  const [modalIp, setModalIp] = useState<string | null>(null);
  const [mobileNav, setMobileNav] = useState(false);

  const stats = useMemo(() => {
    if (!data) return null;
    const peak = data.timeline.reduce((a, t) => (t[1] > a[1] ? t : a), [0, 0, 0] as [number, number, number]);
    const bycc: Record<string, number> = {};
    const byuser: Record<string, number> = {};
    data.top.forEach((t) => { bycc[t.cc || '?'] = (bycc[t.cc || '?'] || 0) + t.hits; byuser[t.user] = (byuser[t.user] || 0) + t.hits; });
    const topcc = Object.entries(bycc).sort((a, b) => b[1] - a[1])[0] ?? ['?', 0];
    const topuser = Object.entries(byuser).sort((a, b) => b[1] - a[1])[0] ?? ['?', 0];
    const okTotal = data.timeline.reduce((a, t) => a + (t[2] || 0), 0);
    return { peak, topcc, topuser, okTotal };
  }, [data]);

  const regions = useMemo(() => {
    if (!data) return [];
    const m: Record<string, { cc: string; country: string; hits: number }> = {};
    data.top.forEach((t) => {
      const k = t.cc || '?';
      m[k] = m[k] ?? { cc: k, country: t.country || k, hits: 0 };
      m[k].hits += t.hits;
    });
    return Object.values(m).sort((a, b) => b.hits - a.hits);
  }, [data]);

  const pins = useMemo(() => (data?.top ?? [])
    .filter((t) => t.lat != null && t.lon != null)
    .map((t) => ({ lat: t.lat as number, lon: t.lon as number, hits: t.hits, label: t.ip })), [data]);

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className={clsx(
        'fixed inset-y-0 left-0 z-40 flex flex-col border-r border-[#1e2a3f] bg-[#0c1322]/90 backdrop-blur-xl transition-all md:static',
        collapsed ? 'w-16' : 'w-60', mobileNav ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
      )}>
        <div className="flex items-center gap-2.5 border-b border-[#1e2a3f] p-4">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-[#f85149] to-[#a40e26] shadow-lg shadow-[#f85149]/25">
            <ShieldAlert size={18} className="text-white" />
          </span>
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
        <div className="hidden border-t border-[#1e2a3f] p-3 md:block">
          <button onClick={() => setCollapsed(!collapsed)} className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-xs text-[#8b98ad] hover:text-white">
            <ChevronLeft size={15} className={clsx('transition-transform', collapsed && 'rotate-180')} />{!collapsed && 'Collapse'}
          </button>
        </div>
      </aside>

      {/* Main */}
      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-30 border-b border-[#1e2a3f] bg-[#0a0f1c]/80 backdrop-blur-xl">
          <div className="flex items-center gap-3 px-4 py-3 md:px-6">
            <button className="rounded-lg p-2 hover:bg-white/10 md:hidden" onClick={() => setMobileNav(!mobileNav)} aria-label="Menu">
              <ListOrdered size={18} />
            </button>
            <div>
              <h1 className="text-lg font-bold tracking-tight">SSH Security Operations</h1>
              <p className="text-xs text-[#8b98ad]">live from <code className="rounded bg-white/5 px-1">/var/log/auth.log</code> · {data ? `${data.total.toLocaleString()} attempts · ${data.ips} IPs` : 'connecting…'}</p>
            </div>
            <div className="ml-auto flex items-center gap-2 text-xs text-[#8b98ad]">
              <Eye size={13} />{updated ? `updated ${fmtClock(updated)}` : '…'}
            </div>
          </div>
        </header>

        <main className="space-y-4 p-4 md:p-6">
          {err && <div className="rounded-xl border border-[#f85149]/50 bg-[#f85149]/10 p-3 text-sm text-[#ff9d97]">Backend unreachable: {err}</div>}

          {view === 'overview' && (
            <>
              {!data ? <OverviewSkeleton /> : (
                <>
                  <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                    <MetricCard icon={<AlertTriangle size={16} />} label="Failed attempts" value={data.total.toLocaleString()} sub={`+${data.excluded_self.toLocaleString()} self excluded`} tone="bad" />
                    <MetricCard icon={<Globe2 size={16} />} label="Attacker IPs" value={data.ips} sub={`${data.geo_cached} geo-located`} tone="acc" />
                    <MetricCard icon={<CheckCircle2 size={16} />} label="Successful logins" value={data.logins.length} sub="last 60 in range" tone="ok" />
                    <MetricCard icon={<Activity size={16} />} label="Peak hour" value={`${stats!.peak[1]}/h`} sub="48h window" tone="warn" />
                    <MetricCard icon={<MapIcon size={16} />} label="Top origin" value={stats!.topcc[0]} sub={`${stats!.topcc[1]} hits`} tone="acc" />
                    <MetricCard icon={<Users size={16} />} label="Most wanted" value={stats!.topuser[0]} sub={`${stats!.topuser[1]} tries`} tone="bad" />
                  </div>
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
                      <Suspense fallback={<Skeleton className="h-56" />}><WorldMap pins={pins} /></Suspense>
                    </Card>
                    <Card title="Top attacking regions" icon={<MapIcon size={15} className="text-[#f0883e]" />}>
                      <Suspense fallback={<Skeleton className="h-48" />}><RegionChart rows={regions} /></Suspense>
                    </Card>
                  </div>
                  <Card title="Top attackers" icon={<Crosshair size={15} className="text-[#f85149]" />}
                    action={<button onClick={() => setView('attackers')} className="text-xs text-[#58a6ff] hover:underline">view all →</button>}>
                    <AttackerTable rows={data.top.slice(0, 8)} onIp={setModalIp} />
                  </Card>
                </>
              )}
            </>
          )}

          {view === 'attackers' && (
            <Card title="All attackers" icon={<Crosshair size={15} className="text-[#f85149]" />}>
              {!data ? <Skeleton className="h-64" /> : <AttackerTable rows={data.top} onIp={setModalIp} full />}
            </Card>
          )}

          {view === 'events' && <EventFeed />}
        </main>

        <footer className="flex flex-wrap gap-x-5 gap-y-1 border-t border-[#1e2a3f] px-4 py-2.5 text-xs text-[#8b98ad] md:px-6">
          <span><i className="live-dot mr-1.5 inline-block h-2 w-2 rounded-full bg-[#3fb950]" />live</span>
          <span>geo cache: <b className="text-white">{data?.geo_cached ?? '…'}</b></span>
          <span>self excluded: <b className="text-white">{data?.excluded_self ?? '…'}</b></span>
          <span>auto-refresh 60s</span>
          <span className="ml-auto">times in {TZ}</span>
        </footer>
      </div>
      {modalIp && <Suspense fallback={null}><AttackerModal ip={modalIp} onClose={() => setModalIp(null)} /></Suspense>}
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
            <th className="pb-2 pr-3 font-medium">Hits</th><th className="pb-2 pr-3 font-medium">Origin</th><th className="pb-2 font-medium">Recon</th>
          </tr></thead>
          <tbody>
            {filtered.map((t) => (
              <tr key={`${t.user}@${t.ip}`} onClick={() => onIp(t.ip)} className="cursor-pointer border-t border-[#1e2a3f] transition-colors hover:bg-[#58a6ff]/5">
                <td className="py-2 pr-3">{t.cc ? <img src={`https://flagcdn.com/w40/${t.cc.toLowerCase()}.png`} width={22} className="rounded-[3px]" loading="lazy" alt={t.cc} /> : <span>🌐</span>}</td>
                <td className="py-2 pr-3 font-mono">{t.user}</td>
                <td className="py-2 pr-3 font-mono text-[#a5d6ff]">{t.ip}</td>
                <td className="py-2 pr-3 font-bold">{t.hits}</td>
                <td className="py-2 pr-3 text-[#8b98ad]">{[t.city, t.country].filter(Boolean).join(', ') || t.cc || '—'}</td>
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

function EventFeed() {
  const [lines, setLines] = useState<string[]>([]);
  const [q, setQ] = useState('');
  const [paused, setPaused] = useState(false);
  const [newestFirst, setNewestFirst] = useState(true);
  useEffect(() => {
    let live = true;
    const load = async () => {
      if (paused) return;
      try {
        const l = await fetchTail(q, 200);
        if (live) setLines(newestFirst ? [...l].reverse() : l);
      } catch { /* keep stale */ }
    };
    load();
    const t = setInterval(load, 15000);
    return () => { live = false; clearInterval(t); };
  }, [q, paused, newestFirst]);
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
              <span className="break-all text-[#c4cfdf]">{ln}</span>
            </div>
          );
        })}
        {lines.length === 0 && <Empty>No matching lines.</Empty>}
      </div>
      <p className="mt-2 text-xs text-[#8b98ad]">auto-refresh 15s · times in {TZ} · {fmtT(Date.now())}</p>
    </Card>
  );
}
