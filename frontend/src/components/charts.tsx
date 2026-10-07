import DottedMap from 'dotted-map';
import { useMemo } from 'react';
import {
  Area, CartesianGrid, Cell, ComposedChart, Line, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import { fmtH } from '../lib/api';

const tooltipStyle = {
  backgroundColor: 'rgba(17,25,40,.96)', border: '1px solid #2c3f58',
  borderRadius: 10, fontSize: 12, color: '#dbe4f3',
} as const;

// --- SSH activity trends: failures (area) + successful logins (line) ---
export function TrendChart({ timeline }: { timeline: [number, number, number][] }) {
  const data = timeline.map(([t, fail, ok]) => ({ t: fmtH(t), fail, ok }));
  return (
    <ResponsiveContainer width="100%" height={240}>
      <ComposedChart data={data} margin={{ top: 5, right: 5, left: -14, bottom: 0 }}>
        <defs>
          <linearGradient id="failG" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f85149" stopOpacity={0.55} />
            <stop offset="100%" stopColor="#f85149" stopOpacity={0.04} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1e2a3f" strokeDasharray="3 6" vertical={false} />
        <XAxis dataKey="t" tick={{ fill: '#8b98ad', fontSize: 10 }} interval={11} tickLine={false} axisLine={{ stroke: '#1e2a3f' }} />
        <YAxis tick={{ fill: '#8b98ad', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Area type="monotone" dataKey="fail" name="failed attempts" stroke="#f85149" strokeWidth={2} fill="url(#failG)" />
        <Line type="monotone" dataKey="ok" name="successful logins" stroke="#3fb950" strokeWidth={2} dot={false} />
      </ComposedChart>
    </ResponsiveContainer>
  );
}

// --- Top attacking regions (flag + country + hits bars) ---
export function RegionChart({ rows }: { rows: { cc: string; country: string; flag: string; hits: number; ips?: number }[] }) {
  const data = rows.slice(0, 8);
  const max = Math.max(1, ...data.map((r) => r.hits));
  if (data.length === 0) return <p className="py-6 text-center text-sm text-[#8b98ad]">No regions yet.</p>;
  return (
    <div className="space-y-2.5">
      {data.map((r, i) => {
        const share = Math.round((r.hits / max) * 100);
        const color = i === 0 ? '#f85149' : i < 3 ? '#f0883e' : '#58a6ff';
        const cc = (r.cc || '?').toUpperCase();
        const showImg = cc !== '?' && /^[A-Z]{2}$/.test(cc);
        return (
          <div key={cc + i} title={`${r.country || cc}: ${r.hits} hits${r.ips ? ` from ${r.ips} IPs` : ''}`} className="flex items-center gap-2">
            <span className="flex w-16 shrink-0 items-center gap-1.5">
              {showImg ? (
                <img src={`https://flagcdn.com/w40/${cc.toLowerCase()}.png`} width={22} height={15} loading="lazy" alt={cc} className="rounded-[3px]" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
              ) : (
                <span>{r.flag || '🌐'}</span>
              )}
              <span className="text-xs font-bold text-[#dbe4f3]">{cc}</span>
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className="truncate text-xs text-[#8b98ad]">{r.country || cc}{r.ips ? ` · ${r.ips} IP${r.ips === 1 ? '' : 's'}` : ''}</span>
                <span className="shrink-0 text-xs font-bold text-white">{r.hits}</span>
              </div>
              <div className="mt-1 h-4 overflow-hidden rounded-r-md rounded-l-sm bg-white/5">
                <div className="h-full rounded-r-md" style={{ width: `${Math.max(6, share)}%`, backgroundColor: color, opacity: i === 0 ? 0.95 : 0.8 }} />
              </div>
            </div>
          </div>
        );
      })}
      <p className="pt-1 text-[11px] text-[#5b6b82]">Share is relative to the top region. Hover a row for IP count.</p>
    </div>
  );
}

// --- Auth success vs failure donut ---
export function AuthDonut({ fail, ok }: { fail: number; ok: number }) {
  const data = [{ name: 'Failed', value: fail }, { name: 'Accepted', value: ok }];
  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Tooltip contentStyle={tooltipStyle} />
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={82} paddingAngle={3} strokeWidth={0}>
          <Cell fill="#f85149" />
          <Cell fill="#3fb950" />
        </Pie>
        <text x="50%" y="46%" textAnchor="middle" fill="#dbe4f3" fontSize={22} fontWeight={700}>
          {fail + ok === 0 ? '—' : `${Math.round((ok / (fail + ok)) * 100)}%`}
        </text>
        <text x="50%" y="58%" textAnchor="middle" fill="#8b98ad" fontSize={11}>login success</text>
      </PieChart>
    </ResponsiveContainer>
  );
}

// --- World attack map (offline dotted map, pins from cached geo) ---
export interface MapPin {
  lat: number; lon: number; hits: number; label: string; ip?: string;
  cc: string; country: string; city?: string; flag?: string; org?: string;
}
export function WorldMap({ pins, total }: { pins: MapPin[]; total?: number }) {
  const max = Math.max(1, ...pins.map((p) => p.hits));
  const svg = useMemo(() => {
    const map = new DottedMap({ height: 60, grid: 'diagonal' });
    pins.slice(0, 60).forEach((p) => {
      const hot = p.hits / max;
      map.addPin({
        lat: p.lat, lng: p.lon,
        svgOptions: {
          color: hot > 0.5 ? '#f85149' : hot > 0.2 ? '#f0883e' : '#58a6ff',
          radius: 0.35 + hot * 0.55,
        },
      });
    });
    return map.getSVG({ radius: 0.18, color: '#22314a', shape: 'circle', backgroundColor: 'transparent' });
  }, [pins, max]);
  const sorted = useMemo(() => [...pins].sort((a, b) => b.hits - a.hits), [pins]);
  const heavy = pins.filter((p) => p.hits / max > 0.5).length;
  const moderate = pins.filter((p) => p.hits / max > 0.2 && p.hits / max <= 0.5).length;
  const probing = pins.length - heavy - moderate;
  const mappedHits = pins.reduce((a, p) => a + p.hits, 0);
  const top = sorted[0];
  if (pins.length === 0) return <p className="py-6 text-center text-sm text-[#8b98ad]">No geo-located attackers yet.</p>;
  return (
    <div className="relative">
      <div dangerouslySetInnerHTML={{ __html: svg }} className="[&>svg]:h-auto [&>svg]:w-full" />
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[#8b98ad]">
        <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-[#f85149]" />heavy ({heavy})</span>
        <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-[#f0883e]" />moderate ({moderate})</span>
        <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-[#58a6ff]" />probing ({probing})</span>
        <span className="ml-auto">{pins.length} origins · {mappedHits.toLocaleString()} hits mapped{total ? ` of ${total.toLocaleString()}` : ''}</span>
      </div>
      {top && (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-xl bg-white/[.02] px-3 py-2 text-xs ring-1 ring-inset ring-white/10">
          <span className="text-[#8b98ad]">Hottest:</span>
          {top.cc && /^[A-Za-z]{2}$/.test(top.cc) ? (
            <img src={`https://flagcdn.com/w40/${top.cc.toLowerCase()}.png`} width={20} alt={top.cc} loading="lazy" className="rounded-[3px]" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
          ) : (
            <span>{top.flag || '🌐'}</span>
          )}
          <span className="font-bold text-white">{top.flag || ''} {top.country || top.cc}</span>
          {top.city && <span className="text-[#8b98ad]">{top.city}</span>}
          <span className="font-mono text-[#a5d6ff]">{top.label}</span>
          <span className="ml-auto font-bold text-[#ff9d97]">{top.hits} hits</span>
        </div>
      )}
      <div className="mt-2 grid grid-cols-1 gap-1 sm:grid-cols-2">
        {sorted.slice(0, 6).map((p, i) => (
          <div key={(p.ip || p.label) + i} title={`${p.ip || p.label} · ${p.org || ''}`} className="flex items-center gap-2 rounded-lg bg-black/30 px-2.5 py-1.5 text-xs">
            <span className="font-bold text-[#5b6b82]">{i + 1}</span>
            {p.cc && /^[A-Za-z]{2}$/.test(p.cc) ? (
              <img src={`https://flagcdn.com/w40/${p.cc.toLowerCase()}.png`} width={18} alt={p.cc} loading="lazy" className="rounded-[2px]" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
            ) : (
              <span>{p.flag || '🌐'}</span>
            )}
            <span className="truncate text-[#dbe4f3]">{p.country || p.cc}{p.city ? ` · ${p.city}` : ''}</span>
            <span className="ml-auto shrink-0 font-mono text-[#8b98ad]">{p.hits} hits</span>
          </div>
        ))}
      </div>
    </div>
  );
}
