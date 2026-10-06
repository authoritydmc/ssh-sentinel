import DottedMap from 'dotted-map';
import { useMemo } from 'react';
import {
  Area, Bar, CartesianGrid, Cell, ComposedChart, Line, Pie, PieChart,
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

// --- Top attacking regions (horizontal bars) ---
export function RegionChart({ rows }: { rows: { cc: string; country: string; hits: number }[] }) {
  const data = rows.slice(0, 8);
  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 34)}>
      <ComposedChart layout="vertical" data={data} margin={{ top: 0, right: 10, left: 10, bottom: 0 }}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="cc" tick={{ fill: '#dbe4f3', fontSize: 12 }} tickLine={false} axisLine={false} width={44} />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar dataKey="hits" radius={[0, 6, 6, 0]} barSize={16}>
          {data.map((_, i) => (
            <Cell key={i} fill={i === 0 ? '#f85149' : i < 3 ? '#f0883e' : '#58a6ff'} fillOpacity={i === 0 ? 0.95 : 0.8} />
          ))}
        </Bar>
      </ComposedChart>
    </ResponsiveContainer>
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
export function WorldMap({ pins }: { pins: { lat: number; lon: number; hits: number; label: string }[] }) {
  const svg = useMemo(() => {
    const map = new DottedMap({ height: 60, grid: 'diagonal' });
    const max = Math.max(1, ...pins.map((p) => p.hits));
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
  }, [pins]);
  return (
    <div className="relative">
      <div dangerouslySetInnerHTML={{ __html: svg }} className="[&>svg]:h-auto [&>svg]:w-full" />
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[#8b98ad]">
        <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-[#f85149]" />heavy</span>
        <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-[#f0883e]" />moderate</span>
        <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-[#58a6ff]" />probing</span>
        <span className="ml-auto">{pins.length} geo-located origins</span>
      </div>
    </div>
  );
}
