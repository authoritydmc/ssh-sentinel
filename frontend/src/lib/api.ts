// API client + types for the sshlog backend (same origin, base-relative).
const BASE: string = new URL('.', window.location.href).pathname.replace(/\/?$/, '/');
const api = (p: string) => `${BASE}api/${p}`;

export interface TopEntry {
  user: string; ip: string; hits: number; flag: string; cc: string;
  country: string; city: string; org: string; lat: number | null; lon: number | null;
  recon: { state: string; count: number };
}
export interface LoginEntry {
  user: string; user_display: string; ip: string; ts: number | null;
  suspicious: boolean; trusted: boolean; reason: string;
}
export interface Summary {
  total: number; ips: number; top: TopEntry[];
  timeline: [number, number, number][]; logins: LoginEntry[];
  suspicious_count: number; privacy_mode: string; trusted_configured: boolean;
  excluded_self: number; self_ips: string[]; geo_cached: number; now: number;
  host: string; hosts: Host[];
}
export interface IpIntel {
  ip: string; cc?: string; country?: string; city?: string; org?: string; isp?: string;
  as?: string; ptr?: string; rdap_name?: string; rdap_handle?: string; rdap_cc?: string;
  flag?: string; private?: boolean;
  ban?: { banned: boolean; source?: string; created?: number; expires?: number };
  reports?: { provider: string; ts: number; status: string }[];
  history: { users: [string, number][]; hits: number; first: number | null; last: number | null };
}
export interface ReconResult { type: string; data: string; module: string }
export interface ReconState {
  state: 'cached' | 'started' | 'running' | 'done' | 'error';
  scan?: string; status?: string; count?: number; results?: ReconResult[]; error?: string;
}

async function get<T>(p: string): Promise<T> {
  const r = await fetch(api(p));
  if (!r.ok) throw new Error(`${p} → HTTP ${r.status}`);
  return r.json() as Promise<T>;
}

export interface Host { id: string; local: boolean; last_seen: number; online: boolean; lines?: number }
export const fetchHosts = () => get<Host[]>('hosts');
export interface AuthInfo { mode: string; login: string; user: string | null; safe: boolean; version?: string; setup_needed?: boolean; abusers_public?: boolean }
export interface VersionInfo { version: string; commit: string; changelog: string }
export const fetchVersion = () => get<VersionInfo>('version');
export const REPO_URL = 'https://github.com/authoritydmc/ssh-sentinel';
export interface SelfInfo {
  ip: string; whitelisted: boolean; listed: boolean; hits: number;
  risk: number; band: string; first: number | null; last: number | null; message: string;
}
export const fetchSelf = () => get<SelfInfo>('self');
export const fetchAuth = () => get<AuthInfo>('auth');
const withHost = (p: string, host: string) => (host && host !== 'all' ? `${p}${p.includes('?') ? '&' : '?'}host=${encodeURIComponent(host)}` : p);
export const fetchSummary = (host = 'all') => get<Summary>(withHost('summary', host));
export const fetchIntel = (ip: string, host = 'all') => get<IpIntel>(withHost(`ipinfo?ip=${encodeURIComponent(ip)}`, host));
export const postRecon = (ip: string, force = false) =>
  fetch(api(`recon?ip=${encodeURIComponent(ip)}${force ? '&force=1' : ''}`), { method: 'POST' })
    .then(async (r) => {
      if (!r.ok) throw new Error(`recon → HTTP ${r.status}`);
      return (await r.json()) as ReconState;
    });
export const fetchTail = async (q: string, n: number, host = 'all'): Promise<string[]> => {
  const r = await fetch(api(withHost(`tail?q=${encodeURIComponent(q)}&n=${n}`, host)));
  if (!r.ok) throw new Error(`tail → HTTP ${r.status}`);
  return (await r.text()).split('\n').filter((x) => x.trim() !== '');
};

async function post<T>(p: string, body: unknown): Promise<T> {
  const r = await fetch(api(p), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${p} → HTTP ${r.status}`);
  return r.json() as Promise<T>;
}

export interface AdminStatus {
  setup_needed: boolean; setup_token_configured: boolean;
  ban_enabled: boolean; ban_auto: boolean; ban_jail: string;
  ban_threshold: number; ban_window: number;
  report_enabled: boolean; report_provider: string; report_throttle_days: number;
  auth_mode: string; version?: string;
}
export interface BanEntry {
  ip: string; jail: string; reason: string; source: string;
  created: number; expires: number | null; fail2ban_ok: boolean;
}
export interface ActivityEntry { ts: number; actor: string; action: string; ip: string; detail: string }
export interface ReportEntry { ip: string; provider: string; ts: number; status: string; detail: string }

export const fetchAdminStatus = () => get<AdminStatus>('admin/status');
export const fetchBans = async (): Promise<BanEntry[]> =>
  (await get<{ bans: BanEntry[] }>('admin/bans')).bans;
export const fetchActivity = async (limit = 200): Promise<ActivityEntry[]> =>
  (await get<{ activity: ActivityEntry[] }>(`admin/activity?limit=${limit}`)).activity;
export const fetchReports = async (): Promise<ReportEntry[]> =>
  (await get<{ reports: ReportEntry[] }>('admin/reports')).reports;
export const postBan = (ip: string, reason = '') =>
  post<{ ok: boolean; ip: string }>('admin/ban', { ip, reason });
export const postUnban = (ip: string) =>
  post<{ ok: boolean; ip: string }>('admin/unban', { ip });
export const postReport = (ip: string, hits: number, risk: number, band: string) =>
  post<{ ok: boolean }>('admin/report', { ip, hits, risk, band });
export const postSetup = (token: string, user: string, password: string) =>
  post<{ ok: boolean; user: string }>('admin/setup', { token, user, password });
export const postPassword = (oldPw: string, newPw: string) =>
  post<{ ok: boolean }>('admin/password', { old: oldPw, new: newPw });

export const fmtT = (e: number | null): string =>
  e ? new Date(e).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
export const fmtH = (e: number): string =>
  new Date(e).toLocaleString([], { day: 'numeric', hour: '2-digit' });
export const fmtClock = (e: number): string =>
  new Date(e).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
export const relT = (e: number | null): string => {
  if (!e) return '—';
  const s = Math.max(0, (Date.now() - e) / 1000);
  if (s < 60) return 'just now';
  const m = s / 60;
  if (m < 60) return `${Math.floor(m)}m ago`;
  const h = m / 60;
  if (h < 24) return `${Math.floor(h)}h ago`;
  const d = h / 24;
  if (d < 30) return `${Math.floor(d)}d ago`;
  return fmtT(e);
};
export const TZ: string = Intl.DateTimeFormat().resolvedOptions().timeZone || 'local';
