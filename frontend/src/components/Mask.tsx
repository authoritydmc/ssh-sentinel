import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

const KEY = 'sentinel-mask';

// Pure helpers: pass the toggle flag, get display text back.
// Raw values stay in props and API calls. Only rendered text is masked.

export function maskIp(ip: string, on: boolean): string {
  if (!on) return ip;
  if (ip.includes('.') && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    return ip.split('.').slice(0, 3).join('.') + '.*';
  }
  if (ip.includes(':')) return '****:****:****';
  return '***.***.***';
}

export function maskUser(u: string, on: boolean): string {
  if (!on) return u;
  if (u === '?' || u === '') return u;
  return '••••••';
}

export function maskHost(h: string, on: boolean): string {
  if (!on) return h;
  return '••••••';
}

const IPV4 = /\b\d{1,3}(\.\d{1,3}){3}\b/g;
const IPV6 = /\b([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]+\b/g;
const FOR_USER = /\bfor (invalid user |invalid user )?(\S+)/g;
const INVALID_USER = /\b[Ii]nvalid user (\S+)/g;
const AC_BY = /\bclosed by (\S+)/g;
const DISC_FROM = /\bfrom (\S+) port \d+/g;

export function maskLine(ln: string, on: boolean): string {
  if (!on) return ln;
  return ln
    .replace(IPV4, (m) => maskIp(m, true))
    .replace(IPV6, '****:****:****')
    .replace(FOR_USER, (_m, p1) => `for ${p1 || ''}••••••`)
    .replace(INVALID_USER, 'invalid user ••••••')
    .replace(AC_BY, 'closed by ••••••')
    .replace(DISC_FROM, 'from •••••• port');
}

interface MaskCtx {
  masked: boolean;
  toggle: () => void;
}

const Ctx = createContext<MaskCtx>({ masked: false, toggle: () => {} });

export function MaskProvider({ children }: { children: ReactNode }) {
  const [masked, setMasked] = useState(() => {
    try {
      return localStorage.getItem(KEY) === '1';
    } catch {
      return false;
    }
  });
  const toggle = useCallback(() => {
    setMasked((m) => {
      try {
        localStorage.setItem(KEY, m ? '0' : '1');
      } catch {
        /* private mode: keep in-memory state */
      }
      return !m;
    });
  }, []);
  const v = useMemo(() => ({ masked, toggle }), [masked, toggle]);
  return <Ctx.Provider value={v}>{children}</Ctx.Provider>;
}

export const useMask = () => useContext(Ctx);
