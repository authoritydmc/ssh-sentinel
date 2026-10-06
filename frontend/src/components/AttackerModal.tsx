import { Ban, Fingerprint, Flag, Globe2, Network, Radar, RefreshCw, Server, X } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { fetchIntel, fetchTail, fmtT, postBan, postRecon, postReport, postUnban, relT, type IpIntel, type ReconState } from '../lib/api';
import { Badge, eventTone } from './ui';

export default function AttackerModal({ ip, host, onClose }: { ip: string; host: string; onClose: () => void }) {
  const [intel, setIntel] = useState<IpIntel | null>(null);
  const [err, setErr] = useState('');
  const [recon, setRecon] = useState<ReconState | null>(null);
  const [chain, setChain] = useState<string[] | null>(null);
  const [banMsg, setBanMsg] = useState('');

  const reload = useCallback(() => {
    fetchIntel(ip, host).then(setIntel).catch((e) => setErr(e.message));
  }, [ip, host]);

  useEffect(() => {
    let live = true;
    fetchIntel(ip, host).then((d) => live && setIntel(d)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [ip, host]);

  const pollRecon = useCallback(async (force: boolean) => {
    for (let i = 0; i < 25; i++) {
      try {
        const r = await postRecon(ip, force && i === 0);
        setRecon(r);
        if (r.state === 'done' || r.state === 'cached' || r.state === 'error') return;
      } catch (e) { setRecon({ state: 'error', error: (e as Error).message }); return; }
      await new Promise((r) => setTimeout(r, 5000));
      force = false;
    }
  }, [ip]);

  useEffect(() => { pollRecon(false); }, [pollRecon]);

  const _host = host;
  const loadChain = async () => {
    try {
      const lines = await fetchTail(ip, 500, _host);
      setChain([...lines].reverse());
    } catch (e) { setChain([`chain failed: ${(e as Error).message}`]); }
  };

  const h = intel?.history;
  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 p-4 backdrop-blur-sm" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="glass mx-auto my-8 max-w-3xl rounded-2xl p-6 shadow-2xl">
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h2 className="font-mono text-2xl font-bold tracking-tight">{ip}</h2>
            <p className="text-sm text-[#8b98ad]">
              {intel ? (<>{intel.city && `${intel.city}, `}{intel.country} · {intel.org || intel.isp || 'unknown org'}</>) : 'resolving intel…'}
            </p>
          </div>
          <button onClick={onClose} className="rounded-lg p-2 text-[#8b98ad] hover:bg-white/10 hover:text-white" aria-label="Close"><X size={18} /></button>
        </div>
        {err && <p className="mb-3 rounded-lg bg-[#f85149]/10 p-3 text-sm text-[#ff9d97]">{err}</p>}

        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-xl bg-white/[.02] p-2.5 ring-1 ring-inset ring-white/5">
          {intel?.ban?.banned ? (
            <Badge tone="bad">banned · {intel.ban.source}</Badge>
          ) : (
            <Badge tone="dim">not banned</Badge>
          )}
          {(intel?.reports?.length ?? 0) > 0 && (
            <Badge tone="warn" title={intel?.reports?.map((r) => `${r.provider}: ${r.status}`).join('; ')}>
              reported ×{intel?.reports?.length}
            </Badge>
          )}
          <span className="ml-auto flex gap-1.5">
            {intel?.ban?.banned ? (
              <button
                onClick={() => postUnban(ip).then(reload).then(() => setBanMsg('Unbanned.')).catch((e) => setBanMsg(`Unban failed: ${e.message}`))}
                className="inline-flex items-center gap-1 rounded-lg bg-white/5 px-2.5 py-1 text-xs ring-1 ring-inset ring-white/10 hover:bg-white/10"
              >
                <Ban size={13} /> Unban
              </button>
            ) : (
              <button
                onClick={() => postBan(ip, 'manual from intel modal').then(reload).then(() => setBanMsg('Banned.')).catch((e) => setBanMsg(`Ban failed: ${e.message}`))}
                className="inline-flex items-center gap-1 rounded-lg bg-[#f85149]/20 px-2.5 py-1 text-xs text-[#ff9d97] ring-1 ring-inset ring-[#f85149]/50 hover:bg-[#f85149]/30"
              >
                <Ban size={13} /> Ban IP
              </button>
            )}
            <button
              onClick={() => postReport(ip, h?.hits ?? 0, 80, 'high').then(() => setBanMsg('Report sent (or throttled).')).catch((e) => setBanMsg(`Report failed: ${e.message}`))}
              className="inline-flex items-center gap-1 rounded-lg bg-[#58a6ff]/15 px-2.5 py-1 text-xs text-[#a5d6ff] ring-1 ring-inset ring-[#58a6ff]/40 hover:bg-[#58a6ff]/25"
            >
              <Flag size={13} /> Report
            </button>
          </span>
        </div>
        {banMsg && <p className="mb-3 text-xs text-[#8b98ad]">{banMsg}</p>}

        <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { icon: <Radar size={14} />, k: 'Attempts', v: h ? String(h.hits) : '…' },
            { icon: <Globe2 size={14} />, k: 'First seen', v: h ? `${relT(h.first)}` : '…', t: h ? fmtT(h.first) : '' },
            { icon: <Globe2 size={14} />, k: 'Last seen', v: h ? `${relT(h.last)}` : '…', t: h ? fmtT(h.last) : '' },
            { icon: <Fingerprint size={14} />, k: 'Users tried', v: h ? String(h.users.length) : '…' },
          ].map((s) => (
            <div key={s.k} className="rounded-xl bg-white/[.03] p-3 ring-1 ring-inset ring-white/5">
              <div className="flex items-center gap-1.5 text-[11px] text-[#8b98ad]">{s.icon}{s.k}</div>
              <div className="mt-0.5 text-lg font-semibold" title={s.t}>{s.v}</div>
            </div>
          ))}
        </div>

        <div className="mb-5 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
          {[['Location', `${intel?.city || ''}${intel?.city && intel?.country ? ', ' : ''}${intel?.country || '—'} ${intel?.cc || ''}`],
            ['Org / ISP', intel?.org || intel?.isp || '—'], ['ASN', intel?.as || '—'],
            ['rDNS', intel?.ptr || '—'],
            ['RDAP net', `${intel?.rdap_name || ''} ${intel?.rdap_handle || ''} ${intel?.rdap_cc || ''}`.trim() || '—'],
            ['Tried', h?.users.map(([u, n]) => `${u} (${n})`).join(', ') || '—'],
          ].map(([k, v]) => (
            <div key={k} className="flex gap-2"><span className="w-20 shrink-0 text-[#8b98ad]">{k}</span><span className="break-all">{v}</span></div>
          ))}
        </div>

        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold"><Radar size={15} className="text-[#58a6ff]" /> Recon
          <span className="text-xs font-normal text-[#8b98ad]">(auto-started, cached 7d)</span></h3>
        <div className="mb-2 rounded-xl bg-black/30 p-3">
          {!recon && <p className="text-sm text-[#8b98ad]">starting recon…</p>}
          {recon && (recon.state === 'done' || recon.state === 'cached') && (
            <>
              <p className="mb-2 text-xs text-[#8b98ad]">{recon.count} findings · scan {recon.scan} {recon.state === 'cached' && '(cached)'}</p>
              {(recon.results?.length ?? 0) === 0 && <p className="text-sm text-[#8b98ad]">No notable findings — bare scanner IP.</p>}
              <div className="flex flex-wrap gap-1.5">
                {recon.results?.map((r, i) => (
                  <span key={i} title={`${r.module}: ${r.data}`} className="inline-flex max-w-full items-center gap-1.5 truncate rounded-lg bg-white/[.04] px-2 py-1 text-xs ring-1 ring-inset ring-white/10">
                    <Badge tone="info">{r.type}</Badge><span className="truncate">{r.data}</span>
                  </span>
                ))}
              </div>
            </>
          )}
          {recon && (recon.state === 'running' || recon.state === 'started') && (
            <p className="text-sm text-[#8b98ad]">recon {recon.state}… (scan {recon.scan}) auto-refreshing</p>
          )}
          {recon?.state === 'error' && <p className="text-sm text-[#ff9d97]">recon failed: {recon.error}</p>}
        </div>
        <button onClick={() => pollRecon(true)} className="mb-5 inline-flex items-center gap-1.5 rounded-lg bg-[#58a6ff]/15 px-3 py-1.5 text-sm text-[#a5d6ff] ring-1 ring-inset ring-[#58a6ff]/40 hover:bg-[#58a6ff]/25">
          <RefreshCw size={14} /> re-run recon
        </button>

        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold"><Network size={15} className="text-[#58a6ff]" /> Attack chain</h3>
        {!chain && (
          <button onClick={loadChain} className="mb-2 rounded-lg bg-white/5 px-3 py-1.5 text-sm ring-1 ring-inset ring-white/10 hover:bg-white/10">
            Show full log chain ({h?.hits ?? '…'} lines)
          </button>
        )}
        {chain && (
          <div className="scroll-thin max-h-72 overflow-y-auto rounded-xl bg-black/40 p-2 font-mono text-xs leading-relaxed">
            {chain.map((ln, i) => {
              const t = eventTone(ln);
              const cls = t === 'bad' ? 'text-[#ff9d97] border-[#f85149]' : t === 'ok' ? 'text-[#7ee787] border-[#3fb950]' : t === 'info' ? 'text-[#a5d6ff] border-transparent' : 'text-[#8b98ad] border-transparent';
              return <div key={i} className={`border-l-2 px-2 py-px break-all ${cls}`}>{ln}</div>;
            })}
          </div>
        )}
        <p className="mt-3 flex items-center gap-1.5 text-xs text-[#8b98ad]"><Server size={12} /> Sources: ip-api, RDAP, rDNS, SpiderFoot, local auth.log</p>
      </div>
    </div>
  );
}
