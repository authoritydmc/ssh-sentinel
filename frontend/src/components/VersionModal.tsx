import { GitBranch, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { fetchVersion, type VersionInfo } from '../lib/api';

export default function VersionModal({ onClose }: { onClose: () => void }) {
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    let live = true;
    fetchVersion()
      .then((v) => live && setInfo(v))
      .catch((e) => live && setErr(e.message));
    return () => {
      live = false;
    };
  }, []);

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 p-4 backdrop-blur-sm" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="glass mx-auto my-8 max-w-2xl rounded-2xl p-6 shadow-2xl">
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-bold tracking-tight">
              <GitBranch size={18} className="text-[#58a6ff]" />
              {info ? `SSH Sentinel v${info.version}` : 'Version…'}
            </h2>
            <p className="text-xs text-[#8b98ad]">
              {info?.commit ? `commit ${info.commit}` : info ? 'dev build' : 'loading…'}
            </p>
          </div>
          <button onClick={onClose} className="rounded-lg p-2 text-[#8b98ad] hover:bg-white/10 hover:text-white" aria-label="Close"><X size={18} /></button>
        </div>
        {err && <p className="mb-3 rounded-lg bg-[#f85149]/10 p-3 text-sm text-[#ff9d97]">{err}</p>}
        {!info && !err && <p className="text-sm text-[#8b98ad]">Loading changelog…</p>}
        {info && <Changelog text={info.changelog} />}
      </div>
    </div>
  );
}

function Changelog({ text }: { text: string }) {
  const blocks: React.ReactNode[] = [];
  let items: string[] = [];
  const flush = (key: string) => {
    if (items.length > 0) {
      blocks.push(
        <ul key={key} className="mb-3 list-disc space-y-1 pl-5 text-sm text-[#c4cfdf]">
          {items.map((it, i) => <li key={i}>{it}</li>)}
        </ul>,
      );
      items = [];
    }
  };
  text.split('\n').forEach((ln, i) => {
    const t = ln.trim();
    if (t.startsWith('## ')) {
      flush(`ul-${i}`);
      blocks.push(<h4 key={i} className="mb-1 mt-4 text-[15px] font-bold text-white">{t.slice(3)}</h4>);
    } else if (t.startsWith('### ')) {
      flush(`ul-${i}`);
      blocks.push(<h5 key={i} className="mb-1 mt-3 text-sm font-semibold text-[#a5d6ff]">{t.slice(4)}</h5>);
    } else if (t.startsWith('- ')) {
      items.push(t.slice(2));
    } else if (t !== '') {
      flush(`ul-${i}`);
      blocks.push(<p key={i} className="mb-2 text-sm text-[#8b98ad]">{t}</p>);
    }
  });
  flush('ul-end');
  return <div className="scroll-thin max-h-[55vh] overflow-y-auto pr-1">{blocks}</div>;
}
