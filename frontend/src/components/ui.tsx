import { clsx } from 'clsx';
import type { ReactNode } from 'react';

export const Card = ({ title, icon, action, children, className }: {
  title: string; icon?: ReactNode; action?: ReactNode; children: ReactNode; className?: string;
}) => (
  <section className={clsx('glass rounded-2xl p-5 shadow-xl shadow-black/20 transition-colors hover:border-[#2c3f58]', className)}>
    <header className="mb-4 flex items-center justify-between border-b border-[#1e2a3f] pb-3">
      <h3 className="flex items-center gap-2 text-[15px] font-semibold tracking-tight">{icon}{title}</h3>
      {action}
    </header>
    {children}
  </section>
);

export const MetricCard = ({ icon, label, value, sub, tone }: {
  icon: ReactNode; label: string; value: ReactNode; sub?: ReactNode; tone?: 'bad' | 'ok' | 'acc' | 'warn';
}) => {
  // Opaque gradient stops only: fading to transparent made glyphs look blurry.
  const tones: Record<string, string> = {
    bad: 'from-[#ffb4b4] to-[#f85149]',
    ok: 'from-[#a9f0b4] to-[#3fb950]',
    warn: 'from-[#f5d47a] to-[#d29922]',
    acc: 'from-[#b9d9ff] to-[#58a6ff]',
  };
  return (
    <div className="glass group rounded-2xl p-4 shadow-lg shadow-black/20 transition-all hover:-translate-y-0.5 hover:border-[#58a6ff]/50">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-[#8b98ad]">{label}</span>
        <span className="text-[#8b98ad] transition-colors group-hover:text-[#58a6ff]">{icon}</span>
      </div>
      <div className={clsx('mt-1 bg-gradient-to-b bg-clip-text text-3xl font-bold tracking-tight text-transparent', tones[tone ?? 'acc'])}>
        {value}
      </div>
      {sub && <div className="mt-1 text-xs text-[#8b98ad]">{sub}</div>}
    </div>
  );
};

export const Badge = ({ tone, children, title }: { tone: 'bad' | 'ok' | 'warn' | 'info' | 'dim'; children: ReactNode; title?: string }) => {
  const tones: Record<string, string> = {
    bad: 'bg-[#f85149]/15 text-[#ff9d97] ring-[#f85149]/40',
    ok: 'bg-[#3fb950]/15 text-[#7ee787] ring-[#3fb950]/40',
    warn: 'bg-[#d29922]/15 text-[#e8b93e] ring-[#d29922]/40',
    info: 'bg-[#58a6ff]/15 text-[#a5d6ff] ring-[#58a6ff]/40',
    dim: 'bg-white/5 text-[#8b98ad] ring-white/10',
  };
  return (
    <span title={title} className={clsx('inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset', tones[tone])}>
      {children}
    </span>
  );
};

export const eventTone = (line: string): 'bad' | 'ok' | 'info' | 'dim' => {
  const l = line.toLowerCase();
  if (/failed|invalid user|disconnected|connection closed|bye bye|error|denied|failure/.test(l)) return 'bad';
  if (/accepted|session opened|success/.test(l)) return 'ok';
  if (/sudo:|pam_unix|session/.test(l)) return 'info';
  return 'dim';
};

export const Skeleton = ({ className }: { className?: string }) => (
  <div className={clsx('skeleton rounded-xl', className)} />
);

export const Empty = ({ children }: { children: ReactNode }) => (
  <p className="py-6 text-center text-sm text-[#8b98ad]">{children}</p>
);
