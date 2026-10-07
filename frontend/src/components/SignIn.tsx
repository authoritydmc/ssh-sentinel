import { KeyRound, Lock, RefreshCw } from 'lucide-react';
import type { AuthInfo } from '../lib/api';
import { Card } from './ui';

// Full sign-in panel. Shown when the API answers 401.
// Mode comes from /api/auth: local (browser prompt), forward (proxy),
// oidc (SSO button), none (open, no panel needed).
export default function SignIn({ auth, onRetry }: { auth: AuthInfo | null; onRetry: () => void }) {
  const login = auth?.login ?? '';
  return (
    <Card title="Sign in to SSH Sentinel" icon={<Lock size={15} className="text-[#d29922]" />}>
      <div className="mx-auto max-w-md space-y-3 py-2 text-center">
        <p className="text-sm text-[#8b98ad]">
          {login === 'oidc' && 'This server uses single sign-on. Continue with your identity provider.'}
          {login === 'forward' && 'This server trusts your SSO proxy. The proxy must pass your identity header.'}
          {login !== 'oidc' && login !== 'forward' && 'This server uses local login. Use the browser sign-in prompt.'}
        </p>
        {login === 'oidc' && (
          <button
            onClick={() => { window.location.href = 'oidc/login'; }}
            className="inline-flex items-center gap-2 rounded-xl bg-[#58a6ff]/20 px-5 py-2.5 text-sm font-bold text-white ring-1 ring-inset ring-[#58a6ff]/50 hover:bg-[#58a6ff]/30"
          >
            <KeyRound size={15} />
            Sign in with SSO
          </button>
        )}
        {login === 'forward' && (
          <p className="rounded-xl bg-black/30 px-3 py-2 font-mono text-xs text-[#a5d6ff]">
            X-Forwarded-User via Authentik / Traefik
          </p>
        )}
        {login !== 'oidc' && login !== 'forward' && (
          <p className="rounded-xl bg-black/30 px-3 py-2 text-xs text-[#8b98ad]">
            Enter the admin user plus password in the browser prompt, then reload.
            {auth?.setup_needed ? ' No admin exists yet — open Admin with the one-time setup token.' : ''}
          </p>
        )}
        <div>
          <button
            onClick={onRetry}
            className="inline-flex items-center gap-1.5 rounded-xl bg-white/5 px-3 py-1.5 text-xs text-white ring-1 ring-inset ring-white/10 hover:bg-white/10"
          >
            <RefreshCw size={12} />
            Reload after sign-in
          </button>
        </div>
        <p className="text-[11px] text-[#5b6b82]">
          Mode: {auth?.mode ?? '…'} · signed in as {auth?.user ?? 'nobody'}
        </p>
      </div>
    </Card>
  );
}
