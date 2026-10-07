# Fail2ban setup for SSH Sentinel

> Style note: this document uses simplified English.
> Sentences are short. Each step has one action.

## 1. Purpose

SSH Sentinel detects SSH attackers. It does not block packets by itself.
Fail2ban blocks packets on the host. This guide links the two.

Terms:

- central: the main container. It serves the UI and the API.
- jail: a fail2ban rule set. Use `sshd` for SSH.
- banlist: a file with one banned IP per line.

## 2. How blocking works

1. You ban an IP in the UI intel modal.
2. Central writes the IP to SQLite plus `banlist.txt`.
3. Central calls `fail2ban-client` only when `BAN_ENABLED=1`.
4. Fail2ban drops packets for `BAN_TIME` seconds.
5. Expires means the DB record turns inactive at that time.
6. Expires does not delete the firewall rule by itself.
7. A banned IP can still show in logs when block is off.

Check the Admin Bans tab. The Block column shows the state.
`firewall` means fail2ban accepted the call.
`monitor` means DB plus banlist only.

## 3. UI mapping

Set these in Admin Settings. No restart is needed for UI saves.
An env var set locks that field in the UI.

| UI field | Env var | Use |
| -------- | ------- | --- |
| Bans | `BAN_ENABLED` | `1` calls fail2ban. Empty keeps monitor only. |
| Jail | `BAN_JAIL` | Jail name. Default is `sshd`. |
| Ban time | `BAN_TIME` | Manual ban life in seconds. |
| Auto-ban | `BAN_AUTO` | `1` auto blocks hammering IPs each 60 seconds. |
| Threshold | `BAN_THRESHOLD` | Fails needed for auto-ban. |
| Window | `BAN_WINDOW` | Time window for the threshold. |
| Auto-ban time | `BAN_AUTO_TIME` | Auto-ban life in seconds. |
| Whitelist IPs | `WHITELIST_IPS` | Never list or ban these IPs. |
| Trusted IPs and users | `TRUSTED_IPS`, `TRUSTED_USERS` | Tune suspicious login flags. |
| Self public IPs | `SELF_PUBLIC_IPS` | Exclude NAT egress from stats. |

## 4. Option A — same host push

Use this when fail2ban runs on the central host.

1. Install fail2ban on the central host.
2. Confirm the `sshd` jail exists.
3. Run `fail2ban-client status sshd`.
4. Set Bans to on in Admin Settings.
5. Set Jail to `sshd` in Admin Settings.
6. Ban a test IP from the attacker modal.
7. Run `fail2ban-client status sshd` again.
8. Confirm the test IP is banned.
9. Unban the test IP from the Admin Bans tab.
10. Run `fail2ban-client status sshd` again.
11. Confirm the test IP is gone.

Docker note:

- The central container must see the fail2ban socket.
- Host install plus shared socket works best.
- Pure container setups often lack fail2ban.
- Monitor mode is normal there. Use Option B instead.

## 5. Option B — pull banlist on any host

Use this when fail2ban runs on members or on another host.

1. Open central Admin Settings.
2. Confirm Bans are on or off as you need.
3. Note that central always writes `DATA_DIR/banlist.txt`.
4. Fetch the list with login: `GET /api/banlist`.
5. Example: `curl -s -u admin:PASSWORD http://central:8079/api/banlist`.
6. Copy `examples/fail2ban-action.conf` to `/etc/fail2ban/action.d/sentinel.conf`.
7. Add the sample `[sentinel]` jail to `jail.local`.
8. Set `bantime`, `findtime`, and `maxretry` to match central.
9. Reload fail2ban.
10. Check bans with `fail2ban-client status sentinel`.

## 6. Verify

1. Trigger fails from a test IP you own.
2. Check the IP in Attackers with geo and risk.
3. Ban it from the modal with a reason.
4. Check Admin Bans for Created plus Expires.
5. Check Block shows `firewall` for Option A.
6. Check `/api/banlist` contains the IP.
7. Unban it after the test.
8. Check the activity tab for `ban` plus `unban` rows.

## 7. Troubleshoot

- Block shows `monitor`. Set `BAN_ENABLED=1`. Install fail2ban.
- `fail2ban-client` is missing. Install fail2ban on that host.
- Wrong jail name. Use `fail2ban-client status` to list jails.
- Ban rejected as private. Sentinel bans public IPs only.
- Ban rejected as whitelisted. Remove the IP from the whitelist first.
- Banned IP still logs attempts. Normal when block is off.
- Banned IP still logs attempts with block on. Check iptables rules.
- Never ban your own access IP. Add it to the whitelist first.
- Keep port 8079 private. Use tailnet or SSO in front.
