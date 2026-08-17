'use strict';

const STRINGS = {
  th: {
    help: `ใช้งาน: vpn-bypass [--lang th|en] <คำสั่ง>

คำสั่ง:
  status                         แสดงสถานะ (เบา ไม่รอ IP สาธารณะ)
  on [--mode inverse|domains] [--dry-run]
                                 ใส่เส้นทาง (ค่าเริ่ม inverse)
  off                            ลบเฉพาะเส้นทางที่โปรแกรมนี้ใส่
  domain add|rm|list [โฮสต์]     จัดการโดเมนโหมดขั้นสูง
  try <โฮสต์>                    ลอง :443 ผ่านเน็ตบ้าน หลัง inverse
  allow <โฮสต์>                  ใส่ host route ผ่าน VPN (หลังยืนยัน)
  deny <โฮสต์>                   เอา host route VPN ออก
  watch [on|off]                 เฝ้าทับเส้นทางใน CLI (ค่าเริ่มปิด; ต้องเปิดโปรเซสทิ้งไว้)
                                 UI ซ่อมเส้นที่ VPN ทับให้อัตโนมัติขณะเปิดอยู่ หลังยืนยันรหัสผู้ดูแลครั้งแรก
  lookup <โฮสต์>                 ดูว่าโฮสต์/ไอพีวิ่งเน็ตบ้านหรือ VPN
  ui                             เปิด UI ที่ 127.0.0.1 (ไม่ต้อง sudo — จะถามรหัสเมื่อกดเริ่มใช้/หยุดใช้)
  lang th|en                     บันทึกภาษาในคอนฟิก

ค่าเริ่มคือ inverse: เว็บทั่วไปออกเน็ตบ้าน ของบริษัทเข้า VPN (DNS เว็บทั่วไปก็ถามเน็ตบ้าน)
โหมด domains ใช้ไม่ได้ถ้ายังไม่มีโดเมนในลิสต์
ลองเว็บไม่ใช่โหมดที่สาม และไม่มี failover อัตโนมัติ`,
    usage: 'ใช้งาน: vpn-bypass [--lang th|en] <คำสั่ง>',
    'error.EPRIV': 'ต้องใช้สิทธิ์ผู้ดูแลระบบ (เช่น sudo หรือหน้าต่างรหัสผ่านใน UI) เพื่อใส่หรือลบเส้นทาง',
    'error.EACCES': 'เปิดไฟล์คอนฟิกไม่ได้ (สิทธิ์ถูกปฏิเสธ) — ถ้าเคยรันด้วย sudo ให้คืนเจ้าของแล้วเปิด UI โดยไม่ใช้ sudo:\nsudo chown -R "$(whoami)" ~/.config/vpn-bypass',
    'error.EPERM': 'ระบบปฏิเสธการแก้ตารางเส้นทาง',
    'error.EINVAL': 'อินพุตไม่ถูกต้อง: {message}',
    'error.ENOTVPN': 'ยังไม่พบ VPN — ต้องมีอุโมงค์หรือ default แยกจากเน็ตบ้าน (ชื่ออะแดปเตอร์อะไรก็ได้)',
    'error.EDOMAIN_EMPTY': 'โหมดระบุเว็บใช้ไม่ได้เมื่อลิสต์โดเมนว่าง',
    'error.ENOTLOOPBACK': 'เซิร์ฟเวอร์ต้องฟังที่ 127.0.0.1 เท่านั้น',
    'error.EBLOCKED': 'โฮสต์นี้ถูกบล็อก (localhost / link-local / metadata)',
    'error.ELOCK': 'กำลังใส่เส้นทางอยู่แล้ว ลองใหม่ภายหลัง',
    'error.ENOLAN': 'หาเกตเวย์เน็ตบ้านไม่เจอ',
    'error.EPROBE': 'เชื่อม {host}:443 ไม่สำเร็จ',
    'error.ENOTAPPLIED': 'ยังไม่ได้กดใช้เส้นทาง',
    'error.EUNSUPPORTED': 'ระบบปฏิบัติการนี้ยังไม่รองรับ',
    'error.EAUTH': 'โทเค็นไม่ถูกต้องหรือไม่มี',
    'error.EORIGIN': 'Origin/Host ต้องเป็น http://127.0.0.1',
    'error.EFAIL': 'เกิดข้อผิดพลาด',
    'warn.dns': 'ขณะที่กำลังใช้เส้นทาง DNS ของเว็บทั่วไปถามเน็ตบ้าน ไม่ผ่าน VPN ของบริษัท — คำต่อท้ายองค์กรและ PTR ของ RFC1918 ยังถาม DNS ของ VPN',
    'warn.endpoint': 'เครื่องมือนี้ซ่อนได้แค่เส้นทางอุโมงค์/ไฟร์วอลล์ของ DNS+ข้อมูล ไม่ได้ซ่อนจากเอเจนต์ GlobalProtect/EDR บนเครื่อง (รายการโปรเซส, HIP) — ไม่ได้ทำให้ล่องหน',
    'warn.ipv6': 'แยก IPv6 แบบ best-effort บน macOS/Linux เมื่อมีเกตเวย์ inet6 — Windows ยังเป็น IPv4 เท่านั้น',
    'warn.gp': 'GlobalProtect หรือไคลเอนต์ VPN อาจทับเส้นทางและ DNS ที่ใส่ไว้',
    'warn.policy': 'การแยกเส้นทางนี้อาจขัดนโยบายบริษัท — ไม่ใช่ split tunnel ทางการ',
    'warn.dnsWindows': 'Windows ไม่ได้เปลี่ยน DNS ของระบบ (กันอะแดปเตอร์พัง) — ชื่อเว็บบ้านอาจยังรั่วผ่าน DNS ของ VPN',
    'status.os': 'ระบบ',
    'status.admin': 'สิทธิ์ผู้ดูแล',
    'status.yes': 'ใช่',
    'status.no': 'ไม่',
    'status.vpn': 'VPN',
    'status.lan': 'เน็ตบ้าน',
    'status.mode': 'โหมด',
    'status.applied': 'กำลังใช้เส้นทาง',
    'status.dns': 'DNS',
    'status.dns.split': 'แยก (เว็บทั่วไปเน็ตบ้าน / คำต่อท้ายองค์กรผ่าน VPN)',
    'status.dns.lan': 'เน็ตบ้าน',
    'status.dns.vpn': 'VPN',
    'status.dns.none': 'ยังไม่แยก',
    'status.dns.unsupported': 'ไม่รองรับบนระบบนี้',
    'status.dns.skipped': 'ข้าม (ไม่เปลี่ยน)',
    'status.dns.unknown': 'ไม่ทราบ',
    'status.watch': 'เฝ้าทับ',
    'status.repair': 'ซ่อมขณะเปิด UI',
    'status.hijacked': 'VPN ทับเส้นทางที่ใส่ไว้ — กดใช้ใหม่ หรือเปิด UI ทิ้งไว้เพื่อซ่อม',
    'status.locale': 'ภาษา',
    'status.down': 'ไม่ขึ้น',
    'status.up': 'ขึ้น',
    'status.idle': 'ยังไม่ได้ใส่เส้นทาง',
    'confirm.allowVpn': 'เน็ตบ้านเข้า {host}:443 ไม่ได้ — ส่งโฮสต์นี้ผ่าน VPN? [y/N] ',
    'confirm.cancelled': 'ยกเลิก ไม่ได้ใส่เส้นทาง VPN',
    'try.ok': 'เข้า {host}:443 ผ่านเน็ตบ้านได้',
    'try.fail': 'เข้า {host}:443 ผ่านเน็ตบ้านไม่ได้ ({error})',
    'on.done': 'ใส่เส้นทางโหมด {mode} แล้ว — ปิดโปรแกรมได้ เส้นทางยังอยู่จนกว่าจะ off',
    'on.dryRun': 'โหมดจำลอง (ไม่แก้ตารางจริง)',
    'off.done': 'ลบเฉพาะเส้นทางในสมุดบัญชีแล้ว และคืน DNS ที่เครื่องมือนี้เปลี่ยนไว้',
    'allow.done': 'ใส่ host route ของ {host} ผ่าน VPN แล้ว',
    'deny.done': 'เอา host route ของ {host} ออกแล้ว',
    'lang.set': 'ตั้งภาษาเป็น {locale}',
    'lang.current': 'ภาษาปัจจุบัน: {locale}',
    'watch.on': 'เปิดเฝ้าทับ CLI แล้ว — ต้องเปิดโปรเซสนี้ทิ้งไว้ (Ctrl+C ไม่ได้ off)',
    'watch.off': 'ปิดเฝ้าทับแล้ว',
    'domain.added': 'เพิ่มโดเมน {host}',
    'domain.removed': 'ลบโดเมน {host}',
    'domain.empty': '(ไม่มีโดเมน)',
    'ui.hint': 'UI: {url}\nโทเค็น (เฮดเดอร์ X-Vpn-Bypass-Token): {token}',
    'lookup.title': 'เส้นทางของ {host}',
    'lookup.via.lan': 'เน็ตบ้าน',
    'lookup.via.vpn': 'VPN',
    'lookup.via.other': 'อื่น',
    'lookup.via.unknown': 'ไม่ทราบ',
    'ui.missing': 'ยังไม่มีไฟล์ UI — เซิร์ฟเวอร์ API พร้อมที่ {url}',
    'browser.open': 'กำลังเปิดเบราว์เซอร์',
    'needSudo': 'คำสั่งนี้ต้องใช้สิทธิ์ผู้ดูแล (sudo หรือหน้าต่างรหัสผ่านเมื่อกดเริ่มใช้ใน UI)',
    'unknown.command': 'ไม่รู้จักคำสั่ง: {command}',
    'unknown.flag': 'ไม่รู้จักแฟลก: {flag}',
  },
  en: {
    help: `Usage: vpn-bypass [--lang th|en] <command>

Commands:
  status                         Show status (lightweight; no public-IP wait)
  on [--mode inverse|domains] [--dry-run]
                                 Apply routes (default mode: inverse)
  off                            Delete only routes this tool added
  domain add|rm|list [host]      Manage advanced domain list
  try <host>                     Probe host:443 via LAN after inverse
  allow <host>                   Add a host route via the VPN (after confirm)
  deny <host>                    Remove that VPN host route
  watch [on|off]                 Re-apply missing/overwritten routes (off by default; process must stay up)
                                 The UI repairs overwritten routes while it stays open (after the first admin password in that session)
  lookup <host>                  Show whether a host/IP uses LAN or VPN
  ui                             Open the UI on 127.0.0.1 (no sudo; macOS asks for an admin password on Start/Stop)
  lang th|en                     Save CLI/UI language in config

Default mode is inverse: general web via home LAN, corp via VPN (general-web DNS also uses LAN).
domains mode cannot be enabled with an empty domain list.
try is not a third mode and never failovers automatically.`,
    usage: 'Usage: vpn-bypass [--lang th|en] <command>',
    'error.EPRIV': 'Administrator privileges (e.g. sudo, or the UI password dialog) are required to add or delete routes',
    'error.EACCES': 'Cannot open config (permission denied). If a previous sudo run left root-owned files, fix ownership then run the UI without sudo:\nsudo chown -R "$(whoami)" ~/.config/vpn-bypass',
    'error.EPERM': 'The OS refused to change the routing table',
    'error.EINVAL': 'Invalid input: {message}',
    'error.ENOTVPN': 'No VPN detected — need a tunnel or a default route separate from home LAN (any adapter name)',
    'error.EDOMAIN_EMPTY': 'domains mode cannot be enabled with an empty domain list',
    'error.ENOTLOOPBACK': 'The server must listen on 127.0.0.1 only',
    'error.EBLOCKED': 'This host is blocked (localhost / link-local / metadata)',
    'error.ELOCK': 'Another apply is in progress; try again',
    'error.ENOLAN': 'Could not find the LAN gateway',
    'error.EPROBE': 'Could not connect to {host}:443',
    'error.ENOTAPPLIED': 'Routes have not been applied yet',
    'error.EUNSUPPORTED': 'This operating system is not supported',
    'error.EAUTH': 'Missing or invalid token',
    'error.EORIGIN': 'Origin/Host must be http://127.0.0.1',
    'error.EFAIL': 'Something went wrong',
    'warn.dns': 'While applied, general-web DNS uses home LAN — not the corporate VPN. Corporate suffixes and RFC1918 reverse lookups still use VPN DNS.',
    'warn.endpoint': 'This can hide tunnel/firewall visibility of DNS and IPv4/IPv6 data paths. It cannot hide a GlobalProtect/EDR endpoint agent on this laptop (process list, HIP). This is not invisibility.',
    'warn.ipv6': 'IPv6 split is best-effort on macOS/Linux when an inet6 LAN gateway is present; Windows stays IPv4-only',
    'warn.gp': 'GlobalProtect or another VPN client may overwrite these routes and DNS',
    'warn.policy': 'This split may violate corporate policy — it is not official split tunnel',
    'warn.dnsWindows': 'Windows system DNS is left unchanged (to avoid breaking adapters). Home-web names may still leak via VPN DNS.',
    'status.os': 'OS',
    'status.admin': 'Admin',
    'status.yes': 'yes',
    'status.no': 'no',
    'status.vpn': 'VPN',
    'status.lan': 'LAN',
    'status.mode': 'Mode',
    'status.applied': 'Routes applied',
    'status.dns': 'DNS',
    'status.dns.split': 'split (general web via LAN / corp suffixes via VPN)',
    'status.dns.lan': 'LAN',
    'status.dns.vpn': 'VPN',
    'status.dns.none': 'not split',
    'status.dns.unsupported': 'unsupported on this OS',
    'status.dns.skipped': 'skipped (unchanged)',
    'status.dns.unknown': 'unknown',
    'status.watch': 'Watch',
    'status.repair': 'Repair while UI open',
    'status.hijacked': 'VPN overwrote owned routes — apply again, or leave the UI open to repair',
    'status.locale': 'Language',
    'status.down': 'down',
    'status.up': 'up',
    'status.idle': 'routes not applied',
    'confirm.allowVpn': 'LAN cannot reach {host}:443 — send this host via VPN? [y/N] ',
    'confirm.cancelled': 'Cancelled; no VPN host route added',
    'try.ok': 'Reached {host}:443 via LAN',
    'try.fail': 'Could not reach {host}:443 via LAN ({error})',
    'on.done': 'Applied {mode} routes — you can quit; routes stay until off',
    'on.dryRun': 'Dry-run (routing table not changed)',
    'off.done': 'Removed only ledger-owned routes and restored DNS this tool changed',
    'allow.done': 'Added VPN host route for {host}',
    'deny.done': 'Removed VPN host route for {host}',
    'lang.set': 'Language set to {locale}',
    'lang.current': 'Current language: {locale}',
    'watch.on': 'CLI watch enabled — keep this process running (Ctrl+C does not run off)',
    'watch.off': 'Watch disabled',
    'domain.added': 'Added domain {host}',
    'domain.removed': 'Removed domain {host}',
    'domain.empty': '(no domains)',
    'ui.hint': 'UI: {url}\nToken (X-Vpn-Bypass-Token header): {token}',
    'lookup.title': 'Path for {host}',
    'lookup.via.lan': 'home LAN',
    'lookup.via.vpn': 'VPN',
    'lookup.via.other': 'other',
    'lookup.via.unknown': 'unknown',
    'ui.missing': 'UI files not present yet — API is ready at {url}',
    'browser.open': 'Opening the browser',
    'needSudo': 'This command needs administrator rights (sudo, or the UI password dialog)',
    'unknown.command': 'Unknown command: {command}',
    'unknown.flag': 'Unknown flag: {flag}',
  },
};

function normalizeLocale(value) {
  if (value == null || value === '') return null;
  const v = String(value).trim().toLowerCase();
  if (v === 'th' || v === 'en') return v;
  return null;
}

function t(locale, key, vars = {}) {
  const loc = normalizeLocale(locale) || 'th';
  const dict = STRINGS[loc] || STRINGS.th;
  let s = dict[key] ?? STRINGS.en[key] ?? STRINGS.th[key] ?? key;
  for (const [k, v] of Object.entries(vars)) {
    s = s.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v));
  }
  return s;
}

function warningList(locale, extra = {}) {
  const list = [
    t(locale, 'warn.dns'),
    t(locale, 'warn.endpoint'),
    t(locale, 'warn.ipv6'),
    t(locale, 'warn.gp'),
    t(locale, 'warn.policy'),
  ];
  const os = extra.os || '';
  if (os === 'win32') list.push(t(locale, 'warn.dnsWindows'));
  if (extra.dns && extra.dns.warning) {
    const w = String(extra.dns.warning);
    if (w && list.indexOf(w) === -1) list.push(w);
  }
  return list;
}

module.exports = { STRINGS, normalizeLocale, t, warningList };
