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
  watch [on|off]                 เฝ้าทับเส้นทาง (ค่าเริ่มปิด; ต้องเปิดโปรเซสทิ้งไว้)
  lookup <โฮสต์>                 ดูว่าโฮสต์/ไอพีวิ่งเน็ตบ้านหรือ VPN
  ui                             เปิด UI ที่ 127.0.0.1
  lang th|en                     บันทึกภาษาในคอนฟิก

ค่าเริ่มคือ inverse: เว็บทั่วไปออกเน็ตบ้าน ของบริษัทเข้า VPN
โหมด domains ใช้ไม่ได้ถ้ายังไม่มีโดเมนในลิสต์
ลองเว็บไม่ใช่โหมดที่สาม และไม่มี failover อัตโนมัติ`,
    usage: 'ใช้งาน: vpn-bypass [--lang th|en] <คำสั่ง>',
    'error.EPRIV': 'ต้องใช้สิทธิ์ผู้ดูแลระบบ (เช่น sudo) เพื่อใส่หรือลบเส้นทาง',
    'error.EPERM': 'ระบบปฏิเสธการแก้ตารางเส้นทาง',
    'error.EINVAL': 'อินพุตไม่ถูกต้อง: {message}',
    'error.ENOTVPN': 'ยังไม่พบ VPN (utun/tun/tap/ppp/ipsec/gpd)',
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
    'warn.dns': 'DNS ยังผ่าน VPN — ชื่อโฮสต์อาจไม่ตรงกับเส้นทาง IPv4',
    'warn.ipv6': 'แยกเฉพาะ IPv4 — IPv6 อาจรั่วหรือยังเต็มอุโมงค์',
    'warn.gp': 'GlobalProtect หรือไคลเอนต์ VPN อาจทับเส้นทางที่ใส่ไว้',
    'warn.policy': 'การแยกเส้นทางนี้อาจขัดนโยบายบริษัท — ไม่ใช่ split tunnel ทางการ',
    'status.os': 'ระบบ',
    'status.admin': 'สิทธิ์ผู้ดูแล',
    'status.yes': 'ใช่',
    'status.no': 'ไม่',
    'status.vpn': 'VPN',
    'status.lan': 'เน็ตบ้าน',
    'status.mode': 'โหมด',
    'status.applied': 'กำลังใช้เส้นทาง',
    'status.watch': 'เฝ้าทับ',
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
    'off.done': 'ลบเฉพาะเส้นทางในสมุดบัญชีแล้ว',
    'allow.done': 'ใส่ host route ของ {host} ผ่าน VPN แล้ว',
    'deny.done': 'เอา host route ของ {host} ออกแล้ว',
    'lang.set': 'ตั้งภาษาเป็น {locale}',
    'lang.current': 'ภาษาปัจจุบัน: {locale}',
    'watch.on': 'เปิดเฝ้าทับแล้ว — ต้องเปิดโปรเซสนี้ทิ้งไว้ (Ctrl+C ไม่ได้ off)',
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
    'needSudo': 'คำสั่งนี้ต้องใช้ sudo',
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
  watch [on|off]                 Re-apply missing routes (off by default; process must stay up)
  lookup <host>                  Show whether a host/IP uses LAN or VPN
  ui                             Open the UI on 127.0.0.1
  lang th|en                     Save CLI/UI language in config

Default mode is inverse: general web via home LAN, corp via VPN.
domains mode cannot be enabled with an empty domain list.
try is not a third mode and never failovers automatically.`,
    usage: 'Usage: vpn-bypass [--lang th|en] <command>',
    'error.EPRIV': 'Administrator privileges (e.g. sudo) are required to add or delete routes',
    'error.EPERM': 'The OS refused to change the routing table',
    'error.EINVAL': 'Invalid input: {message}',
    'error.ENOTVPN': 'No VPN interface detected (utun/tun/tap/ppp/ipsec/gpd)',
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
    'warn.dns': 'DNS still goes via the VPN — names may not match IPv4 routes',
    'warn.ipv6': 'IPv4 only — IPv6 may leak or stay full-tunnel',
    'warn.gp': 'GlobalProtect or another VPN client may overwrite these routes',
    'warn.policy': 'This split may violate corporate policy — it is not official split tunnel',
    'status.os': 'OS',
    'status.admin': 'Admin',
    'status.yes': 'yes',
    'status.no': 'no',
    'status.vpn': 'VPN',
    'status.lan': 'LAN',
    'status.mode': 'Mode',
    'status.applied': 'Routes applied',
    'status.watch': 'Watch',
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
    'off.done': 'Removed only ledger-owned routes',
    'allow.done': 'Added VPN host route for {host}',
    'deny.done': 'Removed VPN host route for {host}',
    'lang.set': 'Language set to {locale}',
    'lang.current': 'Current language: {locale}',
    'watch.on': 'Watch enabled — keep this process running (Ctrl+C does not run off)',
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
    'needSudo': 'This command needs sudo',
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

function warningList(locale) {
  return [
    t(locale, 'warn.dns'),
    t(locale, 'warn.ipv6'),
    t(locale, 'warn.gp'),
    t(locale, 'warn.policy'),
  ];
}

module.exports = { STRINGS, normalizeLocale, t, warningList };
