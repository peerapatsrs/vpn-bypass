(() => {
  "use strict";

  const LOCALE_KEY = "vpn-bypass-locale";
  const POLL_MS = 2000;

  const I18N = {
    th: {
      docTitle: "VPN Bypass",
      skip: "ข้ามไปเนื้อหาหลัก",
      brand: "VPN Bypass",
      tagline: "แยกเส้นทางเว็บบ้านกับของบริษัท",
      langGroup: "ภาษา",
      langTh: "ไทย",
      langEn: "EN",
      persistTitle: "ปิดแท็บหรือปิดเทอร์มินัล ไม่ได้หยุดเส้นทาง",
      persistBody:
        "การปิดแท็บนี้ไม่ได้ปิดเส้นทางในเครื่อง การปิดหน้าต่างเทอร์มินัลก็เช่นกัน ต้องกด «หยุดใช้» เท่านั้นจึงจะคืนเส้นทางที่เครื่องมือนี้ใส่ไว้",
      privTitle: "จะถามรหัสผู้ดูแลเมื่อเปลี่ยนเส้นทาง",
      privBody:
        "ดูสถานะและดูตัวอย่างได้เลย จะถามรหัสผู้ดูแลเมื่อกดเริ่มใช้/หยุดใช้ รวมถึงอนุญาต ปฏิเสธ เฝ้าทับ หรือการแก้เส้นทาง/DNS ของระบบ",
      privLocked: "ระบบนี้ยังยกสิทธิ์อัตโนมัติไม่ได้ — ปุ่มที่เปลี่ยนเส้นทางถูกล็อกไว้",
      statusTitle: "สถานะ",
      os: "ระบบ",
      lanIface: "เน็ตบ้าน (อินเทอร์เฟซ)",
      lanGw: "เกตเวย์บ้าน",
      vpnIface: "VPN (อินเทอร์เฟซ)",
      currentMode: "โหมดที่ใช้ตอนนี้",
      routesState: "เส้นทาง",
      routesOn: "กำลังแยกเส้นอยู่",
      routesOff: "ยังไม่ได้เริ่มใช้",
      ipLan: "IP สาธารณะเน็ตบ้าน",
      ipVpn: "IP สาธารณะ VPN",
      ipPending: "ยังไม่ทราบ",
      ipFail: "ตรวจไม่สำเร็จ",
      unknown: "ไม่ทราบ",
      na: "—",
      dnsLabel: "DNS",
      dnsSplit: "แยก (เว็บบ้าน / องค์กร VPN)",
      dnsLan: "เน็ตบ้าน",
      dnsVpn: "VPN",
      dnsNone: "ยังไม่แยก",
      dnsUnsupported: "ไม่รองรับบนระบบนี้",
      dnsSkipped: "ข้าม (ไม่เปลี่ยน)",
      dnsUnknown: "ไม่ทราบ",
      osMac: "macOS",
      osWin: "Windows",
      osLinux: "Linux",
      modeTitle: "วิธีแยกเส้นทาง",
      modeDefaultEyebrow: "ค่าเริ่ม",
      modeDefaultTitle: "เว็บทั่วไปออกเน็ตบ้าน ของบริษัทเข้า VPN",
      modeDefaultBody:
        "เว็บภายนอกใช้เน็ตบ้าน วงในองค์กรยังเข้าผ่าน VPN",
      modeAdvancedEyebrow: "ขั้นสูง",
      modeAdvancedTitle: "ระบุเว็บให้ออกเน็ตบ้าน",
      modeAdvancedBody:
        "VPN เต็มอุโมงค์ตามเดิม เฉพาะเว็บในรายการถูกบังคับออกเน็ตบ้าน",
      modeSelected: "กำลังเลือกอยู่",
      modeEmptyHint: "เพิ่มอย่างน้อยหนึ่งเว็บก่อน จึงจะเริ่มใช้โหมดนี้ได้",
      start: "เริ่มใช้",
      stop: "หยุดใช้",
      starting: "กำลังใส่เส้นทาง…",
      stopping: "กำลังคืนเส้นทาง…",
      dryRun: "ดูตัวอย่างก่อนใช้",
      dryRunning: "กำลังสร้างตัวอย่าง…",
      dryRunTitle: "เส้นทางที่จะใส่ (ยังไม่ลงของจริง)",
      dryRunEmpty: "ไม่มีรายการเส้นทางในตัวอย่าง",
      dryRunColDest: "ปลายทาง",
      dryRunColVia: "ผ่าน",
      dryRunColIface: "อินเทอร์เฟซ",
      dryRunColKind: "ชนิด",
      domainsTitle: "เว็บที่ให้ออกเน็ตบ้าน",
      domainsHint: "เมื่อเพิ่ม ระบบจะเติมทั้งชื่อหลักและ www ให้",
      domainsEmpty: "ยังไม่มีเว็บในรายการ",
      domainPlaceholder: "เช่น youtube.com",
      domainAdd: "เพิ่ม",
      domainRemove: "ลบ",
      adding: "กำลังเพิ่ม…",
      tryTitle: "ลองเว็บ",
      tryBody:
        "ทดสอบว่าเว็บเข้าได้ผ่านเน็ตบ้านหรือไม่ ถ้าเข้าไม่ได้จะไม่ส่งเข้า VPN จนกว่าคุณจะยืนยัน",
      tryPlaceholder: "เช่น intranet.company.com",
      tryAction: "ลองเว็บ",
      trying: "กำลังลอง…",
      tryNeedOn: "แนะนำให้กดเริ่มใช้โหมดค่าเริ่มก่อน แล้วค่อยลองเว็บ",
      tryOk: "เข้าได้ผ่านเน็ตบ้าน — ไม่ส่งเข้า VPN",
      tryFail: "เน็ตบ้านเข้า {host} ไม่ได้",
      allowedTitle: "เว็บที่อนุญาตให้เข้าผ่าน VPN",
      allowedEmpty: "ยังไม่มีเว็บที่เจาะเข้า VPN",
      deny: "ยกเลิกการเจาะ VPN",
      modalTitle: "ส่งเว็บนี้ผ่าน VPN?",
      modalBody:
        "เน็ตบ้านเข้า {host} ไม่ได้ หากยืนยัน จะใส่เส้นทางโฮสต์นี้ผ่าน VPN การกระทำนี้ไม่ใช่ค่าเริ่ม และจะไม่ส่งให้อัตโนมัติ",
      modalType: "พิมพ์ชื่อโฮสต์อีกครั้งเพื่อยืนยัน",
      modalTypePh: "พิมพ์ {host}",
      modalCheck:
        "รับทราบว่าทราฟฟิกของโฮสต์นี้จะเดินทางผ่าน VPN ของบริษัท",
      modalCancel: "ยกเลิก",
      modalConfirm: "ส่งผ่าน VPN",
      modalBusy: "กำลังใส่เส้นทาง…",
      watchTitle: "เฝ้าทับเส้นทาง",
      watchBody:
        "คำสั่ง watch ใน CLI ปิดเป็นค่าเริ่ม เพื่อกดเริ่มใช้แล้วปิดเทอร์มินัลได้ ขณะเปิดหน้านี้ หลังยืนยันรหัสผู้ดูแลครั้งแรก ระบบซ่อมเส้นที่ VPN ทับให้อัตโนมัติ โดยไม่บันทึกเป็นเฝ้าทับถาวร",
      watchCost:
        "ปิดแท็บไม่ได้เท่ากับหยุดเส้นทาง ปิดเทอร์มินัลก็ไม่ได้คืนเส้นทาง ต้องกดหยุดใช้เอง ปิดหน้านี้แล้วจะไม่ซ่อม reconnect จนกว่าจะเปิด UI อีกหรือรัน watch ใน CLI",
      watchOn: "เฝ้าทับ CLI เปิดอยู่",
      watchOff: "เฝ้าทับ CLI ปิดอยู่",
      repairActive: "กำลังซ่อมเส้นทางอัตโนมัติขณะเปิดหน้านี้",
      repairIdle: "หลังกดเริ่มใช้และยืนยันรหัสผู้ดูแลแล้ว ระบบจะซ่อมเส้นที่ VPN ทับให้อัตโนมัติขณะเปิดหน้านี้",
      hijackTitle: "VPN ทับเส้นทางแล้ว",
      hijackBody:
        "ไคลเอนต์ VPN เขียนเส้นทางทับ กด «เริ่มใช้» อีกครั้ง (จะถามรหัสถ้ายังไม่เคยใส่ในเซสชันนี้) หรือรอซ่อมอัตโนมัติหลังเคยยืนยันรหัสแล้ว",
      hijackRepairing: "พบว่าเส้นถูกทับ — กำลังซ่อม",
      logTitle: "บันทึกกิจกรรม",
      logEmpty: "ยังไม่มีรายการ",
      routesTitle: "เส้นทางที่วิ่งอยู่",
      routesHint: "เส้นที่เครื่องมือใส่ไว้ในตารางเส้นทาง ไม่ใช่เว็บที่กำลังเปิด",
      routesEmpty: "ยังไม่มีเส้นทางที่ใส่ไว้ — กดเริ่มใช้ก่อน",
      routesColDest: "ปลายทาง",
      routesColVia: "วิ่งทาง",
      routesColIface: "อินเทอร์เฟซ",
      routesColGw: "เกตเวย์",
      routesColKind: "ชนิด",
      routesColDomain: "โดเมน",
      viaLan: "เน็ตบ้าน",
      viaVpn: "VPN",
      viaOther: "อื่น",
      viaUnknown: "ไม่ทราบ",
      lookupTitle: "ตรวจเว็บ / ไอพี",
      lookupHint: "เช่น facebook.com จะบอกว่าแต่ละไอพีออกเน็ตบ้านหรือ VPN",
      lookupPlaceholder: "เช่น facebook.com",
      lookupAction: "ตรวจเส้นทาง",
      lookingUp: "กำลังตรวจ…",
      lookupEmpty: "ยังไม่ได้ตรวจ",
      trafficTitle: "เว็บที่กำลังเปิด",
      trafficHint: "เปิดเว็บในเบราว์เซอร์ รายการนี้จะบอกเองว่าออกเน็ตบ้านหรือ VPN (ดูเฉพาะ HTTP/HTTPS)",
      trafficEmpty: "ยังไม่เห็นการเชื่อมเว็บ — เปิดไซต์แล้วรอประมาณ 2 วินาที",
      trafficRecent: "เพิ่งเข้า",
      trafficRecentEmpty: "ยังไม่มีประวัติในรอบนี้",
      trafficColSite: "เว็บ",
      trafficColApp: "แอป",
      trafficColIp: "ไอพี",
      trafficColNet: "เน็ต",
      kindSplit: "เว็บทั่วไปออกบ้าน",
      kindLan: "กัน LAN บ้าน",
      kindVpnKeep: "วงในองค์กรเข้า VPN",
      kindDomain: "โดเมนออกบ้าน",
      kindAllow: "เจาะเข้า VPN",
      errorGeneric: "ทำรายการไม่สำเร็จ",
      errorNetwork:
        "ติดต่อเซิร์ฟเวอร์ไม่ได้ ตรวจว่าเปิด vpn-bypass ui อยู่",
      errorHost: "ใส่ได้แค่ชื่อโฮสต์หรือไอพี ไม่ใช่ URL",
      errorEmptyDomains: "โหมดระบุเว็บใช้ไม่ได้เมื่อรายการว่าง",
      errorPriv: "ยกเลิกหน้าต่างรหัสผ่าน หรือไม่มีสิทธิ์ผู้ดูแล — กดอีกครั้งเพื่อลองใหม่",
      noticeOn:
        "ใส่เส้นทางแล้ว เทียบ IP สาธารณะเน็ตบ้านกับ VPN ได้ด้านบน",
      noticeOff: "คืนเส้นทางที่เครื่องมือนี้ใส่แล้ว",
      noticeWatchOn: "เปิดเฝ้าทับแล้ว ต้องเปิดเทอร์มินัลทิ้งไว้",
      noticeWatchOff: "ปิดเฝ้าทับแล้ว",
      loading: "กำลังโหลด…",
      offline: "ยังไม่มีข้อมูลจากเซิร์ฟเวอร์",
    },
    en: {
      docTitle: "VPN Bypass",
      skip: "Skip to main content",
      brand: "VPN Bypass",
      tagline: "Split home web traffic from company VPN",
      langGroup: "Language",
      langTh: "ไทย",
      langEn: "EN",
      persistTitle: "Closing the tab or terminal does not stop routes",
      persistBody:
        "Closing this tab does not remove routes. Closing the terminal does not either. Only Stop using restores the routes this tool added.",
      privTitle: "Admin password is asked when routes change",
      privBody:
        "Status and preview work without admin. Start, Stop, allow, deny, watch, and anything that changes routes or system DNS will ask for an administrator password.",
      privLocked: "This OS cannot prompt for admin from the UI — route-changing controls are locked",
      statusTitle: "Status",
      os: "System",
      lanIface: "Home network (interface)",
      lanGw: "Home gateway",
      vpnIface: "VPN (interface)",
      currentMode: "Mode in use",
      routesState: "Routes",
      routesOn: "Split routing is on",
      routesOff: "Not applied yet",
      ipLan: "Public IP via home internet",
      ipVpn: "Public IP via VPN",
      ipPending: "Not known yet",
      ipFail: "Lookup failed",
      unknown: "Unknown",
      na: "—",
      dnsLabel: "DNS",
      dnsSplit: "split (home web / corp VPN)",
      dnsLan: "home LAN",
      dnsVpn: "VPN",
      dnsNone: "not split",
      dnsUnsupported: "unsupported on this OS",
      dnsSkipped: "skipped (unchanged)",
      dnsUnknown: "unknown",
      osMac: "macOS",
      osWin: "Windows",
      osLinux: "Linux",
      modeTitle: "How traffic is split",
      modeDefaultEyebrow: "Default",
      modeDefaultTitle: "General web via home internet, company sites via VPN",
      modeDefaultBody:
        "External sites use home internet. Internal company networks stay on the VPN.",
      modeAdvancedEyebrow: "Advanced",
      modeAdvancedTitle: "Only listed sites use home internet",
      modeAdvancedBody:
        "The full VPN tunnel stays. Only sites in the list are forced onto home internet.",
      modeSelected: "Selected",
      modeEmptyHint: "Add at least one site before this mode can be applied.",
      start: "Start using",
      stop: "Stop using",
      starting: "Applying routes…",
      stopping: "Removing routes…",
      dryRun: "Preview without applying",
      dryRunning: "Building preview…",
      dryRunTitle: "Routes that would be added (not applied)",
      dryRunEmpty: "No routes in the preview",
      dryRunColDest: "Destination",
      dryRunColVia: "Via",
      dryRunColIface: "Interface",
      dryRunColKind: "Kind",
      domainsTitle: "Sites that use home internet",
      domainsHint: "Adding a site also stores the apex and www names on the server.",
      domainsEmpty: "No sites in the list yet",
      domainPlaceholder: "e.g. youtube.com",
      domainAdd: "Add",
      domainRemove: "Remove",
      adding: "Adding…",
      tryTitle: "Try a site",
      tryBody:
        "Probe whether the site is reachable on home internet. If it is not, nothing is sent via VPN until you confirm.",
      tryPlaceholder: "e.g. intranet.company.com",
      tryAction: "Try site",
      trying: "Probing…",
      tryNeedOn: "Apply the default mode first, then try a site.",
      tryOk: "Reachable on home internet — not sent via VPN",
      tryFail: "Home internet could not reach {host}",
      allowedTitle: "Sites allowed through the VPN",
      allowedEmpty: "No hosts are pinned through the VPN",
      deny: "Remove VPN pin",
      modalTitle: "Send this site through the VPN?",
      modalBody:
        "Home internet could not reach {host}. Confirming adds a host route via the VPN. This is not the default, and it is never sent automatically.",
      modalType: "Type the hostname again to confirm",
      modalTypePh: "Type {host}",
      modalCheck:
        "I understand this host’s traffic will travel through the company VPN",
      modalCancel: "Cancel",
      modalConfirm: "Send via VPN",
      modalBusy: "Adding route…",
      watchTitle: "Watch routes",
      watchBody:
        "CLI watch stays off by default so Start using can be save-and-close. While this page is open, after the first administrator password in the session, overwritten routes are repaired automatically without saving a persistent watch flag.",
      watchCost:
        "Closing the tab does not turn routes off. Closing the terminal does not restore routes either. You must press Stop using. After you close this UI, reconnects are not repaired until you open the UI again or run CLI watch.",
      watchOn: "CLI watch is on",
      watchOff: "CLI watch is off",
      repairActive: "Repairing overwritten routes while this page is open",
      repairIdle: "After Start using and the admin password, overwritten routes are repaired automatically while this page stays open",
      hijackTitle: "VPN overwrote the routes",
      hijackBody:
        "The VPN client overwrote owned routes. Click Start using again (it will ask for a password if this session has not elevated yet), or wait for automatic repair after you have already authenticated.",
      hijackRepairing: "Owned routes were overwritten — repairing",
      logTitle: "Activity log",
      logEmpty: "No entries yet",
      routesTitle: "Where traffic goes",
      routesHint: "Routes this tool installed — not the sites you currently have open",
      routesEmpty: "No installed routes yet — click Start first",
      routesColDest: "Destination",
      routesColVia: "Path",
      routesColIface: "Interface",
      routesColGw: "Gateway",
      routesColKind: "Kind",
      routesColDomain: "Domain",
      viaLan: "home LAN",
      viaVpn: "VPN",
      viaOther: "other",
      viaUnknown: "unknown",
      lookupTitle: "Check a site / IP",
      lookupHint: "e.g. facebook.com — shows whether each IP uses home LAN or VPN",
      lookupPlaceholder: "e.g. facebook.com",
      lookupAction: "Check path",
      lookingUp: "Checking…",
      lookupEmpty: "Not checked yet",
      trafficTitle: "Sites currently open",
      trafficHint: "Open a site in your browser. This list shows whether each HTTPS/HTTP connection uses home LAN or VPN.",
      trafficEmpty: "No web connections yet — open a site and wait about 2 seconds",
      trafficRecent: "Just visited",
      trafficRecentEmpty: "No visits recorded in this session",
      trafficColSite: "Site",
      trafficColApp: "App",
      trafficColIp: "IP",
      trafficColNet: "Net",
      kindSplit: "general web via LAN",
      kindLan: "protect home LAN",
      kindVpnKeep: "corp nets via VPN",
      kindDomain: "domain via LAN",
      kindAllow: "punch through VPN",
      errorGeneric: "The request failed",
      errorNetwork:
        "Could not reach the server. Check that vpn-bypass ui is running.",
      errorHost: "Enter a hostname or IPv4 address, not a URL",
      errorEmptyDomains: "Listed-sites mode cannot start with an empty list",
      errorPriv: "Administrator password was cancelled or denied — try again",
      noticeOn:
        "Routes applied. Compare the home and VPN public IPs above.",
      noticeOff: "Routes added by this tool were removed.",
      noticeWatchOn: "Watch is on. Keep the terminal running.",
      noticeWatchOff: "Watch is off.",
      loading: "Loading…",
      offline: "No server data yet",
    },
  };

  const state = {
    locale: "th",
    status: null,
    ips: null,
    config: null,
    domains: [],
    allowed: [],
    log: [],
    logOpen: true,
    ownedRoutes: [],
    traffic: { live: [], recent: [] },
    watchEnabled: false,
    selectedMode: "inverse",
    modeTouched: false,
    localeTouched: false,
    ui: {
      busy: null,
      error: null,
      notice: null,
      dryRun: null,
      modal: null,
      tryHost: "",
      domainHost: "",
      lookupHost: "",
      lookupResult: null,
      tryResult: null,
      noAdmin: false,
      pollRender: false,
      openedModal: false,
    },
  };

  const app = document.getElementById("app");
  let pollTimer = null;
  let lastView = "";

  function readStoredLocale() {
    try {
      const v = localStorage.getItem(LOCALE_KEY);
      if (v === "en" || v === "th") return v;
    } catch (_err) {
      /* ignore */
    }
    return null;
  }

  function writeStoredLocale(locale) {
    try {
      localStorage.setItem(LOCALE_KEY, locale);
    } catch (_err) {
      /* ignore */
    }
  }

  function t(key, vars) {
    const dict = I18N[state.locale] || I18N.th;
    let s = dict[key] || I18N.th[key] || key;
    if (vars) {
      s = s.replace(/\{(\w+)\}/g, (_, k) =>
        vars[k] == null ? "" : String(vars[k])
      );
    }
    return s;
  }

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function th(key, vars) {
    return esc(t(key, vars));
  }

  function getToken() {
    if (typeof window.__VPN_BYPASS_TOKEN__ === "string" && window.__VPN_BYPASS_TOKEN__) {
      return window.__VPN_BYPASS_TOKEN__;
    }
    const meta = document.querySelector('meta[name="vpn-bypass-token"]');
    if (meta && meta.content) return meta.content;
    try {
      const q = new URLSearchParams(window.location.search).get("token");
      if (q) return q;
    } catch (_err) {
      /* ignore */
    }
    return "";
  }

  function pick(obj, paths, fallback) {
    if (obj == null) return fallback;
    for (let i = 0; i < paths.length; i += 1) {
      const parts = paths[i].split(".");
      let cur = obj;
      let ok = true;
      for (let j = 0; j < parts.length; j += 1) {
        if (cur == null || typeof cur !== "object") {
          ok = false;
          break;
        }
        cur = cur[parts[j]];
      }
      if (ok && cur !== undefined && cur !== null && cur !== "") return cur;
    }
    return fallback;
  }

  function asList(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value;
    if (Array.isArray(value.domains)) return value.domains;
    if (Array.isArray(value.hosts)) return value.hosts;
    if (Array.isArray(value.items)) return value.items;
    if (Array.isArray(value.entries)) return value.entries;
    if (Array.isArray(value.lines)) return value.lines;
    return [];
  }

  function unwrap(payload) {
    if (payload && typeof payload === "object" && payload.data != null) {
      return payload.data;
    }
    return payload;
  }

  function errorMessage(json, fallbackKey) {
    const code = pick(json, ["error.code", "code"], "");
    if (code === "EPRIV" || code === "EPERM") return t("errorPriv");
    if (code === "EDOMAIN_EMPTY") return t("errorEmptyDomains");
    if (code === "EINVAL") {
      const msg = pick(json, ["error.message", "message"], "");
      return msg || t("errorHost");
    }
    return pick(json, ["error.message", "message"], t(fallbackKey || "errorGeneric"));
  }

  async function api(method, path, body) {
    const headers = {
      Accept: "application/json",
      "X-Vpn-Bypass-Token": getToken(),
    };
    const opts = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, opts);
    } catch (_err) {
      return { ok: false, network: true, error: { code: "ENET", message: t("errorNetwork") } };
    }
    let json = null;
    try {
      json = await res.json();
    } catch (_err) {
      json = null;
    }
    if (json && json.ok === false) {
      return {
        ok: false,
        status: res.status,
        error: json.error || { code: "EFAIL", message: errorMessage(json) },
        json,
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        error: {
          code: pick(json, ["error.code"], "EHTTP"),
          message: errorMessage(json),
        },
        json,
      };
    }
    return { ok: true, status: res.status, data: unwrap(json), json };
  }

  function locked() {
    if (state.status && state.status.hasAdmin) return false;
    if (state.status && state.status.canElevate) return false;
    if (state.ui.noAdmin) return true;
    if (state.status && state.status.hasAdmin === false) return true;
    return false;
  }

  function busy() {
    return !!state.ui.busy;
  }

  function mutateDisabled() {
    return locked() || busy();
  }

  function normalizeStatus(data) {
    if (!data || typeof data !== "object") return null;
    const appliedRaw = data.applied;
    const applied =
      appliedRaw === true ||
      (appliedRaw && typeof appliedRaw === "object") ||
      data.active === true ||
      data.enabled === true;
    const mode = String(
      pick(data, ["mode", "applied.mode", "config.mode"], "inverse")
    ).toLowerCase();
    return {
      hasAdmin: data.hasAdmin !== false,
      canElevate: data.canElevate === true,
      os: pick(data, ["os", "platform", "ifaces.os"], ""),
      mode: mode === "domains" ? "domains" : "inverse",
      applied: !!applied,
      lanIface: pick(data, ["ifaces.lan.name", "ifaces.lan.iface", "lan.iface", "lanIface", "lan.ifname"], ""),
      lanGw: pick(data, ["ifaces.lan.gateway", "ifaces.lan.gw", "lan.gateway", "lanGw", "lan.gw"], ""),
      vpnIface: pick(data, ["ifaces.vpn.name", "ifaces.vpn.iface", "vpn.iface", "vpnIface", "vpn.ifname"], ""),
      watchActive: !!(data.watch),
      repairActive: !!(data.repairActive),
      hijacked: !!(data.hijacked),
      dns: normalizeDns(data.dns),
      allowed: asList(data.allowVpnHosts || data.allowedHosts || data.allowed),
      ownedRoutes: asList(data.ownedRoutes),
    };
  }

  function normalizeDns(raw) {
    if (!raw || typeof raw !== "object") return { mode: "none", suffixes: [], warning: null, hijacked: false };
    const mode = String(raw.mode || "none").toLowerCase();
    const allowed = ["split", "lan", "vpn", "none", "unsupported", "skipped", "unknown"];
    return {
      mode: allowed.indexOf(mode) >= 0 ? mode : "unknown",
      listen: raw.listen || "",
      lanServers: asList(raw.lanServers),
      vpnServers: asList(raw.vpnServers),
      suffixes: asList(raw.suffixes),
      warning: raw.warning || null,
      hijacked: !!raw.hijacked,
    };
  }

  function dnsLabel(dns) {
    const mode = dns && dns.mode ? dns.mode : "none";
    if (mode === "split") return t("dnsSplit");
    if (mode === "lan") return t("dnsLan");
    if (mode === "vpn") return t("dnsVpn");
    if (mode === "unsupported") return t("dnsUnsupported");
    if (mode === "skipped") return t("dnsSkipped");
    if (mode === "unknown") return t("dnsUnknown");
    return t("dnsNone");
  }

  function dnsPillClass(dns) {
    const mode = dns && dns.mode ? dns.mode : "none";
    if (mode === "split" || mode === "lan") return "pill pill-on";
    if (mode === "vpn") return "pill pill-vpn";
    return "pill pill-off";
  }

  function normalizeIps(data) {
    if (!data || typeof data !== "object") return { lan: null, vpn: null, fail: false };
    const lan = pick(data, ["lan", "lanIp", "publicLan", "home", "isp"], null);
    const vpn = pick(data, ["vpn", "vpnIp", "publicVpn"], null);
    const fail = data.ok === false || (!lan && !vpn && (data.error || data.failed));
    return { lan: lan || null, vpn: vpn || null, fail: !!fail };
  }

  function normalizeDomains(data) {
    const list = asList(data).map((item) => {
      if (typeof item === "string") return item;
      return pick(item, ["host", "domain", "name"], "");
    }).filter(Boolean);
    return Array.from(new Set(list));
  }

  function normalizeLog(data) {
    return asList(data).map((item, idx) => {
      if (typeof item === "string") {
        return { id: String(idx), ts: null, message: item, level: "info" };
      }
      return {
        id: String(pick(item, ["id", "ts"], idx)),
        ts: pick(item, ["ts", "time", "at"], null),
        message: pick(item, ["message", "msg", "text", "line"], JSON.stringify(item)),
        level: pick(item, ["level", "type"], "info"),
      };
    });
  }

  function normalizePlan(data) {
    if (!data) return [];
    const raw =
      data.routes ||
      (data.plan && data.plan.routes) ||
      (Array.isArray(data.plan) ? data.plan : null) ||
      data.preview ||
      data.commands ||
      data.lines ||
      (Array.isArray(data) ? data : []);
    if (!Array.isArray(raw)) return [];
    return raw.map((row) => {
      if (typeof row === "string") {
        return { dest: row, via: "", iface: "", kind: "" };
      }
      return {
        dest: pick(row, ["dest", "destination", "prefix", "cidr", "dst", "host"], ""),
        via: pick(row, ["via", "gateway", "gw"], ""),
        iface: pick(row, ["iface", "interface", "device", "dev"], ""),
        kind: pick(row, ["kind", "type", "action"], ""),
      };
    });
  }

  function viaLabel(via) {
    if (via === "lan") return t("viaLan");
    if (via === "vpn") return t("viaVpn");
    if (via === "other") return t("viaOther");
    return t("viaUnknown");
  }

  function viaClass(via) {
    if (via === "lan") return "via via-lan";
    if (via === "vpn") return "via via-vpn";
    return "via";
  }

  function kindLabel(kind) {
    if (kind === "split") return t("kindSplit");
    if (kind === "lan-protect") return t("kindLan");
    if (kind === "vpn-keep") return t("kindVpnKeep");
    if (kind === "domain") return t("kindDomain");
    if (kind === "allow-vpn") return t("kindAllow");
    return kind || t("na");
  }

  function routeDest(row) {
    if (row.cidr) return row.cidr;
    if (row.dest && row.prefix != null) return `${row.dest}/${row.prefix}`;
    return row.dest || "";
  }

  function trafficSite(row) {
    return (row && row.host) || (row && row.ip) || "";
  }

  function trafficApp(row) {
    const list = (row && row.processes) || (row && row.process ? [row.process] : []);
    return list.filter(Boolean).join(", ");
  }

  function trafficHostIsName(row) {
    const host = String((row && row.host) || "");
    const ip = String((row && row.ip) || "");
    if (!host) return false;
    if (ip && host === ip) return false;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return false;
    return true;
  }

  function formatClock(ts) {
    if (ts == null || ts === "") return "";
    const d = typeof ts === "number" ? new Date(ts < 1e12 ? ts * 1000 : ts) : new Date(ts);
    if (Number.isNaN(d.getTime())) return String(ts);
    try {
      return d.toLocaleTimeString(state.locale === "en" ? "en-GB" : "th-TH", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
    } catch (_err) {
      return d.toISOString().slice(11, 19);
    }
  }

  function clockDatetimeAttr(ts) {
    if (ts == null || ts === "") return "";
    const d = typeof ts === "number" ? new Date(ts < 1e12 ? ts * 1000 : ts) : new Date(ts);
    if (Number.isNaN(d.getTime())) return "";
    return ` datetime="${esc(d.toISOString())}"`;
  }

  function trafficViaMod(via) {
    if (via === "lan") return "is-lan";
    if (via === "vpn") return "is-vpn";
    return "is-other";
  }

  function trafficMetaHtml(row) {
    const bits = [];
    const app = trafficApp(row);
    if (app) {
      bits.push(`<span><span class="sr-only">${th("trafficColApp")} </span>${esc(app)}</span>`);
    }
    if (row && row.iface) {
      bits.push(`<span><span class="sr-only">${th("trafficColNet")} </span>${esc(row.iface)}</span>`);
    }
    if (trafficHostIsName(row) && row.ip) {
      bits.push(`<span><span class="sr-only">${th("trafficColIp")} </span><code>${esc(row.ip)}</code></span>`);
    }
    if (!bits.length) return "";
    const sep = `<span class="traffic-sep" aria-hidden="true">·</span>`;
    return `<div class="traffic-meta">${bits.join(sep)}</div>`;
  }

  function trafficItemHtml(row, opts) {
    const named = trafficHostIsName(row);
    const primary = trafficSite(row) || t("na");
    const withTime = !!(opts && opts.withTime);
    const time = withTime
      ? `<time class="traffic-time"${clockDatetimeAttr(row.ts)}>${esc(formatClock(row.ts))}</time>`
      : "";
    return `<li class="traffic-item ${trafficViaMod(row.via)}">
      ${time}
      <div class="traffic-main">
        <div class="traffic-host${named ? "" : " is-addr"}">${esc(primary)}</div>
        ${trafficMetaHtml(row)}
      </div>
      <span class="${viaClass(row.via)}">${esc(viaLabel(row.via))}</span>
    </li>`;
  }

  function humanMode(mode) {
    return mode === "domains" ? t("modeAdvancedTitle") : t("modeDefaultTitle");
  }

  function osLabel(os) {
    const k = String(os || "").toLowerCase();
    if (k.includes("darwin") || k === "macos" || k === "mac") return t("osMac");
    if (k.includes("win")) return t("osWin");
    if (k.includes("linux")) return t("osLinux");
    return os || t("unknown");
  }

  function isValidHost(raw) {
    const h = String(raw || "").trim().toLowerCase();
    if (!h) return false;
    if (/[;|&$\n\r]/.test(h) || h.startsWith("-")) return false;
    if (/^https?:\/\//i.test(h) || h.includes("/") || h.includes(" ")) return false;
    if (h === "localhost" || /^127\./.test(h) || /^169\.254\./.test(h)) return false;
    if (h === "metadata.google.internal" || h === "169.254.169.254") return false;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h)) return true;
    return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(h);
  }

  function canConfirmModal() {
    const modal = state.ui.modal;
    if (!modal) return false;
    const typed = String(modal.typed || "").trim().toLowerCase();
    const host = String(modal.host || "").trim().toLowerCase();
    return modal.checked === true || (host && typed === host);
  }

  function captureFocus() {
    const el = document.activeElement;
    if (!el || !app.contains(el)) return null;
    return {
      id: el.id || null,
      action: el.getAttribute("data-action"),
      host: el.getAttribute("data-host"),
      start: typeof el.selectionStart === "number" ? el.selectionStart : null,
      end: typeof el.selectionEnd === "number" ? el.selectionEnd : null,
    };
  }

  function restoreFocus(snap, poll) {
    if (!snap) {
      if (!poll && state.ui.modal && !state.ui.openedModal) {
        const cancel = document.getElementById("modal-cancel");
        if (cancel) cancel.focus();
        state.ui.openedModal = true;
      }
      return;
    }
    let el = snap.id ? document.getElementById(snap.id) : null;
    if (!el && snap.action) {
      const sel = snap.host
        ? `[data-action="${snap.action}"][data-host="${CSS.escape(snap.host)}"]`
        : `[data-action="${snap.action}"]`;
      el = app.querySelector(sel);
    }
    if (el && typeof el.focus === "function") {
      el.focus({ preventScroll: true });
      if (snap.start != null && typeof el.setSelectionRange === "function") {
        try {
          el.setSelectionRange(snap.start, snap.end);
        } catch (_err) {
          /* ignore */
        }
      }
    }
  }

  function setNotice(type, text) {
    state.ui.notice = text ? { type, text } : null;
  }

  function setError(text) {
    state.ui.error = text || null;
  }

  function render(opts) {
    const poll = !!(opts && opts.poll);
    state.ui.pollRender = poll;
    document.documentElement.lang = state.locale === "en" ? "en" : "th";
    document.title = t("docTitle");

    const st = state.status;
    const ips = state.ips;
    const mutOff = mutateDisabled();
    const mode = state.selectedMode === "domains" ? "domains" : "inverse";
    const domainsEmpty = state.domains.length === 0;
    const canStart = !(mutOff || (mode === "domains" && domainsEmpty));
    const dryDisabled = busy();
    const appliedMode = st ? st.mode : null;

    const dryRows = state.ui.dryRun || [];
    const modal = state.ui.modal;
    const tryResult = state.ui.tryResult;
    const ipLanText = !ips
      ? t("ipPending")
      : ips.lan
        ? ips.lan
        : ips.fail
          ? t("ipFail")
          : t("ipPending");
    const ipVpnText = !ips
      ? t("ipPending")
      : ips.vpn
        ? ips.vpn
        : ips.fail
          ? t("ipFail")
          : t("ipPending");

    const html = `
      <a class="skip-link" href="#main">${th("skip")}</a>
      <div class="wrap">
        <header class="topbar">
          <div class="brand">
            <div class="mark" aria-hidden="true"></div>
            <div>
              <h1>${th("brand")}</h1>
              <p class="tagline">${th("tagline")}</p>
            </div>
          </div>
          <div class="lang-switch" role="group" aria-label="${th("langGroup")}">
            <button type="button" data-action="locale" data-locale="th" aria-pressed="${state.locale === "th" ? "true" : "false"}">${th("langTh")}</button>
            <button type="button" data-action="locale" data-locale="en" aria-pressed="${state.locale === "en" ? "true" : "false"}">${th("langEn")}</button>
          </div>
        </header>

        <div class="banner banner-persist">
          <h2>${th("persistTitle")}</h2>
          <p>${th("persistBody")}</p>
        </div>

        ${st && st.hijacked ? `
          <div class="banner banner-hijack" role="alert">
            <h2>${th("hijackTitle")}</h2>
            <p>${esc(st.repairActive ? t("hijackRepairing") : t("hijackBody"))}</p>
          </div>` : ""}

        ${st && st.hasAdmin === false ? `
          <div class="banner ${st.canElevate ? "banner-priv-info" : "banner-priv"}" role="${st.canElevate ? "status" : "alert"}">
            <h2>${th("privTitle")}</h2>
            <p>${th("privBody")}</p>
            ${st.canElevate ? "" : `<p class="hint">${th("privLocked")}</p>`}
          </div>` : ""}

        <main id="main">
          <section class="card" aria-labelledby="status-title">
            <h2 id="status-title">${th("statusTitle")}</h2>
            ${st ? "" : `<p class="hint">${th("offline")}</p>`}
            <dl class="status-grid">
              <div class="stat"><dt>${th("os")}</dt><dd>${esc(st ? osLabel(st.os) : t("na"))}</dd></div>
              <div class="stat"><dt>${th("lanIface")}</dt><dd>${esc(st && st.lanIface ? st.lanIface : t("na"))}</dd></div>
              <div class="stat"><dt>${th("lanGw")}</dt><dd>${esc(st && st.lanGw ? st.lanGw : t("na"))}</dd></div>
              <div class="stat"><dt>${th("vpnIface")}</dt><dd>${esc(st && st.vpnIface ? st.vpnIface : t("na"))}</dd></div>
              <div class="stat"><dt>${th("currentMode")}</dt><dd>${esc(st && st.applied ? humanMode(appliedMode) : t("routesOff"))}</dd></div>
              <div class="stat"><dt>${th("routesState")}</dt><dd><span class="pill ${st && st.applied ? "pill-on" : "pill-off"}">${esc(st && st.applied ? t("routesOn") : t("routesOff"))}</span></dd></div>
              <div class="stat"><dt>${th("dnsLabel")}</dt><dd><span class="${dnsPillClass(st && st.dns)}">${esc(dnsLabel(st && st.dns))}</span></dd></div>
            </dl>
            <div class="ip-pair">
              <div class="ip-box lan">
                <span class="k">${th("ipLan")}</span>
                <span class="v">${esc(ipLanText)}</span>
              </div>
              <div class="ip-box vpn">
                <span class="k">${th("ipVpn")}</span>
                <span class="v">${esc(ipVpnText)}</span>
              </div>
            </div>
          </section>

          <section class="card traffic-card" aria-labelledby="traffic-title">
            <h2 id="traffic-title" class="traffic-head">
              ${th("trafficTitle")}
              ${state.traffic.live.length ? `<span class="traffic-count">${state.traffic.live.length}</span>` : ""}
            </h2>
            <p class="hint">${th("trafficHint")}</p>
            ${!state.traffic.live.length ? `
              <div class="traffic-empty" role="status">
                <span class="mark" aria-hidden="true"></span>
                <p>${th("trafficEmpty")}</p>
              </div>` : `
              <ul class="traffic-live" aria-labelledby="traffic-title">
                ${state.traffic.live.map((row) => trafficItemHtml(row)).join("")}
              </ul>`}
            <h3 id="traffic-recent-title">${th("trafficRecent")}</h3>
            ${!state.traffic.recent.length ? `
              <p class="traffic-empty-sm">${th("trafficRecentEmpty")}</p>` : `
              <ul class="traffic-recent" aria-labelledby="traffic-recent-title" aria-live="polite">
                ${state.traffic.recent.map((row) => trafficItemHtml(row, { withTime: true })).join("")}
              </ul>`}
          </section>

          <section class="card" aria-labelledby="mode-title">
            <h2 id="mode-title">${th("modeTitle")}</h2>
            <div class="mode-stack">
              <button type="button" class="mode-card" data-action="mode-inverse" aria-pressed="${mode === "inverse" ? "true" : "false"}">
                <span class="eyebrow">${th("modeDefaultEyebrow")}${mode === "inverse" ? " · " + t("modeSelected") : ""}</span>
                <strong>${th("modeDefaultTitle")}</strong>
                <span class="desc">${th("modeDefaultBody")}</span>
              </button>
              <button type="button" class="mode-card advanced" data-action="mode-domains" aria-pressed="${mode === "domains" ? "true" : "false"}">
                <span class="eyebrow">${th("modeAdvancedEyebrow")}${mode === "domains" ? " · " + t("modeSelected") : ""}</span>
                <strong>${th("modeAdvancedTitle")}</strong>
                <span class="desc">${th("modeAdvancedBody")}</span>
              </button>
            </div>
            ${mode === "domains" && domainsEmpty ? `<p class="hint" style="margin-top:10px">${th("modeEmptyHint")}</p>` : ""}
            <div class="actions">
              <button type="button" class="btn btn-primary" data-action="on" ${canStart ? "" : "disabled"}>${state.ui.busy === "on" ? th("starting") : th("start")}</button>
              <button type="button" class="btn btn-stop" data-action="off" ${mutOff ? "disabled" : ""}>${state.ui.busy === "off" ? th("stopping") : th("stop")}</button>
              <button type="button" class="btn" data-action="dry-run" ${dryDisabled ? "disabled" : ""}>${state.ui.busy === "dry" ? th("dryRunning") : th("dryRun")}</button>
            </div>
            ${state.ui.notice ? `<div class="notice ${esc(state.ui.notice.type)}" role="status">${esc(state.ui.notice.text)}</div>` : ""}
            ${state.ui.error ? `<div class="notice err" role="alert">${esc(state.ui.error)}</div>` : ""}
            ${state.ui.dryRun ? `
              <h3 style="margin:16px 0 0">${th("dryRunTitle")}</h3>
              ${dryRows.length === 0 ? `<p class="empty">${th("dryRunEmpty")}</p>` : `
                <div class="table-wrap">
                  <table>
                    <thead><tr>
                      <th>${th("dryRunColDest")}</th>
                      <th>${th("dryRunColVia")}</th>
                      <th>${th("dryRunColIface")}</th>
                      <th>${th("dryRunColKind")}</th>
                    </tr></thead>
                    <tbody>
                      ${dryRows.map((r) => `<tr><td>${esc(r.dest)}</td><td>${esc(r.via)}</td><td>${esc(r.iface)}</td><td>${esc(r.kind)}</td></tr>`).join("")}
                    </tbody>
                  </table>
                </div>`}
            ` : ""}
          </section>

          ${mode === "domains" ? `
          <section class="card" aria-labelledby="domains-title">
            <h2 id="domains-title">${th("domainsTitle")}</h2>
            <p class="hint">${th("domainsHint")}</p>
            <form class="row" data-action="domain-add-form">
              <label class="field sr-only" for="domain-host">${th("domainsTitle")}</label>
              <input id="domain-host" type="text" autocomplete="off" spellcheck="false" placeholder="${th("domainPlaceholder")}" value="${esc(state.ui.domainHost)}" ${mutOff ? "disabled" : ""}>
              <button type="submit" class="btn" ${mutOff ? "disabled" : ""}>${state.ui.busy === "domain" ? th("adding") : th("domainAdd")}</button>
            </form>
            ${state.domains.length === 0 ? `<p class="empty" style="margin-top:10px">${th("domainsEmpty")}</p>` : `
              <ul class="list">
                ${state.domains.map((host) => `
                  <li>
                    <span>${esc(host)}</span>
                    <button type="button" class="linkish" data-action="domain-remove" data-host="${esc(host)}" ${mutOff ? "disabled" : ""}>${th("domainRemove")}</button>
                  </li>`).join("")}
              </ul>`}
          </section>` : ""}

          ${mode === "inverse" ? `
          <section class="card" aria-labelledby="try-title">
            <h2 id="try-title">${th("tryTitle")}</h2>
            <p class="hint">${th("tryBody")}</p>
            ${st && !st.applied ? `<p class="hint">${th("tryNeedOn")}</p>` : ""}
            <form class="row" data-action="try-form">
              <label class="field sr-only" for="try-host">${th("tryTitle")}</label>
              <input id="try-host" type="text" autocomplete="off" spellcheck="false" placeholder="${th("tryPlaceholder")}" value="${esc(state.ui.tryHost)}" ${busy() ? "disabled" : ""}>
              <button type="submit" class="btn btn-primary" ${busy() ? "disabled" : ""}>${state.ui.busy === "try" ? th("trying") : th("tryAction")}</button>
            </form>
            ${tryResult && tryResult.ok ? `<div class="notice ok" role="status">${th("tryOk")}</div>` : ""}
            ${tryResult && tryResult.ok === false && !modal ? `<div class="notice err">${esc(t("tryFail", { host: tryResult.host }))}</div>` : ""}
            <h3 style="margin:16px 0 0">${th("allowedTitle")}</h3>
            ${state.allowed.length === 0 ? `<p class="empty">${th("allowedEmpty")}</p>` : `
              <ul class="list">
                ${state.allowed.map((host) => `
                  <li>
                    <span>${esc(host)}</span>
                    <button type="button" class="linkish" data-action="deny" data-host="${esc(host)}" ${mutOff ? "disabled" : ""}>${th("deny")}</button>
                  </li>`).join("")}
              </ul>`}
          </section>` : ""}

          <section class="card" aria-labelledby="routes-title">
            <h2 id="routes-title">${th("routesTitle")}</h2>
            <p class="hint">${th("routesHint")}</p>
            ${state.ownedRoutes.length === 0 ? `<p class="empty">${th("routesEmpty")}</p>` : `
              <div class="table-wrap">
                <table>
                  <thead><tr>
                    <th>${th("routesColDest")}</th>
                    <th>${th("routesColVia")}</th>
                    <th>${th("routesColIface")}</th>
                    <th>${th("routesColGw")}</th>
                    <th>${th("routesColKind")}</th>
                    <th>${th("routesColDomain")}</th>
                  </tr></thead>
                  <tbody>
                    ${state.ownedRoutes.map((r) => `
                      <tr>
                        <td><code>${esc(routeDest(r))}</code></td>
                        <td><span class="${viaClass(r.via)}">${esc(viaLabel(r.via))}</span></td>
                        <td>${esc(r.iface || t("na"))}</td>
                        <td>${esc(r.gw || t("na"))}</td>
                        <td>${esc(kindLabel(r.kind))}</td>
                        <td>${esc(r.domain || t("na"))}</td>
                      </tr>`).join("")}
                  </tbody>
                </table>
              </div>`}
            <h3 style="margin:16px 0 0">${th("lookupTitle")}</h3>
            <p class="hint">${th("lookupHint")}</p>
            <form class="row" data-action="lookup-form">
              <label class="field sr-only" for="lookup-host">${th("lookupTitle")}</label>
              <input id="lookup-host" type="text" autocomplete="off" spellcheck="false" placeholder="${th("lookupPlaceholder")}" value="${esc(state.ui.lookupHost)}">
              <button type="submit" class="btn btn-primary" ${busy() ? "disabled" : ""}>${state.ui.busy === "lookup" ? th("lookingUp") : th("lookupAction")}</button>
            </form>
            ${!state.ui.lookupResult ? `<p class="empty">${th("lookupEmpty")}</p>` : `
              <div class="table-wrap" style="margin-top:10px">
                <table>
                  <thead><tr>
                    <th>IP</th>
                    <th>${th("routesColVia")}</th>
                    <th>${th("routesColIface")}</th>
                    <th>${th("routesColGw")}</th>
                    <th>${th("routesColDest")}</th>
                  </tr></thead>
                  <tbody>
                    ${state.ui.lookupResult.hits.map((h) => `
                      <tr>
                        <td><code>${esc(h.ip)}</code></td>
                        <td><span class="${viaClass(h.via)}">${esc(viaLabel(h.via))}</span></td>
                        <td>${esc(h.iface || t("na"))}</td>
                        <td>${esc(h.gw || t("na"))}</td>
                        <td><code>${esc(h.cidr || t("na"))}</code></td>
                      </tr>`).join("")}
                  </tbody>
                </table>
              </div>`}
          </section>

          <section class="card" aria-labelledby="watch-title">
            <h2 id="watch-title">${th("watchTitle")}</h2>
            <p class="hint">${th("watchBody")}</p>
            <div class="banner banner-watch" style="margin-top:12px">
              <p>${th("watchCost")}</p>
            </div>
            <p class="hint" style="margin-top:12px">${esc(st && st.repairActive ? t("repairActive") : t("repairIdle"))}</p>
            <div class="switch-row">
              <span>${esc(state.watchEnabled ? t("watchOn") : t("watchOff"))}</span>
              <button type="button" class="switch" role="switch" data-action="watch" aria-checked="${state.watchEnabled ? "true" : "false"}" ${mutOff ? "disabled" : ""} aria-label="${th("watchTitle")}"></button>
            </div>
          </section>

          <details class="card log-panel" ${state.logOpen ? "open" : ""} data-log-panel>
            <summary>${th("logTitle")}</summary>
            <div class="log" aria-live="polite">
              ${state.log.length === 0
                ? `<div>${th("logEmpty")}</div>`
                : state.log.map((row) => `<div><time>${esc(formatTime(row.ts))}</time>${esc(row.message)}</div>`).join("")}
            </div>
          </details>
        </main>
      </div>
      ${modal ? `
        <div class="modal-root">
          <div class="modal-backdrop" data-action="modal-cancel"></div>
          <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="modal-desc">
            <h2 id="modal-title">${th("modalTitle")}</h2>
            <p id="modal-desc">${esc(t("modalBody", { host: modal.host }))}</p>
            <label class="field" for="confirm-host">${th("modalType")}</label>
            <input id="confirm-host" type="text" autocomplete="off" spellcheck="false" placeholder="${esc(t("modalTypePh", { host: modal.host }))}" value="${esc(modal.typed || "")}">
            <label class="check">
              <input id="confirm-check" type="checkbox" data-action="modal-check" ${modal.checked ? "checked" : ""}>
              <span>${th("modalCheck")}</span>
            </label>
            <div class="modal-actions">
              <button type="button" class="btn btn-primary" id="modal-cancel" data-action="modal-cancel">${th("modalCancel")}</button>
              <button type="button" class="btn btn-danger" id="modal-confirm" data-action="modal-allow" ${canConfirmModal() && !busy() ? "" : "disabled"}>${state.ui.busy === "allow" ? th("modalBusy") : th("modalConfirm")}</button>
            </div>
          </div>
        </div>` : ""}
    `;

    if (poll && html === lastView) return;
    const snap = captureFocus();
    app.innerHTML = html;
    lastView = html;
    restoreFocus(snap, poll);
    if (modal) state.ui.openedModal = true;
    else state.ui.openedModal = false;
  }

  function formatTime(ts) {
    if (ts == null || ts === "") return "";
    const d = typeof ts === "number" ? new Date(ts < 1e12 ? ts * 1000 : ts) : new Date(ts);
    if (Number.isNaN(d.getTime())) return String(ts);
    try {
      return d.toLocaleString(state.locale === "en" ? "en" : "th");
    } catch (_err) {
      return d.toISOString();
    }
  }

  async function refreshStatus(opts) {
    const poll = !!(opts && opts.poll);
    const res = await api("GET", "/api/status");
    if (!res.ok) {
      if (!poll) setError(res.network ? t("errorNetwork") : errorMessage(res, "errorGeneric"));
      render({ poll });
      return;
    }
    state.status = normalizeStatus(res.data);
    if (state.status && state.status.hasAdmin === false && !state.status.canElevate) {
      state.ui.noAdmin = true;
    } else if (state.status && (state.status.hasAdmin || state.status.canElevate)) {
      state.ui.noAdmin = false;
    }
    if (!state.modeTouched && state.status) {
      state.selectedMode = state.status.mode;
    }
    if (state.status) {
      state.watchEnabled = !!state.status.watchActive;
      if (state.status.allowed.length) state.allowed = state.status.allowed;
      if (Array.isArray(state.status.ownedRoutes)) state.ownedRoutes = state.status.ownedRoutes;
    }
    render({ poll });
  }

  async function refreshIps() {
    const res = await api("GET", "/api/ips");
    if (!res.ok) {
      state.ips = { lan: null, vpn: null, fail: true };
      render();
      return;
    }
    state.ips = normalizeIps(res.data);
    render();
  }

  async function refreshDomains() {
    const res = await api("GET", "/api/domains");
    if (res.ok) {
      state.domains = normalizeDomains(res.data);
      render();
      return;
    }
    if (state.config) {
      state.domains = normalizeDomains(state.config.domains);
      render();
    }
  }

  async function refreshLog() {
    const res = await api("GET", "/api/log");
    if (!res.ok) return;
    state.log = normalizeLog(res.data);
    render();
  }

  function normalizeTraffic(data) {
    const src = data && typeof data === "object" ? data : {};
    const live = Array.isArray(src.live) ? src.live : [];
    const recent = Array.isArray(src.recent) ? src.recent : [];
    return { live, recent };
  }

  async function refreshTraffic(opts) {
    const poll = !!(opts && opts.poll);
    const res = await api("GET", "/api/traffic");
    if (!res.ok) return;
    state.traffic = normalizeTraffic(res.data);
    render({ poll });
  }

  async function refreshConfig() {
    const res = await api("GET", "/api/config");
    if (!res.ok) return;
    const cfg = res.data && typeof res.data === "object" ? res.data : {};
    state.config = cfg;
    const cfgLocale = pick(cfg, ["locale", "lang"], null);
    const stored = readStoredLocale();
    if (!stored && (cfgLocale === "th" || cfgLocale === "en") && !state.localeTouched) {
      state.locale = cfgLocale;
    }
    if (stored && cfgLocale && stored !== cfgLocale) {
      api("PUT", "/api/config", { locale: stored });
    }
    if (!state.modeTouched) {
      const m = pick(cfg, ["mode"], null);
      if (m === "domains" || m === "inverse") state.selectedMode = m;
    }
    const domains = normalizeDomains(cfg.domains);
    if (domains.length && state.domains.length === 0) state.domains = domains;
    const allowed = asList(cfg.allowVpnHosts || cfg.allowedHosts || cfg.allowed);
    if (allowed.length) state.allowed = normalizeDomains(allowed);
    render();
  }

  async function persistLocale(locale) {
    state.locale = locale;
    state.localeTouched = true;
    writeStoredLocale(locale);
    render();
    const res = await api("PUT", "/api/config", { locale });
    if (!res.ok && !res.network) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      return;
    }
    await refreshStatus();
  }

  async function applyOn(dryRun) {
    const mode = state.selectedMode === "domains" ? "domains" : "inverse";
    if (!dryRun && mode === "domains" && state.domains.length === 0) {
      setError(t("errorEmptyDomains"));
      render();
      return;
    }
    if (!dryRun && locked()) return;
    state.ui.busy = dryRun ? "dry" : "on";
    setError(null);
    render();
    const res = await api("POST", "/api/on", { mode, dryRun: !!dryRun });
    state.ui.busy = null;
    if (!res.ok) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      await refreshStatus();
      return;
    }
    if (dryRun) {
      state.ui.dryRun = normalizePlan(res.data);
      setNotice("info", t("dryRunTitle"));
      render();
      return;
    }
    state.ui.dryRun = null;
    setNotice("ok", t("noticeOn"));
    await Promise.all([refreshStatus(), refreshIps(), refreshLog()]);
    render();
  }

  async function applyOff() {
    if (locked()) return;
    state.ui.busy = "off";
    setError(null);
    render();
    const res = await api("POST", "/api/off");
    state.ui.busy = null;
    if (!res.ok) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      await refreshStatus();
      return;
    }
    setNotice("ok", t("noticeOff"));
    await Promise.all([refreshStatus(), refreshIps(), refreshLog()]);
    render();
  }

  async function addDomain() {
    const host = state.ui.domainHost.trim();
    if (!isValidHost(host)) {
      setError(t("errorHost"));
      render();
      return;
    }
    if (locked()) return;
    state.ui.busy = "domain";
    setError(null);
    render();
    const res = await api("POST", "/api/domains", { host });
    state.ui.busy = null;
    if (!res.ok) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      return;
    }
    state.ui.domainHost = "";
    await Promise.all([refreshDomains(), refreshLog(), refreshConfig()]);
    render();
  }

  async function removeDomain(host) {
    if (locked()) return;
    state.ui.busy = "domain";
    setError(null);
    render();
    const res = await api("DELETE", "/api/domains", { host });
    state.ui.busy = null;
    if (!res.ok) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      return;
    }
    await Promise.all([refreshDomains(), refreshLog(), refreshConfig()]);
    render();
  }

  function probeReached(data) {
    if (!data || typeof data !== "object") return false;
    if (data.reachable === true || data.reached === true || data.success === true || data.alive === true) {
      return true;
    }
    if (data.reachable === false || data.reached === false || data.ok === false) return false;
    if (data.via === "lan" || data.result === "ok") return true;
    return false;
  }

  async function tryHost() {
    const host = state.ui.tryHost.trim();
    if (!isValidHost(host)) {
      setError(t("errorHost"));
      render();
      return;
    }
    state.ui.busy = "try";
    state.ui.tryResult = null;
    setError(null);
    render();
    const res = await api("POST", "/api/try", { host });
    state.ui.busy = null;
    if (!res.ok) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      await refreshLog();
      return;
    }
    const reached = probeReached(res.data);
    if (reached) {
      state.ui.tryResult = { ok: true, host };
      render();
      await refreshLog();
      return;
    }
    state.ui.tryResult = { ok: false, host };
    state.ui.modal = { host, typed: "", checked: false };
    state.ui.openedModal = false;
    render();
    await refreshLog();
  }

  async function lookupHost() {
    const host = state.ui.lookupHost.trim();
    if (!isValidHost(host)) {
      setError(t("errorHost"));
      render();
      return;
    }
    state.ui.busy = "lookup";
    setError(null);
    render();
    const res = await api("POST", "/api/lookup", { host });
    state.ui.busy = null;
    if (!res.ok) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      return;
    }
    const data = res.data || {};
    state.ui.lookupResult = {
      host: data.host || host,
      hits: Array.isArray(data.hits) ? data.hits : [],
    };
    state.logOpen = true;
    await refreshLog();
    render();
  }

  function closeModal() {
    state.ui.modal = null;
    render();
  }

  async function confirmAllow() {
    if (!state.ui.modal || !canConfirmModal() || locked()) return;
    const host = state.ui.modal.host;
    state.ui.busy = "allow";
    render();
    const res = await api("POST", "/api/allow", { host });
    state.ui.busy = null;
    if (!res.ok) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      return;
    }
    state.ui.modal = null;
    state.ui.tryResult = null;
    if (state.allowed.indexOf(host) === -1) state.allowed = state.allowed.concat([host]);
    await Promise.all([refreshStatus(), refreshLog(), refreshConfig()]);
    render();
  }

  async function denyHost(host) {
    if (locked()) return;
    state.ui.busy = "deny";
    render();
    const res = await api("POST", "/api/deny", { host });
    state.ui.busy = null;
    if (!res.ok) {
      setError(errorMessage(res, "errorGeneric"));
      render();
      return;
    }
    state.allowed = state.allowed.filter((h) => h !== host);
    await Promise.all([refreshStatus(), refreshLog(), refreshConfig()]);
    render();
  }

  async function setWatch(enabled) {
    const prev = state.watchEnabled;
    if (locked()) {
      state.watchEnabled = prev;
      render();
      return;
    }
    state.ui.busy = "watch";
    setError(null);
    render();
    const res = await api("POST", "/api/watch", { enabled: !!enabled });
    state.ui.busy = null;
    if (!res.ok) {
      state.watchEnabled = prev;
      setError(errorMessage(res, "errorGeneric"));
      render();
      return;
    }
    state.watchEnabled = !!enabled;
    setNotice("info", enabled ? t("noticeWatchOn") : t("noticeWatchOff"));
    await Promise.all([refreshStatus(), refreshLog()]);
    render();
  }

  function onClick(event) {
    const actionEl = event.target.closest("[data-action]");
    if (!actionEl || !app.contains(actionEl)) return;
    const action = actionEl.getAttribute("data-action");
    if (action === "modal-cancel") {
      event.preventDefault();
      closeModal();
      return;
    }
    if (action === "modal-allow") {
      event.preventDefault();
      confirmAllow();
      return;
    }
    if (action === "modal-check") {
      if (state.ui.modal) {
        state.ui.modal.checked = !!actionEl.checked;
        const btn = document.getElementById("modal-confirm");
        if (btn) btn.disabled = !canConfirmModal() || busy();
      }
      return;
    }
    if (action === "locale") {
      const locale = actionEl.getAttribute("data-locale") === "en" ? "en" : "th";
      persistLocale(locale);
      return;
    }
    if (action === "mode-inverse") {
      state.selectedMode = "inverse";
      state.modeTouched = true;
      render();
      return;
    }
    if (action === "mode-domains") {
      state.selectedMode = "domains";
      state.modeTouched = true;
      render();
      return;
    }
    if (action === "on") {
      event.preventDefault();
      applyOn(false);
      return;
    }
    if (action === "off") {
      event.preventDefault();
      applyOff();
      return;
    }
    if (action === "dry-run") {
      event.preventDefault();
      applyOn(true);
      return;
    }
    if (action === "domain-remove") {
      event.preventDefault();
      removeDomain(actionEl.getAttribute("data-host") || "");
      return;
    }
    if (action === "deny") {
      event.preventDefault();
      denyHost(actionEl.getAttribute("data-host") || "");
      return;
    }
    if (action === "watch") {
      event.preventDefault();
      setWatch(!state.watchEnabled);
    }
  }

  function onSubmit(event) {
    const form = event.target.closest("form");
    if (!form) return;
    event.preventDefault();
    const action = form.getAttribute("data-action");
    if (action === "domain-add-form") addDomain();
    if (action === "try-form") tryHost();
    if (action === "lookup-form") lookupHost();
  }

  function onInput(event) {
    const el = event.target;
    if (el.id === "try-host") state.ui.tryHost = el.value;
    if (el.id === "lookup-host") state.ui.lookupHost = el.value;
    if (el.id === "domain-host") state.ui.domainHost = el.value;
    if (el.id === "confirm-host" && state.ui.modal) {
      state.ui.modal.typed = el.value;
      const btn = document.getElementById("modal-confirm");
      if (btn) btn.disabled = !canConfirmModal() || busy();
    }
  }

  function onToggle(event) {
    const panel = event.target.closest("[data-log-panel]");
    if (panel) state.logOpen = panel.open;
  }

  function onKey(event) {
    if (event.key === "Escape" && state.ui.modal) {
      event.preventDefault();
      closeModal();
      return;
    }
    if (event.key === "Enter" && event.target && event.target.id === "confirm-host") {
      event.preventDefault();
      if (canConfirmModal()) confirmAllow();
    }
  }

  function schedulePoll() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => {
      if (document.visibilityState === "visible") {
        refreshStatus({ poll: true });
        refreshTraffic({ poll: true });
      }
    }, POLL_MS);
  }

  async function init() {
    const stored = readStoredLocale();
    state.locale = stored || "th";
    render();
    bind();
    await Promise.all([
      refreshStatus(),
      refreshConfig(),
      refreshDomains(),
      refreshIps(),
      refreshLog(),
      refreshTraffic(),
    ]);
    schedulePoll();
  }

  function bind() {
    app.addEventListener("click", onClick);
    app.addEventListener("submit", onSubmit);
    app.addEventListener("input", onInput);
    app.addEventListener("change", (event) => {
      if (event.target && event.target.id === "confirm-check" && state.ui.modal) {
        state.ui.modal.checked = !!event.target.checked;
        const btn = document.getElementById("modal-confirm");
        if (btn) btn.disabled = !canConfirmModal() || busy();
      }
    });
    app.addEventListener("toggle", onToggle, true);
    document.addEventListener("keydown", onKey);
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") refreshStatus({ poll: true });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
