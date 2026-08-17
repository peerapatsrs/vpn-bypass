# Handoff Context Document: vpn-bypass & Cloudflare One Client Analysis

## 1. Goal & Context (เป้าหมายและบริบท)
สืบสวนและแก้ไขปัญหาที่ `vpn-bypass` ใช้งานได้กับ GlobalProtect แต่ยังใช้งานไม่ได้กับ **Cloudflare One Client (Cloudflare WARP / Zero Trust)** บน Windows พร้อมทั้งวิเคราะห์เชิงลึกและปรับปรุง Codebase

---

## 2. Key Findings & Technical Analysis (ข้อค้นพบทางเทคนิค)

### ความแตกต่างระหว่าง GlobalProtect vs Cloudflare One
1. **Network Layer:**
   - **GlobalProtect:** ทำงานใน Layer 3 (IP Routing Table) ผ่าน Virtual Adapter ทั่วไป เมื่อใส่เส้นทาง `/1` หรือ `/32` ชี้ไปที่ Home LAN Gateway ระบบจะส่งแพ็กเก็ตออกเน็ตบ้านได้ตามกลไก Longest Prefix Match (LPM)
   - **Cloudflare One (WARP):** ทำงานร่วมกับ **Windows Filtering Platform (WFP)** ในระดับ Windows Kernel ซึ่งจะ Hook Network Socket ของแอปพลิเคชัน (เช่น Chrome/Edge) ก่อนที่แพ็กเก็ตจะถูกส่งไปประมวลผลที่ Routing Table ทำให้การทำ Route-based Bypass บนเครื่องไม่สามารถหลบการดักจับได้
2. **DNS Level:**
   - Cloudflare WARP เซ็ต Local DoH Proxy `127.0.2.2:53` บน Windows และส่ง Interceptor IP ของ Block Page กลับมาเมื่อผู้ใช้เข้าเว็บที่ติดนโยบายองค์กร (เช่น Gaming/Entertainment)
3. **Gateway Policy (Zero Trust):**
   - Cloudflare มีการทำ TLS/SNI Inspection ที่ Gateway ดักจับ URL ปลายทางและ Redirect ไปยังหน้า Block Page ขององค์กร

---

## 3. Completed Tasks (สิ่งที่ทำเสร็จแล้ว)

1. **เพิ่มการตรวจจับ Cloudflare WARP:**
   - ปรับปรุง `src/platform/common.js`: เพิ่ม pattern `cloudflare`, `warp`, `cloudflared` ใน `isVpnIface()` และปรับ `inferTopology()` ให้คำนวณ `vpn.up = true` ได้แม่นยำแม้ไม่มี Default Route `0.0.0.0/0`
   - ปรับปรุง `src/platform/win32.js`: แมป Interface Name จาก `ipconfig` (`CloudflareWARP`) กับ `route print` (`Cloudflare WARP Interface Tunnel`) ได้อย่างถูกต้อง
2. **ป้องกันการ Re-pin Large Route Chunks:**
   - ปรับปรุง `src/core/plan.js`: ใน `skipVpnKeepCidr()` ข้าม Subnet ที่กว้าง (`prefix < 8`) เพื่อไม่ให้ดึง full tunnel chunk partitions ของ WARP มา re-pin
3. **ปรับปรุง DNS Probe:**
   - ปรับปรุง `src/core/probe.js`: เพิ่ม fallback public DNS และ timeout ที่เหมาะสมใน `createLanResolve4()`
4. **เพิ่ม Unit Test & Validation:**
   - เพิ่ม test case ใน `test/platform.test.js` (รัน `npm test` ผ่านครบ 78/78 tests)

---

## 4. Relevant Files (ไฟล์ที่เกี่ยวข้อง)

- `src/platform/common.js`: ตรวจจับ Adapter และคำนวณ Topology
- `src/platform/win32.js`: การแมป Route และ Adapter บน Windows
- `src/core/plan.js`: การวางแผน Routing actions (Inverse / Domains mode)
- `src/core/probe.js`: DNS Resolution และ Connectivity Probe
- `test/platform.test.js`: Test suites สำหรับ Platform adapters
- `README.md`: เอกสารโปรเจกต์

---

## 5. Suggested Skills (สกิลที่แนะนำสำหรับเซสชันถัดไป)

- `code-review` — ใช้สำหรับตรวจเช็คความเรียบร้อยของ Diff และ Code Changes
- `my-commit-message` — ใช้สำหรับสร้าง Commit Message ตามมาตรฐาน Conventional Commits (ภาษาไทย)

---

## 6. Next Steps (ขั้นตอนที่แนะนำต่อไป)

1. อัปเดต `README.md` ในหัวข้อ Supported VPNs / Warnings เพื่อระบุข้อจำกัดเกี่ยวกับ WFP-based ZTNA clients (เช่น Cloudflare Zero Trust)
2. Commit การเปลี่ยนแปลงโค้ดที่ผ่านการทดสอบแล้ว
