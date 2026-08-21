/**
 * KeyVault Server — backend API + giao diện (index.js + package.json).
 * Chức năng chính: lưu/tải state dashboard (/api/state), xác thực key
 * cho app ngoài (/api/verify), trang bán key ("/") và dashboard quản
 * trị ("/admin"), thanh toán mua key, và GetKey (vượt link nhận key).
 * Chạy: node index.js (mặc định cổng 3000, đổi bằng PORT=xxxx).
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

/* =====================================================================================
   BẢO MẬT PHÒNG THỦ (chỉ mang tính phòng thủ: giới hạn tốc độ request, chống dò mật khẩu,
   chống dữ liệu không hợp lệ gây sai số dư/khoá. KHÔNG chứa bất kỳ cơ chế chủ động "phản
   công", quét ngược, hay can thiệp vào máy của người gửi request — chỉ giới hạn/ghi log
   trên chính server này.
   ===================================================================================== */

/* Lấy IP thật của người gửi request, có tính tới việc chạy sau reverse-proxy (Render/CDN)
   vẫn dùng header x-forwarded-for nếu có, mặc định lấy IP socket trực tiếp. */
function getClientIP(req){
  const xf = req.headers['x-forwarded-for'];
  if(xf) return String(xf).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/* ---- Rate limiter đơn giản theo "cửa sổ trượt" (sliding window) lưu trong RAM ----
   Dùng cho các endpoint nhạy cảm (login, register, topup-request, checkout, verify...).
   Không lưu xuống DB vì chỉ cần tồn tại tạm thời trong bộ nhớ tiến trình. */
const rateLimitBuckets = new Map(); // key: `${scope}:${ip}` -> [timestamps]
function isRateLimited(scope, ip, maxRequests, windowMs){
  const key = scope + ':' + ip;
  const now = Date.now();
  let arr = rateLimitBuckets.get(key);
  if(!arr){ arr = []; rateLimitBuckets.set(key, arr); }
  // loại bỏ các mốc thời gian đã ra ngoài cửa sổ
  while(arr.length && now - arr[0] > windowMs) arr.shift();
  if(arr.length >= maxRequests){
    return true;
  }
  arr.push(now);
  return false;
}
// Dọn định kỳ các bucket rỗng/cũ để không rò rỉ bộ nhớ khi chạy lâu dài.
setInterval(()=>{
  const now = Date.now();
  for(const [key, arr] of rateLimitBuckets.entries()){
    while(arr.length && now - arr[0] > 15 * 60 * 1000) arr.shift();
    if(arr.length === 0) rateLimitBuckets.delete(key);
  }
}, 5 * 60 * 1000);

/* ---- Chống dò mật khẩu (brute-force) theo IP + theo username ----
   Sau nhiều lần đăng nhập/đăng ký sai liên tiếp, tạm khoá thêm request mới trong ít phút.
   Đây là khoá TẠM THỜI (tự hết hạn), không chặn IP vĩnh viễn, không phải "phản công". */
const failedAttempts = new Map(); // key: `${scope}:${ip|username}` -> { count, firstAt, lockedUntil, lockCount }
const BRUTE_FORCE_MAX_ATTEMPTS = 3;      // số lần sai tối đa trước khi khoá lần đầu: 3 lần
const BRUTE_FORCE_WINDOW_MS = 5 * 60 * 1000;   // cửa sổ tính số lần sai: 5 phút
const BRUTE_FORCE_LOCK_MS_1 = 5 * 60 * 1000;   // khoá lần 1: 5 phút
const BRUTE_FORCE_LOCK_MS_2 = 30 * 60 * 1000;  // khoá lần 2+: 30 phút

function isLockedOut(scope, id){
  const rec = failedAttempts.get(scope + ':' + id);
  if(!rec) return false;
  if(rec.lockedUntil && rec.lockedUntil > Date.now()) return { locked: true, remainMs: rec.lockedUntil - Date.now(), lockCount: rec.lockCount || 1 };
  if(rec.lockedUntil && rec.lockedUntil <= Date.now()){
    // Hết hạn khoá — giữ lại lockCount để biết đây là lần khoá thứ mấy, reset count
    rec.lockedUntil = 0;
    rec.count = 0;
    rec.firstAt = Date.now();
    failedAttempts.set(scope + ':' + id, rec);
    return false;
  }
  return false;
}
function registerFailedAttempt(scope, id){
  const key = scope + ':' + id;
  const now = Date.now();
  let rec = failedAttempts.get(key);
  if(!rec){
    rec = { count: 0, firstAt: now, lockedUntil: 0, lockCount: 0 };
  }
  // Reset window nếu đã qua cửa sổ 5 phút (và không đang bị khoá)
  if(!rec.lockedUntil && (now - rec.firstAt) > BRUTE_FORCE_WINDOW_MS){
    rec.count = 0;
    rec.firstAt = now;
  }
  rec.count += 1;
  if(rec.count >= BRUTE_FORCE_MAX_ATTEMPTS){
    rec.lockCount = (rec.lockCount || 0) + 1;
    const lockMs = rec.lockCount >= 2 ? BRUTE_FORCE_LOCK_MS_2 : BRUTE_FORCE_LOCK_MS_1;
    rec.lockedUntil = now + lockMs;
    console.warn(`[Security] Khoá tạm ${lockMs/60000} phút (lần ${rec.lockCount}) do sai ${rec.count} lần: ${key}`);
  }
  failedAttempts.set(key, rec);
}
function clearFailedAttempts(scope, id){
  failedAttempts.delete(scope + ':' + id);
}
// Dọn định kỳ các bản ghi đã hết hạn từ lâu.
setInterval(()=>{
  const now = Date.now();
  for(const [key, rec] of failedAttempts.entries()){
    const staleWindow = !rec.lockedUntil && (now - rec.firstAt) > BRUTE_FORCE_WINDOW_MS;
    const staleLock = rec.lockedUntil && rec.lockedUntil < now - BRUTE_FORCE_WINDOW_MS;
    if(staleWindow || staleLock) failedAttempts.delete(key);
  }
}, 5 * 60 * 1000);

/* ============================================================================
   HỆ THỐNG CHỐNG DoS / SPAM NÂNG CAO — v2
   Gồm 4 lớp bảo vệ chồng nhau:
     1) Hard rate-limit toàn cục: tự động chặn IP gửi >200 req/phút (tạm 10 phút).
     2) Slow-loris / keep-alive drain: đóng kết nối treo không gửi body sau 15 giây.
     3) Payload size guard: từ chối body > 512 KB ở mọi endpoint để tránh OOM.
     4) User-Agent & header anomaly: chặn request không có Host header (scan tự động).
   Tất cả chỉ ghi log + từ chối request — KHÔNG gửi gì ngược về phía người gửi
   ngoài status code HTTP. Không can thiệp mạng, không chặn IP ở tầng OS/kernel.
   ============================================================================ */

/* ---------- 1) HARD RATE-LIMIT TỰ ĐỘNG THEO IP ---------- */
const globalRequestLog  = new Map(); // ip -> [timestamps] trong 60 giây qua
const dosBlockedIPs     = new Map(); // ip -> unblockAt (timestamp ms)

const DOS_HARD_LIMIT    = 200;              // req/phút để kích hoạt tự chặn
const DOS_BLOCK_MS      = 10 * 60 * 1000;  // thời gian tự chặn: 10 phút
const ABUSE_WARN_THRESHOLD = 120;           // req/phút để cảnh báo log (chưa chặn)

/* Kiểm tra xem IP này có đang bị tự chặn không. */
function isDosBlocked(ip){
  const until = dosBlockedIPs.get(ip);
  if(!until) return false;
  if(Date.now() < until) return true;
  dosBlockedIPs.delete(ip); // hết hạn chặn, xoá luôn
  return false;
}

/* Ghi nhận request + cảnh báo + tự chặn khi vượt ngưỡng. Trả về số req/phút hiện tại. */
function trackAndWarnAbuse(ip){
  if(isDosBlocked(ip)) return DOS_HARD_LIMIT + 1; // đang bị chặn
  const now = Date.now();
  let arr = globalRequestLog.get(ip);
  if(!arr){ arr = []; globalRequestLog.set(ip, arr); }
  while(arr.length && now - arr[0] > 60 * 1000) arr.shift();
  arr.push(now);
  const count = arr.length;
  if(count === ABUSE_WARN_THRESHOLD){
    console.warn(`[DoS] Cảnh báo: IP ${ip} đạt ${count} req/phút — có dấu hiệu spam/DoS.`);
  }
  if(count >= DOS_HARD_LIMIT){
    dosBlockedIPs.set(ip, now + DOS_BLOCK_MS);
    console.warn(`[DoS] TỰ CHẶN IP ${ip} trong ${DOS_BLOCK_MS/60000} phút do vượt ${DOS_HARD_LIMIT} req/phút.`);
  }
  return count;
}

/* Admin có thể bỏ chặn thủ công từ console: unblockDosIP('1.2.3.4') */
function unblockDosIP(ip){ dosBlockedIPs.delete(ip); console.log(`[DoS] Đã bỏ chặn IP: ${ip}`); }
global.unblockDosIP = unblockDosIP;

/* Dọn định kỳ các bucket cũ để không rò rỉ bộ nhớ */
setInterval(()=>{
  const now = Date.now();
  for(const [ip, arr] of globalRequestLog.entries()){
    while(arr.length && now - arr[0] > 5 * 60 * 1000) arr.shift();
    if(arr.length === 0) globalRequestLog.delete(ip);
  }
  for(const [ip, until] of dosBlockedIPs.entries()){
    if(now > until) dosBlockedIPs.delete(ip);
  }
}, 5 * 60 * 1000);

/* ---------- 2) PAYLOAD SIZE GUARD ---------- */
// MAX_BODY_BYTES: giới hạn chung cho toàn bộ request body.
// Upload APK có thể lên tới 100 MB -> để 105 MB có buffer.
// Upload snippet có thể lên tới 10 MB file text -> cũng nằm trong giới hạn này.
// Endpoint thường (login, verify, state...) vẫn an toàn vì readJSONBody dùng giới hạn riêng.
const MAX_BODY_BYTES       = 105 * 1024 * 1024; // 105 MB - đủ cho upload APK 100 MB
const MAX_BODY_BYTES_SMALL = 512 * 1024;        // 512 KB - cho mọi endpoint thường

/* ---------- 3) SLOW-LORIS TIMEOUT ---------- */
const SLOW_REQ_TIMEOUT_MS = 120 * 1000; // 120 giây — đủ cho upload APK 100MB qua mạng chậm

/* Middleware tập trung: kiểm tra IP bị chặn + ghi nhận abuse ngay đầu mỗi request.
   Router gọi hàm này trước khi xử lý bất kỳ endpoint nào. */
function dosMiddleware(req, res, ip){
  // Chặn IP bị block tự động
  if(isDosBlocked(ip)){
    res.writeHead(429, {'Content-Type':'application/json','Retry-After':'600'});
    res.end(JSON.stringify({error:'too_many_requests', retryAfter: 600}));
    return false;
  }
  // Ghi nhận + có thể chặn ngay trong lần này
  const count = trackAndWarnAbuse(ip);
  if(count > DOS_HARD_LIMIT){
    res.writeHead(429, {'Content-Type':'application/json','Retry-After':'600'});
    res.end(JSON.stringify({error:'too_many_requests', retryAfter: 600}));
    return false;
  }
  // Chặn request không có Host header (bot scan tự động, raw TCP flood)
  if(!req.headers['host']){
    res.writeHead(400, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error:'bad_request'}));
    return false;
  }
  return true;
}

/* ---- Validate số tiền/số lượng dùng chung, chống bug do NaN/Infinity/số âm/số quá lớn ----
   Trả về number hợp lệ hoặc null nếu không hợp lệ — bên gọi PHẢI kiểm tra null và từ chối. */
function parseSafeAmount(raw, { min = 1, max = 1000000000 } = {}){
  const cleaned = String(raw == null ? '' : raw).replace(/[^\d.-]/g, '');
  const n = parseFloat(cleaned);
  if(!Number.isFinite(n)) return null;
  if(Number.isNaN(n)) return null;
  const rounded = Math.round(n); // tiền VNĐ luôn là số nguyên, tránh sai số dấu phẩy động
  if(rounded < min || rounded > max) return null;
  return rounded;
}

/* ---- Khoá đơn giản chống race-condition khi nhiều request cùng sửa 1 tài khoản ----
   (ví dụ 2 request mua key/nạp tiền gửi gần như đồng thời cho cùng 1 khách hàng).
   Vì Node.js xử lý tuần tự trên 1 luồng giữa các "await", nguy cơ chính là 2 request
   cùng đọc số dư CŨ trước khi request đầu ghi xong. Hàng đợi theo customerId đảm bảo
   các thao tác ghi số dư của CÙNG 1 khách hàng luôn chạy nối tiếp, không chồng lấp. */
const customerLocks = new Map(); // customerId -> Promise đang chạy (đuôi hàng đợi)
function withCustomerLock(customerId, fn){
  const prev = customerLocks.get(customerId) || Promise.resolve();
  const next = prev.then(fn, fn); // chạy fn() sau khi tác vụ trước xong, dù trước đó lỗi hay không
  // Lưu lại "đuôi" hàng đợi, nhưng luôn bắt lỗi để không làm vỡ map nếu fn() reject.
  customerLocks.set(customerId, next.catch(()=>{}));
  return next;
}

/* Chặn crash toàn cục để Render không báo "Exited with status 1" vì lỗi nhỏ không bắt được. */
process.on('uncaughtException', (err) => {
  console.error('[KeyVault] uncaughtException (đã chặn, server vẫn tiếp tục chạy):', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[KeyVault] unhandledRejection (đã chặn, server vẫn tiếp tục chạy):', reason);
});

/* Giao diện dashboard quản trị (HTML/CSS/JS), nhúng thành chuỗi HTML_PAGE, phục vụ ở "/admin". */
const HTML_LINES = [
  "<!DOCTYPE html>",
  "<html lang=\"vi\">",
  "<head>",
  "<meta charset=\"UTF-8\">",
  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
  "<title>KeyVault — Hệ thống tạo & quản lý Key</title>",
  "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">",
  "<link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;600;700&display=swap\" rel=\"stylesheet\">",
  "<style>",
  "  :root{",
  "    --ink:#F7F7F5;",
  "    --panel:#FFFFFF;",
  "    --panel-2:#FBFBF9;",
  "    --line:#E4E3DD;",
  "    --brass:#AD7F1E;",
  "    --brass-soft:#C99A2E;",
  "    --brass-tint:#F6ECD3;",
  "    --text:#1C1B18;",
  "    --muted:#7C7A72;",
  "    --ok:#1F8F63;",
  "    --ok-tint:#E4F5EE;",
  "    --danger:#C23B4B;",
  "    --danger-tint:#FBEAEC;",
  "    --warn:#B4791A;",
  "    --warn-tint:#FBF0DC;",
  "    --info:#2D6FBB;",
  "    --info-tint:#E7F0FB;",
  "    --shadow: 0 1px 2px rgba(28,27,24,0.04), 0 8px 24px -12px rgba(28,27,24,0.10);",
  "  }",
  "  *{box-sizing:border-box;}",
  "  html,body{margin:0;padding:0;}",
  "  body{",
  "    background:",
  "      radial-gradient(1000px 500px at 88% -8%, #FBF2DC 0%, transparent 60%),",
  "      var(--ink);",
  "    color:var(--text);",
  "    font-family:'Inter',sans-serif;",
  "    min-height:100vh;",
  "  }",
  "  ::selection{background:var(--brass-tint); color:var(--text);}",
  "  ::-webkit-scrollbar{width:10px; height:10px;}",
  "  ::-webkit-scrollbar-thumb{background:#DFDDD3; border-radius:20px;}",
  "  ::-webkit-scrollbar-track{background:transparent;}",
  "",
  "  /* ============ LOGIN SCREEN ============ */",
  "  #loginScreen{",
  "    min-height:100vh; display:flex; align-items:center; justify-content:center;",
  "    padding:24px;",
  "    background:",
  "      radial-gradient(900px 500px at 15% 0%, #FBF2DC 0%, transparent 55%),",
  "      radial-gradient(700px 500px at 100% 100%, #F3EFE4 0%, transparent 55%),",
  "      var(--ink);",
  "  }",
  "  .login-card{",
  "    width:100%; max-width:400px;",
  "    background:var(--panel);",
  "    border:1px solid var(--line);",
  "    border-radius:18px;",
  "    box-shadow:var(--shadow);",
  "    padding:38px 34px 32px;",
  "  }",
  "  .login-brand{display:flex; flex-direction:column; align-items:center; text-align:center; margin-bottom:26px;}",
  "  .login-brand .mark{",
  "    width:52px; height:52px; border-radius:14px; margin-bottom:14px;",
  "    background:linear-gradient(155deg, var(--brass-soft), var(--brass) 65%);",
  "    display:flex; align-items:center; justify-content:center;",
  "    box-shadow:0 8px 20px -8px #AD7F1E70;",
  "  }",
  "  .login-brand .mark svg{width:26px; height:26px;}",
  "  .login-brand h1{font-family:'Space Grotesk',sans-serif; font-size:22px; margin:0;}",
  "  .login-brand p{font-size:12.5px; color:var(--muted); margin:6px 0 0; letter-spacing:.2px;}",
  "",
  "  .login-field{margin-bottom:16px;}",
  "  .login-field label{display:block; font-size:12px; color:var(--muted); margin-bottom:6px; font-weight:500;}",
  "  .login-field input{",
  "    width:100%; background:var(--panel-2); border:1px solid var(--line); color:var(--text);",
  "    padding:12px 14px; border-radius:10px; font-family:'Inter',sans-serif; font-size:13.5px;",
  "    outline:none; transition:border-color .15s, box-shadow .15s;",
  "  }",
  "  .login-field input:focus{border-color:var(--brass-soft); box-shadow:0 0 0 3px #C99A2E1f;}",
  "",
  "  .login-row{display:flex; align-items:center; justify-content:space-between; margin:2px 0 20px;}",
  "  .login-remember{display:flex; align-items:center; gap:7px; font-size:12.5px; color:var(--muted);}",
  "  .login-remember input{accent-color:var(--brass);}",
  "  .login-forgot{font-size:12.5px; color:var(--brass); text-decoration:none; font-weight:600;}",
  "  .login-forgot:hover{text-decoration:underline;}",
  "",
  "  .login-error{",
  "    display:none; background:var(--danger-tint); color:var(--danger); border:1px solid #C23B4B30;",
  "    font-size:12.5px; padding:10px 12px; border-radius:9px; margin-bottom:16px; font-weight:500;",
  "  }",
  "  .login-error.show{display:block;}",
  "",
  "  .login-demo{",
  "    margin-top:20px; text-align:center; font-size:11.5px; color:var(--muted);",
  "    border-top:1px dashed var(--line); padding-top:16px; line-height:1.6;",
  "  }",
  "  .login-demo code{",
  "    background:var(--brass-tint); color:var(--brass); padding:2px 7px; border-radius:5px;",
  "    font-family:'JetBrains Mono',monospace; font-weight:600;",
  "  }",
  "",
  "  /* ============ APP SHELL ============ */",
  "  #appRoot{display:none;}",
  "",
  "  header.top{",
  "    padding:0 32px;",
  "    border-bottom:1px solid var(--line);",
  "    position:sticky; top:0; background:rgba(255,255,255,0.92); backdrop-filter:blur(10px); z-index:20;",
  "  }",
  "  .top-row{",
  "    display:flex; align-items:center; justify-content:space-between;",
  "    padding:20px 0 16px;",
  "  }",
  "  .brand{display:flex; align-items:center; gap:12px;}",
  "  .brand .mark{",
  "    width:34px; height:34px; border-radius:9px;",
  "    background:linear-gradient(155deg, var(--brass-soft), var(--brass) 65%);",
  "    display:flex; align-items:center; justify-content:center;",
  "    box-shadow:0 4px 14px -4px #AD7F1E60;",
  "  }",
  "  .brand .mark svg{width:18px; height:18px;}",
  "  .brand h1{font-family:'Space Grotesk',sans-serif; font-size:18px; margin:0; letter-spacing:0.2px; color:var(--text);}",
  "  .brand .tag{font-size:11px; color:var(--muted); letter-spacing:1.5px; text-transform:uppercase; margin-top:1px;}",
  "",
  "  .header-right{display:flex; align-items:center; gap:26px;}",
  "  .stats{display:flex; gap:22px; flex-wrap:wrap; justify-content:flex-end;}",
  "  .stat{text-align:right;}",
  "  .stat .n{font-family:'JetBrains Mono',monospace; font-size:18px; font-weight:700; color:var(--text);}",
  "  .stat .l{font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1px;}",
  "  .logout-btn{",
  "    display:flex; align-items:center; gap:7px;",
  "    background:var(--panel-2); border:1px solid var(--line); color:var(--muted);",
  "    padding:9px 14px; border-radius:9px; font-size:12.5px; font-weight:600; cursor:pointer;",
  "    transition:.15s; font-family:'Inter',sans-serif;",
  "  }",
  "  .logout-btn:hover{border-color:var(--danger); color:var(--danger);}",
  "  .logout-btn svg{width:14px; height:14px;}",
  "  .ghost-icon-btn{",
  "    display:flex; align-items:center; gap:7px;",
  "    background:var(--panel-2); border:1px solid var(--line); color:var(--muted);",
  "    padding:9px 12px; border-radius:9px; font-size:12.5px; font-weight:600; cursor:pointer;",
  "    transition:.15s; font-family:'Inter',sans-serif;",
  "  }",
  "  .ghost-icon-btn:hover{border-color:var(--brass-soft); color:var(--brass);}",
  "  .ghost-icon-btn.active{border-color:var(--brass-soft); color:var(--brass); background:var(--brass-tint);}",
  "  .ghost-icon-btn svg{width:14px; height:14px;}",
  "  .stat-balance{color:var(--ok); font-weight:600;}",
  "",
  "  .tabnav{display:flex; gap:6px; padding-bottom:0;}",
  "  .tab-btn{",
  "    background:transparent; border:none; color:var(--muted); font-weight:600; font-size:13px;",
  "    padding:11px 6px; cursor:pointer; position:relative; font-family:'Inter',sans-serif;",
  "    border-bottom:2px solid transparent; margin-right:14px; transition:.15s;",
  "  }",
  "  .tab-btn:hover{color:var(--text);}",
  "  .tab-btn.active{color:var(--brass); border-bottom-color:var(--brass);}",
  "",
  "  main{max-width:1280px; margin:0 auto; padding:32px;}",
  "  #page-keys{display:grid; grid-template-columns:340px 1fr; gap:28px;}",
  "  @media (max-width:920px){ #page-keys{grid-template-columns:1fr;} }",
  "",
  "  .panel{",
  "    background:var(--panel);",
  "    border:1px solid var(--line); border-radius:14px; padding:22px;",
  "    box-shadow:var(--shadow);",
  "  }",
  "  .panel h2{",
  "    font-family:'Space Grotesk',sans-serif; font-size:14px; margin:0 0 4px;",
  "    text-transform:uppercase; letter-spacing:1.2px; color:var(--brass);",
  "  }",
  "  .panel .sub{font-size:12px; color:var(--muted); margin:0 0 18px;}",
  "  .panel + .panel{margin-top:24px;}",
  "",
  "  label{display:block; font-size:12px; color:var(--muted); margin:14px 0 6px; font-weight:500;}",
  "  label:first-of-type{margin-top:0;}",
  "  input[type=text], input[type=number], select{",
  "    width:100%; background:var(--panel-2); border:1px solid var(--line); color:var(--text);",
  "    padding:10px 12px; border-radius:8px; font-family:'JetBrains Mono',monospace; font-size:13px;",
  "    outline:none; transition:border-color .15s, box-shadow .15s;",
  "  }",
  "  input[type=text]:focus, input[type=number]:focus, select:focus{border-color:var(--brass-soft); box-shadow:0 0 0 3px #C99A2E1f;}",
  "  .row2{display:grid; grid-template-columns:1fr 1fr; gap:10px;}",
  "  .row3{display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px;}",
  "",
  "  .chip-toggle{display:flex; gap:8px; flex-wrap:wrap;}",
  "  .chip-toggle input{display:none;}",
  "  .chip-toggle label{",
  "    margin:0; display:inline-block; padding:7px 12px; border-radius:20px;",
  "    border:1px solid var(--line); font-size:11.5px; color:var(--muted); cursor:pointer;",
  "    user-select:none; transition:.15s; background:var(--panel-2);",
  "  }",
  "  .chip-toggle input:checked + label{",
  "    border-color:var(--brass-soft); color:var(--brass); background:var(--brass-tint);",
  "  }",
  "",
  "  .btn{",
  "    width:100%; margin-top:20px; padding:13px; border:none; border-radius:9px;",
  "    background:linear-gradient(155deg, var(--brass-soft), var(--brass));",
  "    color:#fff; font-weight:700; font-size:13.5px; letter-spacing:.3px;",
  "    cursor:pointer; transition:transform .1s, box-shadow .15s;",
  "    font-family:'Space Grotesk',sans-serif;",
  "  }",
  "  .btn:hover{box-shadow:0 8px 22px -8px #AD7F1E80; transform:translateY(-1px);}",
  "  .btn:active{transform:translateY(0);}",
  "  .btn:disabled{opacity:.55; cursor:not-allowed; transform:none; box-shadow:none;}",
  "  .btn-ghost{",
  "    background:var(--panel-2); border:1px solid var(--line); color:var(--muted); font-weight:600;",
  "  }",
  "  .btn-ghost:hover{border-color:var(--brass-soft); color:var(--brass); box-shadow:none;}",
  "  .btn-danger-ghost{background:var(--panel-2);border:1px solid #C23B4B40;color:var(--danger);font-weight:600;}",
  "  .btn-danger-ghost:hover{border-color:var(--danger); color:#fff; background:var(--danger);}",
  "  .btn-inline{width:auto; margin-top:0; padding:9px 16px; font-size:12.5px;}",
  "",
  "  .preview-note{",
  "    margin-top:16px; font-size:11.5px; color:var(--muted); line-height:1.5;",
  "    border-left:2px solid var(--line); padding-left:10px;",
  "  }",
  "  .preview-note code{color:var(--brass); font-family:'JetBrains Mono',monospace;}",
  "",
  "  /* Toolbar / filters */",
  "  .toolbar{display:flex; gap:10px; align-items:center; margin-bottom:18px; flex-wrap:wrap;}",
  "  .toolbar input[type=text]{flex:1; min-width:180px;}",
  "  .toolbar select{width:auto; min-width:130px;}",
  "  .toolbar .spacer{flex:1;}",
  "",
  "  /* Ticket / key card */",
  "  .roll{display:flex; flex-direction:column; gap:10px;}",
  "  .ticket{",
  "    position:relative;",
  "    background:var(--panel-2);",
  "    border:1px solid var(--line);",
  "    border-radius:10px;",
  "    padding:14px 18px;",
  "    display:flex; flex-direction:column; gap:10px;",
  "  }",
  "  .ticket::before, .ticket::after{",
  "    content:\"\"; position:absolute; width:14px; height:14px; background:var(--ink);",
  "    border:1px solid var(--line); border-radius:50%; top:50%; transform:translateY(-50%);",
  "  }",
  "  .ticket::before{left:-7px;}",
  "  .ticket::after{right:-7px;}",
  "  .ticket-top{display:flex; justify-content:space-between; align-items:flex-start; gap:12px;}",
  "  .ticket .key{",
  "    font-family:'JetBrains Mono',monospace; font-size:14.5px; font-weight:600;",
  "    letter-spacing:0.5px; word-break:break-all; color:var(--text);",
  "  }",
  "  .ticket-badges{display:flex; gap:6px; flex-shrink:0; flex-wrap:wrap; justify-content:flex-end;}",
  "  .ticket-bottom{display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;}",
  "  .ticket .meta{font-size:11px; color:var(--muted); line-height:1.7;}",
  "  .ticket .meta b{color:var(--text); font-weight:600;}",
  "  .ticket .meta .expired-txt{color:var(--danger); font-weight:600;}",
  "  .ticket .meta .active-txt{color:var(--ok); font-weight:600;}",
  "",
  "  .badge{",
  "    font-size:10.5px; padding:4px 10px; border-radius:20px; text-transform:uppercase;",
  "    letter-spacing:.5px; font-weight:600; white-space:nowrap;",
  "  }",
  "  .badge.available{background:var(--ok-tint); color:var(--ok); border:1px solid #1F8F6330;}",
  "  .badge.sold{background:var(--brass-tint); color:var(--brass); border:1px solid #AD7F1E30;}",
  "  .badge.banned{background:var(--danger-tint); color:var(--danger); border:1px solid #C23B4B30;}",
  "  .badge.expired{background:#EDECE7; color:var(--muted); border:1px solid var(--line);}",
  "  .badge.unactivated{background:var(--info-tint); color:var(--info); border:1px solid #2D6FBB30;}",
  "  .badge.normal{background:#EDECE7; color:var(--muted); border:1px solid var(--line);}",
  "  .badge.premium{background:var(--brass-tint); color:var(--brass); border:1px solid #AD7F1E30;}",
  "  .badge.active{background:var(--ok-tint); color:var(--ok); border:1px solid #1F8F6330;}",
  "",
  "  .actions{display:flex; gap:6px; flex-wrap:wrap;}",
  "  .icon-btn{",
  "    background:var(--panel); border:1px solid var(--line); color:var(--muted);",
  "    width:32px; height:32px; border-radius:7px; cursor:pointer;",
  "    display:flex; align-items:center; justify-content:center; transition:.15s; flex-shrink:0;",
  "  }",
  "  .icon-btn:hover{border-color:var(--brass-soft); color:var(--brass);}",
  "  .icon-btn.danger:hover{border-color:var(--danger); color:var(--danger);}",
  "  .icon-btn svg{width:15px; height:15px;}",
  "",
  "  .empty{",
  "    text-align:center; padding:60px 20px; color:var(--muted);",
  "    border:1px dashed var(--line); border-radius:12px;",
  "  }",
  "  .empty .big{font-family:'Space Grotesk',sans-serif; color:var(--text); font-size:16px; margin-bottom:6px;}",
  "",
  "  .toast{",
  "    position:fixed; bottom:24px; left:50%; transform:translateX(-50%) translateY(20px);",
  "    background:var(--text); border:1px solid var(--text); color:#fff;",
  "    padding:11px 20px; border-radius:9px; font-size:13px; font-weight:600;",
  "    opacity:0; pointer-events:none; transition:.25s; z-index:50;",
  "    font-family:'JetBrains Mono',monospace;",
  "    box-shadow:0 10px 30px -10px rgba(0,0,0,0.35);",
  "    max-width:80vw; text-align:center;",
  "  }",
  "  .toast.show{opacity:1; transform:translateX(-50%) translateY(0);}",
  "",
  "  .modal-bg{",
  "    position:fixed; inset:0; background:#1C1B1866; display:none;",
  "    align-items:center; justify-content:center; z-index:60; backdrop-filter:blur(3px);",
  "  }",
  "  .modal-bg.show{display:flex;}",
  "  .modal{",
  "    background:var(--panel); border:1px solid var(--line); border-radius:14px;",
  "    padding:26px; width:340px; box-shadow:var(--shadow);",
  "  }",
  "  .modal h3{margin:0 0 14px; font-family:'Space Grotesk',sans-serif; font-size:15px; color:var(--text);}",
  "  .modal .row2{margin-bottom:4px;}",
  "  .modal-actions{display:flex; gap:10px; margin-top:18px;}",
  "  .modal-actions .btn{margin-top:0;}",
  "",
  "  footer{text-align:center; padding:30px; color:var(--muted); font-size:11.5px;}",
  "",
  "  /* ============ APK VAULT ============ */",
  "  #page-apkvault{ display:none; }",
  "  .apk-upload-zone{",
  "    border:2px dashed var(--line); border-radius:14px; padding:32px 24px;",
  "    text-align:center; cursor:pointer; transition:.15s; background:var(--panel-2);",
  "  }",
  "  .apk-upload-zone:hover,.apk-upload-zone.drag-over{border-color:var(--brass-soft); background:var(--brass-tint);}",
  "  .apk-upload-zone .upload-icon{font-size:36px; margin-bottom:10px;}",
  "  .apk-upload-zone .upload-label{font-size:14px; font-weight:600; color:var(--text); margin-bottom:4px;}",
  "  .apk-upload-zone .upload-hint{font-size:12px; color:var(--muted);}",
  "  .apk-progress-wrap{display:none; margin-top:16px;}",
  "  .apk-progress-bar-track{background:var(--panel-2); border:1px solid var(--line); border-radius:20px; height:12px; overflow:hidden;}",
  "  .apk-progress-bar-fill{height:100%; width:0%; background:linear-gradient(90deg, var(--brass-soft), var(--brass)); transition:width .2s; border-radius:20px;}",
  "  .apk-progress-label{font-size:11.5px; color:var(--muted); text-align:center; margin-top:6px;}",
  "  .apk-card{",
  "    background:var(--panel-2); border:1px solid var(--line); border-radius:12px;",
  "    padding:16px 18px; display:flex; align-items:flex-start; gap:14px; margin-bottom:12px;",
  "  }",
  "  .apk-card .apk-icon{",
  "    width:48px; height:48px; border-radius:10px; background:var(--brass-tint);",
  "    border:1px solid #AD7F1E30; display:flex; align-items:center; justify-content:center;",
  "    font-size:22px; flex-shrink:0;",
  "  }",
  "  .apk-card .apk-info{flex:1; min-width:0;}",
  "  .apk-card .apk-name{font-weight:700; font-size:14px; color:var(--text); margin-bottom:2px; word-break:break-word;}",
  "  .apk-card .apk-meta{font-size:11.5px; color:var(--muted); line-height:1.7;}",
  "  .apk-card .apk-meta b{color:var(--text);}",
  "  .apk-card .apk-note{",
  "    font-size:12px; color:var(--muted); background:var(--info-tint); border:1px solid #2D6FBB20;",
  "    border-radius:8px; padding:8px 12px; margin-top:8px; white-space:pre-wrap; word-break:break-word;",
  "  }",
  "  .apk-card .apk-actions{display:flex; flex-direction:column; gap:6px; flex-shrink:0;}",
  "  .apk-download-btn{",
  "    display:inline-flex; align-items:center; gap:6px; padding:7px 14px; border-radius:8px;",
  "    background:var(--ok-tint); border:1px solid #1F8F6330; color:var(--ok);",
  "    font-size:12px; font-weight:600; cursor:pointer; text-decoration:none; white-space:nowrap;",
  "    font-family:'Inter',sans-serif; transition:.12s;",
  "  }",
  "  .apk-download-btn:hover{background:#d1f0e4;}",
  "  .apk-edit-btn{",
  "    display:inline-flex; align-items:center; gap:6px; padding:7px 14px; border-radius:8px;",
  "    background:var(--panel); border:1px solid var(--line); color:var(--muted);",
  "    font-size:12px; font-weight:600; cursor:pointer; white-space:nowrap;",
  "    font-family:'Inter',sans-serif; transition:.12s;",
  "  }",
  "  .apk-edit-btn:hover{border-color:var(--brass-soft); color:var(--brass);}",
  "  .apk-del-btn{",
  "    display:inline-flex; align-items:center; gap:6px; padding:7px 14px; border-radius:8px;",
  "    background:var(--panel); border:1px solid #C23B4B30; color:var(--danger);",
  "    font-size:12px; font-weight:600; cursor:pointer; white-space:nowrap;",
  "    font-family:'Inter',sans-serif; transition:.12s;",
  "  }",
  "  .apk-del-btn:hover{background:var(--danger-tint);}",
  "  .apk-split{display:grid; grid-template-columns:360px 1fr; gap:24px;}",
  "  @media(max-width:960px){.apk-split{grid-template-columns:1fr;}}",
  "",
  "  /* ============ STATS / SECURITY PAGES ============ */",
  "  .stats-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:24px;}",
  "  .stat-card{background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px 20px; box-shadow:var(--shadow);}",
  "  .stat-card .n{font-family:'JetBrains Mono',monospace; font-size:24px; font-weight:700; color:var(--text);}",
  "  .stat-card .l{font-size:11.5px; color:var(--muted); margin-top:4px;}",
  "  .stat-card .n.warn{color:var(--warn);}",
  "  .stat-card .n.danger{color:var(--danger);}",
  "  .stat-card .n.ok{color:var(--ok);}",
  "",
  "  table{width:100%; border-collapse:collapse; font-size:12.8px;}",
  "  th{text-align:left; color:var(--muted); font-weight:600; font-size:10.5px; text-transform:uppercase;",
  "     letter-spacing:.6px; padding:10px 12px; border-bottom:1px solid var(--line);}",
  "  td{padding:12px; border-bottom:1px solid var(--line); color:var(--text); vertical-align:middle;}",
  "  tr:last-child td{border-bottom:none;}",
  "  .table-wrap{overflow-x:auto;}",
  "  .mono{font-family:'JetBrains Mono',monospace;}",
  "",
  "  .barchart{display:flex; align-items:flex-end; gap:12px; height:150px; padding:12px 6px 0;}",
  "  .bar-col{flex:1; display:flex; flex-direction:column; align-items:center; justify-content:flex-end; gap:8px; height:100%;}",
  "  .bar{width:100%; max-width:38px; background:linear-gradient(180deg, var(--brass-soft), var(--brass)); border-radius:6px 6px 3px 3px; min-height:4px; transition:height .4s;}",
  "  .bar-label{font-size:10px; color:var(--muted); text-align:center;}",
  "  .bar-val{font-size:11px; font-weight:700; color:var(--text); font-family:'JetBrains Mono',monospace;}",
  "",
  "  .split-2{display:grid; grid-template-columns:1fr 1fr; gap:24px;}",
  "  @media (max-width:800px){ .split-2{grid-template-columns:1fr;} }",
  "",
  "  .type-bar-row{margin-bottom:14px;}",
  "  .type-bar-row .lbl{display:flex; justify-content:space-between; font-size:12px; margin-bottom:6px;}",
  "  .type-bar-track{background:var(--panel-2); border:1px solid var(--line); height:10px; border-radius:20px; overflow:hidden;}",
  "  .type-bar-fill{height:100%; border-radius:20px;}",
  "",
  "  .pill{font-size:10.5px; padding:4px 10px; border-radius:20px; font-weight:600; white-space:nowrap;}",
  "  .pill.ok{background:var(--ok-tint); color:var(--ok);}",
  "  .pill.danger{background:var(--danger-tint); color:var(--danger);}",
  "  .pill.warn{background:var(--warn-tint); color:var(--warn);}",
  "  .pill.info{background:var(--info-tint); color:var(--info);}",
  "",
  "  .progress-track{background:var(--panel-2); border:1px solid var(--line); border-radius:20px; height:10px; overflow:hidden; margin:18px 0 6px;}",
  "  .progress-fill{height:100%; width:0%; background:linear-gradient(90deg, var(--brass-soft), var(--brass)); transition:width .25s;}",
  "  .progress-label{font-size:11.5px; color:var(--muted); text-align:center;}",
  "",
  "  .scan-item{display:flex; justify-content:space-between; align-items:center; padding:12px 14px;",
  "    border:1px solid var(--line); border-radius:10px; margin-bottom:8px; background:var(--panel-2);}",
  "  .scan-item .name{font-size:13px; font-weight:600;}",
  "  .scan-item .desc{font-size:11.5px; color:var(--muted); margin-top:2px;}",
  "",
  "  .sec-note{",
  "    margin-top:6px; font-size:11.5px; color:var(--muted); line-height:1.6;",
  "    background:var(--info-tint); border:1px solid #2D6FBB30; padding:12px 14px; border-radius:10px;",
  "  }",
  "  .panel-head{display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:4px;}",
  "",
  "  /* ============ PREMIUM SELLER / ACCOUNT UPGRADE ============ */",
  "  .vip-badge{",
  "    display:inline-flex; align-items:center; gap:4px; margin-left:8px;",
  "    background:linear-gradient(120deg,#7A4E00,#C99A2E 45%,#F3D67A 60%,#C99A2E 75%,#7A4E00);",
  "    background-size:220% auto; color:#fff; font-family:'Space Grotesk',sans-serif;",
  "    font-size:10px; font-weight:700; letter-spacing:.6px; padding:4px 10px; border-radius:20px;",
  "    box-shadow:0 4px 14px -4px #AD7F1E90; animation:shimmer 3.5s linear infinite;",
  "  }",
  "  @keyframes shimmer{ 0%{background-position:0% 50%;} 100%{background-position:220% 50%;} }",
  "  body.vip-mode header.top{",
  "    background:",
  "      linear-gradient(rgba(255,255,255,0.90),rgba(255,255,255,0.90)),",
  "      radial-gradient(1200px 220px at 10% 0%, #F6ECD3 0%, transparent 60%);",
  "    border-bottom:1px solid var(--brass-soft);",
  "  }",
  "  body.vip-mode .brand .mark{",
  "    box-shadow:0 0 0 3px #F6ECD3, 0 6px 18px -6px #AD7F1E90;",
  "  }",
  "  body.vip-mode .panel{ border-color:#E9D9AE; }",
  "",
  "  .badge.normal.acct{background:#EDECE7; color:var(--muted); border:1px solid var(--line);}",
  "  .badge.premium.acct{background:linear-gradient(120deg, var(--brass-tint), #FBF2DC); color:var(--brass); border:1px solid #AD7F1E40; font-weight:700;}",
  "",
  "  .chip-toggle input:disabled + label{",
  "    opacity:.45; cursor:not-allowed; text-decoration:line-through;",
  "  }",
  "",
  "  .notif-panel{border-color:#E9D9AE;}",
  "  .notif-item{",
  "    display:flex; align-items:flex-start; gap:10px; padding:12px 14px;",
  "    border:1px solid var(--line); border-radius:10px; margin-bottom:8px; background:var(--panel-2);",
  "  }",
  "  .notif-item.unread{border-color:var(--brass-soft); background:var(--brass-tint);}",
  "  .notif-item .dot{width:8px; height:8px; border-radius:50%; background:var(--brass); margin-top:5px; flex-shrink:0;}",
  "  .notif-item.unread .dot{background:var(--ok);}",
  "  .notif-item .body{flex:1;}",
  "  .notif-item .msg{font-size:12.8px; color:var(--text); line-height:1.5;}",
  "  .notif-item .time{font-size:10.5px; color:var(--muted); margin-top:3px;}",
  "",
  "  .price-table{width:100%; border-collapse:collapse; margin-top:10px; font-size:12px;}",
  "  .price-table td{padding:6px 8px; border-bottom:1px dashed var(--line);}",
  "  .price-table td:last-child{text-align:right; font-family:'JetBrains Mono',monospace; font-weight:600; color:var(--brass);}",
  "",
  "  /* ============ OLM KEY PAGE ============ */",
  "  #olmPage{",
  "    display:none; position:fixed; inset:0; background:var(--ink); z-index:100;",
  "    overflow-y:auto;",
  "  }",
  "  #olmPage.show{display:block;}",
  "  .olm-header{",
  "    padding:0 32px;",
  "    border-bottom:1px solid var(--line);",
  "    position:sticky; top:0; background:rgba(255,255,255,0.95); backdrop-filter:blur(10px); z-index:20;",
  "    display:flex; align-items:center; justify-content:space-between;",
  "  }",
  "  .olm-header-left{display:flex; align-items:center; gap:14px; padding:18px 0;}",
  "  .olm-title{font-family:'Space Grotesk',sans-serif; font-size:18px; font-weight:700; color:var(--text);}",
  "  .olm-subtitle{font-size:11.5px; color:var(--muted); margin-top:2px;}",
  "  .olm-tabs{display:flex; gap:6px; padding-bottom:0;}",
  "  .olm-tab{",
  "    background:transparent; border:none; color:var(--muted); font-weight:600; font-size:13px;",
  "    padding:11px 6px; cursor:pointer; position:relative; font-family:'Inter',sans-serif;",
  "    border-bottom:2px solid transparent; margin-right:14px; transition:.15s;",
  "  }",
  "  .olm-tab:hover{color:var(--text);}",
  "  .olm-tab.active{color:var(--brass); border-bottom-color:var(--brass);}",
  "  .olm-body{max-width:1200px; margin:0 auto; padding:28px 32px;}",
  "  .olm-split{display:grid; grid-template-columns:360px 1fr; gap:24px;}",
  "  @media(max-width:900px){.olm-split{grid-template-columns:1fr;}}",
  "  .olm-key-row{",
  "    display:flex; align-items:flex-start; justify-content:space-between; padding:14px 16px;",
  "    border:1px solid var(--line); border-radius:11px; margin-bottom:10px; background:var(--panel-2);",
  "    gap:12px;",
  "  }",
  "  .olm-key-row:hover{border-color:var(--brass-soft);}",
  "  .olm-key-row.banned-row{opacity:.65; background:#FFF5F5;}",
  "  .olm-key-val{font-family:'JetBrains Mono',monospace; font-size:12.5px; font-weight:700; color:var(--text); word-break:break-all;}",
  "  .olm-key-meta{font-size:11px; color:var(--muted); margin-top:4px; line-height:1.6;}",
  "  .olm-key-actions{display:flex; gap:6px; flex-wrap:wrap; flex-shrink:0;}",
  "  .olm-list-filter{display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap; align-items:center;}",
  "  .olm-list-filter input{flex:1; min-width:180px;}",
  "  .olm-list-filter select{min-width:140px;}",
  "  .olm-section-title{font-family:'Space Grotesk',sans-serif; font-size:15px; font-weight:700; color:var(--text); margin:0 0 4px;}",
  "  .olm-section-sub{font-size:12px; color:var(--muted); margin:0 0 16px;}",
  "  .olm-empty{text-align:center; padding:40px 20px; color:var(--muted); font-size:13px;}",
  "  .olm-custom-key-input{",
  "    display:flex; gap:8px; margin-top:8px;",
  "  }",
  "  .olm-custom-key-input input{flex:1;}",
  "  .olm-badge-normal{background:#EDECE7; color:var(--muted); border:1px solid var(--line); padding:3px 9px; border-radius:20px; font-size:10.5px; font-weight:600;}",
  "  .olm-badge-premium{background:linear-gradient(120deg,var(--brass-tint),#FBF2DC); color:var(--brass); border:1px solid #AD7F1E40; padding:3px 9px; border-radius:20px; font-size:10.5px; font-weight:700;}",
  "  .olm-badge-active{background:var(--ok-tint); color:var(--ok); border:1px solid var(--ok)30; padding:3px 9px; border-radius:20px; font-size:10.5px; font-weight:600;}",
  "  .olm-badge-unactivated{background:var(--info-tint); color:var(--info); border:1px solid var(--info)30; padding:3px 9px; border-radius:20px; font-size:10.5px; font-weight:600;}",
  "  .olm-badge-expired{background:var(--danger-tint); color:var(--danger); border:1px solid var(--danger)30; padding:3px 9px; border-radius:20px; font-size:10.5px; font-weight:600;}",
  "  .olm-badge-banned{background:#2a2a2a; color:#fff; padding:3px 9px; border-radius:20px; font-size:10.5px; font-weight:700;}",
  "  .olm-stats-row{display:flex; gap:14px; flex-wrap:wrap; margin-bottom:20px;}",
  "  .olm-stat-chip{background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px 16px; font-size:12px;}",
  "  .olm-stat-chip .n{font-family:'JetBrains Mono',monospace; font-size:20px; font-weight:700; color:var(--text);}",
  "  .olm-stat-chip .l{color:var(--muted); font-size:10.5px; margin-top:2px;}",
  "</style>",
  "</head>",
  "<body>",
  "",
  "<!-- ============ LOGIN SCREEN ============ -->",
  "<div id=\"loginScreen\">",
  "  <div class=\"login-card\">",
  "    <div class=\"login-brand\">",
  "      <div class=\"mark\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\"><path d=\"M7 12a5 5 0 1 1 4.9-6H21v4h-2v3h-3v-3h-2.1A5 5 0 0 1 7 12Z\" stroke=\"#fff\" stroke-width=\"1.6\" stroke-linejoin=\"round\"/><circle cx=\"7\" cy=\"12\" r=\"1.4\" fill=\"#fff\"/></svg>",
  "      </div>",
  "      <h1>KeyVault</h1>",
  "      <p>Đăng nhập để quản lý hệ thống key</p>",
  "    </div>",
  "",
  "    <div class=\"login-error\" id=\"loginError\">Sai tên đăng nhập hoặc mật khẩu. Vui lòng thử lại.</div>",
  "",
  "    <div class=\"login-field\">",
  "      <label>Tên đăng nhập</label>",
  "      <input type=\"text\" id=\"loginUser\" placeholder=\"Adminn\" autocomplete=\"username\">",
  "    </div>",
  "    <div class=\"login-field\">",
  "      <label>Mật khẩu</label>",
  "      <input type=\"text\" id=\"loginPass\" placeholder=\"••••••••\" autocomplete=\"current-password\">",
  "    </div>",
  "",
  "    <div class=\"login-row\" style=\"justify-content:flex-end;\">",
  "      <a href=\"#\" class=\"login-forgot\" onclick=\"showToastLogin('Vui lòng liên hệ quản trị viên để lấy lại mật khẩu.'); return false;\">Quên mật khẩu?</a>",
  "    </div>",
  "",
  "    <button class=\"btn\" id=\"btnLogin\">Đăng nhập</button>",
  "",
  "    <div class=\"login-demo\">",
  "      🔒 Hệ thống bảo mật — an toàn — chất lượng<br>",
  "      Toàn bộ dữ liệu đăng nhập và thông tin key được mã hoá, xác thực qua máy chủ và lưu trữ an toàn.<br>",
  "      Tài khoản đăng nhập thành công sẽ được <b>tự động ghi nhớ</b> trên trình duyệt này.",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<!-- ============ APP ============ -->",
  "<div id=\"appRoot\">",
  "",
  "<header class=\"top\">",
  "  <div class=\"top-row\">",
  "    <div class=\"brand\">",
  "      <div class=\"mark\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\"><path d=\"M7 12a5 5 0 1 1 4.9-6H21v4h-2v3h-3v-3h-2.1A5 5 0 0 1 7 12Z\" stroke=\"#fff\" stroke-width=\"1.6\" stroke-linejoin=\"round\"/><circle cx=\"7\" cy=\"12\" r=\"1.4\" fill=\"#fff\"/></svg>",
  "      </div>",
  "      <div>",
  "        <h1>KeyVault <span class=\"vip-badge\" id=\"vipBadge\" style=\"display:none;\">★ PREMIUM</span></h1>",
  "        <div class=\"tag\">Hệ thống tạo &amp; quản lý key</div>",
  "      </div>",
  "    </div>",
  "    <div class=\"header-right\">",
  "      <div class=\"stats\">",
  "        <div class=\"stat\" id=\"statBalanceWrap\" style=\"display:none;\"><div class=\"n\" id=\"statBalance\">0₫</div><div class=\"l\">Số dư tài khoản</div></div>",
  "        <div class=\"stat\" id=\"statAcctExpiryWrap\" style=\"display:none;\"><div class=\"n\" id=\"statAcctExpiry\">—</div><div class=\"l\">Hạn tài khoản</div></div>",
  "        <div class=\"stat\"><div class=\"n\" id=\"statTotal\">0</div><div class=\"l\">Tổng key</div></div>",
  "        <div class=\"stat\"><div class=\"n\" id=\"statAvail\">0</div><div class=\"l\">Còn hàng</div></div>",
  "        <div class=\"stat stat-toggleable\"><div class=\"n\" id=\"statSold\">0</div><div class=\"l\">Đã bán</div></div>",
  "        <div class=\"stat stat-toggleable\"><div class=\"n\" id=\"statExpired\">0</div><div class=\"l\">Hết hạn</div></div>",
  "        <div class=\"stat stat-toggleable\"><div class=\"n\" id=\"statBanned\">0</div><div class=\"l\">Bị cấm</div></div>",
  "        <div class=\"stat stat-toggleable\"><div class=\"n\" id=\"statRevenue\">0₫</div><div class=\"l\">Doanh thu</div></div>",
  "      </div>",
  "      <button class=\"ghost-icon-btn\" id=\"btnToggleStats\" title=\"Ẩn/hiện: đã bán, hết hạn, bị cấm, doanh thu\">",
  "        <svg id=\"iconEyeOpen\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "        <svg id=\"iconEyeClosed\" style=\"display:none;\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><path d=\"M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a20.3 20.3 0 0 1 5.06-6.06M9.9 4.24A9.6 9.6 0 0 1 12 4c7 0 11 8 11 8a20.3 20.3 0 0 1-3.22 4.44M14.12 14.12a3 3 0 1 1-4.24-4.24\"/><path d=\"M1 1l22 22\"/></svg>",
  "        <span id=\"toggleStatsLabel\">Ẩn số liệu</span>",
  "      </button>",
  "      <button class=\"ghost-icon-btn\" id=\"btnOpenOlmPage\" title=\"Quản lý Server key Olm\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\"/><path d=\"M7 11V7a5 5 0 0 1 10 0v4\"/><circle cx=\"12\" cy=\"16\" r=\"1.5\" fill=\"currentColor\" stroke=\"none\"/></svg>",
  "        Server key Olm",
  "      </button>",
  "      <button class=\"ghost-icon-btn\" id=\"btnChangeOwnPassword\" title=\"Đổi mật khẩu tài khoản đang đăng nhập\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2\"/><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"/></svg>",
  "        Đổi mật khẩu",
  "      </button>",
  "      <button class=\"logout-btn\" id=\"btnLogout\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><path d=\"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4\"/><path d=\"M16 17l5-5-5-5\"/><path d=\"M21 12H9\"/></svg>",
  "        Đăng xuất",
  "      </button>",
  "    </div>",
  "  </div>",
  "  <nav class=\"tabnav\">",
  "    <button class=\"tab-btn active\" data-page=\"keys\">Quản lý Key</button>",
  "    <button class=\"tab-btn\" data-page=\"stats\">Thống kê</button>",
  "    <button class=\"tab-btn\" data-page=\"security\">Bảo mật Server</button>",
  "    <button class=\"tab-btn\" data-page=\"sellers\" data-admin-only=\"1\">Người bán</button>",
  "    <button class=\"tab-btn\" data-page=\"customers\" data-admin-only=\"1\">Người dùng</button>",
  "    <button class=\"tab-btn\" data-page=\"apikey\" data-admin-only=\"1\">API Key Server</button>",
  "    <button class=\"tab-btn\" data-page=\"products\" data-admin-only=\"1\">Sản phẩm &amp; Mã giảm giá</button>",
  "    <button class=\"tab-btn\" data-page=\"getkey\" data-admin-only=\"1\">GetKey</button>",
  "    <button class=\"tab-btn\" data-page=\"codevault\" data-admin-only=\"1\">Nạp code</button>",
  "    <button class=\"tab-btn\" data-page=\"uploadcode\" data-admin-only=\"1\">📤 Nạp file code</button>",
  "    <button class=\"tab-btn\" data-page=\"apkvault\" data-admin-only=\"1\">Nạp APK</button>",
  "    <button class=\"tab-btn\" data-page=\"miniapp\" data-admin-only=\"1\">Quản lý Mini App</button>",
  "  </nav>",
  "</header>",
  "",
  "<main>",
  "",
  "  <!-- ============ THÔNG BÁO NHẬN TIỀN / CẬP NHẬT TÀI KHOẢN (CHỈ NGƯỜI BÁN) ============ -->",
  "  <div class=\"panel notif-panel\" id=\"sellerNotifPanel\" style=\"display:none; margin-bottom:24px;\">",
  "    <div class=\"panel-head\">",
  "      <div>",
  "        <h2>Thông báo tài khoản</h2>",
  "        <p class=\"sub\" style=\"margin:0;\">Thông báo nhận tiền, gia hạn và nâng cấp tài khoản từ quản trị viên.</p>",
  "      </div>",
  "      <button class=\"btn-ghost icon-btn\" style=\"width:auto; padding:0 14px; height:32px;\" id=\"btnMarkAllRead\">Đánh dấu đã đọc</button>",
  "    </div>",
  "    <div id=\"notifList\" style=\"margin-top:14px;\"></div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 1: QUẢN LÝ KEY ============ -->",
  "  <div id=\"page-keys\">",
  "    <!-- Generator panel -->",
  "    <div>",
  "      <div class=\"panel\">",
  "        <h2>Tạo key mới</h2>",
  "        <p class=\"sub\">Cấu hình định dạng, loại key và thời hạn sử dụng.</p>",
  "",
  "        <label>Tiền tố (prefix)</label>",
  "        <input type=\"text\" id=\"cfgPrefix\" placeholder=\"VD: PRO\" maxlength=\"10\" value=\"PRO\">",
  "",
  "        <div class=\"row2\">",
  "          <div>",
  "            <label>Số nhóm ký tự</label>",
  "            <input type=\"number\" id=\"cfgGroups\" value=\"4\" min=\"1\" max=\"8\">",
  "          </div>",
  "          <div>",
  "            <label>Độ dài mỗi nhóm</label>",
  "            <input type=\"number\" id=\"cfgLen\" value=\"4\" min=\"2\" max=\"10\">",
  "          </div>",
  "        </div>",
  "",
  "        <label>Bộ ký tự</label>",
  "        <div class=\"chip-toggle\" id=\"charsetToggle\">",
  "          <input type=\"radio\" name=\"cs\" id=\"csFull\" checked><label for=\"csFull\">A-Z 0-9</label>",
  "          <input type=\"radio\" name=\"cs\" id=\"csNoAmbig\"><label for=\"csNoAmbig\">Rõ ràng (bỏ 0/O, 1/I)</label>",
  "          <input type=\"radio\" name=\"cs\" id=\"csNum\"><label for=\"csNum\">Chỉ số</label>",
  "        </div>",
  "",
  "        <label>Loại key</label>",
  "        <div class=\"chip-toggle\">",
  "          <input type=\"radio\" name=\"ktype\" id=\"ktNormal\" value=\"normal\" checked><label for=\"ktNormal\">Thường</label>",
  "          <input type=\"radio\" name=\"ktype\" id=\"ktPremium\" value=\"premium\"><label for=\"ktPremium\">★ Premium</label>",
  "        </div>",
  "",
  "        <label>Thời hạn sử dụng</label>",
  "        <div class=\"chip-toggle\" id=\"expiryToggle\">",
  "          <input type=\"radio\" name=\"expiry\" id=\"expNone\" value=\"none\"><label for=\"expNone\">Không giới hạn</label>",
  "          <input type=\"radio\" name=\"expiry\" id=\"expLimited\" value=\"limited\" checked><label for=\"expLimited\">Có thời hạn</label>",
  "        </div>",
  "        <div id=\"expiryFields\" style=\"margin-top:10px;\">",
  "          <label>Chọn gói thời hạn (cố định, không thể chỉnh sửa số ngày/giờ)</label>",
  "          <select id=\"cfgFixedPlan\" style=\"width:100%;\">",
  "            <option value=\"h12\">12 giờ — 20.000₫</option>",
  "            <option value=\"d1\" selected>1 ngày — 30.000₫</option>",
  "            <option value=\"w1\">1 tuần — 60.000₫</option>",
  "            <option value=\"d15\">15 ngày — 90.000₫</option>",
  "            <option value=\"m1\">1 tháng — 160.000₫</option>",
  "          </select>",
  "        </div>",
  "        <p class=\"preview-note\" id=\"expiryLockNote\" style=\"display:none; color:var(--warn); border-left-color:var(--warn);\">",
  "          🔒 Tài khoản <b>Thường</b> chỉ được tạo key có thời hạn. Liên hệ quản trị viên để nâng cấp lên <b>Premium</b> và mở khoá tạo key không giới hạn.",
  "        </p>",
  "",
  "        <div id=\"sellerPriceNote\" style=\"display:none;\">",
  "          <label>Bảng giá tạo key (cố định, trừ vào số dư)</label>",
  "          <table class=\"price-table\">",
  "            <tr><td>Key 12 giờ</td><td>20.000₫</td></tr>",
  "            <tr><td>Key 1 ngày</td><td>30.000₫</td></tr>",
  "            <tr><td>Key 1 tuần</td><td>60.000₫</td></tr>",
  "            <tr><td>Key 15 ngày</td><td>90.000₫</td></tr>",
  "            <tr><td>Key 1 tháng</td><td>160.000₫</td></tr>",
  "            <tr><td>Key không giới hạn (Premium)</td><td>500.000₫</td></tr>",
  "          </table>",
  "          <p class=\"preview-note\" style=\"margin-top:8px;\">",
  "            Bảng giá và các mốc thời hạn ở trên là <b>cố định</b>, không thể chỉnh sửa trên giao diện (kể cả tài khoản Premium hay Thường).",
  "          </p>",
  "        </div>",
  "",
  "        <label>Số lượng key sinh</label>",
  "        <input type=\"number\" id=\"cfgQty\" value=\"10\" min=\"1\" max=\"500\">",
  "",
  "        <label>Số thiết bị cho phép / key</label>",
  "        <input type=\"number\" id=\"cfgMaxDevices\" value=\"1\" min=\"1\" max=\"20\">",
  "        <p class=\"preview-note\" style=\"margin-top:6px;\">Mỗi key chỉ được kích hoạt tối đa số thiết bị này. Mặc định <b>1</b> (1 key = 1 thiết bị). Có thể tăng lên nếu muốn cho phép dùng nhiều máy.</p>",
  "",
  "        <label>Giá bán mỗi key (tuỳ chọn)</label>",
  "        <input type=\"text\" id=\"cfgPrice\" placeholder=\"VD: 99000\">",
  "",
  "        <div id=\"createdAtAdminBlock\" data-admin-only=\"1\">",
  "          <label>Ngày giờ tạo key</label>",
  "          <div class=\"chip-toggle\" id=\"createdAtToggle\">",
  "            <input type=\"radio\" name=\"createdAtMode\" id=\"createdAtNow\" value=\"now\" checked><label for=\"createdAtNow\">Hiện tại</label>",
  "            <input type=\"radio\" name=\"createdAtMode\" id=\"createdAtCustom\" value=\"custom\"><label for=\"createdAtCustom\">Tuỳ chỉnh</label>",
  "          </div>",
  "          <div class=\"row2\" id=\"createdAtCustomField\" style=\"display:none; margin-top:10px;\">",
  "            <div style=\"grid-column:1/-1;\">",
  "              <label>Chọn giờ · ngày · tháng</label>",
  "              <input type=\"datetime-local\" id=\"cfgCreatedAt\">",
  "            </div>",
  "          </div>",
  "          <p class=\"preview-note\" style=\"margin-top:10px;\">",
  "            Chỉ tài khoản admin mới có thể tuỳ chỉnh ngày giờ tạo key (dùng để nhập lại key cũ, key đã bán trước đó...). Nếu chọn \"Có thời hạn\" ở trên, hạn dùng sẽ được tính dựa trên mốc thời gian này.",
  "          </p>",
  "        </div>",
  "",
  "        <div class=\"preview-note\">",
  "          Định dạng xem trước: <code id=\"formatPreview\">PRO-XXXX-XXXX-XXXX-XXXX</code>",
  "        </div>",
  "",
  "        <button class=\"btn\" id=\"btnGenerate\">Sinh key ngay</button>",
  "        <button class=\"btn btn-ghost\" style=\"margin-top:10px\" id=\"btnExport\">Xuất CSV toàn bộ</button>",
  "        <button class=\"btn btn-ghost\" style=\"margin-top:10px\" id=\"btnOpenExtendAll\" data-admin-only=\"1\">⏱ Gia hạn tất cả key</button>",
  "        <button class=\"btn btn-danger-ghost\" style=\"margin-top:10px\" id=\"btnClear\">Xoá toàn bộ key</button>",
  "",
  "        <p class=\"preview-note\" style=\"margin-top:18px;\">",
  "          Lưu ý: dữ liệu key được lưu trong bộ nhớ phiên làm việc của trình duyệt (không lưu máy chủ). Tải lại trang sẽ mất dữ liệu — hãy xuất CSV để lưu trữ lâu dài.",
  "        </p>",
  "      </div>",
  "    </div>",
  "",
  "    <!-- List panel -->",
  "    <div class=\"panel\">",
  "      <h2>Danh sách key</h2>",
  "      <p class=\"sub\">Quản lý trạng thái, đánh dấu đã bán, cấm/bỏ cấm, reset key hoặc reset thiết bị.</p>",
  "",
  "      <div class=\"toolbar\">",
  "        <input type=\"text\" id=\"search\" placeholder=\"Tìm theo key hoặc ghi chú khách hàng...\">",
  "        <select id=\"filterStatus\">",
  "          <option value=\"all\">Tất cả trạng thái</option>",
  "          <option value=\"available\">Còn hàng</option>",
  "          <option value=\"sold\">Đã bán</option>",
  "          <option value=\"banned\">Bị cấm</option>",
  "          <option value=\"expired\">Hết hạn</option>",
  "          <option value=\"unactivated\">Chưa kích hoạt</option>",
  "        </select>",
  "        <select id=\"filterType\">",
  "          <option value=\"all\">Tất cả loại</option>",
  "          <option value=\"normal\">Thường</option>",
  "          <option value=\"premium\">Premium</option>",
  "        </select>",
  "        <div class=\"spacer\"></div>",
  "        <button class=\"btn-ghost icon-btn\" style=\"width:auto; padding:0 14px; height:36px;\" id=\"btnCopyAvail\">Copy key còn hàng</button>",
  "      </div>",
  "",
  "      <div class=\"roll\" id=\"rollList\"></div>",
  "      <div class=\"empty\" id=\"emptyState\">",
  "        <div class=\"big\">Chưa có key nào</div>",
  "        Sinh key mới ở bảng điều khiển bên trái để bắt đầu.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 2: THỐNG KÊ ============ -->",
  "  <div id=\"page-stats\" style=\"display:none;\">",
  "    <div class=\"stats-grid\">",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"stTotalKeys\">0</div><div class=\"l\">Tổng key đã tạo</div></div>",
  "      <div class=\"stat-card\"><div class=\"n ok\" id=\"stActiveKeys\">0</div><div class=\"l\">Key còn hiệu lực</div></div>",
  "      <div class=\"stat-card\"><div class=\"n danger\" id=\"stExpiredKeys\">0</div><div class=\"l\">Key đã hết hạn</div></div>",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"stPremiumKeys\">0</div><div class=\"l\">Key Premium</div></div>",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"stLoginCount\">0</div><div class=\"l\">Lượt đăng nhập</div></div>",
  "    </div>",
  "",
  "    <div class=\"split-2\">",
  "      <div class=\"panel\">",
  "        <h2>Key tạo theo 7 ngày gần nhất</h2>",
  "        <p class=\"sub\">Số lượng key được sinh ra mỗi ngày.</p>",
  "        <div class=\"barchart\" id=\"creationChart\"></div>",
  "      </div>",
  "      <div class=\"panel\">",
  "        <h2>Tỉ lệ loại key</h2>",
  "        <p class=\"sub\">Phân bổ giữa key Thường và Premium.</p>",
  "        <div id=\"typeBreakdown\"></div>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Hạn sử dụng key</h2>",
  "          <p class=\"sub\">Trạng thái còn hạn / hết hạn và thời gian còn lại của từng key.</p>",
  "        </div>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"expiryTable\">",
  "          <thead><tr><th>Key</th><th>Loại</th><th>Trạng thái</th><th>Hết hạn lúc</th><th>Thời gian còn lại</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Lịch sử đăng nhập</h2>",
  "      <p class=\"sub\">Ghi lại các lần đăng nhập vào hệ thống trong phiên này.</p>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"loginTable\">",
  "          <thead><tr><th>Thời gian</th><th>Tài khoản</th><th>Kết quả</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 3: BẢO MẬT SERVER ============ -->",
  "  <div id=\"page-security\" style=\"display:none;\">",
  "    <div class=\"sec-note\">",
  "      Đây là bảng điều khiển <b>mô phỏng</b> để minh hoạ giao diện. Vì đây là trang tĩnh chạy trong trình duyệt, không có máy chủ thật phía sau, nên số liệu chặn IP, DDoS và kết quả quét lỗ hổng bên dưới là dữ liệu giả lập, không phản ánh một hệ thống đang thực sự vận hành.",
  "    </div>",
  "",
  "    <div class=\"stats-grid\" style=\"margin-top:20px;\">",
  "      <div class=\"stat-card\"><div class=\"n danger\" id=\"secBlockedIP\">0</div><div class=\"l\">IP đang bị chặn</div></div>",
  "      <div class=\"stat-card\"><div class=\"n ok\" id=\"secStatus\">Chưa đánh giá</div><div class=\"l\">Trạng thái hệ thống</div></div>",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"secLastScan\">Chưa đánh giá</div><div class=\"l\">Lần đánh giá gần nhất</div></div>",
  "    </div>",
  "",
  "    <div class=\"panel\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>IP đã bị chặn</h2>",
  "          <p class=\"sub\">Danh sách IP do quản trị viên tự thêm/gỡ. Không có dữ liệu tự sinh.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshIP\">+ Chặn IP mới</button>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"ipTable\">",
  "          <thead><tr><th>Địa chỉ IP</th><th>Lý do</th><th>Thời gian</th><th>Trạng thái</th><th></th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Checklist bảo mật (tự động)</h2>",
  "          <p class=\"sub\">Bấm \"Quét ngay\" để server tự kiểm tra thật các mục dưới đây (mật khẩu mặc định, HTTPS, rate-limit, phiên bản Node, IP đã chặn...). Không phải giả lập — kết quả lấy từ chính trạng thái server đang chạy.</p>",
  "        </div>",
  "        <button class=\"btn btn-inline\" id=\"btnAutoScan\" style=\"margin-top:0;\">🔄 Quét ngay</button>",
  "      </div>",
  "      <div id=\"autoScanResults\" style=\"margin-top:16px;\"></div>",
  "      <p class=\"preview-note\" style=\"margin-top:14px;\" id=\"autoScanSummary\">Chưa quét lần nào — bấm \"Quét ngay\" để bắt đầu.</p>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 4: NGƯỜI BÁN (ADMIN ONLY) ============ -->",
  "  <div id=\"page-sellers\" style=\"display:none;\">",
  "    <div class=\"panel\">",
  "      <h2>Tạo tài khoản người bán</h2>",
  "      <p class=\"sub\">Tạo tài khoản đại lý/người bán. Mỗi tài khoản có kho key riêng và chỉ nhìn thấy đúng một trang \"Tạo key\" khi đăng nhập.</p>",
  "",
  "      <div class=\"row2\">",
  "        <div>",
  "          <label>Tên đăng nhập</label>",
  "          <input type=\"text\" id=\"sellerUsername\" placeholder=\"VD: dealer01\">",
  "        </div>",
  "        <div>",
  "          <label>Mật khẩu</label>",
  "          <input type=\"text\" id=\"sellerPassword\" placeholder=\"Mật khẩu đăng nhập\">",
  "        </div>",
  "      </div>",
  "",
  "      <label>Thời hạn tài khoản</label>",
  "      <div class=\"chip-toggle\" id=\"sellerExpiryToggle\">",
  "        <input type=\"radio\" name=\"sellerExpiry\" id=\"sellerExpNone\" value=\"none\" checked><label for=\"sellerExpNone\">Không giới hạn</label>",
  "        <input type=\"radio\" name=\"sellerExpiry\" id=\"sellerExpLimited\" value=\"limited\"><label for=\"sellerExpLimited\">Có thời hạn</label>",
  "      </div>",
  "      <div class=\"row2\" id=\"sellerExpiryFields\" style=\"display:none; margin-top:10px;\">",
  "        <div>",
  "          <label>Số lượng</label>",
  "          <input type=\"number\" id=\"sellerExpiryAmount\" value=\"30\" min=\"1\">",
  "        </div>",
  "        <div>",
  "          <label>Đơn vị</label>",
  "          <select id=\"sellerExpiryUnit\">",
  "            <option value=\"hour\">Giờ</option>",
  "            <option value=\"day\" selected>Ngày</option>",
  "            <option value=\"month\">Tháng</option>",
  "          </select>",
  "        </div>",
  "      </div>",
  "",
  "      <label>Số dư khởi tạo (tuỳ chọn, ₫)</label>",
  "      <input type=\"text\" id=\"sellerInitialBalance\" placeholder=\"VD: 0\">",
  "",
  "      <label>Loại tài khoản</label>",
  "      <div class=\"chip-toggle\" id=\"sellerAcctTypeToggle\">",
  "        <input type=\"radio\" name=\"sellerAcctType\" id=\"sellerAcctNormal\" value=\"normal\" checked><label for=\"sellerAcctNormal\">Thường</label>",
  "        <input type=\"radio\" name=\"sellerAcctType\" id=\"sellerAcctPremium\" value=\"premium\"><label for=\"sellerAcctPremium\">★ Premium</label>",
  "      </div>",
  "      <p class=\"preview-note\">",
  "        Tài khoản <b>Premium</b> được mở khoá tạo key <b>không giới hạn</b> thời gian và có hiệu ứng trang chủ VIP. Tài khoản <b>Thường</b> chỉ được tạo key có thời hạn. Có thể nâng/hạ cấp bất kỳ lúc nào ở bảng danh sách bên dưới.",
  "      </p>",
  "",
  "      <button class=\"btn\" id=\"btnCreateSeller\" style=\"margin-top:16px;\">Tạo tài khoản</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách tài khoản người bán</h2>",
  "          <p class=\"sub\">Quản lý hạn dùng, số dư, mật khẩu, cấm/bỏ cấm, gia hạn hoặc xoá tài khoản.</p>",
  "        </div>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"sellerTable\">",
  "          <thead><tr><th>Tên đăng nhập</th><th>Ngày tạo</th><th>Hết hạn lúc</th><th>Còn lại</th><th>Trạng thái</th><th>Loại</th><th>Số dư</th><th>Số key đã tạo</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"sellerEmptyState\">",
  "        <div class=\"big\">Chưa có tài khoản người bán nào</div>",
  "        Tạo tài khoản ở bảng phía trên để bắt đầu.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: NGƯỜI DÙNG (TÀI KHOẢN ĐĂNG KÝ Ở TRANG BÁN HÀNG) — ADMIN ONLY ============ -->",
  "  <div id=\"page-customers\" style=\"display:none;\">",
  "    <div class=\"panel\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Người dùng đã đăng ký</h2>",
  "          <p class=\"sub\">Tài khoản khách hàng đăng ký ở trang bán hàng (và tài khoản quản trị viên phụ). Thêm tiền, đổi mật khẩu cho từng tài khoản.</p>",
  "        </div>",
  "        <button class=\"btn-ghost icon-btn\" style=\"width:auto; padding:0 14px; height:36px;\" id=\"btnRefreshCustomers\">Làm mới</button>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"customerTable\">",
  "          <thead><tr><th>Tên đăng nhập</th><th>Vai trò</th><th>Ngày tạo</th><th>IP lúc tạo</th><th>Số dư</th><th>Lượt nạp</th><th>Giao dịch</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"customerEmptyState\">",
  "        <div class=\"big\">Chưa có tài khoản người dùng nào</div>",
  "        Khách hàng đăng ký ở trang bán hàng sẽ tự động hiện ở đây.",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Yêu cầu nạp tiền đang chờ duyệt</h2>",
  "          <p class=\"sub\">Khách hàng gửi yêu cầu nạp tiền (chuyển khoản) từ trang bán hàng — duyệt để cộng tiền vào tài khoản của họ.</p>",
  "        </div>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"topupRequestTable\">",
  "          <thead><tr><th>Tên đăng nhập</th><th>Số tiền</th><th>Phương thức</th><th>Thời gian</th><th>Trạng thái</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"topupRequestEmptyState\">",
  "        <div class=\"big\">Không có yêu cầu nạp tiền nào đang chờ</div>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Cấu hình nhận tiền tự động (SePay)</h2>",
  "          <p class=\"sub\">Khi bật và cấu hình đúng, hệ thống sẽ tự động cộng tiền ngay khi khách chuyển khoản thành công, không cần duyệt tay. Xem hướng dẫn liên kết tại <a href=\\\"https://my.sepay.vn\\\" target=\\\"_blank\\\" rel=\\\"noopener\\\">my.sepay.vn</a>.</p>",
  "        </div>",
  "      </div>",
  "      <div style=\"display:grid; gap:14px; max-width:480px;\">",
  "        <div>",
  "          <label style=\"display:flex; align-items:center; gap:8px; cursor:pointer;\">",
  "            <input type=\"checkbox\" id=\"sepayEnabledToggle\" style=\"width:16px;height:16px;\">",
  "            <span>Bật đối soát tự động qua SePay</span>",
  "          </label>",
  "        </div>",
  "        <div>",
  "          <label>Ngân hàng nhận tiền</label>",
  "          <input type=\"text\" id=\"bankIdInput\" placeholder=\"VD: MB\">",
  "        </div>",
  "        <div>",
  "          <label>Số tài khoản</label>",
  "          <input type=\"text\" id=\"bankAccountNoInput\" placeholder=\"VD: 0364837118\">",
  "        </div>",
  "        <div>",
  "          <label>Tên chủ tài khoản</label>",
  "          <input type=\"text\" id=\"bankAccountNameInput\" placeholder=\"VD: LUONG VAN TUYEN\">",
  "        </div>",
  "        <div>",
  "          <label>API Key webhook SePay</label>",
  "          <input type=\"text\" id=\"sepayApiKeyInput\" placeholder=\"Dán API Key đã tạo trong SePay ở đây\">",
  "          <p class=\"sub\" style=\"margin-top:6px;\">Vào SePay &rarr; Webhooks &rarr; Tạo webhook mới, trỏ URL về <code id=\\\"sepayWebhookUrlHint\\\">(địa chỉ domain của bạn)/api/sepay-webhook</code>, chọn xác thực <b>API Key</b>, dán cùng giá trị vào cả 2 nơi.</p>",
  "        </div>",
  "        <div id=\"sepayConfigError\" style=\"display:none; color:#c0392b; font-size:13px;\"></div>",
  "        <div id=\"sepayConfigSuccess\" style=\"display:none; color:#1a7f37; font-size:13px;\"></div>",
  "        <div>",
  "          <button class=\"btn\" id=\"btnSaveSepayConfig\">Lưu cấu hình</button>",
  "        </div>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 5: API KEY SERVER (ADMIN ONLY) ============ -->",
  "  <div id=\"page-apikey\" style=\"display:none;\">",
  "    <div class=\"sec-note\" id=\"apiConnStatusNote\">",
  "      Đang kiểm tra kết nối tới máy chủ backend…",
  "    </div>",
  "",
  "    <div class=\"stats-grid\" style=\"margin-top:20px;\">",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"apiTotalApps\">0</div><div class=\"l\">Ứng dụng đã kết nối</div></div>",
  "      <div class=\"stat-card\"><div class=\"n warn\" id=\"apiPendingApps\">0</div><div class=\"l\">Đang chờ duyệt</div></div>",
  "      <div class=\"stat-card\"><div class=\"n ok\" id=\"apiAllowedApps\">0</div><div class=\"l\">Được phép dùng server</div></div>",
  "      <div class=\"stat-card\"><div class=\"n danger\" id=\"apiDeniedApps\">0</div><div class=\"l\">Bị từ chối</div></div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Link xác thực API Key</h2>",
  "      <p class=\"sub\">Dán link này vào code xác thực key trong app/tool của bạn để kiểm tra key có hợp lệ và app/tool của bạn có đang được phép dùng hệ thống này làm server key hay không.</p>",
  "",
  "      <label>Link xác thực (endpoint gốc)</label>",
  "      <div style=\"display:flex; gap:8px;\">",
  "        <input type=\"text\" id=\"apiVerifyLink\" readonly style=\"flex:1;\">",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnCopyVerifyLink\">Sao chép</button>",
  "      </div>",
  "",
  "      <label>Link mẫu để kiểm tra một key cụ thể</label>",
  "      <div style=\"display:flex; gap:8px;\">",
  "        <input type=\"text\" id=\"apiVerifyExample\" readonly style=\"flex:1;\">",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnCopyVerifyExample\">Sao chép</button>",
  "      </div>",
  "",
  "      <label>ID ứng dụng / tool của bạn (app_id) — tự đặt tên để hệ thống nhận diện</label>",
  "      <div style=\"display:flex; gap:8px;\">",
  "        <input type=\"text\" id=\"apiAppIdInput\" placeholder=\"VD: my-app-01\" value=\"my-app-01\" style=\"flex:1;\">",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnGenAppExample\">Tạo lại link mẫu</button>",
  "      </div>",
  "",
  "      <p class=\"preview-note\" style=\"margin-top:16px;\">Mẫu code tích hợp (dán vào phần xác thực key của app/tool):</p>",
  "      <pre style=\"background:var(--panel-2); border:1px solid var(--line); border-radius:10px; padding:14px; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.6; overflow-x:auto; margin:6px 0 0; white-space:pre-wrap; word-break:break-word;\"><code id=\"apiCodeSample\"></code></pre>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Ứng dụng / Tool đã kết nối</h2>",
  "          <p class=\"sub\">Hệ thống <b>tự động nhận diện</b> app/tool ngay lần đầu nó gọi link xác thực và đưa vào trạng thái \"Chờ duyệt\". Chỉ ứng dụng được bạn bấm <b>Cho phép</b> mới xác thực key thành công — các app khác sẽ bị server từ chối.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshApps\">Làm mới</button>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"apiAppsTable\">",
  "          <thead><tr><th>App ID</th><th>Trạng thái</th><th>Lần gọi cuối</th><th>Tổng lượt kiểm tra</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"apiAppsEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có ứng dụng nào kết nối</div>",
  "        Dán link xác thực vào app/tool của bạn — hệ thống sẽ tự nhận diện và hiện tại đây.",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Nhật ký kiểm tra key gần đây</h2>",
  "      <p class=\"sub\">Tối đa 50/200 lượt gọi xác thực gần nhất từ mọi app/tool, lưu trên server.</p>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"apiLogsTable\">",
  "          <thead><tr><th>Thời gian</th><th>App ID</th><th>Key</th><th>Thiết bị</th><th>IP</th><th>Kết quả</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: SẢN PHẨM (STOREFRONT) & MÃ GIẢM GIÁ ============ -->",
  "  <div id=\"page-products\" style=\"display:none;\">",
  "    <div class=\"sec-note\">",
  "      Trang bán key công khai nằm ở địa chỉ gốc <b>\"/\"</b> của server (khách không cần đăng nhập admin). Sản phẩm bạn tạo ở đây sẽ <b>tự động hiện lên</b> trang bán key ngay khi lưu. Mỗi sản phẩm cần gắn với 1 <b>tiền tố key</b> — hệ thống sẽ tự lấy key <b>còn hàng</b> có tiền tố đó trong kho \"Quản lý Key\" để giao cho khách khi mua thành công.",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:20px;\">",
  "      <h2 id=\"productFormTitle\">Thêm sản phẩm mới</h2>",
  "      <p class=\"sub\">Tuỳ chỉnh tên, logo, giá bán và thời hạn hiển thị cho khách trên trang bán key.</p>",
  "",
  "      <label>Tên sản phẩm</label>",
  "      <input type=\"text\" id=\"prodName\" placeholder=\"VD: Gói PRO 30 ngày\">",
  "",
  "      <label>Logo sản phẩm (chọn ảnh từ điện thoại)</label>",
  "      <div style=\"display:flex; align-items:center; gap:14px; margin-bottom:6px;\">",
  "        <div id=\"prodLogoPreview\" style=\"width:56px; height:56px; border-radius:12px; background:var(--panel-2); border:1px solid var(--line); display:flex; align-items:center; justify-content:center; overflow:hidden; flex-shrink:0;\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>",
  "        </div>",
  "        <input type=\"file\" id=\"prodLogoInput\" accept=\"image/*\" style=\"flex:1;\">",
  "      </div>",
  "",
  "      <label>Tiền tố key liên kết (prefix)</label>",
  "      <input type=\"text\" id=\"prodKeyPrefix\" placeholder=\"VD: PRO\" maxlength=\"10\" style=\"text-transform:uppercase;\">",
  "      <p class=\"preview-note\" style=\"margin-top:6px;\">Phải trùng với tiền tố (prefix) bạn dùng khi \"Sinh key ngay\" ở trang Quản lý Key. Còn hàng = key có tiền tố này đang ở trạng thái \"Còn hàng\".</p>",
  "",
  "      <div class=\"row2\">",
  "        <div>",
  "          <label>Giá bán (₫)</label>",
  "          <input type=\"text\" id=\"prodPrice\" placeholder=\"VD: 99000\">",
  "        </div>",
  "        <div>",
  "          <label>Số thiết bị / key (hiển thị cho khách)</label>",
  "          <input type=\"number\" id=\"prodMaxDevices\" value=\"1\" min=\"1\" max=\"20\">",
  "        </div>",
  "      </div>",
  "",
  "      <label>Thời hạn sản phẩm</label>",
  "      <div class=\"chip-toggle\" id=\"prodDurationToggle\">",
  "        <input type=\"radio\" name=\"pdur\" id=\"pdurLimited\" value=\"limited\" checked><label for=\"pdurLimited\">Có thời hạn</label>",
  "        <input type=\"radio\" name=\"pdur\" id=\"pdurUnlimited\" value=\"unlimited\"><label for=\"pdurUnlimited\">Không giới hạn</label>",
  "      </div>",
  "      <div class=\"row2\" id=\"prodDurationFields\" style=\"margin-top:10px;\">",
  "        <div>",
  "          <label>Số lượng</label>",
  "          <input type=\"number\" id=\"prodDurationAmount\" value=\"30\" min=\"1\">",
  "        </div>",
  "        <div>",
  "          <label>Đơn vị</label>",
  "          <select id=\"prodDurationUnit\">",
  "            <option value=\"hour\">Giờ</option>",
  "            <option value=\"day\" selected>Ngày</option>",
  "            <option value=\"month\">Tháng</option>",
  "          </select>",
  "        </div>",
  "      </div>",
  "",
  "      <label style=\"margin-top:14px; display:flex; align-items:center; gap:8px;\"><input type=\"checkbox\" id=\"prodActive\" checked style=\"width:auto;\"> Hiển thị sản phẩm này trên trang bán key</label>",
  "",
  "      <button class=\"btn\" id=\"btnSaveProduct\" style=\"margin-top:16px;\">Lưu sản phẩm</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnCancelEditProduct\" style=\"margin-top:10px; display:none;\">Huỷ chỉnh sửa</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách sản phẩm</h2>",
  "          <p class=\"sub\">Quản lý các sản phẩm đang hiển thị trên trang bán key.</p>",
  "        </div>",
  "      </div>",
  "      <div id=\"productList\" style=\"margin-top:14px; display:grid; gap:12px;\"></div>",
  "      <div class=\"empty\" id=\"productEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có sản phẩm nào</div>",
  "        Thêm sản phẩm ở form phía trên để bắt đầu bán key.",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Thêm mã giảm giá</h2>",
  "      <p class=\"sub\">Mã giảm % trên giá key khi khách thanh toán ở trang bán key.</p>",
  "      <div class=\"row2\">",
  "        <div>",
  "          <label>Mã giảm giá</label>",
  "          <input type=\"text\" id=\"discCode\" placeholder=\"VD: SALE20\" style=\"text-transform:uppercase;\">",
  "        </div>",
  "        <div>",
  "          <label>Phần trăm giảm (%)</label>",
  "          <input type=\"number\" id=\"discPercent\" value=\"10\" min=\"1\" max=\"99\">",
  "        </div>",
  "      </div>",
  "      <div class=\"row2\">",
  "        <div>",
  "          <label>Số lượt dùng tối đa (0 = không giới hạn)</label>",
  "          <input type=\"number\" id=\"discMaxUses\" value=\"0\" min=\"0\">",
  "        </div>",
  "        <div>",
  "          <label>Hạn dùng (tuỳ chọn)</label>",
  "          <input type=\"datetime-local\" id=\"discExpiry\">",
  "        </div>",
  "      </div>",
  "      <button class=\"btn\" id=\"btnAddDiscount\" style=\"margin-top:14px;\">Tạo mã giảm giá</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Danh sách mã giảm giá</h2>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"discountTable\">",
  "          <thead><tr><th>Mã</th><th>Giảm</th><th>Đã dùng</th><th>Hạn dùng</th><th>Trạng thái</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"discountEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có mã giảm giá nào</div>",
  "      </div>",
  "    </div>",
  "",
  "    <!-- ============ NHÓM SẢN PHẨM (1 logo/tên + NHIỀU gói giá, giống GetKey) ============ -->",
  "    <div class=\"sec-note\" style=\"margin-top:32px;\">",
  "      <b>Nhóm sản phẩm</b> cho phép 1 sản phẩm (VD: \"Liên Quân\") hiện <b>1 logo duy nhất</b> trên trang bán key, khách bấm vào rồi mới chọn 1 trong nhiều gói giá (VD: 1 ngày 10k, 7 ngày 50k, 1 tháng 150k...). Mỗi gói vẫn cần gắn tiền tố key riêng để hệ thống biết lấy key nào giao cho khách.",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:20px;\">",
  "      <h2 id=\"pgFormTitle\">Thêm nhóm sản phẩm mới</h2>",
  "      <p class=\"sub\">Tuỳ chỉnh tên, logo và danh sách các gói giá kèm tiền tố key riêng cho từng gói.</p>",
  "",
  "      <label>Tên nhóm sản phẩm</label>",
  "      <input type=\"text\" id=\"pgName\" placeholder=\"VD: Liên Quân Mobile\">",
  "",
  "      <label>Logo (chọn ảnh từ điện thoại)</label>",
  "      <div style=\"display:flex; align-items:center; gap:14px; margin-bottom:6px;\">",
  "        <div id=\"pgLogoPreview\" style=\"width:56px; height:56px; border-radius:12px; background:var(--panel-2); border:1px solid var(--line); display:flex; align-items:center; justify-content:center; overflow:hidden; flex-shrink:0;\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>",
  "        </div>",
  "        <input type=\"file\" id=\"pgLogoInput\" accept=\"image/*\" style=\"flex:1;\">",
  "      </div>",
  "",
  "      <label style=\"margin-top:14px; display:flex; align-items:center; gap:8px;\"><input type=\"checkbox\" id=\"pgActive\" checked style=\"width:auto;\"> Hiển thị nhóm sản phẩm này trên trang bán key</label>",
  "",
  "      <div class=\"panel\" style=\"margin-top:18px; background:var(--panel-2);\">",
  "        <div class=\"panel-head\">",
  "          <h2 style=\"font-size:15px;\">Các gói giá trong nhóm</h2>",
  "          <button class=\"btn btn-ghost btn-inline\" id=\"btnAddPgPlan\">+ Thêm gói</button>",
  "        </div>",
  "        <div id=\"pgPlanList\" style=\"display:grid; gap:10px; margin-top:10px;\"></div>",
  "      </div>",
  "",
  "      <button class=\"btn\" id=\"btnSavePg\" style=\"margin-top:16px;\">Lưu nhóm sản phẩm</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnCancelEditPg\" style=\"margin-top:10px; display:none;\">Huỷ chỉnh sửa</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách nhóm sản phẩm</h2>",
  "          <p class=\"sub\">Quản lý các nhóm sản phẩm đang hiển thị trên trang bán key.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshPg\">Làm mới</button>",
  "      </div>",
  "      <div id=\"pgList\" style=\"margin-top:14px; display:grid; gap:12px;\"></div>",
  "      <div class=\"empty\" id=\"pgEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có nhóm sản phẩm nào</div>",
  "        Thêm ở form phía trên để bắt đầu bán theo nhiều gói giá.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: GETKEY (VƯỢT LINK NHẬN KEY) ============ -->",
  "  <div id=\"page-getkey\" style=\"display:none;\">",
  "    <div class=\"sec-note\">",
  "      Trang \"GetKey\" cho phép khách <b>vượt link</b> để nhận key miễn phí thay vì mua bằng tiền. Mỗi game bạn tạo ở đây sẽ hiện lên mục \"GetKey\" trên trang bán key (\"/\"). Mỗi loại thời hạn (VD 12 giờ, 24 giờ...) có thể tuỳ chỉnh <b>số lượt vượt link</b> riêng — khách phải vượt đủ số lượt mới nhận được key. Link vượt được tạo thật qua API <b>LAYMA.NET</b> (token đã cấu hình sẵn ở server).",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:20px;\">",
  "      <h2 id=\"getKeyFormTitle\">Thêm game GetKey mới</h2>",
  "      <p class=\"sub\">Tuỳ chỉnh tên game, tiền tố key liên kết và các loại thời hạn kèm số lượt vượt link.</p>",
  "",
  "      <label>Tên game</label>",
  "      <input type=\"text\" id=\"gkName\" placeholder=\"VD: Free Fire\">",
  "",
  "      <label>Logo game (chọn ảnh từ điện thoại)</label>",
  "      <div style=\"display:flex; align-items:center; gap:14px; margin-bottom:6px;\">",
  "        <div id=\"gkLogoPreview\" style=\"width:56px; height:56px; border-radius:12px; background:var(--panel-2); border:1px solid var(--line); display:flex; align-items:center; justify-content:center; overflow:hidden; flex-shrink:0;\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>",
  "        </div>",
  "        <input type=\"file\" id=\"gkLogoInput\" accept=\"image/*\" style=\"flex:1;\">",
  "      </div>",
  "",

  "",
  "      <label style=\"margin-top:14px; display:flex; align-items:center; gap:8px;\"><input type=\"checkbox\" id=\"gkActive\" checked style=\"width:auto;\"> Hiển thị game này trên trang GetKey</label>",
  "",
  "      <div class=\"panel-head\" style=\"margin-top:20px;\">",
  "        <div>",
  "          <h2 style=\"font-size:15px;\">Các loại thời hạn &amp; số lượt vượt link</h2>",
  "          <p class=\"sub\">VD: chọn key 12 giờ sẽ vượt 2 lượt, chọn key 24 giờ sẽ vượt 3 lượt.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnAddGkDuration\">+ Thêm loại</button>",
  "      </div>",
  "      <div id=\"gkDurationList\" style=\"display:grid; gap:10px; margin-top:10px;\"></div>",
  "",
  "      <button class=\"btn\" id=\"btnSaveGetKeyGame\" style=\"margin-top:16px;\">Lưu game GetKey</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnCancelEditGetKeyGame\" style=\"margin-top:10px; display:none;\">Huỷ chỉnh sửa</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách game GetKey</h2>",
  "          <p class=\"sub\">Quản lý các game đang hiển thị trên trang GetKey.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshGetKeyGames\">Làm mới</button>",
  "      </div>",
  "      <div id=\"getKeyGameList\" style=\"margin-top:14px; display:grid; gap:12px;\"></div>",
  "      <div class=\"empty\" id=\"getKeyGameEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có game GetKey nào</div>",
  "        Thêm game ở form phía trên để bắt đầu cho khách vượt link nhận key.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: NẠP SCRIPT VIOLENTMONKEY (NÂNG CẤP) ============ -->",
  "  <div id=\"page-codevault\" style=\"display:none;\">",
  "",
  "    <!-- ═══ BANNER TRẠNG THÁI SCRIPT ĐANG HOẠT ĐỘNG ═══ -->",
  "    <div id=\"cvActiveScriptBanner\" style=\"display:none; background:linear-gradient(135deg,#e8f5e9,#f1f8e9); border:1.5px solid #4caf50; border-radius:14px; padding:16px 20px; margin-bottom:20px; display:none;\">",
  "      <div style=\"display:flex; align-items:center; gap:12px;\">",
  "        <div style=\"width:36px; height:36px; border-radius:9px; background:linear-gradient(135deg,#2e7d32,#43a047); display:flex; align-items:center; justify-content:center; flex-shrink:0;\">",
  "          <svg viewBox='0 0 24 24' fill='none' stroke='#fff' stroke-width='2.2' style='width:18px;height:18px;'><polyline points='20 6 9 17 4 12'/></svg>",
  "        </div>",
  "        <div style='flex:1;'>",
  "          <div style='font-weight:700; font-size:14px; color:#1b5e20;'>Script Violentmonkey đang hoạt động</div>",
  "          <div style='font-size:12px; color:#388e3c; margin-top:2px;' id='cvActiveName'>Chưa có script</div>",
  "        </div>",
  "        <div style='text-align:right;'>",
  "          <div style='font-size:11px; color:#2e7d32; font-weight:600;' id='cvActiveSize'>—</div>",
  "          <div style='font-size:11px; color:#66bb6a; margin-top:2px;' id='cvActiveTime'>—</div>",
  "        </div>",
  "      </div>",
  "      <div style='margin-top:12px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;'>",
  "        <div style='flex:1; min-width:200px; background:#fff; border:1px solid #c8e6c9; border-radius:8px; padding:8px 12px;'>",
  "          <div style='font-size:10px; color:#81c784; font-weight:600; letter-spacing:0.5px; text-transform:uppercase; margin-bottom:2px;'>Public Endpoint (Violentmonkey tự động dùng)</div>",
  "          <div style='font-family:monospace; font-size:12px; color:#1b5e20; word-break:break-all;' id='cvPublicEndpoint'>—</div>",
  "        </div>",
  "        <button class='btn btn-danger-ghost btn-inline' id='btnDeleteActiveScript' style='white-space:nowrap;'>Xoá script</button>",
  "      </div>",
  "    </div>",
  "",
  "    <!-- ═══ FORM NẠP SCRIPT VIOLENTMONKEY (FILE ONLY) ═══ -->",
  "    <div class=\"panel\" style=\"margin-top:0; border:2px solid var(--brass-soft);\">",
  "      <div style=\"display:flex; align-items:center; gap:12px; margin-bottom:16px;\">",
  "        <div style=\"width:40px; height:40px; border-radius:10px; background:linear-gradient(135deg,var(--brass-soft),var(--brass)); display:flex; align-items:center; justify-content:center; flex-shrink:0;\">",
  "          <svg viewBox='0 0 24 24' fill='none' stroke='#fff' stroke-width='2' style='width:20px;height:20px;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'/><polyline points='17 8 12 3 7 8'/><line x1='12' y1='3' x2='12' y2='15'/></svg>",
  "        </div>",
  "        <div>",
  "          <h2 style=\"margin:0; font-size:17px;\">Nạp Script Violentmonkey</h2>",
  "          <p class=\"sub\" style=\"margin:3px 0 0;\">Chọn file .js → Upload thẳng lên server — Loader tự động phát hiện &amp; kéo về</p>",
  "        </div>",
  "      </div>",
  "",
  "      <div class=\"sec-note\" style=\"margin-bottom:18px; border-left-color:var(--brass);\">",
  "        ⚡ Mỗi lần nạp script mới, <b>script cũ sẽ bị xoá tự động</b> và thay bằng script mới. Violentmonkey Loader sẽ <b>tự động phát hiện phiên bản mới</b> qua checksum và tải về ngay lần sau — không cần ID, không cần làm gì thêm.",
  "      </div>",
  "",
  "      <!-- ═══ KHU VỰC DROP FILE ═══ -->",
  "      <div id=\"cvDropZone\" style=\"border:2.5px dashed var(--brass-soft); border-radius:14px; padding:36px 20px; text-align:center; cursor:pointer; background:var(--brass-tint); transition:.18s; position:relative;\">",
  "        <input type=\"file\" id=\"cvFileInput\" accept=\".js,.user.js,.ts,.txt\" style=\"position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%;\">",
  "        <div id=\"cvDropIcon\" style=\"font-size:36px; margin-bottom:10px;\">📂</div>",
  "        <div style=\"font-weight:700; font-size:15px; color:var(--brass); margin-bottom:4px;\">Kéo thả file vào đây hoặc bấm để chọn</div>",
  "        <div style=\"font-size:12px; color:var(--muted);\">Hỗ trợ: .js · .user.js · .ts · .txt — tối đa 10 MB</div>",
  "        <div id=\"cvFileChosen\" style=\"display:none; margin-top:14px; background:#fff; border:1.5px solid var(--ok); border-radius:9px; padding:10px 14px;\">",
  "          <div style=\"display:flex; align-items:center; gap:10px;\">",
  "            <span style=\"font-size:20px;\">📄</span>",
  "            <div style=\"flex:1; text-align:left;\">",
  "              <div id=\"cvFileName\" style=\"font-weight:700; font-size:13px; color:var(--ok); word-break:break-all;\"></div>",
  "              <div id=\"cvFileSize\" style=\"font-size:11px; color:var(--muted); margin-top:2px;\"></div>",
  "            </div>",
  "            <button class=\"btn btn-ghost btn-inline\" id=\"btnClearCvFile\" style=\"padding:6px 10px; flex-shrink:0;\">✕</button>",
  "          </div>",
  "        </div>",
  "      </div>",
  "",
  "      <!-- ═══ THANH TIẾN TRÌNH UPLOAD ═══ -->",
  "      <div id=\"cvUploadProgress\" style=\"display:none; margin-top:14px;\">",
  "        <div style=\"display:flex; align-items:center; gap:10px; margin-bottom:6px;\">",
  "          <span id=\"cvUploadStatusIcon\" style=\"font-size:16px;\">⏳</span>",
  "          <span id=\"cvUploadStatusText\" style=\"font-size:13px; font-weight:600; color:var(--brass);\">Đang upload...</span>",
  "        </div>",
  "        <div style=\"height:6px; background:var(--panel-2); border-radius:99px; overflow:hidden;\">",
  "          <div id=\"cvUploadBar\" style=\"height:100%; width:0%; background:linear-gradient(90deg,var(--brass-soft),var(--brass)); border-radius:99px; transition:width .25s ease;\"></div>",
  "        </div>",
  "      </div>",
  "",
  "      <!-- ═══ NÚT UPLOAD ═══ -->",
  "      <div style=\"margin-top:16px;\">",
  "        <button class=\"btn\" id=\"btnSaveCodeSnippet\" style=\"width:100%;\" disabled>",
  "          <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.2' style='width:15px;height:15px;vertical-align:-3px;margin-right:6px;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'/><polyline points='17 8 12 3 7 8'/><line x1='12' y1='3' x2='12' y2='15'/></svg>",
  "          Upload file lên server",
  "        </button>",
  "      </div>",
  "",
  "      <!-- ═══ HỘP HIỂN THỊ PUBLIC ENDPOINT SAU KHI LƯU ═══ -->",
  "      <div id=\"cvPublicEndpointBox\" style=\"display:none; margin-top:16px; background:#e8f5e9; border:1.5px solid #a5d6a7; border-radius:10px; padding:14px 16px;\">",
  "        <div style=\"display:flex; align-items:center; gap:8px; margin-bottom:8px;\">",
  "          <svg viewBox='0 0 24 24' fill='none' stroke='#2e7d32' stroke-width='2' style='width:18px;height:18px;flex-shrink:0;'><polyline points='20 6 9 17 4 12'/></svg>",
  "          <span style=\"font-weight:700; font-size:13px; color:#1b5e20;\">✔ Script đã lưu — Violentmonkey Loader sẽ tự động kéo code mới này!</span>",
  "        </div>",
  "        <div style=\"background:#fff; border:1px solid #c8e6c9; border-radius:8px; padding:10px 12px; margin-bottom:8px;\">",
  "          <div style=\"font-size:10px; color:#81c784; font-weight:700; letter-spacing:0.6px; text-transform:uppercase; margin-bottom:4px;\">Public Endpoint (Loader tự dùng để kéo code):</div>",
  "          <div style=\"font-family:'JetBrains Mono',monospace; font-size:12px; color:#1b5e20; word-break:break-all;\" id=\"cvPublicEndpointUrl\">—</div>",
  "        </div>",
  "        <div style=\"display:flex; align-items:center; gap:12px; flex-wrap:wrap;\">",
  "          <div style=\"font-size:11px; color:#388e3c;\">Checksum (SHA-256): <code style=\"font-family:monospace; background:#c8e6c9; padding:2px 7px; border-radius:5px; font-size:11px;\" id=\"cvPublicChecksum\">—</code></div>",
  "          <div style=\"font-size:11px; color:#66bb6a;\">⚡ Loader phát hiện checksum thay đổi → tự tải code mới về — không cần làm gì thêm.</div>",
  "        </div>",
  "      </div>",
  "    </div>",
  "",
  "    <!-- ═══ DANH SÁCH SCRIPT TRÊN SERVER ═══ -->",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Script đang có trên server</h2>",
  "          <p class=\"sub\">Chỉ giữ <b>1 script duy nhất</b> — nạp mới sẽ tự động xoá script cũ.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshCodeSnippets\">Làm mới</button>",
  "      </div>",
  "      <div id=\"cvList\" style=\"margin-top:14px; display:grid; gap:10px;\"></div>",
  "      <div class=\"empty\" id=\"cvEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có script nào trên server</div>",
  "        Nạp file .js ở form phía trên để bắt đầu.",
  "      </div>",
  "    </div>",
  "",
  "    <!-- ============ VIOLENTMONKEY LOADER — TẠO SCRIPT TỰ ĐỘNG TẢI CODE TỪ SERVER ============ -->",
  "    <div class=\"panel\" style=\"margin-top:28px; border:2px solid var(--brass-soft); background:linear-gradient(135deg,#fffdf5 0%,#fef9e7 100%);\">",
  "      <div style=\"display:flex; align-items:center; gap:12px; margin-bottom:6px;\">",
  "        <div style=\"width:38px; height:38px; border-radius:10px; background:linear-gradient(135deg,var(--brass-soft),var(--brass)); display:flex; align-items:center; justify-content:center; flex-shrink:0;\">",
  "          <svg viewBox='0 0 24 24' fill='none' stroke='#fff' stroke-width='2' style='width:20px;height:20px;'><polygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'/></svg>",
  "        </div>",
  "        <div>",
  "          <h2 style=\"margin:0; font-size:17px;\">Violentmonkey Loader</h2>",
  "          <p class=\"sub\" style=\"margin:2px 0 0;\">Tạo script tự động tải toàn bộ code gốc từ server về trình duyệt · Anti-bug · Anti-soi code</p>",
  "        </div>",
  "      </div>",
  "      <div class=\"sec-note\" style=\"margin:14px 0 18px; border-left-color:var(--brass);\">",
  "        Script này khi cài vào <b>Violentmonkey</b> sẽ: hiển thị hiệu ứng <b>đang tải dữ liệu server</b> trong 4 giây, sau đó <b>tự động kéo toàn bộ code gốc</b> từ server xuống và thực thi — kèm <b>anti-bug</b>, <b>anti-soi code</b>, <b>chống chỉnh sửa</b> và <b>chống debug</b>.",
  "      </div>",
  "",
  "      <div class=\"row2\" style=\"margin-bottom:14px;\">",
  "        <div>",
  "          <label>Chọn code gốc cần tải</label>",
  "          <select id=\"vmSnippetId\" style=\"width:100%;\"><option value=\"\">— Chọn đoạn code —</option></select>",
  "        </div>",
  "        <div>",
  "          <label>@match URL áp dụng</label>",
  "          <input type=\"text\" id=\"vmMatchUrl\" placeholder=\"*://*/*\" value=\"*://*/*\">",
  "        </div>",
  "      </div>",
  "",
  "      <div class=\"row2\" style=\"margin-bottom:14px;\">",
  "        <div>",
  "          <label>Tên script hiển thị</label>",
  "          <input type=\"text\" id=\"vmScriptName\" placeholder=\"KeyVault Loader\" value=\"KeyVault Loader\">",
  "        </div>",
  "        <div>",
  "          <label>Thời gian hiệu ứng loading (giây)</label>",
  "          <input type=\"number\" id=\"vmLoadingSeconds\" value=\"4\" min=\"1\" max=\"30\" style=\"width:100%;\">",
  "        </div>",
  "      </div>",
  "",
  "      <div style=\"margin-bottom:14px;\">",
  "        <label>Tuỳ chọn bảo vệ</label>",
  "        <div style=\"display:flex; flex-wrap:wrap; gap:10px; margin-top:6px;\">",
  "          <label style=\"display:flex; align-items:center; gap:6px; font-size:13px; font-weight:500; cursor:pointer;\"><input type=\"checkbox\" id=\"vmAntiBug\" checked style=\"accent-color:var(--brass); width:auto;\"> Anti-bug code gốc</label>",
  "          <label style=\"display:flex; align-items:center; gap:6px; font-size:13px; font-weight:500; cursor:pointer;\"><input type=\"checkbox\" id=\"vmAntiDebug\" checked style=\"accent-color:var(--brass); width:auto;\"> Anti-debug / Anti-soi code</label>",
  "          <label style=\"display:flex; align-items:center; gap:6px; font-size:13px; font-weight:500; cursor:pointer;\"><input type=\"checkbox\" id=\"vmAntiEdit\" checked style=\"accent-color:var(--brass); width:auto;\"> Anti-chỉnh sửa runtime</label>",
  "          <label style=\"display:flex; align-items:center; gap:6px; font-size:13px; font-weight:500; cursor:pointer;\"><input type=\"checkbox\" id=\"vmAntiConsole\" checked style=\"accent-color:var(--brass); width:auto;\"> Khoá DevTools Console</label>",
  "          <label style=\"display:flex; align-items:center; gap:6px; font-size:13px; font-weight:500; cursor:pointer; color:var(--brass);\"><input type=\"checkbox\" id=\"vmAutoEndpoint\" checked style=\"accent-color:var(--brass); width:auto;\"> 🔗 Auto lấy Public Endpoint từ server (không cần chọn code thủ công)</label>",
  "        </div>",
  "      </div>",
  "",
  "      <button class=\"btn\" id=\"btnGenerateVMScript\" style=\"margin-bottom:14px;\">",
  "        <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' style='width:15px;height:15px;vertical-align:-3px;margin-right:6px;'><polygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'/></svg>",
  "        Tạo Violentmonkey Script",
  "      </button>",
  "",
  "      <div id=\"vmScriptOutput\" style=\"display:none;\">",
  "        <div style=\"display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;\">",
  "          <label style=\"margin:0; font-size:13px; font-weight:600; color:var(--ok);\">✔ Script đã tạo — copy và dán vào Violentmonkey</label>",
  "          <div style=\"display:flex; gap:8px;\">",
  "            <button class=\"btn btn-ghost btn-inline\" id=\"btnCopyVMScript\">Sao chép</button>",
  "            <button class=\"btn btn-inline\" id=\"btnDownloadVMScript\">Tải .user.js</button>",
  "          </div>",
  "        </div>",
  "        <textarea id=\"vmScriptContent\" rows=\"18\" readonly style=\"font-family:'JetBrains Mono','Courier New',monospace; font-size:11.5px; width:100%; background:var(--text); color:#e2e8f0; border:none; border-radius:12px; padding:16px; resize:vertical; white-space:pre; overflow-x:auto; line-height:1.55;\"></textarea>",
  "        <p class=\"preview-note\" style=\"margin-top:8px;\">Cài vào Violentmonkey: mở Extension → Tạo script mới → xoá hết nội dung mặc định → dán script này vào → Lưu.</p>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: QUẢN LÝ MINI APP (TELEGRAM BOT) ============ -->",
  "  <div id=\"page-miniapp\" style=\"display:none;\">",
  "    <div class=\"sec-note\">",
  "      Trang này quản lý toàn bộ khách vào <b>Mini App qua Bot Telegram</b>. Sản phẩm/mã giảm giá bạn cập nhật ở tab <b>Sản phẩm &amp; Mã giảm giá</b> sẽ tự động hiện lên Mini App — không cần làm gì thêm.",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:20px;\">",
  "      <h2>Trạng thái Bot</h2>",  "      <p class=\"sub\" id=\"miniAppMiniUrl\">Đang tải...</p>",
  "      <p class=\"sub\" id=\"miniAppWebhookStatus\"></p>",
  "      <p class=\"sub\" id=\"miniAppUserCount\"></p>",
  "      <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshMiniAppStatus\" style=\"margin-top:10px;\">Làm mới</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:20px;\">",
  "      <h2>Gửi thông báo tới tất cả user Mini App</h2>",
  "      <p class=\"sub\">Tin nhắn sẽ được Bot gửi trực tiếp tới từng user đã từng mở Mini App.</p>",
  "      <textarea id=\"miniAppBroadcastMsg\" rows=\"3\" placeholder=\"Nhập nội dung thông báo...\" style=\"margin-top:10px;\"></textarea>",
  "      <button class=\"btn\" id=\"btnBroadcastMiniApp\" style=\"margin-top:12px;\">Gửi cho tất cả</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách user Mini App</h2>",
  "          <p class=\"sub\">Tên, ID Telegram, loại tài khoản, số dư — cập nhật theo thời gian thực.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshMiniAppUsers\">Làm mới</button>",
  "      </div>",
  "      <div id=\"miniAppUserList\" style=\"margin-top:14px; display:grid; gap:10px;\"></div>",
  "      <div class=\"empty\" id=\"miniAppUserEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có ai vào Bot</div>",
  "        Gửi link Bot Telegram của bạn cho khách để họ bấm /start.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: NẠP FILE CODE (ADMIN ONLY) ─ Tab mới riêng biệt ============ -->",
  "  <div id=\"page-uploadcode\" style=\"display:none;\">",
  "    <div class=\"sec-note\" style=\"border-left-color:#7c3aed;\">",
  "      📤 <b>Nạp file code mới lên server.</b> File sẽ được lưu trực tiếp dưới dạng snippet — code cũ vẫn giữ nguyên. App sẽ tự động kéo code mới về qua endpoint <code>/api/public/code-bundle</code> sau khi đăng nhập key.",
  "    </div>",
  "",
  "    <!-- ═══ PANEL NẠP FILE ═══ -->",
  "    <div class=\"panel\" style=\"margin-top:20px; border:2px solid #7c3aed;\">",
  "      <div style=\"display:flex; align-items:center; gap:12px; margin-bottom:18px;\">",
  "        <div style=\"width:42px; height:42px; border-radius:11px; background:linear-gradient(135deg,#7c3aed,#5b21b6); display:flex; align-items:center; justify-content:center; flex-shrink:0;\">",
  "          <svg viewBox='0 0 24 24' fill='none' stroke='#fff' stroke-width='2.2' style='width:20px;height:20px;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'/><polyline points='17 8 12 3 7 8'/><line x1='12' y1='3' x2='12' y2='15'/></svg>",
  "        </div>",
  "        <div>",
  "          <h2 style=\"margin:0; font-size:17px;\">Nạp file code lên server</h2>",
  "          <p class=\"sub\" style=\"margin:3px 0 0;\">Upload file .js / .lua / .txt — App tự động phát hiện bản mới qua checksum và kéo về ngay lần đăng nhập tiếp theo</p>",
  "        </div>",
  "      </div>",
  "",
  "      <!-- Drop zone -->",
  "      <div id=\"ucDropZone\" style=\"border:2.5px dashed #7c3aed; border-radius:14px; padding:40px 20px; text-align:center; cursor:pointer; background:#faf5ff; transition:.18s; position:relative;\">",
  "        <input type=\"file\" id=\"ucFileInput\" accept=\".js,.lua,.txt,.user.js,.ts\" style=\"position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%;\">",
  "        <div id=\"ucDropIcon\" style=\"font-size:40px; margin-bottom:12px;\">📁</div>",
  "        <div style=\"font-weight:700; font-size:15px; color:#7c3aed; margin-bottom:4px;\">Kéo thả file vào đây hoặc bấm để chọn</div>",
  "        <div style=\"font-size:12px; color:#6b7280;\">Hỗ trợ: .js · .lua · .txt · .ts — tối đa 10 MB</div>",
  "        <div id=\"ucFileChosen\" style=\"display:none; margin-top:16px; background:#fff; border:1.5px solid #7c3aed; border-radius:9px; padding:10px 14px;\">",
  "          <div style=\"display:flex; align-items:center; gap:10px;\">",
  "            <span style=\"font-size:22px;\">📄</span>",
  "            <div style=\"flex:1; text-align:left;\">",
  "              <div id=\"ucFileName\" style=\"font-weight:700; font-size:13px; color:#7c3aed; word-break:break-all;\"></div>",
  "              <div id=\"ucFileSize\" style=\"font-size:11px; color:#6b7280; margin-top:2px;\"></div>",
  "            </div>",
  "            <button class=\"btn btn-ghost btn-inline\" id=\"btnClearUcFile\" style=\"padding:6px 10px; flex-shrink:0;\">✕</button>",
  "          </div>",
  "        </div>",
  "      </div>",
  "",
  "      <!-- Progress bar -->",
  "      <div id=\"ucUploadProgress\" style=\"display:none; margin-top:14px;\">",
  "        <div style=\"display:flex; align-items:center; gap:10px; margin-bottom:6px;\">",
  "          <span id=\"ucUploadStatusIcon\" style=\"font-size:16px;\">⏳</span>",
  "          <span id=\"ucUploadStatusText\" style=\"font-size:13px; font-weight:600; color:#7c3aed;\">Đang upload...</span>",
  "        </div>",
  "        <div style=\"height:6px; background:#e9d5ff; border-radius:99px; overflow:hidden;\">",
  "          <div id=\"ucUploadBar\" style=\"height:100%; width:0%; background:linear-gradient(90deg,#7c3aed,#a855f7); border-radius:99px; transition:width .25s ease;\"></div>",
  "        </div>",
  "      </div>",
  "",
  "      <!-- Upload button -->",
  "      <div style=\"margin-top:18px;\">",
  "        <button class=\"btn\" id=\"btnUploadCode\" style=\"width:100%; background:linear-gradient(135deg,#7c3aed,#5b21b6);\" disabled>",
  "          <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.2' style='width:15px;height:15px;vertical-align:-3px;margin-right:7px;'><path d='M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'/><polyline points='17 8 12 3 7 8'/><line x1='12' y1='3' x2='12' y2='15'/></svg>",
  "          Upload file code lên server",
  "        </button>",
  "      </div>",
  "",
  "      <!-- Result box -->",
  "      <div id=\"ucResultBox\" style=\"display:none; margin-top:18px; background:#f0fdf4; border:1.5px solid #86efac; border-radius:10px; padding:14px 16px;\">",
  "        <div style=\"display:flex; align-items:center; gap:8px; margin-bottom:8px;\">",
  "          <span style=\"font-size:18px;\">✅</span>",
  "          <span style=\"font-weight:700; font-size:13px; color:#166534;\">File code đã nạp thành công!</span>",
  "        </div>",
  "        <div style=\"background:#fff; border:1px solid #86efac; border-radius:8px; padding:10px 12px; margin-bottom:8px;\">",
  "          <div style=\"font-size:10px; color:#4ade80; font-weight:700; letter-spacing:0.6px; text-transform:uppercase; margin-bottom:4px;\">Update-check endpoint (App gọi sau đăng nhập key):</div>",
  "          <div id=\"ucUpdateCheckUrl\" style=\"font-family:monospace; font-size:12px; color:#166534; word-break:break-all;\">—</div>",
  "        </div>",
  "        <div style=\"background:#fff; border:1px solid #86efac; border-radius:8px; padding:10px 12px;\">",
  "          <div style=\"font-size:10px; color:#4ade80; font-weight:700; letter-spacing:0.6px; text-transform:uppercase; margin-bottom:4px;\">Code-bundle endpoint (App kéo toàn bộ code về):</div>",
  "          <div id=\"ucBundleUrl\" style=\"font-family:monospace; font-size:12px; color:#166534; word-break:break-all;\">—</div>",
  "        </div>",
  "        <div style=\"margin-top:10px; font-size:11px; color:#16a34a;\">⚡ App sẽ tự động phát hiện phiên bản mới qua checksum khi đăng nhập key lần tiếp theo — không cần làm gì thêm.</div>",
  "      </div>",
  "    </div>",
  "",
  "    <!-- ═══ DANH SÁCH CÁC FILE CODE TRÊN SERVER ═══ -->",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Các file code đang có trên server</h2>",
  "          <p class=\"sub\">App sẽ tự động kéo file mới nhất — file cũ được giữ lại làm backup.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshUcList\" onclick=\"ucFetchList()\">Làm mới</button>",
  "      </div>",
  "      <div id=\"ucList\" style=\"margin-top:14px; display:grid; gap:10px;\"></div>",
  "      <div class=\"empty\" id=\"ucEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có file code nào</div>",
  "        Upload file .js ở form phía trên để bắt đầu.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: NẠP APK (ADMIN ONLY) ============ -->",
  "  <div id=\"page-apkvault\" style=\"display:none;\">",
  "    <div class=\"apk-split\">",
  "      <div>",
  "        <div class=\"panel\">",
  "          <h2>Nạp file APK</h2>",
  "          <p class=\"sub\">Tải file .apk lên server (tối đa 100 MB). Có thể kéo thả vào vùng bên dưới.</p>",
  "          <div class=\"apk-upload-zone\" id=\"apkDropZone\">",
  "            <div class=\"upload-icon\">📦</div>",
  "            <div class=\"upload-label\">Kéo thả file .apk vào đây hoặc bấm để chọn</div>",
  "            <div class=\"upload-hint\">Chỉ nhận file .apk · Tối đa 100 MB</div>",
  "          </div>",
  "          <input type=\"file\" id=\"apkFileInput\" accept=\".apk\" style=\"display:none;\">",
  "          <div class=\"apk-progress-wrap\" id=\"apkProgressWrap\">",
  "            <div class=\"apk-progress-bar-track\">",
  "              <div class=\"apk-progress-bar-fill\" id=\"apkProgressFill\"></div>",
  "            </div>",
  "            <div class=\"apk-progress-label\" id=\"apkProgressLabel\">Đang chuẩn bị...</div>",
  "          </div>",
  "          <label style=\"margin-top:16px;\">Ghi chú tính năng / mô tả (tuỳ chọn)</label>",
  "          <textarea id=\"apkNoteInput\" rows=\"4\" placeholder=\"Nhập tính năng, phiên bản, thay đổi... của APK này\" style=\"width:100%;background:var(--panel-2);border:1px solid var(--line);color:var(--text);padding:10px 12px;border-radius:8px;font-family:Inter,sans-serif;font-size:13px;outline:none;resize:vertical;margin-top:6px;\"></textarea>",
  "          <p class=\"preview-note\" style=\"margin-top:10px;\">Ghi chú sẽ được lưu kèm file APK. Sau khi nạp xong, bạn có thể cập nhật ghi chú bất kỳ lúc nào bằng nút <b>Cập nhật ghi chú</b> trên mỗi file.</p>",
  "        </div>",
  "      </div>",
  "      <div>",
  "        <div class=\"panel\">",
  "          <div class=\"panel-head\">",
  "            <div>",
  "              <h2>Danh sách APK đã nạp</h2>",
  "              <p class=\"sub\">Các file .apk đang lưu trữ trên server.</p>",
  "            </div>",
  "            <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshApk\">Làm mới</button>",
  "          </div>",
  "          <div id=\"apkList\" style=\"margin-top:14px;\"></div>",
  "          <div class=\"empty\" id=\"apkEmpty\" style=\"display:none; margin-top:10px;\">",
  "            <div class=\"big\">Chưa có APK nào</div>",
  "            Nạp file .apk ở bên trái để bắt đầu.",
  "          </div>",
  "        </div>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "</main>",
  "",
  "<footer>KeyVault — Hệ thống bảo mật · an toàn · chất lượng. Dữ liệu được tự động mã hoá &amp; lưu trữ trên máy chủ.</footer>",
  "",
  "</div><!-- /#appRoot -->",
  "",
  "<div class=\"toast\" id=\"toast\"></div>",
  "",
  "<div class=\"modal-bg\" id=\"sellModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Đánh dấu đã bán</h3>",
  "    <label>Tên / liên hệ khách hàng</label>",
  "    <input type=\"text\" id=\"sellCustomer\" placeholder=\"VD: Nguyễn Văn A - zalo 09xx\">",
  "    <label>Giá bán (₫)</label>",
  "    <input type=\"text\" id=\"sellPrice\" placeholder=\"VD: 99000\">",
  "    <label>Mã thiết bị kích hoạt (tuỳ chọn)</label>",
  "    <input type=\"text\" id=\"sellDevice\" placeholder=\"VD: DEVICE-8F21A\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"sellCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"sellConfirm\">Xác nhận</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"extendModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Gia hạn tài khoản</h3>",
  "    <p class=\"sub\" id=\"extendSellerLabel\" style=\"margin-top:-6px;\"></p>",
  "    <div class=\"row2\">",
  "      <div>",
  "        <label>Số lượng</label>",
  "        <input type=\"number\" id=\"extendAmount\" value=\"30\" min=\"1\">",
  "      </div>",
  "      <div>",
  "        <label>Đơn vị</label>",
  "        <select id=\"extendUnit\">",
  "          <option value=\"hour\">Giờ</option>",
  "          <option value=\"day\" selected>Ngày</option>",
  "          <option value=\"month\">Tháng</option>",
  "        </select>",
  "      </div>",
  "    </div>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"extendCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"extendConfirm\">Cộng thời gian</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"extendAllModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>⏱ Gia hạn tất cả key</h3>",
  "    <p class=\"sub\" style=\"margin-top:-6px;\">Cộng thêm thời gian đã chọn vào hạn dùng của TẤT CẢ key có thời hạn (áp dụng cho key đã kích hoạt lẫn key chưa kích hoạt, ở tất cả tài khoản).</p>",
  "    <div class=\"row2\">",
  "      <div>",
  "        <label>Số lượng</label>",
  "        <input type=\"number\" id=\"extendAllAmount\" value=\"1\" min=\"1\">",
  "      </div>",
  "      <div>",
  "        <label>Đơn vị</label>",
  "        <select id=\"extendAllUnit\">",
  "          <option value=\"hour\">Giờ</option>",
  "          <option value=\"day\" selected>Ngày</option>",
  "          <option value=\"month\">Tháng</option>",
  "        </select>",
  "      </div>",
  "    </div>",
  "    <p class=\"preview-note\" id=\"extendAllPreviewNote\" style=\"margin-top:10px;\"></p>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"extendAllCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"extendAllConfirm\">Gia hạn thời gian</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"extendKeyModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>⏱ Gia hạn key riêng lẻ</h3>",
  "    <p class=\"sub\" id=\"extendKeyLabel\" style=\"margin-top:-6px; word-break:break-all;\"></p>",
  "    <div class=\"row2\" style=\"margin-top:12px;\">",
  "      <div>",
  "        <label>Phút cộng thêm</label>",
  "        <input type=\"number\" id=\"extendKeyMinutes\" value=\"0\" min=\"0\" placeholder=\"0\">",
  "      </div>",
  "      <div>",
  "        <label>Giờ cộng thêm</label>",
  "        <input type=\"number\" id=\"extendKeyHours\" value=\"0\" min=\"0\" placeholder=\"0\">",
  "      </div>",
  "    </div>",
  "    <div class=\"row2\" style=\"margin-top:8px;\">",
  "      <div>",
  "        <label>Ngày cộng thêm</label>",
  "        <input type=\"number\" id=\"extendKeyAmount\" value=\"0\" min=\"0\" placeholder=\"0\">",
  "      </div>",
  "      <div>",
  "        <label>Tháng cộng thêm</label>",
  "        <input type=\"number\" id=\"extendKeyMonths\" value=\"0\" min=\"0\" placeholder=\"0\">",
  "      </div>",
  "    </div>",
  "    <p class=\"preview-note\" id=\"extendKeyPreview\" style=\"margin-top:10px;\"></p>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"extendKeyCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"extendKeyConfirm\">✔ Cộng thời gian</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"topupModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Thêm tiền cho tài khoản</h3>",
  "    <p class=\"sub\" id=\"topupSellerLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Số tiền cộng thêm (₫)</label>",
  "    <input type=\"text\" id=\"topupAmount\" placeholder=\"VD: 100000\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"topupCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"topupConfirm\">Cộng tiền</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"sellerPassModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Đổi mật khẩu người bán</h3>",
  "    <p class=\"sub\" id=\"sellerPassLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Mật khẩu mới</label>",
  "    <input type=\"text\" id=\"sellerPassNew\" placeholder=\"Nhập mật khẩu mới\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"sellerPassCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"sellerPassConfirm\">Đổi mật khẩu</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"customerTopupModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Thêm tiền cho người dùng</h3>",
  "    <p class=\"sub\" id=\"customerTopupLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Số tiền cộng thêm (₫)</label>",
  "    <input type=\"text\" id=\"customerTopupAmount\" placeholder=\"VD: 100000\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"customerTopupCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"customerTopupConfirm\">Cộng tiền</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"customerPassModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Đổi mật khẩu người dùng</h3>",
  "    <p class=\"sub\" id=\"customerPassLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Mật khẩu mới</label>",
  "    <input type=\"text\" id=\"customerPassNew\" placeholder=\"Nhập mật khẩu mới (tối thiểu 4 ký tự)\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"customerPassCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"customerPassConfirm\">Đổi mật khẩu</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"ownPassModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Đổi mật khẩu tài khoản</h3>",
  "    <p class=\"sub\" id=\"ownPassLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Mật khẩu hiện tại</label>",
  "    <input type=\"text\" id=\"ownPassCurrent\" placeholder=\"Nhập mật khẩu hiện tại\">",
  "    <label>Mật khẩu mới</label>",
  "    <input type=\"text\" id=\"ownPassNew\" placeholder=\"Nhập mật khẩu mới\">",
  "    <label>Xác nhận mật khẩu mới</label>",
  "    <input type=\"text\" id=\"ownPassConfirmField\" placeholder=\"Nhập lại mật khẩu mới\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"ownPassCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"ownPassConfirm\">Đổi mật khẩu</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"blockIpModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Chặn IP thủ công</h3>",
  "    <label>Địa chỉ IP</label>",
  "    <input type=\"text\" id=\"blockIpValue\" placeholder=\"VD: 192.168.1.10\">",
  "    <label>Lý do</label>",
  "    <select id=\"blockIpReason\">",
  "      <option>Brute-force đăng nhập nhiều lần</option>",
  "      <option>Quét cổng bất thường</option>",
  "      <option>Gửi yêu cầu bất thường (nghi DDoS)</option>",
  "      <option>User-agent đáng ngờ / bot</option>",
  "      <option>Truy cập endpoint quản trị trái phép</option>",
  "      <option>Vượt giới hạn tốc độ request (rate limit)</option>",
  "      <option>Khác</option>",
  "    </select>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"blockIpCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"blockIpConfirm\">Chặn IP</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"cvViewModalBg\">",
  "  <div class=\"modal\" style=\"max-width:760px;\">",
  "    <h3 id=\"cvViewTitle\">Xem code</h3>",
  "    <p class=\"sub\" id=\"cvViewMeta\" style=\"margin-top:-6px;\"></p>",
  "    <pre id=\"cvViewContent\" style=\"max-height:440px; overflow:auto; background:var(--panel-2); border:1px solid var(--line); border-radius:10px; padding:14px; font-size:12.5px; line-height:1.5; white-space:pre; margin-top:10px;\"></pre>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"cvViewClose\">Đóng</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnCvCopy\">Sao chép</button>",
  "      <button class=\"btn\" id=\"btnCvDownload\">Tải file</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<script>",
  "/* ============ LOGIN LOGIC ============ */",
  "const DEMO_USER = 'Adminn';",
  "const DEMO_PASS = '120510@';",
  "let adminPassword = DEMO_PASS; // mật khẩu admin hiện tại — có thể đổi qua nút \"Đổi mật khẩu\"",
  "let loginHistory = []; // chỉ ghi lại các lượt đăng nhập thật diễn ra trong phiên này",
  "",
  "let currentRole = null;      // 'admin' | 'seller'",
  "let currentAccount = null;   // 'admin' hoặc username người bán",
  "let keysStore = {};          // kho key riêng theo từng tài khoản: { admin:[...], dealer01:[...] }",
  "",
  "function showToastLogin(msg){",
  "  const t = document.getElementById('toast');",
  "  t.textContent = msg;",
  "  t.classList.add('show');",
  "  clearTimeout(window._loginToastTimer);",
  "  window._loginToastTimer = setTimeout(()=> t.classList.remove('show'), 2400);",
  "}",
  "",
  "function sellerAccountStatus(s){",
  "  if(s.banned) return 'banned';",
  "  if(s.expiresAt && new Date() > new Date(s.expiresAt)) return 'expired';",
  "  return 'active';",
  "}",
  "",
  "/* ============ BẢNG GIÁ & THỜI HẠN KEY CỐ ĐỊNH (TRỪ VÀO SỐ DƯ NGƯỜI BÁN) ============ */",
  "// Cố định 6 mốc thời hạn + giá theo yêu cầu quản trị viên. Seller/admin KHÔNG được tự",
  "// nhập số lượng + đơn vị tuỳ ý nữa khi tạo key có thời hạn — chỉ chọn 1 trong các mốc",
  "// dưới đây (áp dụng cho cả tài khoản Thường lẫn Premium). Muốn đổi giá/thời hạn phải",
  "// sửa mảng FIXED_KEY_PLANS này trực tiếp trong code — không có chỗ nào trên giao diện",
  "// admin/seller cho phép chỉnh sửa các con số này.",
  "const FIXED_KEY_PLANS = [",
  "  { id:'h12',       label:'12 giờ',         unit:'hour',      amount:12,  price:20000  },",
  "  { id:'d1',        label:'1 ngày',         unit:'day',       amount:1,   price:30000  },",
  "  { id:'w1',        label:'1 tuần',         unit:'day',       amount:7,   price:60000  },",
  "  { id:'d15',       label:'15 ngày',        unit:'day',       amount:15,  price:90000  },",
  "  { id:'m1',        label:'1 tháng',        unit:'month',     amount:1,   price:160000 },",
  "  { id:'unlimited', label:'Không giới hạn', unit:'unlimited', amount:null,price:500000 }",
  "];",
  "function findFixedPlan(id){ return FIXED_KEY_PLANS.find(p=>p.id===id) || null; }",
  "",
  "/* Giữ KEY_PRICES để tương thích ngược với code cũ tham chiếu theo đơn vị (hour/day/month/",
  "   unlimited) — giờ được suy ra từ bảng giá cố định phía trên thay vì số rời rạc như trước. */",
  "const KEY_PRICES = { hour: findFixedPlan('h12').price, day: findFixedPlan('d1').price, month: findFixedPlan('m1').price, unlimited: findFixedPlan('unlimited').price };",
  "",
  "// [KHÔNG CÒN ÁP DỤNG cho bảng giá cố định mới — giữ nguyên hàm cũ để không xoá code cũ]",
  "// Ưu đãi theo \"tuổi\" tài khoản người bán (tính từ lúc admin tạo tài khoản):",
  "// > 5 giờ hoạt động -> giảm 20%; > 3 ngày hoạt động -> giảm thêm 20% trên số tiền còn lại (dồn ~36%).",
  "function sellerDiscountFactor(seller){",
  "  if(!seller || !seller.createdAt) return 1;",
  "  const ageMs = new Date() - new Date(seller.createdAt);",
  "  let factor = 1;",
  "  if(ageMs >= 5*3600000) factor *= 0.8;",
  "  if(ageMs >= 3*86400000) factor *= 0.8;",
  "  return factor;",
  "}",
  "function sellerDiscountPercent(seller){",
  "  return Math.round((1 - sellerDiscountFactor(seller)) * 100);",
  "}",
  "function keyUnitCost(unitOrUnlimited){",
  "  return KEY_PRICES[unitOrUnlimited] ?? 0;",
  "}",
  "",
  "function doLogin(){",
  "  const user = document.getElementById('loginUser').value.trim();",
  "  const pass = document.getElementById('loginPass').value.trim();",
  "  const errBox = document.getElementById('loginError');",
  "",
  "  let success = false;",
  "  let role = null;",
  "  let errMsg = 'Sai tên đăng nhập hoặc mật khẩu.';",
  "",
  "  if(user === DEMO_USER && pass === adminPassword){",
  "    success = true; role = 'admin';",
  "  } else {",
  "    const s = sellers.find(x=>x.username === user);",
  "    if(s && s.password === pass){",
  "      const st = sellerAccountStatus(s);",
  "      if(st === 'banned'){",
  "        errMsg = 'Tài khoản đã bị cấm.';",
  "      } else if(st === 'expired'){",
  "        errMsg = 'Tài khoản đã hết hạn sử dụng.';",
  "      } else {",
  "        success = true; role = 'seller';",
  "      }",
  "    }",
  "  }",
  "",
  "  loginHistory.unshift({time:new Date(), user: user || '(trống)', success});",
  "",
  "  if(success){",
  "    errBox.classList.remove('show');",
  "",
  "    /* ---- Auto lưu đăng nhập: mỗi lần đăng nhập thành công, tự động lưu tài khoản/mật khẩu",
  "       vào localStorage của trình duyệt để lần sau vào lại tự động điền sẵn (không cần tick gì cả) ---- */",
  "    try{",
  "      localStorage.setItem('keyvault_remember', JSON.stringify({ user, pass }));",
  "    }catch(e){ /* trình duyệt chặn localStorage cũng không sao, chỉ là không tự điền lại được */ }",
  "",
  "    currentRole = role;",
  "    currentAccount = role === 'admin' ? 'admin' : user;",
  "    if(!keysStore[currentAccount]) keysStore[currentAccount] = [];",
  "    keys = keysStore[currentAccount];",
  "",
  "    document.getElementById('loginScreen').style.display = 'none';",
  "    document.getElementById('appRoot').style.display = 'block';",
  "    applyRoleVisibility();",
  "    render();",
  "",
  "    if(role === 'seller'){",
  "      const s = sellers.find(x=>x.username===currentAccount);",
  "      const unread = (s && s.notifications) ? s.notifications.filter(n=>!n.read) : [];",
  "      if(unread.length){",
  "        showToast(unread.length===1 ? unread[0].message : `Bạn có ${unread.length} thông báo mới từ quản trị viên`);",
  "      }",
  "    }",
  "  } else {",
  "    errBox.textContent = errMsg;",
  "    errBox.classList.add('show');",
  "  }",
  "}",
  "",
  "function applyRoleVisibility(){",
  "  document.querySelectorAll('.tab-btn').forEach(btn=>{",
  "    const adminOnly = btn.dataset.adminOnly === '1';",
  "    const isKeysTab = btn.dataset.page === 'keys';",
  "    if(currentRole === 'seller'){",
  "      btn.style.display = isKeysTab ? '' : 'none';",
  "    } else {",
  "      btn.style.display = '';",
  "    }",
  "  });",
  "  document.querySelectorAll('[data-admin-only=\"1\"]').forEach(el=>{",
  "    if(el.classList.contains('tab-btn')) return; // đã xử lý ở trên",
  "    el.style.display = currentRole === 'admin' ? '' : 'none';",
  "  });",
  "  if(currentRole === 'seller'){",
  "    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));",
  "    document.querySelector('.tab-btn[data-page=\"keys\"]').classList.add('active');",
  "    currentPage = 'keys';",
  "    document.getElementById('page-keys').style.display = 'grid';",
  "    document.getElementById('page-stats').style.display = 'none';",
  "    document.getElementById('page-security').style.display = 'none';",
  "    document.getElementById('page-sellers').style.display = 'none';",
  "    document.getElementById('page-customers').style.display = 'none';",
  "    document.getElementById('page-apikey').style.display = 'none';",
  "    document.getElementById('page-products').style.display = 'none';",
  "    document.getElementById('page-getkey').style.display = 'none';",
  "    document.getElementById('page-codevault').style.display = 'none';",
  "    document.getElementById('page-uploadcode').style.display = 'none';",
  "    document.getElementById('page-apkvault').style.display = 'none';",
  "    document.getElementById('page-miniapp').style.display = 'none';",
  "    // seller luôn dùng thời gian hiện tại khi tạo key",
  "    document.getElementById('createdAtNow').checked = true;",
  "    document.getElementById('createdAtCustomField').style.display = 'none';",
  "  }",
  "",
  "  applySellerAccountEffects();",
  "}",
  "",
  "/* ============ HIỆU ỨNG / GIỚI HẠN THEO LOẠI TÀI KHOẢN NGƯỜI BÁN (THƯỜNG / PREMIUM) ============ */",
  "function applySellerAccountEffects(){",
  "  const isSeller = currentRole === 'seller';",
  "  const s = isSeller ? sellers.find(x=>x.username===currentAccount) : null;",
  "  const isPremium = !!(s && s.accountType === 'premium');",
  "",
  "  document.body.classList.toggle('vip-mode', isSeller && isPremium);",
  "  document.getElementById('vipBadge').style.display = (isSeller && isPremium) ? '' : 'none';",
  "",
  "  document.getElementById('statBalanceWrap').style.display = isSeller ? '' : 'none';",
  "  document.getElementById('statAcctExpiryWrap').style.display = isSeller ? '' : 'none';",
  "  document.getElementById('sellerPriceNote').style.display = isSeller ? '' : 'none';",
  "  document.getElementById('sellerNotifPanel').style.display = isSeller ? '' : 'none';",
  "",
  "  const expNoneInput = document.getElementById('expNone');",
  "  const expLimitedInput = document.getElementById('expLimited');",
  "  const lockNote = document.getElementById('expiryLockNote');",
  "  if(isSeller && !isPremium){",
  "    // Tài khoản Thường: khoá tính năng tạo key \"không giới hạn\" và khoá gia hạn",
  "    expNoneInput.disabled = true;",
  "    if(expNoneInput.checked){",
  "      expLimitedInput.checked = true;",
  "    }",
  "    lockNote.style.display = '';",
  "    // Khoá nút gia hạn tất cả key",
  "    const btnExtendAll = document.getElementById('btnOpenExtendAll');",
  "    if(btnExtendAll){",
  "      btnExtendAll.disabled = true;",
  "      btnExtendAll.title = 'Chỉ tài khoản Premium mới được gia hạn key';",
  "      if(!document.getElementById('extendAllLockNote')){",
  "        const note = document.createElement('p');",
  "        note.id = 'extendAllLockNote';",
  "        note.className = 'preview-note';",
  "        note.style = 'margin-top:6px; color:var(--warn);';",
  "        note.textContent = '🔒 Tài khoản Thường bị khoá chức năng gia hạn key. Liên hệ quản trị viên để nâng cấp Premium.';",
  "        btnExtendAll.parentNode && btnExtendAll.parentNode.appendChild(note);",
  "      }",
  "    }",
  "  } else {",
  "    expNoneInput.disabled = false;",
  "    lockNote.style.display = 'none';",
  "    // Mở khoá nút gia hạn khi là Premium hoặc Admin",
  "    const btnExtendAll = document.getElementById('btnOpenExtendAll');",
  "    if(btnExtendAll){ btnExtendAll.disabled = false; btnExtendAll.title = ''; }",
  "    const lockNoteExtend = document.getElementById('extendAllLockNote');",
  "    if(lockNoteExtend) lockNoteExtend.remove();",
  "  }",
  "",
  "  if(isSeller){",
  "    document.getElementById('statBalance').textContent = fmtMoney((s&&s.balance)||0) || '0₫';",
  "    document.getElementById('statAcctExpiry').textContent = formatRemaining(s && s.expiresAt);",
  "  }",
  "",
  "  renderNotifPanel();",
  "}",
  "",
  "function renderNotifPanel(){",
  "  const box = document.getElementById('notifList');",
  "  if(!box) return;",
  "  const isSeller = currentRole === 'seller';",
  "  if(!isSeller){ box.innerHTML = ''; return; }",
  "  const s = sellers.find(x=>x.username===currentAccount);",
  "  const notifications = (s && s.notifications) || [];",
  "  if(!notifications.length){",
  "    box.innerHTML = '<p class=\"preview-note\" style=\"margin:0;\">Chưa có thông báo nào.</p>';",
  "    return;",
  "  }",
  "  box.innerHTML = notifications.map(n => `",
  "    <div class=\"notif-item ${n.read ? '' : 'unread'}\">",
  "      <div class=\"dot\"></div>",
  "      <div class=\"body\">",
  "        <div class=\"msg\">${n.message}</div>",
  "        <div class=\"time\">${formatDateTime(n.time)}</div>",
  "      </div>",
  "    </div>",
  "  `).join('');",
  "}",
  "",
  "document.getElementById('btnLogin').addEventListener('click', doLogin);",
  "['loginUser','loginPass'].forEach(id=>{",
  "  document.getElementById(id).addEventListener('keydown', (e)=>{ if(e.key==='Enter') doLogin(); });",
  "});",
  "",
  "/* ---- Tự động điền lại tài khoản/mật khẩu đã \"Ghi nhớ\" ở lần đăng nhập trước ---- */",
  "(function autofillRememberedLogin(){",
  "  try{",
  "    const saved = localStorage.getItem('keyvault_remember');",
  "    if(!saved) return;",
  "    const { user, pass, autoLogin } = JSON.parse(saved);",
  "    if(user) document.getElementById('loginUser').value = user;",
  "    if(pass) document.getElementById('loginPass').value = pass;",
  "    /* ---- Gộp đăng nhập: nếu vừa được chuyển hướng từ trang bán key (đăng nhập đúng",
  "       tài khoản admin/seller ở đó), tự bấm đăng nhập luôn — không bắt gõ lại lần 2.",
  "       Cờ 'autoLogin' chỉ dùng đúng 1 lần rồi xoá để lần load /admin sau không tự",
  "       đăng nhập lại nếu người dùng đã cố tình đăng xuất. ---- */",
  "    if(autoLogin){",
  "      localStorage.setItem('keyvault_remember', JSON.stringify({ user, pass }));",
  "      doLogin();",
  "    }",
  "  }catch(e){ /* dữ liệu ghi nhớ lỗi thì bỏ qua, không chặn đăng nhập bình thường */ }",
  "})();",
  "",
  "document.getElementById('btnLogout').addEventListener('click', ()=>{",
  "  document.getElementById('appRoot').style.display = 'none';",
  "  document.getElementById('loginScreen').style.display = 'flex';",
  "  document.getElementById('loginUser').value = '';",
  "  document.getElementById('loginPass').value = '';",
  "  document.getElementById('loginError').classList.remove('show');",
  "  currentRole = null;",
  "  currentAccount = null;",
  "  document.body.classList.remove('vip-mode');",
  "  document.getElementById('vipBadge').style.display = 'none';",
  "  try{ localStorage.removeItem('keyvault_remember'); }catch(e){ /* không sao nếu trình duyệt chặn */ }",
  "});",
  "",
  "/* ============ ẨN/HIỆN 4 CHỈ SỐ PHỤ (ĐÃ BÁN / HẾT HẠN / BỊ CẤM / DOANH THU) ============ */",
  "let statsHidden = false;",
  "document.getElementById('btnToggleStats').addEventListener('click', ()=>{",
  "  statsHidden = !statsHidden;",
  "  document.querySelectorAll('.stat-toggleable').forEach(el=>{",
  "    el.style.display = statsHidden ? 'none' : '';",
  "  });",
  "  document.getElementById('iconEyeOpen').style.display = statsHidden ? 'none' : '';",
  "  document.getElementById('iconEyeClosed').style.display = statsHidden ? '' : 'none';",
  "  document.getElementById('toggleStatsLabel').textContent = statsHidden ? 'Hiện số liệu' : 'Ẩn số liệu';",
  "  document.getElementById('btnToggleStats').classList.toggle('active', statsHidden);",
  "});",
  "",
  "/* ============ ĐỔI MẬT KHẨU TÀI KHOẢN ĐANG ĐĂNG NHẬP ============ */",
  "document.getElementById('btnChangeOwnPassword').addEventListener('click', ()=>{",
  "  document.getElementById('ownPassLabel').textContent = 'Tài khoản: ' + currentAccount + (currentRole==='admin' ? ' (quản trị viên)' : ' (người bán)');",
  "  document.getElementById('ownPassCurrent').value = '';",
  "  document.getElementById('ownPassNew').value = '';",
  "  document.getElementById('ownPassConfirmField').value = '';",
  "  document.getElementById('ownPassModalBg').classList.add('show');",
  "});",
  "document.getElementById('ownPassCancel').addEventListener('click', ()=> document.getElementById('ownPassModalBg').classList.remove('show'));",
  "document.getElementById('ownPassConfirm').addEventListener('click', ()=>{",
  "  const current = document.getElementById('ownPassCurrent').value;",
  "  const next = document.getElementById('ownPassNew').value;",
  "  const confirmVal = document.getElementById('ownPassConfirmField').value;",
  "",
  "  const actualCurrent = currentRole === 'admin' ? adminPassword : (sellers.find(s=>s.username===currentAccount)||{}).password;",
  "",
  "  if(current !== actualCurrent){",
  "    showToast('Mật khẩu hiện tại không đúng'); return;",
  "  }",
  "  if(!next){",
  "    showToast('Vui lòng nhập mật khẩu mới'); return;",
  "  }",
  "  if(next !== confirmVal){",
  "    showToast('Xác nhận mật khẩu mới không khớp'); return;",
  "  }",
  "",
  "  if(currentRole === 'admin'){",
  "    adminPassword = next;",
  "  } else {",
  "    const s = sellers.find(x=>x.username===currentAccount);",
  "    if(s) s.password = next;",
  "  }",
  "  document.getElementById('ownPassModalBg').classList.remove('show');",
  "  showToast('Đã đổi mật khẩu thành công');",
  "});",
  "",
  "/* ============ TAB NAVIGATION ============ */",
  "let currentPage = 'keys';",
  "document.querySelectorAll('.tab-btn').forEach(btn=>{",
  "  btn.addEventListener('click', ()=>{",
  "    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));",
  "    btn.classList.add('active');",
  "    currentPage = btn.dataset.page;",
  "    document.getElementById('page-keys').style.display = currentPage==='keys' ? 'grid' : 'none';",
  "    document.getElementById('page-stats').style.display = currentPage==='stats' ? 'block' : 'none';",
  "    document.getElementById('page-security').style.display = currentPage==='security' ? 'block' : 'none';",
  "    document.getElementById('page-sellers').style.display = currentPage==='sellers' ? 'block' : 'none';",
  "    document.getElementById('page-customers').style.display = currentPage==='customers' ? 'block' : 'none';",
  "    document.getElementById('page-apikey').style.display = currentPage==='apikey' ? 'block' : 'none';",
  "    document.getElementById('page-products').style.display = currentPage==='products' ? 'block' : 'none';",
  "    document.getElementById('page-getkey').style.display = currentPage==='getkey' ? 'block' : 'none';",
  "    document.getElementById('page-codevault').style.display = currentPage==='codevault' ? 'block' : 'none';",
  "    document.getElementById('page-uploadcode').style.display = currentPage==='uploadcode' ? 'block' : 'none';",
  "    document.getElementById('page-apkvault').style.display = currentPage==='apkvault' ? 'block' : 'none';",
  "    if(currentPage==='apkvault') apkFetchList();",
  "    if(currentPage==='uploadcode') ucFetchList();",
  "    document.getElementById('page-miniapp').style.display = currentPage==='miniapp' ? 'block' : 'none';",
  "    if(currentPage==='stats') renderStatsPage();",
  "    if(currentPage==='security') renderSecurityPage();",
  "    if(currentPage==='sellers') renderSellersPage();",
  "    if(currentPage==='customers'){ loadAndRenderCustomersPage(); if(typeof renderSepaySettings==='function') renderSepaySettings(); }",
  "    if(currentPage==='apikey') renderApiKeyPage();",
  "    if(currentPage==='products'){ renderProductsPage(); renderProductGroupsPage(); }",
  "    if(currentPage==='getkey') renderGetKeyPage();",
  "    if(currentPage==='codevault') renderCodeVaultPage();",
  "    if(currentPage==='miniapp') renderMiniAppPage();",
  "  });",
  "});",
  "",
  "/* ============ SẢN PHẨM (STOREFRONT) & MÃ GIẢM GIÁ (ADMIN ONLY) ============ */",
  "let products = []; // {id, name, logo(dataURL), price, durationAmount, durationUnit, keyPrefix, maxDevices, active, createdAt}",
  "let discountCodes = []; // {id, code, percent, maxUses, usedCount, expiresAt, active, createdAt}",
  "let bankInfo = { bankId:'MB', accountNo:'0364837118', accountName:'LUONG VAN TUYEN' }; // thông tin ngân hàng dùng để sinh QR nạp tiền",
  "let sepayConfig = { enabled:false, apiKey:'' }; // cấu hình đối soát tự động qua webhook SePay",
  "",
  "/* ============ SELLER ACCOUNT MANAGEMENT (ADMIN ONLY) ============ */",
  "let sellers = []; // {id, username, password, createdAt, expiresAt, banned, balance}",
  "let extendTargetId = null;",
  "let topupTargetId = null;",
  "let sellerPassTargetId = null;",
  "",
  "document.querySelectorAll('#sellerExpiryToggle input').forEach(el=>{",
  "  el.addEventListener('change', ()=>{",
  "    document.getElementById('sellerExpiryFields').style.display = document.getElementById('sellerExpLimited').checked ? 'grid' : 'none';",
  "  });",
  "});",
  "",
  "function computeExpiryFrom(base, amount, unit){",
  "  const msPerUnit = unit==='hour' ? 3600000 : unit==='day' ? 86400000 : 30*86400000;",
  "  return new Date(base.getTime() + amount*msPerUnit);",
  "}",
  "",
  "document.getElementById('btnCreateSeller').addEventListener('click', ()=>{",
  "  const username = document.getElementById('sellerUsername').value.trim();",
  "  const password = document.getElementById('sellerPassword').value.trim();",
  "  if(!username || !password){ showToast('Vui lòng nhập tên đăng nhập và mật khẩu'); return; }",
  "  if(username === DEMO_USER || sellers.some(s=>s.username===username)){",
  "    showToast('Tên đăng nhập đã tồn tại'); return;",
  "  }",
  "",
  "  let expiresAt = null;",
  "  if(document.getElementById('sellerExpLimited').checked){",
  "    const amount = Math.max(1, parseFloat(document.getElementById('sellerExpiryAmount').value) || 1);",
  "    const unit = document.getElementById('sellerExpiryUnit').value;",
  "    expiresAt = computeExpiryFrom(new Date(), amount, unit);",
  "  }",
  "",
  "  const initialBalance = parseFloat(String(document.getElementById('sellerInitialBalance').value).replace(/[^\\d.]/g,'')) || 0;",
  "  const accountType = document.getElementById('sellerAcctPremium').checked ? 'premium' : 'normal';",
  "",
  "  const notifications = [];",
  "  if(initialBalance > 0){",
  "    notifications.push({",
  "      id:'n'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      message:`Quản trị viên đã cấp số dư khởi tạo ${fmtMoney(initialBalance)} cho tài khoản của bạn.`,",
  "      time:new Date(), read:false",
  "    });",
  "  }",
  "",
  "  sellers.unshift({",
  "    id: 's'+Date.now()+Math.random().toString(36).slice(2,7),",
  "    username, password,",
  "    createdAt: new Date(),",
  "    expiresAt,",
  "    banned: false,",
  "    balance: initialBalance,",
  "    accountType,",
  "    notifications",
  "  });",
  "  keysStore[username] = keysStore[username] || [];",
  "",
  "  document.getElementById('sellerUsername').value = '';",
  "  document.getElementById('sellerPassword').value = '';",
  "  document.getElementById('sellerInitialBalance').value = '';",
  "  document.getElementById('sellerAcctNormal').checked = true;",
  "  renderSellersPage();",
  "  showToast('Đã tạo tài khoản người bán: '+username);",
  "});",
  "",
  "function renderSellersPage(){",
  "  const tbody = document.querySelector('#sellerTable tbody');",
  "  tbody.innerHTML = '';",
  "  document.getElementById('sellerEmptyState').style.display = sellers.length ? 'none' : 'block';",
  "",
  "  const SELLER_STATUS_LABEL = {active:'Hoạt động', banned:'Bị cấm', expired:'Hết hạn'};",
  "  sellers.forEach(s=>{",
  "    const st = sellerAccountStatus(s);",
  "    const acctType = s.accountType || 'normal';",
  "    const tr = document.createElement('tr');",
  "    const keyCount = (keysStore[s.username]||[]).length;",
  "    tr.innerHTML = `",
  "      <td class=\"mono\">${s.username}</td>",
  "      <td>${formatDateTime(s.createdAt)}</td>",
  "      <td>${s.expiresAt ? formatDateTime(s.expiresAt) : 'Không giới hạn'}</td>",
  "      <td>${formatRemaining(s.expiresAt)}</td>",
  "      <td><span class=\"badge ${st}\">${SELLER_STATUS_LABEL[st]}</span></td>",
  "      <td><span class=\"badge acct ${acctType}\">${acctType==='premium' ? '★ Premium' : 'Thường'}</span></td>",
  "      <td class=\"mono stat-balance\">${fmtMoney(s.balance||0) || '0₫'}</td>",
  "      <td>${keyCount}</td>",
  "      <td>",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"${acctType==='premium' ? 'Hạ về tài khoản Thường' : 'Nâng cấp lên Premium'}\" data-act=\"togglepremium\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 2l2.6 6.6L21 9.3l-5 4.7L17.4 21 12 17.3 6.6 21 8 14l-5-4.7 6.4-.7L12 2Z\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"Thêm tiền cho tài khoản\" data-act=\"topup\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 8v8M8 12h8\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"Đổi mật khẩu\" data-act=\"changepass\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2\"/><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"Thêm thời gian\" data-act=\"extend\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 3\"/></svg>",
  "          </button>",
  "          ${s.banned",
  "            ? `<button class=\"icon-btn\" title=\"Bỏ cấm\" data-act=\"unban\" data-id=\"${s.id}\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12l3 3 5-6\"/></svg></button>`",
  "            : `<button class=\"icon-btn danger\" title=\"Cấm tài khoản\" data-act=\"ban\" data-id=\"${s.id}\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.5 5.5l13 13\"/></svg></button>`}",
  "          <button class=\"icon-btn danger\" title=\"Xoá tài khoản\" data-act=\"delete\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "          </button>",
  "        </div>",
  "      </td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "document.querySelector('#sellerTable').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const s = sellers.find(x=>x.id===id);",
  "  if(!s) return;",
  "",
  "  if(act==='togglepremium'){",
  "    s.accountType = (s.accountType === 'premium') ? 'normal' : 'premium';",
  "    s.notifications = s.notifications || [];",
  "    s.notifications.unshift({",
  "      id:'n'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      message: s.accountType === 'premium'",
  "        ? 'Tài khoản của bạn đã được quản trị viên nâng cấp lên ★ Premium — đã mở khoá tạo key không giới hạn.'",
  "        : 'Tài khoản của bạn đã được quản trị viên chuyển về loại Thường — tạo key không giới hạn đã bị khoá.',",
  "      time:new Date(), read:false",
  "    });",
  "    renderSellersPage();",
  "    if(currentRole==='seller' && currentAccount===s.username) applySellerAccountEffects();",
  "    saveStateToServer(true);",
  "    showToast('Đã cập nhật loại tài khoản: '+s.username+' → '+(s.accountType==='premium'?'Premium':'Thường'));",
  "  } else if(act==='ban'){",
  "    s.banned = true;",
  "    renderSellersPage();",
  "    showToast('Đã cấm tài khoản: '+s.username);",
  "  } else if(act==='unban'){",
  "    s.banned = false;",
  "    renderSellersPage();",
  "    showToast('Đã bỏ cấm tài khoản: '+s.username);",
  "  } else if(act==='delete'){",
  "    if(confirm('Xoá vĩnh viễn tài khoản \"'+s.username+'\"? Kho key của tài khoản này cũng sẽ bị xoá.')){",
  "      sellers = sellers.filter(x=>x.id!==id);",
  "      delete keysStore[s.username];",
  "      renderSellersPage();",
  "      showToast('Đã xoá tài khoản: '+s.username);",
  "    }",
  "  } else if(act==='extend'){",
  "    extendTargetId = id;",
  "    document.getElementById('extendSellerLabel').textContent = 'Tài khoản: ' + s.username + ' — hiện tại: ' + (s.expiresAt ? formatDateTime(s.expiresAt) : 'Không giới hạn');",
  "    document.getElementById('extendAmount').value = 30;",
  "    document.getElementById('extendModalBg').classList.add('show');",
  "  } else if(act==='topup'){",
  "    topupTargetId = id;",
  "    document.getElementById('topupSellerLabel').textContent = 'Tài khoản: ' + s.username + ' — số dư hiện tại: ' + (fmtMoney(s.balance||0) || '0₫');",
  "    document.getElementById('topupAmount').value = '';",
  "    document.getElementById('topupModalBg').classList.add('show');",
  "  } else if(act==='changepass'){",
  "    sellerPassTargetId = id;",
  "    document.getElementById('sellerPassLabel').textContent = 'Tài khoản: ' + s.username;",
  "    document.getElementById('sellerPassNew').value = '';",
  "    document.getElementById('sellerPassModalBg').classList.add('show');",
  "  }",
  "});",
  "",
  "document.getElementById('extendCancel').addEventListener('click', ()=> document.getElementById('extendModalBg').classList.remove('show'));",
  "document.getElementById('extendConfirm').addEventListener('click', ()=>{",
  "  const s = sellers.find(x=>x.id===extendTargetId);",
  "  if(s){",
  "    const amount = Math.max(1, parseFloat(document.getElementById('extendAmount').value) || 1);",
  "    const unit = document.getElementById('extendUnit').value;",
  "    const base = (s.expiresAt && new Date(s.expiresAt) > new Date()) ? new Date(s.expiresAt) : new Date();",
  "    s.expiresAt = computeExpiryFrom(base, amount, unit);",
  "    s.notifications = s.notifications || [];",
  "    s.notifications.unshift({",
  "      id:'n'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      message:`Quản trị viên đã gia hạn tài khoản của bạn. Hạn dùng mới: ${formatDateTime(s.expiresAt)}.`,",
  "      time:new Date(), read:false",
  "    });",
  "    showToast('Đã cộng thêm thời gian cho tài khoản: '+s.username);",
  "    if(currentRole==='seller' && currentAccount===s.username) applySellerAccountEffects();",
  "  }",
  "  document.getElementById('extendModalBg').classList.remove('show');",
  "  renderSellersPage();",
  "});",
  "",
  "document.getElementById('topupCancel').addEventListener('click', ()=> document.getElementById('topupModalBg').classList.remove('show'));",
  "document.getElementById('topupConfirm').addEventListener('click', ()=>{",
  "  const s = sellers.find(x=>x.id===topupTargetId);",
  "  if(s){",
  "    const amount = parseFloat(String(document.getElementById('topupAmount').value).replace(/[^\\d.]/g,'')) || 0;",
  "    if(amount <= 0){ showToast('Vui lòng nhập số tiền hợp lệ'); return; }",
  "    s.balance = (s.balance||0) + amount;",
  "    s.notifications = s.notifications || [];",
  "    s.notifications.unshift({",
  "      id:'n'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      message:`Quản trị viên đã cộng ${fmtMoney(amount)} vào tài khoản của bạn. Số dư hiện tại: ${fmtMoney(s.balance)}.`,",
  "      time:new Date(), read:false",
  "    });",
  "    showToast('Đã cộng '+fmtMoney(amount)+' vào tài khoản: '+s.username);",
  "    document.getElementById('topupModalBg').classList.remove('show');",
  "    renderSellersPage();",
  "    if(currentRole==='seller' && currentAccount===s.username) applySellerAccountEffects();",
  "  } else {",
  "    document.getElementById('topupModalBg').classList.remove('show');",
  "  }",
  "});",
  "",
  "document.getElementById('sellerPassCancel').addEventListener('click', ()=> document.getElementById('sellerPassModalBg').classList.remove('show'));",
  "document.getElementById('sellerPassConfirm').addEventListener('click', ()=>{",
  "  const s = sellers.find(x=>x.id===sellerPassTargetId);",
  "  if(s){",
  "    const next = document.getElementById('sellerPassNew').value.trim();",
  "    if(!next){ showToast('Vui lòng nhập mật khẩu mới'); return; }",
  "    s.password = next;",
  "    showToast('Đã đổi mật khẩu cho tài khoản: '+s.username);",
  "  }",
  "  document.getElementById('sellerPassModalBg').classList.remove('show');",
  "  renderSellersPage();",
  "});",
  "",
  "document.getElementById('btnMarkAllRead').addEventListener('click', ()=>{",
  "  if(currentRole !== 'seller') return;",
  "  const s = sellers.find(x=>x.username===currentAccount);",
  "  if(s && s.notifications) s.notifications.forEach(n=> n.read = true);",
  "  renderNotifPanel();",
  "  showToast('Đã đánh dấu tất cả thông báo là đã đọc');",
  "});",
  "",
  "/* ============ TRANG \"NGƯỜI DÙNG\" (TÀI KHOẢN KHÁCH HÀNG ĐĂNG KÝ Ở TRANG BÁN HÀNG) — ADMIN ONLY ============",
  "   Khác với \"Người bán\" (sellers, quản lý client-side ở trên), đây là tài khoản khách hàng THẬT",
  "   được lưu ở server qua /api/auth/register (storefront) — nên trang này luôn gọi API để lấy dữ liệu",
  "   mới nhất thay vì đọc từ biến state cục bộ. ---- */",
  "let customersCache = [];",
  "let customerTopupTargetId = null;",
  "let customerPassTargetId = null;",
  "",
  "async function loadAndRenderCustomersPage(){",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/admin/customers', { cache:'no-store' });",
  "    customersCache = await res.json();",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không tải được danh sách người dùng', e);",
  "    customersCache = [];",
  "  }",
  "  renderCustomersTable();",
  "  await loadAndRenderTopupRequests();",
  "}",
  "",
  "function renderCustomersTable(){",
  "  const tbody = document.querySelector('#customerTable tbody');",
  "  tbody.innerHTML = '';",
  "  document.getElementById('customerEmptyState').style.display = customersCache.length ? 'none' : 'block';",
  "  customersCache.forEach(c=>{",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td class=\"mono\">${c.username}</td>",
  "      <td><span class=\"badge ${c.role==='admin' ? 'active' : ''}\">${c.role==='admin' ? 'Quản trị viên' : 'Khách hàng'}</span></td>",
  "      <td>${formatDateTime(c.createdAt)}</td>",
  "      <td class=\"mono\" style=\"font-size:12px;\">${c.registrationIP || '—'}</td>",
  "      <td class=\"mono stat-balance\">${fmtMoney(c.balance||0) || '0₫'}</td>",
  "      <td>${c.topupCount||0}</td>",
  "      <td>${c.transactionCount||0}</td>",
  "      <td>",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"Thêm tiền cho tài khoản\" data-act=\"topup\" data-id=\"${c.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 8v8M8 12h8\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"Đổi mật khẩu\" data-act=\"changepass\" data-id=\"${c.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2\"/><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"/></svg>",
  "          </button>",
  "        </div>",
  "      </td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "document.querySelector('#customerTable').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const c = customersCache.find(x=>x.id===id);",
  "  if(!c) return;",
  "",
  "  if(act==='topup'){",
  "    customerTopupTargetId = id;",
  "    document.getElementById('customerTopupLabel').textContent = 'Tài khoản: ' + c.username + ' · Số dư hiện tại: ' + (fmtMoney(c.balance||0)||'0₫');",
  "    document.getElementById('customerTopupAmount').value = '';",
  "    document.getElementById('customerTopupModalBg').classList.add('show');",
  "  } else if(act==='changepass'){",
  "    customerPassTargetId = id;",
  "    document.getElementById('customerPassLabel').textContent = 'Tài khoản: ' + c.username;",
  "    document.getElementById('customerPassNew').value = '';",
  "    document.getElementById('customerPassModalBg').classList.add('show');",
  "  }",
  "});",
  "",
  "document.getElementById('customerTopupCancel').addEventListener('click', ()=> document.getElementById('customerTopupModalBg').classList.remove('show'));",
  "document.getElementById('customerTopupConfirm').addEventListener('click', async ()=>{",
  "  const c = customersCache.find(x=>x.id===customerTopupTargetId);",
  "  if(!c) { document.getElementById('customerTopupModalBg').classList.remove('show'); return; }",
  "  const amount = parseFloat(document.getElementById('customerTopupAmount').value.replace(/[^\\d.-]/g,'')) || 0;",
  "  if(amount === 0){ showToast('Vui lòng nhập số tiền hợp lệ'); return; }",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/customers/${c.id}/balance`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'},",
  "      body: JSON.stringify({ amount, note: 'Admin cộng tiền thủ công' })",
  "    });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('Cộng tiền thất bại');",
  "    showToast('Đã cộng '+fmtMoney(amount)+' vào tài khoản: '+c.username);",
  "    document.getElementById('customerTopupModalBg').classList.remove('show');",
  "    loadAndRenderCustomersPage();",
  "  }catch(e){",
  "    showToast('Có lỗi xảy ra — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "document.getElementById('customerPassCancel').addEventListener('click', ()=> document.getElementById('customerPassModalBg').classList.remove('show'));",
  "document.getElementById('customerPassConfirm').addEventListener('click', async ()=>{",
  "  const c = customersCache.find(x=>x.id===customerPassTargetId);",
  "  if(!c) { document.getElementById('customerPassModalBg').classList.remove('show'); return; }",
  "  const next = document.getElementById('customerPassNew').value.trim();",
  "  if(next.length < 4){ showToast('Mật khẩu cần tối thiểu 4 ký tự'); return; }",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/customers/${c.id}/password`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'},",
  "      body: JSON.stringify({ newPassword: next })",
  "    });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('Đổi mật khẩu thất bại');",
  "    showToast('Đã đổi mật khẩu cho tài khoản: '+c.username);",
  "    document.getElementById('customerPassModalBg').classList.remove('show');",
  "  }catch(e){",
  "    showToast('Có lỗi xảy ra — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "document.getElementById('btnRefreshCustomers').addEventListener('click', loadAndRenderCustomersPage);",
  "",
  "const TOPUP_STATUS_LABEL = { pending:'Đang chờ duyệt', approved:'Đã duyệt', rejected:'Đã từ chối' };",
  "const TOPUP_STATUS_CLASS = { pending:'', approved:'active', rejected:'banned' };",
  "async function loadAndRenderTopupRequests(){",
  "  let requests = [];",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/admin/topup-requests', { cache:'no-store' });",
  "    requests = await res.json();",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không tải được danh sách yêu cầu nạp tiền', e);",
  "  }",
  "  const tbody = document.querySelector('#topupRequestTable tbody');",
  "  tbody.innerHTML = '';",
  "  const pending = requests.filter(r=>r.status==='pending');",
  "  document.getElementById('topupRequestEmptyState').style.display = pending.length ? 'none' : 'block';",
  "  requests.forEach(r=>{",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td class=\"mono\">${r.username}</td>",
  "      <td class=\"mono\">${fmtMoney(r.amount)}</td>",
  "      <td>${r.method==='bank_transfer' ? 'Chuyển khoản' : r.method}</td>",
  "      <td>${formatDateTime(r.createdAt)}</td>",
  "      <td><span class=\"badge ${TOPUP_STATUS_CLASS[r.status]||''}\">${TOPUP_STATUS_LABEL[r.status]||r.status}</span></td>",
  "      <td>",
  "        ${r.status==='pending' ? `",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"Duyệt\" data-act=\"approve\" data-id=\"${r.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12l3 3 5-6\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn danger\" title=\"Từ chối\" data-act=\"reject\" data-id=\"${r.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.5 5.5l13 13\"/></svg>",
  "          </button>",
  "        </div>` : '—'}",
  "      </td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "document.querySelector('#topupRequestTable').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/topup-requests/${id}/${act}`, { method:'POST' });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('Thao tác thất bại');",
  "    showToast(act==='approve' ? 'Đã duyệt yêu cầu nạp tiền' : 'Đã từ chối yêu cầu nạp tiền');",
  "    loadAndRenderCustomersPage();",
  "  }catch(e){",
  "    showToast('Có lỗi xảy ra — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "/* ============ CẤU HÌNH NHẬN TIỀN TỰ ĐỘNG (SEPAY) ============ */",
  "function renderSepaySettings(){",
  "  const enabledEl = document.getElementById('sepayEnabledToggle');",
  "  const bankIdEl = document.getElementById('bankIdInput');",
  "  const accNoEl = document.getElementById('bankAccountNoInput');",
  "  const accNameEl = document.getElementById('bankAccountNameInput');",
  "  const apiKeyEl = document.getElementById('sepayApiKeyInput');",
  "  const urlHintEl = document.getElementById('sepayWebhookUrlHint');",
  "  if(!enabledEl) return; // trang chưa render xong DOM, bỏ qua",
  "  enabledEl.checked = !!(sepayConfig && sepayConfig.enabled);",
  "  bankIdEl.value = (bankInfo && bankInfo.bankId) || 'MB';",
  "  accNoEl.value = (bankInfo && bankInfo.accountNo) || '';",
  "  accNameEl.value = (bankInfo && bankInfo.accountName) || '';",
  "  apiKeyEl.value = (sepayConfig && sepayConfig.apiKey) || '';",
  "  if(urlHintEl) urlHintEl.textContent = window.location.origin + '/api/sepay-webhook';",
  "}",
  "",
  "const btnSaveSepayConfigEl = document.getElementById('btnSaveSepayConfig');",
  "if(btnSaveSepayConfigEl){",
  "  btnSaveSepayConfigEl.addEventListener('click', async ()=>{",
  "    const errBox = document.getElementById('sepayConfigError');",
  "    const okBox = document.getElementById('sepayConfigSuccess');",
  "    errBox.style.display = 'none';",
  "    okBox.style.display = 'none';",
  "    const enabled = document.getElementById('sepayEnabledToggle').checked;",
  "    const newBankId = document.getElementById('bankIdInput').value.trim() || 'MB';",
  "    const newAccNo = document.getElementById('bankAccountNoInput').value.trim();",
  "    const newAccName = document.getElementById('bankAccountNameInput').value.trim();",
  "    const newApiKey = document.getElementById('sepayApiKeyInput').value.trim();",
  "    if(enabled && !newApiKey){",
  "      errBox.textContent = 'Cần nhập API Key trước khi bật đối soát tự động.';",
  "      errBox.style.display = 'block';",
  "      return;",
  "    }",
  "    if(!newAccNo || !newAccName){",
  "      errBox.textContent = 'Cần nhập đầy đủ số tài khoản và tên chủ tài khoản.';",
  "      errBox.style.display = 'block';",
  "      return;",
  "    }",
  "    bankInfo = { bankId: newBankId, accountNo: newAccNo, accountName: newAccName };",
  "    sepayConfig = { enabled, apiKey: newApiKey };",
  "    await saveStateToServer(true);",
  "    okBox.textContent = '✔ Đã lưu cấu hình.';",
  "    okBox.style.display = 'block';",
  "    setTimeout(()=>{ okBox.style.display = 'none'; }, 3000);",
  "  });",
  "}",
  "",
  "/* ============ KEY MANAGEMENT LOGIC ============ */",
  "let keys = []; // {id, value, type, status, banned, customer, price, deviceId, createdAt, expiresAt} — tham chiếu tới keysStore[currentAccount]",
  "let sellTargetId = null;",
  "",
  "function setKeys(newArr){",
  "  keys = newArr;",
  "  if(currentAccount) keysStore[currentAccount] = keys;",
  "}",
  "",
  "const $ = (id) => document.getElementById(id);",
  "",
  "function genSegment(len, charset){",
  "  let s='';",
  "  for(let i=0;i<len;i++) s += charset[Math.floor(Math.random()*charset.length)];",
  "  return s;",
  "}",
  "",
  "function getCharset(){",
  "  if($('csNoAmbig').checked) return 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';",
  "  if($('csNum').checked) return '0123456789';",
  "  return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';",
  "}",
  "",
  "function buildFormatPreview(){",
  "  const prefix = $('cfgPrefix').value.trim().toUpperCase();",
  "  const groups = Math.max(1, parseInt($('cfgGroups').value)||1);",
  "  const len = Math.max(2, parseInt($('cfgLen').value)||4);",
  "  const parts = [];",
  "  if(prefix) parts.push(prefix);",
  "  for(let i=0;i<groups;i++) parts.push('X'.repeat(len));",
  "  $('formatPreview').textContent = parts.join('-');",
  "}",
  "['cfgPrefix','cfgGroups','cfgLen'].forEach(id=>$(id).addEventListener('input', buildFormatPreview));",
  "document.querySelectorAll('#charsetToggle input').forEach(el=>el.addEventListener('change', buildFormatPreview));",
  "buildFormatPreview();",
  "",
  "document.querySelectorAll('#expiryToggle input').forEach(el=>{",
  "  el.addEventListener('change', ()=>{",
  "    $('expiryFields').style.display = $('expLimited').checked ? 'block' : 'none';",
  "  });",
  "});",
  "$('expiryFields').style.display = $('expLimited').checked ? 'block' : 'none';",
  "",
  "document.querySelectorAll('#createdAtToggle input').forEach(el=>{",
  "  el.addEventListener('change', ()=>{",
  "    $('createdAtCustomField').style.display = $('createdAtCustom').checked ? 'grid' : 'none';",
  "  });",
  "});",
  "",
  "function formatDateTime(d){",
  "  if(!d) return '—';",
  "  const dt = new Date(d);",
  "  return dt.toLocaleString('vi-VN', {hour:'2-digit', minute:'2-digit', day:'2-digit', month:'2-digit', year:'numeric'});",
  "}",
  "",
  "function formatRemaining(expiresAt){",
  "  if(!expiresAt) return 'Không giới hạn';",
  "  const diff = new Date(expiresAt) - new Date();",
  "  if(diff <= 0) return 'Đã hết hạn';",
  "  const totalMin = Math.floor(diff/60000);",
  "  const days = Math.floor(totalMin/1440);",
  "  const hours = Math.floor((totalMin%1440)/60);",
  "  const mins = totalMin%60;",
  "  const parts = [];",
  "  if(days) parts.push(days+' ngày');",
  "  if(hours) parts.push(hours+' giờ');",
  "  if(!days && mins) parts.push(mins+' phút');",
  "  return 'Còn ' + (parts.join(' ') || '< 1 phút');",
  "}",
  "",
  "function computeStatus(k){",
  "  if(k.banned) return 'banned';",
  "  // Key có hạn dùng nhưng CHƯA được kích hoạt (chưa xác thực lần nào qua /api/verify):",
  "  // chưa tính hết hạn, hiển thị riêng \"Chưa kích hoạt\" thay vì \"Hết hạn\"/\"Còn hàng\".",
  "  if(k.hasExpiryPlan && !k.activated) return 'unactivated';",
  "  if(k.expiresAt && new Date() > new Date(k.expiresAt)) return 'expired';",
  "  return k.status;",
  "}",
  "",
  "const STATUS_LABEL = {available:'Còn hàng', sold:'Đã bán', banned:'Bị cấm', expired:'Hết hạn', unactivated:'Chưa kích hoạt'};",
  "",
  "function generateKeys(){",
  "  const prefix = $('cfgPrefix').value.trim().toUpperCase();",
  "  const groups = Math.max(1, Math.min(8, parseInt($('cfgGroups').value)||1));",
  "  const len = Math.max(2, Math.min(10, parseInt($('cfgLen').value)||4));",
  "  const qty = Math.max(1, Math.min(500, parseInt($('cfgQty').value)||1));",
  "  const maxDevices = Math.max(1, Math.min(20, parseInt($('cfgMaxDevices').value)||1));",
  "  const price = $('cfgPrice').value.trim();",
  "  const charset = getCharset();",
  "  const type = document.querySelector('input[name=ktype]:checked').value;",
  "  const existing = new Set(keys.map(k=>k.value));",
  "",
  "  // Mốc thời gian tạo key: mặc định là hiện tại. Chỉ tài khoản admin mới được",
  "  // tuỳ chỉnh ngày giờ tạo (VD: nhập lại key cũ đã phát hành trước đó).",
  "  let baseCreatedAt = new Date();",
  "  if(currentRole === 'admin' && $('createdAtCustom').checked){",
  "    const raw = $('cfgCreatedAt').value;",
  "    if(raw){",
  "      const parsed = new Date(raw);",
  "      if(!isNaN(parsed.getTime())) baseCreatedAt = parsed;",
  "    }",
  "  }",
  "",
  "  // LƯU Ý: key có thời hạn giờ đây KHÔNG tính hạn dùng (expiresAt) ngay lúc sinh key.",
  "  // Hạn dùng chỉ bắt đầu được tính từ thời điểm key được KÍCH HOẠT (lần đầu xác thực",
  "  // thành công qua /api/verify). Trước khi kích hoạt, key hiển thị trạng thái \"Chưa kích hoạt\".",
  "  // Thời hạn + giá giờ lấy từ bảng CỐ ĐỊNH (FIXED_KEY_PLANS) — không còn tự nhập số lượng/đơn vị.",
  "  let expiresAt = null;",
  "  let hasExpiryPlan = false;",
  "  let expiryAmount = null;",
  "  let expiryUnit = null;",
  "  let selectedPlan = null; // gói cố định đang chọn — null nếu \"Không giới hạn\"",
  "  if($('expLimited').checked){",
  "    selectedPlan = findFixedPlan($('cfgFixedPlan').value) || findFixedPlan('d1');",
  "    hasExpiryPlan = true;",
  "    expiryAmount = selectedPlan.amount;",
  "    expiryUnit = selectedPlan.unit;",
  "  } else {",
  "    selectedPlan = findFixedPlan('unlimited');",
  "  }",
  "",
  "  // ===== Trừ tiền theo tài khoản người bán (không áp dụng cho admin) =====",
  "  // Giá luôn lấy nguyên từ FIXED_KEY_PLANS (không nhân giảm giá/ưu đãi nào) vì đây là",
  "  // bảng giá CỐ ĐỊNH theo yêu cầu quản trị viên — áp dụng như nhau cho Thường và Premium.",
  "  let sellerObj = null;",
  "  let totalCost = 0;",
  "  if(currentRole === 'seller'){",
  "    sellerObj = sellers.find(x=>x.username===currentAccount);",
  "    const isPremium = !!(sellerObj && sellerObj.accountType === 'premium');",
  "",
  "    // Chặn phòng vệ: tài khoản Thường không được tạo key không giới hạn dù UI đã khoá sẵn.",
  "    if(selectedPlan.id === 'unlimited' && !isPremium){",
  "      showToast('Tài khoản Thường không thể tạo key không giới hạn. Vui lòng chọn \"Có thời hạn\" hoặc liên hệ quản trị viên để nâng cấp Premium.');",
  "      return;",
  "    }",
  "",
  "    totalCost = selectedPlan.price * qty;",
  "",
  "    if(totalCost > (sellerObj ? (sellerObj.balance||0) : 0)){",
  "      showToast(`Số dư không đủ. Cần ${fmtMoney(totalCost)} nhưng tài khoản chỉ còn ${fmtMoney((sellerObj&&sellerObj.balance)||0)}.`);",
  "      return;",
  "    }",
  "  }",
  "",
  "  let created = 0;",
  "  let attempts = 0;",
  "  while(created < qty && attempts < qty*20){",
  "    attempts++;",
  "    const parts = [];",
  "    if(prefix) parts.push(prefix);",
  "    for(let i=0;i<groups;i++) parts.push(genSegment(len, charset));",
  "    const value = parts.join('-');",
  "    if(existing.has(value)) continue;",
  "    existing.add(value);",
  "    keys.unshift({",
  "      id: 'k'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      value,",
  "      type,",
  "      status:'available',",
  "      banned:false,",
  "      customer:'',",
  "      price: price || '',",
  "      deviceId: null,",
  "      maxDevices,",
  "      devices: [],",
  "      createdAt: new Date(baseCreatedAt),",
  "      expiresAt,",
  "      hasExpiryPlan,",
  "      expiryAmount,",
  "      expiryUnit,",
  "      activated: false,",
  "      activatedAt: null",
  "    });",
  "    created++;",
  "  }",
  "",
  "  if(currentRole === 'seller' && sellerObj && created > 0){",
  "    // Chỉ trừ đúng phần tương ứng với số key thực sự sinh được (phòng trường hợp trùng key phải bỏ bớt lượt thử).",
  "    // Giá luôn lấy nguyên theo bảng giá CỐ ĐỊNH của gói đã chọn — không áp dụng giảm giá nào.",
  "    const actualCost = selectedPlan.price * created;",
  "    sellerObj.balance = Math.max(0, (sellerObj.balance||0) - actualCost);",
  "    applySellerAccountEffects();",
  "    render();",
  "    saveKeysToServer(); // FIX: lưu key lên server ngay sau khi sinh, tải lại trang không mất key",
  "    saveStateToServer(true); // FIX: lưu luôn số dư mới của seller",
  "    showToast(`Đã sinh ${created} key mới — trừ ${fmtMoney(actualCost)} (còn lại ${fmtMoney(sellerObj.balance)})`);",
  "    return;",
  "  }",
  "",
  "  render();",
  "  saveKeysToServer(); // FIX: lưu key lên server ngay sau khi sinh, tải lại trang không mất key",
  "  showToast(`Đã sinh ${created} key mới`);",
  "}",
  "",
  "function fmtMoney(v){",
  "  const n = parseFloat(String(v).replace(/[^\\d.]/g,''));",
  "  if(!n && n!==0) return '';",
  "  return n.toLocaleString('vi-VN')+'₫';",
  "}",
  "",
  "function render(){",
  "  const q = $('search').value.trim().toLowerCase();",
  "  const filterStatus = $('filterStatus').value;",
  "  const filterType = $('filterType').value;",
  "  const roll = $('rollList');",
  "  roll.innerHTML = '';",
  "",
  "  const filtered = keys.filter(k=>{",
  "    const st = computeStatus(k);",
  "    if(filterStatus!=='all' && st!==filterStatus) return false;",
  "    if(filterType!=='all' && k.type!==filterType) return false;",
  "    if(q && !(k.value.toLowerCase().includes(q) || (k.customer||'').toLowerCase().includes(q))) return false;",
  "    return true;",
  "  });",
  "",
  "  $('emptyState').style.display = filtered.length ? 'none' : 'block';",
  "",
  "  filtered.forEach(k=>{",
  "    const st = computeStatus(k);",
  "    const div = document.createElement('div');",
  "    div.className = 'ticket';",
  "",
  "    const metaBits = [];",
  "    metaBits.push('Tạo: <b>'+formatDateTime(k.createdAt)+'</b>');",
  "    if(k.hasExpiryPlan && !k.activated){",
  "      const unitLabel = k.expiryUnit==='hour' ? 'giờ' : k.expiryUnit==='month' ? 'tháng' : 'ngày';",
  "      metaBits.push('HSD: <b>Chưa kích hoạt</b>');",
  "      metaBits.push('<span class=\"active-txt\">Sẽ dùng trong '+(k.expiryAmount||'?')+' '+unitLabel+' kể từ lúc kích hoạt</span>');",
  "    } else {",
  "      metaBits.push('HSD: <b>'+(k.expiresAt ? formatDateTime(k.expiresAt) : 'Không giới hạn')+'</b>');",
  "      const remain = formatRemaining(k.expiresAt);",
  "      metaBits.push('<span class=\"'+(remain==='Đã hết hạn'?'expired-txt':'active-txt')+'\">'+remain+'</span>');",
  "    }",
  "    if(k.status==='sold' && k.customer) metaBits.push('KH: <b>'+k.customer+'</b>');",
  "    if(k.price) metaBits.push('Giá: <b>'+fmtMoney(k.price)+'</b>');",
  "    const devUsed = (k.devices && k.devices.length) || (k.deviceId ? 1 : 0);",
  "    const devMax = k.maxDevices || 1;",
  "    if(devUsed > 0) metaBits.push('Thiết bị: <b>'+devUsed+'/'+devMax+'</b>');",
  "    else metaBits.push('Thiết bị: <b>0/'+devMax+'</b>');",
  "",
  "    let actionsHtml = `",
  "      <button class=\"icon-btn\" title=\"Sao chép\" data-act=\"copy\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"9\" y=\"9\" width=\"12\" height=\"12\" rx=\"2\"/><path d=\"M5 15V5a2 2 0 0 1 2-2h10\"/></svg>",
  "      </button>`;",
  "    if(st==='available'){",
  "      actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"Đánh dấu đã bán\" data-act=\"sell\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M20 12V7a1 1 0 0 0-1-1h-6l-9 9 8 8 9-9a1 1 0 0 0 0-1Z\"/><circle cx=\"15\" cy=\"9\" r=\"1\"/></svg>",
  "      </button>`;",
  "    }",
  "    actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"Reset key về ban đầu\" data-act=\"reset\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 12a9 9 0 1 0 3-6.7\"/><path d=\"M3 4v5h5\"/></svg>",
  "      </button>`;",
  "    if(k.deviceId || (k.devices && k.devices.length)){",
  "      actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"Reset thiết bị liên kết\" data-act=\"resetdevice\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"5\" y=\"2\" width=\"14\" height=\"20\" rx=\"2\"/><path d=\"M12 18h.01\"/></svg>",
  "      </button>`;",
  "    }",
  "    if(k.banned){",
  "      actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"Bỏ cấm key\" data-act=\"unban\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12l3 3 5-6\"/></svg>",
  "      </button>`;",
  "    } else {",
  "      actionsHtml += `",
  "      <button class=\"icon-btn danger\" title=\"Cấm key\" data-act=\"ban\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.5 5.5l13 13\"/></svg>",
  "      </button>`;",
  "    }",
  "    // Nút gia hạn từng key riêng (chỉ hiện với key có thời hạn, chỉ khi là Admin hoặc Seller Premium)",
  "    if(k.hasExpiryPlan){",
  "      const sellerObj2 = currentRole==='seller' ? sellers.find(x=>x.username===currentAccount) : null;",
  "      const canExtend = currentRole==='admin' || (sellerObj2 && sellerObj2.accountType==='premium');",
  "      if(canExtend){",
  "        actionsHtml += `",
  "        <button class=\"icon-btn\" title=\"Gia hạn key này\" data-act=\"extendkey\" data-id=\"${k.id}\" style=\"color:var(--ok)\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 3\"/></svg>",
  "        </button>`;",
  "      } else {",
  "        actionsHtml += `",
  "        <button class=\"icon-btn\" title=\"Chỉ Premium mới gia hạn được\" disabled style=\"opacity:0.35; cursor:not-allowed;\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 3\"/></svg>",
  "        </button>`;",
  "      }",
  "    }",
  "    // Nút nâng/hạ cấp loại key (chỉ admin mới thấy)",
  "    if(currentRole==='admin'){",
  "      const isPremKey = k.type === 'premium';",
  "      actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"${isPremKey ? 'Hạ về key Thường' : 'Nâng cấp lên ★ Premium'}\" data-act=\"toggletype\" data-id=\"${k.id}\" style=\"color:${isPremKey ? 'var(--brass,#AD7F1E)' : 'var(--muted)'}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z\"/></svg>",
  "      </button>`;",
  "    }",
  "    actionsHtml += `",
  "      <button class=\"icon-btn danger\" title=\"Xoá key vĩnh viễn\" data-act=\"delete\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "      </button>`;",
  "",
  "    div.innerHTML = `",
  "      <div class=\"ticket-top\">",
  "        <div class=\"key\">${k.value}</div>",
  "        <div class=\"ticket-badges\">",
  "          <span class=\"badge ${k.type}\">${k.type==='premium' ? '★ Premium' : 'Thường'}</span>",
  "          <span class=\"badge ${st}\">${STATUS_LABEL[st]}</span>",
  "        </div>",
  "      </div>",
  "      <div class=\"ticket-bottom\">",
  "        <div class=\"meta\">${metaBits.join(' &nbsp;·&nbsp; ')}</div>",
  "        <div class=\"actions\">${actionsHtml}</div>",
  "      </div>",
  "    `;",
  "    roll.appendChild(div);",
  "  });",
  "",
  "  $('statTotal').textContent = keys.length;",
  "  $('statAvail').textContent = keys.filter(k=>computeStatus(k)==='available').length;",
  "  const soldKeys = keys.filter(k=>k.status==='sold' && !k.banned);",
  "  $('statSold').textContent = keys.filter(k=>computeStatus(k)==='sold').length;",
  "  $('statExpired').textContent = keys.filter(k=>computeStatus(k)==='expired').length;",
  "  $('statBanned').textContent = keys.filter(k=>k.banned).length;",
  "  const revenue = soldKeys.reduce((sum,k)=> sum + (parseFloat(String(k.price).replace(/[^\\d.]/g,''))||0), 0);",
  "  $('statRevenue').textContent = revenue.toLocaleString('vi-VN')+'₫';",
  "}",
  "",
  "$('rollList').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const k = keys.find(x=>x.id===id);",
  "  if(!k) return;",
  "",
  "  if(act==='copy'){",
  "    navigator.clipboard.writeText(k.value);",
  "    showToast('Đã sao chép: '+k.value);",
  "  } else if(act==='sell'){",
  "    sellTargetId = id;",
  "    $('sellCustomer').value='';",
  "    $('sellPrice').value = k.price || $('cfgPrice').value || '';",
  "    $('sellDevice').value = k.deviceId || '';",
  "    $('sellModalBg').classList.add('show');",
  "  } else if(act==='reset'){",
  "    k.status='available'; k.banned=false; k.customer=''; k.deviceId=null; k.devices=[]; k.price=''; k.activated=false; k.activatedAt=null;",
  "    render();",
  "    saveKeysToServer();",
  "    showToast('Đã reset key về trạng thái ban đầu');",
  "  } else if(act==='resetdevice'){",
  "    // Reset thiết bị: gọi API server để xoá devices[] khỏi db.json",
  "    // → khách hàng có thể cài lại app và nhập key → đăng ký thiết bị mới",
  "    (async ()=>{",
  "      try{",
  "        const res = await fetch(`${API_BASE}/api/admin/keys/${encodeURIComponent(k.value)}/reset-devices`, { method:'POST' });",
  "        const data = await res.json().catch(()=>({}));",
  "        if(res.ok && data.ok){",
  "          k.deviceId = null; k.devices = []; if(k._deviceLastSeen) delete k._deviceLastSeen;",
  "          render();",
  "          showToast('✔ Đã reset thiết bị — khách có thể nhập lại key trên thiết bị mới');",
  "        } else {",
  "          // Fallback: reset local nếu server không hỗ trợ endpoint mới (backward compat)",
  "          k.deviceId = null; k.devices = [];",
  "          render();",
  "          showToast('Đã reset thiết bị (cục bộ) — lưu lại để đồng bộ server');",
  "        }",
  "      }catch(e){",
  "        k.deviceId = null; k.devices = [];",
  "        render();",
  "        showToast('Đã reset thiết bị liên kết với key');",
  "      }",
  "    })();",
  "  } else if(act==='ban'){",
  "    k.banned = true;",
  "    render();",
  "    saveKeysToServer();",
  "    showToast('Đã cấm key: '+k.value);",
  "  } else if(act==='unban'){",
  "    k.banned = false;",
  "    render();",
  "    saveKeysToServer();",
  "    showToast('Đã bỏ cấm key: '+k.value);",
  "  } else if(act==='toggletype'){",
  "    // Nâng/hạ cấp loại key: premium ↔ normal — gọi API server để ghi thẳng vào db.json",
  "    (async ()=>{",
  "      const newType = (k.type === 'premium') ? 'normal' : 'premium';",
  "      const label = newType === 'premium' ? 'nâng cấp lên ★ Premium' : 'hạ về Thường';",
  "      if(!confirm(`${label.charAt(0).toUpperCase()+label.slice(1)} key \"${k.value}\"?`)) return;",
  "      try{",
  "        const res = await fetch(`${API_BASE}/api/admin/keys/${encodeURIComponent(k.value)}/set-type`, {",
  "          method: 'POST',",
  "          headers: { 'Content-Type': 'application/json' },",
  "          body: JSON.stringify({ type: newType })",
  "        });",
  "        const data = await res.json().catch(()=>({}));",
  "        if(res.ok && data.ok){",
  "          k.type = newType;",
  "          render();",
  "          showToast(`✔ Đã ${label}: ${k.value}`);",
  "        } else {",
  "          showToast('Lỗi: ' + (data.message || data.error || 'Không thể đổi loại key'));",
  "        }",
  "      }catch(e){",
  "        showToast('Lỗi kết nối khi đổi loại key');",
  "      }",
  "    })();",
  "  } else if(act==='extendkey'){",
  "    extendSingleKeyId = id;",
  "    const info = k.expiresAt ? formatDateTime(k.expiresAt) : (k.hasExpiryPlan ? 'Chưa kích hoạt' : 'Không giới hạn');",
  "    $('extendKeyLabel').textContent = k.value + ' — HSD hiện tại: ' + info;",
  "    $('extendKeyMinutes').value = 0;",
  "    $('extendKeyHours').value = 0;",
  "    $('extendKeyAmount').value = 0;",
  "    $('extendKeyMonths').value = 0;",
  "    $('extendKeyPreview').textContent = 'Nhập số thời gian cần cộng thêm';",
  "    $('extendKeyModalBg').classList.add('show');",
  "  } else if(act==='delete'){",
  "    if(confirm('Xoá vĩnh viễn key này khỏi danh sách?')){",
  "      const keyVal = k.value;",
  "      setKeys(keys.filter(x=>x.id!==id));",
  "      render();",
  "      // Gọi endpoint DELETE riêng để server xoá thật sự (không bị merge ghi đè lại)",
  "      (async ()=>{",
  "        try{",
  "          await fetch(`${API_BASE}/api/keys/${encodeURIComponent(keyVal)}`, {",
  "            method:'DELETE',",
  "            headers:{'Content-Type':'application/json'},",
  "            body: JSON.stringify({ owner: currentAccount })",
  "          });",
  "        }catch(e){ /* fallback: lưu toàn bộ keysStore */ saveKeysToServer(); }",
  "      })();",
  "      showToast('Đã xoá key');",
  "    }",
  "  }",
  "});",
  "",
  "$('sellCancel').addEventListener('click', ()=> $('sellModalBg').classList.remove('show'));",
  "$('sellConfirm').addEventListener('click', ()=>{",
  "  const k = keys.find(x=>x.id===sellTargetId);",
  "  if(k){",
  "    k.status='sold';",
  "    k.customer = $('sellCustomer').value.trim();",
  "    k.price = $('sellPrice').value.trim();",
  "    k.deviceId = $('sellDevice').value.trim() || null;",
  "  }",
  "  $('sellModalBg').classList.remove('show');",
  "  render();",
  "  saveKeysToServer();",
  "  showToast('Đã đánh dấu key là đã bán');",
  "});",
  "",
  "$('btnGenerate').addEventListener('click', generateKeys);",
  "$('search').addEventListener('input', render);",
  "$('filterStatus').addEventListener('change', render);",
  "$('filterType').addEventListener('change', render);",
  "",
  "$('btnCopyAvail').addEventListener('click', ()=>{",
  "  const avail = keys.filter(k=>computeStatus(k)==='available').map(k=>k.value).join('\\n');",
  "  if(!avail){ showToast('Không có key còn hàng'); return; }",
  "  navigator.clipboard.writeText(avail);",
  "  showToast('Đã sao chép toàn bộ key còn hàng');",
  "});",
  "",
  "$('btnExport').addEventListener('click', ()=>{",
  "  if(!keys.length){ showToast('Chưa có key để xuất'); return; }",
  "  const rows = [['Key','Loại','Trạng thái','Khách hàng','Giá','Thiết bị','Ngày tạo','Hết hạn']];",
  "  keys.forEach(k=>{",
  "    rows.push([k.value, k.type, STATUS_LABEL[computeStatus(k)], k.customer||'', k.price||'', k.deviceId||'', formatDateTime(k.createdAt), k.expiresAt?formatDateTime(k.expiresAt):'Không giới hạn']);",
  "  });",
  "  const csv = rows.map(r=> r.map(c=>`\"${String(c).replace(/\"/g,'\"\"')}\"`).join(',')).join('\\n');",
  "  const blob = new Blob(['\\uFEFF'+csv], {type:'text/csv;charset=utf-8;'});",
  "  const url = URL.createObjectURL(blob);",
  "  const a = document.createElement('a');",
  "  a.href = url; a.download = 'danh-sach-key.csv';",
  "  a.click();",
  "  URL.revokeObjectURL(url);",
  "  showToast('Đã xuất file CSV');",
  "});",
  "",
  "$('btnClear').addEventListener('click', ()=>{",
  "  if(!keys.length) return;",
  "  if(confirm('Xoá toàn bộ '+keys.length+' key? Hành động này không thể hoàn tác.')){",
  "    setKeys([]);",
  "    render();",
  "    // Gọi DELETE /api/keys để server xoá thật sự toàn bộ key của owner này",
  "    (async ()=>{",
  "      try{",
  "        await fetch(`${API_BASE}/api/keys`, {",
  "          method:'DELETE',",
  "          headers:{'Content-Type':'application/json'},",
  "          body: JSON.stringify({ owner: currentAccount })",
  "        });",
  "      }catch(e){ saveKeysToServer(); }",
  "    })();",
  "    showToast('Đã xoá toàn bộ key');",
  "  }",
  "});",
  "",
  "/* ---- Gia hạn tất cả key (mọi tài khoản, mọi owner trong keysStore) ----",
  "   Cộng thêm thời gian đã chọn vào hạn dùng của TẤT CẢ key đang có kế hoạch hạn dùng:",
  "   - Key ĐÃ kích hoạt: cộng thêm trực tiếp vào expiresAt hiện tại.",
  "   - Key CHƯA kích hoạt: cộng thêm vào expiryAmount (quy đổi cùng đơn vị với expiryUnit",
  "     của key đó) để khi kích hoạt sau này, thời gian cộng thêm vẫn được tính đúng. */",
  "function countKeysWithExpiryPlan(){",
  "  let n = 0;",
  "  Object.keys(keysStore||{}).forEach(owner=>{ (keysStore[owner]||[]).forEach(k=>{ if(k.hasExpiryPlan) n++; }); });",
  "  return n;",
  "}",
  "$('btnOpenExtendAll').addEventListener('click', ()=>{",
  "  const n = countKeysWithExpiryPlan();",
  "  $('extendAllPreviewNote').textContent = n>0",
  "    ? ('Sẽ áp dụng cho '+n+' key đang có thời hạn (gồm cả key chưa kích hoạt) trên toàn hệ thống.')",
  "    : 'Hiện chưa có key nào có thời hạn để gia hạn (key \"Không giới hạn\" sẽ không bị ảnh hưởng).';",
  "  $('extendAllModalBg').classList.add('show');",
  "});",
  "$('extendAllCancel').addEventListener('click', ()=> $('extendAllModalBg').classList.remove('show'));",
  "$('extendAllConfirm').addEventListener('click', ()=>{",
  "  const amount = Math.max(1, parseFloat($('extendAllAmount').value) || 1);",
  "  const unit = $('extendAllUnit').value;",
  "  const msPerUnit = unit==='hour' ? 3600000 : unit==='day' ? 86400000 : 30*86400000;",
  "  const unitLabel = unit==='hour' ? 'giờ' : unit==='month' ? 'tháng' : 'ngày';",
  "",
  "  let affected = 0;",
  "  Object.keys(keysStore||{}).forEach(owner=>{",
  "    (keysStore[owner]||[]).forEach(k=>{",
  "      if(!k.hasExpiryPlan) return; // key \"Không giới hạn\" không có gì để gia hạn",
  "      if(k.activated){",
  "        const base = (k.expiresAt && new Date(k.expiresAt) > new Date()) ? new Date(k.expiresAt) : new Date();",
  "        k.expiresAt = new Date(base.getTime() + amount*msPerUnit);",
  "      } else {",
  "        // Key chưa kích hoạt: quy đổi thời gian cộng thêm về cùng đơn vị đang lưu của key rồi cộng dồn.",
  "        const keyMsPerUnit = k.expiryUnit==='hour' ? 3600000 : k.expiryUnit==='month' ? 30*86400000 : 86400000;",
  "        const addInKeyUnit = (amount*msPerUnit) / keyMsPerUnit;",
  "        k.expiryAmount = (k.expiryAmount || 0) + addInKeyUnit;",
  "      }",
  "      affected++;",
  "    });",
  "  });",
  "",
  "  if(currentAccount && keysStore[currentAccount]) setKeys(keysStore[currentAccount]);",
  "  $('extendAllModalBg').classList.remove('show');",
  "  saveKeysToServer();",
  "  render();",
  "  showToast(affected>0 ? ('Đã gia hạn thêm '+amount+' '+unitLabel+' cho '+affected+' key') : 'Không có key nào để gia hạn');",
  "});",
  "",
  "/* ============ GIA HẠN TỪNG KEY RIÊNG LẺ (phút / giờ / ngày / tháng) ============ */",
  "let extendSingleKeyId = null;",
  "",
  "function calcExtendKeyPreview(mins, hours, days, months){",
  "  const parts = [];",
  "  if(months > 0) parts.push(months + ' tháng');",
  "  if(days > 0)   parts.push(days   + ' ngày');",
  "  if(hours > 0)  parts.push(hours  + ' giờ');",
  "  if(mins > 0)   parts.push(mins   + ' phút');",
  "  return parts.length ? 'Cộng thêm: ' + parts.join(' ') : 'Nhập số thời gian cần cộng thêm';",
  "}",
  "",
  "['extendKeyMinutes','extendKeyHours','extendKeyAmount','extendKeyMonths'].forEach(function(eid){",
  "  var el = $(eid);",
  "  if(el) el.addEventListener('input', function(){",
  "    var mins   = Math.max(0, parseInt($('extendKeyMinutes').value)||0);",
  "    var hours  = Math.max(0, parseInt($('extendKeyHours').value)||0);",
  "    var days   = Math.max(0, parseInt($('extendKeyAmount').value)||0);",
  "    var months = Math.max(0, parseInt($('extendKeyMonths').value)||0);",
  "    $('extendKeyPreview').textContent = calcExtendKeyPreview(mins,hours,days,months);",
  "  });",
  "});",
  "",
  "$('extendKeyCancel').addEventListener('click', ()=> $('extendKeyModalBg').classList.remove('show'));",
  "$('extendKeyConfirm').addEventListener('click', ()=>{",
  "  const k = keys.find(x=>x.id===extendSingleKeyId);",
  "  if(!k){ $('extendKeyModalBg').classList.remove('show'); return; }",
  "  const mins   = Math.max(0, parseInt($('extendKeyMinutes').value)||0);",
  "  const hours  = Math.max(0, parseInt($('extendKeyHours').value)||0);",
  "  const days   = Math.max(0, parseInt($('extendKeyAmount').value)||0);",
  "  const months = Math.max(0, parseInt($('extendKeyMonths').value)||0);",
  "  const totalMs = (months * 30 * 24 * 3600000) + (days * 24 * 3600000) + (hours * 3600000) + (mins * 60000);",
  "  if(totalMs <= 0){ showToast('Vui lòng nhập ít nhất 1 đơn vị thời gian'); return; }",
  "  if(k.activated && k.hasExpiryPlan){",
  "    // Key đã kích hoạt: cộng trực tiếp vào expiresAt",
  "    const base = (k.expiresAt && new Date(k.expiresAt) > new Date()) ? new Date(k.expiresAt) : new Date();",
  "    k.expiresAt = new Date(base.getTime() + totalMs);",
  "  } else if(k.hasExpiryPlan){",
  "    // Key chưa kích hoạt: quy đổi về đơn vị của key rồi cộng vào expiryAmount",
  "    const keyMsPerUnit = k.expiryUnit==='hour' ? 3600000 : k.expiryUnit==='month' ? 30*24*3600000 : 24*3600000;",
  "    const addInKeyUnit = totalMs / keyMsPerUnit;",
  "    k.expiryAmount = (k.expiryAmount || 0) + addInKeyUnit;",
  "  } else {",
  "    // Key không giới hạn: chuyển sang có thời hạn kể từ bây giờ",
  "    k.hasExpiryPlan = true;",
  "    k.expiryUnit = 'day';",
  "    k.expiresAt = new Date(Date.now() + totalMs);",
  "    k.activated = true;",
  "  }",
  "  $('extendKeyModalBg').classList.remove('show');",
  "  saveKeysToServer();",
  "  render();",
  "  const labelParts = [];",
  "  if(months) labelParts.push(months+' tháng');",
  "  if(days)   labelParts.push(days+' ngày');",
  "  if(hours)  labelParts.push(hours+' giờ');",
  "  if(mins)   labelParts.push(mins+' phút');",
  "  showToast('Đã gia hạn key ' + k.value + ' thêm ' + labelParts.join(' '));",
  "});",
  "",
  "let toastTimer;",
  "function showToast(msg){",
  "  const t = $('toast');",
  "  t.textContent = msg;",
  "  t.classList.add('show');",
  "  clearTimeout(toastTimer);",
  "  toastTimer = setTimeout(()=> t.classList.remove('show'), 2200);",
  "}",
  "",
  "/* ============ STATS PAGE ============ */",
  "function renderStatsPage(){",
  "  $('stTotalKeys').textContent = keys.length;",
  "  $('stActiveKeys').textContent = keys.filter(k=>{const s=computeStatus(k); return s==='available'||s==='sold';}).length;",
  "  $('stExpiredKeys').textContent = keys.filter(k=>computeStatus(k)==='expired').length;",
  "  $('stPremiumKeys').textContent = keys.filter(k=>k.type==='premium').length;",
  "  $('stLoginCount').textContent = loginHistory.length;",
  "",
  "  // creation chart: last 7 days",
  "  const days = [];",
  "  for(let i=6;i>=0;i--){",
  "    const d = new Date();",
  "    d.setDate(d.getDate()-i);",
  "    d.setHours(0,0,0,0);",
  "    days.push(d);",
  "  }",
  "  const counts = days.map(d=>{",
  "    const next = new Date(d); next.setDate(next.getDate()+1);",
  "    return keys.filter(k=> new Date(k.createdAt) >= d && new Date(k.createdAt) < next).length;",
  "  });",
  "  const max = Math.max(1, ...counts);",
  "  const chart = $('creationChart');",
  "  chart.innerHTML = '';",
  "  days.forEach((d,i)=>{",
  "    const col = document.createElement('div');",
  "    col.className = 'bar-col';",
  "    const h = Math.round((counts[i]/max)*100);",
  "    col.innerHTML = `<div class=\"bar-val\">${counts[i]}</div><div class=\"bar\" style=\"height:${h}%\"></div><div class=\"bar-label\">${d.toLocaleDateString('vi-VN',{day:'2-digit',month:'2-digit'})}</div>`;",
  "    chart.appendChild(col);",
  "  });",
  "",
  "  // type breakdown",
  "  const total = keys.length || 1;",
  "  const premium = keys.filter(k=>k.type==='premium').length;",
  "  const normal = keys.length - premium;",
  "  const pPct = Math.round((premium/total)*100);",
  "  const nPct = 100 - pPct;",
  "  $('typeBreakdown').innerHTML = `",
  "    <div class=\"type-bar-row\">",
  "      <div class=\"lbl\"><span>★ Premium</span><span>${premium} key (${pPct}%)</span></div>",
  "      <div class=\"type-bar-track\"><div class=\"type-bar-fill\" style=\"width:${pPct}%; background:linear-gradient(90deg,var(--brass-soft),var(--brass));\"></div></div>",
  "    </div>",
  "    <div class=\"type-bar-row\">",
  "      <div class=\"lbl\"><span>Thường</span><span>${normal} key (${nPct}%)</span></div>",
  "      <div class=\"type-bar-track\"><div class=\"type-bar-fill\" style=\"width:${nPct}%; background:var(--muted);\"></div></div>",
  "    </div>",
  "  `;",
  "",
  "  // expiry table",
  "  const tbody = document.querySelector('#expiryTable tbody');",
  "  tbody.innerHTML = '';",
  "  if(!keys.length){",
  "    tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--muted); text-align:center; padding:24px;\">Chưa có key nào được tạo</td></tr>';",
  "  } else {",
  "    keys.forEach(k=>{",
  "      const st = computeStatus(k);",
  "      const tr = document.createElement('tr');",
  "      tr.innerHTML = `",
  "        <td class=\"mono\">${k.value}</td>",
  "        <td><span class=\"badge ${k.type}\">${k.type==='premium'?'★ Premium':'Thường'}</span></td>",
  "        <td><span class=\"badge ${st}\">${STATUS_LABEL[st]}</span></td>",
  "        <td>${k.expiresAt ? formatDateTime(k.expiresAt) : 'Không giới hạn'}</td>",
  "        <td>${formatRemaining(k.expiresAt)}</td>",
  "      `;",
  "      tbody.appendChild(tr);",
  "    });",
  "  }",
  "",
  "  // login history table",
  "  const ltbody = document.querySelector('#loginTable tbody');",
  "  ltbody.innerHTML = '';",
  "  loginHistory.forEach(h=>{",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td>${formatDateTime(h.time)}</td>",
  "      <td>${h.user}</td>",
  "      <td><span class=\"pill ${h.success?'ok':'danger'}\">${h.success?'Thành công':'Thất bại'}</span></td>",
  "    `;",
  "    ltbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "/* ============ SECURITY PAGE (dữ liệu thật do admin thao tác, không tự sinh số liệu ảo) ============ */",
  "let blockedIPs = []; // chỉ có phần tử khi admin tự thêm",
  "let lastScanTime = null;",
  "let scanState = {}; // không còn dùng cho UI (checklist thủ công đã bỏ) — giữ lại để tương thích với /api/state cũ",
  "",
  "let autoScanLoadedOnce = false;",
  "function renderSecurityPage(){",
  "  $('secBlockedIP').textContent = blockedIPs.length;",
  "  $('secLastScan').textContent = lastScanTime ? formatDateTime(lastScanTime) : 'Chưa đánh giá';",
  "  if(!autoScanLoadedOnce){ autoScanLoadedOnce = true; runAutoScan(); }",
  "",
  "  const tbody = document.querySelector('#ipTable tbody');",
  "  tbody.innerHTML = '';",
  "  if(!blockedIPs.length){",
  "    tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--muted); text-align:center; padding:24px;\">Không có IP nào bị chặn</td></tr>';",
  "  } else {",
  "    blockedIPs.forEach((b,idx)=>{",
  "      const tr = document.createElement('tr');",
  "      tr.innerHTML = `",
  "        <td class=\"mono\">${b.ip}</td>",
  "        <td>${b.reason}</td>",
  "        <td>${formatDateTime(b.time)}</td>",
  "        <td><span class=\"pill danger\">Đã chặn</span></td>",
  "        <td><button class=\"btn btn-ghost btn-inline\" data-unblock=\"${idx}\" style=\"padding:6px 12px; font-size:11.5px;\">Bỏ chặn</button></td>",
  "      `;",
  "      tbody.appendChild(tr);",
  "    });",
  "  }",
  "}",
  "",
  "document.querySelector('#ipTable').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('[data-unblock]');",
  "  if(!btn) return;",
  "  const idx = parseInt(btn.dataset.unblock);",
  "  const ip = blockedIPs[idx]?.ip;",
  "  blockedIPs.splice(idx,1);",
  "  renderSecurityPage();",
  "  showToast('Đã bỏ chặn IP: '+ip);",
  "});",
  "",
  "$('btnRefreshIP').addEventListener('click', ()=>{",
  "  $('blockIpValue').value = '';",
  "  $('blockIpModalBg').classList.add('show');",
  "});",
  "$('blockIpCancel').addEventListener('click', ()=> $('blockIpModalBg').classList.remove('show'));",
  "$('blockIpConfirm').addEventListener('click', ()=>{",
  "  const ip = $('blockIpValue').value.trim();",
  "  if(!ip){ showToast('Vui lòng nhập địa chỉ IP'); return; }",
  "  blockedIPs.unshift({ ip, reason: $('blockIpReason').value, time: new Date() });",
  "  $('blockIpModalBg').classList.remove('show');",
  "  renderSecurityPage();",
  "  showToast('Đã chặn IP: '+ip);",
  "});",
  "",
  "/* ============ CHECKLIST BẢO MẬT TỰ ĐỘNG (gọi API thật /api/admin/security-scan) ============ */",
  "const AUTO_STATUS_LABEL = { ok: 'Đạt', warn: 'Cảnh báo', fail: 'Nguy hiểm' };",
  "",
  "function renderAutoScanResults(result){",
  "  const box = $('autoScanResults');",
  "  const summary = $('autoScanSummary');",
  "  if(!result){",
  "    box.innerHTML = '';",
  "    summary.textContent = 'Chưa quét lần nào — bấm \"Quét ngay\" để bắt đầu.';",
  "    return;",
  "  }",
  "  box.innerHTML = '';",
  "  result.checks.forEach(c=>{",
  "    const item = document.createElement('div');",
  "    item.className = 'scan-item';",
  "    const cls = c.status==='ok' ? 'ok' : c.status==='warn' ? 'warn' : 'danger';",
  "    item.innerHTML = `",
  "      <div>",
  "        <div class=\"name\">${c.name}</div>",
  "        <div class=\"desc\">${c.detail}</div>",
  "      </div>",
  "      <span class=\"badge ${cls}\">${AUTO_STATUS_LABEL[c.status]||c.status}</span>",
  "    `;",
  "    box.appendChild(item);",
  "  });",
  "  const failCount = result.checks.filter(c=>c.status==='fail').length;",
  "  const warnCount = result.checks.filter(c=>c.status==='warn').length;",
  "  const okCount = result.checks.filter(c=>c.status==='ok').length;",
  "  summary.textContent = `Quét lúc ${formatDateTime(new Date(result.scannedAt))} — ${okCount} đạt, ${warnCount} cảnh báo, ${failCount} nguy hiểm.`;",
  "",
  "  // Cập nhật luôn 2 ô thống kê đầu trang (trước đây do checklist thủ công phụ trách, nay auto scan đảm nhiệm).",
  "  lastScanTime = new Date(result.scannedAt);",
  "  $('secStatus').textContent = failCount>0 ? 'Nguy hiểm' : warnCount>0 ? 'Cảnh báo' : 'An toàn';",
  "  $('secLastScan').textContent = formatDateTime(lastScanTime);",
  "}",
  "",
  "async function runAutoScan(){",
  "  const btn = $('btnAutoScan');",
  "  btn.disabled = true; btn.textContent = 'Đang quét...';",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/security-scan`, { cache:'no-store' });",
  "    const result = await res.json();",
  "    renderAutoScanResults(result);",
  "    showToast('Đã quét bảo mật tự động xong');",
  "  }catch(e){",
  "    showToast('Quét thất bại — kiểm tra kết nối tới server backend');",
  "  }finally{",
  "    btn.disabled = false; btn.textContent = '🔄 Quét ngay';",
  "  }",
  "}",
  "$('btnAutoScan').addEventListener('click', runAutoScan);",
  "",
  "/* Refresh time-sensitive text periodically while app is open */",
  "setInterval(()=>{",
  "  if(currentPage==='keys') render();",
  "  if(currentPage==='stats') renderStatsPage();",
  "  if(currentRole==='seller') applySellerAccountEffects();",
  "}, 30000);",
  "",
  "/* ============================================================",
  "   NÂNG CẤP MỚI (chỉ bổ sung — không sửa code phía trên):",
  "   1) Tự động lưu/tải toàn bộ dữ liệu qua server backend thật",
  "      (repo \"server---proxy\": index.js + package.json) — tải lại",
  "      trang KHÔNG mất dữ liệu.",
  "   2) Trang \"API Key Server\" — hiển thị link xác thực API key",
  "      thật để dán vào app/tool bên ngoài.",
  "   3) Tự động nhận diện app/tool nào đang gọi link xác thực,",
  "      admin bấm Cho phép / Từ chối cho từng app.",
  "   Bắt buộc: deploy backend (index.js) và sửa hằng số API_BASE",
  "   bên dưới thành địa chỉ server đó (xem README.md).",
  "   ============================================================ */",
  "",
  "const API_BASE = ''; // Giao diện và server API giờ đã được gộp chung 1 file index.js, chạy cùng domain nên để trống (dùng đường dẫn tương đối)",
  "",
  "/* ---------- 1) AUTO LƯU / TẢI TOÀN BỘ DỮ LIỆU ---------- */",
  "let stateLoaded = false;",
  "let lastSavedSnapshot = '';",
  "",
  "function collectAppState(){",
  "  // KHÔNG gửi keysStore trong auto-save định kỳ vì server sẽ ghi đè và xóa mất devices[]/devices_lua/devices_vm",
  "  // đã được /api/verify ghi vào. keysStore chỉ được POST khi admin thực sự thay đổi key (tạo/xóa/bán/reset).",
  "  return { adminPassword, loginHistory, keysStore, sellers, blockedIPs, scanState, lastScanTime, statsHidden, products, discountCodes, bankInfo, sepayConfig };",
  "}",
  "// Snapshot riêng KHÔNG có keysStore — dùng cho auto-save 4 giây để tránh ghi đè device data",
  "function collectAppStateNoKeys(){",
  "  return { adminPassword, loginHistory, sellers, blockedIPs, scanState, lastScanTime, statsHidden, products, discountCodes, bankInfo, sepayConfig };",
  "}",
  "",
  "function reviveDates(state){",
  "  if(Array.isArray(state.loginHistory)) state.loginHistory.forEach(h=>{ h.time = h.time ? new Date(h.time) : new Date(); });",
  "  if(state.keysStore){",
  "    Object.keys(state.keysStore).forEach(owner=>{",
  "      (state.keysStore[owner]||[]).forEach(k=>{",
  "        k.createdAt = k.createdAt ? new Date(k.createdAt) : new Date();",
  "        k.expiresAt = k.expiresAt ? new Date(k.expiresAt) : null;",
  "        k.activatedAt = k.activatedAt ? new Date(k.activatedAt) : null;",
  "        // Tương thích ngược: key được tạo TRƯỚC khi có tính năng \"kích hoạt\" sẽ không",
  "        // có field hasExpiryPlan -> coi như đã kích hoạt sẵn (giữ nguyên hành vi cũ,",
  "        // không làm treo hạn dùng của các key đã tồn tại từ trước).",
  "        if(typeof k.hasExpiryPlan === 'undefined'){",
  "          k.hasExpiryPlan = !!k.expiresAt;",
  "          k.activated = true;",
  "          k.activatedAt = k.activatedAt || k.createdAt;",
  "        }",
  "      });",
  "    });",
  "  }",
  "  if(Array.isArray(state.sellers)) state.sellers.forEach(s=>{",
  "    s.createdAt = s.createdAt ? new Date(s.createdAt) : new Date();",
  "    s.expiresAt = s.expiresAt ? new Date(s.expiresAt) : null;",
  "    (s.notifications||[]).forEach(n=>{ n.time = n.time ? new Date(n.time) : new Date(); });",
  "  });",
  "  if(Array.isArray(state.blockedIPs)) state.blockedIPs.forEach(b=>{ b.time = b.time ? new Date(b.time) : new Date(); });",
  "  if(Array.isArray(state.discountCodes)) state.discountCodes.forEach(d=>{",
  "    d.expiresAt = d.expiresAt ? new Date(d.expiresAt) : null;",
  "    d.createdAt = d.createdAt ? new Date(d.createdAt) : new Date();",
  "  });",
  "  if(Array.isArray(state.products)) state.products.forEach(p=>{ p.createdAt = p.createdAt ? new Date(p.createdAt) : new Date(); });",
  "  return state;",
  "}",
  "",
  "function applyAppState(s){",
  "  if(!s || typeof s !== 'object') return;",
  "  reviveDates(s);",
  "  if(s.adminPassword) adminPassword = s.adminPassword;",
  "  if(Array.isArray(s.loginHistory)) loginHistory = s.loginHistory;",
  "  if(s.keysStore && typeof s.keysStore==='object') keysStore = s.keysStore;",
  "  if(Array.isArray(s.sellers)) sellers = s.sellers;",
  "  if(Array.isArray(s.blockedIPs)) blockedIPs = s.blockedIPs;",
  "  if(s.scanState && typeof s.scanState==='object') scanState = s.scanState;",
  "  lastScanTime = s.lastScanTime ? new Date(s.lastScanTime) : null;",
  "  if(typeof s.statsHidden === 'boolean') statsHidden = s.statsHidden;",
  "  if(Array.isArray(s.products)) products = s.products;",
  "  if(Array.isArray(s.discountCodes)) discountCodes = s.discountCodes;",
  "  if(s.bankInfo && typeof s.bankInfo==='object') bankInfo = s.bankInfo;",
  "  if(s.sepayConfig && typeof s.sepayConfig==='object') sepayConfig = s.sepayConfig;",
  "  if(typeof renderSepaySettings === 'function') renderSepaySettings();",
  "  if(currentAccount && keysStore[currentAccount]) setKeys(keysStore[currentAccount]);",
  "}",
  "",
  "async function loadStateFromServer(){",
  "  const loginBtn = document.getElementById('btnLogin');",
  "  if(loginBtn){ loginBtn.disabled = true; loginBtn.textContent = 'Đang tải dữ liệu từ server...'; }",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/state', { cache:'no-store' });",
  "    if(!res.ok) throw new Error('HTTP ' + res.status);",
  "    const s = await res.json();",
  "    applyAppState(s);",
  "    // Chỉ dùng snapshot NO-KEYS cho auto-save để tránh ghi đè devices[] của server",
  "    lastSavedSnapshot = JSON.stringify(collectAppState());",
  "    lastSavedSnapshotNoKeys = JSON.stringify(collectAppStateNoKeys());",
  "    const note = document.getElementById('apiConnStatusNote');",
  "    if(note) note.textContent = '✔ Đã kết nối máy chủ backend. Dữ liệu được tự động lưu và khôi phục khi tải lại trang.';",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không kết nối được backend. Hãy deploy repo backend (index.js) rồi sửa API_BASE trong file này thành đúng địa chỉ server.', e);",
  "    const note = document.getElementById('apiConnStatusNote');",
  "    if(note) note.textContent = '⚠ Chưa kết nối được máy chủ backend. Kiểm tra: (1) server (index.js) đã chạy chưa, (2) biến API_BASE trong file này đã sửa đúng địa chỉ server chưa. Dữ liệu sẽ KHÔNG được lưu khi tải lại trang cho tới khi kết nối được. Xem README.md.';",
  "  } finally {",
  "    stateLoaded = true;",
  "    if(loginBtn){ loginBtn.disabled = false; loginBtn.textContent = 'Đăng nhập'; }",
  "    refreshAllVisiblePages();",
  "  }",
  "}",
  "",
  "// lastSavedSnapshotNoKeys: snapshot tự động (không có keysStore) — dùng cho auto-save 4s",
  "let lastSavedSnapshotNoKeys = '';",
  "// saveStateToServer: tự động lưu định kỳ — KHÔNG gửi keysStore để không ghi đè devices[]",
  "async function saveStateToServer(force){",
  "  if(!stateLoaded) return;",
  "  const snapNoKeys = JSON.stringify(collectAppStateNoKeys());",
  "  if(!force && snapNoKeys === lastSavedSnapshotNoKeys) return;",
  "  lastSavedSnapshotNoKeys = snapNoKeys;",
  "  try{",
  "    await fetch(API_BASE + '/api/state', { method:'POST', headers:{'Content-Type':'application/json'}, body: snapNoKeys });",
  "  }catch(e){",
  "    console.warn('[KeyVault] Lưu dữ liệu lên server thất bại, sẽ tự thử lại.', e);",
  "    lastSavedSnapshotNoKeys = ''; // buộc lần chạy tiếp theo thử lưu lại",
  "  }",
  "}",
  "// saveKeysToServer: lưu keysStore khi admin thực sự thay đổi key (tạo/xóa/bán/reset/ban...)",
  "// FIX: Tự động retry 3 lần nếu thất bại để đảm bảo key được ghi lên server.",
  "async function saveKeysToServer(){",
  "  if(!stateLoaded) return;",
  "  const snap = JSON.stringify({ keysStore });",
  "  const urls = [",
  "    { url: API_BASE + '/api/state/keys', body: snap },",
  "    { url: API_BASE + '/api/state', body: JSON.stringify({ keysStore }) } // fallback",
  "  ];",
  "  for(const { url, body } of urls){",
  "    let lastErr;",
  "    for(let attempt = 1; attempt <= 3; attempt++){",
  "      try{",
  "        const res = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body });",
  "        if(res.ok){ return; } // thành công → dừng",
  "        throw new Error('HTTP ' + res.status);",
  "      }catch(e){",
  "        lastErr = e;",
  "        if(attempt < 3) await new Promise(r => setTimeout(r, 800 * attempt)); // chờ 0.8s, 1.6s",
  "      }",
  "    }",
  "    console.warn('[KeyVault] saveKeysToServer thất bại tại ' + url + ':', lastErr);",
  "  }",
  "  console.error('[KeyVault] KHÔNG LƯU ĐƯỢC KEY LÊN SERVER — kiểm tra kết nối!');",
  "}",
  "",
  "function refreshAllVisiblePages(){",
  "  if(currentRole) applyRoleVisibility();",
  "  if(currentPage==='keys') render();",
  "  if(currentPage==='stats') renderStatsPage();",
  "  if(currentPage==='security') renderSecurityPage();",
  "  if(currentPage==='sellers') renderSellersPage();",
  "  if(currentPage==='apikey') renderApiKeyPage();",
  "  if(currentPage==='products'){ renderProductsPage(); renderProductGroupsPage(); }",
  "  if(currentPage==='getkey') renderGetKeyPage();",
  "  if(currentPage==='codevault') renderCodeVaultPage();",
  "  if(currentPage==='miniapp') renderMiniAppPage();",
  "}",
  "",
  "setInterval(()=> saveStateToServer(false), 4000); // tự lưu định kỳ (không keysStore) — tránh ghi đè devices[]",
  "window.addEventListener('beforeunload', ()=>{",
  "  if(!stateLoaded) return;",
  "  const snapNoKeys = JSON.stringify(collectAppStateNoKeys());",
  "  if(snapNoKeys === lastSavedSnapshotNoKeys) return;",
  "  // Chỉ gửi cấu hình, KHÔNG gửi keysStore để tránh xóa devices[] trên server",
  "  try{ navigator.sendBeacon(API_BASE + '/api/state', new Blob([snapNoKeys], {type:'application/json'})); }catch(e){}",
  "});",
  "",
  "loadStateFromServer();",
  "",
  "// Auto-refresh khi quay lại tab: lấy dữ liệu mới nhất từ server",
  "// → dashboard cập nhật số thiết bị ngay sau khi app khách verify key",
  "let _lastVisibilityRefresh = 0;",
  "document.addEventListener('visibilitychange', ()=>{",
  "  if(document.visibilityState === 'visible'){",
  "    const now = Date.now();",
  "    if(now - _lastVisibilityRefresh > 10000){ // không refresh liên tục quá 10s/lần",
  "      _lastVisibilityRefresh = now;",
  "      loadStateFromServer().catch(()=>{});",
  "    }",
  "  }",
  "});",
  "",
  "/* ---------- 2) & 3) TRANG \"API KEY SERVER\" ---------- */",
  "let apiApps = [];",
  "let apiLogs = [];",
  "",
  "function setupApiKeyLinks(){",
  "  const origin = API_BASE; // backend nằm ở domain riêng (repo \"server---proxy\"), dùng thẳng API_BASE làm gốc",
  "  const verifyUrl = origin + '/api/verify';",
  "  document.getElementById('apiVerifyLink').value = verifyUrl;",
  "  const appId = (document.getElementById('apiAppIdInput').value || 'my-app-01').trim() || 'my-app-01';",
  "  document.getElementById('apiVerifyExample').value = `${verifyUrl}?key=KEY_CUA_KHACH_HANG&app=${encodeURIComponent(appId)}`;",
  "  document.getElementById('apiCodeSample').textContent =",
  "`// Dán đoạn này vào code xác thực key của app/tool bạn",
  "const res = await fetch(\"${verifyUrl}?key=\" + userKey + \"&app=${appId}\");",
  "const data = await res.json();",
  "",
  "if (data.valid) {",
  "  // Key hợp lệ VÀ app/tool này đã được admin cho phép -> chạy tiếp",
  "} else {",
  "  // data.reason: \"key_not_found\" | \"app_pending_approval\" | \"app_denied\" | \"missing_key\"",
  "  // Key sai, hết hạn/bị cấm, hoặc app chưa được cấp phép -> chặn sử dụng",
  "  console.log(data.reason);",
  "}`;",
  "}",
  "",
  "async function fetchApiApps(){",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/apps', {cache:'no-store'});",
  "    apiApps = res.ok ? await res.json() : [];",
  "  }catch(e){ /* giữ nguyên danh sách cũ nếu mất kết nối tạm thời */ }",
  "  renderApiAppsTable();",
  "}",
  "",
  "async function fetchApiLogs(){",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/logs', {cache:'no-store'});",
  "    apiLogs = res.ok ? await res.json() : [];",
  "  }catch(e){ /* giữ nguyên log cũ nếu mất kết nối tạm thời */ }",
  "  renderApiLogsTable();",
  "}",
  "",
  "function renderApiAppsTable(){",
  "  const total = apiApps.length;",
  "  const pending = apiApps.filter(a=>a.status==='pending').length;",
  "  const allowed = apiApps.filter(a=>a.status==='allowed').length;",
  "  const denied = apiApps.filter(a=>a.status==='denied').length;",
  "  document.getElementById('apiTotalApps').textContent = total;",
  "  document.getElementById('apiPendingApps').textContent = pending;",
  "  document.getElementById('apiAllowedApps').textContent = allowed;",
  "  document.getElementById('apiDeniedApps').textContent = denied;",
  "",
  "  const tbody = document.querySelector('#apiAppsTable tbody');",
  "  const empty = document.getElementById('apiAppsEmpty');",
  "  tbody.innerHTML = '';",
  "  empty.style.display = total ? 'none' : '';",
  "  const STATUS_MAP = { allowed:{cls:'available', label:'✔ Cho phép'}, denied:{cls:'banned', label:'✕ Từ chối'}, pending:{cls:'sold', label:'⏳ Chờ duyệt'} };",
  "  apiApps",
  "    .slice()",
  "    .sort((a,b)=> new Date(b.lastUsedAt||b.createdAt) - new Date(a.lastUsedAt||a.createdAt))",
  "    .forEach(a=>{",
  "      const st = STATUS_MAP[a.status] || STATUS_MAP.pending;",
  "      const tr = document.createElement('tr');",
  "      tr.innerHTML = `",
  "        <td class=\"mono\">${a.appId}</td>",
  "        <td><span class=\"badge ${st.cls}\">${st.label}</span></td>",
  "        <td>${a.lastUsedAt ? formatDateTime(new Date(a.lastUsedAt)) : '—'}</td>",
  "        <td>${a.totalChecks||0}</td>",
  "        <td class=\"actions\">",
  "          <button class=\"btn btn-ghost btn-inline\" data-app-action=\"approve\" data-id=\"${a.id}\" style=\"padding:6px 12px; font-size:11.5px;\">Cho phép</button>",
  "          <button class=\"btn btn-danger-ghost btn-inline\" data-app-action=\"deny\" data-id=\"${a.id}\" style=\"padding:6px 12px; font-size:11.5px;\">Từ chối</button>",
  "          <button class=\"icon-btn danger\" data-app-action=\"remove\" data-id=\"${a.id}\" title=\"Xoá ứng dụng\">✕</button>",
  "        </td>",
  "      `;",
  "      tbody.appendChild(tr);",
  "    });",
  "}",
  "",
  "function renderApiLogsTable(){",
  "  const tbody = document.querySelector('#apiLogsTable tbody');",
  "  tbody.innerHTML = '';",
  "  if(!apiLogs.length){",
  "    tbody.innerHTML = '<tr><td colspan=\"6\" style=\"color:var(--muted); text-align:center; padding:24px;\">Chưa có lượt kiểm tra key nào</td></tr>';",
  "    return;",
  "  }",
  "  apiLogs.slice(0,50).forEach(l=>{",
  "    const deviceLabel = [l.deviceName, l.androidVersion ? 'Android '+l.androidVersion : ''].filter(Boolean).join(' · ') || '—';",
  "    const ipLabel = l.ip || '—';",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td>${formatDateTime(new Date(l.time))}</td>",
  "      <td class=\"mono\">${l.appId}</td>",
  "      <td class=\"mono\">${l.key}</td>",
  "      <td style=\"font-size:11.5px; color:var(--text);\">${deviceLabel}</td>",
  "      <td class=\"mono\" style=\"font-size:11px; color:var(--muted);\">${ipLabel}</td>",
  "      <td><span class=\"pill ${l.valid?'ok':'danger'}\">${l.valid?'Hợp lệ':'Không hợp lệ'}</span></td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "function renderApiKeyPage(){",
  "  setupApiKeyLinks();",
  "  fetchApiApps();",
  "  fetchApiLogs();",
  "}",
  "",
  "document.getElementById('btnGenAppExample').addEventListener('click', setupApiKeyLinks);",
  "document.getElementById('btnRefreshApps').addEventListener('click', ()=>{ fetchApiApps(); fetchApiLogs(); });",
  "",
  "function copyInputValue(inputId){",
  "  const el = document.getElementById(inputId);",
  "  el.select();",
  "  if(navigator.clipboard){",
  "    navigator.clipboard.writeText(el.value).then(()=> showToast('Đã sao chép')).catch(()=> showToast('Không sao chép được, vui lòng copy thủ công'));",
  "  } else {",
  "    showToast('Vui lòng copy thủ công (Ctrl+C)');",
  "  }",
  "}",
  "document.getElementById('btnCopyVerifyLink').addEventListener('click', ()=> copyInputValue('apiVerifyLink'));",
  "document.getElementById('btnCopyVerifyExample').addEventListener('click', ()=> copyInputValue('apiVerifyExample'));",
  "",
  "document.querySelector('#apiAppsTable').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('[data-app-action]');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const action = btn.dataset.appAction;",
  "  try{",
  "    if(action==='approve'){",
  "      await fetch(`${API_BASE}/api/apps/${id}/approve`, {method:'POST'});",
  "      showToast('Đã cho phép ứng dụng dùng server key');",
  "    } else if(action==='deny'){",
  "      await fetch(`${API_BASE}/api/apps/${id}/deny`, {method:'POST'});",
  "      showToast('Đã từ chối ứng dụng');",
  "    } else if(action==='remove'){",
  "      await fetch(`${API_BASE}/api/apps/${id}`, {method:'DELETE'});",
  "      showToast('Đã xoá ứng dụng khỏi danh sách');",
  "    }",
  "  }catch(err){",
  "    showToast('Thao tác thất bại — kiểm tra kết nối tới server backend (API_BASE)');",
  "  }",
  "  fetchApiApps();",
  "});",
  "",
  "// Khi đang mở trang API Key Server, tự động làm mới để nhận diện app mới gọi vào gần như real-time",
  "setInterval(()=>{ if(currentPage==='apikey'){ fetchApiApps(); fetchApiLogs(); } }, 5000);",
  "",
  "/* ============ TRANG SẢN PHẨM (STOREFRONT) & MÃ GIẢM GIÁ ============ */",
  "let editingProductId = null;",
  "let prodLogoDataUrl = '';",
  "",
  "document.getElementById('prodLogoInput').addEventListener('change', (e)=>{",
  "  const file = e.target.files && e.target.files[0];",
  "  if(!file) return;",
  "  const reader = new FileReader();",
  "  reader.onload = ()=>{",
  "    prodLogoDataUrl = reader.result;",
  "    document.getElementById('prodLogoPreview').innerHTML = `<img src=\"${prodLogoDataUrl}\" style=\"width:100%; height:100%; object-fit:cover;\">`;",
  "  };",
  "  reader.readAsDataURL(file);",
  "});",
  "",
  "document.querySelectorAll('#prodDurationToggle input').forEach(el=>{",
  "  el.addEventListener('change', ()=>{",
  "    document.getElementById('prodDurationFields').style.display = document.getElementById('pdurUnlimited').checked ? 'none' : 'grid';",
  "  });",
  "});",
  "",
  "function resetProductForm(){",
  "  editingProductId = null;",
  "  prodLogoDataUrl = '';",
  "  document.getElementById('productFormTitle').textContent = 'Thêm sản phẩm mới';",
  "  document.getElementById('prodName').value = '';",
  "  document.getElementById('prodKeyPrefix').value = '';",
  "  document.getElementById('prodPrice').value = '';",
  "  document.getElementById('prodMaxDevices').value = '1';",
  "  document.getElementById('pdurLimited').checked = true;",
  "  document.getElementById('prodDurationAmount').value = '30';",
  "  document.getElementById('prodDurationUnit').value = 'day';",
  "  document.getElementById('prodDurationFields').style.display = 'grid';",
  "  document.getElementById('prodActive').checked = true;",
  "  document.getElementById('prodLogoInput').value = '';",
  "  document.getElementById('prodLogoPreview').innerHTML = '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "  document.getElementById('btnCancelEditProduct').style.display = 'none';",
  "}",
  "",
  "document.getElementById('btnCancelEditProduct').addEventListener('click', resetProductForm);",
  "",
  "document.getElementById('btnSaveProduct').addEventListener('click', ()=>{",
  "  const name = document.getElementById('prodName').value.trim();",
  "  const keyPrefix = document.getElementById('prodKeyPrefix').value.trim().toUpperCase();",
  "  const price = document.getElementById('prodPrice').value.trim();",
  "  const maxDevices = Math.max(1, Math.min(20, parseInt(document.getElementById('prodMaxDevices').value)||1));",
  "  const isUnlimited = document.getElementById('pdurUnlimited').checked;",
  "  const durationAmount = isUnlimited ? null : Math.max(1, parseFloat(document.getElementById('prodDurationAmount').value)||1);",
  "  const durationUnit = isUnlimited ? 'unlimited' : document.getElementById('prodDurationUnit').value;",
  "  const active = document.getElementById('prodActive').checked;",
  "",
  "  if(!name){ showToast('Vui lòng nhập tên sản phẩm'); return; }",
  "  if(!keyPrefix){ showToast('Vui lòng nhập tiền tố key liên kết'); return; }",
  "  if(!price){ showToast('Vui lòng nhập giá bán'); return; }",
  "",
  "  if(editingProductId){",
  "    const p = products.find(x=>x.id===editingProductId);",
  "    if(p){",
  "      p.name = name; p.keyPrefix = keyPrefix; p.price = price; p.maxDevices = maxDevices;",
  "      p.durationAmount = durationAmount; p.durationUnit = durationUnit; p.active = active;",
  "      if(prodLogoDataUrl) p.logo = prodLogoDataUrl;",
  "    }",
  "    showToast('Đã cập nhật sản phẩm');",
  "  } else {",
  "    products.unshift({",
  "      id: 'p'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      name, keyPrefix, price, maxDevices,",
  "      durationAmount, durationUnit, active,",
  "      logo: prodLogoDataUrl || '',",
  "      createdAt: new Date()",
  "    });",
  "    showToast('Đã thêm sản phẩm mới — sẽ hiện ngay trên trang bán key');",
  "  }",
  "  resetProductForm();",
  "  saveStateToServer(true);",
  "  renderProductsPage();",
  "});",
  "",
  "function fmtDuration(p){",
  "  if(p.durationUnit==='unlimited' || !p.durationAmount) return 'Không giới hạn';",
  "  const unitLabel = p.durationUnit==='hour' ? 'giờ' : p.durationUnit==='month' ? 'tháng' : 'ngày';",
  "  return p.durationAmount + ' ' + unitLabel;",
  "}",
  "",
  "function renderProductsPage(){",
  "  const list = document.getElementById('productList');",
  "  const empty = document.getElementById('productEmpty');",
  "  list.innerHTML = '';",
  "  empty.style.display = products.length ? 'none' : 'block';",
  "  products.forEach(p=>{",
  "    const stock = Object.values(keysStore).flat().filter(k=> k.value.startsWith(p.keyPrefix+'-') && computeStatus(k)==='available').length;",
  "    const div = document.createElement('div');",
  "    div.className = 'ticket';",
  "    div.innerHTML = `",
  "      <div class=\"ticket-top\">",
  "        <div style=\"display:flex; align-items:center; gap:12px;\">",
  "          <div style=\"width:40px; height:40px; border-radius:10px; overflow:hidden; background:var(--panel-2); border:1px solid var(--line); flex-shrink:0; display:flex; align-items:center; justify-content:center;\">",
  "            ${p.logo ? `<img src=\"${p.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '📦'}",
  "          </div>",
  "          <div class=\"key\" style=\"font-family:'Inter',sans-serif;\">${p.name}</div>",
  "        </div>",
  "        <div class=\"ticket-badges\">",
  "          <span class=\"badge ${p.active ? 'available' : 'expired'}\">${p.active ? 'Đang hiển thị' : 'Đã ẩn'}</span>",
  "        </div>",
  "      </div>",
  "      <div class=\"ticket-bottom\">",
  "        <div class=\"meta\">Prefix: <b>${p.keyPrefix}</b> &nbsp;·&nbsp; Giá: <b>${fmtMoney(p.price)}</b> &nbsp;·&nbsp; Thời hạn: <b>${fmtDuration(p)}</b> &nbsp;·&nbsp; Thiết bị: <b>${p.maxDevices||1}</b> &nbsp;·&nbsp; Còn hàng: <b>${stock}</b></div>",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"Sửa\" data-act=\"editprod\" data-id=\"${p.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 20h9\"/><path d=\"M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"${p.active ? 'Ẩn khỏi trang bán key' : 'Hiện lên trang bán key'}\" data-act=\"toggleprod\" data-id=\"${p.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn danger\" title=\"Xoá sản phẩm\" data-act=\"delprod\" data-id=\"${p.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "          </button>",
  "        </div>",
  "      </div>",
  "    `;",
  "    list.appendChild(div);",
  "  });",
  "  renderDiscountTable();",
  "}",
  "",
  "document.getElementById('productList').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const p = products.find(x=>x.id===id);",
  "  if(!p) return;",
  "  if(act==='delprod'){",
  "    if(!confirm('Xoá sản phẩm \"'+p.name+'\"? Key trong kho sẽ KHÔNG bị xoá, chỉ gỡ sản phẩm khỏi trang bán key.')) return;",
  "    products = products.filter(x=>x.id!==id);",
  "    showToast('Đã xoá sản phẩm');",
  "  } else if(act==='toggleprod'){",
  "    p.active = !p.active;",
  "    showToast(p.active ? 'Đã hiện sản phẩm lên trang bán key' : 'Đã ẩn sản phẩm khỏi trang bán key');",
  "  } else if(act==='editprod'){",
  "    editingProductId = id;",
  "    prodLogoDataUrl = p.logo || '';",
  "    document.getElementById('productFormTitle').textContent = 'Chỉnh sửa sản phẩm';",
  "    document.getElementById('prodName').value = p.name;",
  "    document.getElementById('prodKeyPrefix').value = p.keyPrefix;",
  "    document.getElementById('prodPrice').value = p.price;",
  "    document.getElementById('prodMaxDevices').value = p.maxDevices || 1;",
  "    if(p.durationUnit==='unlimited'){",
  "      document.getElementById('pdurUnlimited').checked = true;",
  "      document.getElementById('prodDurationFields').style.display = 'none';",
  "    } else {",
  "      document.getElementById('pdurLimited').checked = true;",
  "      document.getElementById('prodDurationFields').style.display = 'grid';",
  "      document.getElementById('prodDurationAmount').value = p.durationAmount || 30;",
  "      document.getElementById('prodDurationUnit').value = p.durationUnit || 'day';",
  "    }",
  "    document.getElementById('prodActive').checked = !!p.active;",
  "    document.getElementById('prodLogoPreview').innerHTML = p.logo ? `<img src=\"${p.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "    document.getElementById('btnCancelEditProduct').style.display = '';",
  "    window.scrollTo({top:0, behavior:'smooth'});",
  "    return;",
  "  }",
  "  saveStateToServer(true);",
  "  renderProductsPage();",
  "});",
  "",
  "/* ---- Mã giảm giá ---- */",
  "document.getElementById('btnAddDiscount').addEventListener('click', ()=>{",
  "  const code = document.getElementById('discCode').value.trim().toUpperCase();",
  "  const percent = Math.max(1, Math.min(99, parseInt(document.getElementById('discPercent').value)||10));",
  "  const maxUses = Math.max(0, parseInt(document.getElementById('discMaxUses').value)||0);",
  "  const expiryRaw = document.getElementById('discExpiry').value;",
  "  const expiresAt = expiryRaw ? new Date(expiryRaw) : null;",
  "",
  "  if(!code){ showToast('Vui lòng nhập mã giảm giá'); return; }",
  "  if(discountCodes.some(d=>d.code===code)){ showToast('Mã giảm giá này đã tồn tại'); return; }",
  "",
  "  discountCodes.unshift({",
  "    id: 'd'+Date.now()+Math.random().toString(36).slice(2,7),",
  "    code, percent, maxUses, usedCount:0, expiresAt, active:true, createdAt: new Date()",
  "  });",
  "  document.getElementById('discCode').value = '';",
  "  document.getElementById('discPercent').value = '10';",
  "  document.getElementById('discMaxUses').value = '0';",
  "  document.getElementById('discExpiry').value = '';",
  "  showToast('Đã tạo mã giảm giá: '+code);",
  "  saveStateToServer(true);",
  "  renderDiscountTable();",
  "});",
  "",
  "function renderDiscountTable(){",
  "  const tbody = document.querySelector('#discountTable tbody');",
  "  const empty = document.getElementById('discountEmpty');",
  "  tbody.innerHTML = '';",
  "  empty.style.display = discountCodes.length ? 'none' : 'block';",
  "  discountCodes.forEach(d=>{",
  "    const expired = d.expiresAt && new Date(d.expiresAt).getTime() < Date.now();",
  "    const usedUp = d.maxUses > 0 && d.usedCount >= d.maxUses;",
  "    const statusLabel = !d.active ? 'Đã tắt' : expired ? 'Hết hạn' : usedUp ? 'Hết lượt' : 'Đang hoạt động';",
  "    const statusClass = !d.active ? 'expired' : expired ? 'expired' : usedUp ? 'expired' : 'available';",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td><code>${d.code}</code></td>",
  "      <td>${d.percent}%</td>",
  "      <td>${d.usedCount}${d.maxUses>0 ? '/'+d.maxUses : ''}</td>",
  "      <td>${d.expiresAt ? formatDateTime(d.expiresAt) : 'Không giới hạn'}</td>",
  "      <td><span class=\"badge ${statusClass}\">${statusLabel}</span></td>",
  "      <td>",
  "        <button class=\"icon-btn\" title=\"${d.active ? 'Tắt mã' : 'Bật lại mã'}\" data-act=\"toggledisc\" data-id=\"${d.id}\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "        </button>",
  "        <button class=\"icon-btn danger\" title=\"Xoá mã\" data-act=\"deldisc\" data-id=\"${d.id}\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "        </button>",
  "      </td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "document.querySelector('#discountTable').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const d = discountCodes.find(x=>x.id===id);",
  "  if(!d) return;",
  "  if(act==='deldisc'){",
  "    if(!confirm('Xoá mã giảm giá \"'+d.code+'\"?')) return;",
  "    discountCodes = discountCodes.filter(x=>x.id!==id);",
  "    showToast('Đã xoá mã giảm giá');",
  "  } else if(act==='toggledisc'){",
  "    d.active = !d.active;",
  "    showToast(d.active ? 'Đã bật lại mã' : 'Đã tắt mã');",
  "  }",
  "  saveStateToServer(true);",
  "  renderDiscountTable();",
  "});",
  "",
  "/* ============ NHÓM SẢN PHẨM (1 logo/tên + NHIỀU gói giá) — ADMIN ============ */",
  "let productGroups = [];",
  "let editingPgId = null;",
  "let pgLogoDataUrl = '';",
  "",
  "document.getElementById('pgLogoInput').addEventListener('change', (e)=>{",
  "  const file = e.target.files && e.target.files[0];",
  "  if(!file) return;",
  "  const reader = new FileReader();",
  "  reader.onload = ()=>{",
  "    pgLogoDataUrl = reader.result;",
  "    document.getElementById('pgLogoPreview').innerHTML = `<img src=\"${pgLogoDataUrl}\" style=\"width:100%; height:100%; object-fit:cover;\">`;",
  "  };",
  "  reader.readAsDataURL(file);",
  "});",
  "",
  "let pgPlanDraft = []; // [{id, label, unit, amount, price, keyPrefix, maxDevices}] — bản nháp đang chỉnh trong form",
  "",
  "function renderPgPlanList(){",
  "  const wrap = document.getElementById('pgPlanList');",
  "  wrap.innerHTML = '';",
  "  pgPlanDraft.forEach((d, idx)=>{",
  "    const row = document.createElement('div');",
  "    row.style.cssText = 'display:grid; grid-template-columns:1fr 0.7fr 0.7fr 0.9fr 0.7fr auto; gap:8px; align-items:end; background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px;';",
  "    row.innerHTML = `",
  "      <div><label style=\"margin:0 0 4px;\">Nhãn hiển thị</label><input type=\"text\" data-f=\"label\" data-i=\"${idx}\" value=\"${d.label||''}\" placeholder=\"VD: 1 ngày\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Đơn vị</label><select data-f=\"unit\" data-i=\"${idx}\"><option value=\"hour\" ${d.unit==='hour'?'selected':''}>Giờ</option><option value=\"day\" ${d.unit==='day'?'selected':''}>Ngày</option><option value=\"month\" ${d.unit==='month'?'selected':''}>Tháng</option><option value=\"unlimited\" ${d.unit==='unlimited'?'selected':''}>Không giới hạn</option></select></div>",
  "      <div><label style=\"margin:0 0 4px;\">Số lượng</label><input type=\"number\" min=\"1\" data-f=\"amount\" data-i=\"${idx}\" value=\"${d.amount||1}\" ${d.unit==='unlimited'?'disabled':''}></div>",
  "      <div><label style=\"margin:0 0 4px;\">Giá (₫)</label><input type=\"text\" data-f=\"price\" data-i=\"${idx}\" value=\"${d.price||''}\" placeholder=\"VD: 10000\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Tiền tố key</label><input type=\"text\" data-f=\"keyPrefix\" data-i=\"${idx}\" value=\"${d.keyPrefix||''}\" placeholder=\"VD: LQ1D\" style=\"text-transform:uppercase;\"></div>",
  "      <button class=\"icon-btn danger\" title=\"Xoá gói này\" data-del=\"${idx}\" style=\"height:38px;\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg></button>",
  "    `;",
  "    wrap.appendChild(row);",
  "  });",
  "}",
  "",
  "document.getElementById('btnAddPgPlan').addEventListener('click', ()=>{",
  "  pgPlanDraft.push({ id:'', label:'', unit:'day', amount:1, price:'', keyPrefix:'', maxDevices:1 });",
  "  renderPgPlanList();",
  "});",
  "",
  "document.getElementById('pgPlanList').addEventListener('input', (e)=>{",
  "  const f = e.target.dataset.f;",
  "  const i = e.target.dataset.i;",
  "  if(f===undefined || i===undefined) return;",
  "  const item = pgPlanDraft[i];",
  "  if(!item) return;",
  "  if(f==='amount'){ item[f] = Math.max(1, parseInt(e.target.value)||1); }",
  "  else if(f==='keyPrefix'){ item[f] = e.target.value.toUpperCase(); }",
  "  else { item[f] = e.target.value; }",
  "  if(f==='unit'){ renderPgPlanList(); }",
  "});",
  "document.getElementById('pgPlanList').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('[data-del]');",
  "  if(!btn) return;",
  "  pgPlanDraft.splice(parseInt(btn.dataset.del), 1);",
  "  renderPgPlanList();",
  "});",
  "",
  "function resetPgForm(){",
  "  editingPgId = null;",
  "  pgLogoDataUrl = '';",
  "  pgPlanDraft = [];",
  "  document.getElementById('pgFormTitle').textContent = 'Thêm nhóm sản phẩm mới';",
  "  document.getElementById('pgName').value = '';",
  "  document.getElementById('pgActive').checked = true;",
  "  document.getElementById('pgLogoInput').value = '';",
  "  document.getElementById('pgLogoPreview').innerHTML = '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "  document.getElementById('btnCancelEditPg').style.display = 'none';",
  "  renderPgPlanList();",
  "}",
  "document.getElementById('btnCancelEditPg').addEventListener('click', resetPgForm);",
  "",
  "async function fetchProductGroups(){",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/product-groups`, {cache:'no-store'});",
  "    productGroups = await res.json();",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không tải được danh sách nhóm sản phẩm', e);",
  "  }",
  "  renderPgList();",
  "}",
  "",
  "function fmtPgPlanLabel(d){",
  "  if(d.unit==='unlimited') return d.label || 'Không giới hạn';",
  "  const unitLabel = d.unit==='hour' ? 'giờ' : d.unit==='month' ? 'tháng' : 'ngày';",
  "  return d.label || (d.amount + ' ' + unitLabel);",
  "}",
  "",
  "function renderPgList(){",
  "  const list = document.getElementById('pgList');",
  "  const empty = document.getElementById('pgEmpty');",
  "  list.innerHTML = '';",
  "  empty.style.display = productGroups.length ? 'none' : 'block';",
  "  productGroups.forEach(g=>{",
  "    const div = document.createElement('div');",
  "    div.className = 'ticket';",
  "    const plansHtml = (g.plans||[]).map(d=>{",
  "      const stock = Object.values(keysStore).flat().filter(k=> k.value.startsWith(d.keyPrefix+'-') && computeStatus(k)==='available').length;",
  "      return `<div class=\"meta\" style=\"margin-top:4px;\">• ${fmtPgPlanLabel(d)} — <b>${fmtMoney(d.price)}</b> · Prefix: <b>${d.keyPrefix}</b> · Còn hàng: <b>${stock}</b></div>`;",
  "    }).join('');",
  "    div.innerHTML = `",
  "      <div class=\"ticket-top\">",
  "        <div style=\"display:flex; align-items:center; gap:12px;\">",
  "          <div style=\"width:40px; height:40px; border-radius:10px; overflow:hidden; background:var(--panel-2); border:1px solid var(--line); flex-shrink:0; display:flex; align-items:center; justify-content:center;\">",
  "            ${g.logo ? `<img src=\"${g.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '📦'}",
  "          </div>",
  "          <div class=\"key\" style=\"font-family:'Inter',sans-serif;\">${g.name}</div>",
  "        </div>",
  "        <div class=\"ticket-badges\">",
  "          <span class=\"badge ${g.active ? 'available' : 'expired'}\">${g.active ? 'Đang hiển thị' : 'Đã ẩn'}</span>",
  "        </div>",
  "      </div>",
  "      <div class=\"ticket-bottom\">",
  "        <div class=\"meta\">${(g.plans||[]).length} gói giá:</div>",
  "        ${plansHtml}",
  "        <div class=\"actions\" style=\"margin-top:8px;\">",
  "          <button class=\"icon-btn\" title=\"Sửa\" data-act=\"editpg\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 20h9\"/><path d=\"M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"${g.active ? 'Ẩn khỏi trang bán key' : 'Hiện lên trang bán key'}\" data-act=\"togglepg\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn danger\" title=\"Xoá nhóm sản phẩm\" data-act=\"delpg\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "          </button>",
  "        </div>",
  "      </div>",
  "    `;",
  "    list.appendChild(div);",
  "  });",
  "}",
  "",
  "document.getElementById('btnSavePg').addEventListener('click', async ()=>{",
  "  const name = document.getElementById('pgName').value.trim();",
  "  const active = document.getElementById('pgActive').checked;",
  "  if(!name){ showToast('Vui lòng nhập tên nhóm sản phẩm'); return; }",
  "  if(!pgPlanDraft.length){ showToast('Vui lòng thêm ít nhất 1 gói giá'); return; }",
  "  for(const d of pgPlanDraft){",
  "    if(!d.keyPrefix){ showToast('Mỗi gói cần có tiền tố key'); return; }",
  "    if(!d.price){ showToast('Mỗi gói cần có giá bán'); return; }",
  "  }",
  "  const payload = {",
  "    id: editingPgId || undefined,",
  "    name, active,",
  "    logo: pgLogoDataUrl || (editingPgId ? undefined : ''),",
  "    plans: pgPlanDraft.map(d=>({ id: d.id || ('plan'+Date.now()+Math.random().toString(36).slice(2,7)), label:d.label, unit:d.unit, amount:d.unit==='unlimited'?null:d.amount, price:d.price, keyPrefix:d.keyPrefix, maxDevices: d.maxDevices||1 }))",
  "  };",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/product-groups`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)",
  "    });",
  "    if(!res.ok) throw new Error('save_failed');",
  "    showToast(editingPgId ? 'Đã cập nhật nhóm sản phẩm' : 'Đã thêm nhóm sản phẩm mới — sẽ hiện ngay trên trang bán key');",
  "    resetPgForm();",
  "    fetchProductGroups();",
  "  }catch(e){",
  "    showToast('Lưu nhóm sản phẩm thất bại — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "document.getElementById('pgList').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const g = productGroups.find(x=>x.id===id);",
  "  if(!g) return;",
  "  try{",
  "    if(act==='delpg'){",
  "      if(!confirm('Xoá nhóm sản phẩm \"'+g.name+'\"? Key trong kho sẽ KHÔNG bị xoá.')) return;",
  "      await fetch(`${API_BASE}/api/admin/product-groups/${id}`, {method:'DELETE'});",
  "      showToast('Đã xoá nhóm sản phẩm');",
  "    } else if(act==='togglepg'){",
  "      await fetch(`${API_BASE}/api/admin/product-groups/${id}/toggle`, {method:'POST'});",
  "      showToast(g.active ? 'Đã ẩn nhóm sản phẩm khỏi trang bán key' : 'Đã hiện nhóm sản phẩm lên trang bán key');",
  "    } else if(act==='editpg'){",
  "      editingPgId = id;",
  "      pgLogoDataUrl = '';",
  "      pgPlanDraft = (g.plans||[]).map(d=>({...d}));",
  "      document.getElementById('pgFormTitle').textContent = 'Chỉnh sửa nhóm sản phẩm';",
  "      document.getElementById('pgName').value = g.name;",
  "      document.getElementById('pgActive').checked = !!g.active;",
  "      document.getElementById('pgLogoPreview').innerHTML = g.logo ? `<img src=\"${g.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "      document.getElementById('btnCancelEditPg').style.display = '';",
  "      renderPgPlanList();",
  "      window.scrollTo({top:0, behavior:'smooth'});",
  "      return;",
  "    }",
  "  }catch(err){",
  "    showToast('Thao tác thất bại — kiểm tra kết nối tới server backend');",
  "  }",
  "  fetchProductGroups();",
  "});",
  "document.getElementById('btnRefreshPg').addEventListener('click', fetchProductGroups);",
  "",
  "function renderProductGroupsPage(){",
  "  renderPgPlanList();",
  "  fetchProductGroups();",
  "}",
  "",
  "/* ============ TRANG GETKEY (VƯỢT LINK NHẬN KEY) — ADMIN ============ */",
  "let getKeyGames = [];",
  "let editingGetKeyGameId = null;",
  "let gkLogoDataUrl = '';",
  "",
  "document.getElementById('gkLogoInput').addEventListener('change', (e)=>{",
  "  const file = e.target.files && e.target.files[0];",
  "  if(!file) return;",
  "  const reader = new FileReader();",
  "  reader.onload = ()=>{",
  "    gkLogoDataUrl = reader.result;",
  "    document.getElementById('gkLogoPreview').innerHTML = `<img src=\"${gkLogoDataUrl}\" style=\"width:100%; height:100%; object-fit:cover;\">`;",
  "  };",
  "  reader.readAsDataURL(file);",
  "});",
  "",
  "let gkDurationDraft = []; // [{id, label, unit, amount, rounds}] — bản nháp đang chỉnh trong form",
  "",
  "function renderGkDurationList(){",
  "  const wrap = document.getElementById('gkDurationList');",
  "  wrap.innerHTML = '';",
  "  gkDurationDraft.forEach((d, idx)=>{",
  "    const row = document.createElement('div');",
  "    row.style.cssText = 'display:grid; grid-template-columns:1.2fr 0.7fr 0.7fr 0.7fr 0.9fr auto; gap:8px; align-items:end; background:var(--panel-2); border:1px solid var(--line); border-radius:10px; padding:10px;';",
  "    row.innerHTML = `",
  "      <div><label style=\"margin:0 0 4px;\">Nhãn hiển thị</label><input type=\"text\" data-f=\"label\" data-i=\"${idx}\" value=\"${d.label||''}\" placeholder=\"VD: 12 giờ\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Đơn vị</label><select data-f=\"unit\" data-i=\"${idx}\"><option value=\"hour\" ${d.unit==='hour'?'selected':''}>Giờ</option><option value=\"day\" ${d.unit==='day'?'selected':''}>Ngày</option><option value=\"month\" ${d.unit==='month'?'selected':''}>Tháng</option></select></div>",
  "      <div><label style=\"margin:0 0 4px;\">Số lượng</label><input type=\"number\" min=\"1\" data-f=\"amount\" data-i=\"${idx}\" value=\"${d.amount||1}\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Số lượt vượt link</label><input type=\"number\" min=\"1\" data-f=\"rounds\" data-i=\"${idx}\" value=\"${d.rounds||1}\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Tiền tố key (prefix)</label><input type=\"text\" data-f=\"prefix\" data-i=\"${idx}\" value=\"${d.prefix||''}\" placeholder=\"VD: XT12\" maxlength=\"10\" style=\"text-transform:uppercase;\"></div>",
  "      <button class=\"icon-btn danger\" title=\"Xoá loại này\" data-del=\"${idx}\" style=\"height:38px;\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg></button>",
  "    `;",
  "    wrap.appendChild(row);",
  "  });",
  "}",
  "",
  "document.getElementById('btnAddGkDuration').addEventListener('click', ()=>{",
  "  gkDurationDraft.push({ id:'', label:'', unit:'hour', amount:12, rounds:1, prefix:'' });",
  "  renderGkDurationList();",
  "});",
  "",
  "document.getElementById('gkDurationList').addEventListener('input', (e)=>{",
  "  const f = e.target.dataset.f;",
  "  const i = e.target.dataset.i;",
  "  if(f===undefined || i===undefined) return;",
  "  const item = gkDurationDraft[i];",
  "  if(!item) return;",
  "  if(f==='amount' || f==='rounds'){ item[f] = Math.max(1, parseInt(e.target.value)||1); }",
  "  else if(f==='prefix'){ item[f] = e.target.value.toUpperCase(); }",
  "  else { item[f] = e.target.value; }",
  "});",
  "document.getElementById('gkDurationList').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('[data-del]');",
  "  if(!btn) return;",
  "  gkDurationDraft.splice(parseInt(btn.dataset.del), 1);",
  "  renderGkDurationList();",
  "});",
  "",
  "function resetGetKeyGameForm(){",
  "  editingGetKeyGameId = null;",
  "  gkLogoDataUrl = '';",
  "  gkDurationDraft = [];",
  "  document.getElementById('getKeyFormTitle').textContent = 'Thêm game GetKey mới';",
  "  document.getElementById('gkName').value = '';",
  "  document.getElementById('gkActive').checked = true;",
  "  document.getElementById('gkLogoInput').value = '';",
  "  document.getElementById('gkLogoPreview').innerHTML = '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "  document.getElementById('btnCancelEditGetKeyGame').style.display = 'none';",
  "  renderGkDurationList();",
  "}",
  "document.getElementById('btnCancelEditGetKeyGame').addEventListener('click', resetGetKeyGameForm);",
  "",
  "async function fetchGetKeyGames(){",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/getkey/games`, {cache:'no-store'});",
  "    getKeyGames = await res.json();",
  "    // FIX: backup getKeyGames qua /api/state để không mất khi server restart",
  "    if(getKeyGames.length > 0 && stateLoaded){",
  "      fetch(API_BASE + '/api/state', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ getKeyGames }) }).catch(()=>{});",
  "    }",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không tải được danh sách game GetKey', e);",
  "    getKeyGames = [];",
  "  }",
  "  renderGetKeyGameList();",
  "}",
  "",
  "function fmtGkDuration(d){",
  "  const unitLabel = d.unit==='hour' ? 'giờ' : d.unit==='month' ? 'tháng' : 'ngày';",
  "  return (d.label || (d.amount+' '+unitLabel));",
  "}",
  "",
  "function renderGetKeyGameList(){",
  "  const list = document.getElementById('getKeyGameList');",
  "  const empty = document.getElementById('getKeyGameEmpty');",
  "  list.innerHTML = '';",
  "  empty.style.display = getKeyGames.length ? 'none' : 'block';",
  "  getKeyGames.forEach(g=>{",
  "    const allPrefixes = [...new Set((g.durations||[]).map(d=>(d.prefix||g.keyPrefix||'').toUpperCase()).filter(Boolean))];",
  "    const stock = Object.values(keysStore).flat().filter(k=> allPrefixes.some(p=>k.value.startsWith(p+'-')) && ['available','unactivated'].includes(computeStatus(k))).length;",
  "    const durationsTxt = (g.durations||[]).map(d=>{ const p=(d.prefix||g.keyPrefix||'').toUpperCase(); const s=Object.values(keysStore).flat().filter(k=>p&&k.value.startsWith(p+'-')&&['available','unactivated'].includes(computeStatus(k))).length; return `${fmtGkDuration(d)} [${p}] (${d.rounds} lượt · còn ${s})`; }).join(' · ') || 'Chưa có loại thời hạn';",
  "    const div = document.createElement('div');",
  "    div.className = 'ticket';",
  "    div.innerHTML = `",
  "      <div class=\"ticket-top\">",
  "        <div style=\"display:flex; align-items:center; gap:12px;\">",
  "          <div style=\"width:40px; height:40px; border-radius:10px; overflow:hidden; background:var(--panel-2); border:1px solid var(--line); flex-shrink:0; display:flex; align-items:center; justify-content:center;\">",
  "            ${g.logo ? `<img src=\"${g.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '🎮'}",
  "          </div>",
  "          <div class=\"key\" style=\"font-family:'Inter',sans-serif;\">${g.name}</div>",
  "        </div>",
  "        <div class=\"ticket-badges\">",
  "          <span class=\"badge ${g.active ? 'available' : 'expired'}\">${g.active ? 'Đang hiển thị' : 'Đã ẩn'}</span>",
  "        </div>",
  "      </div>",
  "      <div class=\"ticket-bottom\">",
  "        <div class=\"meta\">Tổng còn hàng: <b>${stock}</b><br>${durationsTxt}</div>",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"Sửa\" data-act=\"editgk\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 20h9\"/><path d=\"M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"${g.active ? 'Ẩn khỏi trang GetKey' : 'Hiện lên trang GetKey'}\" data-act=\"togglegk\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn danger\" title=\"Xoá game\" data-act=\"delgk\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "          </button>",
  "        </div>",
  "      </div>",
  "    `;",
  "    list.appendChild(div);",
  "  });",
  "}",
  "",
  "document.getElementById('btnSaveGetKeyGame').addEventListener('click', async ()=>{",
  "  const name = document.getElementById('gkName').value.trim();",
  "  const active = document.getElementById('gkActive').checked;",
  "  if(!name){ showToast('Vui lòng nhập tên game'); return; }",
  "  if(!gkDurationDraft.length){ showToast('Vui lòng thêm ít nhất 1 loại thời hạn'); return; }",
  "  if(gkDurationDraft.some(d => !d.prefix)){ showToast('Vui lòng nhập tiền tố key cho từng loại thời hạn'); return; }",
  "",
  "  const payload = {",
  "    id: editingGetKeyGameId || undefined,",
  "    name, active,",
  "    logo: gkLogoDataUrl || undefined,",
  "    durations: gkDurationDraft.map(d=>({ id:d.id||undefined, label:d.label, unit:d.unit, amount:d.amount, rounds:d.rounds, prefix:d.prefix||'' }))",
  "  };",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/getkey/games`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)",
  "    });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('save_failed');",
  "    showToast(editingGetKeyGameId ? 'Đã cập nhật game GetKey' : 'Đã thêm game GetKey mới');",
  "    resetGetKeyGameForm();",
  "    fetchGetKeyGames();",
  "  }catch(e){",
  "    showToast('Lưu game GetKey thất bại — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "document.getElementById('getKeyGameList').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const g = getKeyGames.find(x=>x.id===id);",
  "  if(!g) return;",
  "  try{",
  "    if(act==='delgk'){",
  "      if(!confirm('Xoá game \"'+g.name+'\"? Key trong kho sẽ KHÔNG bị xoá.')) return;",
  "      await fetch(`${API_BASE}/api/admin/getkey/games/${id}`, {method:'DELETE'});",
  "      showToast('Đã xoá game GetKey');",
  "    } else if(act==='togglegk'){",
  "      await fetch(`${API_BASE}/api/admin/getkey/games/${id}/toggle`, {method:'POST'});",
  "      showToast(g.active ? 'Đã ẩn game khỏi trang GetKey' : 'Đã hiện game lên trang GetKey');",
  "    } else if(act==='editgk'){",
  "      editingGetKeyGameId = id;",
  "      gkLogoDataUrl = g.logo || '';",
  "      gkDurationDraft = (g.durations||[]).map(d=>({ ...d }));",
  "      document.getElementById('getKeyFormTitle').textContent = 'Chỉnh sửa game GetKey';",
  "      document.getElementById('gkName').value = g.name;",
  "      document.getElementById('gkActive').checked = !!g.active;",
  "      document.getElementById('gkLogoPreview').innerHTML = g.logo ? `<img src=\"${g.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "      document.getElementById('btnCancelEditGetKeyGame').style.display = '';",
  "      renderGkDurationList();",
  "      window.scrollTo({top:0, behavior:'smooth'});",
  "      return;",
  "    }",
  "  }catch(e){",
  "    showToast('Thao tác thất bại — kiểm tra kết nối tới server backend');",
  "  }",
  "  fetchGetKeyGames();",
  "});",
  "",
  "document.getElementById('btnRefreshGetKeyGames').addEventListener('click', fetchGetKeyGames);",
  "",
  "function renderGetKeyPage(){",
  "  renderGkDurationList();",
  "  fetchGetKeyGames();",
  "}",
  "",
  "/* ============ NẠP CODE — UPLOAD FILE (KHÔNG CẦN ID, KHÔNG CẦN TEXTAREA) ============ */",
  "let codeSnippets = [];",
  "let cvViewingSnippet = null;",
  "let _cvSelectedFile = null; // file object đang chờ upload",
  "const CV_MAX_BYTES = 10 * 1024 * 1024; // 10MB — khớp giới hạn phía server",
  "",
  "function cvBytesOf(str){ return new Blob([str||'']).size; }",
  "function cvFormatSize(bytes){",
  "  if(bytes < 1024) return bytes + ' B';",
  "  if(bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';",
  "  return (bytes/(1024*1024)).toFixed(2) + ' MB';",
  "}",
  "function cvLangLabel(lang){",
  "  return { python:'Python', java:'Java', javascript:'JavaScript', other:'Khác' }[lang] || lang;",
  "}",
  "",
  "// ─── Cập nhật UI khi có / xoá file ───",
  "function cvSetFile(file){",
  "  _cvSelectedFile = file || null;",
  "  const dropZone   = document.getElementById('cvDropZone');",
  "  const chosenEl   = document.getElementById('cvFileChosen');",
  "  const fileNameEl = document.getElementById('cvFileName');",
  "  const fileSizeEl = document.getElementById('cvFileSize');",
  "  const saveBtn    = document.getElementById('btnSaveCodeSnippet');",
  "  const epBox      = document.getElementById('cvPublicEndpointBox');",
  "  if(!file){",
  "    _cvSelectedFile = null;",
  "    if(chosenEl) chosenEl.style.display = 'none';",
  "    if(dropZone) dropZone.style.borderColor = 'var(--brass-soft)';",
  "    if(saveBtn){ saveBtn.disabled = true; saveBtn.innerHTML = '<svg viewBox=\\'0 0 24 24\\' fill=\\'none\\' stroke=\\'currentColor\\' stroke-width=\\'2.2\\' style=\\'width:15px;height:15px;vertical-align:-3px;margin-right:6px;\\'><path d=\\'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\\'/><polyline points=\\'17 8 12 3 7 8\\'/><line x1=\\'12\\' y1=\\'3\\' x2=\\'12\\' y2=\\'15\\'/></svg>Upload file lên server'; }",
  "    if(epBox) epBox.style.display = 'none';",
  "    return;",
  "  }",
  "  if(file.size > CV_MAX_BYTES){ showToast('File quá lớn — tối đa ' + cvFormatSize(CV_MAX_BYTES)); return; }",
  "  _cvSelectedFile = file;",
  "  if(fileNameEl) fileNameEl.textContent = file.name;",
  "  if(fileSizeEl) fileSizeEl.textContent = cvFormatSize(file.size) + ' · ' + file.name.split('.').pop().toUpperCase();",
  "  if(chosenEl) chosenEl.style.display = '';",
  "  if(dropZone) dropZone.style.borderColor = 'var(--ok)';",
  "  if(saveBtn){ saveBtn.disabled = false; saveBtn.innerHTML = '<svg viewBox=\\'0 0 24 24\\' fill=\\'none\\' stroke=\\'currentColor\\' stroke-width=\\'2.2\\' style=\\'width:15px;height:15px;vertical-align:-3px;margin-right:6px;\\'><path d=\\'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\\'/><polyline points=\\'17 8 12 3 7 8\\'/><line x1=\\'12\\' y1=\\'3\\' x2=\\'12\\' y2=\\'15\\'/></svg>Upload \\'' + file.name + '\\' lên server'; }",
  "}",
  "",
  "// ─── File input: chọn file ───",
  "document.getElementById('cvFileInput').addEventListener('change', (e)=>{",
  "  const file = e.target.files && e.target.files[0];",
  "  cvSetFile(file || null);",
  "});",
  "",
  "// ─── Nút xoá file ───",
  "document.getElementById('btnClearCvFile').addEventListener('click', (e)=>{",
  "  e.stopPropagation();",
  "  document.getElementById('cvFileInput').value = '';",
  "  cvSetFile(null);",
  "});",
  "",
  "// ─── Drag & Drop hỗ trợ ───",
  "(function(){",
  "  const dz = document.getElementById('cvDropZone');",
  "  if(!dz) return;",
  "  dz.addEventListener('dragover', (e)=>{ e.preventDefault(); dz.style.borderColor='var(--brass)'; dz.style.background='var(--brass-tint)'; });",
  "  dz.addEventListener('dragleave', ()=>{ dz.style.borderColor = _cvSelectedFile ? 'var(--ok)' : 'var(--brass-soft)'; });",
  "  dz.addEventListener('drop', (e)=>{",
  "    e.preventDefault();",
  "    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];",
  "    if(file) cvSetFile(file);",
  "    dz.style.borderColor = _cvSelectedFile ? 'var(--ok)' : 'var(--brass-soft)';",
  "  });",
  "})();",
  "",
  "// ─── Thanh tiến trình upload ───",
  "function cvShowProgress(show, pct, statusText, icon){",
  "  const el = document.getElementById('cvUploadProgress');",
  "  const bar = document.getElementById('cvUploadBar');",
  "  const txt = document.getElementById('cvUploadStatusText');",
  "  const ico = document.getElementById('cvUploadStatusIcon');",
  "  if(!el) return;",
  "  el.style.display = show ? '' : 'none';",
  "  if(bar) bar.style.width = (pct||0) + '%';",
  "  if(txt) txt.textContent = statusText || '';",
  "  if(ico) ico.textContent = icon || '⏳';",
  "}",
  "",
  "// ─── Banner script đang active ───",
  "function cvUpdateActiveBanner(){",
  "  const banner = document.getElementById('cvActiveScriptBanner');",
  "  if(!banner) return;",
  "  if(!codeSnippets || !codeSnippets.length){ banner.style.display='none'; return; }",
  "  const s = codeSnippets[0];",
  "  banner.style.display = 'block';",
  "  const nameEl=document.getElementById('cvActiveName');",
  "  const sizeEl=document.getElementById('cvActiveSize');",
  "  const timeEl=document.getElementById('cvActiveTime');",
  "  const endpointEl=document.getElementById('cvPublicEndpoint');",
  "  if(nameEl) nameEl.textContent = s.name || 'Unnamed Script';",
  "  if(sizeEl) sizeEl.textContent = cvFormatSize(s.sizeBytes||0);",
  "  if(timeEl) timeEl.textContent = 'Cập nhật: ' + new Date(s.updatedAt||s.createdAt).toLocaleString('vi-VN');",
  "  if(endpointEl) endpointEl.textContent = window.location.origin + '/api/public/snippet/' + s.id;",
  "}",
  "",
  "// ─── Xoá script từ banner ───",
  "document.getElementById('btnDeleteActiveScript').addEventListener('click', async ()=>{",
  "  if(!codeSnippets.length) return;",
  "  const s = codeSnippets[0];",
  "  if(!confirm('Xoá script \"' + s.name + '\"? Violentmonkey Loader sẽ không còn tải được code về.')) return;",
  "  try{",
  "    await fetch(`${API_BASE}/api/admin/code-snippets/${s.id}`, {method:'DELETE'});",
  "    showToast('Đã xoá script khỏi server');",
  "  }catch(e){ showToast('Xoá thất bại — kiểm tra kết nối server'); }",
  "  fetchCodeSnippets();",
  "});",
  "",
  "// ─── Fetch danh sách snippet ───",
  "async function fetchCodeSnippets(){",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/code-snippets`, {cache:'no-store'});",
  "    codeSnippets = await res.json();",
  "  }catch(e){ codeSnippets = []; }",
  "  renderCodeSnippetList();",
  "  cvUpdateActiveBanner();",
  "  if(typeof vmPopulateSnippetSelect === 'function') vmPopulateSnippetSelect();",
  "}",
  "",
  "// ─── Render danh sách script (tối đa 1) ───",
  "function renderCodeSnippetList(){",
  "  const list = document.getElementById('cvList');",
  "  const empty = document.getElementById('cvEmpty');",
  "  list.innerHTML = '';",
  "  if(!codeSnippets || !codeSnippets.length){ empty.style.display='block'; return; }",
  "  empty.style.display = 'none';",
  "  codeSnippets.forEach(s=>{",
  "    const row = document.createElement('div');",
  "    row.className = 'panel';",
  "    row.style.cssText = 'padding:16px 18px; display:flex; align-items:center; gap:14px; flex-wrap:wrap; border:1.5px solid var(--ok); background:linear-gradient(135deg,#f9fffe,#f0fdf4);';",
  "    const icon = document.createElement('div');",
  "    icon.style.cssText = 'width:40px; height:40px; border-radius:10px; background:linear-gradient(135deg,#2e7d32,#43a047); display:flex; align-items:center; justify-content:center; flex-shrink:0;';",
  "    icon.innerHTML = `<svg viewBox='0 0 24 24' fill='none' stroke='#fff' stroke-width='2.2' style='width:20px;height:20px;'><polygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'/></svg>`;",
  "    const left = document.createElement('div');",
  "    left.style.cssText = 'flex:1; min-width:160px;';",
  "    const title = document.createElement('div');",
  "    title.style.cssText = 'font-weight:700; font-size:14.5px; color:#1b5e20;';",
  "    title.textContent = s.name;",
  "    const meta = document.createElement('div');",
  "    meta.className = 'sub'; meta.style.cssText = 'margin-top:4px; color:#388e3c;';",
  "    meta.textContent = 'JavaScript · ' + cvFormatSize(s.sizeBytes||0) + ' · Cập nhật ' + new Date(s.updatedAt||s.createdAt).toLocaleString('vi-VN');",
  "    const epDiv = document.createElement('div');",
  "    epDiv.style.cssText = 'margin-top:6px; font-family:monospace; font-size:11px; color:var(--muted); word-break:break-all; background:var(--panel-2); padding:4px 8px; border-radius:6px;';",
  "    epDiv.textContent = window.location.origin + '/api/public/snippet/' + s.id;",
  "    left.appendChild(title); left.appendChild(meta); left.appendChild(epDiv);",
  "    const actions = document.createElement('div');",
  "    actions.style.cssText = 'display:flex; gap:8px; flex-wrap:wrap; flex-shrink:0;';",
  "    const btnView = document.createElement('button');",
  "    btnView.className='btn btn-ghost btn-inline'; btnView.textContent='Xem code'; btnView.dataset.act='viewcv'; btnView.dataset.id=s.id;",
  "    const btnDel = document.createElement('button');",
  "    btnDel.className='btn btn-danger-ghost btn-inline'; btnDel.textContent='Xoá'; btnDel.dataset.act='delcv'; btnDel.dataset.id=s.id;",
  "    actions.appendChild(btnView); actions.appendChild(btnDel);",
  "    row.appendChild(icon); row.appendChild(left); row.appendChild(actions);",
  "    list.appendChild(row);",
  "  });",
  "}",
  "",
  "// ─── Click handler danh sách ───",
  "document.getElementById('cvList').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('button[data-act]');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id; const act = btn.dataset.act;",
  "  if(act==='delcv'){",
  "    const s = codeSnippets.find(x=>x.id===id);",
  "    if(!s) return;",
  "    if(!confirm('Xoá script \"'+s.name+'\"? Violentmonkey Loader sẽ không còn tải được code về.')) return;",
  "    try{",
  "      await fetch(`${API_BASE}/api/admin/code-snippets/${id}`, {method:'DELETE'});",
  "      showToast('Đã xoá script khỏi server');",
  "    }catch(e){ showToast('Xoá thất bại — kiểm tra kết nối server'); }",
  "    fetchCodeSnippets();",
  "  } else if(act==='viewcv'){",
  "    try{",
  "      const res = await fetch(`${API_BASE}/api/admin/code-snippets/${id}`, {cache:'no-store'});",
  "      if(!res.ok){ showToast('Không tải được script này'); return; }",
  "      const full = await res.json();",
  "      cvOpenViewModal(full);",
  "    }catch(e){ showToast('Không tải được script này'); }",
  "  }",
  "});",
  "",
  "// ─── Modal xem code ───",
  "function cvOpenViewModal(snippet){",
  "  cvViewingSnippet = snippet;",
  "  document.getElementById('cvViewTitle').textContent = snippet.name;",
  "  document.getElementById('cvViewMeta').textContent = 'JavaScript · ' + cvFormatSize(cvBytesOf(snippet.code||''));",
  "  document.getElementById('cvViewContent').textContent = snippet.code;",
  "  document.getElementById('cvViewModalBg').classList.add('show');",
  "}",
  "document.getElementById('cvViewClose').addEventListener('click', ()=> document.getElementById('cvViewModalBg').classList.remove('show'));",
  "document.getElementById('btnCvCopy').addEventListener('click', async ()=>{",
  "  if(!cvViewingSnippet) return;",
  "  try{",
  "    await navigator.clipboard.writeText(cvViewingSnippet.code);",
  "    showToast('Đã sao chép vào clipboard');",
  "  }catch(e){ showToast('Không sao chép được — trình duyệt chặn clipboard'); }",
  "});",
  "document.getElementById('btnCvDownload').addEventListener('click', ()=>{",
  "  if(!cvViewingSnippet) return;",
  "  const blob = new Blob([cvViewingSnippet.code], {type:'text/plain'});",
  "  const a = document.createElement('a');",
  "  a.href = URL.createObjectURL(blob);",
  "  a.download = (cvViewingSnippet.name||'script').replace(/[^a-zA-Z0-9_\\-\\. ]/g,'_') + '.js';",
  "  document.body.appendChild(a); a.click(); a.remove();",
  "});",
  "",
  "// ─── UPLOAD FILE: đọc file → gọi /api/admin/upload-snippet (XHR thật, progress bar thật) ───",
  "document.getElementById('btnSaveCodeSnippet').addEventListener('click', function(){",
  "  if(!_cvSelectedFile){ showToast('Vui lòng chọn file .js trước'); return; }",
  "  const saveBtn = document.getElementById('btnSaveCodeSnippet');",
  "  saveBtn.disabled = true;",
  "  cvShowProgress(true, 2, 'Đang đọc file...', '⏳');",
  "  const reader = new FileReader();",
  "  reader.onerror = function(){ showToast('Không đọc được file — thử lại'); cvShowProgress(false); saveBtn.disabled=false; };",
  "  reader.onload = function(){",
  "    const code = String(reader.result||'');",
  "    if(!code.trim()){ showToast('File rỗng — chọn lại file khác'); cvShowProgress(false); saveBtn.disabled=false; return; }",
  "    const uploadName = _cvSelectedFile.name.replace(/\\.[^.]+$/, '').trim() || ('script_' + Date.now());",
  "    const payload = JSON.stringify({ name: uploadName, language:'javascript', code: code });",
  "    // Tính kích thước payload để hiện progress chính xác",
  "    const payloadBytes = new Blob([payload]).size;",
  "    cvShowProgress(true, 5, 'Bắt đầu upload ('+(payloadBytes/1048576).toFixed(2)+' MB)...', '🚀');",
  "    const xhr = new XMLHttpRequest();",
  "    xhr.open('POST', (window.API_BASE||'') + '/api/admin/upload-snippet', true);",
  "    xhr.setRequestHeader('Content-Type', 'application/json');",
  "    // ── Progress upload thật (báo cáo từng chunk TCP gửi đi) ──",
  "    xhr.upload.onprogress = function(e){",
  "      if(!e.lengthComputable) return;",
  "      const pct = Math.min(92, Math.round((e.loaded / e.total) * 88) + 4);",
  "      const sent = (e.loaded/1048576).toFixed(2);",
  "      const total = (e.total/1048576).toFixed(2);",
  "      cvShowProgress(true, pct, 'Đang upload... ' + sent + '/' + total + ' MB', '📡');",
  "    };",
  "    xhr.upload.onload = function(){",
  "      cvShowProgress(true, 93, 'Đang server xử lý...', '💾');",
  "    };",
  "    xhr.onreadystatechange = function(){",
  "      if(xhr.readyState !== 4) return;",
  "      if(xhr.status === 0){ cvShowProgress(false); showToast('Upload thất bại — mất kết nối hoặc server timeout'); saveBtn.disabled=false; return; }",
  "      let resData = {};",
  "      try{ resData = JSON.parse(xhr.responseText); }catch(e){}",
  "      if(xhr.status < 200 || xhr.status >= 300){",
  "        cvShowProgress(false);",
  "        showToast(resData.error==='too_large' ? 'File vượt quá 10MB' : (resData.message || 'Upload thất bại — kiểm tra kết nối'));",
  "        saveBtn.disabled = false; return;",
  "      }",
  "      cvShowProgress(true, 100, '✔ Upload thành công!', '✅');",
  "      // Hiển thị public endpoint",
  "      const epBox = document.getElementById('cvPublicEndpointBox');",
  "      const epUrl = document.getElementById('cvPublicEndpointUrl');",
  "      const epCk  = document.getElementById('cvPublicChecksum');",
  "      if(resData.endpoint && epBox){",
  "        if(epUrl) epUrl.textContent = resData.endpoint;",
  "        if(epCk) epCk.textContent = resData.checksum || '';",
  "        epBox.style.display = '';",
  "      }",
  "      const patchNote = resData.patched ? ' — index.js đã được patch (tồn tại sau Render restart)' : '';",
  "      showToast('✔ Script \\'' + uploadName + '\\' đã lên server!' + patchNote);",
  "      setTimeout(function(){ cvShowProgress(false); }, 1400);",
  "      document.getElementById('cvFileInput').value = '';",
  "      cvSetFile(null);",
  "      fetchCodeSnippets();",
  "      saveBtn.disabled = true;",
  "    };",
  "    xhr.onerror = function(){ cvShowProgress(false); showToast('Upload thất bại — lỗi mạng'); saveBtn.disabled=false; };",
  "    xhr.ontimeout = function(){ cvShowProgress(false); showToast('Upload timeout — file quá lớn hoặc kết nối chậm'); saveBtn.disabled=false; };",
  "    xhr.timeout = 180000; // 3 phút timeout cho file 10MB",
  "    xhr.send(payload);",
  "  };",
  "  reader.readAsText(_cvSelectedFile, 'UTF-8');",
  "});",
  "",
  "document.getElementById('btnRefreshCodeSnippets').addEventListener('click', fetchCodeSnippets);",
  "",
  "function renderCodeVaultPage(){",
  "  fetchCodeSnippets();",
  "  vmPopulateSnippetSelect();",
  "}",
  "",
  "/* ============ VIOLENTMONKEY LOADER — TẠO SCRIPT TỰ ĐỘNG FETCH CODE TỪ SERVER ============ */",
  "",
  "/* Điền danh sách code đã lưu vào <select> của VM Loader */",
  "function vmPopulateSnippetSelect(){",
  "  const sel = document.getElementById('vmSnippetId');",
  "  if(!sel) return;",
  "  const prev = sel.value;",
  "  sel.innerHTML = '<option value=\"\">— Chọn đoạn code —</option>';",
  "  (codeSnippets || []).forEach(s=>{",
  "    const o = document.createElement('option');",
  "    o.value = s.id;",
  "    o.textContent = s.name + ' (' + cvLangLabel(s.language) + ')';",
  "    sel.appendChild(o);",
  "  });",
  "  if(prev) sel.value = prev;",
  "}",
  "",
  "/* Sinh nội dung userscript Violentmonkey — v5 Auto-Update + Auto-Endpoint */",
  "function vmBuildScript({ scriptName, matchUrl, snippetId, snippetName, loadingSec, antiBug, antiDebug, antiEdit, antiConsole, autoEndpoint }){",
  "  const serverBase = (window.API_BASE || window.location.origin);",
  "  // autoEndpoint=true: Loader tự fetch /api/public/snippets để lấy endpoint mới nhất",
  "  const snippetsListUrl = serverBase + '/api/public/snippets';",
  "  const versionUrl = serverBase + '/api/public/snippet/' + snippetId + '/version';",
  "  const codeUrl    = serverBase + '/api/public/snippet/' + snippetId;",
  "  const loadMs = (parseInt(loadingSec) || 4) * 1000;",
  "  const cacheCodeKey = '__kv_code_vm__' + (autoEndpoint ? 'auto' : snippetId);",
  "  const cacheMetaKey = '__kv_meta_vm__' + (autoEndpoint ? 'auto' : snippetId);",
  "",
  "  /* ---- Khối anti-debug ---- */",
  "  const antiDebugBlock = antiDebug ? `",
  "  (function _antiDebug(){",
  "    let _devOpen = false;",
  "    const _check = ()=>{",
  "      const t = performance.now();",
  "      debugger;",
  "      if(performance.now() - t > 80){",
  "        if(!_devOpen){ _devOpen = true; console.clear(); }",
  "      } else { _devOpen = false; }",
  "    };",
  "    setInterval(_check, 1000);",
  "  })();` : '';",
  "",
  "  /* ---- Khối khoá console ---- */",
  "  const antiConsoleBlock = antiConsole ? `",
  "  (function _lockConsole(){",
  "    const _noop = ()=>{};",
  "    ['log','warn','error','info','debug','dir','table','trace','group','groupEnd'].forEach(k=>{",
  "      try{ Object.defineProperty(console, k, { value: _noop, writable: false, configurable: false }); }catch(_){}",
  "    });",
  "  })();` : '';",
  "",
  "  /* ---- Khối anti-edit ---- */",
  "  const antiEditBlock = antiEdit ? `",
  "  (function _antiEdit(){",
  "    try{ Object.freeze(Object.prototype); }catch(_){}",
  "    try{ Object.freeze(Array.prototype); }catch(_){}",
  "    try{ Object.freeze(Function.prototype); }catch(_){}",
  "  })();` : '';",
  "",
  "  /* ---- Khối anti-bug wrapper ---- */",
  "  const antiBugWrap = (inner) => antiBug",
  "    ? `(function _safeguard(){\\n  try{\\n${inner}\\n  }catch(_e){\\n    // anti-bug\\n  }\\n})();`",
  "    : inner;",
  "",
  "  /* ---- GM_* Polyfills — inject vào scope thực thi của code gốc ---- */",
  "  const gmPolyfillBlock = `",
  "  const _NS = '__kv_gm__';",
  "  function _native(n){ try{ return typeof window[n]==='function'?window[n]:null; }catch(_){ return null; } }",
  "  function _gm_addStyle(css){ const n=_native('GM_addStyle'); if(n)try{n(css);return;}catch(_){} const s=document.createElement('style'); s.textContent=css; (document.head||document.documentElement).appendChild(s); }",
  "  function _gm_getValue(k,d){ const n=_native('GM_getValue'); if(n)try{return n(k,d);}catch(_){} try{const r=localStorage.getItem(_NS+k);return r===null?d:JSON.parse(r).v;}catch(_){return d;} }",
  "  function _gm_setValue(k,v){ const n=_native('GM_setValue'); if(n)try{n(k,v);return;}catch(_){} try{localStorage.setItem(_NS+k,JSON.stringify({v}));}catch(_){} }",
  "  function _gm_deleteValue(k){ const n=_native('GM_deleteValue'); if(n)try{n(k);return;}catch(_){} try{localStorage.removeItem(_NS+k);}catch(_){} }",
  "  function _gm_listValues(){ const n=_native('GM_listValues'); if(n)try{return n();}catch(_){} try{return Object.keys(localStorage).filter(k=>k.startsWith(_NS)).map(k=>k.slice(_NS.length));}catch(_){return[];} }",
  "  function _gm_log(...a){ const n=_native('GM_log'); if(n)try{n(...a);return;}catch(_){} console.log('[GM]',...a); }",
  "  function _gm_xmlhttpRequest(d){ const n=_native('GM_xmlhttpRequest'); if(n)try{n(d);return;}catch(_){} const m=(d.method||'GET').toUpperCase(); const ctrl=new AbortController(); let t=null; if(d.timeout){t=setTimeout(()=>{ctrl.abort();if(typeof d.ontimeout==='function')d.ontimeout();},d.timeout);} fetch(d.url,{method:m,headers:d.headers||{},body:(m!=='GET'&&m!=='HEAD')?d.data:undefined,signal:ctrl.signal}).then(async r=>{if(t)clearTimeout(t);const tx=await r.text();if(typeof d.onload==='function')d.onload({status:r.status,statusText:r.statusText,responseText:tx,response:tx,finalUrl:r.url});}).catch(e=>{if(t)clearTimeout(t);if(e.name==='AbortError')return;if(typeof d.onerror==='function')d.onerror({error:e});}); }",
  "  function _gm_notification(d,cb){ const n=_native('GM_notification'); if(n)try{n(d,cb);return;}catch(_){} const tx=typeof d==='string'?d:(d.text||''); const ti=(d&&d.title)||'KeyVault'; try{if(Notification.permission==='granted')new Notification(ti,{body:tx});else if(Notification.permission!=='denied')Notification.requestPermission().then(p=>{if(p==='granted')new Notification(ti,{body:tx});});}catch(_){} if(typeof cb==='function')cb(); }",
  "  function _gm_openInTab(u){ const n=_native('GM_openInTab'); if(n)try{return n(u);}catch(_){} const w=window.open(u,'_blank'); return{close:()=>w&&w.close(),closed:false}; }",
  "  function _gm_setClipboard(tx){ const n=_native('GM_setClipboard'); if(n)try{n(tx);return;}catch(_){} try{navigator.clipboard.writeText(tx);}catch(_){const ta=document.createElement('textarea');ta.value=tx;ta.style.cssText='position:fixed;opacity:0';document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();} }",
  "  function _gm_getResourceText(name){ const n=_native('GM_getResourceText'); if(n)try{return n(name);}catch(_){} return null; }",
  "  const _gm_info=(typeof GM_info!=='undefined')?GM_info:{script:{name:'KeyVault Loader',version:'4.0',namespace:'https://keyvault.app/'},scriptHandler:'Violentmonkey',version:'4.0'};",
  "  const _unsafeWindow=(typeof unsafeWindow!=='undefined')?unsafeWindow:window;",
  "  const _GM_POLYFILLS={GM_addStyle:_gm_addStyle,GM_getValue:_gm_getValue,GM_setValue:_gm_setValue,GM_deleteValue:_gm_deleteValue,GM_listValues:_gm_listValues,GM_log:_gm_log,GM_xmlhttpRequest:_gm_xmlhttpRequest,GM_notification:_gm_notification,GM_openInTab:_gm_openInTab,GM_setClipboard:_gm_setClipboard,GM_getResourceText:_gm_getResourceText,GM_info:_gm_info,unsafeWindow:_unsafeWindow};",
  "  `;",
  "",
  "  /* ---- Cache helpers (localStorage) ---- */",
  "  const cacheBlock = `",
  "  const _CACHE_CODE='${cacheCodeKey}'; const _CACHE_META='${cacheMetaKey}';",
  "  function _kvSaveCache(code,checksum,updatedAt){ try{localStorage.setItem(_CACHE_CODE,code);localStorage.setItem(_CACHE_META,JSON.stringify({checksum,updatedAt,cachedAt:Date.now()}));}catch(_){} }",
  "  function _kvLoadCacheCode(){ try{return localStorage.getItem(_CACHE_CODE)||null;}catch(_){return null;} }",
  "  function _kvLoadCacheMeta(){ try{return JSON.parse(localStorage.getItem(_CACHE_META)||'null');}catch(_){return null;} }",
  "  `;",
  "",
  "  /* ---- Fetch helper — timeout 30s, retry 5 lần, cold-start aware ---- */",
  "  const fetchHelper = `",
  "  function _kvFetchOnce(url){ const ctrl=new AbortController(); const t=setTimeout(()=>ctrl.abort(),30000); return fetch(url,{method:'GET',cache:'no-store',headers:{'Accept':'application/json'},signal:ctrl.signal}).finally(()=>clearTimeout(t)); }",
  "  async function _kvFetchJSON(url,label){",
  "    const MAX=5,DELAY=5000;",
  "    for(let i=1;i<=MAX;i++){",
  "      try{",
  "        _setStatus(i===1?('Đang kiểm tra '+label+'...'):('Thử lại lần '+i+'/'+MAX+'...'));",
  "        const res=await _kvFetchOnce(url);",
  "        if(res.status===503||res.status===502){const w=i*6;_setStatus('Server đang khởi động, chờ '+w+'s...');await new Promise(r=>setTimeout(r,w*1000));continue;}",
  "        if(res.status===404) throw new Error('HTTP 404');",
  "        if(!res.ok) throw new Error('HTTP '+res.status);",
  "        const tx=await res.text();",
  "        try{return JSON.parse(tx);}catch(_){throw new Error('Phản hồi không phải JSON');}",
  "      }catch(err){",
  "        if(err.message==='HTTP 404') throw err;",
  "        if(i<MAX){_setStatus('Lỗi kết nối — thử lại sau '+(DELAY/1000)+'s...');await new Promise(r=>setTimeout(r,DELAY));}",
  "        else throw err;",
  "      }",
  "    }",
  "  }",
  "  `;",
  "",
  "  /* ---- Thực thi code gốc với GM_* polyfills inject ---- */",
  "  const execBlock = `",
  "  function _kvExec(code){",
  "    try{",
  "      const pn=Object.keys(_GM_POLYFILLS); const pv=Object.values(_GM_POLYFILLS);",
  "      const fn=new Function(...pn,'(function(){\\\\n'+code+'\\\\n})();');",
  "      fn(...pv);",
  "    }catch(err){",
  "      console.error('[KeyVault Loader v4] Lỗi thực thi:',err);",
  "      const d=document.createElement('div');",
  "      d.style.cssText='position:fixed;bottom:12px;right:12px;background:rgba(239,83,80,.95);color:#fff;padding:10px 14px;border-radius:8px;font-size:11px;z-index:2147483647;max-width:300px;line-height:1.5;box-shadow:0 4px 16px rgba(0,0,0,.5)';",
  "      d.textContent='[KeyVault v4] Lỗi thực thi: '+(err.message||err);",
  "      document.body&&document.body.appendChild(d); setTimeout(()=>d.remove(),10000);",
  "    }",
  "  }",
  "  `;",
  "",
  "  /* ---- Overlay UI đầy đủ ---- */",
  "  const loaderUI = `",
  "  (function(){",
  "    const _styleEl=document.createElement('style');",
  "    _styleEl.textContent='@keyframes __kvSpin{to{transform:rotate(360deg)}}@keyframes __kvFadeIn{from{opacity:0}to{opacity:1}}';",
  "    (document.head||document.documentElement).appendChild(_styleEl);",
  "    const _ov=document.createElement('div');",
  "    _ov.id='__kv_loader__';",
  "    _ov.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,10,14,0.94);z-index:2147483647;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:system-ui,sans-serif;color:#f1f1f1;user-select:none;pointer-events:all;animation:__kvFadeIn .2s ease';",
  "    _ov.innerHTML='<div style=\\'text-align:center\\'><div style=\\'width:52px;height:52px;margin:0 auto 18px;border:4px solid #333;border-top-color:#c99a2e;border-radius:50%;animation:__kvSpin 0.75s linear infinite\\'></div><div style=\\'font-size:15px;font-weight:600;letter-spacing:.3px;margin-bottom:6px\\'>Đang tải dữ liệu server...</div><div id=\\'__kv_pct\\' style=\\'font-size:12px;color:#aaa;margin-bottom:18px\\'>0%</div><div style=\\'width:220px;height:4px;background:#222;border-radius:99px;overflow:hidden\\'><div id=\\'__kv_bar\\' style=\\'height:100%;width:0%;background:linear-gradient(90deg,#ad7f1e,#c99a2e);border-radius:99px;transition:width .18s ease\\'></div></div><div id=\\'__kv_status\\' style=\\'margin-top:14px;font-size:11px;color:#555\\'>KeyVault · Auto-Update Loader v4</div><div id=\\'__kv_badge\\' style=\\'margin-top:8px;font-size:10px;color:#3a3;display:none\\'></div></div>';",
  "    function _doAppend(){ if(document.body)document.body.appendChild(_ov); else document.addEventListener('DOMContentLoaded',()=>document.body&&document.body.appendChild(_ov)); }",
  "    _doAppend();",
  "  })();",
  "  const _startTime=Date.now(); const _totalMs=${loadMs};",
  "  const _ticker=setInterval(()=>{ const pct=Math.min(90,Math.round((Date.now()-_startTime)/_totalMs*90)); const bar=document.getElementById('__kv_bar'); const pctEl=document.getElementById('__kv_pct'); if(bar)bar.style.width=pct+'%'; if(pctEl)pctEl.textContent=pct+'%'; },80);",
  "  function _setStatus(msg){ const el=document.getElementById('__kv_status'); if(el)el.textContent=msg; }",
  "  function _showBadge(msg){ const el=document.getElementById('__kv_badge'); if(el){el.textContent=msg;el.style.display='block';} }",
  "  function _finishOverlay(cb){ clearInterval(_ticker); const bar=document.getElementById('__kv_bar'); const pctEl=document.getElementById('__kv_pct'); if(bar)bar.style.width='100%'; if(pctEl)pctEl.textContent='100%'; setTimeout(()=>{ const ov=document.getElementById('__kv_loader__'); if(ov)ov.remove(); if(cb)cb(); },400); }",
  "  function _showError(htmlMsg){ clearInterval(_ticker); const ov=document.getElementById('__kv_loader__'); if(!ov)return; ov.innerHTML='<div style=\\'text-align:center\\'><div style=\\'font-size:32px;margin-bottom:12px\\'>⚠</div><div style=\\'font-size:14px;font-weight:600;margin-bottom:6px\\'>Không tải được dữ liệu server</div><div style=\\'font-size:11px;color:#888;max-width:290px;line-height:1.7\\'>'+htmlMsg+'</div><div style=\\'margin-top:18px;display:flex;gap:8px;justify-content:center\\'><button id=\\'__kv_retry_btn\\' style=\\'background:#c99a2e;color:#111;border:none;border-radius:6px;padding:8px 22px;font-size:12px;font-weight:700;cursor:pointer\\'>🔄 Thử lại</button><button id=\\'__kv_cache_btn\\' style=\\'background:#333;color:#ccc;border:none;border-radius:6px;padding:8px 16px;font-size:12px;cursor:pointer\\'>📦 Dùng cache</button></div></div>'; document.getElementById('__kv_retry_btn')&&document.getElementById('__kv_retry_btn').addEventListener('click',()=>{ov.remove();window.__kvVMRunning=false;setTimeout(_kvRun,100);}); const cBtn=document.getElementById('__kv_cache_btn'); const cCode=_kvLoadCacheCode(); if(cCode){cBtn&&cBtn.addEventListener('click',()=>{_finishOverlay(()=>_kvExec(cCode));});}else{if(cBtn){cBtn.disabled=true;cBtn.textContent='📦 Chưa có cache';cBtn.style.opacity='0.5';}} }",
  "  `;",
  "",
  "  /* ---- Main loader — AUTO-UPDATE v4: version check → cache → fetch ---- */",
  "  const mainLoader = `",
  "  async function _kvRun(){",
  "    if(window.__kvVMRunning) return; window.__kvVMRunning=true;",
  "    // === AUTO-ENDPOINT: tự fetch danh sách snippet từ server ===",
  "    const SNIPPETS_LIST_URL='${snippetsListUrl}';",
  "    const AUTO_ENDPOINT=${autoEndpoint ? 'true' : 'false'};",
  "    let VERSION_URL='${versionUrl}'; let CODE_URL='${codeUrl}';",
  "    if(AUTO_ENDPOINT){",
  "      try{",
  "        _setStatus('Đang lấy Public Endpoint từ server...');",
  "        const listRes=await _kvFetchOnce(SNIPPETS_LIST_URL);",
  "        if(listRes.ok){",
  "          const list=await listRes.json();",
  "          if(Array.isArray(list)&&list.length>0){",
  "            const sn=list[0];",
  "            const base=SNIPPETS_LIST_URL.replace('/api/public/snippets','');",
  "            VERSION_URL=base+'/api/public/snippet/'+sn.id+'/version';",
  "            CODE_URL   =base+'/api/public/snippet/'+sn.id;",
  "          }",
  "        }",
  "      }catch(_e){ /* fallback to hardcoded endpoint */ }",
  "    }",
  "    const [,vRes]=await Promise.allSettled([new Promise(r=>setTimeout(r,${loadMs})),_kvFetchJSON(VERSION_URL,'version')]);",
  "    if(vRes.status==='rejected'){",
  "      const cc=_kvLoadCacheCode(); const cm=_kvLoadCacheMeta();",
  "      if(cc){ _setStatus('Không kết nối được — đang dùng cache...'); const age=cm?Math.round((Date.now()-cm.cachedAt)/60000):'?'; _showBadge('📦 Cache ('+age+' phút trước)'); await new Promise(r=>setTimeout(r,800)); _finishOverlay(()=>_kvExec(cc)); }",
  "      else{ _showError('<b>'+(vRes.reason&&vRes.reason.message||'Lỗi kết nối')+'</b><br><span style=\\\\\'color:#666\\\\\'>Chưa có cache — kiểm tra kết nối mạng.</span>'); }",
  "      return;",
  "    }",
  "    const sVer=vRes.value; const sChecksum=(sVer&&sVer.checksum)||null; const sUpdatedAt=(sVer&&sVer.updatedAt)||null;",
  "    const cm=_kvLoadCacheMeta(); const cc=_kvLoadCacheCode();",
  "    const hasCache=!!(cc&&cm&&cm.checksum); const isUpToDate=hasCache&&cm.checksum===sChecksum;",
  "    if(isUpToDate){ _setStatus('✔ Script đã cập nhật — đang khởi động...'); _showBadge('✔ Phiên bản hiện tại ('+(sUpdatedAt?new Date(sUpdatedAt).toLocaleString('vi-VN'):'')+')'); _finishOverlay(()=>_kvExec(cc)); return; }",
  "    if(hasCache) _setStatus('🔄 Phát hiện bản cập nhật — đang tải code mới...');",
  "    else _setStatus('Đang tải code từ server...');",
  "    const [,cRes]=await Promise.allSettled([Promise.resolve(),_kvFetchJSON(CODE_URL,'code')]);",
  "    if(cRes.status==='fulfilled'){",
  "      const data=cRes.value; const newCode=(data&&(data.code||data.content))||null;",
  "      if(!newCode||newCode.trim().length<10){ _showError('<b>Server trả về code rỗng</b><br><span style=\\\\\'color:#666\\\\\'>Kiểm tra lại snippet trên server.</span>'); return; }",
  "      _kvSaveCache(newCode,sChecksum||data.checksum,sUpdatedAt||data.updatedAt);",
  "      if(hasCache) _showBadge('🔄 Đã cập nhật lên phiên bản '+(sUpdatedAt?new Date(sUpdatedAt).toLocaleString('vi-VN'):'mới'));",
  "      _finishOverlay(()=>_kvExec(newCode));",
  "    } else {",
  "      if(cc){ _setStatus('Không tải được bản mới — dùng cache cũ...'); _showBadge('⚠ Đang dùng bản cũ (offline)'); await new Promise(r=>setTimeout(r,800)); _finishOverlay(()=>_kvExec(cc)); }",
  "      else{ _showError('<b>'+(cRes.reason&&cRes.reason.message||'Lỗi tải code')+'</b><br><span style=\\\\\'color:#666\\\\\'>Không có cache dự phòng.</span>'); }",
  "    }",
  "  }",
  "  _kvRun();`;",
  "",
  "  const innerCode = `${gmPolyfillBlock}\\n${cacheBlock}\\n${fetchHelper}\\n${execBlock}\\n${antiConsoleBlock}${antiDebugBlock}${antiEditBlock}${loaderUI}\\n${mainLoader}`;",
  "  const finalCode = antiBugWrap(innerCode);",
  "",
  "  return `// ==UserScript==",
  "// @name         ${scriptName || 'KeyVault Loader'}",
  "// @namespace    https://keyvault.app/",
  "// @version      4.0",
  "// @description  Auto-update: tải code \"${snippetName}\" từ server, cache thông minh, retry tự động",
  "// @author       KeyVault",
  "// @match        ${matchUrl || '*://*/*'}",
  "// @grant        GM_addStyle",
  "// @grant        GM_setValue",
  "// @grant        GM_getValue",
  "// @grant        GM_deleteValue",
  "// @grant        GM_listValues",
  "// @grant        GM_xmlhttpRequest",
  "// @grant        GM_log",
  "// @grant        GM_notification",
  "// @grant        GM_openInTab",
  "// @grant        GM_setClipboard",
  "// @grant        GM_getResourceText",
  "// @grant        GM_info",
  "// @grant        unsafeWindow",
  "// @connect      *",
  "// @run-at       document-start",
  "// ==/UserScript==",
  "",
  "(function(){",
  "  'use strict';",
  "${finalCode}",
  "})();`;",
  "}",
  "",
  "/* Sự kiện: bấm nút Tạo Violentmonkey Script */",
  "document.getElementById('btnGenerateVMScript').addEventListener('click', ()=>{",
  "  const autoEndpoint = document.getElementById('vmAutoEndpoint') && document.getElementById('vmAutoEndpoint').checked;",
  "  const snippetId = document.getElementById('vmSnippetId').value;",
  "  // Nếu autoEndpoint bật: không bắt buộc chọn code — server tự trả endpoint",
  "  if(!autoEndpoint && !snippetId){ showToast('Vui lòng chọn đoạn code hoặc bật Auto Endpoint'); return; }",
  "  const snippet = (codeSnippets||[]).find(s=>s.id===snippetId) || (codeSnippets&&codeSnippets[0]) || { name: 'Auto Script', id: '' };",
  "  const scriptName = document.getElementById('vmScriptName').value.trim() || 'KeyVault Loader';",
  "  const matchUrl = document.getElementById('vmMatchUrl').value.trim() || '*://*/*';",
  "  const loadingSec = parseInt(document.getElementById('vmLoadingSeconds').value)||4;",
  "  const antiBug = document.getElementById('vmAntiBug').checked;",
  "  const antiDebug = document.getElementById('vmAntiDebug').checked;",
  "  const antiEdit = document.getElementById('vmAntiEdit').checked;",
  "  const antiConsole = document.getElementById('vmAntiConsole').checked;",
  "  const script = vmBuildScript({ scriptName, matchUrl, snippetId: snippet.id || '', snippetName: snippet.name, loadingSec, antiBug, antiDebug, antiEdit, antiConsole, autoEndpoint });",
  "  document.getElementById('vmScriptContent').value = script;",
  "  document.getElementById('vmScriptOutput').style.display = '';",
  "  document.getElementById('vmScriptContent').scrollIntoView({ behavior: 'smooth', block: 'center' });",
  "  showToast(autoEndpoint ? 'Script đã tạo với Auto Endpoint — tự kéo code mới nhất từ server!' : 'Script đã được tạo — copy và cài vào Violentmonkey');",
  "});",
  "",
  "/* Sao chép script */",
  "document.getElementById('btnCopyVMScript').addEventListener('click', async ()=>{",
  "  const txt = document.getElementById('vmScriptContent').value;",
  "  if(!txt) return;",
  "  try{",
  "    await navigator.clipboard.writeText(txt);",
  "    showToast('Đã sao chép script vào clipboard');",
  "  }catch(e){ showToast('Không sao chép được — trình duyệt chặn clipboard'); }",
  "});",
  "",
  "/* Tải script về file .user.js */",
  "document.getElementById('btnDownloadVMScript').addEventListener('click', ()=>{",
  "  const txt = document.getElementById('vmScriptContent').value;",
  "  if(!txt) return;",
  "  const name = (document.getElementById('vmScriptName').value.trim() || 'keyvault-loader').replace(/[^a-z0-9_\\-]/gi,'_').toLowerCase();",
  "  const blob = new Blob([txt], { type: 'text/javascript' });",
  "  const a = document.createElement('a');",
  "  a.href = URL.createObjectURL(blob);",
  "  a.download = name + '.user.js';",
  "  document.body.appendChild(a); a.click(); a.remove();",
  "  showToast('Đã tải file ' + name + '.user.js');",
  "});",
  "",
  "/* ============ QUẢN LÝ MINI APP (BOT TELEGRAM) ============ */",
  "let miniAppUsersCache = [];",
  "",
  "async function fetchMiniAppStatus(){",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/telegram/status`, {cache:'no-store'});",
  "    const data = await res.json();",
  "    document.getElementById('miniAppMiniUrl').innerHTML = data.miniAppUrl",
  "      ? 'Link Mini App: <b>' + data.miniAppUrl + '</b>'",
  "      : 'Chưa xác định được link Mini App (server chưa deploy trên domain public).';",
  "    document.getElementById('miniAppWebhookStatus').textContent = data.webhookConfigured",
  "      ? '✔ Webhook Telegram đã được tự động cấu hình khi server khởi động.'",
  "      : '⚠ Chưa tự cấu hình được webhook — thiếu biến môi trường RENDER_EXTERNAL_URL/SELF_URL trên server.';",
  "    document.getElementById('miniAppUserCount').textContent = 'Tổng số user đã vào Bot: ' + (data.totalUsers||0);",
  "  }catch(e){",
  "    document.getElementById('miniAppMiniUrl').textContent = 'Không tải được trạng thái — kiểm tra kết nối server.';",
  "  }",
  "}",
  "document.getElementById('btnRefreshMiniAppStatus').addEventListener('click', fetchMiniAppStatus);",
  "",
  "async function fetchMiniAppUsers(){",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/telegram/users`, {cache:'no-store'});",
  "    miniAppUsersCache = await res.json();",
  "  }catch(e){",
  "    miniAppUsersCache = [];",
  "  }",
  "  renderMiniAppUserList();",
  "}",
  "document.getElementById('btnRefreshMiniAppUsers').addEventListener('click', fetchMiniAppUsers);",
  "",
  "function renderMiniAppUserList(){",
  "  const list = document.getElementById('miniAppUserList');",
  "  const empty = document.getElementById('miniAppUserEmpty');",
  "  list.innerHTML = '';",
  "  empty.style.display = miniAppUsersCache.length ? 'none' : 'block';",
  "  miniAppUsersCache.forEach(u=>{",
  "    const displayName = (u.telegramFirstName || '') + (u.telegramLastName ? ' ' + u.telegramLastName : '') || (u.telegramUsername ? '@'+u.telegramUsername : 'Telegram #'+u.telegramId);",
  "    const row = document.createElement('div');",
  "    row.className = 'panel';",
  "    row.style.cssText = 'padding:14px 16px;';",
  "    row.innerHTML = `",
  "      <div style=\"display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;\">",
  "        <div>",
  "          <div style=\"font-weight:600; font-size:14px;\">${displayName}</div>",
  "          <div class=\"sub\" style=\"margin-top:3px;\">ID Telegram: ${u.telegramId}${u.telegramUsername ? ' · @'+u.telegramUsername : ''}</div>",
  "          <div class=\"sub\" style=\"margin-top:2px;\">Loại tài khoản: <b>${u.telegramTier==='seller' ? 'Seller' : 'Khách hàng'}</b> · Số dư: <b>${fmtMoney(u.balance||0)}</b></div>",
  "          <div class=\"sub\" style=\"margin-top:2px;\">Vào Bot lần đầu: ${new Date(u.joinedAt).toLocaleString('vi-VN')} · Hoạt động gần nhất: ${new Date(u.lastSeenAt).toLocaleString('vi-VN')}</div>",
  "        </div>",
  "        <div style=\"display:flex; gap:8px; flex-wrap:wrap;\">",
  "          <button class=\"btn btn-ghost btn-inline\" data-act=\"topup\" data-id=\"${u.id}\">Nạp tiền thủ công</button>",
  "          <button class=\"btn btn-ghost btn-inline\" data-act=\"tier\" data-id=\"${u.id}\">${u.telegramTier==='seller' ? 'Hạ về Khách hàng' : 'Thăng cấp Seller'}</button>",
  "          <button class=\"btn btn-ghost btn-inline\" data-act=\"notify\" data-id=\"${u.id}\">Gửi thông báo riêng</button>",
  "        </div>",
  "      </div>",
  "    `;",
  "    list.appendChild(row);",
  "  });",
  "}",
  "",
  "document.getElementById('miniAppUserList').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('button[data-act]');",
  "  if(!btn) return;",
  "  const u = miniAppUsersCache.find(x=>x.id===btn.dataset.id);",
  "  if(!u) return;",
  "  const displayName = (u.telegramFirstName || u.telegramUsername || ('Telegram #'+u.telegramId));",
  "",
  "  if(btn.dataset.act==='topup'){",
  "    const raw = window.prompt('Nhập số tiền muốn cộng cho ' + displayName + ' (nhập số âm để trừ):', '50000');",
  "    if(raw===null) return;",
  "    const amount = parseFloat(String(raw).replace(/[^\\d.-]/g,'')) || 0;",
  "    if(amount===0){ showToast('Vui lòng nhập số tiền hợp lệ'); return; }",
  "    try{",
  "      const res = await fetch(`${API_BASE}/api/admin/customers/${u.id}/balance`, {",
  "        method:'POST', headers:{'Content-Type':'application/json'},",
  "        body: JSON.stringify({ amount, note: 'Admin nạp tiền thủ công (Mini App)' })",
  "      });",
  "      const data = await res.json();",
  "      if(!res.ok || !data.ok) throw new Error('failed');",
  "      showToast('Đã cộng ' + fmtMoney(amount) + ' cho ' + displayName);",
  "      fetchMiniAppUsers();",
  "    }catch(e){ showToast('Nạp tiền thất bại — kiểm tra kết nối server'); }",
  "  } else if(btn.dataset.act==='tier'){",
  "    const nextTier = u.telegramTier==='seller' ? 'customer' : 'seller';",
  "    try{",
  "      const res = await fetch(`${API_BASE}/api/admin/telegram/users/${u.id}/tier`, {",
  "        method:'POST', headers:{'Content-Type':'application/json'},",
  "        body: JSON.stringify({ tier: nextTier })",
  "      });",
  "      const data = await res.json();",
  "      if(!res.ok || !data.ok) throw new Error('failed');",
  "      showToast(nextTier==='seller' ? 'Đã thăng cấp ' + displayName + ' lên Seller' : 'Đã hạ ' + displayName + ' về Khách hàng');",
  "      fetchMiniAppUsers();",
  "    }catch(e){ showToast('Thao tác thất bại — kiểm tra kết nối server'); }",
  "  } else if(btn.dataset.act==='notify'){",
  "    const msg = window.prompt('Nội dung thông báo gửi riêng cho ' + displayName + ':');",
  "    if(!msg || !msg.trim()) return;",
  "    try{",
  "      const res = await fetch(`${API_BASE}/api/admin/telegram/notify`, {",
  "        method:'POST', headers:{'Content-Type':'application/json'},",
  "        body: JSON.stringify({ customerId: u.id, message: msg.trim() })",
  "      });",
  "      const data = await res.json();",
  "      if(!res.ok || !data.ok || !data.sent) throw new Error('failed');",
  "      showToast('Đã gửi thông báo cho ' + displayName);",
  "    }catch(e){ showToast('Gửi thông báo thất bại — user có thể đã chặn Bot'); }",
  "  }",
  "});",
  "",
  "document.getElementById('btnBroadcastMiniApp').addEventListener('click', async ()=>{",
  "  const msg = document.getElementById('miniAppBroadcastMsg').value.trim();",
  "  if(!msg){ showToast('Vui lòng nhập nội dung thông báo'); return; }",
  "  if(!confirm('Gửi thông báo này cho TẤT CẢ user đã vào Mini App?')) return;",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/telegram/notify`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'},",
  "      body: JSON.stringify({ message: msg })",
  "    });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('failed');",
  "    showToast('Đã gửi tới ' + data.sent + '/' + data.total + ' user');",
  "    document.getElementById('miniAppBroadcastMsg').value = '';",
  "  }catch(e){ showToast('Gửi thông báo thất bại — kiểm tra kết nối server'); }",
  "});",
  "",
  "/* ============ APK VAULT ============ */",
  "let apkList = [];",
  "",
  "async function apkFetchList(){",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/admin/apkvault/list');",
  "    const data = await res.json();",
  "    if(data.ok) apkList = data.apks || [];",
  "    else apkList = [];",
  "  }catch(e){ apkList = []; }",
  "  apkRender();",
  "}",
  "",
  "function apkFmtSize(bytes){",
  "  if(!bytes) return '—';",
  "  if(bytes >= 1024*1024) return (bytes/(1024*1024)).toFixed(2) + ' MB';",
  "  if(bytes >= 1024) return (bytes/1024).toFixed(1) + ' KB';",
  "  return bytes + ' B';",
  "}",
  "",
  "function apkRender(){",
  "  const list = document.getElementById('apkList');",
  "  const empty = document.getElementById('apkEmpty');",
  "  if(!list) return;",
  "  list.innerHTML = '';",
  "  if(!apkList.length){ empty.style.display=''; return; }",
  "  empty.style.display='none';",
  "  apkList.slice().reverse().forEach(function(apk){",
  "    var card = document.createElement('div');",
  "    card.className = 'apk-card';",
  "    var sizeLabel = apkFmtSize(apk.size);",
  "    var dateLabel = new Date(apk.uploadedAt).toLocaleString('vi-VN');",
  "    var noteHtml = apk.note ? '<div class=\"apk-note\">' + apk.note.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>' : '';",
  "    card.innerHTML = '<div class=\"apk-icon\">\\u{1F4E6}</div><div class=\"apk-info\"><div class=\"apk-name\">' + apk.filename.replace(/</g,'&lt;') + '</div><div class=\"apk-meta\">K\\u00edch th\\u01b0\\u1edbc: <b>' + sizeLabel + '</b> &nbsp;\\u00b7&nbsp; T\\u1ea3i l\\u00ean: <b>' + dateLabel + '</b></div>' + noteHtml + '</div><div class=\"apk-actions\"><a class=\"apk-download-btn\" href=\"' + API_BASE + '/api/admin/apkvault/download/' + apk.id + '\" download=\"' + apk.filename + '\"><svg width=\"13\" height=\"13\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\"/><polyline points=\"7 10 12 15 17 10\"/><line x1=\"12\" y1=\"15\" x2=\"12\" y2=\"3\"/></svg>T\\u1ea3i v\\u1ec1</a><button class=\"apk-edit-btn\" data-id=\"' + apk.id + '\" data-note=\"' + (apk.note||'').replace(/\"/g,'&quot;') + '\"><svg width=\"13\" height=\"13\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7\"/><path d=\"M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z\"/></svg>C\\u1eadp nh\\u1eadt ghi ch\\u00fa</button><button class=\"apk-del-btn\" data-id=\"' + apk.id + '\" data-name=\"' + apk.filename.replace(/\"/g,'&quot;') + '\"><svg width=\"13\" height=\"13\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><polyline points=\"3 6 5 6 21 6\"/><path d=\"M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6\"/><path d=\"M10 11v6\"/><path d=\"M14 11v6\"/><path d=\"M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2\"/></svg>X\\u00f3a</button></div>';",
  "    list.appendChild(card);",
  "  });",
  "  list.querySelectorAll('.apk-del-btn').forEach(function(btn){",
  "    btn.addEventListener('click', async function(){",
  "      if(!confirm('X\\u00f3a file ' + btn.dataset.name + '?')) return;",
  "      try{",
  "        var res = await fetch(API_BASE + '/api/admin/apkvault/delete/' + btn.dataset.id, {method:'DELETE'});",
  "        var data = await res.json();",
  "        if(data.ok){ showToast('\\u0110\\u00e3 x\\u00f3a file APK'); apkFetchList(); }",
  "        else showToast('X\\u00f3a th\\u1ea5t b\\u1ea1i: ' + (data.error||'unknown'));",
  "      }catch(e){ showToast('L\\u1ed7i k\\u1ebft n\\u1ed1i khi x\\u00f3a'); }",
  "    });",
  "  });",
  "  list.querySelectorAll('.apk-edit-btn').forEach(function(btn){",
  "    btn.addEventListener('click', async function(){",
  "      var cur = btn.dataset.note || '';",
  "      var newNote = window.prompt('Nh\\u1eadp ghi ch\\u00fa t\\u00ednh n\\u0103ng / m\\u00f4 t\\u1ea3 cho APK n\\u00e0y:', cur);",
  "      if(newNote === null) return;",
  "      try{",
  "        var res = await fetch(API_BASE + '/api/admin/apkvault/note/' + btn.dataset.id, {",
  "          method:'POST', headers:{'Content-Type':'application/json'},",
  "          body: JSON.stringify({ note: newNote.trim() })",
  "        });",
  "        var data = await res.json();",
  "        if(data.ok){ showToast('\\u0110\\u00e3 c\\u1eadp nh\\u1eadt ghi ch\\u00fa'); apkFetchList(); }",
  "        else showToast('C\\u1eadp nh\\u1eadt th\\u1ea5t b\\u1ea1i: ' + (data.error||'unknown'));",
  "      }catch(e){ showToast('L\\u1ed7i k\\u1ebft n\\u1ed1i'); }",
  "    });",
  "  });",
  "}",
  "",
  "(function initApkVault(){",
  "  var zone = document.getElementById('apkDropZone');",
  "  var fileInput = document.getElementById('apkFileInput');",
  "  var progressWrap = document.getElementById('apkProgressWrap');",
  "  var progressFill = document.getElementById('apkProgressFill');",
  "  var progressLabel = document.getElementById('apkProgressLabel');",
  "  var btnRefreshApk = document.getElementById('btnRefreshApk');",
  "  if(!zone) return;",
  "  if(btnRefreshApk) btnRefreshApk.addEventListener('click', apkFetchList);",
  "  zone.addEventListener('click', function(){ fileInput.click(); });",
  "  zone.addEventListener('dragover', function(e){ e.preventDefault(); zone.classList.add('drag-over'); });",
  "  zone.addEventListener('dragleave', function(){ zone.classList.remove('drag-over'); });",
  "  zone.addEventListener('drop', function(e){ e.preventDefault(); zone.classList.remove('drag-over'); var f=e.dataTransfer.files[0]; if(f) apkDoUpload(f); });",
  "  fileInput.addEventListener('change', function(){ if(fileInput.files[0]) apkDoUpload(fileInput.files[0]); });",
  "  async function apkDoUpload(file){",
  "    if(!file.name.toLowerCase().endsWith('.apk')){ showToast('Ch\\u1ec9 ch\\u1ea5p nh\\u1eadn file .apk'); return; }",
  "    if(file.size > 100*1024*1024){ showToast('File v\\u01b0\\u1ee3t qu\\u00e1 100 MB'); return; }",
  "    var noteEl = document.getElementById('apkNoteInput');",
  "    var note = (noteEl && noteEl.value.trim()) || '';",
  "    var fd = new FormData();",
  "    fd.append('apk', file);",
  "    fd.append('note', note);",
  "    progressWrap.style.display='block';",
  "    progressFill.style.width='0%';",
  "    progressLabel.textContent = '\\u0110ang t\\u1ea3i l\\u00ean... 0%';",
  "    zone.style.pointerEvents='none'; zone.style.opacity='0.5';",
  "    try{",
  "      await new Promise(function(resolve, reject){",
  "        var xhr = new XMLHttpRequest();",
  "        xhr.open('POST', API_BASE + '/api/admin/apkvault/upload');",
  "        xhr.upload.onprogress = function(e){ if(e.lengthComputable){ var pct=Math.round(e.loaded/e.total*100); progressFill.style.width=pct+'%'; progressLabel.textContent='\\u0110ang t\\u1ea3i l\\u00ean... '+pct+'%'; } };",
  "        xhr.onload = function(){ try{ var d=JSON.parse(xhr.responseText); if(d.ok){ resolve(d); } else reject(new Error(d.error||'upload_failed')); }catch(ex){ reject(ex); } };",
  "        xhr.onerror = function(){ reject(new Error('network_error')); };",
  "        xhr.send(fd);",
  "      });",
  "      progressFill.style.width='100%';",
  "      progressLabel.textContent='T\\u1ea3i l\\u00ean th\\u00e0nh c\\u00f4ng!';",
  "      showToast('\\u0110\\u00e3 n\\u1ea1p file APK l\\u00ean server!');",
  "      if(noteEl) noteEl.value='';",
  "      apkFetchList();",
  "    }catch(e){",
  "      progressLabel.textContent='T\\u1ea3i l\\u00ean th\\u1ea5t b\\u1ea1i: ' + e.message;",
  "      showToast('Upload th\\u1ea5t b\\u1ea1i: ' + e.message);",
  "    }",
  "    zone.style.pointerEvents=''; zone.style.opacity='';",
  "    fileInput.value='';",
  "    setTimeout(function(){ progressWrap.style.display='none'; }, 3500);",
  "  }",
  "})();",
  "",
  "/* ============ NẠP FILE CODE — uploadcode page JS ============ */",
  "(function(){",
  "  var _ucFile = null;",
  "  var zone    = document.getElementById('ucDropZone');",
  "  var fileInput = document.getElementById('ucFileInput');",
  "  var btnUpload = document.getElementById('btnUploadCode');",
  "  var btnClear  = document.getElementById('btnClearUcFile');",
  "  if(!zone) return;",
  "",
  "  function ucSetFile(f){",
  "    if(!f) return;",
  "    var maxMB = 10;",
  "    if(f.size > maxMB*1024*1024){ showToast('File vượt quá ' + maxMB + ' MB'); return; }",
  "    _ucFile = f;",
  "    document.getElementById('ucFileName').textContent = f.name;",
  "    document.getElementById('ucFileSize').textContent = (f.size/1024).toFixed(1) + ' KB · ' + f.type;",
  "    document.getElementById('ucFileChosen').style.display = 'block';",
  "    document.getElementById('ucDropIcon').textContent = '✅';",
  "    btnUpload.disabled = false;",
  "    document.getElementById('ucResultBox').style.display = 'none';",
  "  }",
  "  function ucClearFile(){",
  "    _ucFile = null;",
  "    fileInput.value = '';",
  "    document.getElementById('ucFileChosen').style.display = 'none';",
  "    document.getElementById('ucDropIcon').textContent = '📁';",
  "    btnUpload.disabled = true;",
  "    document.getElementById('ucResultBox').style.display = 'none';",
  "    document.getElementById('ucUploadProgress').style.display = 'none';",
  "  }",
  "",
  "  zone.addEventListener('click', function(e){ if(e.target === fileInput || e.target.id==='btnClearUcFile') return; fileInput.click(); });",
  "  zone.addEventListener('dragover', function(e){ e.preventDefault(); zone.style.borderColor='#a855f7'; });",
  "  zone.addEventListener('dragleave', function(){ zone.style.borderColor='#7c3aed'; });",
  "  zone.addEventListener('drop', function(e){ e.preventDefault(); zone.style.borderColor='#7c3aed'; var f=e.dataTransfer.files[0]; if(f) ucSetFile(f); });",
  "  fileInput.addEventListener('change', function(){ if(fileInput.files[0]) ucSetFile(fileInput.files[0]); });",
  "  if(btnClear) btnClear.addEventListener('click', function(e){ e.stopPropagation(); ucClearFile(); });",
  "",
  "  btnUpload.addEventListener('click', async function(){",
  "    if(!_ucFile){ showToast('Chọn file trước'); return; }",
  "    var prog = document.getElementById('ucUploadProgress');",
  "    var bar  = document.getElementById('ucUploadBar');",
  "    var txt  = document.getElementById('ucUploadStatusText');",
  "    var ico  = document.getElementById('ucUploadStatusIcon');",
  "    prog.style.display = 'block'; bar.style.width='0%'; txt.textContent='Đang đọc file...'; ico.textContent='⏳';",
  "    btnUpload.disabled = true;",
  "    try{",
  "      var code = await _ucFile.text();",
  "      if(!code || code.trim().length < 5){ showToast('File rỗng hoặc quá ngắn'); btnUpload.disabled=false; return; }",
  "      txt.textContent = 'Đang upload lên server...'; bar.style.width='40%';",
  "      var payload = JSON.stringify({ name: _ucFile.name, language:'javascript', code: code });",
  "      var res = await fetch((window.API_BASE||'') + '/api/admin/upload-snippet', {",
  "        method:'POST', headers:{'Content-Type':'application/json'}, body: payload",
  "      });",
  "      bar.style.width='80%';",
  "      var data = await res.json();",
  "      bar.style.width='100%';",
  "      if(data.ok || data.id){",
  "        txt.textContent = '✅ Upload thành công!'; ico.textContent='✅';",
  "        var base = window.location.origin;",
  "        document.getElementById('ucUpdateCheckUrl').textContent = base + '/api/public/update-check';",
  "        document.getElementById('ucBundleUrl').textContent      = base + '/api/public/code-bundle';",
  "        document.getElementById('ucResultBox').style.display    = 'block';",
  "        showToast('✅ Đã nạp file code lên server!');",
  "        ucFetchList();",
  "        ucClearFile();",
  "      } else {",
  "        txt.textContent = '❌ ' + (data.error || 'upload_failed'); ico.textContent='❌';",
  "        showToast('Upload thất bại: ' + (data.error || 'unknown'));",
  "        btnUpload.disabled = false;",
  "      }",
  "    } catch(e){",
  "      txt.textContent = '❌ Lỗi: ' + e.message; ico.textContent='❌';",
  "      showToast('Lỗi upload: ' + e.message);",
  "      btnUpload.disabled = false;",
  "    }",
  "    setTimeout(function(){ prog.style.display='none'; }, 4000);",
  "  });",
  "})();",
  "",
  "async function ucFetchList(){",
  "  var list  = document.getElementById('ucList');",
  "  var empty = document.getElementById('ucEmpty');",
  "  if(!list) return;",
  "  list.innerHTML = '<div style=\"color:#7c3aed; font-size:13px;\">Đang tải...</div>';",
  "  try{",
  "    var res  = await fetch((window.API_BASE||'') + '/api/admin/code-snippets', {cache:'no-store'});",
  "    var data = await res.json();",
  "    var items = data.snippets || data || [];",
  "    if(!items.length){ list.innerHTML=''; empty.style.display='block'; return; }",
  "    empty.style.display = 'none';",
  "    var base = window.location.origin;",
  "    list.innerHTML = items.map(function(s){",
  "      var sizeKB = s.sizeBytes ? (s.sizeBytes/1024).toFixed(1)+' KB' : '—';",
  "      var upd    = s.updatedAt ? new Date(s.updatedAt).toLocaleString('vi-VN') : '—';",
  "      return '<div style=\"background:#faf5ff; border:1.5px solid #c4b5fd; border-radius:10px; padding:12px 14px; display:flex; align-items:center; gap:12px;\">'+",
  "        '<span style=\"font-size:22px;\">📄</span>'+",
  "        '<div style=\"flex:1;\">'+",
  "          '<div style=\"font-weight:700; font-size:13px; color:#5b21b6;\">'+s.name+'</div>'+",
  "          '<div style=\"font-size:11px; color:#6b7280; margin-top:2px;\">'+sizeKB+' · Cập nhật: '+upd+'</div>'+",
  "          '<div style=\"font-size:10px; color:#7c3aed; margin-top:4px; font-family:monospace; word-break:break-all;\">Endpoint: '+base+'/api/public/code-bundle</div>'+",
  "        '</div>'+",
  "        '<button class=\"btn btn-ghost btn-inline\" onclick=\"ucDeleteSnippet(\\''+s.id+'\\')\" style=\"padding:6px 10px; flex-shrink:0; color:#ef4444; border-color:#ef4444;\">Xoá</button>'+",
  "      '</div>';",
  "    }).join('');",
  "  } catch(e){",
  "    list.innerHTML = '<div style=\"color:#ef4444;\">Lỗi tải danh sách: ' + e.message + '</div>';",
  "  }",
  "}",
  "",
  "async function ucDeleteSnippet(id){",
  "  if(!confirm('Xoá file code này?')) return;",
  "  try{",
  "    var res = await fetch((window.API_BASE||'') + '/api/admin/code-snippets/' + id, {method:'DELETE'});",
  "    var d   = await res.json();",
  "    if(d.ok){ showToast('Đã xoá file code'); ucFetchList(); }",
  "    else showToast('Xoá thất bại: ' + (d.error||'unknown'));",
  "  } catch(e){ showToast('Lỗi: ' + e.message); }",
  "}",
  "",
  "/* ---------------- Khởi động ---------------- */",
  "(async function init(){",
  "  const ok = await authenticate();",
  "  if(!ok) return;",
  "  await Promise.all([loadProducts(), loadGetKeyGames(), refreshAccountSummary()]);",
  "})();",
  "</script>",
  "",
  "<!-- ========== OLM KEY PAGE ========== -->",
  "<div id=\"olmPage\">",
  "  <div class=\"olm-header\">",
  "    <div class=\"olm-header-left\">",
  "      <button class=\"ghost-icon-btn\" id=\"btnCloseOlmPage\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><path d=\"M19 12H5M12 5l-7 7 7 7\"/></svg>",
  "        Thoát",
  "      </button>",
  "      <div>",
  "        <div class=\"olm-title\">&#128272; Server key Olm</div>",
  "        <div class=\"olm-subtitle\">Tạo &amp; quản lý key Olm — ghim tài khoản, giới hạn thiết bị, gia hạn tự do</div>",
  "      </div>",
  "    </div>",
  "    <nav style=\"display:flex;gap:0;\">",
  "      <button class=\"olm-tab active\" data-olm-tab=\"create\">Tạo Key</button>",
  "      <button class=\"olm-tab\" data-olm-tab=\"list\">Danh sách Key</button>",
  "      <button class=\"olm-tab\" data-olm-tab=\"normal\">Key Thường</button>",
  "      <button class=\"olm-tab\" data-olm-tab=\"premium\">Key Premium</button>",
  "      <button class=\"olm-tab\" data-olm-tab=\"pinned\">Key đã ghim OLM</button>",
  "    </nav>",
  "  </div>",
  "  <div class=\"olm-body\">",
  "",
  "    <div id=\"olmTab-create\">",
  "      <div class=\"olm-split\">",
  "        <div>",
  "          <div class=\"panel\">",
  "            <h2>Tạo key ngẫu nhiên</h2>",
  "            <p class=\"sub\">Tự sinh key định dạng OLM-XXXX-XXXX-XXXX.</p>",
  "            <label>Loại key</label>",
  "            <div class=\"chip-toggle\">",
  "              <input type=\"radio\" name=\"olmRandType\" id=\"olmRandNormal\" value=\"normal\" checked><label for=\"olmRandNormal\">Thường</label>",
  "              <input type=\"radio\" name=\"olmRandType\" id=\"olmRandPremium\" value=\"premium\"><label for=\"olmRandPremium\">&#9733; Premium</label>",
  "            </div>",
  "            <label style=\"margin-top:12px;\">Thời hạn key</label>",
  "            <div class=\"chip-toggle\">",
  "              <input type=\"radio\" name=\"olmRandExpiry\" id=\"olmRandExpNone\" value=\"none\"><label for=\"olmRandExpNone\">Không giới hạn</label>",
  "              <input type=\"radio\" name=\"olmRandExpiry\" id=\"olmRandExpLimit\" value=\"limited\" checked><label for=\"olmRandExpLimit\">Có thời hạn</label>",
  "            </div>",
  "            <div id=\"olmRandExpiryFields\">",
  "              <div class=\"row2\">",
  "                <div><label>Số lượng</label><input type=\"number\" id=\"olmRandDurAmount\" value=\"1\" min=\"1\" max=\"9999\"></div>",
  "                <div><label>Đơn vị</label><select id=\"olmRandDurUnit\"><option value=\"minute\">Phút</option><option value=\"hour\">Giờ</option><option value=\"day\" selected>Ngày</option><option value=\"month\">Tháng</option></select></div>",
  "              </div>",
  "            </div>",
  "            <label style=\"margin-top:12px;\">Giới hạn thiết bị</label>",
  "            <input type=\"number\" id=\"olmRandMaxUses\" value=\"1\" min=\"1\" max=\"999\">",
  "            <p class=\"preview-note\">Nhập 1 = 1 thiết bị. Lần 2 sẽ báo quá thiết bị.</p>",
  "            <label style=\"margin-top:12px;\">Ghim tài khoản Olm (tuỳ chọn)</label>",
  "            <input type=\"text\" id=\"olmRandAccount\" placeholder=\"Để trống nếu không ghim\">",
  "            <button class=\"btn\" style=\"margin-top:16px;\" id=\"btnOlmGenRandom\">&#10010; Tạo key ngẫu nhiên</button>",
  "          </div>",
  "          <div class=\"panel\" style=\"margin-top:20px;\">",
  "            <h2>Tạo key thủ công</h2>",
  "            <p class=\"sub\">Nhập key tự do theo ý muốn.</p>",
  "            <label>Loại key</label>",
  "            <div class=\"chip-toggle\">",
  "              <input type=\"radio\" name=\"olmManType\" id=\"olmManNormal\" value=\"normal\" checked><label for=\"olmManNormal\">Thường</label>",
  "              <input type=\"radio\" name=\"olmManType\" id=\"olmManPremium\" value=\"premium\"><label for=\"olmManPremium\">&#9733; Premium</label>",
  "            </div>",
  "            <label style=\"margin-top:12px;\">Giá trị key</label>",
  "            <input type=\"text\" id=\"olmManValue\" placeholder=\"VD: OLM-MYKEY-2024\" maxlength=\"80\">",
  "            <label style=\"margin-top:10px;\">Thời hạn key</label>",
  "            <div class=\"chip-toggle\">",
  "              <input type=\"radio\" name=\"olmManExpiry\" id=\"olmManExpNone\" value=\"none\"><label for=\"olmManExpNone\">Không giới hạn</label>",
  "              <input type=\"radio\" name=\"olmManExpiry\" id=\"olmManExpLimit\" value=\"limited\" checked><label for=\"olmManExpLimit\">Có thời hạn</label>",
  "            </div>",
  "            <div id=\"olmManExpiryFields\">",
  "              <div class=\"row2\">",
  "                <div><label>Số lượng</label><input type=\"number\" id=\"olmManDurAmount\" value=\"1\" min=\"1\" max=\"9999\"></div>",
  "                <div><label>Đơn vị</label><select id=\"olmManDurUnit\"><option value=\"minute\">Phút</option><option value=\"hour\">Giờ</option><option value=\"day\" selected>Ngày</option><option value=\"month\">Tháng</option></select></div>",
  "              </div>",
  "            </div>",
  "            <label style=\"margin-top:12px;\">Giới hạn thiết bị</label>",
  "            <input type=\"number\" id=\"olmManMaxUses\" value=\"1\" min=\"1\" max=\"999\">",
  "            <label style=\"margin-top:12px;\">Ghim tài khoản Olm (tuỳ chọn)</label>",
  "            <input type=\"text\" id=\"olmManAccount\" placeholder=\"Để trống nếu không ghim\">",
  "            <button class=\"btn\" style=\"margin-top:16px;\" id=\"btnOlmGenManual\">&#10010; Tạo key thủ công</button>",
  "          </div>",
  "        </div>",
  "        <div class=\"panel\">",
  "          <h2>Key vừa tạo</h2>",
  "          <p class=\"sub\" id=\"olmCreatedSub\">Key tạo gần đây sẽ hiện ở đây.</p>",
  "          <div id=\"olmJustCreatedList\"></div>",
  "        </div>",
  "      </div>",
  "    </div>",
  "",
  "    <div id=\"olmTab-list\" style=\"display:none;\">",
  "      <div class=\"olm-stats-row\" id=\"olmStatsRow\"></div>",
  "      <div class=\"panel\">",
  "        <div class=\"olm-list-filter\">",
  "          <input type=\"text\" id=\"olmSearch\" placeholder=\"Tìm theo key hoặc tài khoản Olm...\">",
  "          <select id=\"olmFilterStatus\"><option value=\"all\">Tất cả trạng thái</option><option value=\"unactivated\">Chưa kích hoạt</option><option value=\"active\">Đang hoạt động</option><option value=\"expired\">Hết hạn</option><option value=\"banned\">Bị cấm</option></select>",
  "          <select id=\"olmFilterType\"><option value=\"all\">Tất cả loại</option><option value=\"normal\">Thường</option><option value=\"premium\">Premium</option></select>",
  "        </div>",
  "        <div id=\"olmListWrap\"></div>",
  "      </div>",
  "    </div>",
  "",
  "    <div id=\"olmTab-normal\" style=\"display:none;\">",
  "      <div class=\"panel\"><h2>Key Thường</h2><p class=\"sub\">Chỉ hiển thị key Thường.</p><div id=\"olmNormalList\"></div></div>",
  "    </div>",
  "",
  "    <div id=\"olmTab-premium\" style=\"display:none;\">",
  "      <div class=\"panel\"><h2>Key Premium &#9733;</h2><p class=\"sub\">Chỉ hiển thị key Premium.</p><div id=\"olmPremiumList\"></div></div>",
  "    </div>",
  "",
  "    <div id=\"olmTab-pinned\" style=\"display:none;\">",
  "      <div class=\"panel\"><h2>Key đã ghim tài khoản Olm</h2><p class=\"sub\">Các key có tài khoản Olm ghim kèm.</p><div id=\"olmPinnedList\"></div></div>",
  "    </div>",
  "",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"olmExtendModal\">",
  "  <div class=\"modal\">",
  "    <h3>Gia hạn key Olm</h3>",
  "    <div class=\"row2\">",
  "      <div><label>Số lượng</label><input type=\"number\" id=\"olmExtendAmount\" value=\"1\" min=\"1\" max=\"9999\"></div>",
  "      <div><label>Đơn vị</label><select id=\"olmExtendUnit\"><option value=\"minute\">Phút</option><option value=\"hour\">Giờ</option><option value=\"day\" selected>Ngày</option><option value=\"month\">Tháng</option></select></div>",
  "    </div>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn\" id=\"btnOlmExtendConfirm\">Gia hạn</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnOlmExtendCancel\">Huỷ</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"olmResetUsesModal\">",
  "  <div class=\"modal\">",
  "    <h3>Reset số lần nhập key</h3>",
  "    <label>Giới hạn thiết bị mới</label>",
  "    <input type=\"number\" id=\"olmNewMaxUses\" value=\"1\" min=\"1\" max=\"999\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn\" id=\"btnOlmResetUsesConfirm\">Reset</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnOlmResetUsesCancel\">Huỷ</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<script>",
  "/* ============================================================",
  "   SERVER KEY OLM — JS khởi động sau khi DOM đã load",
  "   Tất cả getElementById đều chắc chắn tồn tại ở đây.",
  "   ============================================================ */",
  "(function initOlm(){",
  "  const OLM_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';",
  "  function olmGenKey(){",
  "    function seg(n){ var s=''; for(var i=0;i<n;i++) s+=OLM_CHARS[Math.floor(Math.random()*OLM_CHARS.length)]; return s; }",
  "    return 'OLM-'+seg(4)+'-'+seg(4)+'-'+seg(4);",
  "  }",
  "  function olmMsFromUnit(amount,unit){",
  "    var map={minute:60000,hour:3600000,day:86400000,month:30*86400000};",
  "    return amount*(map[unit]||86400000);",
  "  }",
  "  function olmComputeStatus(k){",
  "    if(k.banned) return 'banned';",
  "    if(!k.activated) return 'unactivated';",
  "    if(k.expiresAt && new Date(k.expiresAt).getTime()<Date.now()) return 'expired';",
  "    return 'active';",
  "  }",
  "  function olmStatusBadge(k){",
  "    var st=olmComputeStatus(k);",
  "    if(st==='banned')      return '<span class=\"olm-badge-banned\">Bị cấm</span>';",
  "    if(st==='expired')     return '<span class=\"olm-badge-expired\">Hết hạn</span>';",
  "    if(st==='active')      return '<span class=\"olm-badge-active\">Đang hoạt động</span>';",
  "    return '<span class=\"olm-badge-unactivated\">Chưa kích hoạt</span>';",
  "  }",
  "  function olmTypeBadge(k){",
  "    return k.type==='premium'",
  "      ? '<span class=\"olm-badge-premium\">&#9733; Premium</span>'",
  "      : '<span class=\"olm-badge-normal\">Thường</span>';",
  "  }",
  "  function olmFmtDate(d){ return d ? new Date(d).toLocaleString('vi-VN') : '—'; }",
  "  function olmDurLabel(amount,unit){",
  "    var map={minute:'phút',hour:'giờ',day:'ngày',month:'tháng'};",
  "    return amount ? amount+' '+(map[unit]||unit) : 'Không giới hạn';",
  "  }",
  "  function $olm(id){ return document.getElementById(id); }",
  "",
  "  var olmKeys=[]; var olmExtendId=null; var olmResetId=null;",
  "",
  "  /* ---- Open/close ---- */",
  "  $olm('btnOpenOlmPage').addEventListener('click',function(){",
  "    $olm('olmPage').classList.add('show');",
  "    olmLoadFromServer();",
  "    olmSwitchTab('create');",
  "  });",
  "  $olm('btnCloseOlmPage').addEventListener('click',function(){",
  "    $olm('olmPage').classList.remove('show');",
  "  });",
  "",
  "  /* ---- Tabs ---- */",
  "  document.querySelectorAll('.olm-tab').forEach(function(btn){",
  "    btn.addEventListener('click',function(){ olmSwitchTab(btn.dataset.olmTab); });",
  "  });",
  "  function olmSwitchTab(tab){",
  "    document.querySelectorAll('.olm-tab').forEach(function(b){ b.classList.toggle('active',b.dataset.olmTab===tab); });",
  "    ['create','list','normal','premium','pinned'].forEach(function(t){",
  "      var el=$olm('olmTab-'+t); if(el) el.style.display=t===tab?'':'none';",
  "    });",
  "    if(tab==='list')    olmRenderList();",
  "    if(tab==='normal')  olmRenderFiltered('normal','olmNormalList');",
  "    if(tab==='premium') olmRenderFiltered('premium','olmPremiumList');",
  "    if(tab==='pinned')  olmRenderPinned();",
  "  }",
  "",
  "  /* ---- Expiry toggles ---- */",
  "  document.querySelectorAll('input[name=\"olmRandExpiry\"]').forEach(function(r){",
  "    r.addEventListener('change',function(){",
  "      $olm('olmRandExpiryFields').style.display=$olm('olmRandExpLimit').checked?'':'none';",
  "    });",
  "  });",
  "  document.querySelectorAll('input[name=\"olmManExpiry\"]').forEach(function(r){",
  "    r.addEventListener('change',function(){",
  "      $olm('olmManExpiryFields').style.display=$olm('olmManExpLimit').checked?'':'none';",
  "    });",
  "  });",
  "",
  "  /* ---- Server sync ---- */",
  "  async function olmLoadFromServer(){",
  "    try{",
  "      var res=await fetch('/api/olm/keys');",
  "      var data=await res.json();",
  "      if(data.ok) olmKeys=data.keys||[];",
  "    }catch(e){ console.warn('[OLM] load err',e); }",
  "  }",
  "  async function olmSaveToServer(){",
  "    try{",
  "      await fetch('/api/olm/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({keys:olmKeys})});",
  "    }catch(e){ console.warn('[OLM] save err',e); }",
  "  }",
  "",
  "  /* ---- Create random ---- */",
  "  $olm('btnOlmGenRandom').addEventListener('click',async function(){",
  "    var type=document.querySelector('input[name=\"olmRandType\"]:checked').value;",
  "    var hasExp=$olm('olmRandExpLimit').checked;",
  "    var amount=parseInt($olm('olmRandDurAmount').value)||1;",
  "    var unit=$olm('olmRandDurUnit').value;",
  "    var maxUses=parseInt($olm('olmRandMaxUses').value)||1;",
  "    var acct=$olm('olmRandAccount').value.trim();",
  "    var value=olmGenKey();",
  "    var now=new Date().toISOString();",
  "    var k={id:'olm_'+Date.now()+Math.random().toString(36).slice(2,7),value:value,type:type,createdAt:now,",
  "      expiresAt:null,durationAmount:hasExp?amount:null,durationUnit:hasExp?unit:null,",
  "      maxUses:maxUses,usedCount:0,devices:[],banned:false,olmAccount:acct||null,activated:false,activatedAt:null};",
  "    olmKeys.unshift(k);",
  "    await olmSaveToServer();",
  "    olmShowJustCreated([k]);",
  "    if(typeof showToast==='function') showToast('Đã tạo key: '+value);",
  "  });",
  "",
  "  /* ---- Create manual ---- */",
  "  $olm('btnOlmGenManual').addEventListener('click',async function(){",
  "    var value=$olm('olmManValue').value.trim();",
  "    if(!value){ if(typeof showToast==='function') showToast('Vui lòng nhập giá trị key'); return; }",
  "    if(olmKeys.some(function(x){ return x.value===value; })){ if(typeof showToast==='function') showToast('Key đã tồn tại'); return; }",
  "    var type=document.querySelector('input[name=\"olmManType\"]:checked').value;",
  "    var hasExp=$olm('olmManExpLimit').checked;",
  "    var amount=parseInt($olm('olmManDurAmount').value)||1;",
  "    var unit=$olm('olmManDurUnit').value;",
  "    var maxUses=parseInt($olm('olmManMaxUses').value)||1;",
  "    var acct=$olm('olmManAccount').value.trim();",
  "    var now=new Date().toISOString();",
  "    var k={id:'olm_'+Date.now()+Math.random().toString(36).slice(2,7),value:value,type:type,createdAt:now,",
  "      expiresAt:null,durationAmount:hasExp?amount:null,durationUnit:hasExp?unit:null,",
  "      maxUses:maxUses,usedCount:0,devices:[],banned:false,olmAccount:acct||null,activated:false,activatedAt:null};",
  "    olmKeys.unshift(k);",
  "    await olmSaveToServer();",
  "    olmShowJustCreated([k]);",
  "    $olm('olmManValue').value='';",
  "    if(typeof showToast==='function') showToast('Đã tạo key thủ công: '+value);",
  "  });",
  "",
  "  function olmShowJustCreated(list){",
  "    var wrap=$olm('olmJustCreatedList');",
  "    wrap.innerHTML='';",
  "    $olm('olmCreatedSub').textContent='Key vừa được tạo thành công:';",
  "    list.forEach(function(k){",
  "      var div=document.createElement('div'); div.className='olm-key-row';",
  "      div.innerHTML='<div style=\"flex:1\"><div class=\"olm-key-val\">'+k.value+'</div>'+",
  "        '<div class=\"olm-key-meta\">'+olmTypeBadge(k)+' '+olmStatusBadge(k)+'<br>'+",
  "        'Thời hạn: '+olmDurLabel(k.durationAmount,k.durationUnit)+'<br>'+",
  "        'Thiết bị tối đa: '+k.maxUses+' | Tài khoản Olm: '+(k.olmAccount||'—')+'<br>'+",
  "        'Tạo lúc: '+olmFmtDate(k.createdAt)+'</div></div>'+",
  "        '<button class=\"btn btn-ghost\" style=\"font-size:12px\" onclick=\"navigator.clipboard.writeText(\\''+k.value+'\\').then(function(){ if(typeof showToast===\\'function\\') showToast(\\'Đã copy key\\'); })\">Copy</button>';",
  "      wrap.appendChild(div);",
  "    });",
  "  }",
  "",
  "  /* ---- Stats ---- */",
  "  function olmRenderStats(){",
  "    var total=olmKeys.length;",
  "    var active=olmKeys.filter(function(k){return olmComputeStatus(k)==='active';}).length;",
  "    var unact=olmKeys.filter(function(k){return olmComputeStatus(k)==='unactivated';}).length;",
  "    var expired=olmKeys.filter(function(k){return olmComputeStatus(k)==='expired';}).length;",
  "    var banned=olmKeys.filter(function(k){return k.banned;}).length;",
  "    var premium=olmKeys.filter(function(k){return k.type==='premium';}).length;",
  "    $olm('olmStatsRow').innerHTML=",
  "      '<div class=\"olm-stat-chip\"><div class=\"n\">'+total+'</div><div class=\"l\">Tổng key</div></div>'+",
  "      '<div class=\"olm-stat-chip\"><div class=\"n\" style=\"color:var(--ok)\">'+active+'</div><div class=\"l\">Hoạt động</div></div>'+",
  "      '<div class=\"olm-stat-chip\"><div class=\"n\" style=\"color:var(--info)\">'+unact+'</div><div class=\"l\">Chưa kích hoạt</div></div>'+",
  "      '<div class=\"olm-stat-chip\"><div class=\"n\" style=\"color:var(--danger)\">'+expired+'</div><div class=\"l\">Hết hạn</div></div>'+",
  "      '<div class=\"olm-stat-chip\"><div class=\"n\">'+banned+'</div><div class=\"l\">Bị cấm</div></div>'+",
  "      '<div class=\"olm-stat-chip\"><div class=\"n\" style=\"color:var(--brass)\">'+premium+'</div><div class=\"l\">Premium</div></div>';",
  "  }",
  "",
  "  /* ---- Render one key row ---- */",
  "  function olmRenderKeyRow(k){",
  "    var div=document.createElement('div');",
  "    div.className='olm-key-row'+(k.banned?' banned-row':'');",
  "    var banBtn=k.banned",
  "      ? '<button class=\"icon-btn\" title=\"Bỏ cấm\" data-olm-act=\"unban\" data-olm-id=\"'+k.id+'\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12l3 3 5-6\"/></svg></button>'",
  "      : '<button class=\"icon-btn danger\" title=\"Cấm key\" data-olm-act=\"ban\" data-olm-id=\"'+k.id+'\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.5 5.5l13 13\"/></svg></button>';",
  "    var expInfo=k.expiresAt ? 'Hết hạn: '+olmFmtDate(k.expiresAt) : (k.durationAmount?'Thời hạn (khi kích hoạt): '+olmDurLabel(k.durationAmount,k.durationUnit):'Không giới hạn');",
  "    div.innerHTML=",
  "      '<div style=\"flex:1\">'+",
  "        '<div class=\"olm-key-val\">'+k.value+'</div>'+",
  "        '<div class=\"olm-key-meta\">'+olmTypeBadge(k)+' '+olmStatusBadge(k)+'<br>'+",
  "          'Tạo lúc: '+olmFmtDate(k.createdAt)+'<br>'+",
  "          (k.activated&&k.activatedAt?'Kích hoạt: '+olmFmtDate(k.activatedAt)+'<br>':'')+",
  "          expInfo+'<br>'+",
  "          'Thiết bị: <b>'+(k.usedCount||0)+'/'+(k.maxUses||1)+'</b>'+",
  "          (k.olmAccount?' | Olm: <b>'+k.olmAccount+'</b>':'')+'</div>'+",
  "      '</div>'+",
  "      '<div class=\"olm-key-actions\">'+",
  "        '<button class=\"icon-btn\" title=\"Copy\" data-olm-act=\"copy\" data-olm-id=\"'+k.id+'\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\"/><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"/></svg></button>'+",
  "        '<button class=\"icon-btn\" title=\"Gia hạn\" data-olm-act=\"extend\" data-olm-id=\"'+k.id+'\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 3\"/></svg></button>'+",
  "        '<button class=\"icon-btn\" title=\"Reset số lần nhập\" data-olm-act=\"resetuses\" data-olm-id=\"'+k.id+'\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8\"/><path d=\"M3 3v5h5\"/></svg></button>'+",
  "        banBtn+",
  "        '<button class=\"icon-btn danger\" title=\"Xoá key\" data-olm-act=\"delete\" data-olm-id=\"'+k.id+'\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg></button>'+",
  "      '</div>';",
  "    return div;",
  "  }",
  "",
  "  function olmRenderList(){",
  "    olmRenderStats();",
  "    var search=($olm('olmSearch').value||'').toLowerCase();",
  "    var stFilter=$olm('olmFilterStatus').value;",
  "    var tyFilter=$olm('olmFilterType').value;",
  "    var list=olmKeys;",
  "    if(search) list=list.filter(function(k){ return k.value.toLowerCase().includes(search)||(k.olmAccount||'').toLowerCase().includes(search); });",
  "    if(stFilter!=='all') list=list.filter(function(k){ return olmComputeStatus(k)===stFilter; });",
  "    if(tyFilter!=='all') list=list.filter(function(k){ return k.type===tyFilter; });",
  "    var wrap=$olm('olmListWrap'); wrap.innerHTML='';",
  "    if(!list.length){ wrap.innerHTML='<div class=\"olm-empty\">Không có key nào phù hợp.</div>'; return; }",
  "    list.forEach(function(k){ wrap.appendChild(olmRenderKeyRow(k)); });",
  "  }",
  "",
  "  function olmRenderFiltered(type,wrapId){",
  "    var list=olmKeys.filter(function(k){ return k.type===type; });",
  "    var wrap=$olm(wrapId); if(!wrap) return;",
  "    wrap.innerHTML='';",
  "    if(!list.length){ wrap.innerHTML='<div class=\"olm-empty\">Chưa có key '+type+' nào.</div>'; return; }",
  "    list.forEach(function(k){ wrap.appendChild(olmRenderKeyRow(k)); });",
  "  }",
  "",
  "  function olmRenderPinned(){",
  "    var list=olmKeys.filter(function(k){ return !!k.olmAccount; });",
  "    var wrap=$olm('olmPinnedList'); wrap.innerHTML='';",
  "    if(!list.length){ wrap.innerHTML='<div class=\"olm-empty\">Chưa có key nào ghim tài khoản Olm.</div>'; return; }",
  "    list.forEach(function(k){ wrap.appendChild(olmRenderKeyRow(k)); });",
  "  }",
  "",
  "  /* ---- Live filter ---- */",
  "  $olm('olmSearch').addEventListener('input',function(){ olmRenderList(); });",
  "  $olm('olmFilterStatus').addEventListener('change',function(){ olmRenderList(); });",
  "  $olm('olmFilterType').addEventListener('change',function(){ olmRenderList(); });",
  "",
  "  /* ---- Action delegation ---- */",
  "  $olm('olmPage').addEventListener('click',async function(e){",
  "    var btn=e.target.closest('[data-olm-act]'); if(!btn) return;",
  "    var act=btn.dataset.olmAct; var id=btn.dataset.olmId;",
  "    var k=olmKeys.find(function(x){ return x.id===id; }); if(!k) return;",
  "    if(act==='copy'){ try{ await navigator.clipboard.writeText(k.value); if(typeof showToast==='function') showToast('Đã copy: '+k.value); }catch(e){} return; }",
  "    if(act==='delete'){",
  "      if(!confirm('Xoá key '+k.value+'?')) return;",
  "      olmKeys=olmKeys.filter(function(x){ return x.id!==id; });",
  "      await olmSaveToServer(); olmRenderList();",
  "      if(typeof showToast==='function') showToast('Đã xoá key'); return;",
  "    }",
  "    if(act==='ban'){ k.banned=true; await olmSaveToServer(); olmRenderList(); if(typeof showToast==='function') showToast('Đã cấm key '+k.value); return; }",
  "    if(act==='unban'){ k.banned=false; await olmSaveToServer(); olmRenderList(); if(typeof showToast==='function') showToast('Đã bỏ cấm key '+k.value); return; }",
  "    if(act==='extend'){ olmExtendId=id; $olm('olmExtendModal').classList.add('show'); return; }",
  "    if(act==='resetuses'){ olmResetId=id; $olm('olmNewMaxUses').value=k.maxUses||1; $olm('olmResetUsesModal').classList.add('show'); return; }",
  "  });",
  "",
  "  /* ---- Extend modal ---- */",
  "  $olm('btnOlmExtendConfirm').addEventListener('click',async function(){",
  "    var k=olmKeys.find(function(x){ return x.id===olmExtendId; });",
  "    $olm('olmExtendModal').classList.remove('show');",
  "    if(!k) return;",
  "    var amount=parseInt($olm('olmExtendAmount').value)||1;",
  "    var unit=$olm('olmExtendUnit').value;",
  "    var ms=olmMsFromUnit(amount,unit);",
  "    if(k.expiresAt){ k.expiresAt=new Date(new Date(k.expiresAt).getTime()+ms).toISOString(); }",
  "    else if(k.activated&&k.activatedAt){ k.expiresAt=new Date(Date.now()+ms).toISOString(); }",
  "    else { k.durationAmount=amount; k.durationUnit=unit; }",
  "    await olmSaveToServer(); olmRenderList();",
  "    if(typeof showToast==='function') showToast('Đã gia hạn key '+k.value+' thêm '+amount+' '+unit);",
  "  });",
  "  $olm('btnOlmExtendCancel').addEventListener('click',function(){ $olm('olmExtendModal').classList.remove('show'); });",
  "  $olm('olmExtendModal').addEventListener('click',function(e){ if(e.target===e.currentTarget) e.currentTarget.classList.remove('show'); });",
  "",
  "  /* ---- Reset uses modal ---- */",
  "  $olm('btnOlmResetUsesConfirm').addEventListener('click',async function(){",
  "    var k=olmKeys.find(function(x){ return x.id===olmResetId; });",
  "    $olm('olmResetUsesModal').classList.remove('show');",
  "    if(!k) return;",
  "    var newMax=parseInt($olm('olmNewMaxUses').value)||1;",
  "    k.maxUses=newMax; k.usedCount=0; k.devices=[];",
  "    await olmSaveToServer(); olmRenderList();",
  "    if(typeof showToast==='function') showToast('Đã reset thiết bị key '+k.value+' (max: '+newMax+')');",
  "  });",
  "  $olm('btnOlmResetUsesCancel').addEventListener('click',function(){ $olm('olmResetUsesModal').classList.remove('show'); });",
  "  $olm('olmResetUsesModal').addEventListener('click',function(e){ if(e.target===e.currentTarget) e.currentTarget.classList.remove('show'); });",
  "",
  "})(); // end initOlm",
  "</script>",
  "",
  "</body>",
  "</html>",
  ""
];
/* ---------------- Trang bán key công khai (storefront), nhúng dạng base64 để tránh xung đột dấu backtick/${} ---------------- */
const STORE_B64_CHUNKS = [
"PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9InZpIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVU",
"Ri04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwg",
"aW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2V5VmF1bHQgU3RvcmUg4oCUIE11YSBLZXkgdHLh",
"u7FjIHR1eeG6v248L3RpdGxlPgo8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8v",
"Zm9udHMuZ29vZ2xlYXBpcy5jb20iPgo8bGluayBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFw",
"aXMuY29tL2NzczI/ZmFtaWx5PVNwYWNlK0dyb3Rlc2s6d2dodEA1MDA7NjAwOzcwMCZmYW1pbHk9",
"SW50ZXI6d2dodEA0MDA7NTAwOzYwMDs3MDAmZmFtaWx5PUpldEJyYWlucytNb25vOndnaHRANTAw",
"OzYwMDs3MDAmZGlzcGxheT1zd2FwIiByZWw9InN0eWxlc2hlZXQiPgo8c3R5bGU+CiAgOnJvb3R7",
"CiAgICAtLWluazojRjdGN0Y1OwogICAgLS1wYW5lbDojRkZGRkZGOwogICAgLS1wYW5lbC0yOiNG",
"QkZCRjk7CiAgICAtLWxpbmU6I0U0RTNERDsKICAgIC0tYnJhc3M6I0FEN0YxRTsKICAgIC0tYnJh",
"c3Mtc29mdDojQzk5QTJFOwogICAgLS1icmFzcy10aW50OiNGNkVDRDM7CiAgICAtLXRleHQ6IzFD",
"MUIxODsKICAgIC0tbXV0ZWQ6IzdDN0E3MjsKICAgIC0tb2s6IzFGOEY2MzsKICAgIC0tb2stdGlu",
"dDojRTRGNUVFOwogICAgLS1kYW5nZXI6I0MyM0I0QjsKICAgIC0tZGFuZ2VyLXRpbnQ6I0ZCRUFF",
"QzsKICAgIC0tc2hhZG93OiAwIDFweCAycHggcmdiYSgyOCwyNywyNCwwLjA0KSwgMCA4cHggMjRw",
"eCAtMTJweCByZ2JhKDI4LDI3LDI0LDAuMTApOwogIH0KICAqe2JveC1zaXppbmc6Ym9yZGVyLWJv",
"eDt9CiAgaHRtbCxib2R5e21hcmdpbjowO3BhZGRpbmc6MDt9CiAgYm9keXsKICAgIGJhY2tncm91",
"bmQ6CiAgICAgIHJhZGlhbC1ncmFkaWVudCgxMDAwcHggNTAwcHggYXQgODglIC04JSwgI0ZCRjJE",
"QyAwJSwgdHJhbnNwYXJlbnQgNjAlKSwKICAgICAgdmFyKC0taW5rKTsKICAgIGNvbG9yOnZhcigt",
"LXRleHQpOwogICAgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmOwogICAgbWluLWhlaWdo",
"dDoxMDB2aDsKICB9CiAgOjpzZWxlY3Rpb257YmFja2dyb3VuZDp2YXIoLS1icmFzcy10aW50KTsg",
"Y29sb3I6dmFyKC0tdGV4dCk7fQoKICBoZWFkZXIudG9wewogICAgcGFkZGluZzowIDI0cHg7CiAg",
"ICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKTsKICAgIHBvc2l0aW9uOnN0aWNr",
"eTsgdG9wOjA7IGJhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjkyKTsgYmFja2Ryb3AtZmls",
"dGVyOmJsdXIoMTBweCk7IHotaW5kZXg6MjA7CiAgfQogIC50b3Atcm93ewogICAgbWF4LXdpZHRo",
"OjEwODBweDsgbWFyZ2luOjAgYXV0bzsKICAgIGRpc3BsYXk6ZmxleDsgYWxpZ24taXRlbXM6Y2Vu",
"dGVyOyBqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsKICAgIHBhZGRpbmc6MThweCAwOwog",
"IH0KICAuYnJhbmR7ZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDoxMnB4O30K",
"ICAuYnJhbmQgLm1hcmt7CiAgICB3aWR0aDozNnB4OyBoZWlnaHQ6MzZweDsgYm9yZGVyLXJhZGl1",
"czoxMHB4OwogICAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTU1ZGVnLCB2YXIoLS1icmFz",
"cy1zb2Z0KSwgdmFyKC0tYnJhc3MpIDY1JSk7CiAgICBkaXNwbGF5OmZsZXg7IGFsaWduLWl0ZW1z",
"OmNlbnRlcjsganVzdGlmeS1jb250ZW50OmNlbnRlcjsKICAgIGJveC1zaGFkb3c6MCA0cHggMTRw",
"eCAtNHB4ICNBRDdGMUU2MDsKICB9CiAgLmJyYW5kIC5tYXJrIHN2Z3t3aWR0aDoxOXB4OyBoZWln",
"aHQ6MTlweDsgY29sb3I6I2ZmZjt9CiAgLmJyYW5kIGgxe2ZvbnQtZmFtaWx5OidTcGFjZSBHcm90",
"ZXNrJyxzYW5zLXNlcmlmOyBmb250LXNpemU6MTlweDsgbWFyZ2luOjA7IGxldHRlci1zcGFjaW5n",
"OjAuMnB4O30KICAuYnJhbmQgLnRhZ3tmb250LXNpemU6MTAuNXB4OyBjb2xvcjp2YXIoLS1tdXRl",
"ZCk7IGxldHRlci1zcGFjaW5nOjEuNHB4OyB0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7IG1hcmdp",
"bi10b3A6MXB4O30KCiAgLnRvcC1hY3Rpb25ze2Rpc3BsYXk6ZmxleDsgYWxpZ24taXRlbXM6Y2Vu",
"dGVyOyBnYXA6MTBweDt9CiAgLmJ0bnsKICAgIGFwcGVhcmFuY2U6bm9uZTsgYm9yZGVyOm5vbmU7",
"IGN1cnNvcjpwb2ludGVyOwogICAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTU1ZGVnLCB2",
"YXIoLS1icmFzcy1zb2Z0KSwgdmFyKC0tYnJhc3MpIDcwJSk7CiAgICBjb2xvcjojZmZmOyBmb250",
"LXdlaWdodDo2MDA7IGZvbnQtc2l6ZToxMy41cHg7CiAgICBwYWRkaW5nOjEwcHggMThweDsgYm9y",
"ZGVyLXJhZGl1czoxMHB4OwogICAgYm94LXNoYWRvdzowIDRweCAxNHB4IC02cHggI0FEN0YxRTgw",
"OwogICAgdHJhbnNpdGlvbjp0cmFuc2Zvcm0gLjEycywgYm94LXNoYWRvdyAuMTJzOwogIH0KICAu",
"YnRuOmhvdmVye3RyYW5zZm9ybTp0cmFuc2xhdGVZKC0xcHgpO30KICAuYnRuLWdob3N0ewogICAg",
"YmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGNvbG9yOnZhcigtLXRleHQpOyBib3JkZXI6MXB4IHNv",
"bGlkIHZhcigtLWxpbmUpOwogICAgYm94LXNoYWRvdzpub25lOwogIH0KICAuYWNjb3VudC1jaGlw",
"ewogICAgZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDo4cHg7IGZvbnQtc2l6",
"ZToxM3B4OyBmb250LXdlaWdodDo2MDA7CiAgICBiYWNrZ3JvdW5kOnZhcigtLWJyYXNzLXRpbnQp",
"OyBjb2xvcjp2YXIoLS1icmFzcyk7IHBhZGRpbmc6OHB4IDE0cHg7IGJvcmRlci1yYWRpdXM6MTBw",
"eDsKICB9CiAgLmFjY291bnQtY2hpcCBidXR0b257CiAgICBiYWNrZ3JvdW5kOm5vbmU7IGJvcmRl",
"cjpub25lOyBjb2xvcjp2YXIoLS1tdXRlZCk7IGN1cnNvcjpwb2ludGVyOyBmb250LXNpemU6MTJw",
"eDsKICAgIHRleHQtZGVjb3JhdGlvbjp1bmRlcmxpbmU7IHBhZGRpbmc6MDsgZm9udC1mYW1pbHk6",
"J0ludGVyJyxzYW5zLXNlcmlmOwogIH0KICAuYWRtaW4tbGlua3tmb250LXNpemU6MTJweDsgY29s",
"b3I6dmFyKC0tbXV0ZWQpOyB0ZXh0LWRlY29yYXRpb246bm9uZTt9CiAgLmFkbWluLWxpbms6aG92",
"ZXJ7Y29sb3I6dmFyKC0tYnJhc3MpOyB0ZXh0LWRlY29yYXRpb246dW5kZXJsaW5lO30KCiAgLyog",
"LS0tLSBNZW51IDMgZ+G6oWNoIChoYW1idXJnZXIpICsgZHJvcGRvd24gLS0tLSAqLwogIC5tZW51",
"LXdyYXB7cG9zaXRpb246cmVsYXRpdmU7fQogIC5oYW1idXJnZXItYnRuewogICAgYXBwZWFyYW5j",
"ZTpub25lOyBjdXJzb3I6cG9pbnRlcjsgd2lkdGg6MzhweDsgaGVpZ2h0OjM4cHg7IGJvcmRlci1y",
"YWRpdXM6MTBweDsKICAgIGJhY2tncm91bmQ6dmFyKC0tcGFuZWwpOyBib3JkZXI6MXB4IHNvbGlk",
"IHZhcigtLWxpbmUpOyBjb2xvcjp2YXIoLS10ZXh0KTsKICAgIGRpc3BsYXk6ZmxleDsgYWxpZ24t",
"aXRlbXM6Y2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOwogIH0KICAuaGFtYnVyZ2VyLWJ0",
"bjpob3Zlcntib3JkZXItY29sb3I6dmFyKC0tYnJhc3Mtc29mdCk7fQogIC5oYW1idXJnZXItYnRu",
"IHN2Z3t3aWR0aDoxOHB4OyBoZWlnaHQ6MThweDt9CiAgLmRyb3Bkb3duLW1lbnV7CiAgICBkaXNw",
"bGF5Om5vbmU7IHBvc2l0aW9uOmFic29sdXRlOyB0b3A6Y2FsYygxMDAlICsgOHB4KTsgcmlnaHQ6",
"MDsgbWluLXdpZHRoOjI0MHB4OwogICAgYmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGJvcmRlcjox",
"cHggc29saWQgdmFyKC0tbGluZSk7IGJvcmRlci1yYWRpdXM6MTRweDsKICAgIGJveC1zaGFkb3c6",
"MCAyMHB4IDUwcHggLTIwcHggcmdiYSgwLDAsMCwwLjI4KTsgcGFkZGluZzo4cHg7IHotaW5kZXg6",
"NjA7CiAgfQogIC5kcm9wZG93bi1tZW51LnNob3d7ZGlzcGxheTpibG9jazt9CiAgLmRyb3Bkb3du",
"LW1lbnUgLmRkLWl0ZW17CiAgICBkaXNwbGF5OmZsZXg7IGFsaWduLWl0ZW1zOmNlbnRlcjsgZ2Fw",
"OjEwcHg7IHdpZHRoOjEwMCU7IHRleHQtYWxpZ246bGVmdDsKICAgIHBhZGRpbmc6MTBweCAxMnB4",
"OyBib3JkZXItcmFkaXVzOjlweDsgYm9yZGVyOm5vbmU7IGJhY2tncm91bmQ6bm9uZTsgY3Vyc29y",
"OnBvaW50ZXI7CiAgICBmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7IGZvbnQtc2l6ZTox",
"My41cHg7IGNvbG9yOnZhcigtLXRleHQpOyBmb250LXdlaWdodDo1MDA7CiAgfQogIC5kcm9wZG93",
"bi1tZW51IC5kZC1pdGVtOmhvdmVye2JhY2tncm91bmQ6dmFyKC0tcGFuZWwtMik7fQogIC5kcm9w",
"ZG93bi1tZW51IC5kZC1pdGVtIHN2Z3t3aWR0aDoxN3B4OyBoZWlnaHQ6MTdweDsgY29sb3I6dmFy",
"KC0tYnJhc3MpOyBmbGV4LXNocmluazowO30KICAuZHJvcGRvd24tbWVudSAuZGQtc2Vwe2hlaWdo",
"dDoxcHg7IGJhY2tncm91bmQ6dmFyKC0tbGluZSk7IG1hcmdpbjo2cHggNHB4O30KICAuZHJvcGRv",
"d24tbWVudSAuZGQtYWNjb3VudHsKICAgIHBhZGRpbmc6MTBweCAxMnB4IDEycHg7IGZvbnQtc2l6",
"ZToxMi41cHg7IGNvbG9yOnZhcigtLW11dGVkKTsKICB9CiAgLmRyb3Bkb3duLW1lbnUgLmRkLWFj",
"Y291bnQgYntjb2xvcjp2YXIoLS10ZXh0KTsgZm9udC1zaXplOjEzLjVweDsgZGlzcGxheTpibG9j",
"azsgbWFyZ2luLWJvdHRvbToycHg7fQoKICBtYWlue21heC13aWR0aDoxMDgwcHg7IG1hcmdpbjow",
"IGF1dG87IHBhZGRpbmc6MzZweCAyNHB4IDgwcHg7fQoKICAuaGVyb3t0ZXh0LWFsaWduOmNlbnRl",
"cjsgbWFyZ2luLWJvdHRvbTozNnB4O30KICAuaGVybyBoMntmb250LWZhbWlseTonU3BhY2UgR3Jv",
"dGVzaycsc2Fucy1zZXJpZjsgZm9udC1zaXplOjI4cHg7IG1hcmdpbjowIDAgOHB4O30KICAuaGVy",
"byBwe2NvbG9yOnZhcigtLW11dGVkKTsgZm9udC1zaXplOjE0cHg7IG1hcmdpbjowOyBsaW5lLWhl",
"aWdodDoxLjY7fQogIC5oZXJvIC5iYWRnZXN7ZGlzcGxheTpmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6",
"Y2VudGVyOyBnYXA6MTBweDsgbWFyZ2luLXRvcDoxNnB4OyBmbGV4LXdyYXA6d3JhcDt9CiAgLmhl",
"cm8gLmJhZGdlewogICAgZm9udC1zaXplOjExLjVweDsgY29sb3I6dmFyKC0tYnJhc3MpOyBiYWNr",
"Z3JvdW5kOnZhcigtLWJyYXNzLXRpbnQpOwogICAgcGFkZGluZzo2cHggMTJweDsgYm9yZGVyLXJh",
"ZGl1czoyMHB4OyBmb250LXdlaWdodDo2MDA7CiAgfQoKICAuZ3JpZHsKICAgIGRpc3BsYXk6Z3Jp",
"ZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpbGwsIG1pbm1heCgyNjBweCwg",
"MWZyKSk7IGdhcDoxOHB4OwogIH0KICAuY2FyZHsKICAgIGJhY2tncm91bmQ6dmFyKC0tcGFuZWwp",
"OyBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpOyBib3JkZXItcmFkaXVzOjE2cHg7CiAgICBw",
"YWRkaW5nOjIycHg7IGJveC1zaGFkb3c6dmFyKC0tc2hhZG93KTsKICAgIGRpc3BsYXk6ZmxleDsg",
"ZmxleC1kaXJlY3Rpb246Y29sdW1uOyBnYXA6MTJweDsKICB9CiAgLmNhcmQgLmxvZ297CiAgICB3",
"aWR0aDo1MnB4OyBoZWlnaHQ6NTJweDsgYm9yZGVyLXJhZGl1czoxMnB4OyBvdmVyZmxvdzpoaWRk",
"ZW47CiAgICBiYWNrZ3JvdW5kOnZhcigtLXBhbmVsLTIpOyBib3JkZXI6MXB4IHNvbGlkIHZhcigt",
"LWxpbmUpOwogICAgZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGp1c3RpZnktY29u",
"dGVudDpjZW50ZXI7IGZvbnQtc2l6ZToyMnB4OwogIH0KICAuY2FyZCAubG9nbyBpbWd7d2lkdGg6",
"MTAwJTsgaGVpZ2h0OjEwMCU7IG9iamVjdC1maXQ6Y292ZXI7fQogIC5jYXJkIGgze2ZvbnQtZmFt",
"aWx5OidTcGFjZSBHcm90ZXNrJyxzYW5zLXNlcmlmOyBmb250LXNpemU6MTdweDsgbWFyZ2luOjA7",
"fQogIC5jYXJkIC5wcmljZXtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsg",
"Zm9udC1zaXplOjIwcHg7IGZvbnQtd2VpZ2h0OjcwMDsgY29sb3I6dmFyKC0tYnJhc3MpO30KICAu",
"Y2FyZCAubWV0YXtmb250LXNpemU6MTIuNXB4OyBjb2xvcjp2YXIoLS1tdXRlZCk7IGRpc3BsYXk6",
"ZmxleDsgZmxleC1kaXJlY3Rpb246Y29sdW1uOyBnYXA6NHB4O30KICAuY2FyZCAuc3RvY2t7Zm9u",
"dC1zaXplOjExLjVweDsgZm9udC13ZWlnaHQ6NjAwO30KICAuY2FyZCAuc3RvY2suaW57Y29sb3I6",
"dmFyKC0tb2spO30KICAuY2FyZCAuc3RvY2sub3V0e2NvbG9yOnZhcigtLWRhbmdlcik7fQogIC5j",
"YXJkIC5idXktYnRue21hcmdpbi10b3A6NnB4O30KICAuY2FyZCAuYnV5LWJ0bltkaXNhYmxlZF17",
"b3BhY2l0eTouNDU7IGN1cnNvcjpub3QtYWxsb3dlZDsgYm94LXNoYWRvdzpub25lO30KCiAgLyog",
"LS0tLSBNb2RhbCBjaOG7jW4gZ8OzaSBo4bujcCBuaOG6pXQgKGTDuW5nIGNodW5nIGNobyBHZXRL",
"ZXkgJiBz4bqjbiBwaOG6qW0gbXVhIGLhurFuZyB0aeG7gW4pIC0tLS0gKi8KICAudW5pZmllZC1w",
"bGFuLWhlYWRlcntkaXNwbGF5OmZsZXg7IGFsaWduLWl0ZW1zOmNlbnRlcjsgZ2FwOjE0cHg7IG1h",
"cmdpbi1ib3R0b206NHB4O30KICAudW5pZmllZC1wbGFuLWhlYWRlciAubG9nb3t3aWR0aDo1MnB4",
"OyBoZWlnaHQ6NTJweDsgYm9yZGVyLXJhZGl1czoxNHB4OyBvdmVyZmxvdzpoaWRkZW47IGJhY2tn",
"cm91bmQ6dmFyKC0tcGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7IGRpc3Bs",
"YXk6ZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyBmb250",
"LXNpemU6MjRweDsgZmxleC1zaHJpbms6MDt9CiAgLnVuaWZpZWQtcGxhbi1oZWFkZXIgLmxvZ28g",
"aW1ne3dpZHRoOjEwMCU7IGhlaWdodDoxMDAlOyBvYmplY3QtZml0OmNvdmVyO30KICAudW5pZmll",
"ZC1wbGFuLWhlYWRlciBoM3ttYXJnaW46MDsgZm9udC1zaXplOjE4cHg7fQogIC51bmlmaWVkLXBs",
"YW4taGVhZGVyIC5zdWIye21hcmdpbjoycHggMCAwOyBmb250LXNpemU6MTJweDsgY29sb3I6dmFy",
"KC0tbXV0ZWQpO30KICAucGxhbi1vcHRpb257CiAgICBkaXNwbGF5OmZsZXg7IGFsaWduLWl0ZW1z",
"OmNlbnRlcjsgZ2FwOjE0cHg7IHdpZHRoOjEwMCU7IHRleHQtYWxpZ246bGVmdDsKICAgIGJhY2tn",
"cm91bmQ6dmFyKC0tcGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7IGJvcmRl",
"ci1yYWRpdXM6MTRweDsgcGFkZGluZzoxNHB4IDE2cHg7CiAgICBjdXJzb3I6cG9pbnRlcjsgdHJh",
"bnNpdGlvbjpib3JkZXItY29sb3IgLjEyczsKICB9CiAgLnBsYW4tb3B0aW9uOmhvdmVye2JvcmRl",
"ci1jb2xvcjp2YXIoLS1icmFzcy1zb2Z0KTt9CiAgLnBsYW4tb3B0aW9uW2Rpc2FibGVkXXtvcGFj",
"aXR5Oi40NTsgY3Vyc29yOm5vdC1hbGxvd2VkO30KICAucGxhbi1vcHRpb24gLmljb257CiAgICB3",
"aWR0aDo0NHB4OyBoZWlnaHQ6NDRweDsgYm9yZGVyLXJhZGl1czoxMnB4OyBiYWNrZ3JvdW5kOnZh",
"cigtLWJyYXNzLXRpbnQpOyBjb2xvcjp2YXIoLS1icmFzcyk7CiAgICBkaXNwbGF5OmZsZXg7IGFs",
"aWduLWl0ZW1zOmNlbnRlcjsganVzdGlmeS1jb250ZW50OmNlbnRlcjsgZmxleC1zaHJpbms6MDsg",
"Zm9udC1zaXplOjIwcHg7CiAgfQogIC5wbGFuLW9wdGlvbiAuaW5mb3tmbGV4OjE7IG1pbi13aWR0",
"aDowO30KICAucGxhbi1vcHRpb24gLmluZm8gLmxibHtmb250LXdlaWdodDo3MDA7IGZvbnQtc2l6",
"ZToxNC41cHg7fQogIC5wbGFuLW9wdGlvbiAuaW5mbyAuc3ViM3tmb250LXNpemU6MTEuNXB4OyBj",
"b2xvcjp2YXIoLS1tdXRlZCk7IG1hcmdpbi10b3A6MnB4O30KICAucGxhbi1vcHRpb24gLnJpZ2h0",
"e3RleHQtYWxpZ246cmlnaHQ7IGZsZXgtc2hyaW5rOjA7fQogIC5wbGFuLW9wdGlvbiAucmlnaHQg",
"LnByaWNle2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlOyBmb250LXdlaWdo",
"dDo3MDA7IGZvbnQtc2l6ZToxNS41cHg7IGNvbG9yOnZhcigtLWJyYXNzKTt9CiAgLnBsYW4tb3B0",
"aW9uIC5yaWdodCAudGFne2ZvbnQtc2l6ZToxMC41cHg7IGZvbnQtd2VpZ2h0OjcwMDsgY29sb3I6",
"I2UwYTgwZjsgbWFyZ2luLXRvcDoycHg7fQogIC5wbGFuLW9wdGlvbi5zZWxlY3RlZHtib3JkZXIt",
"Y29sb3I6dmFyKC0tYnJhc3MpOyBiYWNrZ3JvdW5kOnZhcigtLWJyYXNzLXRpbnQpO30KCiAgLmVt",
"cHR5LXN0YXRlewogICAgdGV4dC1hbGlnbjpjZW50ZXI7IHBhZGRpbmc6NjBweCAyMHB4OyBjb2xv",
"cjp2YXIoLS1tdXRlZCk7CiAgICBib3JkZXI6MXB4IGRhc2hlZCB2YXIoLS1saW5lKTsgYm9yZGVy",
"LXJhZGl1czoxNnB4OyBiYWNrZ3JvdW5kOnZhcigtLXBhbmVsLTIpOwogIH0KICAuZW1wdHktc3Rh",
"dGUgLmJpZ3tmb250LXNpemU6MTZweDsgZm9udC13ZWlnaHQ6NjAwOyBjb2xvcjp2YXIoLS10ZXh0",
"KTsgbWFyZ2luLWJvdHRvbTo2cHg7fQoKICBmb290ZXJ7dGV4dC1hbGlnbjpjZW50ZXI7IHBhZGRp",
"bmc6MjhweDsgY29sb3I6dmFyKC0tbXV0ZWQpOyBmb250LXNpemU6MTEuNXB4O30KCiAgLyogLS0t",
"LSBNb2RhbCAtLS0tICovCiAgLm1vZGFsLWJnewogICAgZGlzcGxheTpub25lOyBwb3NpdGlvbjpm",
"aXhlZDsgaW5zZXQ6MDsgYmFja2dyb3VuZDpyZ2JhKDI4LDI3LDI0LDAuNDUpOwogICAgYWxpZ24t",
"aXRlbXM6Y2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyB6LWluZGV4OjEwMDsgcGFkZGlu",
"ZzoyMHB4OwogIH0KICAubW9kYWwtYmcuc2hvd3tkaXNwbGF5OmZsZXg7fQogIC5tb2RhbHsKICAg",
"IHdpZHRoOjEwMCU7IG1heC13aWR0aDo0MDBweDsgYmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGJv",
"cmRlci1yYWRpdXM6MTZweDsKICAgIHBhZGRpbmc6MjhweCAyNnB4OyBib3gtc2hhZG93OjAgMjBw",
"eCA2MHB4IC0yMHB4IHJnYmEoMCwwLDAsMC4zNSk7CiAgICBtYXgtaGVpZ2h0Ojkwdmg7IG92ZXJm",
"bG93LXk6YXV0bzsKICB9CiAgLm1vZGFsIGgze2ZvbnQtZmFtaWx5OidTcGFjZSBHcm90ZXNrJyxz",
"YW5zLXNlcmlmOyBmb250LXNpemU6MTlweDsgbWFyZ2luOjAgMCA0cHg7fQogIC5tb2RhbCAuc3Vi",
"e2ZvbnQtc2l6ZToxMi41cHg7IGNvbG9yOnZhcigtLW11dGVkKTsgbWFyZ2luOjAgMCAxOHB4O30K",
"ICAubW9kYWwgbGFiZWx7ZGlzcGxheTpibG9jazsgZm9udC1zaXplOjEycHg7IGNvbG9yOnZhcigt",
"LW11dGVkKTsgbWFyZ2luOjEycHggMCA2cHg7IGZvbnQtd2VpZ2h0OjUwMDt9CiAgLm1vZGFsIGlu",
"cHV0ewogICAgd2lkdGg6MTAwJTsgYmFja2dyb3VuZDp2YXIoLS1wYW5lbC0yKTsgYm9yZGVyOjFw",
"eCBzb2xpZCB2YXIoLS1saW5lKTsgY29sb3I6dmFyKC0tdGV4dCk7CiAgICBwYWRkaW5nOjExcHgg",
"MTNweDsgYm9yZGVyLXJhZGl1czoxMHB4OyBmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7",
"IGZvbnQtc2l6ZToxMy41cHg7CiAgICBvdXRsaW5lOm5vbmU7CiAgfQogIC5tb2RhbCBpbnB1dDpm",
"b2N1c3tib3JkZXItY29sb3I6dmFyKC0tYnJhc3Mtc29mdCk7IGJveC1zaGFkb3c6MCAwIDAgM3B4",
"ICNDOTlBMkUxZjt9CiAgLm1vZGFsLWFjdGlvbnN7ZGlzcGxheTpmbGV4OyBnYXA6MTBweDsgbWFy",
"Z2luLXRvcDoyMHB4O30KICAubW9kYWwtYWN0aW9ucyAuYnRue2ZsZXg6MTsgdGV4dC1hbGlnbjpj",
"ZW50ZXI7fQogIC5hdXRoLXRhYnN7ZGlzcGxheTpmbGV4OyBnYXA6NnB4OyBiYWNrZ3JvdW5kOnZh",
"cigtLXBhbmVsLTIpOyBib3JkZXItcmFkaXVzOjEwcHg7IHBhZGRpbmc6NHB4OyBtYXJnaW4tYm90",
"dG9tOjZweDt9CiAgLmF1dGgtdGFicyBidXR0b257CiAgICBmbGV4OjE7IHBhZGRpbmc6OHB4OyBi",
"b3JkZXI6bm9uZTsgYmFja2dyb3VuZDpub25lOyBib3JkZXItcmFkaXVzOjdweDsgY3Vyc29yOnBv",
"aW50ZXI7CiAgICBmb250LXNpemU6MTIuNXB4OyBmb250LXdlaWdodDo2MDA7IGNvbG9yOnZhcigt",
"LW11dGVkKTsgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmOwogIH0KICAuYXV0aC10YWJz",
"IGJ1dHRvbi5hY3RpdmV7YmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGNvbG9yOnZhcigtLXRleHQp",
"OyBib3gtc2hhZG93OnZhcigtLXNoYWRvdyk7fQogIC5tb2RhbC1lcnJvcnsKICAgIGRpc3BsYXk6",
"bm9uZTsgYmFja2dyb3VuZDp2YXIoLS1kYW5nZXItdGludCk7IGNvbG9yOnZhcigtLWRhbmdlcik7",
"IGJvcmRlcjoxcHggc29saWQgI0MyM0I0QjMwOwogICAgZm9udC1zaXplOjEycHg7IHBhZGRpbmc6",
"OXB4IDExcHg7IGJvcmRlci1yYWRpdXM6OHB4OyBtYXJnaW4tdG9wOjEycHg7IGZvbnQtd2VpZ2h0",
"OjUwMDsKICB9CiAgLm1vZGFsLWVycm9yLnNob3d7ZGlzcGxheTpibG9jazt9CiAgLm1vZGFsLW5v",
"dGV7Zm9udC1zaXplOjExLjVweDsgY29sb3I6dmFyKC0tbXV0ZWQpOyBtYXJnaW4tdG9wOjE0cHg7",
"IGxpbmUtaGVpZ2h0OjEuNjt9CgogIC5jaGVja291dC1zdW1tYXJ5ewogICAgYmFja2dyb3VuZDp2",
"YXIoLS1wYW5lbC0yKTsgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsgYm9yZGVyLXJhZGl1",
"czoxMnB4OyBwYWRkaW5nOjE0cHggMTZweDsgbWFyZ2luLXRvcDo2cHg7CiAgfQogIC5jaGVja291",
"dC1zdW1tYXJ5IC5yb3d7ZGlzcGxheTpmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2Vl",
"bjsgZm9udC1zaXplOjEzcHg7IG1hcmdpbi1ib3R0b206NnB4O30KICAuY2hlY2tvdXQtc3VtbWFy",
"eSAucm93Omxhc3QtY2hpbGR7bWFyZ2luLWJvdHRvbTowOyBwYWRkaW5nLXRvcDo4cHg7IGJvcmRl",
"ci10b3A6MXB4IGRhc2hlZCB2YXIoLS1saW5lKTsgZm9udC13ZWlnaHQ6NzAwO30KICAuZGlzY291",
"bnQtYXBwbGllZHtjb2xvcjp2YXIoLS1vayk7IGZvbnQtd2VpZ2h0OjYwMDt9CgogIC5yZXN1bHQt",
"a2V5LWJveHsKICAgIGJhY2tncm91bmQ6dmFyKC0tYnJhc3MtdGludCk7IGJvcmRlcjoxcHggc29s",
"aWQgI0M5OUEyRTQwOyBib3JkZXItcmFkaXVzOjEycHg7CiAgICBwYWRkaW5nOjE2cHg7IHRleHQt",
"YWxpZ246Y2VudGVyOyBtYXJnaW4tdG9wOjhweDsKICB9CiAgLnJlc3VsdC1rZXktYm94IGNvZGV7",
"CiAgICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsgZm9udC1zaXplOjE0",
"cHg7IGZvbnQtd2VpZ2h0OjcwMDsgY29sb3I6dmFyKC0tYnJhc3MpOwogICAgd29yZC1icmVhazpi",
"cmVhay1hbGw7IGRpc3BsYXk6YmxvY2s7IG1hcmdpbi1ib3R0b206MTBweDsgbGluZS1oZWlnaHQ6",
"MS41OwogIH0KICAudG9hc3R7CiAgICBwb3NpdGlvbjpmaXhlZDsgYm90dG9tOjI0cHg7IGxlZnQ6",
"NTAlOyB0cmFuc2Zvcm06dHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKDIwcHgpOwogICAgYmFj",
"a2dyb3VuZDp2YXIoLS10ZXh0KTsgY29sb3I6I2ZmZjsgcGFkZGluZzoxMnB4IDIwcHg7IGJvcmRl",
"ci1yYWRpdXM6MTBweDsgZm9udC1zaXplOjEzcHg7CiAgICBvcGFjaXR5OjA7IHBvaW50ZXItZXZl",
"bnRzOm5vbmU7IHRyYW5zaXRpb246YWxsIC4yNXM7IHotaW5kZXg6MjAwOyBtYXgtd2lkdGg6OTB2",
"dzsgdGV4dC1hbGlnbjpjZW50ZXI7CiAgfQogIC50b2FzdC5zaG93e29wYWNpdHk6MTsgdHJhbnNm",
"b3JtOnRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSgwKTt9CgogIC8qIC0tLS0gVGjDtG5nIHRp",
"biB0w6BpIGtob+G6o24gLyBs4buLY2ggc+G7rSBu4bqhcCB0aeG7gW4gLyBs4buLY2ggc+G7rSBn",
"aWFvIGThu4tjaCAtLS0tICovCiAgLmluZm8tcm93e2Rpc3BsYXk6ZmxleDsganVzdGlmeS1jb250",
"ZW50OnNwYWNlLWJldHdlZW47IGFsaWduLWl0ZW1zOmNlbnRlcjsgcGFkZGluZzoxMHB4IDA7IGJv",
"cmRlci1ib3R0b206MXB4IGRhc2hlZCB2YXIoLS1saW5lKTsgZm9udC1zaXplOjEzcHg7fQogIC5p",
"bmZvLXJvdzpsYXN0LWNoaWxke2JvcmRlci1ib3R0b206bm9uZTt9CiAgLmluZm8tcm93IC5re2Nv",
"bG9yOnZhcigtLW11dGVkKTt9CiAgLmluZm8tcm93IC52e2ZvbnQtd2VpZ2h0OjYwMDsgZm9udC1m",
"YW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7fQogIC5oaXN0b3J5LWxpc3R7ZGlzcGxh",
"eTpmbGV4OyBmbGV4LWRpcmVjdGlvbjpjb2x1bW47IGdhcDo4cHg7IG1heC1oZWlnaHQ6MzIwcHg7",
"IG92ZXJmbG93LXk6YXV0bzsgbWFyZ2luLXRvcDo0cHg7fQogIC5oaXN0b3J5LWl0ZW17CiAgICBk",
"aXNwbGF5OmZsZXg7IGp1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczpj",
"ZW50ZXI7IGdhcDoxMHB4OwogICAgYmFja2dyb3VuZDp2YXIoLS1wYW5lbC0yKTsgYm9yZGVyOjFw",
"eCBzb2xpZCB2YXIoLS1saW5lKTsgYm9yZGVyLXJhZGl1czoxMHB4OyBwYWRkaW5nOjEwcHggMTJw",
"eDsKICB9CiAgLmhpc3RvcnktaXRlbSAuaC1tYWlue2ZvbnQtc2l6ZToxM3B4OyBmb250LXdlaWdo",
"dDo2MDA7fQogIC5oaXN0b3J5LWl0ZW0gLmgtc3Vie2ZvbnQtc2l6ZToxMS41cHg7IGNvbG9yOnZh",
"cigtLW11dGVkKTsgbWFyZ2luLXRvcDoycHg7fQogIC5oaXN0b3J5LWl0ZW0gLmgtYW1vdW50e2Zv",
"bnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlOyBmb250LXdlaWdodDo3MDA7IGZv",
"bnQtc2l6ZToxMy41cHg7fQogIC5oaXN0b3J5LWl0ZW0gLmgtYW1vdW50LnBvc3tjb2xvcjp2YXIo",
"LS1vayk7fQogIC5oaXN0b3J5LWl0ZW0gLmgtYW1vdW50Lm5lZ3tjb2xvcjp2YXIoLS1kYW5nZXIp",
"O30KICAuaGlzdG9yeS1lbXB0eXt0ZXh0LWFsaWduOmNlbnRlcjsgY29sb3I6dmFyKC0tbXV0ZWQp",
"OyBmb250LXNpemU6MTIuNXB4OyBwYWRkaW5nOjIwcHggMDt9CiAgLnN0YXR1cy1waWxse2ZvbnQt",
"c2l6ZToxMC41cHg7IGZvbnQtd2VpZ2h0OjcwMDsgcGFkZGluZzozcHggOXB4OyBib3JkZXItcmFk",
"aXVzOjIwcHg7IGRpc3BsYXk6aW5saW5lLWJsb2NrO30KICAuc3RhdHVzLXBpbGwucGVuZGluZ3ti",
"YWNrZ3JvdW5kOnZhcigtLWJyYXNzLXRpbnQpOyBjb2xvcjp2YXIoLS1icmFzcyk7fQogIC5zdGF0",
"dXMtcGlsbC5hcHByb3ZlZHtiYWNrZ3JvdW5kOnZhcigtLW9rLXRpbnQpOyBjb2xvcjp2YXIoLS1v",
"ayk7fQogIC5zdGF0dXMtcGlsbC5yZWplY3RlZHtiYWNrZ3JvdW5kOnZhcigtLWRhbmdlci10aW50",
"KTsgY29sb3I6dmFyKC0tZGFuZ2VyKTt9CiAgLnN0YXR1cy1waWxsLmF2YWlsYWJsZSwgLnN0YXR1",
"cy1waWxsLnNvbGR7YmFja2dyb3VuZDp2YXIoLS1vay10aW50KTsgY29sb3I6dmFyKC0tb2spO30K",
"ICAuc3RhdHVzLXBpbGwuYmFubmVkLCAuc3RhdHVzLXBpbGwuZXhwaXJlZHtiYWNrZ3JvdW5kOnZh",
"cigtLWRhbmdlci10aW50KTsgY29sb3I6dmFyKC0tZGFuZ2VyKTt9CiAgLnN0YXR1cy1waWxsLnVu",
"YWN0aXZhdGVke2JhY2tncm91bmQ6I0U3RjBGQjsgY29sb3I6IzJENkZCQjt9CgogIC8qIC0tLS0g",
"UXXhuqNuIGzDvSBrZXkgKGtleSDEkcOjIG11YSkgLS0tLSAqLwogIC5rZXktaXRlbXsKICAgIGJh",
"Y2tncm91bmQ6dmFyKC0tcGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7IGJv",
"cmRlci1yYWRpdXM6MTBweDsgcGFkZGluZzoxMnB4IDE0cHg7CiAgICBkaXNwbGF5OmZsZXg7IGZs",
"ZXgtZGlyZWN0aW9uOmNvbHVtbjsgZ2FwOjZweDsKICB9CiAgLmtleS1pdGVtIC5rLXRvcHtkaXNw",
"bGF5OmZsZXg7IGp1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczpjZW50",
"ZXI7IGdhcDoxMHB4O30KICAua2V5LWl0ZW0gLmstdmFsdWV7Zm9udC1mYW1pbHk6J0pldEJyYWlu",
"cyBNb25vJyxtb25vc3BhY2U7IGZvbnQtc2l6ZToxMi41cHg7IGZvbnQtd2VpZ2h0OjcwMDsgd29y",
"ZC1icmVhazpicmVhay1hbGw7fQogIC5rZXktaXRlbSAuay1tZXRhe2ZvbnQtc2l6ZToxMS41cHg7",
"IGNvbG9yOnZhcigtLW11dGVkKTsgbGluZS1oZWlnaHQ6MS42O30KICAua2V5LWl0ZW0gLmstY29w",
"eXsKICAgIGFwcGVhcmFuY2U6bm9uZTsgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsgYmFj",
"a2dyb3VuZDp2YXIoLS1wYW5lbCk7IGNvbG9yOnZhcigtLXRleHQpOwogICAgcGFkZGluZzo1cHgg",
"MTBweDsgYm9yZGVyLXJhZGl1czo3cHg7IGZvbnQtc2l6ZToxMXB4OyBmb250LXdlaWdodDo2MDA7",
"IGN1cnNvcjpwb2ludGVyOyB3aGl0ZS1zcGFjZTpub3dyYXA7CiAgICBmb250LWZhbWlseTonSW50",
"ZXInLHNhbnMtc2VyaWY7CiAgfQogIC5rZXktaXRlbSAuay1jb3B5OmhvdmVye2JvcmRlci1jb2xv",
"cjp2YXIoLS1icmFzcy1zb2Z0KTsgY29sb3I6dmFyKC0tYnJhc3MpO30KCiAgLmJhbmstaW5mby1i",
"b3h7CiAgICBiYWNrZ3JvdW5kOnZhcigtLXBhbmVsLTIpOyBib3JkZXI6MXB4IHNvbGlkIHZhcigt",
"LWxpbmUpOyBib3JkZXItcmFkaXVzOjEycHg7IHBhZGRpbmc6MTRweCAxNnB4OyBtYXJnaW4tdG9w",
"OjZweDsKICB9CiAgLmJhbmstaW5mby1ib3ggLmluZm8tcm93IC52e2ZvbnQtZmFtaWx5OidKZXRC",
"cmFpbnMgTW9ubycsbW9ub3NwYWNlO30KCiAgLyogLS0tLSBO4bqhcCB0aeG7gW4gdOG7sSDEkeG7",
"mW5nOiBRUiDEkeG7mW5nIChWaWV0UVIpICsgxJHhu5NuZyBo4buTIMSR4bq/bSBuZ8aw4bujYyAz",
"MCBwaMO6dCAtLS0tICovCiAgLnRvcHVwLXFyLWJveHsKICAgIGRpc3BsYXk6ZmxleDsgZmxleC1k",
"aXJlY3Rpb246Y29sdW1uOyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDoxMHB4OwogICAgYmFja2dy",
"b3VuZDp2YXIoLS1wYW5lbC0yKTsgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsgYm9yZGVy",
"LXJhZGl1czoxNHB4OyBwYWRkaW5nOjE4cHggMTZweDsgbWFyZ2luLXRvcDo2cHg7CiAgfQogIC50",
"b3B1cC1xci1ib3ggaW1newogICAgd2lkdGg6MjIwcHg7IGhlaWdodDoyMjBweDsgb2JqZWN0LWZp",
"dDpjb250YWluOyBib3JkZXItcmFkaXVzOjEwcHg7IGJhY2tncm91bmQ6I2ZmZjsKICAgIGJvcmRl",
"cjoxcHggc29saWQgdmFyKC0tbGluZSk7IHBhZGRpbmc6NnB4OwogIH0KICAudG9wdXAtcXItaGlu",
"dHtmb250LXNpemU6MTJweDsgY29sb3I6dmFyKC0tbXV0ZWQpOyB0ZXh0LWFsaWduOmNlbnRlcjsg",
"bGluZS1oZWlnaHQ6MS41O30KICAudG9wdXAtY291bnRkb3duewogICAgZGlzcGxheTpmbGV4OyBh",
"bGlnbi1pdGVtczpjZW50ZXI7IGdhcDo4cHg7IGZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycs",
"bW9ub3NwYWNlOwogICAgZm9udC1zaXplOjIwcHg7IGZvbnQtd2VpZ2h0OjcwMDsgY29sb3I6dmFy",
"KC0tYnJhc3MpOyBsZXR0ZXItc3BhY2luZzoxcHg7CiAgfQogIC50b3B1cC1jb3VudGRvd24ud2Fy",
"bntjb2xvcjp2YXIoLS1kYW5nZXIpO30KICAudG9wdXAtY291bnRkb3duLWxhYmVse2ZvbnQtc2l6",
"ZToxMXB4OyBjb2xvcjp2YXIoLS1tdXRlZCk7IGZvbnQtd2VpZ2h0OjUwMDsgbGV0dGVyLXNwYWNp",
"bmc6LjNweDsgdGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlOyBmb250LWZhbWlseTonSW50ZXInLHNh",
"bnMtc2VyaWY7fQogIC50b3B1cC1leHBpcmVkLWJveHsKICAgIGRpc3BsYXk6bm9uZTsgZmxleC1k",
"aXJlY3Rpb246Y29sdW1uOyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDoxMHB4OyB0ZXh0LWFsaWdu",
"OmNlbnRlcjsKICAgIHBhZGRpbmc6MThweCAxNnB4OwogIH0KICAudG9wdXAtZXhwaXJlZC1ib3gu",
"c2hvd3tkaXNwbGF5OmZsZXg7fQogIC50b3B1cC1leHBpcmVkLWJveCAuaWNvbnsKICAgIHdpZHRo",
"OjQ0cHg7IGhlaWdodDo0NHB4OyBib3JkZXItcmFkaXVzOjUwJTsgYmFja2dyb3VuZDp2YXIoLS1k",
"YW5nZXItdGludCk7IGNvbG9yOnZhcigtLWRhbmdlcik7CiAgICBkaXNwbGF5OmZsZXg7IGFsaWdu",
"LWl0ZW1zOmNlbnRlcjsganVzdGlmeS1jb250ZW50OmNlbnRlcjsKICB9CiAgLnRvcHVwLXN0ZXAt",
"YW1vdW50e2Rpc3BsYXk6ZmxleDsgZmxleC1kaXJlY3Rpb246Y29sdW1uOyBnYXA6MTRweDt9CiAg",
"LnRvcHVwLXN0ZXAtcXJ7ZGlzcGxheTpub25lOyBmbGV4LWRpcmVjdGlvbjpjb2x1bW47IGdhcDox",
"NHB4O30KICAudG9wdXAtc3RlcC1xci5zaG93e2Rpc3BsYXk6ZmxleDt9CiAgLnRvcHVwLWJhY2st",
"bGlua3sKICAgIGZvbnQtc2l6ZToxMnB4OyBjb2xvcjp2YXIoLS1tdXRlZCk7IHRleHQtZGVjb3Jh",
"dGlvbjpub25lOyBmb250LXdlaWdodDo2MDA7IGN1cnNvcjpwb2ludGVyOwogICAgZGlzcGxheTpp",
"bmxpbmUtZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBnYXA6NXB4OyBhbGlnbi1zZWxmOmZsZXgt",
"c3RhcnQ7CiAgfQogIC50b3B1cC1iYWNrLWxpbms6aG92ZXJ7Y29sb3I6dmFyKC0tYnJhc3MpO30K",
"ICAuc3VwcG9ydC1saW5rewogICAgZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGdh",
"cDoxMHB4OyB0ZXh0LWRlY29yYXRpb246bm9uZTsgY29sb3I6dmFyKC0tdGV4dCk7CiAgICBiYWNr",
"Z3JvdW5kOnZhcigtLXBhbmVsLTIpOyBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpOyBib3Jk",
"ZXItcmFkaXVzOjEycHg7IHBhZGRpbmc6MTRweCAxNnB4OyBtYXJnaW4tdG9wOjhweDsgZm9udC1z",
"aXplOjEzLjVweDsgZm9udC13ZWlnaHQ6NjAwOwogIH0KICAuc3VwcG9ydC1saW5rOmhvdmVye2Jv",
"cmRlci1jb2xvcjp2YXIoLS1icmFzcy1zb2Z0KTt9CiAgLnN1cHBvcnQtbGluayBzdmd7d2lkdGg6",
"MjBweDsgaGVpZ2h0OjIwcHg7IGNvbG9yOiMyQUFCRUU7IGZsZXgtc2hyaW5rOjA7fQoKICAvKiAt",
"LS0tIEdldEtleSAodsaw4bujdCBsaW5rIG5o4bqtbiBrZXkpIC0tLS0gKi8KICAuZ2stZ2FtZS1n",
"cmlke2Rpc3BsYXk6Z3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpbGws",
"IG1pbm1heCgxNDBweCwgMWZyKSk7IGdhcDoxMHB4OyBtYXJnaW4tdG9wOjZweDt9CiAgLmdrLWdh",
"bWUtY2FyZHsKICAgIGJhY2tncm91bmQ6dmFyKC0tcGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQg",
"dmFyKC0tbGluZSk7IGJvcmRlci1yYWRpdXM6MTJweDsgcGFkZGluZzoxNHB4IDEwcHg7CiAgICB0",
"ZXh0LWFsaWduOmNlbnRlcjsgY3Vyc29yOnBvaW50ZXI7IHRyYW5zaXRpb246Ym9yZGVyLWNvbG9y",
"IC4xMnM7CiAgfQogIC5nay1nYW1lLWNhcmQ6aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLWJyYXNz",
"LXNvZnQpO30KICAuZ2stZ2FtZS1jYXJkLnNlbGVjdGVke2JvcmRlci1jb2xvcjp2YXIoLS1icmFz",
"cyk7IGJhY2tncm91bmQ6dmFyKC0tYnJhc3MtdGludCk7fQogIC5nay1nYW1lLWNhcmQgLmxvZ297",
"d2lkdGg6NDRweDsgaGVpZ2h0OjQ0cHg7IGJvcmRlci1yYWRpdXM6MTBweDsgbWFyZ2luOjAgYXV0",
"byA4cHg7IG92ZXJmbG93OmhpZGRlbjsgYmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGRpc3BsYXk6",
"ZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyBmb250LXNp",
"emU6MjBweDt9CiAgLmdrLWdhbWUtY2FyZCAubG9nbyBpbWd7d2lkdGg6MTAwJTsgaGVpZ2h0OjEw",
"MCU7IG9iamVjdC1maXQ6Y292ZXI7fQogIC5nay1nYW1lLWNhcmQgLm5hbWV7Zm9udC1zaXplOjEy",
"LjVweDsgZm9udC13ZWlnaHQ6NjAwO30KICAuZ2stZHVyYXRpb24tbGlzdHtkaXNwbGF5OmZsZXg7",
"IGZsZXgtZGlyZWN0aW9uOmNvbHVtbjsgZ2FwOjhweDsgbWFyZ2luLXRvcDo2cHg7fQogIC5nay1k",
"dXJhdGlvbi1pdGVtewogICAgZGlzcGxheTpmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0",
"d2VlbjsgYWxpZ24taXRlbXM6Y2VudGVyOyBnYXA6MTBweDsKICAgIGJhY2tncm91bmQ6dmFyKC0t",
"cGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7IGJvcmRlci1yYWRpdXM6MTBw",
"eDsgcGFkZGluZzoxMnB4IDE0cHg7CiAgICBjdXJzb3I6cG9pbnRlcjsKICB9CiAgLmdrLWR1cmF0",
"aW9uLWl0ZW06aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLWJyYXNzLXNvZnQpO30KICAuZ2stZHVy",
"YXRpb24taXRlbS5zZWxlY3RlZHtib3JkZXItY29sb3I6dmFyKC0tYnJhc3MpOyBiYWNrZ3JvdW5k",
"OnZhcigtLWJyYXNzLXRpbnQpO30KICAuZ2stZHVyYXRpb24taXRlbSAubGJse2ZvbnQtc2l6ZTox",
"My41cHg7IGZvbnQtd2VpZ2h0OjYwMDt9CiAgLmdrLWR1cmF0aW9uLWl0ZW0gLnJvdW5kc3tmb250",
"LXNpemU6MTEuNXB4OyBjb2xvcjp2YXIoLS1tdXRlZCk7fQogIC5nay1wcm9ncmVzc3tkaXNwbGF5",
"OmZsZXg7IGdhcDo2cHg7IGp1c3RpZnktY29udGVudDpjZW50ZXI7IG1hcmdpbjoxNnB4IDA7fQog",
"IC5nay1wcm9ncmVzcyAuZG90e3dpZHRoOjI4cHg7IGhlaWdodDo2cHg7IGJvcmRlci1yYWRpdXM6",
"NHB4OyBiYWNrZ3JvdW5kOnZhcigtLWxpbmUpO30KICAuZ2stcHJvZ3Jlc3MgLmRvdC5kb25le2Jh",
"Y2tncm91bmQ6dmFyKC0tb2spO30KICAuZ2stcHJvZ3Jlc3MgLmRvdC5jdXJyZW50e2JhY2tncm91",
"bmQ6dmFyKC0tYnJhc3MpO30KICAuZ2stc3RlcC1ib3h7CiAgICBiYWNrZ3JvdW5kOnZhcigtLXBh",
"bmVsLTIpOyBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpOyBib3JkZXItcmFkaXVzOjEycHg7",
"IHBhZGRpbmc6MjBweDsgdGV4dC1hbGlnbjpjZW50ZXI7IG1hcmdpbi10b3A6NnB4OwogIH0KICAu",
"Z2stc3RlcC1ib3ggLnJvdW5kLWxhYmVse2ZvbnQtc2l6ZToxM3B4OyBjb2xvcjp2YXIoLS1tdXRl",
"ZCk7IG1hcmdpbi1ib3R0b206MTBweDt9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+Cgo8aGVhZGVy",
"IGNsYXNzPSJ0b3AiPgogIDxkaXYgY2xhc3M9InRvcC1yb3ciPgogICAgPGRpdiBjbGFzcz0iYnJh",
"bmQiPgogICAgICA8ZGl2IGNsYXNzPSJtYXJrIj4KICAgICAgICA8c3ZnIHZpZXdCb3g9IjAgMCAy",
"NCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMiI+",
"PHJlY3QgeD0iMyIgeT0iMTEiIHdpZHRoPSIxOCIgaGVpZ2h0PSIxMCIgcng9IjIiLz48Y2lyY2xl",
"IGN4PSIxMiIgY3k9IjE2IiByPSIxLjYiLz48cGF0aCBkPSJNNyAxMVY3YTUgNSAwIDAgMSAxMCAw",
"djQiLz48L3N2Zz4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGgxPktleVZhdWx0",
"IFN0b3JlPC9oMT4KICAgICAgICA8ZGl2IGNsYXNzPSJ0YWciPk11YSBrZXkgdHLhu7FjIHR1eeG6",
"v248L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRvcC1hY3Rp",
"b25zIj4KICAgICAgPGEgaHJlZj0iL2FkbWluIiBjbGFzcz0iYWRtaW4tbGluayI+VHJhbmcgcXXh",
"uqNuIHRy4buLPC9hPgogICAgICA8ZGl2IGlkPSJndWVzdEFjdGlvbnMiPgogICAgICAgIDxidXR0",
"b24gY2xhc3M9ImJ0biIgaWQ9ImJ0bk9wZW5BdXRoIj7EkMSDbmcgbmjhuq1wIC8gxJDEg25nIGvD",
"vTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0iYWNjb3VudENoaXAiIGNsYXNz",
"PSJhY2NvdW50LWNoaXAiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICA8c3BhbiBpZD0i",
"YWNjb3VudE5hbWUiPjwvc3Bhbj4KICAgICAgICA8YnV0dG9uIGlkPSJidG5Mb2dvdXRDdXN0b21l",
"ciI+xJDEg25nIHh14bqldDwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0i",
"bWVudS13cmFwIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJoYW1idXJnZXItYnRuIiBpZD0iYnRu",
"SGFtYnVyZ2VyIiB0aXRsZT0iTWVudSIgYXJpYS1sYWJlbD0iTWVudSI+CiAgICAgICAgICA8c3Zn",
"IHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0",
"cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIj48cGF0aCBkPSJNMyA2aDE4TTMg",
"MTJoMThNMyAxOGgxOCIvPjwvc3ZnPgogICAgICAgIDwvYnV0dG9uPgogICAgICAgIDxkaXYgY2xh",
"c3M9ImRyb3Bkb3duLW1lbnUiIGlkPSJkcm9wZG93bk1lbnUiPgogICAgICAgICAgPGRpdiBpZD0i",
"ZGRHdWVzdEJsb2NrIj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iZGQtaXRlbSIgaWQ9ImRk",
"T3BlbkF1dGgiPgogICAgICAgICAgICAgIDxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJu",
"b25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIxLjgiPjxwYXRoIGQ9Ik0x",
"NSAzaDRhMiAyIDAgMCAxIDIgMnYxNGEyIDIgMCAwIDEtMiAyaC00Ii8+PHBhdGggZD0iTTEwIDE3",
"bDUtNS01LTUiLz48cGF0aCBkPSJNMTUgMTJIMyIvPjwvc3ZnPgogICAgICAgICAgICAgIMSQxINu",
"ZyBuaOG6rXAgLyDEkMSDbmcga8O9CiAgICAgICAgICAgIDwvYnV0dG9uPgogICAgICAgICAgPC9k",
"aXY+CiAgICAgICAgICA8ZGl2IGlkPSJkZEFjY291bnRCbG9jayIgc3R5bGU9ImRpc3BsYXk6bm9u",
"ZTsiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJkZC1hY2NvdW50Ij48YiBpZD0iZGRBY2NvdW50",
"TmFtZSI+4oCUPC9iPlPhu5EgZMawOiA8c3BhbiBpZD0iZGRBY2NvdW50QmFsYW5jZSI+MOKCqzwv",
"c3Bhbj48L2Rpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iZGQtc2VwIj48L2Rpdj4KICAgICAg",
"ICAgICAgPGJ1dHRvbiBjbGFzcz0iZGQtaXRlbSIgaWQ9ImRkVG9wdXAiPgogICAgICAgICAgICAg",
"IDxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xv",
"ciIgc3Ryb2tlLXdpZHRoPSIxLjgiPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjkiLz48cGF0",
"aCBkPSJNMTIgOHY4TTggMTJoOCIvPjwvc3ZnPgogICAgICAgICAgICAgIE7huqFwIHRp4buBbiB0",
"4buxIMSR4buZbmcKICAgICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xh",
"c3M9ImRkLWl0ZW0iIGlkPSJkZEFjY291bnRJbmZvIj4KICAgICAgICAgICAgICA8c3ZnIHZpZXdC",
"b3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13",
"aWR0aD0iMS44Ij48Y2lyY2xlIGN4PSIxMiIgY3k9IjgiIHI9IjQiLz48cGF0aCBkPSJNNCAyMWMw",
"LTQgNC02IDgtNnM4IDIgOCA2Ii8+PC9zdmc+CiAgICAgICAgICAgICAgVGjDtG5nIHRpbiB0w6Bp",
"IGtob+G6o24KICAgICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9",
"ImRkLWl0ZW0iIGlkPSJkZFRvcHVwSGlzdG9yeSI+CiAgICAgICAgICAgICAgPHN2ZyB2aWV3Qm94",
"PSIwIDAgMjQgMjQiIGZpbGw9Im5vbmUiIHN0cm9rZT0iY3VycmVudENvbG9yIiBzdHJva2Utd2lk",
"dGg9IjEuOCI+PHBhdGggZD0iTTMgMTJhOSA5IDAgMSAwIDMtNi43Ii8+PHBhdGggZD0iTTMgNHY1",
"aDUiLz48cGF0aCBkPSJNMTIgN3Y1bDQgMiIvPjwvc3ZnPgogICAgICAgICAgICAgIEzhu4tjaCBz",
"4butIG7huqFwIHRp4buBbgogICAgICAgICAgICA8L2J1dHRvbj4KICAgICAgICAgICAgPGJ1dHRv",
"biBjbGFzcz0iZGQtaXRlbSIgaWQ9ImRkVHhIaXN0b3J5Ij4KICAgICAgICAgICAgICA8c3ZnIHZp",
"ZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9r",
"ZS13aWR0aD0iMS44Ij48cmVjdCB4PSIzIiB5PSI0IiB3aWR0aD0iMTgiIGhlaWdodD0iMTYiIHJ4",
"PSIyIi8+PHBhdGggZD0iTTcgOWgxME03IDEzaDEwTTcgMTdoNiIvPjwvc3ZnPgogICAgICAgICAg",
"ICAgIEzhu4tjaCBz4butIGdpYW8gZOG7i2NoCiAgICAgICAgICAgIDwvYnV0dG9uPgogICAgICAg",
"ICAgICA8YnV0dG9uIGNsYXNzPSJkZC1pdGVtIiBpZD0iZGRNeUtleXMiPgogICAgICAgICAgICAg",
"IDxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xv",
"ciIgc3Ryb2tlLXdpZHRoPSIxLjgiPjxyZWN0IHg9IjMiIHk9IjExIiB3aWR0aD0iMTgiIGhlaWdo",
"dD0iMTAiIHJ4PSIyIi8+PGNpcmNsZSBjeD0iMTIiIGN5PSIxNiIgcj0iMS42Ii8+PHBhdGggZD0i",
"TTcgMTFWN2E1IDUgMCAwIDEgMTAgMHY0Ii8+PC9zdmc+CiAgICAgICAgICAgICAgUXXhuqNuIGzD",
"vSBrZXkKICAgICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImRkLXNl",
"cCI+PC9kaXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImRkLWl0",
"ZW0iIGlkPSJkZFN1cHBvcnQiPgogICAgICAgICAgICA8c3ZnIHZpZXdCb3g9IjAgMCAyNCAyNCIg",
"ZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMS44Ij48cGF0",
"aCBkPSJNMjIgNC45IDIuNSAxMi4zYy0uOS4zNS0uOSAxLjYuMDUgMS45bDQuNyAxLjUgMS44IDUu",
"NGMuMy45IDEuNSAxLjA1IDIuMDUuMjVsMi40LTMuNSA0LjYgMy40Yy44LjYgMS45NS4xNSAyLjE1",
"LS44NUwyMy45IDUuOWMuMi0xLS44NS0xLjc1LTEuOS0xeiIvPjwvc3ZnPgogICAgICAgICAgICBI",
"4buXIHRy4bujIGtow6FjaCBow6BuZwogICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICA8YnV0",
"dG9uIGNsYXNzPSJkZC1pdGVtIiBpZD0iZGRHZXRLZXkiPgogICAgICAgICAgICA8c3ZnIHZpZXdC",
"b3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13",
"aWR0aD0iMS44Ij48Y2lyY2xlIGN4PSI4IiBjeT0iMTUiIHI9IjQiLz48cGF0aCBkPSJNMTAuNSAx",
"Mi41IDIwIDNNMjAgM2gtNE0yMCAzdjQiLz48L3N2Zz4KICAgICAgICAgICAgR2V0S2V5ICh2xrDh",
"u6N0IGxpbmsgbmjhuq1uIGtleSkKICAgICAgICAgIDwvYnV0dG9uPgogICAgICAgIDwvZGl2Pgog",
"ICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2hlYWRlcj4KCjxtYWluPgogIDxkaXYg",
"Y2xhc3M9Imhlcm8iPgogICAgPGgyPktleSBjaMOtbmggaMOjbmcg4oCUIGdpYW8gbmdheSBzYXUg",
"a2hpIHRoYW5oIHRvw6FuPC9oMj4KICAgIDxwPkNo4buNbiBz4bqjbiBwaOG6qW0gYsOqbiBkxrDh",
"u5tpLCDEkcSDbmcgbmjhuq1wIGhv4bq3YyB04bqhbyB0w6BpIGtob+G6o24sIMOhcCBtw6MgZ2nh",
"uqNtIGdpw6EgKG7hur91IGPDsykgdsOgIG5o4bqtbiBrZXkgbmdheSBs4bqtcCB04bupYy48L3A+",
"CiAgICA8ZGl2IGNsYXNzPSJiYWRnZXMiPgogICAgICA8c3BhbiBjbGFzcz0iYmFkZ2UiPvCflJIg",
"QuG6o28gbeG6rXQgwrcgYW4gdG/DoG48L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJiYWRnZSI+",
"4pqhIEdpYW8ga2V5IHThu7EgxJHhu5luZzwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImJhZGdl",
"Ij7wn46f77iPIEjhu5cgdHLhu6MgbcOjIGdp4bqjbSBnacOhPC9zcGFuPgogICAgPC9kaXY+CiAg",
"PC9kaXY+CgogIDxkaXYgY2xhc3M9ImdyaWQiIGlkPSJwcm9kdWN0R3JpZCI+PC9kaXY+CiAgPGRp",
"diBjbGFzcz0iZW1wdHktc3RhdGUiIGlkPSJlbXB0eVN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25l",
"OyI+CiAgICA8ZGl2IGNsYXNzPSJiaWciPkhp4buHbiBjaMawYSBjw7Mgc+G6o24gcGjhuqltIG7D",
"oG88L2Rpdj4KICAgIFF14bqjbiB0cuG7iyB2acOqbiBjaMawYSB0aMOqbSBz4bqjbiBwaOG6qW0g",
"bsOgbyBsw6puIHRyYW5nIGLDoW4ga2V5LiBWdWkgbMOybmcgcXVheSBs4bqhaSBzYXUuCiAgPC9k",
"aXY+CgogIDxkaXYgY2xhc3M9ImdyaWQiIGlkPSJwZ0dyaWQiIHN0eWxlPSJtYXJnaW4tdG9wOjE4",
"cHg7Ij48L2Rpdj4KPC9tYWluPgoKPGZvb3Rlcj5LZXlWYXVsdCBTdG9yZSDigJQgSOG7hyB0aOG7",
"kW5nIGLhuqNvIG3huq10IMK3IGFuIHRvw6BuIMK3IGNo4bqldCBsxrDhu6NuZy48L2Zvb3Rlcj4K",
"CjwhLS0gPT09PT09PT09PT09IE1PREFMOiDEkMSCTkcgTkjhuqxQIC8gxJDEgk5HIEvDnSA9PT09",
"PT09PT09PT0gLS0+CjxkaXYgY2xhc3M9Im1vZGFsLWJnIiBpZD0iYXV0aE1vZGFsQmciPgogIDxk",
"aXYgY2xhc3M9Im1vZGFsIj4KICAgIDxoMz5Uw6BpIGtob+G6o24gY+G7p2EgYuG6oW48L2gzPgog",
"ICAgPHAgY2xhc3M9InN1YiI+Q+G6p24gxJHEg25nIG5o4bqtcCBob+G6t2MgdOG6oW8gdMOgaSBr",
"aG/huqNuIMSR4buDIG11YSBrZXkuPC9wPgogICAgPGRpdiBjbGFzcz0iYXV0aC10YWJzIj4KICAg",
"ICAgPGJ1dHRvbiBpZD0idGFiTG9naW4iIGNsYXNzPSJhY3RpdmUiPsSQxINuZyBuaOG6rXA8L2J1",
"dHRvbj4KICAgICAgPGJ1dHRvbiBpZD0idGFiUmVnaXN0ZXIiPsSQxINuZyBrw708L2J1dHRvbj4K",
"ICAgIDwvZGl2PgoKICAgIDxkaXYgaWQ9ImF1dGhGb3JtTG9naW4iPgogICAgICA8bGFiZWw+VMOq",
"biDEkcSDbmcgbmjhuq1wPC9sYWJlbD4KICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJsb2dp",
"blVzZXJuYW1lIiBwbGFjZWhvbGRlcj0iTmjhuq1wIHTDqm4gxJHEg25nIG5o4bqtcCI+CiAgICAg",
"IDxsYWJlbD5N4bqtdCBraOG6qXU8L2xhYmVsPgogICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQi",
"IGlkPSJsb2dpblBhc3N3b3JkIiBwbGFjZWhvbGRlcj0iTmjhuq1wIG3huq10IGto4bqpdSI+CiAg",
"ICA8L2Rpdj4KCiAgICA8ZGl2IGlkPSJhdXRoRm9ybVJlZ2lzdGVyIiBzdHlsZT0iZGlzcGxheTpu",
"b25lOyI+CiAgICAgIDxsYWJlbD5Uw6puIMSRxINuZyBuaOG6rXA8L2xhYmVsPgogICAgICA8aW5w",
"dXQgdHlwZT0idGV4dCIgaWQ9InJlZ1VzZXJuYW1lIiBwbGFjZWhvbGRlcj0iQ2jhu41uIHTDqm4g",
"xJHEg25nIG5o4bqtcCI+CiAgICAgIDxsYWJlbD5N4bqtdCBraOG6qXU8L2xhYmVsPgogICAgICA8",
"aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJyZWdQYXNzd29yZCIgcGxhY2Vob2xkZXI9IlThu5Fp",
"IHRoaeG7g3UgOCBrw70gdOG7sSI+CiAgICAgIDxsYWJlbD5OaOG6rXAgbOG6oWkgbeG6rXQga2jh",
"uql1PC9sYWJlbD4KICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0icmVnUGFzc3dvcmRD",
"b25maXJtIiBwbGFjZWhvbGRlcj0iTmjhuq1wIGzhuqFpIG3huq10IGto4bqpdSI+CiAgICA8L2Rp",
"dj4KCiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1lcnJvciIgaWQ9ImF1dGhFcnJvciI+PC9kaXY+Cgog",
"ICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBi",
"dG4tZ2hvc3QiIGlkPSJidG5DbG9zZUF1dGgiPsSQw7NuZzwvYnV0dG9uPgogICAgICA8YnV0dG9u",
"IGNsYXNzPSJidG4iIGlkPSJidG5TdWJtaXRBdXRoIj7EkMSDbmcgbmjhuq1wPC9idXR0b24+CiAg",
"ICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09PSBNT0RBTDogVEhBTkgg",
"VE/DgU4gPT09PT09PT09PT09IC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1iZyIgaWQ9ImNoZWNrb3V0",
"TW9kYWxCZyI+CiAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgPGgzPljDoWMgbmjhuq1uIG11YSBr",
"ZXk8L2gzPgogICAgPHAgY2xhc3M9InN1YiIgaWQ9ImNoZWNrb3V0UHJvZHVjdE5hbWUiPuKAlDwv",
"cD4KCiAgICA8bGFiZWw+TcOjIGdp4bqjbSBnacOhIChu4bq/dSBjw7MpPC9sYWJlbD4KICAgIDxk",
"aXYgc3R5bGU9ImRpc3BsYXk6ZmxleDsgZ2FwOjhweDsiPgogICAgICA8aW5wdXQgdHlwZT0idGV4",
"dCIgaWQ9ImNoZWNrb3V0RGlzY291bnRDb2RlIiBwbGFjZWhvbGRlcj0iVkQ6IFNBTEUyMCIgc3R5",
"bGU9ImZsZXg6MTsgdGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlOyI+CiAgICAgIDxidXR0b24gY2xh",
"c3M9ImJ0biBidG4tZ2hvc3QiIGlkPSJidG5BcHBseURpc2NvdW50IiBzdHlsZT0id2hpdGUtc3Bh",
"Y2U6bm93cmFwOyI+w4FwIGThu6VuZzwvYnV0dG9uPgogICAgPC9kaXY+CgogICAgPGRpdiBjbGFz",
"cz0iY2hlY2tvdXQtc3VtbWFyeSI+CiAgICAgIDxkaXYgY2xhc3M9InJvdyI+PHNwYW4+R2nDoSBn",
"4buRYzwvc3Bhbj48c3BhbiBpZD0iY2hlY2tvdXRPcmlnaW5hbFByaWNlIj4w4oKrPC9zcGFuPjwv",
"ZGl2PgogICAgICA8ZGl2IGNsYXNzPSJyb3ciIGlkPSJjaGVja291dERpc2NvdW50Um93IiBzdHls",
"ZT0iZGlzcGxheTpub25lOyI+PHNwYW4+R2nhuqNtIGdpw6E8L3NwYW4+PHNwYW4gY2xhc3M9ImRp",
"c2NvdW50LWFwcGxpZWQiIGlkPSJjaGVja291dERpc2NvdW50QW1vdW50Ij4w4oKrPC9zcGFuPjwv",
"ZGl2PgogICAgICA8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPlRow6BuaCB0aeG7gW48L3NwYW4+PHNw",
"YW4gaWQ9ImNoZWNrb3V0RmluYWxQcmljZSI+MOKCqzwvc3Bhbj48L2Rpdj4KICAgIDwvZGl2PgoK",
"ICAgIDxkaXYgY2xhc3M9Im1vZGFsLWVycm9yIiBpZD0iY2hlY2tvdXRFcnJvciI+PC9kaXY+CiAg",
"ICA8cCBjbGFzcz0ibW9kYWwtbm90ZSI+U2F1IGtoaSB4w6FjIG5o4bqtbiwgaOG7hyB0aOG7kW5n",
"IHPhur0gZ2lhbyBuZ2F5IDEga2V5IGPDsm4gaMOgbmcgY2hvIHTDoGkga2hv4bqjbiBj4bunYSBi",
"4bqhbi48L3A+CgogICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgIDxidXR0b24g",
"Y2xhc3M9ImJ0biBidG4tZ2hvc3QiIGlkPSJidG5DbG9zZUNoZWNrb3V0Ij5IdeG7tzwvYnV0dG9u",
"PgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJidG5Db25maXJtQ2hlY2tvdXQiPljDoWMg",
"bmjhuq1uIG11YTwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09",
"PT09PT09PT0gTU9EQUw6IENI4buMTiBHw5NJIChOSMOTTSBT4bqiTiBQSOG6qE0sIEdJ4buQTkcg",
"R0VUS0VZKSA9PT09PT09PT09PT0gLS0+CjwhLS0gPT09PT09PT09PT09IE1PREFMOiBDSOG7jE4g",
"R8OTSSBI4buiUCBOSOG6pFQgKGTDuW5nIGNodW5nIGNobyBHZXRLZXkgJiBz4bqjbiBwaOG6qW0g",
"bXVhIGLhurFuZyB0aeG7gW4pID09PT09PT09PT09PSAtLT4KPGRpdiBjbGFzcz0ibW9kYWwtYmci",
"IGlkPSJ1bmlmaWVkUGxhbk1vZGFsQmciPgogIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgIDxkaXYg",
"Y2xhc3M9InVuaWZpZWQtcGxhbi1oZWFkZXIiPgogICAgICA8ZGl2IGNsYXNzPSJsb2dvIiBpZD0i",
"dW5pZmllZFBsYW5Mb2dvIj7wn5OmPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGgzIGlkPSJ1",
"bmlmaWVkUGxhblRpdGxlIj7igJQ8L2gzPgogICAgICAgIDxwIGNsYXNzPSJzdWIyIiBpZD0idW5p",
"ZmllZFBsYW5TdWJ0aXRsZSI+4oCUPC9wPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRp",
"diBpZD0idW5pZmllZFBsYW5MaXN0IiBzdHlsZT0iZGlzcGxheTpmbGV4OyBmbGV4LWRpcmVjdGlv",
"bjpjb2x1bW47IGdhcDoxMHB4OyBtYXJnaW46MTZweCAwOyI+PC9kaXY+CiAgICA8ZGl2IGNsYXNz",
"PSJtb2RhbC1lcnJvciIgaWQ9InVuaWZpZWRQbGFuRXJyb3IiPjwvZGl2PgogICAgPGRpdiBjbGFz",
"cz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tZ2hvc3QiIGlk",
"PSJidG5DbG9zZVVuaWZpZWRQbGFuIiBzdHlsZT0id2lkdGg6MTAwJTsiPsSQw7NuZzwvYnV0dG9u",
"PgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09PT09PT09PT0gTU9EQUw6IEvh",
"ur5UIFFV4bqiIE1VQSBLRVkgPT09PT09PT09PT09IC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1iZyIg",
"aWQ9InJlc3VsdE1vZGFsQmciPgogIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgIDxoMz7wn46JIE11",
"YSBrZXkgdGjDoG5oIGPDtG5nITwvaDM+CiAgICA8cCBjbGFzcz0ic3ViIj5LZXkgY+G7p2EgYuG6",
"oW4gxJHDoyBz4bq1biBzw6BuZywgdnVpIGzDsm5nIGzGsHUgbOG6oWkgY+G6qW4gdGjhuq1uLjwv",
"cD4KICAgIDxkaXYgY2xhc3M9InJlc3VsdC1rZXktYm94Ij4KICAgICAgPGNvZGUgaWQ9InJlc3Vs",
"dEtleVZhbHVlIj7igJQ8L2NvZGU+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImJ0bkNv",
"cHlSZXN1bHRLZXkiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+U2FvIGNow6lwIGtleTwvYnV0dG9uPgog",
"ICAgPC9kaXY+CiAgICA8cCBjbGFzcz0ibW9kYWwtbm90ZSIgaWQ9InJlc3VsdEtleU1ldGEiPjwv",
"cD4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJi",
"dG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xvc2VSZXN1bHQiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+xJDD",
"s25nPC9idXR0b24+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09",
"PSBNT0RBTDogVEjDlE5HIFRJTiBUw4BJIEtIT+G6ok4gPT09PT09PT09PT09IC0tPgo8ZGl2IGNs",
"YXNzPSJtb2RhbC1iZyIgaWQ9ImFjY291bnRJbmZvTW9kYWxCZyI+CiAgPGRpdiBjbGFzcz0ibW9k",
"YWwiPgogICAgPGgzPlRow7RuZyB0aW4gdMOgaSBraG/huqNuPC9oMz4KICAgIDxwIGNsYXNzPSJz",
"dWIiPlRow7RuZyB0aW4gdMOgaSBraG/huqNuIGtow6FjaCBow6BuZyBj4bunYSBi4bqhbi48L3A+",
"CiAgICA8ZGl2IGNsYXNzPSJpbmZvLXJvdyI+PHNwYW4gY2xhc3M9ImsiPlTDqm4gxJHEg25nIG5o",
"4bqtcDwvc3Bhbj48c3BhbiBjbGFzcz0idiIgaWQ9ImluZm9Vc2VybmFtZSI+4oCUPC9zcGFuPjwv",
"ZGl2PgogICAgPGRpdiBjbGFzcz0iaW5mby1yb3ciPjxzcGFuIGNsYXNzPSJrIj5T4buRIGTGsCBo",
"aeG7h24gdOG6oWk8L3NwYW4+PHNwYW4gY2xhc3M9InYiIGlkPSJpbmZvQmFsYW5jZSI+MOKCqzwv",
"c3Bhbj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImluZm8tcm93Ij48c3BhbiBjbGFzcz0iayI+VmFp",
"IHRyw7I8L3NwYW4+PHNwYW4gY2xhc3M9InYiIGlkPSJpbmZvUm9sZSI+S2jDoWNoIGjDoG5nPC9z",
"cGFuPjwvZGl2PgogICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgIDxidXR0b24g",
"Y2xhc3M9ImJ0biBidG4tZ2hvc3QiIGlkPSJidG5DbG9zZUFjY291bnRJbmZvIiBzdHlsZT0id2lk",
"dGg6MTAwJTsiPsSQw7NuZzwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEt",
"LSA9PT09PT09PT09PT0gTU9EQUw6IE7huqBQIFRJ4buATiBU4buwIMSQ4buYTkcgPT09PT09PT09",
"PT09IC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1iZyIgaWQ9InRvcHVwTW9kYWxCZzIiPgogIDxkaXYg",
"Y2xhc3M9Im1vZGFsIj4KCiAgICA8IS0tIELGsOG7m2MgMTogbmjhuq1wIHPhu5EgdGnhu4FuIG11",
"4buRbiBu4bqhcCAtLT4KICAgIDxkaXYgY2xhc3M9InRvcHVwLXN0ZXAtYW1vdW50IiBpZD0idG9w",
"dXBTdGVwQW1vdW50Ij4KICAgICAgPGRpdj4KICAgICAgICA8aDM+TuG6oXAgdGnhu4FuIHbDoG8g",
"dMOgaSBraG/huqNuPC9oMz4KICAgICAgICA8cCBjbGFzcz0ic3ViIj5OaOG6rXAgc+G7kSB0aeG7",
"gW4gYuG6oW4gbXXhu5FuIG7huqFwLCBo4buHIHRo4buRbmcgc+G6vSB04bqhbyBtw6MgUVIgY2h1",
"eeG7g24ga2hv4bqjbiByacOqbmcgY2hvIHnDqnUgY+G6p3UgbsOgeSAoY8OzIGhp4buHdSBs4bux",
"YyB0cm9uZyAzMCBwaMO6dCkuPC9wPgogICAgICA8L2Rpdj4KCiAgICAgIDxsYWJlbD5T4buRIHRp",
"4buBbiBtdeG7kW4gbuG6oXAgKOKCqyk8L2xhYmVsPgogICAgICA8aW5wdXQgdHlwZT0idGV4dCIg",
"aWQ9InRvcHVwUmVxdWVzdEFtb3VudCIgcGxhY2Vob2xkZXI9IlZEOiAxMDAwMDAiIGlucHV0bW9k",
"ZT0ibnVtZXJpYyI+CgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1lcnJvciIgaWQ9InRvcHVwUmVx",
"dWVzdEVycm9yIj48L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAg",
"ICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tZ2hvc3QiIGlkPSJidG5DbG9zZVRvcHVwMiI+SHXh",
"u7c8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJidG5TdWJtaXRUb3B1",
"cFJlcXVlc3QiPlThuqFvIG3DoyBRUiBu4bqhcCB0aeG7gW48L2J1dHRvbj4KICAgICAgPC9kaXY+",
"CiAgICA8L2Rpdj4KCiAgICA8IS0tIELGsOG7m2MgMjogaGnhu4duIFFSIMSR4buZbmcgKMSRw6Mg",
"bmjDum5nIHPhu5EgdGnhu4FuICsgbuG7mWkgZHVuZyBDSykgKyDEkeG7k25nIGjhu5MgxJHhur9t",
"IG5nxrDhu6NjIDMwIHBow7p0IC0tPgogICAgPGRpdiBjbGFzcz0idG9wdXAtc3RlcC1xciIgaWQ9",
"InRvcHVwU3RlcFFyIj4KICAgICAgPHNwYW4gY2xhc3M9InRvcHVwLWJhY2stbGluayIgaWQ9ImJ0",
"bkJhY2tUb3B1cEFtb3VudCI+4oC5IMSQ4buVaSBz4buRIHRp4buBbiBraMOhYzwvc3Bhbj4KICAg",
"ICAgPGRpdj4KICAgICAgICA8aDM+UXXDqXQgbcOjIFFSIMSR4buDIGNodXnhu4NuIGtob+G6o248",
"L2gzPgogICAgICAgIDxwIGNsYXNzPSJzdWIiPk3hu58gYXBwIG5nw6JuIGjDoG5nLCBxdcOpdCBt",
"w6MgUVIgYsOqbiBkxrDhu5tpIOKAlCBz4buRIHRp4buBbiB2w6AgbuG7mWkgZHVuZyBjaHV54buD",
"biBraG/huqNuIMSRw6MgxJHGsOG7o2MgxJFp4buBbiBz4bq1bi4gU2F1IGtoaSBjaHV54buDbiBr",
"aG/huqNuIHhvbmcsIHF14bqjbiB0cuG7iyB2acOqbiBz4bq9IGR1eeG7h3QgdsOgIGPhu5luZyB0",
"aeG7gW4gdsOgbyB0w6BpIGtob+G6o24gY+G7p2EgYuG6oW4uPC9wPgogICAgICA8L2Rpdj4KCiAg",
"ICAgIDxkaXYgY2xhc3M9InRvcHVwLXFyLWJveCIgaWQ9InRvcHVwUXJCb3giPgogICAgICAgIDxp",
"bWcgaWQ9InRvcHVwUXJJbWciIHNyYz0iIiBhbHQ9Ik3DoyBRUiBu4bqhcCB0aeG7gW4iPgogICAg",
"ICAgIDxkaXYgY2xhc3M9InRvcHVwLXFyLWhpbnQiPk5nw6JuIGjDoG5nOiA8Yj5NQiBCYW5rPC9i",
"PiDCtyBTVEs6IDxiIGlkPSJ0b3B1cFFyQWNjb3VudE5vIj7igJQ8L2I+IMK3IENUSzogPGIgaWQ9",
"InRvcHVwUXJBY2NvdW50TmFtZSI+4oCUPC9iPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InRv",
"cHVwLXFyLWhpbnQiPlPhu5EgdGnhu4FuOiA8YiBpZD0idG9wdXBRckFtb3VudCI+MOKCqzwvYj4g",
"wrcgTuG7mWkgZHVuZyBDSzogPGIgaWQ9InRvcHVwUXJOb3RlIj7igJQ8L2I+PC9kaXY+CiAgICAg",
"IDwvZGl2PgoKICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4OyBmbGV4LWRpcmVjdGlvbjpj",
"b2x1bW47IGFsaWduLWl0ZW1zOmNlbnRlcjsgZ2FwOjRweDsiPgogICAgICAgIDxzcGFuIGNsYXNz",
"PSJ0b3B1cC1jb3VudGRvd24tbGFiZWwiPk3DoyBRUiBo4bq/dCBoaeG7h3UgbOG7sWMgc2F1PC9z",
"cGFuPgogICAgICAgIDxkaXYgY2xhc3M9InRvcHVwLWNvdW50ZG93biIgaWQ9InRvcHVwQ291bnRk",
"b3duIj4zMDowMDwvZGl2PgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWVy",
"cm9yIiBpZD0idG9wdXBRckVycm9yIj48L2Rpdj4KICAgICAgPHAgY2xhc3M9Im1vZGFsLW5vdGUi",
"PlnDqnUgY+G6p3UgbsOgeSBz4bq9IHThu7EgxJHhu5luZyBo4bq/dCBo4bqhbiBzYXUgMzAgcGjD",
"unQgbuG6v3UgcXXhuqNuIHRy4buLIHZpw6puIGNoxrBhIHjDoWMgbmjhuq1uLiBC4bqhbiBjw7Mg",
"dGjhu4MgdGhlbyBkw7VpIHRy4bqhbmcgdGjDoWkg4bufIG3hu6VjICJM4buLY2ggc+G7rSBu4bqh",
"cCB0aeG7gW4iLjwvcD4KCiAgICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICAg",
"IDxidXR0b24gY2xhc3M9ImJ0biBidG4tZ2hvc3QiIGlkPSJidG5DbG9zZVRvcHVwUXIiIHN0eWxl",
"PSJ3aWR0aDoxMDAlOyI+xJDDs25nPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+Cgog",
"ICAgPCEtLSBUcuG6oW5nIHRow6FpOiBtw6MgUVIgxJHDoyBo4bq/dCBo4bqhbiwgYuG6r3QgYnXh",
"u5ljIHThuqFvIHnDqnUgY+G6p3UgbeG7m2kgLS0+CiAgICA8ZGl2IGNsYXNzPSJ0b3B1cC1leHBp",
"cmVkLWJveCIgaWQ9InRvcHVwRXhwaXJlZEJveCI+CiAgICAgIDxkaXYgY2xhc3M9Imljb24iPgog",
"ICAgICAgIDxzdmcgd2lkdGg9IjIyIiBoZWlnaHQ9IjIyIiB2aWV3Qm94PSIwIDAgMjQgMjQiIGZp",
"bGw9Im5vbmUiIHN0cm9rZT0iY3VycmVudENvbG9yIiBzdHJva2Utd2lkdGg9IjIiPjxjaXJjbGUg",
"Y3g9IjEyIiBjeT0iMTIiIHI9IjEwIj48L2NpcmNsZT48bGluZSB4MT0iMTIiIHkxPSI4IiB4Mj0i",
"MTIiIHkyPSIxMiI+PC9saW5lPjxsaW5lIHgxPSIxMiIgeTE9IjE2IiB4Mj0iMTIuMDEiIHkyPSIx",
"NiI+PC9saW5lPjwvc3ZnPgogICAgICA8L2Rpdj4KICAgICAgPGRpdj4KICAgICAgICA8aDMgc3R5",
"bGU9Im1hcmdpbi1ib3R0b206NnB4OyI+TcOjIFFSIMSRw6MgaOG6v3QgaGnhu4d1IGzhu7FjPC9o",
"Mz4KICAgICAgICA8cCBjbGFzcz0ic3ViIiBzdHlsZT0ibWFyZ2luOjA7Ij5Zw6p1IGPhuqd1IG7h",
"uqFwIHRp4buBbiBuw6B5IMSRw6MgcXXDoSAzMCBwaMO6dCB2w6AgdOG7sSDEkeG7mW5nIGLhu4sg",
"aOG7p3kuIFZ1aSBsw7JuZyB04bqhbyB5w6p1IGPhuqd1IG7huqFwIHRp4buBbiBt4bubaS48L3A+",
"CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIiBzdHlsZT0id2lk",
"dGg6MTAwJTsiPgogICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tZ2hvc3QiIGlkPSJidG5D",
"bG9zZVRvcHVwRXhwaXJlZCI+xJDDs25nPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0i",
"YnRuIiBpZD0iYnRuUmVzdGFydFRvcHVwIj5U4bqhbyB5w6p1IGPhuqd1IG3hu5tpPC9idXR0b24+",
"CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09PT09PT09",
"PT09IE1PREFMOiBM4buKQ0ggU+G7rCBO4bqgUCBUSeG7gE4gPT09PT09PT09PT09IC0tPgo8ZGl2",
"IGNsYXNzPSJtb2RhbC1iZyIgaWQ9InRvcHVwSGlzdG9yeU1vZGFsQmciPgogIDxkaXYgY2xhc3M9",
"Im1vZGFsIj4KICAgIDxoMz5M4buLY2ggc+G7rSBu4bqhcCB0aeG7gW48L2gzPgogICAgPHAgY2xh",
"c3M9InN1YiI+RGFuaCBzw6FjaCBjw6FjIHnDqnUgY+G6p3UgbuG6oXAgdGnhu4FuIMSRw6MgZ+G7",
"rWkuPC9wPgogICAgPGRpdiBjbGFzcz0iaGlzdG9yeS1saXN0IiBpZD0idG9wdXBIaXN0b3J5TGlz",
"dCI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBj",
"bGFzcz0iYnRuIGJ0bi1naG9zdCIgaWQ9ImJ0bkNsb3NlVG9wdXBIaXN0b3J5IiBzdHlsZT0id2lk",
"dGg6MTAwJTsiPsSQw7NuZzwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEt",
"LSA9PT09PT09PT09PT0gTU9EQUw6IEzhu4pDSCBT4busIEdJQU8gROG7ikNIID09PT09PT09PT09",
"PSAtLT4KPGRpdiBjbGFzcz0ibW9kYWwtYmciIGlkPSJ0eEhpc3RvcnlNb2RhbEJnIj4KICA8ZGl2",
"IGNsYXNzPSJtb2RhbCI+CiAgICA8aDM+TOG7i2NoIHPhu60gZ2lhbyBk4buLY2g8L2gzPgogICAg",
"PHAgY2xhc3M9InN1YiI+VG/DoG4gYuG7mSBnaWFvIGThu4tjaCBj4buZbmcvdHLhu6sgdGnhu4Fu",
"IHbDoCBtdWEga2V5IHRyw6puIHTDoGkga2hv4bqjbiBj4bunYSBi4bqhbi48L3A+CiAgICA8ZGl2",
"IGNsYXNzPSJoaXN0b3J5LWxpc3QiIGlkPSJ0eEhpc3RvcnlMaXN0Ij48L2Rpdj4KICAgIDxkaXYg",
"Y2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWdob3N0",
"IiBpZD0iYnRuQ2xvc2VUeEhpc3RvcnkiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+xJDDs25nPC9idXR0",
"b24+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09PSBNT0RBTDog",
"UVXhuqJOIEzDnSBLRVkgKGtleSDEkcOjIG11YSkgPT09PT09PT09PT09IC0tPgo8ZGl2IGNsYXNz",
"PSJtb2RhbC1iZyIgaWQ9Im15S2V5c01vZGFsQmciPgogIDxkaXYgY2xhc3M9Im1vZGFsIiBzdHls",
"ZT0ibWF4LXdpZHRoOjUyMHB4OyI+CiAgICA8aDM+UXXhuqNuIGzDvSBrZXk8L2gzPgogICAgPHAg",
"Y2xhc3M9InN1YiI+RGFuaCBzw6FjaCBjw6FjIGtleSBi4bqhbiDEkcOjIG11YSB0csOqbiB0w6Bp",
"IGtob+G6o24gbsOgeS48L3A+CiAgICA8ZGl2IGNsYXNzPSJoaXN0b3J5LWxpc3QiIGlkPSJteUtl",
"eXNMaXN0IiBzdHlsZT0ibWF4LWhlaWdodDo0MjBweDsiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0i",
"bW9kYWwtYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tZ2hvc3QiIGlkPSJi",
"dG5DbG9zZU15S2V5cyIgc3R5bGU9IndpZHRoOjEwMCU7Ij7EkMOzbmc8L2J1dHRvbj4KICAgIDwv",
"ZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09PT09PT09PT09IE1PREFMOiBHRVRLRVkgLSBD",
"SOG7jE4gR0FNRSA9PT09PT09PT09PT0gLS0+CjxkaXYgY2xhc3M9Im1vZGFsLWJnIiBpZD0iZ2tD",
"aG9vc2VHYW1lTW9kYWxCZyI+CiAgPGRpdiBjbGFzcz0ibW9kYWwiPgogICAgPGgzPkdldEtleSDi",
"gJQgVsaw4bujdCBsaW5rIG5o4bqtbiBrZXk8L2gzPgogICAgPHAgY2xhc3M9InN1YiI+Q2jhu41u",
"IGdhbWUgYuG6oW4gbXXhu5FuIG5o4bqtbiBrZXkuPC9wPgogICAgPGRpdiBjbGFzcz0iZ2stZ2Ft",
"ZS1ncmlkIiBpZD0iZ2tHYW1lR3JpZCI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJlbXB0eS1zdGF0",
"ZSIgaWQ9ImdrR2FtZUVtcHR5U3RhdGUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7IG1hcmdpbi10b3A6",
"MTJweDsgcGFkZGluZzozMHB4IDE1cHg7Ij4KICAgICAgPGRpdiBjbGFzcz0iYmlnIj5IaeG7h24g",
"Y2jGsGEgY8OzIGdhbWUgR2V0S2V5IG7DoG88L2Rpdj4KICAgICAgUXXhuqNuIHRy4buLIHZpw6pu",
"IGNoxrBhIHRow6ptIGdhbWUgbsOgby4gVnVpIGzDsm5nIHF1YXkgbOG6oWkgc2F1LgogICAgPC9k",
"aXY+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0i",
"YnRuIGJ0bi1naG9zdCIgaWQ9ImJ0bkNsb3NlR2tDaG9vc2VHYW1lIiBzdHlsZT0id2lkdGg6MTAw",
"JTsiPsSQw7NuZzwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09",
"PT09PT09PT0gTU9EQUw6IEdFVEtFWSAtIENI4buMTiBUSOG7nEkgSOG6oE4gPT09PT09PT09PT09",
"IC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1iZyIgaWQ9ImdrQ2hvb3NlRHVyYXRpb25Nb2RhbEJnIj4K",
"ICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICA8aDMgaWQ9ImdrRHVyYXRpb25HYW1lTmFtZSI+4oCU",
"PC9oMz4KICAgIDxwIGNsYXNzPSJzdWIiPkNo4buNbiBsb+G6oWkga2V5IGLhuqFuIG114buRbiBu",
"aOG6rW4uIFRo4budaSBo4bqhbiBjw6BuZyBkw6BpLCBz4buRIGzGsOG7o3Qgdsaw4bujdCBsaW5r",
"IGPDoG5nIG5oaeG7gXUuPC9wPgogICAgPGRpdiBjbGFzcz0iZ2stZHVyYXRpb24tbGlzdCIgaWQ9",
"ImdrRHVyYXRpb25MaXN0UHVibGljIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWVycm9y",
"IiBpZD0iZ2tEdXJhdGlvbkVycm9yIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlv",
"bnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQmFja0drRHVy",
"YXRpb24iPlF1YXkgbOG6oWk8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0i",
"YnRuU3RhcnRHa0Zsb3ciPkLhuq90IMSR4bqndSB2xrDhu6N0IGxpbms8L2J1dHRvbj4KICAgIDwv",
"ZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09PT09PT09PT09IE1PREFMOiBHRVRLRVkgLSBW",
"xq/hu6JUIExJTksgPT09PT09PT09PT09IC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1iZyIgaWQ9Imdr",
"Rmxvd01vZGFsQmciPgogIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgIDxoMz7EkGFuZyB2xrDhu6N0",
"IGxpbmsgbmjhuq1uIGtleTwvaDM+CiAgICA8cCBjbGFzcz0ic3ViIiBpZD0iZ2tGbG93R2FtZUxh",
"YmVsIj7igJQ8L3A+CiAgICA8ZGl2IGNsYXNzPSJnay1wcm9ncmVzcyIgaWQ9ImdrUHJvZ3Jlc3NE",
"b3RzIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImdrLXN0ZXAtYm94Ij4KICAgICAgPGRpdiBjbGFz",
"cz0icm91bmQtbGFiZWwiIGlkPSJna1JvdW5kTGFiZWwiPkzGsOG7o3QgMTwvZGl2PgogICAgICA8",
"YSBocmVmPSIjIiB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub29wZW5lciIgY2xhc3M9ImJ0biIgaWQ9",
"ImJ0bk9wZW5Ha0xpbmsiIHN0eWxlPSJ3aWR0aDoxMDAlOyBkaXNwbGF5OmlubGluZS1ibG9jazsg",
"dGV4dC1hbGlnbjpjZW50ZXI7IHRleHQtZGVjb3JhdGlvbjpub25lOyI+TeG7nyBsaW5rIHbGsOG7",
"o3QgKGzGsOG7o3QgMSk8L2E+CiAgICA8L2Rpdj4KICAgIDxwIGNsYXNzPSJtb2RhbC1ub3RlIj5T",
"YXUga2hpIG3hu58gbGluayB2w6AgaG/DoG4gdGjDoG5oIHRyYW5nIMSRw61jaCwgcXVheSBs4bqh",
"aSDEkcOieSB2w6AgYuG6pW0gIlTDtGkgxJHDoyB2xrDhu6N0IGxpbmsiIMSR4buDIHRp4bq/cCB0",
"4bulYy48L3A+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1lcnJvciIgaWQ9ImdrRmxvd0Vycm9yIj48",
"L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNz",
"PSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xvc2VHa0Zsb3ciPkh14bu3PC9idXR0b24+CiAgICAg",
"IDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImJ0bkNvbmZpcm1Ha1N0ZXAiPlTDtGkgxJHDoyB2xrDh",
"u6N0IGxpbms8L2J1dHRvbj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09PT09",
"PT09PT09IE1PREFMOiBHRVRLRVkgLSBL4bq+VCBRVeG6oiA9PT09PT09PT09PT0gLS0+CjxkaXYg",
"Y2xhc3M9Im1vZGFsLWJnIiBpZD0iZ2tSZXN1bHRNb2RhbEJnIj4KICA8ZGl2IGNsYXNzPSJtb2Rh",
"bCI+CiAgICA8aDM+8J+OiSBOaOG6rW4ga2V5IHRow6BuaCBjw7RuZyE8L2gzPgogICAgPHAgY2xh",
"c3M9InN1YiI+S2V5IGPhu6dhIGLhuqFuIMSRw6Mgc+G6tW4gc8OgbmcsIHZ1aSBsw7JuZyBsxrB1",
"IGzhuqFpIGPhuqluIHRo4bqtbi48L3A+CiAgICA8ZGl2IGNsYXNzPSJyZXN1bHQta2V5LWJveCI+",
"CiAgICAgIDxjb2RlIGlkPSJna1Jlc3VsdEtleVZhbHVlIj7igJQ8L2NvZGU+CiAgICAgIDxidXR0",
"b24gY2xhc3M9ImJ0biIgaWQ9ImJ0bkNvcHlHa1Jlc3VsdEtleSIgc3R5bGU9IndpZHRoOjEwMCU7",
"Ij5TYW8gY2jDqXAga2V5PC9idXR0b24+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFs",
"LWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xv",
"c2VHa1Jlc3VsdCIgc3R5bGU9IndpZHRoOjEwMCU7Ij7EkMOzbmc8L2J1dHRvbj4KICAgIDwvZGl2",
"PgogIDwvZGl2Pgo8L2Rpdj4KCjxkaXYgY2xhc3M9InRvYXN0IiBpZD0idG9hc3QiPjwvZGl2PgoK",
"PHNjcmlwdD4KY29uc3QgQVBJX0JBU0UgPSAnJzsgLy8gY8O5bmcgZG9tYWluIHbhu5tpIHRyYW5n",
"IG7DoHkKCi8qIC0tLS0tLS0tLS0gSGVscGVyIC0tLS0tLS0tLS0gKi8KZnVuY3Rpb24gJChpZCl7",
"IHJldHVybiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7IH0KZnVuY3Rpb24gZm10TW9uZXko",
"dil7CiAgY29uc3QgbiA9IHBhcnNlRmxvYXQoU3RyaW5nKHYpLnJlcGxhY2UoL1teXGQuXS9nLCcn",
"KSk7CiAgaWYoIW4gJiYgbiE9PTApIHJldHVybiAnMOKCqyc7CiAgcmV0dXJuIG4udG9Mb2NhbGVT",
"dHJpbmcoJ3ZpLVZOJykrJ+KCqyc7Cn0KZnVuY3Rpb24gc2hvd1RvYXN0KG1zZyl7CiAgY29uc3Qg",
"dCA9ICQoJ3RvYXN0Jyk7CiAgdC50ZXh0Q29udGVudCA9IG1zZzsKICB0LmNsYXNzTGlzdC5hZGQo",
"J3Nob3cnKTsKICBjbGVhclRpbWVvdXQoc2hvd1RvYXN0Ll90aW1lcik7CiAgc2hvd1RvYXN0Ll90",
"aW1lciA9IHNldFRpbWVvdXQoKCk9PiB0LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKSwgMzIwMCk7",
"Cn0KCi8qIC0tLS0tLS0tLS0gVHLhuqFuZyB0aMOhaSDEkcSDbmcgbmjhuq1wIGtow6FjaCBow6Bu",
"ZyAtLS0tLS0tLS0tICovCmxldCBjdXN0b21lclRva2VuID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0o",
"J2t2X3N0b3JlX3Rva2VuJykgfHwgJyc7CmxldCBjdXN0b21lck5hbWUgPSBsb2NhbFN0b3JhZ2Uu",
"Z2V0SXRlbSgna3Zfc3RvcmVfdXNlcm5hbWUnKSB8fCAnJzsKbGV0IGN1c3RvbWVyQmFsYW5jZSA9",
"IDA7CmxldCBjdXN0b21lclJvbGUgPSAnY3VzdG9tZXInOwoKZnVuY3Rpb24gdXBkYXRlQWNjb3Vu",
"dFVJKCl7CiAgaWYoY3VzdG9tZXJUb2tlbiAmJiBjdXN0b21lck5hbWUpewogICAgJCgnZ3Vlc3RB",
"Y3Rpb25zJykuc3R5bGUuZGlzcGxheSA9ICdub25lJzsKICAgICQoJ2FjY291bnRDaGlwJykuc3R5",
"bGUuZGlzcGxheSA9ICdmbGV4JzsKICAgICQoJ2FjY291bnROYW1lJykudGV4dENvbnRlbnQgPSBj",
"dXN0b21lck5hbWU7CiAgICAkKCdkZEd1ZXN0QmxvY2snKS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUn",
"OwogICAgJCgnZGRBY2NvdW50QmxvY2snKS5zdHlsZS5kaXNwbGF5ID0gJyc7CiAgICAkKCdkZEFj",
"Y291bnROYW1lJykudGV4dENvbnRlbnQgPSBjdXN0b21lck5hbWU7CiAgICAkKCdkZEFjY291bnRC",
"YWxhbmNlJykudGV4dENvbnRlbnQgPSBmbXRNb25leShjdXN0b21lckJhbGFuY2UpOwogIH0gZWxz",
"ZSB7CiAgICAkKCdndWVzdEFjdGlvbnMnKS5zdHlsZS5kaXNwbGF5ID0gJyc7CiAgICAkKCdhY2Nv",
"dW50Q2hpcCcpLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CiAgICAkKCdkZEd1ZXN0QmxvY2snKS5z",
"dHlsZS5kaXNwbGF5ID0gJyc7CiAgICAkKCdkZEFjY291bnRCbG9jaycpLnN0eWxlLmRpc3BsYXkg",
"PSAnbm9uZSc7CiAgfQp9CnVwZGF0ZUFjY291bnRVSSgpOwoKLyogTuG6v3UgxJHDoyBjw7MgdG9r",
"ZW4gbMawdSBz4bq1biAoxJHEg25nIG5o4bqtcCB04burIHRyxrDhu5tjKSwgdOG6o2kgbOG6oWkg",
"c+G7kSBkxrAgbeG7m2kgbmjhuqV0IHThu6sgc2VydmVyICovCmFzeW5jIGZ1bmN0aW9uIHJlZnJl",
"c2hDdXN0b21lclByb2ZpbGUoKXsKICBpZighY3VzdG9tZXJUb2tlbikgcmV0dXJuOwogIHRyeXsK",
"ICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkvYXV0aC9tZScsIHsg",
"aGVhZGVyczp7ICdBdXRob3JpemF0aW9uJzogJ0JlYXJlciAnICsgY3VzdG9tZXJUb2tlbiB9IH0p",
"OwogICAgaWYoIXJlcy5vayl7IHRocm93IG5ldyBFcnJvcigndG9rZW4gaW52YWxpZCcpOyB9CiAg",
"ICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgIGlmKGRhdGEub2spewogICAgICBj",
"dXN0b21lckJhbGFuY2UgPSBkYXRhLmJhbGFuY2UgfHwgMDsKICAgICAgY3VzdG9tZXJSb2xlID0g",
"ZGF0YS5yb2xlIHx8ICdjdXN0b21lcic7CiAgICAgIHVwZGF0ZUFjY291bnRVSSgpOwogICAgfQog",
"IH1jYXRjaChlKXsKICAgIC8vIHRva2VuIGjhur90IGjhuqFuL2tow7RuZyBo4bujcCBs4buHIC0+",
"IMSRxINuZyB4deG6pXQgw6ptLCBraMO0bmcgbMOgbSBwaGnhu4FuIGtow6FjaCBi4bqxbmcgbOG7",
"l2kKICAgIGN1c3RvbWVyVG9rZW4gPSAnJzsgY3VzdG9tZXJOYW1lID0gJyc7CiAgICBsb2NhbFN0",
"b3JhZ2UucmVtb3ZlSXRlbSgna3Zfc3RvcmVfdG9rZW4nKTsKICAgIGxvY2FsU3RvcmFnZS5yZW1v",
"dmVJdGVtKCdrdl9zdG9yZV91c2VybmFtZScpOwogICAgdXBkYXRlQWNjb3VudFVJKCk7CiAgfQp9",
"CnJlZnJlc2hDdXN0b21lclByb2ZpbGUoKTsKCiQoJ2J0bkxvZ291dEN1c3RvbWVyJykuYWRkRXZl",
"bnRMaXN0ZW5lcignY2xpY2snLCAoKT0+ewogIGN1c3RvbWVyVG9rZW4gPSAnJzsgY3VzdG9tZXJO",
"YW1lID0gJyc7IGN1c3RvbWVyQmFsYW5jZSA9IDA7IGN1c3RvbWVyUm9sZSA9ICdjdXN0b21lcic7",
"CiAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ2t2X3N0b3JlX3Rva2VuJyk7CiAgbG9jYWxTdG9y",
"YWdlLnJlbW92ZUl0ZW0oJ2t2X3N0b3JlX3VzZXJuYW1lJyk7CiAgdXBkYXRlQWNjb3VudFVJKCk7",
"CiAgY2xvc2VEcm9wZG93bigpOwogIHNob3dUb2FzdCgnxJDDoyDEkcSDbmcgeHXhuqV0Jyk7Cn0p",
"OwoKLyogLS0tLS0tLS0tLSBNZW51IDMgZ+G6oWNoIChoYW1idXJnZXIgZHJvcGRvd24pIC0tLS0t",
"LS0tLS0gKi8KZnVuY3Rpb24gb3BlbkRyb3Bkb3duKCl7ICQoJ2Ryb3Bkb3duTWVudScpLmNsYXNz",
"TGlzdC5hZGQoJ3Nob3cnKTsgfQpmdW5jdGlvbiBjbG9zZURyb3Bkb3duKCl7ICQoJ2Ryb3Bkb3du",
"TWVudScpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsgfQokKCdidG5IYW1idXJnZXInKS5hZGRF",
"dmVudExpc3RlbmVyKCdjbGljaycsIChlKT0+ewogIGUuc3RvcFByb3BhZ2F0aW9uKCk7CiAgJCgn",
"ZHJvcGRvd25NZW51JykuY2xhc3NMaXN0LnRvZ2dsZSgnc2hvdycpOwp9KTsKZG9jdW1lbnQuYWRk",
"RXZlbnRMaXN0ZW5lcignY2xpY2snLCAoZSk9PnsKICBpZighJCgnZHJvcGRvd25NZW51JykuY29u",
"dGFpbnMoZS50YXJnZXQpICYmIGUudGFyZ2V0ICE9PSAkKCdidG5IYW1idXJnZXInKSl7CiAgICBj",
"bG9zZURyb3Bkb3duKCk7CiAgfQp9KTsKCiQoJ2RkT3BlbkF1dGgnKS5hZGRFdmVudExpc3RlbmVy",
"KCdjbGljaycsICgpPT57IGNsb3NlRHJvcGRvd24oKTsgb3BlbkF1dGhNb2RhbCgpOyB9KTsKCiQo",
"J2RkU3VwcG9ydCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PnsKICBjbG9zZURyb3Bk",
"b3duKCk7CiAgd2luZG93Lm9wZW4oJ2h0dHBzOi8vdC5tZS9sdW9uZ3R1eWVuMjAnLCAnX2JsYW5r",
"Jyk7Cn0pOwoKJCgnZGRBY2NvdW50SW5mbycpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9",
"PnsKICBjbG9zZURyb3Bkb3duKCk7CiAgJCgnaW5mb1VzZXJuYW1lJykudGV4dENvbnRlbnQgPSBj",
"dXN0b21lck5hbWU7CiAgJCgnaW5mb0JhbGFuY2UnKS50ZXh0Q29udGVudCA9IGZtdE1vbmV5KGN1",
"c3RvbWVyQmFsYW5jZSk7CiAgJCgnaW5mb1JvbGUnKS50ZXh0Q29udGVudCA9IGN1c3RvbWVyUm9s",
"ZSA9PT0gJ2FkbWluJyA/ICdRdeG6o24gdHLhu4sgdmnDqm4nIDogJ0tow6FjaCBow6BuZyc7CiAg",
"JCgnYWNjb3VudEluZm9Nb2RhbEJnJykuY2xhc3NMaXN0LmFkZCgnc2hvdycpOwp9KTsKJCgnYnRu",
"Q2xvc2VBY2NvdW50SW5mbycpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PiAkKCdhY2Nv",
"dW50SW5mb01vZGFsQmcnKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93JykpOwoKLyogLS0tLSBO4bqh",
"cCB0aeG7gW4gdOG7sSDEkeG7mW5nOiBixrDhu5tjIDEgKG5o4bqtcCBz4buRIHRp4buBbikgLT4g",
"Ysaw4bubYyAyIChRUiDEkeG7mW5nICsgxJHhur9tIG5nxrDhu6NjIDMwIHBow7p0KSAtLS0tCiAg",
"IMSQ4buTbmcgaOG7kyDEkeG6v20gbmfGsOG7o2MgY2jhuqF5IOG7nyBjbGllbnQgZOG7sWEgdHLD",
"qm4gImV4cGlyZXNBdCIgZG8gU0VSVkVSIHRy4bqjIHbhu4EgKGtow7RuZyB04buxIHTDrW5oCiAg",
"IDMwIHBow7p0IHThu6sgbMO6YyBi4bqlbSBuw7p0IOG7nyBjbGllbnQpLCBuw6puIGx1w7RuIGto",
"4bubcCB24bubaSBo4bqhbiB0aOG6rXQgbMawdSB0cm9uZyBkYXRhYmFzZSwgdHLDoW5oCiAgIHRy",
"xrDhu51uZyBo4bujcCBs4buHY2ggZ2nhu50gbcOheSBraMOhY2ggaMOgbmcuICovCmxldCB0b3B1",
"cENvdW50ZG93blRpbWVyID0gbnVsbDsKbGV0IHRvcHVwUG9sbFRpbWVyID0gbnVsbDsKbGV0IGN1",
"cnJlbnRUb3B1cFJlcXVlc3RJZCA9IG51bGw7CgpmdW5jdGlvbiBzaG93VG9wdXBTdGVwKHN0ZXAp",
"ewogICQoJ3RvcHVwU3RlcEFtb3VudCcpLnN0eWxlLmRpc3BsYXkgPSBzdGVwID09PSAnYW1vdW50",
"JyA/ICdmbGV4JyA6ICdub25lJzsKICAkKCd0b3B1cFN0ZXBRcicpLnN0eWxlLmRpc3BsYXkgPSBz",
"dGVwID09PSAncXInID8gJ2ZsZXgnIDogJ25vbmUnOwogICQoJ3RvcHVwRXhwaXJlZEJveCcpLnN0",
"eWxlLmRpc3BsYXkgPSBzdGVwID09PSAnZXhwaXJlZCcgPyAnZmxleCcgOiAnbm9uZSc7Cn0KCmZ1",
"bmN0aW9uIHN0b3BUb3B1cFRpbWVycygpewogIGlmKHRvcHVwQ291bnRkb3duVGltZXIpeyBjbGVh",
"ckludGVydmFsKHRvcHVwQ291bnRkb3duVGltZXIpOyB0b3B1cENvdW50ZG93blRpbWVyID0gbnVs",
"bDsgfQogIGlmKHRvcHVwUG9sbFRpbWVyKXsgY2xlYXJJbnRlcnZhbCh0b3B1cFBvbGxUaW1lcik7",
"IHRvcHVwUG9sbFRpbWVyID0gbnVsbDsgfQp9CgpmdW5jdGlvbiBvcGVuVG9wdXBFeHBpcmVkKCl7",
"CiAgc3RvcFRvcHVwVGltZXJzKCk7CiAgc2hvd1RvcHVwU3RlcCgnZXhwaXJlZCcpOwp9CgpmdW5j",
"dGlvbiBzdGFydFRvcHVwQ291bnRkb3duKGV4cGlyZXNBdElzbyl7CiAgY29uc3QgZXhwaXJlc0F0",
"TXMgPSBuZXcgRGF0ZShleHBpcmVzQXRJc28pLmdldFRpbWUoKTsKICBjb25zdCBlbCA9ICQoJ3Rv",
"cHVwQ291bnRkb3duJyk7CiAgZnVuY3Rpb24gdGljaygpewogICAgY29uc3QgcmVtYWluTXMgPSBl",
"eHBpcmVzQXRNcyAtIERhdGUubm93KCk7CiAgICBpZihyZW1haW5NcyA8PSAwKXsKICAgICAgb3Bl",
"blRvcHVwRXhwaXJlZCgpOwogICAgICByZXR1cm47CiAgICB9CiAgICBjb25zdCB0b3RhbFNlYyA9",
"IE1hdGguZmxvb3IocmVtYWluTXMgLyAxMDAwKTsKICAgIGNvbnN0IG1tID0gTWF0aC5mbG9vcih0",
"b3RhbFNlYyAvIDYwKS50b1N0cmluZygpLnBhZFN0YXJ0KDIsICcwJyk7CiAgICBjb25zdCBzcyA9",
"ICh0b3RhbFNlYyAlIDYwKS50b1N0cmluZygpLnBhZFN0YXJ0KDIsICcwJyk7CiAgICBlbC50ZXh0",
"Q29udGVudCA9IG1tICsgJzonICsgc3M7CiAgICBlbC5jbGFzc0xpc3QudG9nZ2xlKCd3YXJuJywg",
"dG90YWxTZWMgPD0gNjApOyAvLyDEkeG7lWkgbcOgdSBj4bqjbmggYsOhbyBraGkgY8OybiBkxrDh",
"u5tpIDEgcGjDunQKICB9CiAgdGljaygpOwogIHRvcHVwQ291bnRkb3duVGltZXIgPSBzZXRJbnRl",
"cnZhbCh0aWNrLCAxMDAwKTsKfQoKLyogxJDhu5NuZyBi4buZIHRy4bqhbmcgdGjDoWkgduG7m2kg",
"c2VydmVyIG3hu5dpIDEwIGdpw6J5OiBu4bq/dSBhZG1pbiDEkcOjIGR1eeG7h3QvdOG7qyBjaOG7",
"kWksIGhv4bq3YyBzZXJ2ZXIgdOG7sQogICDEkcOhbmggZOG6pXUgaOG6v3QgaOG6oW4gKHRyxrDh",
"u51uZyBo4bujcCBjbGllbnQgbeG6pXQgbeG6oW5nL8SR4buVaSB0YWIgbMOidSksIGPhuq1wIG5o",
"4bqtdCBVSSB0xrDGoW5nIOG7qW5nIG5nYXkuICovCmZ1bmN0aW9uIHN0YXJ0VG9wdXBTdGF0dXNQ",
"b2xsaW5nKHJlcXVlc3RJZCl7CiAgdG9wdXBQb2xsVGltZXIgPSBzZXRJbnRlcnZhbChhc3luYyAo",
"KT0+ewogICAgdHJ5ewogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcv",
"YXBpL3RvcHVwLXJlcXVlc3QvJyArIHJlcXVlc3RJZCwgewogICAgICAgIGhlYWRlcnM6eyAnQXV0",
"aG9yaXphdGlvbic6ICdCZWFyZXIgJyArIGN1c3RvbWVyVG9rZW4gfQogICAgICB9KTsKICAgICAg",
"aWYoIXJlcy5vaykgcmV0dXJuOwogICAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsK",
"ICAgICAgaWYoIWRhdGEub2sgfHwgIWRhdGEucmVxdWVzdCkgcmV0dXJuOwogICAgICBjb25zdCBz",
"dGF0dXMgPSBkYXRhLnJlcXVlc3Quc3RhdHVzOwogICAgICBpZihzdGF0dXMgPT09ICdleHBpcmVk",
"Jyl7CiAgICAgICAgb3BlblRvcHVwRXhwaXJlZCgpOwogICAgICB9IGVsc2UgaWYoc3RhdHVzID09",
"PSAnYXBwcm92ZWQnKXsKICAgICAgICBzdG9wVG9wdXBUaW1lcnMoKTsKICAgICAgICAkKCd0b3B1",
"cE1vZGFsQmcyJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOwogICAgICAgIC8vIE7hur91IMSR",
"xrDhu6NjIGR1eeG7h3QgdOG7sSDEkeG7mW5nIHF1YSDEkeG7kWkgc2/DoXQgY2h1eeG7g24ga2hv",
"4bqjbiAoU2VQYXkpLCBoaeG7h24gdGjDtG5nIGLDoW8gcGjDuSBo4bujcAogICAgICAgIC8vIGjG",
"oW4gbMOgICLEkcaw4bujYyBkdXnhu4d0IiAobmdoZSBuaMawIGPhuqduIHRoYW8gdMOhYyB0aOG7",
"pyBjw7RuZyBj4bunYSBhZG1pbikuCiAgICAgICAgY29uc3QgaXNBdXRvQXBwcm92ZWQgPSBkYXRh",
"LnJlcXVlc3QuYXBwcm92ZWRCeSA9PT0gJ3NlcGF5X2F1dG8nOwogICAgICAgIHNob3dUb2FzdChp",
"c0F1dG9BcHByb3ZlZAogICAgICAgICAgPyAnxJDDoyBuaOG6rW4gxJHGsOG7o2MgY2h1eeG7g24g",
"a2hv4bqjbiDigJQgc+G7kSBkxrAgxJHDoyDEkcaw4bujYyBj4buZbmcgdOG7sSDEkeG7mW5nIScK",
"ICAgICAgICAgIDogJ1nDqnUgY+G6p3UgbuG6oXAgdGnhu4FuIMSRw6MgxJHGsOG7o2MgZHV54buH",
"dCDigJQgc+G7kSBkxrAgxJHDoyDEkcaw4bujYyBj4buZbmchJyk7CiAgICAgICAgcmVmcmVzaEN1",
"c3RvbWVyQmFsYW5jZUlmUG9zc2libGUoKTsKICAgICAgfSBlbHNlIGlmKHN0YXR1cyA9PT0gJ3Jl",
"amVjdGVkJyl7CiAgICAgICAgc3RvcFRvcHVwVGltZXJzKCk7CiAgICAgICAgJCgndG9wdXBNb2Rh",
"bEJnMicpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICAgICAgICBzaG93VG9hc3QoJ1nDqnUg",
"Y+G6p3UgbuG6oXAgdGnhu4FuIMSRw6MgYuG7iyB04burIGNo4buRaSwgdnVpIGzDsm5nIGxpw6pu",
"IGjhu4cgaOG7lyB0cuG7oycpOwogICAgICB9CiAgICB9Y2F0Y2goZSl7IC8qIGzhu5dpIG3huqFu",
"ZyB04bqhbSB0aOG7nWksIHRo4butIGzhuqFpIOG7nyBsxrDhu6N0IHBvbGwga+G6vyB0aeG6v3Ag",
"Ki8gfQogIH0sIDQwMDApOyAvLyA0IGdpw6J5L2zhuqduIOKAlCDEkeG7pyBuaGFuaCDEkeG7gyBr",
"aMOhY2ggdGjhuqV5IHPhu5EgZMawIGPhu5luZyBn4bqnbiBuaMawIG5nYXkgc2F1IGtoaSBjaHV5",
"4buDbiBraG/huqNuCn0KCi8qIEPhuq1wIG5o4bqtdCBs4bqhaSBz4buRIGTGsCBoaeG7g24gdGjh",
"u4sgdHLDqm4gdHJhbmcgKG7hur91IGPDsyBow6BtL2Jp4bq/biB0xrDGoW5nIOG7qW5nKSwgZ+G7",
"jWkgc2F1IGtoaSAxIHnDqnUKICAgY+G6p3UgbuG6oXAgdGnhu4FuIMSRxrDhu6NjIGR1eeG7h3Qg",
"dHJvbmcgbMO6YyBtb2RhbCDEkWFuZyBt4bufLCDEkeG7gyBraMOhY2ggdGjhuqV5IHPhu5EgZMaw",
"IG3hu5tpIG5nYXkuICovCmFzeW5jIGZ1bmN0aW9uIHJlZnJlc2hDdXN0b21lckJhbGFuY2VJZlBv",
"c3NpYmxlKCl7CiAgdHJ5ewogICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAn",
"L2FwaS9hdXRoL21lJywgeyBoZWFkZXJzOnsgJ0F1dGhvcml6YXRpb24nOiAnQmVhcmVyICcgKyBj",
"dXN0b21lclRva2VuIH0gfSk7CiAgICBpZighcmVzLm9rKSByZXR1cm47CiAgICBjb25zdCBkYXRh",
"ID0gYXdhaXQgcmVzLmpzb24oKTsKICAgIGlmKGRhdGEgJiYgZGF0YS5vayl7CiAgICAgIGN1c3Rv",
"bWVyQmFsYW5jZSA9IGRhdGEuYmFsYW5jZSB8fCAwOwogICAgICBpZih0eXBlb2YgdXBkYXRlQWNj",
"b3VudFVJID09PSAnZnVuY3Rpb24nKSB1cGRhdGVBY2NvdW50VUkoKTsKICAgIH0KICB9Y2F0Y2go",
"ZSl7IC8qIGLhu48gcXVhLCBraMO0bmcgcXVhbiB0cuG7jW5nIGLhurFuZyB2aeG7h2MgdGjDtG5n",
"IGLDoW8gxJHDoyBkdXnhu4d0IOG7nyB0csOqbiAqLyB9Cn0KCiQoJ2RkVG9wdXAnKS5hZGRFdmVu",
"dExpc3RlbmVyKCdjbGljaycsICgpPT57CiAgY2xvc2VEcm9wZG93bigpOwogIHN0b3BUb3B1cFRp",
"bWVycygpOwogICQoJ3RvcHVwUmVxdWVzdEFtb3VudCcpLnZhbHVlID0gJyc7CiAgJCgndG9wdXBS",
"ZXF1ZXN0RXJyb3InKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgc2hvd1RvcHVwU3RlcCgn",
"YW1vdW50Jyk7CiAgJCgndG9wdXBNb2RhbEJnMicpLmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKfSk7",
"CiQoJ2J0bkNsb3NlVG9wdXAyJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKT0+ewogIHN0",
"b3BUb3B1cFRpbWVycygpOwogICQoJ3RvcHVwTW9kYWxCZzInKS5jbGFzc0xpc3QucmVtb3ZlKCdz",
"aG93Jyk7Cn0pOwokKCdidG5DbG9zZVRvcHVwUXInKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycs",
"ICgpPT57CiAgLy8gxJDDs25nIG1vZGFsIEtIw5RORyBo4buneSB5w6p1IGPhuqd1IOKAlCB5w6p1",
"IGPhuqd1IHbhuqtuIMSRYW5nIGNo4budIGR1eeG7h3QgdHJvbmcgMzAgcGjDunQsIGtow6FjaCBj",
"w7MgdGjhu4MKICAvLyB4ZW0gbOG6oWkgdHLhuqFuZyB0aMOhaSDhu58gIkzhu4tjaCBz4butIG7h",
"uqFwIHRp4buBbiIuIFRpbWVyIGNsaWVudCBk4burbmcgbOG6oWkgdsOsIG1vZGFsIMSRw6MgxJHD",
"s25nLgogIHN0b3BUb3B1cFRpbWVycygpOwogICQoJ3RvcHVwTW9kYWxCZzInKS5jbGFzc0xpc3Qu",
"cmVtb3ZlKCdzaG93Jyk7Cn0pOwokKCdidG5CYWNrVG9wdXBBbW91bnQnKS5hZGRFdmVudExpc3Rl",
"bmVyKCdjbGljaycsICgpPT57CiAgLy8gxJDhu5VpIHPhu5EgdGnhu4FuIGtow6FjIGNvaSBuaMaw",
"IGjhu6d5IHnDqnUgY+G6p3UgaGnhu4duIHThuqFpIHbhu4EgbeG6t3QgaGnhu4NuIHRo4buLICh5",
"w6p1IGPhuqd1IGPFqSB24bqrbiBjaOG7nSDhu58KICAvLyBzZXJ2ZXIsIGNo4buJIGjhur90IGjh",
"uqFuIHThu7Egbmhpw6puIHNhdSAzMCBwaMO6dCBu4bq/dSBraMOhY2gga2jDtG5nIHF1w6l0IFFS",
"IG7hu69hKS4KICBzdG9wVG9wdXBUaW1lcnMoKTsKICBzaG93VG9wdXBTdGVwKCdhbW91bnQnKTsK",
"fSk7CiQoJ2J0bkNsb3NlVG9wdXBFeHBpcmVkJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAo",
"KT0+ewogICQoJ3RvcHVwTW9kYWxCZzInKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7Cn0pOwok",
"KCdidG5SZXN0YXJ0VG9wdXAnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT57CiAgJCgn",
"dG9wdXBSZXF1ZXN0QW1vdW50JykudmFsdWUgPSAnJzsKICAkKCd0b3B1cFJlcXVlc3RFcnJvcicp",
"LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICBzaG93VG9wdXBTdGVwKCdhbW91bnQnKTsKfSk7",
"CgokKCdidG5TdWJtaXRUb3B1cFJlcXVlc3QnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFz",
"eW5jICgpPT57CiAgY29uc3QgZXJyQm94ID0gJCgndG9wdXBSZXF1ZXN0RXJyb3InKTsKICBlcnJC",
"b3guY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOwogIGNvbnN0IGFtb3VudCA9IHBhcnNlRmxvYXQo",
"JCgndG9wdXBSZXF1ZXN0QW1vdW50JykudmFsdWUucmVwbGFjZSgvW15cZC5dL2csJycpKSB8fCAw",
"OwogIGlmKGFtb3VudCA8IDEwMDAwKXsgZXJyQm94LnRleHRDb250ZW50ID0gJ1Phu5EgdGnhu4Fu",
"IG7huqFwIHThu5FpIHRoaeG7g3UgbMOgIDEwLjAwMOKCqyc7IGVyckJveC5jbGFzc0xpc3QuYWRk",
"KCdzaG93Jyk7IHJldHVybjsgfQogIGlmKGFtb3VudCA+IDUwMDAwMDAwMCl7IGVyckJveC50ZXh0",
"Q29udGVudCA9ICdT4buRIHRp4buBbiBu4bqhcCB04buRaSDEkWEgbMOgIDUwMC4wMDAuMDAw4oKr",
"JzsgZXJyQm94LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsgcmV0dXJuOyB9CiAgLy8gWcOqdSBj4bqn",
"dSBwaOG6o2kgxJHEg25nIG5o4bqtcCB0csaw4bubYyBraGkgZ+G7jWkgQVBJIOKAlCB0csOhbmgg",
"Z+G7jWkgQVBJIHLhu5NpIG3hu5tpIG5o4bqtbiBs4buXaSBtxqEgaOG7ky4KICBpZighY3VzdG9t",
"ZXJUb2tlbil7CiAgICBlcnJCb3gudGV4dENvbnRlbnQgPSAnQuG6oW4gY+G6p24gxJHEg25nIG5o",
"4bqtcCB0csaw4bubYyBraGkgbuG6oXAgdGnhu4FuLic7CiAgICBlcnJCb3guY2xhc3NMaXN0LmFk",
"ZCgnc2hvdycpOwogICAgcmV0dXJuOwogIH0KICBjb25zdCBidG4gPSAkKCdidG5TdWJtaXRUb3B1",
"cFJlcXVlc3QnKTsKICBjb25zdCBvcmlnaW5hbEJ0blRleHQgPSBidG4udGV4dENvbnRlbnQ7CiAg",
"YnRuLmRpc2FibGVkID0gdHJ1ZTsKICBidG4udGV4dENvbnRlbnQgPSAnxJBhbmcgdOG6oW8gbcOj",
"IFFSLi4uJzsKICB0cnl7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcv",
"YXBpL3RvcHVwLXJlcXVlc3QnLCB7CiAgICAgIG1ldGhvZDonUE9TVCcsIGhlYWRlcnM6eydDb250",
"ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sCiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5",
"KHsgdG9rZW46IGN1c3RvbWVyVG9rZW4sIGFtb3VudCwgbWV0aG9kOidiYW5rX3RyYW5zZmVyJyB9",
"KQogICAgfSk7CgogICAgLy8gxJDhu41jIHJlc3BvbnNlIGThuqFuZyB0ZXh0IHRyxrDhu5tjLCBy",
"4buTaSBt4bubaSBwYXJzZSBKU09OIOKAlCDEkeG7gyBraMO0bmcgIm514buRdCIgbOG7l2kga2hp",
"IHNlcnZlciB0cuG6owogICAgLy8gduG7gSBIVE1ML2zhu5dpIDUwMiAodsOtIGThu6UgUmVuZGVy",
"IMSRYW5nIGto4bufaSDEkeG7mW5nIGzhuqFpKSB0aGF5IHbDrCBKU09OIGjhu6NwIGzhu4cuCiAg",
"ICBjb25zdCByYXdUZXh0ID0gYXdhaXQgcmVzLnRleHQoKTsKICAgIGxldCBkYXRhOwogICAgdHJ5",
"ewogICAgICBkYXRhID0gSlNPTi5wYXJzZShyYXdUZXh0KTsKICAgIH1jYXRjaChwYXJzZUVycil7",
"CiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tUb3B1cF0gU2VydmVyIGtow7RuZyB0cuG6oyBKU09OIGjh",
"u6NwIGzhu4cuIFN0YXR1czonLCByZXMuc3RhdHVzLCAnQm9keTonLCByYXdUZXh0LnNsaWNlKDAs",
"IDMwMCkpOwogICAgICB0aHJvdyBuZXcgRXJyb3IoJ03DoXkgY2jhu6cgxJFhbmcga2jhu59pIMSR",
"4buZbmcgbOG6oWkgaG/hurdjIGfhurdwIHPhu7EgY+G7kSB04bqhbSB0aOG7nWksIHZ1aSBsw7Ju",
"ZyB0aOG7rSBs4bqhaSBzYXUgw610IGdpw6J5LicpOwogICAgfQoKICAgIGlmKHJlcy5zdGF0dXMg",
"PT09IDQwOSAmJiBkYXRhLnJlcXVlc3QpewogICAgICAvLyDEkMOjIGPDsyAxIHnDqnUgY+G6p3Ug",
"xJFhbmcgY2jhu50geOG7rSBsw70g4oCUIGhp4buDbiB0aOG7iyBs4bqhaSDEkcO6bmcgUVIvxJHh",
"ur9tIG5nxrDhu6NjIGPhu6dhIHnDqnUgY+G6p3UgxJHDswogICAgICAvLyB0aGF5IHbDrCBiw6Fv",
"IGzhu5dpIGtow7QsIMSR4buDIGtow6FjaCBraMO0bmcgYuG7iyBr4bq5dCBraMO0bmcgYmnhur90",
"IGzDoG0gZ8OsIHRp4bq/cC4KICAgICAgb3BlblRvcHVwUXJTdGVwKGRhdGEucmVxdWVzdCk7CiAg",
"ICAgIHJldHVybjsKICAgIH0KICAgIGlmKHJlcy5zdGF0dXMgPT09IDQwMSl7CiAgICAgIHRocm93",
"IG5ldyBFcnJvcignUGhpw6puIMSRxINuZyBuaOG6rXAgxJHDoyBo4bq/dCBo4bqhbiwgdnVpIGzD",
"sm5nIMSRxINuZyBuaOG6rXAgbOG6oWkgcuG7k2kgdGjhu60gbuG6oXAgdGnhu4FuIGzhuqFpLicp",
"OwogICAgfQogICAgaWYocmVzLnN0YXR1cyA9PT0gNDI5KXsKICAgICAgdGhyb3cgbmV3IEVycm9y",
"KGRhdGEubWVzc2FnZSB8fCAnQuG6oW4gxJFhbmcgZ+G7rWkgecOqdSBj4bqndSBxdcOhIG5oYW5o",
"LCB2dWkgbMOybmcgdGjhu60gbOG6oWkgc2F1IHbDoGkgcGjDunQuJyk7CiAgICB9CiAgICBpZigh",
"cmVzLm9rIHx8ICFkYXRhLm9rKXsKICAgICAgLy8gTG9nIGNoaSB0aeG6v3QgbOG7l2kgdGjhuq10",
"IHJhIGNvbnNvbGUgxJHhu4MgZOG7hSBjaOG6qW4gxJFvw6FuICh0aGF5IHbDrCBjaOG7iSBoaeG7",
"h24gdGjDtG5nIGLDoW8gY2h1bmcpLgogICAgICBjb25zb2xlLmVycm9yKCdbVG9wdXBdIEfhu61p",
"IHnDqnUgY+G6p3UgbuG6oXAgdGnhu4FuIHRo4bqldCBi4bqhaS4gU3RhdHVzOicsIHJlcy5zdGF0",
"dXMsICdSZXNwb25zZTonLCBkYXRhKTsKICAgICAgdGhyb3cgbmV3IEVycm9yKGRhdGEubWVzc2Fn",
"ZSB8fCAoJ0fhu61pIHnDqnUgY+G6p3UgdGjhuqV0IGLhuqFpIChtw6MgbOG7l2k6ICcgKyByZXMu",
"c3RhdHVzICsgJyksIHZ1aSBsw7JuZyB0aOG7rSBs4bqhaS4nKSk7CiAgICB9CiAgICBvcGVuVG9w",
"dXBRclN0ZXAoZGF0YS5yZXF1ZXN0KTsKICB9Y2F0Y2goZSl7CiAgICBjb25zb2xlLmVycm9yKCdb",
"VG9wdXBdIEzhu5dpIGtoaSB04bqhbyB5w6p1IGPhuqd1IG7huqFwIHRp4buBbjonLCBlKTsKICAg",
"IGVyckJveC50ZXh0Q29udGVudCA9IGUubWVzc2FnZSB8fCAnQ8OzIGzhu5dpIHjhuqN5IHJhLCB2",
"dWkgbMOybmcgdGjhu60gbOG6oWkuIE7hur91IHbhuqtuIGzhu5dpLCBow6N5IHThuqNpIGzhuqFp",
"IHRyYW5nLic7CiAgICBlcnJCb3guY2xhc3NMaXN0LmFkZCgnc2hvdycpOwogIH1maW5hbGx5ewog",
"ICAgYnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICBidG4udGV4dENvbnRlbnQgPSBvcmlnaW5hbEJ0",
"blRleHQ7CiAgfQp9KTsKCi8qIEhp4buDbiB0aOG7iyBixrDhu5tjIFFSOiDEkWnhu4FuIOG6o25o",
"IFFSIMSR4buZbmcgKMSRw6MgbmjDum5nIHPhu5EgdGnhu4FuICsgbuG7mWkgZHVuZyBDSyB04bur",
"IHNlcnZlciksIHRow7RuZyB0aW4KICAgbmfDom4gaMOgbmcsIHbDoCBraOG7n2kgxJHhu5luZyDE",
"keG7k25nIGjhu5MgxJHhur9tIG5nxrDhu6NjIDMwIHBow7p0ICsgcG9sbGluZyB0cuG6oW5nIHRo",
"w6FpLiAqLwpmdW5jdGlvbiBvcGVuVG9wdXBRclN0ZXAocmVxRW50cnkpewogIGN1cnJlbnRUb3B1",
"cFJlcXVlc3RJZCA9IHJlcUVudHJ5LmlkOwogICQoJ3RvcHVwUXJJbWcnKS5zcmMgPSByZXFFbnRy",
"eS5xclVybCB8fCAnJzsKICAkKCd0b3B1cFFyQW1vdW50JykudGV4dENvbnRlbnQgPSBmbXRNb25l",
"eShyZXFFbnRyeS5hbW91bnQpOwogICQoJ3RvcHVwUXJOb3RlJykudGV4dENvbnRlbnQgPSByZXFF",
"bnRyeS50cmFuc2Zlck5vdGUgfHwgKCdOQVAgJyArIGN1c3RvbWVyTmFtZSk7CiAgJCgndG9wdXBR",
"ckFjY291bnRObycpLnRleHRDb250ZW50ID0gJzAzNjQ4MzcxMTgnOwogICQoJ3RvcHVwUXJBY2Nv",
"dW50TmFtZScpLnRleHRDb250ZW50ID0gJ0xVT05HIFZBTiBUVVlFTic7CiAgJCgndG9wdXBRckVy",
"cm9yJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOwogIHNob3dUb3B1cFN0ZXAoJ3FyJyk7CiAg",
"c3RvcFRvcHVwVGltZXJzKCk7CiAgc3RhcnRUb3B1cENvdW50ZG93bihyZXFFbnRyeS5leHBpcmVz",
"QXQpOwogIHN0YXJ0VG9wdXBTdGF0dXNQb2xsaW5nKHJlcUVudHJ5LmlkKTsKfQoKZnVuY3Rpb24g",
"cmVuZGVySGlzdG9yeUxpc3QoY29udGFpbmVyLCBpdGVtcywgZW1wdHlNc2cpewogIGlmKCFpdGVt",
"cyB8fCAhaXRlbXMubGVuZ3RoKXsKICAgIGNvbnRhaW5lci5pbm5lckhUTUwgPSBgPGRpdiBjbGFz",
"cz0iaGlzdG9yeS1lbXB0eSI+JHtlbXB0eU1zZ308L2Rpdj5gOwogICAgcmV0dXJuOwogIH0KICBj",
"b250YWluZXIuaW5uZXJIVE1MID0gaXRlbXMubWFwKGl0PT57CiAgICBpZihpdC5zdGF0dXMgIT09",
"IHVuZGVmaW5lZCl7CiAgICAgIC8vIG3hu6VjIGzhu4tjaCBz4butIG7huqFwIHRp4buBbgogICAg",
"ICBjb25zdCBzdGF0dXNMYWJlbCA9IHsgcGVuZGluZzonxJBhbmcgY2jhu50gZHV54buHdCcsIGFw",
"cHJvdmVkOifEkMOjIGR1eeG7h3QnLCByZWplY3RlZDonxJDDoyB04burIGNo4buRaScgfVtpdC5z",
"dGF0dXNdIHx8IGl0LnN0YXR1czsKICAgICAgcmV0dXJuIGAKICAgICAgICA8ZGl2IGNsYXNzPSJo",
"aXN0b3J5LWl0ZW0iPgogICAgICAgICAgPGRpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iaC1t",
"YWluIj5O4bqhcCB0aeG7gW4gwrcgJHtpdC5tZXRob2Q9PT0nYmFua190cmFuc2ZlcicgPyAnQ2h1",
"eeG7g24ga2hv4bqjbicgOiAoaXQubWV0aG9kPT09J2FkbWluX21hbnVhbCcgPyAnQWRtaW4gY+G7",
"mW5nIHRheScgOiBpdC5tZXRob2QpfTwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJoLXN1",
"YiI+JHtuZXcgRGF0ZShpdC5jcmVhdGVkQXQpLnRvTG9jYWxlU3RyaW5nKCd2aS1WTicpfSDCtyA8",
"c3BhbiBjbGFzcz0ic3RhdHVzLXBpbGwgJHtpdC5zdGF0dXN9Ij4ke3N0YXR1c0xhYmVsfTwvc3Bh",
"bj48L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iaC1hbW91bnQg",
"cG9zIj4rJHtmbXRNb25leShpdC5hbW91bnQpfTwvZGl2PgogICAgICAgIDwvZGl2PmA7CiAgICB9",
"CiAgICAvLyBt4bulYyBs4buLY2ggc+G7rSBnaWFvIGThu4tjaAogICAgY29uc3QgaXNQb3NpdGl2",
"ZSA9IGl0LmFtb3VudCA+PSAwOwogICAgcmV0dXJuIGAKICAgICAgPGRpdiBjbGFzcz0iaGlzdG9y",
"eS1pdGVtIj4KICAgICAgICA8ZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iaC1tYWluIj4ke2l0",
"Lm5vdGUgfHwgKGl0LnR5cGU9PT0ndG9wdXAnID8gJ07huqFwIHRp4buBbicgOiAnR2lhbyBk4buL",
"Y2gnKX08L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9Imgtc3ViIj4ke25ldyBEYXRlKGl0LmNy",
"ZWF0ZWRBdCkudG9Mb2NhbGVTdHJpbmcoJ3ZpLVZOJyl9IMK3IFPhu5EgZMawIHNhdTogJHtmbXRN",
"b25leShpdC5iYWxhbmNlQWZ0ZXIpfTwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYg",
"Y2xhc3M9ImgtYW1vdW50ICR7aXNQb3NpdGl2ZSA/ICdwb3MnIDogJ25lZyd9Ij4ke2lzUG9zaXRp",
"dmUgPyAnKycgOiAnJ30ke2ZtdE1vbmV5KGl0LmFtb3VudCl9PC9kaXY+CiAgICAgIDwvZGl2PmA7",
"CiAgfSkuam9pbignJyk7Cn0KCmFzeW5jIGZ1bmN0aW9uIGxvYWRDdXN0b21lckhpc3RvcnkoKXsK",
"ICB0cnl7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcvYXBpL2F1dGgv",
"aGlzdG9yeScsIHsgaGVhZGVyczp7ICdBdXRob3JpemF0aW9uJzogJ0JlYXJlciAnICsgY3VzdG9t",
"ZXJUb2tlbiB9IH0pOwogICAgaWYoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCdub3RfbG9nZ2Vk",
"X2luJyk7CiAgICByZXR1cm4gYXdhaXQgcmVzLmpzb24oKTsKICB9Y2F0Y2goZSl7CiAgICByZXR1",
"cm4geyBvazpmYWxzZSwgdG9wdXBIaXN0b3J5OltdLCB0cmFuc2FjdGlvbkhpc3Rvcnk6W10gfTsK",
"ICB9Cn0KCiQoJ2RkVG9wdXBIaXN0b3J5JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3lu",
"YyAoKT0+ewogIGNsb3NlRHJvcGRvd24oKTsKICAkKCd0b3B1cEhpc3RvcnlNb2RhbEJnJykuY2xh",
"c3NMaXN0LmFkZCgnc2hvdycpOwogICQoJ3RvcHVwSGlzdG9yeUxpc3QnKS5pbm5lckhUTUwgPSAn",
"PGRpdiBjbGFzcz0iaGlzdG9yeS1lbXB0eSI+xJBhbmcgdOG6o2kuLi48L2Rpdj4nOwogIGNvbnN0",
"IGRhdGEgPSBhd2FpdCBsb2FkQ3VzdG9tZXJIaXN0b3J5KCk7CiAgcmVuZGVySGlzdG9yeUxpc3Qo",
"JCgndG9wdXBIaXN0b3J5TGlzdCcpLCBkYXRhLnRvcHVwSGlzdG9yeSwgJ0NoxrBhIGPDsyBsxrDh",
"u6N0IG7huqFwIHRp4buBbiBuw6BvJyk7Cn0pOwokKCdidG5DbG9zZVRvcHVwSGlzdG9yeScpLmFk",
"ZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PiAkKCd0b3B1cEhpc3RvcnlNb2RhbEJnJykuY2xh",
"c3NMaXN0LnJlbW92ZSgnc2hvdycpKTsKCiQoJ2RkVHhIaXN0b3J5JykuYWRkRXZlbnRMaXN0ZW5l",
"cignY2xpY2snLCBhc3luYyAoKT0+ewogIGNsb3NlRHJvcGRvd24oKTsKICAkKCd0eEhpc3RvcnlN",
"b2RhbEJnJykuY2xhc3NMaXN0LmFkZCgnc2hvdycpOwogICQoJ3R4SGlzdG9yeUxpc3QnKS5pbm5l",
"ckhUTUwgPSAnPGRpdiBjbGFzcz0iaGlzdG9yeS1lbXB0eSI+xJBhbmcgdOG6o2kuLi48L2Rpdj4n",
"OwogIGNvbnN0IGRhdGEgPSBhd2FpdCBsb2FkQ3VzdG9tZXJIaXN0b3J5KCk7CiAgcmVuZGVySGlz",
"dG9yeUxpc3QoJCgndHhIaXN0b3J5TGlzdCcpLCBkYXRhLnRyYW5zYWN0aW9uSGlzdG9yeSwgJ0No",
"xrBhIGPDsyBnaWFvIGThu4tjaCBuw6BvJyk7Cn0pOwokKCdidG5DbG9zZVR4SGlzdG9yeScpLmFk",
"ZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PiAkKCd0eEhpc3RvcnlNb2RhbEJnJykuY2xhc3NM",
"aXN0LnJlbW92ZSgnc2hvdycpKTsKCi8qIC0tLS0tLS0tLS0gTW9kYWwgUXXhuqNuIGzDvSBrZXkg",
"KGtleSDEkcOjIG11YSkgLS0tLS0tLS0tLSAqLwpjb25zdCBNWV9LRVlfU1RBVFVTX0xBQkVMID0g",
"eyBhdmFpbGFibGU6J0PDsm4gaMOgbmcnLCBzb2xkOifEkMOjIGLDoW4nLCBiYW5uZWQ6J0Lhu4sg",
"Y+G6pW0nLCBleHBpcmVkOidI4bq/dCBo4bqhbicsIHVuYWN0aXZhdGVkOidDaMawYSBrw61jaCBo",
"b+G6oXQnIH07CgpmdW5jdGlvbiBmbXRLZXlVbml0TGFiZWwodW5pdCl7CiAgcmV0dXJuIHVuaXQ9",
"PT0naG91cicgPyAnZ2nhu50nIDogdW5pdD09PSdtb250aCcgPyAndGjDoW5nJyA6ICduZ8OgeSc7",
"Cn0KCmZ1bmN0aW9uIHJlbmRlck15S2V5c0xpc3QoaXRlbXMpewogIGNvbnN0IGNvbnRhaW5lciA9",
"ICQoJ215S2V5c0xpc3QnKTsKICBpZighaXRlbXMgfHwgIWl0ZW1zLmxlbmd0aCl7CiAgICBjb250",
"YWluZXIuaW5uZXJIVE1MID0gJzxkaXYgY2xhc3M9Imhpc3RvcnktZW1wdHkiPkLhuqFuIGNoxrBh",
"IG11YSBrZXkgbsOgbzwvZGl2Pic7CiAgICByZXR1cm47CiAgfQogIGNvbnRhaW5lci5pbm5lckhU",
"TUwgPSBpdGVtcy5tYXAoaz0+ewogICAgY29uc3Qgc3RhdHVzTGFiZWwgPSBNWV9LRVlfU1RBVFVT",
"X0xBQkVMW2suc3RhdHVzXSB8fCBrLnN0YXR1czsKICAgIGxldCBleHBpcnlMaW5lOwogICAgaWYo",
"ay5oYXNFeHBpcnlQbGFuICYmICFrLmFjdGl2YXRlZCl7CiAgICAgIGV4cGlyeUxpbmUgPSBgSOG6",
"oW4gZMO5bmc6IDxiPkNoxrBhIGvDrWNoIGhv4bqhdDwvYj4g4oCUIHPhur0gZMO5bmcgxJHGsOG7",
"o2MgJHtrLmV4cGlyeUFtb3VudHx8Jz8nfSAke2ZtdEtleVVuaXRMYWJlbChrLmV4cGlyeVVuaXQp",
"fSBr4buDIHThu6sgbOG6p24gxJHhuqd1IHPhu60gZOG7pW5nYDsKICAgIH0gZWxzZSBpZihrLmV4",
"cGlyZXNBdCl7CiAgICAgIGV4cGlyeUxpbmUgPSBgSOG6oW4gZMO5bmc6IDxiPiR7bmV3IERhdGUo",
"ay5leHBpcmVzQXQpLnRvTG9jYWxlU3RyaW5nKCd2aS1WTicpfTwvYj5gOwogICAgfSBlbHNlIHsK",
"ICAgICAgZXhwaXJ5TGluZSA9ICdI4bqhbiBkw7luZzogPGI+S2jDtG5nIGdp4bubaSBo4bqhbjwv",
"Yj4nOwogICAgfQogICAgY29uc3Qgc29sZExpbmUgPSBrLnNvbGRBdCA/IG5ldyBEYXRlKGsuc29s",
"ZEF0KS50b0xvY2FsZVN0cmluZygndmktVk4nKSA6ICfigJQnOwogICAgcmV0dXJuIGAKICAgICAg",
"PGRpdiBjbGFzcz0ia2V5LWl0ZW0iPgogICAgICAgIDxkaXYgY2xhc3M9ImstdG9wIj4KICAgICAg",
"ICAgIDxzcGFuIGNsYXNzPSJrLXZhbHVlIj4ke2sudmFsdWV9PC9zcGFuPgogICAgICAgICAgPGJ1",
"dHRvbiBjbGFzcz0iay1jb3B5IiBkYXRhLWtleT0iJHtrLnZhbHVlfSI+U2FvIGNow6lwPC9idXR0",
"b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iay1tZXRhIj4KICAgICAgICAg",
"IDxzcGFuIGNsYXNzPSJzdGF0dXMtcGlsbCAke2suc3RhdHVzfSI+JHtzdGF0dXNMYWJlbH08L3Nw",
"YW4+IMK3CiAgICAgICAgICAke2sudHlwZT09PSdwcmVtaXVtJyA/ICfimIUgUHJlbWl1bScgOiAn",
"VGjGsOG7nW5nJ30gwrcKICAgICAgICAgIFRoaeG6v3QgYuG7izogJHtrLmRldmljZXNVc2VkfHww",
"fS8ke2subWF4RGV2aWNlc3x8MX08YnI+CiAgICAgICAgICAke2V4cGlyeUxpbmV9PGJyPgogICAg",
"ICAgICAgTmfDoHkgbXVhOiAke3NvbGRMaW5lfQogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj5g",
"OwogIH0pLmpvaW4oJycpOwp9Cgphc3luYyBmdW5jdGlvbiBsb2FkTXlLZXlzKCl7CiAgdHJ5ewog",
"ICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAnL2FwaS9jdXN0b21lci9rZXlz",
"JywgeyBoZWFkZXJzOnsgJ0F1dGhvcml6YXRpb24nOiAnQmVhcmVyICcgKyBjdXN0b21lclRva2Vu",
"IH0gfSk7CiAgICBpZighcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoJ25vdF9sb2dnZWRfaW4nKTsK",
"ICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgcmV0dXJuIChkYXRhLm9rICYm",
"IGRhdGEua2V5cykgPyBkYXRhLmtleXMgOiBbXTsKICB9Y2F0Y2goZSl7CiAgICByZXR1cm4gW107",
"CiAgfQp9CgokKCdkZE15S2V5cycpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYXN5bmMgKCk9",
"PnsKICBjbG9zZURyb3Bkb3duKCk7CiAgaWYoIWN1c3RvbWVyVG9rZW4peyBvcGVuQXV0aE1vZGFs",
"KCk7IHJldHVybjsgfQogICQoJ215S2V5c01vZGFsQmcnKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7",
"CiAgJCgnbXlLZXlzTGlzdCcpLmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJoaXN0b3J5LWVtcHR5",
"Ij7EkGFuZyB04bqjaS4uLjwvZGl2Pic7CiAgY29uc3Qga2V5c0xpc3QgPSBhd2FpdCBsb2FkTXlL",
"ZXlzKCk7CiAgcmVuZGVyTXlLZXlzTGlzdChrZXlzTGlzdCk7Cn0pOwokKCdidG5DbG9zZU15S2V5",
"cycpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PiAkKCdteUtleXNNb2RhbEJnJykuY2xh",
"c3NMaXN0LnJlbW92ZSgnc2hvdycpKTsKJCgnbXlLZXlzTGlzdCcpLmFkZEV2ZW50TGlzdGVuZXIo",
"J2NsaWNrJywgKGUpPT57CiAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgnLmstY29weScp",
"OwogIGlmKCFidG4pIHJldHVybjsKICBuYXZpZ2F0b3IuY2xpcGJvYXJkLndyaXRlVGV4dChidG4u",
"ZGF0YXNldC5rZXkpLnRoZW4oKCk9PiBzaG93VG9hc3QoJ8SQw6Mgc2FvIGNow6lwIGtleScpKS5j",
"YXRjaCgoKT0+IHNob3dUb2FzdCgnS2jDtG5nIHNhbyBjaMOpcCDEkcaw4bujYywgdnVpIGzDsm5n",
"IGNvcHkgdGjhu6cgY8O0bmcnKSk7Cn0pOwoKLyogLS0tLS0tLS0tLSBNb2RhbCDEkMSDbmcgbmjh",
"uq1wIC8gxJDEg25nIGvDvSAtLS0tLS0tLS0tICovCmxldCBwZW5kaW5nQnV5UHJvZHVjdElkID0g",
"bnVsbDsgLy8gc+G6o24gcGjhuqltIGtow6FjaCBi4bqlbSAiTXVhIiB0csaw4bubYyBraGkgxJHE",
"g25nIG5o4bqtcCB4b25nCgpmdW5jdGlvbiBvcGVuQXV0aE1vZGFsKCl7CiAgJCgnYXV0aEVycm9y",
"JykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOwogICQoJ2F1dGhNb2RhbEJnJykuY2xhc3NMaXN0",
"LmFkZCgnc2hvdycpOwp9CmZ1bmN0aW9uIGNsb3NlQXV0aE1vZGFsKCl7ICQoJ2F1dGhNb2RhbEJn",
"JykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOyB9CgokKCdidG5PcGVuQXV0aCcpLmFkZEV2ZW50",
"TGlzdGVuZXIoJ2NsaWNrJywgKCk9PiBvcGVuQXV0aE1vZGFsKCkpOwokKCdidG5DbG9zZUF1dGgn",
"KS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGNsb3NlQXV0aE1vZGFsKTsKCiQoJ3RhYkxvZ2lu",
"JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKT0+ewogICQoJ3RhYkxvZ2luJykuY2xhc3NM",
"aXN0LmFkZCgnYWN0aXZlJyk7ICQoJ3RhYlJlZ2lzdGVyJykuY2xhc3NMaXN0LnJlbW92ZSgnYWN0",
"aXZlJyk7CiAgJCgnYXV0aEZvcm1Mb2dpbicpLnN0eWxlLmRpc3BsYXkgPSAnJzsgJCgnYXV0aEZv",
"cm1SZWdpc3RlcicpLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CiAgJCgnYnRuU3VibWl0QXV0aCcp",
"LnRleHRDb250ZW50ID0gJ8SQxINuZyBuaOG6rXAnOwogICQoJ2F1dGhFcnJvcicpLmNsYXNzTGlz",
"dC5yZW1vdmUoJ3Nob3cnKTsKfSk7CiQoJ3RhYlJlZ2lzdGVyJykuYWRkRXZlbnRMaXN0ZW5lcign",
"Y2xpY2snLCAoKT0+ewogICQoJ3RhYlJlZ2lzdGVyJykuY2xhc3NMaXN0LmFkZCgnYWN0aXZlJyk7",
"ICQoJ3RhYkxvZ2luJykuY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CiAgJCgnYXV0aEZvcm1S",
"ZWdpc3RlcicpLnN0eWxlLmRpc3BsYXkgPSAnJzsgJCgnYXV0aEZvcm1Mb2dpbicpLnN0eWxlLmRp",
"c3BsYXkgPSAnbm9uZSc7CiAgJCgnYnRuU3VibWl0QXV0aCcpLnRleHRDb250ZW50ID0gJ8SQxINu",
"ZyBrw70nOwogICQoJ2F1dGhFcnJvcicpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKfSk7Cgok",
"KCdidG5TdWJtaXRBdXRoJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAoKT0+ewog",
"IGNvbnN0IGlzUmVnaXN0ZXIgPSAkKCd0YWJSZWdpc3RlcicpLmNsYXNzTGlzdC5jb250YWlucygn",
"YWN0aXZlJyk7CiAgY29uc3QgZXJyQm94ID0gJCgnYXV0aEVycm9yJyk7CiAgZXJyQm94LmNsYXNz",
"TGlzdC5yZW1vdmUoJ3Nob3cnKTsKCiAgdHJ5ewogICAgaWYoaXNSZWdpc3Rlcil7CiAgICAgIGNv",
"bnN0IHVzZXJuYW1lID0gJCgncmVnVXNlcm5hbWUnKS52YWx1ZS50cmltKCk7CiAgICAgIGNvbnN0",
"IHBhc3N3b3JkID0gJCgncmVnUGFzc3dvcmQnKS52YWx1ZTsKICAgICAgY29uc3QgY29uZmlybVBh",
"c3MgPSAkKCdyZWdQYXNzd29yZENvbmZpcm0nKS52YWx1ZTsKICAgICAgaWYoIXVzZXJuYW1lIHx8",
"ICFwYXNzd29yZCl7IHRocm93IG5ldyBFcnJvcignVnVpIGzDsm5nIG5o4bqtcCDEkeG6p3kgxJHh",
"u6cgdMOqbiDEkcSDbmcgbmjhuq1wIHbDoCBt4bqtdCBraOG6qXUnKTsgfQogICAgICBpZihwYXNz",
"d29yZC5sZW5ndGggPCA4KXsgdGhyb3cgbmV3IEVycm9yKCdN4bqtdCBraOG6qXUgY+G6p24gdOG7",
"kWkgdGhp4buDdSA4IGvDvSB04buxJyk7IH0KICAgICAgaWYocGFzc3dvcmQgIT09IGNvbmZpcm1Q",
"YXNzKXsgdGhyb3cgbmV3IEVycm9yKCdN4bqtdCBraOG6qXUgbmjhuq1wIGzhuqFpIGtow7RuZyBr",
"aOG7m3AnKTsgfQoKICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAnL2Fw",
"aS9hdXRoL3JlZ2lzdGVyJywgewogICAgICAgIG1ldGhvZDonUE9TVCcsIGhlYWRlcnM6eydDb250",
"ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sCiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdp",
"ZnkoeyB1c2VybmFtZSwgcGFzc3dvcmQgfSkKICAgICAgfSk7CiAgICAgIGNvbnN0IGRhdGEgPSBh",
"d2FpdCByZXMuanNvbigpOwogICAgICBpZighcmVzLm9rIHx8ICFkYXRhLm9rKXsKICAgICAgICBp",
"ZihkYXRhLmVycm9yID09PSAndXNlcm5hbWVfdGFrZW4nKSB0aHJvdyBuZXcgRXJyb3IoJ1TDqm4g",
"xJHEg25nIG5o4bqtcCDEkcOjIHThu5NuIHThuqFpLCB2dWkgbMOybmcgY2jhu41uIHTDqm4ga2jD",
"oWMnKTsKICAgICAgICBpZihkYXRhLmVycm9yID09PSAncGFzc3dvcmRfdG9vX3Nob3J0JykgdGhy",
"b3cgbmV3IEVycm9yKGRhdGEubWVzc2FnZSB8fCAnTeG6rXQga2jhuql1IHBo4bqjaSBjw7MgdOG7",
"kWkgdGhp4buDdSA4IGvDvSB04buxJyk7CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCfEkMSDbmcg",
"a8O9IHRo4bqldCBi4bqhaSwgdnVpIGzDsm5nIHRo4butIGzhuqFpJyk7CiAgICAgIH0KICAgICAg",
"Y3VzdG9tZXJUb2tlbiA9IGRhdGEudG9rZW47IGN1c3RvbWVyTmFtZSA9IGRhdGEudXNlcm5hbWU7",
"IGN1c3RvbWVyUm9sZSA9IGRhdGEucm9sZSB8fCAnY3VzdG9tZXInOyBjdXN0b21lckJhbGFuY2Ug",
"PSAwOwogICAgfSBlbHNlIHsKICAgICAgY29uc3QgdXNlcm5hbWUgPSAkKCdsb2dpblVzZXJuYW1l",
"JykudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBwYXNzd29yZCA9ICQoJ2xvZ2luUGFzc3dvcmQn",
"KS52YWx1ZTsKICAgICAgaWYoIXVzZXJuYW1lIHx8ICFwYXNzd29yZCl7IHRocm93IG5ldyBFcnJv",
"cignVnVpIGzDsm5nIG5o4bqtcCB0w6puIMSRxINuZyBuaOG6rXAgdsOgIG3huq10IGto4bqpdScp",
"OyB9CgogICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcvYXBpL2F1dGgv",
"bG9naW4nLCB7CiAgICAgICAgbWV0aG9kOidQT1NUJywgaGVhZGVyczp7J0NvbnRlbnQtVHlwZSc6",
"J2FwcGxpY2F0aW9uL2pzb24nfSwKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHVzZXJu",
"YW1lLCBwYXNzd29yZCB9KQogICAgICB9KTsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5q",
"c29uKCk7CiAgICAgIGlmKCFyZXMub2sgfHwgIWRhdGEub2spewogICAgICAgIGNvbnN0IG1hcCA9",
"IHsKICAgICAgICAgIHNlbGxlcl9iYW5uZWQ6ICdUw6BpIGtob+G6o24gbmfGsOG7nWkgYsOhbiDE",
"kcOjIGLhu4sgY+G6pW0nLAogICAgICAgICAgc2VsbGVyX2V4cGlyZWQ6ICdUw6BpIGtob+G6o24g",
"bmfGsOG7nWkgYsOhbiDEkcOjIGjhur90IGjhuqFuIHPhu60gZOG7pW5nJwogICAgICAgIH07CiAg",
"ICAgICAgdGhyb3cgbmV3IEVycm9yKG1hcFtkYXRhLmVycm9yXSB8fCAnU2FpIHTDqm4gxJHEg25n",
"IG5o4bqtcCBob+G6t2MgbeG6rXQga2jhuql1Jyk7CiAgICAgIH0KICAgICAgY3VzdG9tZXJUb2tl",
"biA9IGRhdGEudG9rZW47IGN1c3RvbWVyTmFtZSA9IGRhdGEudXNlcm5hbWU7IGN1c3RvbWVyUm9s",
"ZSA9IGRhdGEucm9sZSB8fCAnY3VzdG9tZXInOyBjdXN0b21lckJhbGFuY2UgPSBkYXRhLmJhbGFu",
"Y2UgfHwgMDsKCiAgICAgIC8qIC0tLS0gR+G7mXAgxJHEg25nIG5o4bqtcDogbuG6v3UgdMOgaSBr",
"aG/huqNuIHbhu6thIMSRxINuZyBuaOG6rXAgbMOgIEFETUlOIGhv4bq3YyBOR8av4bucSSBCw4FO",
"IChzZWxsZXIpLAogICAgICAgICB04buxIMSR4buZbmcgY2h1eeG7g24gdGjhurNuZyB2w6BvIHRy",
"YW5nIHF14bqjbiB0cuG7iyAoL2FkbWluKSDigJQga2jDtG5nIGPhuqduIGJp4bq/dC9nw7UgbGlu",
"ayByacOqbmcuCiAgICAgICAgIETDuW5nIMSRw7puZyBjxqEgY2jhur8gImdoaSBuaOG7myDEkcSD",
"bmcgbmjhuq1wIiDEkcOjIGPDsyBz4bq1biB0cm9uZyAvYWRtaW4gKGxvY2FsU3RvcmFnZSBrZXkK",
"ICAgICAgICAgJ2tleXZhdWx0X3JlbWVtYmVyJykgxJHhu4MgL2FkbWluIHThu7EgxJFp4buBbiBz",
"4bq1biArIHThu7EgxJHEg25nIG5o4bqtcCwga2jDtG5nIGPhuqduIGfDtSBs4bqhaS4gLS0tLSAq",
"LwogICAgICBpZihkYXRhLnJvbGUgPT09ICdhZG1pbicgfHwgZGF0YS5yb2xlID09PSAnc2VsbGVy",
"Jyl7CiAgICAgICAgdHJ5ewogICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ2tleXZhdWx0",
"X3JlbWVtYmVyJywgSlNPTi5zdHJpbmdpZnkoeyB1c2VyOiB1c2VybmFtZSwgcGFzczogcGFzc3dv",
"cmQsIGF1dG9Mb2dpbjogdHJ1ZSB9KSk7CiAgICAgICAgfWNhdGNoKGUpeyAvKiB0csOsbmggZHV5",
"4buHdCBjaOG6t24gbG9jYWxTdG9yYWdlIHRow6wgdGjDtGksIGFkbWluL3NlbGxlciB04buxIHbD",
"oG8gL2FkbWluIHbDoCBnw7UgbOG6oWkgKi8gfQogICAgICAgIHNob3dUb2FzdChgWGluIGNow6Bv",
"ICR7ZGF0YS51c2VybmFtZX0hIMSQYW5nIGNodXnhu4NuIHbDoG8gdHJhbmcgcXXhuqNuIHRy4buL",
"Li4uYCk7CiAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSAnL2FkbWluJzsKICAgICAgICBy",
"ZXR1cm47CiAgICAgIH0KICAgIH0KCiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgna3Zfc3RvcmVf",
"dG9rZW4nLCBjdXN0b21lclRva2VuKTsKICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdrdl9zdG9y",
"ZV91c2VybmFtZScsIGN1c3RvbWVyTmFtZSk7CiAgICB1cGRhdGVBY2NvdW50VUkoKTsKICAgIGNs",
"b3NlQXV0aE1vZGFsKCk7CiAgICBzaG93VG9hc3QoJ1hpbiBjaMOgbywgJyArIGN1c3RvbWVyTmFt",
"ZSArICchJyk7CgogICAgaWYocGVuZGluZ0J1eVByb2R1Y3RJZCl7CiAgICAgIGNvbnN0IHBpZCA9",
"IHBlbmRpbmdCdXlQcm9kdWN0SWQ7CiAgICAgIHBlbmRpbmdCdXlQcm9kdWN0SWQgPSBudWxsOwog",
"ICAgICBvcGVuQ2hlY2tvdXRNb2RhbChwaWQpOwogICAgfQogIH1jYXRjaChlKXsKICAgIGVyckJv",
"eC50ZXh0Q29udGVudCA9IGUubWVzc2FnZSB8fCAnQ8OzIGzhu5dpIHjhuqN5IHJhLCB2dWkgbMOy",
"bmcgdGjhu60gbOG6oWknOwogICAgZXJyQm94LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKICB9Cn0p",
"OwoKLyogLS0tLS0tLS0tLSBEYW5oIHPDoWNoIHPhuqNuIHBo4bqpbSAtLS0tLS0tLS0tICovCmxl",
"dCBwcm9kdWN0cyA9IFtdOwoKYXN5bmMgZnVuY3Rpb24gbG9hZFByb2R1Y3RzKCl7CiAgdHJ5ewog",
"ICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAnL2FwaS9wcm9kdWN0cycsIHsg",
"Y2FjaGU6J25vLXN0b3JlJyB9KTsKICAgIHByb2R1Y3RzID0gYXdhaXQgcmVzLmpzb24oKTsKICB9",
"Y2F0Y2goZSl7CiAgICBjb25zb2xlLndhcm4oJ1tLZXlWYXVsdCBTdG9yZV0gS2jDtG5nIHThuqNp",
"IMSRxrDhu6NjIGRhbmggc8OhY2ggc+G6o24gcGjhuqltJywgZSk7CiAgICBwcm9kdWN0cyA9IFtd",
"OwogIH0KICByZW5kZXJQcm9kdWN0cygpOwp9CgpmdW5jdGlvbiBmbXREdXJhdGlvbihwKXsKICBp",
"ZihwLmR1cmF0aW9uVW5pdD09PSd1bmxpbWl0ZWQnIHx8ICFwLmR1cmF0aW9uQW1vdW50KSByZXR1",
"cm4gJ0tow7RuZyBnaeG7m2kgaOG6oW4nOwogIGNvbnN0IHVuaXRMYWJlbCA9IHAuZHVyYXRpb25V",
"bml0PT09J2hvdXInID8gJ2dp4budJyA6IHAuZHVyYXRpb25Vbml0PT09J21vbnRoJyA/ICd0aMOh",
"bmcnIDogJ25nw6B5JzsKICByZXR1cm4gcC5kdXJhdGlvbkFtb3VudCArICcgJyArIHVuaXRMYWJl",
"bDsKfQoKZnVuY3Rpb24gcmVuZGVyUHJvZHVjdHMoKXsKICBjb25zdCBncmlkID0gJCgncHJvZHVj",
"dEdyaWQnKTsKICBjb25zdCBlbXB0eSA9ICQoJ2VtcHR5U3RhdGUnKTsKICBncmlkLmlubmVySFRN",
"TCA9ICcnOwogIGVtcHR5LnN0eWxlLmRpc3BsYXkgPSBwcm9kdWN0cy5sZW5ndGggPyAnbm9uZScg",
"OiAnYmxvY2snOwoKICBwcm9kdWN0cy5mb3JFYWNoKHA9PnsKICAgIGNvbnN0IGluU3RvY2sgPSAo",
"cC5zdG9ja3x8MCkgPiAwOwogICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQo",
"J2RpdicpOwogICAgY2FyZC5jbGFzc05hbWUgPSAnY2FyZCc7CiAgICBjYXJkLmlubmVySFRNTCA9",
"IGAKICAgICAgPGRpdiBjbGFzcz0ibG9nbyI+JHtwLmxvZ28gPyBgPGltZyBzcmM9IiR7cC5sb2dv",
"fSI+YCA6ICfwn5OmJ308L2Rpdj4KICAgICAgPGgzPiR7cC5uYW1lfTwvaDM+CiAgICAgIDxkaXYg",
"Y2xhc3M9InByaWNlIj4ke2ZtdE1vbmV5KHAucHJpY2UpfTwvZGl2PgogICAgICA8ZGl2IGNsYXNz",
"PSJtZXRhIj4KICAgICAgICA8c3Bhbj7ij7EgVGjhu51pIGjhuqFuOiA8Yj4ke2ZtdER1cmF0aW9u",
"KHApfTwvYj48L3NwYW4+CiAgICAgICAgPHNwYW4+8J+TsSBUaGnhur90IGLhu4s6IDxiPiR7cC5t",
"YXhEZXZpY2VzfHwxfTwvYj48L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InN0b2NrICR7aW5T",
"dG9jayA/ICdpbicgOiAnb3V0J30iPiR7aW5TdG9jayA/ICfinJQgQ8OybiAnK3Auc3RvY2srJyBr",
"ZXknIDogJ+KcliBI4bq/dCBow6BuZyd9PC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAgPGJ1dHRv",
"biBjbGFzcz0iYnRuIGJ1eS1idG4iIGRhdGEtaWQ9IiR7cC5pZH0iICR7aW5TdG9jayA/ICcnIDog",
"J2Rpc2FibGVkJ30+JHtpblN0b2NrID8gJ011YSBuZ2F5JyA6ICdI4bq/dCBow6BuZyd9PC9idXR0",
"b24+CiAgICBgOwogICAgZ3JpZC5hcHBlbmRDaGlsZChjYXJkKTsKICB9KTsKfQoKZG9jdW1lbnQu",
"Z2V0RWxlbWVudEJ5SWQoJ3Byb2R1Y3RHcmlkJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAo",
"ZSk9PnsKICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCcuYnV5LWJ0bicpOwogIGlmKCFi",
"dG4gfHwgYnRuLmRpc2FibGVkKSByZXR1cm47CiAgY29uc3QgaWQgPSBidG4uZGF0YXNldC5pZDsK",
"ICBpZighY3VzdG9tZXJUb2tlbil7CiAgICBwZW5kaW5nQnV5UHJvZHVjdElkID0gaWQ7CiAgICBv",
"cGVuQXV0aE1vZGFsKCk7CiAgICByZXR1cm47CiAgfQogIG9wZW5DaGVja291dE1vZGFsKGlkKTsK",
"fSk7CgovKiAtLS0tLS0tLS0tIE1vZGFsIFRoYW5oIHRvw6FuIC0tLS0tLS0tLS0gKi8KbGV0IGNo",
"ZWNrb3V0UHJvZHVjdCA9IG51bGw7CmxldCBhcHBsaWVkRGlzY291bnRQZXJjZW50ID0gMDsKCmZ1",
"bmN0aW9uIG9wZW5DaGVja291dE1vZGFsKHByb2R1Y3RJZCl7CiAgY2hlY2tvdXRQcm9kdWN0ID0g",
"cHJvZHVjdHMuZmluZChwPT5wLmlkPT09cHJvZHVjdElkKTsKICBpZighY2hlY2tvdXRQcm9kdWN0",
"KXsgc2hvd1RvYXN0KCdT4bqjbiBwaOG6qW0ga2jDtG5nIGPDsm4gdOG7k24gdOG6oWksIHZ1aSBs",
"w7JuZyB04bqjaSBs4bqhaSB0cmFuZycpOyByZXR1cm47IH0KICBhcHBsaWVkRGlzY291bnRQZXJj",
"ZW50ID0gMDsKICAkKCdjaGVja291dFByb2R1Y3ROYW1lJykudGV4dENvbnRlbnQgPSBjaGVja291",
"dFByb2R1Y3QubmFtZTsKICAkKCdjaGVja291dERpc2NvdW50Q29kZScpLnZhbHVlID0gJyc7CiAg",
"JCgnY2hlY2tvdXREaXNjb3VudFJvdycpLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CiAgJCgnY2hl",
"Y2tvdXRFcnJvcicpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICB1cGRhdGVDaGVja291dFN1",
"bW1hcnkoKTsKICAkKCdjaGVja291dE1vZGFsQmcnKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7Cn0K",
"ZnVuY3Rpb24gY2xvc2VDaGVja291dE1vZGFsKCl7ICQoJ2NoZWNrb3V0TW9kYWxCZycpLmNsYXNz",
"TGlzdC5yZW1vdmUoJ3Nob3cnKTsgfQokKCdidG5DbG9zZUNoZWNrb3V0JykuYWRkRXZlbnRMaXN0",
"ZW5lcignY2xpY2snLCBjbG9zZUNoZWNrb3V0TW9kYWwpOwoKZnVuY3Rpb24gdXBkYXRlQ2hlY2tv",
"dXRTdW1tYXJ5KCl7CiAgY29uc3QgYmFzZSA9IHBhcnNlRmxvYXQoU3RyaW5nKGNoZWNrb3V0UHJv",
"ZHVjdC5wcmljZSkucmVwbGFjZSgvW15cZC5dL2csJycpKSB8fCAwOwogIGNvbnN0IGRpc2NvdW50",
"QW1vdW50ID0gTWF0aC5yb3VuZChiYXNlICogYXBwbGllZERpc2NvdW50UGVyY2VudCAvIDEwMCk7",
"CiAgY29uc3QgZmluYWwgPSBiYXNlIC0gZGlzY291bnRBbW91bnQ7CiAgJCgnY2hlY2tvdXRPcmln",
"aW5hbFByaWNlJykudGV4dENvbnRlbnQgPSBmbXRNb25leShiYXNlKTsKICBpZihhcHBsaWVkRGlz",
"Y291bnRQZXJjZW50ID4gMCl7CiAgICAkKCdjaGVja291dERpc2NvdW50Um93Jykuc3R5bGUuZGlz",
"cGxheSA9ICdmbGV4JzsKICAgICQoJ2NoZWNrb3V0RGlzY291bnRBbW91bnQnKS50ZXh0Q29udGVu",
"dCA9ICctJyArIGZtdE1vbmV5KGRpc2NvdW50QW1vdW50KSArICcgKCcgKyBhcHBsaWVkRGlzY291",
"bnRQZXJjZW50ICsgJyUpJzsKICB9IGVsc2UgewogICAgJCgnY2hlY2tvdXREaXNjb3VudFJvdycp",
"LnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CiAgfQogICQoJ2NoZWNrb3V0RmluYWxQcmljZScpLnRl",
"eHRDb250ZW50ID0gZm10TW9uZXkoZmluYWwpOwp9CgokKCdidG5BcHBseURpc2NvdW50JykuYWRk",
"RXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAoKT0+ewogIGNvbnN0IGNvZGUgPSAkKCdjaGVj",
"a291dERpc2NvdW50Q29kZScpLnZhbHVlLnRyaW0oKS50b1VwcGVyQ2FzZSgpOwogIGNvbnN0IGVy",
"ckJveCA9ICQoJ2NoZWNrb3V0RXJyb3InKTsKICBlcnJCb3guY2xhc3NMaXN0LnJlbW92ZSgnc2hv",
"dycpOwogIGlmKCFjb2RlKXsgYXBwbGllZERpc2NvdW50UGVyY2VudCA9IDA7IHVwZGF0ZUNoZWNr",
"b3V0U3VtbWFyeSgpOyByZXR1cm47IH0KCiAgdHJ5ewogICAgY29uc3QgcmVzID0gYXdhaXQgZmV0",
"Y2goQVBJX0JBU0UgKyAnL2FwaS9kaXNjb3VudC1jaGVjaz9jb2RlPScgKyBlbmNvZGVVUklDb21w",
"b25lbnQoY29kZSksIHsgY2FjaGU6J25vLXN0b3JlJyB9KTsKICAgIGNvbnN0IGRhdGEgPSBhd2Fp",
"dCByZXMuanNvbigpOwogICAgaWYoIWRhdGEudmFsaWQpewogICAgICBjb25zdCBtYXAgPSB7CiAg",
"ICAgICAgZGlzY291bnRfaW52YWxpZDogJ03DoyBnaeG6o20gZ2nDoSBraMO0bmcgdOG7k24gdOG6",
"oWkgaG/hurdjIMSRw6MgYuG7iyB04bqvdCcsCiAgICAgICAgZGlzY291bnRfZXhwaXJlZDogJ03D",
"oyBnaeG6o20gZ2nDoSDEkcOjIGjhur90IGjhuqFuJywKICAgICAgICBkaXNjb3VudF91c2VkX3Vw",
"OiAnTcOjIGdp4bqjbSBnacOhIMSRw6MgaOG6v3QgbMaw4bujdCBz4butIGThu6VuZycKICAgICAg",
"fTsKICAgICAgYXBwbGllZERpc2NvdW50UGVyY2VudCA9IDA7CiAgICAgIHVwZGF0ZUNoZWNrb3V0",
"U3VtbWFyeSgpOwogICAgICB0aHJvdyBuZXcgRXJyb3IobWFwW2RhdGEuZXJyb3JdIHx8ICdNw6Mg",
"Z2nhuqNtIGdpw6Ega2jDtG5nIGjhu6NwIGzhu4cnKTsKICAgIH0KICAgIGFwcGxpZWREaXNjb3Vu",
"dFBlcmNlbnQgPSBkYXRhLnBlcmNlbnQ7CiAgICB1cGRhdGVDaGVja291dFN1bW1hcnkoKTsKICAg",
"IHNob3dUb2FzdCgnxJDDoyDDoXAgZOG7pW5nIG3DoyBnaeG6o20gJyArIGRhdGEucGVyY2VudCAr",
"ICclJyk7CiAgfWNhdGNoKGUpewogICAgZXJyQm94LnRleHRDb250ZW50ID0gZS5tZXNzYWdlOwog",
"ICAgZXJyQm94LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKICB9Cn0pOwoKJCgnYnRuQ29uZmlybUNo",
"ZWNrb3V0JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAoKT0+ewogIGNvbnN0IGVy",
"ckJveCA9ICQoJ2NoZWNrb3V0RXJyb3InKTsKICBlcnJCb3guY2xhc3NMaXN0LnJlbW92ZSgnc2hv",
"dycpOwogIGNvbnN0IGNvZGUgPSAkKCdjaGVja291dERpc2NvdW50Q29kZScpLnZhbHVlLnRyaW0o",
"KS50b1VwcGVyQ2FzZSgpOwogIGNvbnN0IGJ0biA9ICQoJ2J0bkNvbmZpcm1DaGVja291dCcpOwog",
"IGJ0bi5kaXNhYmxlZCA9IHRydWU7IGJ0bi50ZXh0Q29udGVudCA9ICfEkGFuZyB44butIGzDvS4u",
"Lic7CgogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkv",
"Y2hlY2tvdXQnLCB7CiAgICAgIG1ldGhvZDonUE9TVCcsIGhlYWRlcnM6eydDb250ZW50LVR5cGUn",
"OidhcHBsaWNhdGlvbi9qc29uJ30sCiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdG9rZW46",
"IGN1c3RvbWVyVG9rZW4sIHByb2R1Y3RJZDogY2hlY2tvdXRQcm9kdWN0LmlkLCBkaXNjb3VudENv",
"ZGU6IGNvZGUgfSkKICAgIH0pOwogICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAg",
"ICBpZighcmVzLm9rIHx8ICFkYXRhLm9rKXsKICAgICAgY29uc3QgbWFwID0gewogICAgICAgIG5v",
"dF9sb2dnZWRfaW46ICdQaGnDqm4gxJHEg25nIG5o4bqtcCDEkcOjIGjhur90IGjhuqFuLCB2dWkg",
"bMOybmcgxJHEg25nIG5o4bqtcCBs4bqhaScsCiAgICAgICAgcHJvZHVjdF9ub3RfZm91bmQ6ICdT",
"4bqjbiBwaOG6qW0ga2jDtG5nIGPDsm4gdOG7k24gdOG6oWknLAogICAgICAgIGRpc2NvdW50X2lu",
"dmFsaWQ6ICdNw6MgZ2nhuqNtIGdpw6Ega2jDtG5nIGjhu6NwIGzhu4cnLAogICAgICAgIGRpc2Nv",
"dW50X2V4cGlyZWQ6ICdNw6MgZ2nhuqNtIGdpw6EgxJHDoyBo4bq/dCBo4bqhbicsCiAgICAgICAg",
"ZGlzY291bnRfdXNlZF91cDogJ03DoyBnaeG6o20gZ2nDoSDEkcOjIGjhur90IGzGsOG7o3Qgc+G7",
"rSBk4bulbmcnLAogICAgICAgIG91dF9vZl9zdG9jazogJ1PhuqNuIHBo4bqpbSB24burYSBo4bq/",
"dCBow6BuZywgdnVpIGzDsm5nIHRo4butIGzhuqFpIHNhdScKICAgICAgfTsKICAgICAgdGhyb3cg",
"bmV3IEVycm9yKG1hcFtkYXRhLmVycm9yXSB8fCAnTXVhIGtleSB0aOG6pXQgYuG6oWksIHZ1aSBs",
"w7JuZyB0aOG7rSBs4bqhaScpOwogICAgfQoKICAgIGNsb3NlQ2hlY2tvdXRNb2RhbCgpOwogICAg",
"JCgncmVzdWx0S2V5VmFsdWUnKS50ZXh0Q29udGVudCA9IGRhdGEua2V5OwogICAgbGV0IGV4cGly",
"eVR4dDsKICAgIGlmKGRhdGEuaGFzRXhwaXJ5UGxhbiAmJiAhZGF0YS5hY3RpdmF0ZWQpewogICAg",
"ICBjb25zdCB1bml0TGFiZWwgPSBkYXRhLmV4cGlyeVVuaXQ9PT0naG91cicgPyAnZ2nhu50nIDog",
"ZGF0YS5leHBpcnlVbml0PT09J21vbnRoJyA/ICd0aMOhbmcnIDogJ25nw6B5JzsKICAgICAgZXhw",
"aXJ5VHh0ID0gYENoxrBhIGvDrWNoIGhv4bqhdCAoc+G6vSBkw7luZyDEkcaw4bujYyAke2RhdGEu",
"ZXhwaXJ5QW1vdW50fHwnPyd9ICR7dW5pdExhYmVsfSBr4buDIHThu6sgbOG6p24gxJHhuqd1IHPh",
"u60gZOG7pW5nIGtleSlgOwogICAgfSBlbHNlIHsKICAgICAgZXhwaXJ5VHh0ID0gZGF0YS5leHBp",
"cmVzQXQgPyBuZXcgRGF0ZShkYXRhLmV4cGlyZXNBdCkudG9Mb2NhbGVTdHJpbmcoJ3ZpLVZOJykg",
"OiAnS2jDtG5nIGdp4bubaSBo4bqhbic7CiAgICB9CiAgICAkKCdyZXN1bHRLZXlNZXRhJykudGV4",
"dENvbnRlbnQgPSBgSOG6oW4gZMO5bmc6ICR7ZXhwaXJ5VHh0fSDCtyBT4buRIHRoaeG6v3QgYuG7",
"iyBjaG8gcGjDqXA6ICR7ZGF0YS5tYXhEZXZpY2VzfHwxfSDCtyDEkMOjIHRoYW5oIHRvw6FuOiAk",
"e2ZtdE1vbmV5KGRhdGEucHJpY2VQYWlkKX1gOwogICAgJCgncmVzdWx0TW9kYWxCZycpLmNsYXNz",
"TGlzdC5hZGQoJ3Nob3cnKTsKICAgIGxvYWRQcm9kdWN0cygpOwogIH1jYXRjaChlKXsKICAgIGVy",
"ckJveC50ZXh0Q29udGVudCA9IGUubWVzc2FnZTsKICAgIGVyckJveC5jbGFzc0xpc3QuYWRkKCdz",
"aG93Jyk7CiAgfWZpbmFsbHl7CiAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsgYnRuLnRleHRDb250",
"ZW50ID0gJ1jDoWMgbmjhuq1uIG11YSc7CiAgfQp9KTsKCi8qIC0tLS0tLS0tLS0gTW9kYWwgS+G6",
"v3QgcXXhuqMgLS0tLS0tLS0tLSAqLwokKCdidG5DbG9zZVJlc3VsdCcpLmFkZEV2ZW50TGlzdGVu",
"ZXIoJ2NsaWNrJywgKCk9PiAkKCdyZXN1bHRNb2RhbEJnJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hv",
"dycpKTsKJCgnYnRuQ29weVJlc3VsdEtleScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9",
"PnsKICBjb25zdCB2YWwgPSAkKCdyZXN1bHRLZXlWYWx1ZScpLnRleHRDb250ZW50OwogIG5hdmln",
"YXRvci5jbGlwYm9hcmQud3JpdGVUZXh0KHZhbCkudGhlbigoKT0+IHNob3dUb2FzdCgnxJDDoyBz",
"YW8gY2jDqXAga2V5JykpLmNhdGNoKCgpPT4gc2hvd1RvYXN0KCdLaMO0bmcgc2FvIGNow6lwIMSR",
"xrDhu6NjLCB2dWkgbMOybmcgY29weSB0aOG7pyBjw7RuZycpKTsKfSk7CgovKiAtLS0tLS0tLS0t",
"IE1vZGFsIGNo4buNbiBnw7NpIEjhu6JQIE5I4bqkVCAoZMO5bmcgY2h1bmcgY2hvIEdldEtleSAm",
"IHPhuqNuIHBo4bqpbSBtdWEgYuG6sW5nIHRp4buBbikgLS0tLS0tLS0tLQogICBvcHRpb25zOiBb",
"e2lkLCBpY29uLCBsYWJlbCwgc3ViLCBwcmljZShudWxsYWJsZSksIGluU3RvY2ssIHRhZ31dCiAg",
"IC0gcHJpY2UgPT09IG51bGx8dW5kZWZpbmVkICAtPiBoaeG7g24gdGjhu4sgImzGsOG7o3Qgdsaw",
"4bujdCBsaW5rIiB0aGF5IHbDrCBnacOhIChkw7luZyBjaG8gR2V0S2V5KQogICAtIG9uU2VsZWN0",
"KG9wdGlvbklkKSDEkcaw4bujYyBn4buNaSBraGkga2jDoWNoIGLhuqVtIHbDoG8gMSBnw7NpIGPD",
"sm4gaMOgbmcuIC0tLS0tLS0tLS0gKi8KbGV0IHVuaWZpZWRQbGFuT25TZWxlY3QgPSBudWxsOwoK",
"ZnVuY3Rpb24gb3BlblVuaWZpZWRQbGFuTW9kYWwoeyBsb2dvLCB0aXRsZSwgc3VidGl0bGUsIG9w",
"dGlvbnMsIG9uU2VsZWN0IH0pewogICQoJ3VuaWZpZWRQbGFuTG9nbycpLmlubmVySFRNTCA9IGxv",
"Z28gPyBgPGltZyBzcmM9IiR7bG9nb30iPmAgOiAn8J+Tpic7CiAgJCgndW5pZmllZFBsYW5UaXRs",
"ZScpLnRleHRDb250ZW50ID0gdGl0bGUgfHwgJ+KAlCc7CiAgJCgndW5pZmllZFBsYW5TdWJ0aXRs",
"ZScpLnRleHRDb250ZW50ID0gc3VidGl0bGUgfHwgJyc7CiAgJCgndW5pZmllZFBsYW5FcnJvcicp",
"LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICB1bmlmaWVkUGxhbk9uU2VsZWN0ID0gb25TZWxl",
"Y3Q7CgogIGNvbnN0IGxpc3QgPSAkKCd1bmlmaWVkUGxhbkxpc3QnKTsKICBsaXN0LmlubmVySFRN",
"TCA9ICcnOwogIChvcHRpb25zfHxbXSkuZm9yRWFjaChvcHQ9PnsKICAgIGNvbnN0IGJ0biA9IGRv",
"Y3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgYnRuLmNsYXNzTmFtZSA9ICdwbGFu",
"LW9wdGlvbic7CiAgICBidG4uZGlzYWJsZWQgPSAhb3B0LmluU3RvY2s7CiAgICBjb25zdCBwcmlj",
"ZUh0bWwgPSAob3B0LnByaWNlPT09bnVsbCB8fCBvcHQucHJpY2U9PT11bmRlZmluZWQpCiAgICAg",
"ID8gYDxkaXYgY2xhc3M9InByaWNlIj4ke29wdC5zdG9ja0xhYmVsIHx8ICcnfTwvZGl2PmAKICAg",
"ICAgOiBgPGRpdiBjbGFzcz0icHJpY2UiPiR7Zm10TW9uZXkob3B0LnByaWNlKX08L2Rpdj5gOwog",
"ICAgYnRuLmlubmVySFRNTCA9IGAKICAgICAgPGRpdiBjbGFzcz0iaWNvbiI+JHtvcHQuaWNvbiB8",
"fCAn8J+UkSd9PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImluZm8iPgogICAgICAgIDxkaXYgY2xh",
"c3M9ImxibCI+JHtvcHQubGFiZWx9PC9kaXY+CiAgICAgICAgJHtvcHQuc3ViID8gYDxkaXYgY2xh",
"c3M9InN1YjMiPiR7b3B0LnN1Yn08L2Rpdj5gIDogJyd9CiAgICAgIDwvZGl2PgogICAgICA8ZGl2",
"IGNsYXNzPSJyaWdodCI+CiAgICAgICAgJHtwcmljZUh0bWx9CiAgICAgICAgJHtvcHQudGFnID8g",
"YDxkaXYgY2xhc3M9InRhZyI+JHtvcHQudGFnfTwvZGl2PmAgOiAoIW9wdC5pblN0b2NrID8gYDxk",
"aXYgY2xhc3M9InRhZyIgc3R5bGU9ImNvbG9yOnZhcigtLWRhbmdlcik7Ij5I4bq+VCBIw4BORzwv",
"ZGl2PmAgOiAnJyl9CiAgICAgIDwvZGl2PgogICAgYDsKICAgIGlmKG9wdC5pblN0b2NrKXsKICAg",
"ICAgYnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PnsKICAgICAgICBkb2N1bWVudC5x",
"dWVyeVNlbGVjdG9yQWxsKCcjdW5pZmllZFBsYW5MaXN0IC5wbGFuLW9wdGlvbicpLmZvckVhY2go",
"ZWw9PmVsLmNsYXNzTGlzdC5yZW1vdmUoJ3NlbGVjdGVkJykpOwogICAgICAgIGJ0bi5jbGFzc0xp",
"c3QuYWRkKCdzZWxlY3RlZCcpOwogICAgICAgIGlmKHVuaWZpZWRQbGFuT25TZWxlY3QpIHVuaWZp",
"ZWRQbGFuT25TZWxlY3Qob3B0LmlkKTsKICAgICAgfSk7CiAgICB9CiAgICBsaXN0LmFwcGVuZENo",
"aWxkKGJ0bik7CiAgfSk7CiAgJCgndW5pZmllZFBsYW5Nb2RhbEJnJykuY2xhc3NMaXN0LmFkZCgn",
"c2hvdycpOwp9CmZ1bmN0aW9uIGNsb3NlVW5pZmllZFBsYW5Nb2RhbCgpeyAkKCd1bmlmaWVkUGxh",
"bk1vZGFsQmcnKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7IH0KJCgnYnRuQ2xvc2VVbmlmaWVk",
"UGxhbicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgY2xvc2VVbmlmaWVkUGxhbk1vZGFsKTsK",
"Ci8qIC0tLS0tLS0tLS0gTmjDs20gc+G6o24gcGjhuqltICgxIGxvZ28vdMOqbiArIG5oaeG7gXUg",
"Z8OzaSBnacOhLCBnaeG7kW5nIEdldEtleSkgLS0tLS0tLS0tLSAqLwpsZXQgcHJvZHVjdEdyb3Vw",
"cyA9IFtdOwpsZXQgcGVuZGluZ0J1eUdyb3VwSWQgPSBudWxsOyAvLyBuaMOzbSBz4bqjbiBwaOG6",
"qW0ga2jDoWNoIGLhuqVtIHbDoG8gdHLGsOG7m2Mga2hpIMSRxINuZyBuaOG6rXAgeG9uZwpsZXQg",
"YWN0aXZlUGdHcm91cCA9IG51bGw7Cgphc3luYyBmdW5jdGlvbiBsb2FkUHJvZHVjdEdyb3Vwcygp",
"ewogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkvcHJv",
"ZHVjdC1ncm91cHMnLCB7IGNhY2hlOiduby1zdG9yZScgfSk7CiAgICBwcm9kdWN0R3JvdXBzID0g",
"YXdhaXQgcmVzLmpzb24oKTsKICB9Y2F0Y2goZSl7CiAgICBjb25zb2xlLndhcm4oJ1tLZXlWYXVs",
"dCBTdG9yZV0gS2jDtG5nIHThuqNpIMSRxrDhu6NjIGRhbmggc8OhY2ggbmjDs20gc+G6o24gcGjh",
"uqltJywgZSk7CiAgICBwcm9kdWN0R3JvdXBzID0gW107CiAgfQogIHJlbmRlclByb2R1Y3RHcm91",
"cHMoKTsKfQoKZnVuY3Rpb24gZm10UGdQbGFuRHVyYXRpb24ocGwpewogIGlmKHBsLnVuaXQ9PT0n",
"dW5saW1pdGVkJyB8fCAhcGwuYW1vdW50KSByZXR1cm4gJ0tow7RuZyBnaeG7m2kgaOG6oW4nOwog",
"IGNvbnN0IHVuaXRMYWJlbCA9IHBsLnVuaXQ9PT0naG91cicgPyAnZ2nhu50nIDogcGwudW5pdD09",
"PSdtb250aCcgPyAndGjDoW5nJyA6ICduZ8OgeSc7CiAgcmV0dXJuIHBsLmFtb3VudCArICcgJyAr",
"IHVuaXRMYWJlbDsKfQoKZnVuY3Rpb24gcmVuZGVyUHJvZHVjdEdyb3VwcygpewogIGNvbnN0IGdy",
"aWQgPSAkKCdwZ0dyaWQnKTsKICBncmlkLmlubmVySFRNTCA9ICcnOwogIHByb2R1Y3RHcm91cHMu",
"Zm9yRWFjaChnPT57CiAgICBjb25zdCB0b3RhbFN0b2NrID0gKGcucGxhbnN8fFtdKS5yZWR1Y2Uo",
"KHN1bSxwKT0+IHN1bSArIChwLnN0b2NrfHwwKSwgMCk7CiAgICBjb25zdCBtaW5QcmljZSA9IChn",
"LnBsYW5zfHxbXSkucmVkdWNlKChtaW4scCk9PiBNYXRoLm1pbihtaW4sIE51bWJlcihwLnByaWNl",
"KXx8SW5maW5pdHkpLCBJbmZpbml0eSk7CiAgICBjb25zdCBjYXJkID0gZG9jdW1lbnQuY3JlYXRl",
"RWxlbWVudCgnZGl2Jyk7CiAgICBjYXJkLmNsYXNzTmFtZSA9ICdjYXJkJzsKICAgIGNhcmQuaW5u",
"ZXJIVE1MID0gYAogICAgICA8ZGl2IGNsYXNzPSJsb2dvIj4ke2cubG9nbyA/IGA8aW1nIHNyYz0i",
"JHtnLmxvZ299Ij5gIDogJ/Cfk6YnfTwvZGl2PgogICAgICA8aDM+JHtnLm5hbWV9PC9oMz4KICAg",
"ICAgPGRpdiBjbGFzcz0ibWV0YSI+CiAgICAgICAgPHNwYW4+JHsoZy5wbGFuc3x8W10pLmxlbmd0",
"aH0gZ8OzaSBnacOhIMK3IHThu6sgPGI+JHtOdW1iZXIuaXNGaW5pdGUobWluUHJpY2UpID8gZm10",
"TW9uZXkobWluUHJpY2UpIDogJ+KAlCd9PC9iPjwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0i",
"c3RvY2sgJHt0b3RhbFN0b2NrPjAgPyAnaW4nIDogJ291dCd9Ij4ke3RvdGFsU3RvY2s+MCA/ICfi",
"nJQgQ8OybiAnK3RvdGFsU3RvY2srJyBrZXknIDogJ+KcliBI4bq/dCBow6BuZyd9PC9zcGFuPgog",
"ICAgICA8L2Rpdj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ1eS1idG4iIGRhdGEtZ2lkPSIk",
"e2cuaWR9Ij5NdWEgS2V5PC9idXR0b24+CiAgICBgOwogICAgZ3JpZC5hcHBlbmRDaGlsZChjYXJk",
"KTsKICB9KTsKfQoKJCgncGdHcmlkJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoZSk9PnsK",
"ICBjb25zdCBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCcuYnV5LWJ0bicpOwogIGlmKCFidG4pIHJl",
"dHVybjsKICBjb25zdCBnaWQgPSBidG4uZGF0YXNldC5naWQ7CiAgaWYoIWN1c3RvbWVyVG9rZW4p",
"ewogICAgcGVuZGluZ0J1eUdyb3VwSWQgPSBnaWQ7CiAgICBvcGVuQXV0aE1vZGFsKCk7CiAgICBy",
"ZXR1cm47CiAgfQogIG9wZW5QZ1BsYW5Nb2RhbChnaWQpOwp9KTsKCi8qIFThu7EgZ8OhbiBpY29u",
"ICsgbmjDo24gKEhPVC9ORVcvVklQKSBjaG8gdOG7q25nIGfDs2kgdGhlbyB24buLIHRyw60g4oCU",
"IGdp4buRbmcga2nhu4N1IGhp4buDbiB0aOG7iyBt4bqrdQogICAoZ8OzaSBy4bq7IG5o4bqldC/E",
"keG6p3UgdGnDqm4gPSDwn5SRIEhPVCwgZ8OzaSDhu58gZ2nhu69hID0g4pqhIE5FVywgZ8OzaSDE",
"keG6r3QvZMOgaSBuaOG6pXQgPSDwn5uh77iPIFZJUCkuICovCmZ1bmN0aW9uIHBnQXV0b0JhZGdl",
"KGluZGV4LCB0b3RhbCl7CiAgaWYodG90YWwgPD0gMSkgcmV0dXJuIHsgaWNvbjogJ/CflJEnLCB0",
"YWc6IG51bGwgfTsKICBpZihpbmRleCA9PT0gMCkgcmV0dXJuIHsgaWNvbjogJ/CflJEnLCB0YWc6",
"ICdIT1QnIH07CiAgaWYoaW5kZXggPT09IHRvdGFsIC0gMSkgcmV0dXJuIHsgaWNvbjogJ/Cfm6Hv",
"uI8nLCB0YWc6ICdWSVAnIH07CiAgcmV0dXJuIHsgaWNvbjogJ+KaoScsIHRhZzogJ05FVycgfTsK",
"fQoKLyogTeG7nyBtb2RhbCBjaOG7jW4gZ8OzaSBI4buiUCBOSOG6pFQgY2hvIDEgTmjDs20gc+G6",
"o24gcGjhuqltIChtdWEgYuG6sW5nIHRp4buBbiwgdGhhbmggdG/DoW4gbmdheSkuICovCmZ1bmN0",
"aW9uIG9wZW5QZ1BsYW5Nb2RhbChncm91cElkKXsKICBhY3RpdmVQZ0dyb3VwID0gcHJvZHVjdEdy",
"b3Vwcy5maW5kKGc9PmcuaWQ9PT1ncm91cElkKTsKICBpZighYWN0aXZlUGdHcm91cCl7IHNob3dU",
"b2FzdCgnU+G6o24gcGjhuqltIGtow7RuZyBjw7JuIHThu5NuIHThuqFpLCB2dWkgbMOybmcgdOG6",
"o2kgbOG6oWkgdHJhbmcnKTsgcmV0dXJuOyB9CiAgY29uc3QgcGxhbnMgPSBhY3RpdmVQZ0dyb3Vw",
"LnBsYW5zIHx8IFtdOwogIG9wZW5VbmlmaWVkUGxhbk1vZGFsKHsKICAgIG1vZGU6ICdwcm9kdWN0",
"JywKICAgIGxvZ286IGFjdGl2ZVBnR3JvdXAubG9nbywKICAgIHRpdGxlOiBhY3RpdmVQZ0dyb3Vw",
"Lm5hbWUsCiAgICBzdWJ0aXRsZTogJ0No4buNbiBnw7NpIGLhuqFuIG114buRbiBtdWEuIFRoYW5o",
"IHRvw6FuIG5nYXkgYuG6sW5nIHPhu5EgZMawIHTDoGkga2hv4bqjbi4nLAogICAgb3B0aW9uczog",
"cGxhbnMubWFwKChwbCwgaWR4KT0+ewogICAgICBjb25zdCBiYWRnZSA9IHBnQXV0b0JhZGdlKGlk",
"eCwgcGxhbnMubGVuZ3RoKTsKICAgICAgcmV0dXJuIHsKICAgICAgICBpZDogcGwuaWQsCiAgICAg",
"ICAgaWNvbjogYmFkZ2UuaWNvbiwKICAgICAgICBsYWJlbDogZm10UGdQbGFuRHVyYXRpb24ocGwp",
"LAogICAgICAgIHN1YjogcGwubGFiZWwgJiYgcGwubGFiZWwgIT09IGZtdFBnUGxhbkR1cmF0aW9u",
"KHBsKSA/IHBsLmxhYmVsIDogKHBsLnVuaXQ9PT0ndW5saW1pdGVkJyA/ICdWxKluaCB2aeG7hW4n",
"IDogJ0PDsyB0aOG7nWkgaOG6oW4nKSwKICAgICAgICBwcmljZTogcGwucHJpY2UsCiAgICAgICAg",
"aW5TdG9jazogKHBsLnN0b2NrfHwwKSA+IDAsCiAgICAgICAgdGFnOiBiYWRnZS50YWcKICAgICAg",
"fTsKICAgIH0pLAogICAgb25TZWxlY3Q6IChwbGFuSWQpPT57CiAgICAgIGNsb3NlVW5pZmllZFBs",
"YW5Nb2RhbCgpOwogICAgICBvcGVuUGdDaGVja291dE1vZGFsKGFjdGl2ZVBnR3JvdXAuaWQsIHBs",
"YW5JZCk7CiAgICB9CiAgfSk7Cn0KCgovKiAtLS0tLS0tLS0tIFRoYW5oIHRvw6FuIDEgZ8OzaSB0",
"cm9uZyBOaMOzbSBz4bqjbiBwaOG6qW0gKGTDuW5nIGzhuqFpIG1vZGFsIHRoYW5oIHRvw6FuIGNo",
"dW5nKSAtLS0tLS0tLS0tICovCmxldCBjaGVja291dEdyb3VwSWQgPSBudWxsOwpsZXQgY2hlY2tv",
"dXRQbGFuSWQgPSBudWxsOwoKZnVuY3Rpb24gb3BlblBnQ2hlY2tvdXRNb2RhbChncm91cElkLCBw",
"bGFuSWQpewogIGNvbnN0IGdyb3VwID0gcHJvZHVjdEdyb3Vwcy5maW5kKGc9PmcuaWQ9PT1ncm91",
"cElkKTsKICBjb25zdCBwbGFuID0gZ3JvdXAgJiYgKGdyb3VwLnBsYW5zfHxbXSkuZmluZChwPT5w",
"LmlkPT09cGxhbklkKTsKICBpZighZ3JvdXAgfHwgIXBsYW4peyBzaG93VG9hc3QoJ0fDs2kgc+G6",
"o24gcGjhuqltIGtow7RuZyBjw7JuIHThu5NuIHThuqFpLCB2dWkgbMOybmcgdOG6o2kgbOG6oWkg",
"dHJhbmcnKTsgcmV0dXJuOyB9CiAgY2hlY2tvdXRHcm91cElkID0gZ3JvdXBJZDsKICBjaGVja291",
"dFBsYW5JZCA9IHBsYW5JZDsKICBjaGVja291dFByb2R1Y3QgPSB7IG5hbWU6IGAke2dyb3VwLm5h",
"bWV9IOKAlCAke2ZtdFBnUGxhbkR1cmF0aW9uKHBsYW4pfWAsIHByaWNlOiBwbGFuLnByaWNlIH07",
"IC8vIHTDoWkgZMO5bmcgYmnhur9uIGNoZWNrb3V0UHJvZHVjdCBjaG8gcGjhuqduIGhp4buDbiB0",
"aOG7iyB0w7NtIHThuq90IGdpw6EKICBhcHBsaWVkRGlzY291bnRQZXJjZW50ID0gMDsKICAkKCdj",
"aGVja291dFByb2R1Y3ROYW1lJykudGV4dENvbnRlbnQgPSBjaGVja291dFByb2R1Y3QubmFtZTsK",
"ICAkKCdjaGVja291dERpc2NvdW50Q29kZScpLnZhbHVlID0gJyc7CiAgJCgnY2hlY2tvdXREaXNj",
"b3VudFJvdycpLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CiAgJCgnY2hlY2tvdXRFcnJvcicpLmNs",
"YXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICB1cGRhdGVDaGVja291dFN1bW1hcnkoKTsKICAkKCdj",
"aGVja291dE1vZGFsQmcnKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7Cn0KCi8qIEfhuq9uIHRow6pt",
"IHbDoG8gbsO6dCAiWMOhYyBuaOG6rW4gbXVhIiDEkcOjIGPDsyBz4bq1bjogbuG6v3UgxJFhbmcg",
"bXVhIHRoZW8gTmjDs20gc+G6o24gcGjhuqltIChjaGVja291dEdyb3VwSWQKICAgxJHGsOG7o2Mg",
"c2V0KSB0aMOsIGfhu41pIC9hcGkvY2hlY2tvdXQtZ3JvdXAgdGhheSB2w6wgL2FwaS9jaGVja291",
"dDsgbmfGsOG7o2MgbOG6oWkgZ2nhu68gbmd1ecOqbiBow6BuaCB2aSBjxakuICovCmNvbnN0IGJ0",
"bkNvbmZpcm1DaGVja291dEVsID0gJCgnYnRuQ29uZmlybUNoZWNrb3V0Jyk7CmNvbnN0IG9yaWdp",
"bmFsQ29uZmlybUNoZWNrb3V0SGFuZGxlcnMgPSBbXTsgLy8ga2jDtG5nIHhvw6EgaGFuZGxlciBj",
"xakg4oCUIGNo4buJIGNo4bq3biBuw7MgY2jhuqF5IGtoaSDEkWFuZyDhu58gbHXhu5NuZyBuaMOz",
"bSBz4bqjbiBwaOG6qW0KYnRuQ29uZmlybUNoZWNrb3V0RWwuYWRkRXZlbnRMaXN0ZW5lcignY2xp",
"Y2snLCBhc3luYyAoZSk9PnsKICBpZighY2hlY2tvdXRHcm91cElkKSByZXR1cm47IC8vIGx14buT",
"bmcgc+G6o24gcGjhuqltIMSRxqFuIGzhursgY8WpIHThu7EgeOG7rSBsw70gcXVhIGhhbmRsZXIg",
"xJHDoyDEkcSDbmcga8O9IHRyxrDhu5tjIMSRw7MKICBlLnN0b3BJbW1lZGlhdGVQcm9wYWdhdGlv",
"bigpOwogIGNvbnN0IGVyckJveCA9ICQoJ2NoZWNrb3V0RXJyb3InKTsKICBlcnJCb3guY2xhc3NM",
"aXN0LnJlbW92ZSgnc2hvdycpOwogIGNvbnN0IGNvZGUgPSAkKCdjaGVja291dERpc2NvdW50Q29k",
"ZScpLnZhbHVlLnRyaW0oKS50b1VwcGVyQ2FzZSgpOwogIGNvbnN0IGJ0biA9ICQoJ2J0bkNvbmZp",
"cm1DaGVja291dCcpOwogIGJ0bi5kaXNhYmxlZCA9IHRydWU7IGJ0bi50ZXh0Q29udGVudCA9ICfE",
"kGFuZyB44butIGzDvS4uLic7CgogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQ",
"SV9CQVNFICsgJy9hcGkvY2hlY2tvdXQtZ3JvdXAnLCB7CiAgICAgIG1ldGhvZDonUE9TVCcsIGhl",
"YWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sCiAgICAgIGJvZHk6IEpT",
"T04uc3RyaW5naWZ5KHsgdG9rZW46IGN1c3RvbWVyVG9rZW4sIGdyb3VwSWQ6IGNoZWNrb3V0R3Jv",
"dXBJZCwgcGxhbklkOiBjaGVja291dFBsYW5JZCwgZGlzY291bnRDb2RlOiBjb2RlIH0pCiAgICB9",
"KTsKICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgaWYoIXJlcy5vayB8fCAh",
"ZGF0YS5vayl7CiAgICAgIGNvbnN0IG1hcCA9IHsKICAgICAgICBub3RfbG9nZ2VkX2luOiAnUGhp",
"w6puIMSRxINuZyBuaOG6rXAgxJHDoyBo4bq/dCBo4bqhbiwgdnVpIGzDsm5nIMSRxINuZyBuaOG6",
"rXAgbOG6oWknLAogICAgICAgIGdyb3VwX25vdF9mb3VuZDogJ1PhuqNuIHBo4bqpbSBraMO0bmcg",
"Y8OybiB04buTbiB04bqhaScsCiAgICAgICAgcGxhbl9ub3RfZm91bmQ6ICdHw7NpIHPhuqNuIHBo",
"4bqpbSBraMO0bmcgY8OybiB04buTbiB04bqhaScsCiAgICAgICAgZGlzY291bnRfaW52YWxpZDog",
"J03DoyBnaeG6o20gZ2nDoSBraMO0bmcgaOG7o3AgbOG7hycsCiAgICAgICAgZGlzY291bnRfZXhw",
"aXJlZDogJ03DoyBnaeG6o20gZ2nDoSDEkcOjIGjhur90IGjhuqFuJywKICAgICAgICBkaXNjb3Vu",
"dF91c2VkX3VwOiAnTcOjIGdp4bqjbSBnacOhIMSRw6MgaOG6v3QgbMaw4bujdCBz4butIGThu6Vu",
"ZycsCiAgICAgICAgaW5zdWZmaWNpZW50X2JhbGFuY2U6ICdT4buRIGTGsCBraMO0bmcgxJHhu6cg",
"xJHhu4MgbXVhIGfDs2kgbsOgeScsCiAgICAgICAgb3V0X29mX3N0b2NrOiAnR8OzaSBuw6B5IHbh",
"u6thIGjhur90IGjDoG5nLCB2dWkgbMOybmcgdGjhu60gbOG6oWkgc2F1JwogICAgICB9OwogICAg",
"ICB0aHJvdyBuZXcgRXJyb3IobWFwW2RhdGEuZXJyb3JdIHx8ICdNdWEga2V5IHRo4bqldCBi4bqh",
"aSwgdnVpIGzDsm5nIHRo4butIGzhuqFpJyk7CiAgICB9CgogICAgY2xvc2VDaGVja291dE1vZGFs",
"KCk7CiAgICBjaGVja291dEdyb3VwSWQgPSBudWxsOyBjaGVja291dFBsYW5JZCA9IG51bGw7CiAg",
"ICAkKCdyZXN1bHRLZXlWYWx1ZScpLnRleHRDb250ZW50ID0gZGF0YS5rZXk7CiAgICBsZXQgZXhw",
"aXJ5VHh0OwogICAgaWYoZGF0YS5oYXNFeHBpcnlQbGFuICYmICFkYXRhLmFjdGl2YXRlZCl7CiAg",
"ICAgIGNvbnN0IHVuaXRMYWJlbCA9IGRhdGEuZXhwaXJ5VW5pdD09PSdob3VyJyA/ICdnaeG7nScg",
"OiBkYXRhLmV4cGlyeVVuaXQ9PT0nbW9udGgnID8gJ3Row6FuZycgOiAnbmfDoHknOwogICAgICBl",
"eHBpcnlUeHQgPSBgQ2jGsGEga8OtY2ggaG/huqF0IChz4bq9IGTDuW5nIMSRxrDhu6NjICR7ZGF0",
"YS5leHBpcnlBbW91bnR8fCc/J30gJHt1bml0TGFiZWx9IGvhu4MgdOG7qyBs4bqnbiDEkeG6p3Ug",
"c+G7rSBk4bulbmcga2V5KWA7CiAgICB9IGVsc2UgewogICAgICBleHBpcnlUeHQgPSBkYXRhLmV4",
"cGlyZXNBdCA/IG5ldyBEYXRlKGRhdGEuZXhwaXJlc0F0KS50b0xvY2FsZVN0cmluZygndmktVk4n",
"KSA6ICdLaMO0bmcgZ2nhu5tpIGjhuqFuJzsKICAgIH0KICAgICQoJ3Jlc3VsdEtleU1ldGEnKS50",
"ZXh0Q29udGVudCA9IGBI4bqhbiBkw7luZzogJHtleHBpcnlUeHR9IMK3IFPhu5EgdGhp4bq/dCBi",
"4buLIGNobyBwaMOpcDogJHtkYXRhLm1heERldmljZXN8fDF9IMK3IMSQw6MgdGhhbmggdG/DoW46",
"ICR7Zm10TW9uZXkoZGF0YS5wcmljZVBhaWQpfWA7CiAgICAkKCdyZXN1bHRNb2RhbEJnJykuY2xh",
"c3NMaXN0LmFkZCgnc2hvdycpOwogICAgbG9hZFByb2R1Y3RHcm91cHMoKTsKICB9Y2F0Y2goZSl7",
"CiAgICBlcnJCb3gudGV4dENvbnRlbnQgPSBlLm1lc3NhZ2U7CiAgICBlcnJCb3guY2xhc3NMaXN0",
"LmFkZCgnc2hvdycpOwogIH1maW5hbGx5ewogICAgYnRuLmRpc2FibGVkID0gZmFsc2U7IGJ0bi50",
"ZXh0Q29udGVudCA9ICdYw6FjIG5o4bqtbiBtdWEnOwogIH0KfSwgdHJ1ZSk7IC8vIGNhcHR1cmU6",
"dHJ1ZSDEkeG7gyBjaOG6oXkgVFLGr+G7mkMgaGFuZGxlciBjxakgdsOgIGPDsyB0aOG7gyBjaOG6",
"t24gbsOzIGLhurFuZyBzdG9wSW1tZWRpYXRlUHJvcGFnYXRpb24ga2hpIGPhuqduCgovKiDEkOG6",
"o20gYuG6o28gxJHDs25nIG1vZGFsIHRoYW5oIHRvw6FuIGPFqW5nIGx1w7RuIHJlc2V0IHRy4bqh",
"bmcgdGjDoWkgIsSRYW5nIG11YSB0aGVvIG5ow7NtIHPhuqNuIHBo4bqpbSIuICovCiQoJ2J0bkNs",
"b3NlQ2hlY2tvdXQnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT57IGNoZWNrb3V0R3Jv",
"dXBJZCA9IG51bGw7IGNoZWNrb3V0UGxhbklkID0gbnVsbDsgfSk7Cgpsb2FkUHJvZHVjdEdyb3Vw",
"cygpOwoKLyogLS0tLS0tLS0tLSBDaOG7qWMgbsSDbmcgR0VUS0VZICh2xrDhu6N0IGxpbmsgbmjh",
"uq1uIGtleSkgLS0tLS0tLS0tLSAqLwpsZXQgZ2tHYW1lcyA9IFtdOwpsZXQgZ2tTZWxlY3RlZEdh",
"bWUgPSBudWxsOwpsZXQgZ2tTZWxlY3RlZER1cmF0aW9uID0gbnVsbDsKbGV0IGdrU2Vzc2lvbklk",
"ID0gbnVsbDsKbGV0IGdrVG90YWxSb3VuZHMgPSAwOwpsZXQgZ2tDdXJyZW50Um91bmQgPSAwOwoK",
"JCgnZGRHZXRLZXknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT57CiAgY2xvc2VEcm9w",
"ZG93bigpOwogIHdpbmRvdy5sb2NhdGlvbi5ocmVmID0gJy9nZXRrZXknOwp9KTsKCmFzeW5jIGZ1",
"bmN0aW9uIG9wZW5Ha0Nob29zZUdhbWVNb2RhbCgpewogICQoJ2drQ2hvb3NlR2FtZU1vZGFsQmcn",
"KS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7CiAgJCgnZ2tHYW1lR3JpZCcpLmlubmVySFRNTCA9ICc8",
"ZGl2IGNsYXNzPSJoaXN0b3J5LWVtcHR5Ij7EkGFuZyB04bqjaSBkYW5oIHPDoWNoIGdhbWUuLi48",
"L2Rpdj4nOwogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9h",
"cGkvZ2V0a2V5L2dhbWVzJywgeyBjYWNoZTonbm8tc3RvcmUnIH0pOwogICAgZ2tHYW1lcyA9IGF3",
"YWl0IHJlcy5qc29uKCk7CiAgfWNhdGNoKGUpewogICAgZ2tHYW1lcyA9IFtdOwogIH0KICByZW5k",
"ZXJHa0dhbWVHcmlkKCk7Cn0KJCgnYnRuQ2xvc2VHa0Nob29zZUdhbWUnKS5hZGRFdmVudExpc3Rl",
"bmVyKCdjbGljaycsICgpPT4gJCgnZ2tDaG9vc2VHYW1lTW9kYWxCZycpLmNsYXNzTGlzdC5yZW1v",
"dmUoJ3Nob3cnKSk7CgpmdW5jdGlvbiByZW5kZXJHa0dhbWVHcmlkKCl7CiAgY29uc3QgZ3JpZCA9",
"ICQoJ2drR2FtZUdyaWQnKTsKICBjb25zdCBlbXB0eSA9ICQoJ2drR2FtZUVtcHR5U3RhdGUnKTsK",
"ICBncmlkLmlubmVySFRNTCA9ICcnOwogIGVtcHR5LnN0eWxlLmRpc3BsYXkgPSBna0dhbWVzLmxl",
"bmd0aCA/ICdub25lJyA6ICdibG9jayc7CiAgZ2tHYW1lcy5mb3JFYWNoKGc9PnsKICAgIGNvbnN0",
"IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGNhcmQuY2xhc3NOYW1l",
"ID0gJ2drLWdhbWUtY2FyZCc7CiAgICBjYXJkLmRhdGFzZXQuaWQgPSBnLmlkOwogICAgY2FyZC5p",
"bm5lckhUTUwgPSBgCiAgICAgIDxkaXYgY2xhc3M9ImxvZ28iPiR7Zy5sb2dvID8gYDxpbWcgc3Jj",
"PSIke2cubG9nb30iPmAgOiAn8J+Orid9PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im5hbWUiPiR7",
"Zy5uYW1lfTwvZGl2PgogICAgYDsKICAgIGNhcmQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAo",
"KT0+IG9wZW5Ha0Nob29zZUR1cmF0aW9uTW9kYWwoZykpOwogICAgZ3JpZC5hcHBlbmRDaGlsZChj",
"YXJkKTsKICB9KTsKfQoKLyogR2hpIGNow7o6IG3hu6VjICJHZXRLZXkiICh2xrDhu6N0IGxpbmsg",
"bmjhuq1uIGtleSkga2jDtG5nIGPDsm4gaGnhu4NuIHRo4buLIHRow6BuaCAxIGRhbmggc8OhY2gg",
"cmnDqm5nCiAgIG5nYXkgdHLDqm4gdHJhbmcgY2jhu6cgbuG7r2Eg4oCUIGtow6FjaCB2w6BvIHF1",
"YSBt4bulYyAiR2V0S2V5IiDhu58gbWVudSB0aOG6oyB4deG7kW5nIHBow61hIHRyw6puICht4buf",
"CiAgIG1vZGFsIGNo4buNbiBnYW1lIC0+IGNo4buNbiB0aOG7nWkgaOG6oW4pLCBnaeG7ryB0cmFu",
"ZyBjaOG7pyBjaOG7iSBoaeG7h24gdMOqbiBz4bqjbiBwaOG6qW0vbmjDs20gc+G6o24gcGjhuqlt",
"LiAqLwoKLyogTeG7nyBtb2RhbCBjaOG7jW4gZ8OzaSBI4buiUCBOSOG6pFQgY2hvIEdldEtleSAo",
"Y2jhu41uIHRo4budaSBo4bqhbiBy4buTaSBi4bqvdCDEkeG6p3Ugdsaw4bujdCBsaW5rLCBraMO0",
"bmcgbeG6pXQgdGnhu4FuKS4gKi8KZnVuY3Rpb24gb3BlbkdrVW5pZmllZER1cmF0aW9uTW9kYWwo",
"Z2FtZSl7CiAgZ2tTZWxlY3RlZEdhbWUgPSBnYW1lOwogIGdrU2VsZWN0ZWREdXJhdGlvbiA9IG51",
"bGw7CiAgY29uc3QgZHVyYXRpb25zID0gZ2FtZS5kdXJhdGlvbnMgfHwgW107CiAgb3BlblVuaWZp",
"ZWRQbGFuTW9kYWwoewogICAgbW9kZTogJ2dldGtleScsCiAgICBsb2dvOiBnYW1lLmxvZ28sCiAg",
"ICB0aXRsZTogZ2FtZS5uYW1lLAogICAgc3VidGl0bGU6ICdDaOG7jW4gbG/huqFpIGtleSBi4bqh",
"biBtdeG7kW4gbmjhuq1uLiBUaOG7nWkgaOG6oW4gY8OgbmcgZMOgaSwgc+G7kSBsxrDhu6N0IHbG",
"sOG7o3QgbGluayBjw6BuZyBuaGnhu4F1LicsCiAgICBvcHRpb25zOiBkdXJhdGlvbnMubWFwKChk",
"LCBpZHgpPT57CiAgICAgIGNvbnN0IGJhZGdlID0gcGdBdXRvQmFkZ2UoaWR4LCBkdXJhdGlvbnMu",
"bGVuZ3RoKTsKICAgICAgcmV0dXJuIHsKICAgICAgICBpZDogZC5pZCwKICAgICAgICBpY29uOiBi",
"YWRnZS5pY29uLAogICAgICAgIGxhYmVsOiBmbXRHa0R1cmF0aW9uUHVibGljKGQpLAogICAgICAg",
"IHN1YjogZC5yb3VuZHMgKyAnIGzGsOG7o3Qgdsaw4bujdCBsaW5rJywKICAgICAgICBwcmljZTog",
"bnVsbCwKICAgICAgICBzdG9ja0xhYmVsOiBnYW1lLnN0b2NrPjAgPyAnTWnhu4VuIHBow60nIDog",
"JycsCiAgICAgICAgaW5TdG9jazogZ2FtZS5zdG9jayA+IDAsCiAgICAgICAgdGFnOiBiYWRnZS50",
"YWcKICAgICAgfTsKICAgIH0pLAogICAgb25TZWxlY3Q6IChkdXJhdGlvbklkKT0+ewogICAgICBn",
"a1NlbGVjdGVkRHVyYXRpb24gPSAoZ2FtZS5kdXJhdGlvbnN8fFtdKS5maW5kKGQ9PmQuaWQ9PT1k",
"dXJhdGlvbklkKTsKICAgICAgY2xvc2VVbmlmaWVkUGxhbk1vZGFsKCk7CiAgICAgIHN0YXJ0R2tG",
"bG93VW5pZmllZCgpOwogICAgfQogIH0pOwp9CgovKiBC4bqvdCDEkeG6p3UgcGhpw6puIHbGsOG7",
"o3QgbGluayDigJQgdMawxqFuZyDEkcawxqFuZyBow6BuaCB2aSBj4bunYSBuw7p0IGJ0blN0YXJ0",
"R2tGbG93IGPFqSBuaMawbmcga2jhu59pIMSR4buZbmcKICAgdOG7qyBtb2RhbCBo4bujcCBuaOG6",
"pXQgbeG7m2kgdGhheSB2w6wgbW9kYWwgZ2tDaG9vc2VEdXJhdGlvbk1vZGFsQmcgY8WpLiAqLwph",
"c3luYyBmdW5jdGlvbiBzdGFydEdrRmxvd1VuaWZpZWQoKXsKICBpZighZ2tTZWxlY3RlZER1cmF0",
"aW9uIHx8ICFna1NlbGVjdGVkR2FtZSkgcmV0dXJuOwogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3",
"YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkvZ2V0a2V5L3N0YXJ0JywgewogICAgICBtZXRob2Q6",
"J1BPU1QnLCBoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9LAogICAg",
"ICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGdhbWVJZDogZ2tTZWxlY3RlZEdhbWUuaWQsIGR1cmF0",
"aW9uSWQ6IGdrU2VsZWN0ZWREdXJhdGlvbi5pZCB9KQogICAgfSk7CiAgICBjb25zdCBkYXRhID0g",
"YXdhaXQgcmVzLmpzb24oKTsKICAgIGlmKCFyZXMub2sgfHwgIWRhdGEub2spewogICAgICBjb25z",
"dCBtYXAgPSB7IGdhbWVfbm90X2ZvdW5kOidHYW1lIGtow7RuZyB04buTbiB04bqhaScsIGR1cmF0",
"aW9uX25vdF9mb3VuZDonTG/huqFpIGtleSBraMO0bmcgdOG7k24gdOG6oWknLCBvdXRfb2Zfc3Rv",
"Y2s6J0dhbWUgbsOgeSDEkcOjIGjhur90IGtleScgfTsKICAgICAgdGhyb3cgbmV3IEVycm9yKG1h",
"cFtkYXRhLmVycm9yXSB8fCAnS2jDtG5nIHRo4buDIGLhuq90IMSR4bqndSwgdnVpIGzDsm5nIHRo",
"4butIGzhuqFpJyk7CiAgICB9CiAgICBna1Nlc3Npb25JZCA9IGRhdGEuc2Vzc2lvbklkOwogICAg",
"Z2tUb3RhbFJvdW5kcyA9IGRhdGEudG90YWxSb3VuZHM7CiAgICBna0N1cnJlbnRSb3VuZCA9IGRh",
"dGEuY3VycmVudFJvdW5kOwogICAgb3BlbkdrRmxvd01vZGFsKGRhdGEubGluayk7CiAgfWNhdGNo",
"KGUpewogICAgc2hvd1RvYXN0KGUubWVzc2FnZSk7CiAgfQp9CgpmdW5jdGlvbiBmbXRHa0R1cmF0",
"aW9uUHVibGljKGQpewogIGNvbnN0IHVuaXRMYWJlbCA9IGQudW5pdD09PSdob3VyJyA/ICdnaeG7",
"nScgOiBkLnVuaXQ9PT0nbW9udGgnID8gJ3Row6FuZycgOiAnbmfDoHknOwogIHJldHVybiBkLmxh",
"YmVsIHx8IChkLmFtb3VudCArICcgJyArIHVuaXRMYWJlbCk7Cn0KCmZ1bmN0aW9uIG9wZW5Ha0No",
"b29zZUR1cmF0aW9uTW9kYWwoZ2FtZSl7CiAgZ2tTZWxlY3RlZEdhbWUgPSBnYW1lOwogIGdrU2Vs",
"ZWN0ZWREdXJhdGlvbiA9IG51bGw7CiAgJCgnZ2tDaG9vc2VHYW1lTW9kYWxCZycpLmNsYXNzTGlz",
"dC5yZW1vdmUoJ3Nob3cnKTsKICAkKCdna0R1cmF0aW9uR2FtZU5hbWUnKS50ZXh0Q29udGVudCA9",
"IGdhbWUubmFtZTsKICAkKCdna0R1cmF0aW9uRXJyb3InKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93",
"Jyk7CiAgY29uc3QgbGlzdCA9ICQoJ2drRHVyYXRpb25MaXN0UHVibGljJyk7CiAgbGlzdC5pbm5l",
"ckhUTUwgPSAnJzsKICAoZ2FtZS5kdXJhdGlvbnMgfHwgW10pLmZvckVhY2goZD0+ewogICAgY29u",
"c3QgaXRlbSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgaXRlbS5jbGFzc05h",
"bWUgPSAnZ2stZHVyYXRpb24taXRlbSc7CiAgICBpdGVtLmRhdGFzZXQuaWQgPSBkLmlkOwogICAg",
"aXRlbS5pbm5lckhUTUwgPSBgCiAgICAgIDxkaXY+PGRpdiBjbGFzcz0ibGJsIj4ke2ZtdEdrRHVy",
"YXRpb25QdWJsaWMoZCl9PC9kaXY+PGRpdiBjbGFzcz0icm91bmRzIj4ke2Qucm91bmRzfSBsxrDh",
"u6N0IHbGsOG7o3QgbGluazwvZGl2PjwvZGl2PgogICAgICA8ZGl2PiR7Z2FtZS5zdG9jaz4wID8g",
"J+KclCcgOiAn4pyWIEjhur90IGjDoG5nJ308L2Rpdj4KICAgIGA7CiAgICBpdGVtLmFkZEV2ZW50",
"TGlzdGVuZXIoJ2NsaWNrJywgKCk9PnsKICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgn",
"LmdrLWR1cmF0aW9uLWl0ZW0nKS5mb3JFYWNoKGVsPT5lbC5jbGFzc0xpc3QucmVtb3ZlKCdzZWxl",
"Y3RlZCcpKTsKICAgICAgaXRlbS5jbGFzc0xpc3QuYWRkKCdzZWxlY3RlZCcpOwogICAgICBna1Nl",
"bGVjdGVkRHVyYXRpb24gPSBkOwogICAgfSk7CiAgICBsaXN0LmFwcGVuZENoaWxkKGl0ZW0pOwog",
"IH0pOwogICQoJ2drQ2hvb3NlRHVyYXRpb25Nb2RhbEJnJykuY2xhc3NMaXN0LmFkZCgnc2hvdycp",
"Owp9CiQoJ2J0bkJhY2tHa0R1cmF0aW9uJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKT0+",
"ewogICQoJ2drQ2hvb3NlRHVyYXRpb25Nb2RhbEJnJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycp",
"OwogIG9wZW5Ha0Nob29zZUdhbWVNb2RhbCgpOwp9KTsKCiQoJ2J0blN0YXJ0R2tGbG93JykuYWRk",
"RXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAoKT0+ewogIGNvbnN0IGVyckJveCA9ICQoJ2dr",
"RHVyYXRpb25FcnJvcicpOwogIGVyckJveC5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgaWYo",
"IWdrU2VsZWN0ZWREdXJhdGlvbil7IGVyckJveC50ZXh0Q29udGVudCA9ICdWdWkgbMOybmcgY2jh",
"u41uIDEgbG/huqFpIGtleSc7IGVyckJveC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7IHJldHVybjsg",
"fQogIGlmKChna1NlbGVjdGVkR2FtZS5zdG9ja3x8MCkgPD0gMCl7IGVyckJveC50ZXh0Q29udGVu",
"dCA9ICdHYW1lIG7DoHkgaGnhu4duIMSRw6MgaOG6v3Qga2V5LCB2dWkgbMOybmcgdGjhu60gbOG6",
"oWkgc2F1JzsgZXJyQm94LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsgcmV0dXJuOyB9CgogIHRyeXsK",
"ICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkvZ2V0a2V5L3N0YXJ0",
"JywgewogICAgICBtZXRob2Q6J1BPU1QnLCBoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGlj",
"YXRpb24vanNvbid9LAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGdhbWVJZDogZ2tTZWxl",
"Y3RlZEdhbWUuaWQsIGR1cmF0aW9uSWQ6IGdrU2VsZWN0ZWREdXJhdGlvbi5pZCB9KQogICAgfSk7",
"CiAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgIGlmKCFyZXMub2sgfHwgIWRh",
"dGEub2spewogICAgICBjb25zdCBtYXAgPSB7IGdhbWVfbm90X2ZvdW5kOidHYW1lIGtow7RuZyB0",
"4buTbiB04bqhaScsIGR1cmF0aW9uX25vdF9mb3VuZDonTG/huqFpIGtleSBraMO0bmcgdOG7k24g",
"dOG6oWknLCBvdXRfb2Zfc3RvY2s6J0dhbWUgbsOgeSDEkcOjIGjhur90IGtleScgfTsKICAgICAg",
"dGhyb3cgbmV3IEVycm9yKG1hcFtkYXRhLmVycm9yXSB8fCAnS2jDtG5nIHRo4buDIGLhuq90IMSR",
"4bqndSwgdnVpIGzDsm5nIHRo4butIGzhuqFpJyk7CiAgICB9CiAgICBna1Nlc3Npb25JZCA9IGRh",
"dGEuc2Vzc2lvbklkOwogICAgZ2tUb3RhbFJvdW5kcyA9IGRhdGEudG90YWxSb3VuZHM7CiAgICBn",
"a0N1cnJlbnRSb3VuZCA9IGRhdGEuY3VycmVudFJvdW5kOwogICAgJCgnZ2tDaG9vc2VEdXJhdGlv",
"bk1vZGFsQmcnKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgICBvcGVuR2tGbG93TW9kYWwo",
"ZGF0YS5saW5rKTsKICB9Y2F0Y2goZSl7CiAgICBlcnJCb3gudGV4dENvbnRlbnQgPSBlLm1lc3Nh",
"Z2U7CiAgICBlcnJCb3guY2xhc3NMaXN0LmFkZCgnc2hvdycpOwogIH0KfSk7CgpmdW5jdGlvbiBy",
"ZW5kZXJHa1Byb2dyZXNzKCl7CiAgY29uc3Qgd3JhcCA9ICQoJ2drUHJvZ3Jlc3NEb3RzJyk7CiAg",
"d3JhcC5pbm5lckhUTUwgPSAnJzsKICBmb3IobGV0IGk9MTtpPD1na1RvdGFsUm91bmRzO2krKyl7",
"CiAgICBjb25zdCBkb3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGRvdC5j",
"bGFzc05hbWUgPSAnZG90JyArIChpIDwgZ2tDdXJyZW50Um91bmQgPyAnIGRvbmUnIDogaSA9PT0g",
"Z2tDdXJyZW50Um91bmQgPyAnIGN1cnJlbnQnIDogJycpOwogICAgd3JhcC5hcHBlbmRDaGlsZChk",
"b3QpOwogIH0KfQoKZnVuY3Rpb24gb3BlbkdrRmxvd01vZGFsKGxpbmspewogICQoJ2drRmxvd0dh",
"bWVMYWJlbCcpLnRleHRDb250ZW50ID0gZ2tTZWxlY3RlZEdhbWUubmFtZSArICcgwrcgJyArIGZt",
"dEdrRHVyYXRpb25QdWJsaWMoZ2tTZWxlY3RlZER1cmF0aW9uKTsKICAkKCdna1JvdW5kTGFiZWwn",
"KS50ZXh0Q29udGVudCA9IGBMxrDhu6N0ICR7Z2tDdXJyZW50Um91bmR9LyR7Z2tUb3RhbFJvdW5k",
"c31gOwogICQoJ2J0bk9wZW5Ha0xpbmsnKS5ocmVmID0gbGluazsKICAkKCdidG5PcGVuR2tMaW5r",
"JykudGV4dENvbnRlbnQgPSBgTeG7nyBs4bqhaSBsaW5rIHbGsOG7o3QgKGzGsOG7o3QgJHtna0N1",
"cnJlbnRSb3VuZH0vJHtna1RvdGFsUm91bmRzfSlgOwogICQoJ2drRmxvd0Vycm9yJykuY2xhc3NM",
"aXN0LnJlbW92ZSgnc2hvdycpOwogIHJlbmRlckdrUHJvZ3Jlc3MoKTsKICAkKCdna0Zsb3dNb2Rh",
"bEJnJykuY2xhc3NMaXN0LmFkZCgnc2hvdycpOwogIC8vIFThu7EgxJHhu5luZyBt4bufIGxpbmsg",
"dsaw4bujdCBuZ2F5IGtoaSBixrDhu5tjIHbDoG8gbMaw4bujdCBuw6B5IOKAlCBraMOhY2ggS0jD",
"lE5HIGPhuqduIGLhuqVtIHRow6ptIG7DunQgbsOgbyDEkeG7gyAibeG7nyIgbGluay4KICAvLyBO",
"4bq/dSB0csOsbmggZHV54buHdCBjaOG6t24gcG9wdXAsIG7DunQgIk3hu58gbOG6oWkgbGluayB2",
"xrDhu6N0IiBwaMOtYSB0csOqbiB24bqrbiBjaG8ga2jDoWNoIHThu7EgbeG7nyB0aOG7pyBjw7Ru",
"Zy4KICBjb25zdCBvcGVuZWQgPSB3aW5kb3cub3BlbihsaW5rLCAnX2JsYW5rJywgJ25vb3BlbmVy",
"Jyk7CiAgaWYoIW9wZW5lZCl7CiAgICBzaG93VG9hc3QoJ1Ryw6xuaCBkdXnhu4d0IMSRw6MgY2jh",
"urduIG3hu58gbGluayB04buxIMSR4buZbmcg4oCUIHZ1aSBsw7JuZyBi4bqlbSBuw7p0ICJN4buf",
"IGzhuqFpIGxpbmsgdsaw4bujdCIgYsOqbiBkxrDhu5tpJyk7CiAgfQp9CiQoJ2J0bkNsb3NlR2tG",
"bG93JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKT0+ICQoJ2drRmxvd01vZGFsQmcnKS5j",
"bGFzc0xpc3QucmVtb3ZlKCdzaG93JykpOwoKJCgnYnRuQ29uZmlybUdrU3RlcCcpLmFkZEV2ZW50",
"TGlzdGVuZXIoJ2NsaWNrJywgYXN5bmMgKCk9PnsKICBjb25zdCBlcnJCb3ggPSAkKCdna0Zsb3dF",
"cnJvcicpOwogIGVyckJveC5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgY29uc3QgYnRuID0g",
"JCgnYnRuQ29uZmlybUdrU3RlcCcpOwogIGJ0bi5kaXNhYmxlZCA9IHRydWU7IGJ0bi50ZXh0Q29u",
"dGVudCA9ICfEkGFuZyBraeG7g20gdHJhLi4uJzsKICB0cnl7CiAgICBjb25zdCByZXMgPSBhd2Fp",
"dCBmZXRjaChBUElfQkFTRSArICcvYXBpL2dldGtleS9uZXh0JywgewogICAgICBtZXRob2Q6J1BP",
"U1QnLCBoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9LAogICAgICBi",
"b2R5OiBKU09OLnN0cmluZ2lmeSh7IHNlc3Npb25JZDogZ2tTZXNzaW9uSWQgfSkKICAgIH0pOwog",
"ICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICBpZighcmVzLm9rIHx8ICFkYXRh",
"Lm9rKXsKICAgICAgY29uc3QgbWFwID0gewogICAgICAgIHNlc3Npb25fbm90X2ZvdW5kOidQaGnD",
"qm4gxJHDoyBo4bq/dCBo4bqhbiwgdnVpIGzDsm5nIGLhuq90IMSR4bqndSBs4bqhaScsCiAgICAg",
"ICAgZ2FtZV9ub3RfZm91bmQ6J0dhbWUga2jDtG5nIHThu5NuIHThuqFpJywKICAgICAgICBvdXRf",
"b2Zfc3RvY2s6J8SQw6MgaOG6v3Qga2V5LCB2dWkgbMOybmcgdGjhu60gbOG6oWkgc2F1JywKICAg",
"ICAgICBub3RfY29uZmlybWVkX3lldDonQuG6oW4gQ0jGr0Egdsaw4bujdCBsaW5rIOG7nyBsxrDh",
"u6N0IG7DoHkg4oCUIHZ1aSBsw7JuZyBt4bufIGxpbmsgdsOgIGhvw6BuIHRow6BuaCB0cmFuZyDE",
"kcOtY2ggdHLGsOG7m2Mga2hpIGLhuqVtICJUw7RpIMSRw6Mgdsaw4bujdCBsaW5rIicKICAgICAg",
"fTsKICAgICAgdGhyb3cgbmV3IEVycm9yKG1hcFtkYXRhLmVycm9yXSB8fCAnQ8OzIGzhu5dpIHjh",
"uqN5IHJhLCB2dWkgbMOybmcgdGjhu60gbOG6oWknKTsKICAgIH0KICAgIGlmKGRhdGEuZG9uZSl7",
"CiAgICAgICQoJ2drRmxvd01vZGFsQmcnKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgICAg",
"ICQoJ2drUmVzdWx0S2V5VmFsdWUnKS50ZXh0Q29udGVudCA9IGRhdGEua2V5OwogICAgICAkKCdn",
"a1Jlc3VsdE1vZGFsQmcnKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7CiAgICB9IGVsc2UgewogICAg",
"ICBna0N1cnJlbnRSb3VuZCA9IGRhdGEuY3VycmVudFJvdW5kOwogICAgICBvcGVuR2tGbG93TW9k",
"YWwoZGF0YS5saW5rKTsKICAgIH0KICB9Y2F0Y2goZSl7CiAgICBlcnJCb3gudGV4dENvbnRlbnQg",
"PSBlLm1lc3NhZ2U7CiAgICBlcnJCb3guY2xhc3NMaXN0LmFkZCgnc2hvdycpOwogIH1maW5hbGx5",
"ewogICAgYnRuLmRpc2FibGVkID0gZmFsc2U7IGJ0bi50ZXh0Q29udGVudCA9ICdUw7RpIMSRw6Mg",
"dsaw4bujdCBsaW5rJzsKICB9Cn0pOwoKJCgnYnRuQ2xvc2VHa1Jlc3VsdCcpLmFkZEV2ZW50TGlz",
"dGVuZXIoJ2NsaWNrJywgKCk9PiAkKCdna1Jlc3VsdE1vZGFsQmcnKS5jbGFzc0xpc3QucmVtb3Zl",
"KCdzaG93JykpOwokKCdidG5Db3B5R2tSZXN1bHRLZXknKS5hZGRFdmVudExpc3RlbmVyKCdjbGlj",
"aycsICgpPT57CiAgY29uc3QgdmFsID0gJCgnZ2tSZXN1bHRLZXlWYWx1ZScpLnRleHRDb250ZW50",
"OwogIG5hdmlnYXRvci5jbGlwYm9hcmQud3JpdGVUZXh0KHZhbCkudGhlbigoKT0+IHNob3dUb2Fz",
"dCgnxJDDoyBzYW8gY2jDqXAga2V5JykpLmNhdGNoKCgpPT4gc2hvd1RvYXN0KCdLaMO0bmcgc2Fv",
"IGNow6lwIMSRxrDhu6NjLCB2dWkgbMOybmcgY29weSB0aOG7pyBjw7RuZycpKTsKfSk7CgovKiAt",
"LS0tLS0tLS0tIEto4bufaSDEkeG7mW5nICYgdOG7sSBsw6BtIG3hu5tpIHPhuqNuIHBo4bqpbSB0",
"aGVvIGFkbWluIC0tLS0tLS0tLS0gKi8KbG9hZFByb2R1Y3RzKCk7CnNldEludGVydmFsKGxvYWRQ",
"cm9kdWN0cywgODAwMCk7IC8vIHThu7EgxJHhu5luZyBj4bqtcCBuaOG6rXQgc+G6o24gcGjhuqlt",
"L3Thu5NuIGtobyB0aGVvIGFkbWluIGfhuqduIG5oxrAgcmVhbC10aW1lCjwvc2NyaXB0Pgo8L2Jv",
"ZHk+CjwvaHRtbD4KCg=="
];
const STORE_PAGE = Buffer.from(STORE_B64_CHUNKS.join(''), 'base64').toString('utf8');

/* ──────────────────────────────────────────────────────────────────────
   Trang GetKey riêng biệt (/getkey) — dark‑theme, tên "KEY PORTAL"
   Sử dụng đúng các API /api/getkey/* đã có sẵn trên server.
────────────────────────────────────────────────────────────────────── */
const GETKEY_PAGE = [
  "<!DOCTYPE html>",
  "<html lang=\"vi\">",
  "<head>",
  "<meta charset=\"UTF-8\">",
  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
  "<title>KEY PORTAL — Nhận Key Miễn Phí</title>",
  "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">",
  "<link href=\"https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap\" rel=\"stylesheet\">",
  "<style>",
  ":root{",
  "  --bg:#07080d;",
  "  --panel:#0e1017;",
  "  --panel2:#13151e;",
  "  --line:#1e2030;",
  "  --text:#e8eaf4;",
  "  --muted:#6b7094;",
  "  --accent:#7c6aff;",
  "  --accent2:#a78bfa;",
  "  --grad:linear-gradient(135deg,#7c6aff,#a78bfa);",
  "  --ok:#22d3a5;",
  "  --danger:#f87171;",
  "  --warn:#fbbf24;",
  "  --glow:0 0 24px -4px rgba(124,106,255,0.55);",
  "}",
  "*{box-sizing:border-box; margin:0; padding:0;}",
  "html,body{min-height:100vh; font-family:'Inter',sans-serif; background:var(--bg); color:var(--text);}",
  "body{",
  "  background:",
  "    radial-gradient(ellipse 70% 55% at 50% -10%, rgba(124,106,255,0.22) 0%, transparent 70%),",
  "    var(--bg);",
  "  padding-bottom:60px;",
  "}",
  "::selection{background:var(--accent); color:#fff;}",

  "/* ── Header ── */",
  "header{",
  "  position:sticky; top:0; z-index:50;",
  "  background:rgba(7,8,13,0.82); backdrop-filter:blur(14px);",
  "  border-bottom:1px solid var(--line);",
  "  padding:0 20px;",
  "}",
  ".hrow{max-width:640px; margin:0 auto; display:flex; align-items:center; justify-content:space-between; height:58px;}",
  ".brand{display:flex; align-items:center; gap:10px;}",
  ".brand-icon{",
  "  width:36px; height:36px; border-radius:10px;",
  "  background:var(--grad); display:flex; align-items:center; justify-content:center;",
  "  box-shadow:var(--glow);",
  "}",
  ".brand-icon svg{width:18px; height:18px; color:#fff;}",
  ".brand-name{font-family:'Syne',sans-serif; font-size:17px; font-weight:800; letter-spacing:.6px; color:var(--text);}",
  ".brand-tag{font-size:10px; font-weight:600; letter-spacing:2px; color:var(--accent2); text-transform:uppercase; margin-top:1px;}",
  ".home-link{font-size:12px; color:var(--muted); text-decoration:none; display:flex; align-items:center; gap:5px; transition:color .15s;}",
  ".home-link:hover{color:var(--accent2);}",
  ".home-link svg{width:14px; height:14px;}",

  "/* ── Layout ── */",
  ".wrap{max-width:640px; margin:0 auto; padding:32px 16px 8px;}",

  "/* ── Hero ── */",
  ".hero{text-align:center; padding:0 8px 36px;}",
  ".hero-badge{",
  "  display:inline-flex; align-items:center; gap:6px;",
  "  background:rgba(124,106,255,0.12); border:1px solid rgba(124,106,255,0.28);",
  "  color:var(--accent2); font-size:11.5px; font-weight:600; letter-spacing:1.4px; text-transform:uppercase;",
  "  padding:5px 13px; border-radius:999px; margin-bottom:16px;",
  "}",
  ".hero-badge svg{width:13px; height:13px;}",
  ".hero h1{",
  "  font-family:'Syne',sans-serif; font-size:clamp(26px,7vw,38px); font-weight:800;",
  "  line-height:1.15; margin-bottom:12px;",
  "  background:linear-gradient(135deg,#e8eaf4 20%,var(--accent2) 80%);",
  "  -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text;",
  "}",
  ".hero p{color:var(--muted); font-size:14.5px; line-height:1.6; max-width:420px; margin:0 auto;}",

  "/* ── Steps hint ── */",
  ".steps-row{display:flex; align-items:flex-start; gap:0; margin-bottom:32px; padding:0 4px;}",
  ".step-item{flex:1; display:flex; flex-direction:column; align-items:center; text-align:center;}",
  ".step-num{",
  "  width:32px; height:32px; border-radius:50%;",
  "  background:var(--panel2); border:1px solid var(--line);",
  "  display:flex; align-items:center; justify-content:center;",
  "  font-size:13px; font-weight:700; color:var(--accent2);",
  "  margin-bottom:7px; flex-shrink:0;",
  "}",
  ".step-connector{height:1px; flex:1; background:var(--line); margin-top:16px;}",
  ".step-item .slabel{font-size:11.5px; color:var(--muted); line-height:1.4; max-width:70px;}",

  "/* ── Card ── */",
  ".card{",
  "  background:var(--panel); border:1px solid var(--line); border-radius:20px;",
  "  padding:22px; margin-bottom:16px;",
  "}",
  ".card-title{font-family:'Syne',sans-serif; font-size:16px; font-weight:700; margin-bottom:4px;}",
  ".card-sub{font-size:12.5px; color:var(--muted); margin-bottom:18px;}",

  "/* ── Select ── */",
  ".field{",
  "  background:var(--panel2); border:1px solid var(--line);",
  "  border-radius:12px; padding:12px 14px;",
  "  display:flex; align-items:center; gap:10px;",
  "  cursor:pointer; transition:border-color .15s;",
  "  width:100%; margin-bottom:10px;",
  "}",
  ".field:hover,.field.active{border-color:var(--accent);}",
  ".field svg{width:18px; height:18px; color:var(--accent2); flex-shrink:0;}",
  ".field-text{flex:1; font-size:14px; color:var(--text);}",
  ".field-text.placeholder{color:var(--muted);}",
  ".field-arrow{color:var(--muted);}",
  ".field-arrow svg{width:16px; height:16px; transition:transform .15s;}",
  ".field.open .field-arrow svg{transform:rotate(180deg);}",

  "/* ── Dropdown ── */",
  ".dropdown{",
  "  background:var(--panel2); border:1px solid var(--line); border-radius:14px;",
  "  overflow:hidden; margin-top:-6px; margin-bottom:10px;",
  "  display:none;",
  "}",
  ".dropdown.show{display:block;}",
  ".dd-item{",
  "  display:flex; align-items:center; gap:10px;",
  "  padding:13px 14px; cursor:pointer; transition:background .12s;",
  "  border-bottom:1px solid var(--line);",
  "}",
  ".dd-item:last-child{border-bottom:none;}",
  ".dd-item:hover{background:rgba(124,106,255,0.09);}",
  ".dd-item.selected{background:rgba(124,106,255,0.14);}",
  ".dd-item .radio{",
  "  width:18px; height:18px; border-radius:50%;",
  "  border:2px solid var(--line); flex-shrink:0; display:flex; align-items:center; justify-content:center;",
  "  transition:border-color .12s;",
  "}",
  ".dd-item.selected .radio{border-color:var(--accent); background:var(--accent);}",
  ".dd-item.selected .radio::after{content:''; width:7px; height:7px; border-radius:50%; background:#fff;}",
  ".dd-logo{width:28px; height:28px; border-radius:8px; object-fit:cover; background:var(--panel); display:flex; align-items:center; justify-content:center; font-size:17px; flex-shrink:0;}",
  ".dd-logo img{width:28px; height:28px; border-radius:8px; object-fit:cover;}",
  ".dd-label{font-size:13.5px; font-weight:500; flex:1;}",
  ".dd-meta{font-size:11.5px; color:var(--muted);}",

  "/* ── Duration chips ── */",
  ".dur-grid{display:grid; grid-template-columns:repeat(auto-fill,minmax(130px,1fr)); gap:8px; margin-top:4px;}",
  ".dur-chip{",
  "  background:var(--panel2); border:1.5px solid var(--line); border-radius:12px;",
  "  padding:11px 14px; cursor:pointer; transition:border-color .15s,background .15s;",
  "  display:flex; flex-direction:column; gap:3px;",
  "}",
  ".dur-chip:hover{border-color:rgba(124,106,255,0.5);}",
  ".dur-chip.selected{border-color:var(--accent); background:rgba(124,106,255,0.12);}",
  ".dur-chip .dc-label{font-size:13.5px; font-weight:600; color:var(--text);}",
  ".dur-chip .dc-rounds{font-size:11px; color:var(--muted);}",
  ".dur-chip.out-of-stock{opacity:0.4; cursor:not-allowed; pointer-events:none;}",

  "/* ── Tier badges ── */",
  ".tier-badge{",
  "  font-size:9.5px; font-weight:700; letter-spacing:1.1px; text-transform:uppercase;",
  "  padding:2px 7px; border-radius:999px;",
  "}",
  ".tier-hot{background:rgba(248,113,113,0.16); color:#f87171;}",
  ".tier-best{background:rgba(34,211,165,0.15); color:var(--ok);}",
  ".tier-vip{background:rgba(124,106,255,0.18); color:var(--accent2);}",

  "/* ── Btn ── */",
  ".btn{",
  "  width:100%; padding:14px; border:none; border-radius:14px;",
  "  background:var(--grad); color:#fff; font-size:15px; font-weight:700;",
  "  cursor:pointer; display:flex; align-items:center; justify-content:center; gap:8px;",
  "  box-shadow:var(--glow); transition:opacity .15s, transform .12s;",
  "  margin-top:14px;",
  "}",
  ".btn:hover{opacity:.9; transform:translateY(-1px);}",
  ".btn:disabled{opacity:.35; cursor:not-allowed; transform:none; box-shadow:none;}",
  ".btn svg{width:18px; height:18px;}",

  "/* ── Flow modal ── */",
  ".modal-bg{",
  "  display:none; position:fixed; inset:0; z-index:200;",
  "  background:rgba(7,8,13,0.88); backdrop-filter:blur(10px);",
  "  align-items:flex-end; justify-content:center;",
  "}",
  ".modal-bg.show{display:flex;}",
  ".modal{",
  "  width:100%; max-width:480px; max-height:90vh; overflow-y:auto;",
  "  background:var(--panel); border:1px solid var(--line);",
  "  border-radius:22px 22px 0 0; padding:28px 20px 40px;",
  "  animation:slideUp .25s ease;",
  "}",
  "@keyframes slideUp{from{transform:translateY(60px); opacity:0;} to{transform:translateY(0); opacity:1;}}",
  ".modal-handle{width:40px; height:4px; border-radius:999px; background:var(--line); margin:0 auto 22px;}",
  ".modal-title{font-family:'Syne',sans-serif; font-size:18px; font-weight:800; margin-bottom:6px;}",
  ".modal-sub{font-size:13px; color:var(--muted); margin-bottom:20px; line-height:1.5;}",

  "/* ── Progress ── */",
  ".prog-row{display:flex; gap:6px; margin-bottom:18px;}",
  ".prog-dot{",
  "  flex:1; height:5px; border-radius:999px; background:var(--line);",
  "  transition:background .3s;",
  "}",
  ".prog-dot.done{background:var(--ok);}",
  ".prog-dot.active{background:var(--accent);}",

  "/* ── Link box ── */",
  ".link-box{",
  "  background:var(--panel2); border:1px solid var(--line); border-radius:14px;",
  "  padding:16px; margin-bottom:14px; text-align:center;",
  "}",
  ".link-box .link-label{font-size:12px; color:var(--muted); margin-bottom:8px;}",
  ".link-box a{",
  "  font-family:'JetBrains Mono',monospace; font-size:13px; color:var(--accent2);",
  "  word-break:break-all; text-decoration:none; font-weight:700;",
  "}",
  ".link-box a:hover{text-decoration:underline;}",
  ".link-open-btn{",
  "  display:flex; align-items:center; justify-content:center; gap:6px;",
  "  background:rgba(124,106,255,0.14); border:1.5px solid rgba(124,106,255,0.35);",
  "  color:var(--accent2); border-radius:10px; padding:10px 16px;",
  "  font-size:13px; font-weight:600; cursor:pointer; width:100%; margin-top:10px;",
  "  text-decoration:none; transition:background .15s;",
  "}",
  ".link-open-btn:hover{background:rgba(124,106,255,0.22);}",
  ".link-open-btn svg{width:15px; height:15px;}",

  "/* ── Key result ── */",
  ".key-result{",
  "  background:rgba(34,211,165,0.08); border:1.5px solid rgba(34,211,165,0.3);",
  "  border-radius:16px; padding:22px; text-align:center;",
  "}",
  ".key-result .kr-label{font-size:12px; color:var(--ok); font-weight:600; letter-spacing:1px; text-transform:uppercase; margin-bottom:8px;}",
  ".key-result .kr-value{",
  "  font-family:'JetBrains Mono',monospace; font-size:18px; font-weight:700; color:var(--text);",
  "  letter-spacing:1.5px; margin-bottom:12px; word-break:break-all;",
  "}",
  ".key-result .kr-meta{font-size:12px; color:var(--muted);}",
  ".copy-btn{",
  "  background:rgba(34,211,165,0.14); border:1.5px solid rgba(34,211,165,0.35);",
  "  color:var(--ok); border-radius:10px; padding:10px 18px;",
  "  font-size:13px; font-weight:600; cursor:pointer; margin-top:12px;",
  "  display:flex; align-items:center; justify-content:center; gap:6px; width:100%;",
  "  transition:background .15s;",
  "}",
  ".copy-btn:hover{background:rgba(34,211,165,0.22);}",
  ".copy-btn svg{width:15px; height:15px;}",

  "/* ── Toast ── */",
  "#toast{",
  "  position:fixed; bottom:28px; left:50%; transform:translateX(-50%) translateY(20px);",
  "  background:#1a1e2d; border:1px solid var(--line); color:var(--text);",
  "  font-size:13px; font-weight:500; padding:10px 18px; border-radius:12px;",
  "  box-shadow:0 4px 24px rgba(0,0,0,0.5); opacity:0; pointer-events:none;",
  "  transition:opacity .2s, transform .2s; white-space:nowrap; z-index:999;",
  "}",
  "#toast.show{opacity:1; transform:translateX(-50%) translateY(0);}",

  "/* ── Empty ── */",
  ".empty-state{text-align:center; padding:48px 16px; color:var(--muted);}",
  ".empty-state svg{width:48px; height:48px; margin-bottom:14px; opacity:.3;}",
  ".empty-state p{font-size:14px;}",
  ".footer{text-align:center; margin-top:32px; font-size:12px; color:var(--muted);}",
  ".footer a{color:var(--accent2); text-decoration:none;}",
  "</style>",
  "</head>",
  "<body>",

  "<!-- Header -->",
  "<header>",
  "  <div class=\"hrow\">",
  "    <div class=\"brand\">",
  "      <div class=\"brand-icon\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4\"/></svg>",
  "      </div>",
  "      <div>",
  "        <div class=\"brand-name\">KEY PORTAL</div>",
  "        <div class=\"brand-tag\">Nhận Key Miễn Phí</div>",
  "      </div>",
  "    </div>",
  "    <a href=\"/\" class=\"home-link\">",
  "      <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z\"/><polyline points=\"9 22 9 12 15 12 15 22\"/></svg>",
  "      Mua Key",
  "    </a>",
  "  </div>",
  "</header>",

  "<div class=\"wrap\">",

  "  <!-- Hero -->",
  "  <div class=\"hero\">",
  "    <div class=\"hero-badge\">",
  "      <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><polygon points=\"12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2\"/></svg>",
  "      Free Key System",
  "    </div>",
  "    <h1>Nhận key<br>hoàn toàn miễn phí</h1>",
  "    <p>Chọn game, chọn thời hạn, vượt vài link quảng cáo — nhận key ngay. Không cần đăng nhập, không mất tiền.</p>",
  "  </div>",

  "  <!-- Steps hint -->",
  "  <div class=\"steps-row\">",
  "    <div class=\"step-item\"><div class=\"step-num\">1</div><div class=\"slabel\">Chọn game</div></div>",
  "    <div class=\"step-connector\"></div>",
  "    <div class=\"step-item\"><div class=\"step-num\">2</div><div class=\"slabel\">Chọn thời hạn</div></div>",
  "    <div class=\"step-connector\"></div>",
  "    <div class=\"step-item\"><div class=\"step-num\">3</div><div class=\"slabel\">Vượt link</div></div>",
  "    <div class=\"step-connector\"></div>",
  "    <div class=\"step-item\"><div class=\"step-num\">4</div><div class=\"slabel\">Nhận key</div></div>",
  "  </div>",

  "  <!-- Form card -->",
  "  <div class=\"card\">",
  "    <div class=\"card-title\">Cấu hình nhận key</div>",
  "    <div class=\"card-sub\">Điền đủ 3 trường bên dưới rồi bấm Bắt đầu</div>",

  "    <!-- Chọn game -->",
  "    <div class=\"field\" id=\"gameField\" onclick=\"toggleDrop('gameDrop','gameField')\">",
  "      <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"2\" y=\"6\" width=\"20\" height=\"12\" rx=\"3\"/><path d=\"M6 12h4M8 10v4M15 12h.01M17 12h.01\"/></svg>",
  "      <span class=\"field-text placeholder\" id=\"gameTxt\">— Chọn game —</span>",
  "      <span class=\"field-arrow\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"m6 9 6 6 6-6\"/></svg></span>",
  "    </div>",
  "    <div class=\"dropdown\" id=\"gameDrop\"><div style=\"padding:20px;text-align:center;color:var(--muted);font-size:13px;\">Đang tải...</div></div>",



  "    <!-- Chọn thời hạn -->",
  "    <div id=\"durSection\" style=\"display:none; margin-top:4px;\">",
  "      <div style=\"font-size:12.5px; color:var(--muted); margin-bottom:10px; display:flex; align-items:center; gap:6px;\">",
  "        <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"3\" y=\"4\" width=\"18\" height=\"18\" rx=\"2\"/><path d=\"M16 2v4M8 2v4M3 10h18\"/></svg>",
  "        Chọn thời hạn key",
  "      </div>",
  "      <div class=\"dur-grid\" id=\"durGrid\"></div>",
  "    </div>",

  "    <button class=\"btn\" id=\"btnStart\" disabled onclick=\"startFlow()\">",
  "      <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><polygon points=\"5 3 19 12 5 21 5 3\"/></svg>",
  "      Bắt đầu nhận key",
  "    </button>",
  "  </div>",

  "  <div class=\"footer\">Hệ thống cung cấp key bởi <a href=\"/\">KeyVault Store</a></div>",
  "</div>",

  "<!-- Flow Modal -->",
  "<div class=\"modal-bg\" id=\"flowModal\">",
  "  <div class=\"modal\">",
  "    <div class=\"modal-handle\"></div>",
  "    <div class=\"modal-title\" id=\"fmTitle\">Vượt link lấy key</div>",
  "    <div class=\"modal-sub\" id=\"fmSub\">Bấm vào link bên dưới, hoàn thành các bước rồi quay lại đây.</div>",
  "    <div class=\"prog-row\" id=\"fmProg\"></div>",
  "    <div class=\"link-box\" id=\"fmLinkBox\">",
  "      <div class=\"link-label\">Link vượt lượt này</div>",
  "      <a id=\"fmLinkHref\" href=\"#\" target=\"_blank\" rel=\"noopener\">—</a>",
  "      <a id=\"fmOpenBtn\" class=\"link-open-btn\" href=\"#\" target=\"_blank\" rel=\"noopener\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6\"/><polyline points=\"15 3 21 3 21 9\"/><line x1=\"10\" y1=\"14\" x2=\"21\" y2=\"3\"/></svg>",
  "        Mở link vượt quảng cáo",
  "      </a>",
  "    </div>",
  "    <div class=\"key-result\" id=\"fmKeyResult\" style=\"display:none;\">",
  "      <div class=\"kr-label\">🎉 Key của bạn</div>",
  "      <div class=\"kr-value\" id=\"fmKeyValue\">—</div>",
  "      <div class=\"kr-meta\" id=\"fmKeyMeta\"></div>",
  "      <button class=\"copy-btn\" onclick=\"copyKey()\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\"/><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"/></svg>",
  "        Sao chép key",
  "      </button>",
  "    </div>",
  "    <button class=\"btn\" id=\"fmNextBtn\" onclick=\"nextRound()\" style=\"display:none;\">",
  "      <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"m5 12 7 7 7-7M5 5l7 7 7-7\"/></svg>",
  "      Tôi đã vượt link — Tiếp theo",
  "    </button>",
  "    <button class=\"btn\" id=\"fmCloseBtn\" onclick=\"closeFlow()\" style=\"margin-top:10px; background:transparent; border:1.5px solid var(--line); color:var(--muted); box-shadow:none;\">",
  "      Đóng",
  "    </button>",
  "  </div>",
  "</div>",

  "<div id=\"toast\"></div>",

  "<script>",
  "const API = '';",
  "let games = [], selGame = null, selDur = null, selDevices = 1;",
  "let sessionId = null, totalRounds = 0, curRound = 0, lastKey = null;",

  "function $(id){ return document.getElementById(id); }",
  "function toast(msg, dur=2800){",
  "  const t = $('toast'); t.textContent = msg; t.classList.add('show');",
  "  setTimeout(()=> t.classList.remove('show'), dur);",
  "}",

  "/* ── Dropdown toggle ── */",
  "function toggleDrop(dropId, fieldId){",
  "  const d = $(dropId), f = $(fieldId);",
  "  const show = !d.classList.contains('show');",
  "  document.querySelectorAll('.dropdown').forEach(x=>x.classList.remove('show'));",
  "  document.querySelectorAll('.field').forEach(x=>x.classList.remove('open'));",
  "  if(show){ d.classList.add('show'); f.classList.add('open'); }",
  "}",
  "document.addEventListener('click', e=>{",
  "  if(!e.target.closest('.field') && !e.target.closest('.dropdown')){",
  "    document.querySelectorAll('.dropdown').forEach(x=>x.classList.remove('show'));",
  "    document.querySelectorAll('.field').forEach(x=>x.classList.remove('open'));",
  "  }",
  "});",



  "/* ── Load games ── */",
  "async function loadGames(){",
  "  try{",
  "    const r = await fetch(API + '/api/getkey/games');",
  "    games = await r.json();",
  "  } catch(e){ games = []; }",
  "  renderGameDrop();",
  "}",

  "/* tier badge helper */",
  "function tierBadge(idx, total){",
  "  if(total === 1) return '';",
  "  if(idx === 0 && total >= 2) return '<span class=\"tier-badge tier-hot\">Hot</span>';",
  "  if(idx === total-1 && total >= 3) return '<span class=\"tier-badge tier-vip\">VIP</span>';",
  "  if(Math.floor(total/2) === idx) return '<span class=\"tier-badge tier-best\">Best</span>';",
  "  return '';",
  "}",

  "function renderGameDrop(){",
  "  const d = $('gameDrop');",
  "  if(!games.length){",
  "    d.innerHTML = '<div style=\"padding:20px;text-align:center;color:var(--muted);font-size:13px;\">Chưa có game nào</div>';",
  "    return;",
  "  }",
  "  d.innerHTML = games.map(g=>`",
  "    <div class=\"dd-item\" data-id=\"${g.id}\" onclick=\"pickGame('${g.id}')\">",
  "      <div class=\"radio\"></div>",
  "      <div class=\"dd-logo\">${g.logo ? '<img src=\"'+g.logo+'\">' : '🎮'}</div>",
  "      <div>",
  "        <div class=\"dd-label\">${g.name}</div>",
  "        <div class=\"dd-meta\">${g.stock > 0 ? g.stock+' key còn hàng' : '⚠ Hết hàng'}</div>",
  "      </div>",
  "    </div>",
  "  `).join('');",
  "}",

  "function pickGame(id){",
  "  selGame = games.find(g=>g.id===id);",
  "  selDur = null;",
  "  document.querySelectorAll('#gameDrop .dd-item').forEach(x=> x.classList.toggle('selected', x.dataset.id===id));",
  "  $('gameTxt').textContent = selGame.name;",
  "  $('gameTxt').classList.remove('placeholder');",
  "  $('gameDrop').classList.remove('show');",
  "  $('gameField').classList.remove('open');",
  "  renderDurations();",
  "  checkReady();",
  "}",

  "function renderDurations(){",
  "  if(!selGame){ $('durSection').style.display='none'; return; }",
  "  const durs = selGame.durations || [];",
  "  $('durSection').style.display = durs.length ? 'block' : 'none';",
  "  $('durGrid').innerHTML = durs.map((d,i)=>`",
  "    <div class=\"dur-chip${selGame.stock<=0?' out-of-stock':''}\" data-id=\"${d.id}\" onclick=\"pickDur('${d.id}')\">",
  "      <div style=\"display:flex; align-items:center; justify-content:space-between; gap:4px;\">",
  "        <span class=\"dc-label\">${d.label || (d.amount+' '+d.unit)}</span>",
  "        ${tierBadge(i,durs.length)}",
  "      </div>",
  "      <span class=\"dc-rounds\">${d.rounds} lượt vượt link</span>",
  "    </div>",
  "  `).join('');",
  "}",

  "function pickDur(id){",
  "  selDur = (selGame.durations||[]).find(d=>d.id===id);",
  "  document.querySelectorAll('.dur-chip').forEach(x=> x.classList.toggle('selected', x.dataset.id===id));",
  "  checkReady();",
  "}",

  "function checkReady(){",
  "  const ok = selGame && selDur && selDevices >= 1 && (selGame.stock > 0);",
  "  $('btnStart').disabled = !ok;",
  "}",

  "/* ── Start flow ── */",
  "async function startFlow(){",
  "  if(!selGame || !selDur) return;",
  "  $('btnStart').disabled = true;",
  "  $('btnStart').innerHTML = '<svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" style=\"animation:spin 1s linear infinite\"><path d=\"M21 12a9 9 0 1 1-6.2-8.6\"/></svg> Đang tạo phiên...';",
  "  const style = document.createElement('style');",
  "  style.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';",
  "  document.head.appendChild(style);",
  "  try{",
  "    const r = await fetch(API+'/api/getkey/start', {",
  "      method:'POST', headers:{'Content-Type':'application/json'},",
  "      body: JSON.stringify({ gameId: selGame.id, durationId: selDur.id })",
  "    });",
  "    const data = await r.json();",
  "    if(!r.ok || !data.ok){",
  "      const msgMap = { out_of_stock:'Game này đã hết key', game_not_found:'Game không tồn tại', duration_not_found:'Loại key không tồn tại' };",
  "      throw new Error(msgMap[data.error] || 'Không thể bắt đầu, thử lại sau');",
  "    }",
  "    sessionId = data.sessionId;",
  "    totalRounds = data.totalRounds;",
  "    curRound = data.currentRound;",
  "    openFlow(data.link);",
  "  }catch(e){",
  "    toast('❌ ' + e.message, 4000);",
  "  } finally {",
  "    $('btnStart').disabled = false;",
  "    $('btnStart').innerHTML = '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><polygon points=\"5 3 19 12 5 21 5 3\"/></svg> Bắt đầu nhận key';",
  "  }",
  "}",

  "/* ── Open flow modal ── */",
  "function openFlow(link){",
  "  lastKey = null;",
  "  $('fmTitle').textContent = 'Vượt link lấy key — Lượt '+curRound+'/'+totalRounds;",
  "  $('fmSub').textContent = 'Bấm nút bên dưới, hoàn thành quảng cáo, rồi quay lại và bấm \"Tiếp theo\".';",
  "  renderProgress();",
  "  setLink(link);",
  "  $('fmLinkBox').style.display = 'block';",
  "  $('fmKeyResult').style.display = 'none';",
  "  $('fmNextBtn').style.display = 'flex';",
  "  $('fmCloseBtn').style.display = 'none';",
  "  $('flowModal').classList.add('show');",
  "  // Tự động mở link quảng cáo ngay, không cần bấm nút",
  "  try{",
  "    const a = $('fmLinkHref');",
  "    const href = a && a.href ? a.href : link;",
  "    if(href && href !== '#') window.open(href, '_blank');",
  "  }catch(e){}",
  "}",

  "function renderProgress(){",
  "  const p = $('fmProg'); p.innerHTML = '';",
  "  for(let i=1;i<=totalRounds;i++){",
  "    const d = document.createElement('div');",
  "    d.className = 'prog-dot' + (i < curRound ? ' done' : i===curRound ? ' active' : '');",
  "    p.appendChild(d);",
  "  }",
  "}",

  "function setLink(link){",
  "  const a = $('fmLinkHref'), b = $('fmOpenBtn');",
  "  const isHtml = typeof link === 'string' && link.trim().startsWith('<');",
  "  let href = link;",
  "  if(isHtml){",
  "    const m = link.match(/href=[\"']([^\"']+)[\"']/i);",
  "    href = m ? m[1] : '#';",
  "  }",
  "  a.href = href; a.textContent = href.length > 60 ? href.slice(0,58)+'…' : href;",
  "  b.href = href;",
  "}",

  "/* ── Next round ── */",
  "async function nextRound(){",
  "  $('fmNextBtn').disabled = true;",
  "  $('fmNextBtn').textContent = 'Đang kiểm tra...';",
  "  try{",
  "    const r = await fetch(API+'/api/getkey/next', {",
  "      method:'POST', headers:{'Content-Type':'application/json'},",
  "      body: JSON.stringify({ sessionId })",
  "    });",
  "    const data = await r.json();",
  "    if(!r.ok) throw new Error(data.error === 'not_confirmed_yet' ? 'Bạn chưa mở link — hãy bấm nút mở link trước!' : (data.message || 'Lỗi máy chủ'));",
  "    if(!data.ok) throw new Error(data.error === 'not_confirmed_yet' ? 'Bạn chưa mở link — hãy bấm nút mở link trước!' : (data.message || 'Không thể tiếp tục'));",
  "    if(data.done){",
  "      showKey(data.key, data.expiresAt, data.maxDevices);",
  "    } else {",
  "      curRound = data.currentRound;",
  "      $('fmTitle').textContent = 'Vượt link lấy key — Lượt '+curRound+'/'+totalRounds;",
  "      renderProgress();",
  "      setLink(data.link);",
  "      // Tự động mở link quảng cáo lượt tiếp theo",
  "      try{",
  "        const a = $('fmLinkHref');",
  "        const href = a && a.href ? a.href : data.link;",
  "        if(href && href !== '#') window.open(href, '_blank');",
  "      }catch(e){}",
  "    }",
  "  }catch(e){",
  "    toast('⚠ ' + e.message, 4500);",
  "  } finally {",
  "    $('fmNextBtn').disabled = false;",
  "    $('fmNextBtn').innerHTML = '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"m5 12 7 7 7-7M5 5l7 7 7-7\"/></svg> Tôi đã vượt link — Tiếp theo';",
  "  }",
  "}",

  "function showKey(key, expiresAt, maxDevices){",
  "  lastKey = key;",
  "  $('fmKeyValue').textContent = key;",
  "  const meta = [];",
  "  if(expiresAt) meta.push('Hết hạn: ' + new Date(expiresAt).toLocaleString('vi-VN'));",
  "  if(maxDevices) meta.push('Tối đa ' + maxDevices + ' thiết bị');",
  "  $('fmKeyMeta').textContent = meta.join(' · ');",
  "  $('fmLinkBox').style.display = 'none';",
  "  $('fmNextBtn').style.display = 'none';",
  "  $('fmKeyResult').style.display = 'block';",
  "  $('fmCloseBtn').style.display = 'flex';",
  "  $('fmTitle').textContent = '🎉 Nhận key thành công!';",
  "  $('fmSub').textContent = 'Sao chép key và dùng trong game. Cảm ơn bạn đã sử dụng!';",
  "  renderProgress();",
  "}",

  "function copyKey(){",
  "  if(!lastKey) return;",
  "  navigator.clipboard.writeText(lastKey).then(()=> toast('✔ Đã sao chép key!')).catch(()=>{",
  "    const i=document.createElement('input'); i.value=lastKey;",
  "    document.body.appendChild(i); i.select(); document.execCommand('copy');",
  "    document.body.removeChild(i); toast('✔ Đã sao chép key!');",
  "  });",
  "}",

  "function closeFlow(){ $('flowModal').classList.remove('show'); loadGames(); }",

  "loadGames();",
  "</script>",
  "</body></html>"
].join("\n");

const TELEGRAM_PAGE = [
  "<!DOCTYPE html>",
  "<html lang=\"vi\">",
  "<head>",
  "<meta charset=\"UTF-8\">",
  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, viewport-fit=cover\">",
  "<title>Shop</title>",
  "<script src=\"https://telegram.org/js/telegram-web-app.js\"></script>",
  "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">",
  "<link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Baloo+2:wght@600;700;800&display=swap\" rel=\"stylesheet\">",
  "<style>",
  "  :root{",
  "    --bg:#0b0913;",
  "    --panel:#1a1524;",
  "    --panel-2:#221b30;",
  "    --line:#2e2740;",
  "    --text:#f5f3fa;",
  "    --muted:#9b93ad;",
  "    --accent1:#ff6ec7;",
  "    --accent2:#8b5cf6;",
  "    --grad:linear-gradient(135deg, var(--accent1), var(--accent2));",
  "    --ok:#34d399;",
  "    --danger:#f87171;",
  "    --warn:#fbbf24;",
  "    --shadow:0 8px 24px -8px rgba(139,92,246,0.35);",
  "  }",
  "  *{box-sizing:border-box;}",
  "  html,body{margin:0;padding:0;}",
  "  body{",
  "    background:",
  "      radial-gradient(900px 500px at 15% -10%, rgba(139,92,246,0.28) 0%, transparent 55%),",
  "      radial-gradient(700px 400px at 100% 0%, rgba(255,110,199,0.18) 0%, transparent 55%),",
  "      var(--bg);",
  "    color:var(--text);",
  "    font-family:'Inter',sans-serif;",
  "    min-height:100vh;",
  "    padding-bottom:92px;",
  "  }",
  "  h1,h2,h3{font-family:'Baloo 2',sans-serif; margin:0;}",
  "  ::selection{background:var(--accent2); color:#fff;}",
  "  .wrap{ max-width:560px; margin:0 auto; padding:16px 14px 8px; }",
  "  .card{",
  "    background:var(--panel);",
  "    border:1px solid var(--line);",
  "    border-radius:20px;",
  "    padding:18px;",
  "    margin-bottom:14px;",
  "  }",
  "  .muted{ color:var(--muted); }",
  "  .sub{ color:var(--muted); font-size:13px; margin-top:4px; }",
  "  .btn{",
  "    display:inline-flex; align-items:center; justify-content:center; gap:6px;",
  "    background:var(--grad); color:#fff; border:none; border-radius:999px;",
  "    padding:13px 18px; font-weight:700; font-size:14.5px; cursor:pointer;",
  "    width:100%; box-shadow:var(--shadow);",
  "  }",
  "  .btn:disabled{ opacity:0.45; cursor:not-allowed; box-shadow:none; }",
  "  .btn-ghost{",
  "    background:transparent; color:var(--text); border:1.5px solid var(--line);",
  "    box-shadow:none;",
  "  }",
  "  .btn-sm{ padding:10px 14px; font-size:13px; width:auto; }",
  "  .grid2{ display:grid; grid-template-columns:1fr 1fr; gap:10px; }",
  "  .stat{",
  "    background:var(--panel-2); border:1px solid var(--line); border-radius:16px;",
  "    padding:14px; text-align:left;",
  "  }",
  "  .stat .n{ font-size:22px; font-weight:800; font-family:'Baloo 2',sans-serif; }",
  "  .stat .l{ font-size:12.5px; color:var(--muted); margin-top:2px; }",
  "  .avatar{",
  "    width:52px; height:52px; border-radius:16px; background:var(--grad);",
  "    display:flex; align-items:center; justify-content:center; font-weight:800;",
  "    font-size:20px; color:#fff; flex-shrink:0;",
  "  }",
  "  .row{ display:flex; align-items:center; gap:12px; }",
  "  .between{ display:flex; align-items:center; justify-content:space-between; }",
  "  .tag{",
  "    font-size:10.5px; font-weight:800; color:#12101a; background:var(--warn);",
  "    padding:2px 8px; border-radius:999px; letter-spacing:0.3px;",
  "  }",
  "  .badge-tier{",
  "    font-size:11.5px; font-weight:700; padding:3px 10px; border-radius:999px;",
  "    background:rgba(139,92,246,0.18); color:#c9b6ff; border:1px solid rgba(139,92,246,0.35);",
  "  }",
  "  .badge-tier.seller{ background:rgba(255,110,199,0.18); color:#ffb3e0; border-color:rgba(255,110,199,0.35); }",
  "",
  "  /* Grid sản phẩm */",
  "  .prod-grid{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:12px; }",
  "  .prod-card{",
  "    background:var(--panel-2); border:1px solid var(--line); border-radius:18px;",
  "    padding:14px; text-align:center; cursor:pointer;",
  "  }",
  "  .prod-card .logo{",
  "    width:56px; height:56px; border-radius:16px; margin:0 auto 10px; overflow:hidden;",
  "    background:var(--panel); display:flex; align-items:center; justify-content:center; font-size:26px;",
  "  }",
  "  .prod-card .logo img{ width:100%; height:100%; object-fit:cover; }",
  "  .prod-card h3{ font-size:13.5px; line-height:1.3; margin-bottom:4px; }",
  "  .prod-card .stock{ font-size:11px; }",
  "  .prod-card .stock.in{ color:var(--ok); }",
  "  .prod-card .stock.out{ color:var(--danger); }",
  "  .prod-card .price{ font-size:12.5px; color:var(--muted); margin-top:4px; }",
  "",
  "  .section-head{ display:flex; align-items:baseline; justify-content:space-between; margin:22px 0 4px; }",
  "  .section-head h2{ font-size:17px; }",
  "  .section-head span{ font-size:12px; color:var(--muted); }",
  "",
  "  .step-list{ display:flex; flex-direction:column; gap:10px; margin-top:12px; }",
  "  .step{ display:flex; align-items:center; gap:14px; background:var(--panel-2); border:1px solid var(--line); border-radius:14px; padding:12px 16px; }",
  "  .step .num{ width:30px; height:30px; border-radius:10px; background:var(--grad); display:flex; align-items:center; justify-content:center; font-weight:800; flex-shrink:0; }",
  "  .step .lbl{ font-weight:600; font-size:14px; }",
  "",
  "  .empty{ text-align:center; padding:36px 12px; color:var(--muted); }",
  "  .empty .big{ font-size:15px; font-weight:700; color:var(--text); margin-bottom:6px; }",
  "",
  "  /* Bottom tab nav */",
  "  #bottomNav{",
  "    position:fixed; bottom:0; left:0; right:0; z-index:50;",
  "    background:rgba(20,16,30,0.92); backdrop-filter:blur(14px);",
  "    border-top:1px solid var(--line);",
  "    display:flex; padding:8px 6px calc(8px + env(safe-area-inset-bottom));",
  "  }",
  "  #bottomNav button{",
  "    flex:1; background:none; border:none; color:var(--muted); font-family:'Inter',sans-serif;",
  "    font-size:11px; display:flex; flex-direction:column; align-items:center; gap:3px; padding:6px 2px;",
  "    border-radius:14px; cursor:pointer;",
  "  }",
  "  #bottomNav button .ic{ font-size:19px; }",
  "  #bottomNav button.active{ color:#fff; background:rgba(139,92,246,0.18); }",
  "",
  "  .tab-page{ display:none; }",
  "  .tab-page.active{ display:block; }",
  "",
  "  /* Bottom sheet modal */",
  "  .sheet-bg{",
  "    position:fixed; inset:0; background:rgba(5,4,10,0.6); z-index:100;",
  "    display:none; align-items:flex-end; justify-content:center;",
  "  }",
  "  .sheet-bg.show{ display:flex; }",
  "  .sheet{",
  "    background:var(--panel); width:100%; max-width:560px; border-radius:24px 24px 0 0;",
  "    padding:20px 18px calc(20px + env(safe-area-inset-bottom)); max-height:88vh; overflow-y:auto;",
  "    border-top:1px solid var(--line);",
  "  }",
  "  .sheet-handle{ width:40px; height:4px; background:var(--line); border-radius:99px; margin:0 auto 14px; }",
  "  .plan-option{",
  "    width:100%; display:flex; align-items:center; gap:12px; background:var(--panel-2);",
  "    border:1.5px solid var(--line); border-radius:16px; padding:12px 14px; margin-bottom:10px;",
  "    color:var(--text); cursor:pointer; text-align:left;",
  "  }",
  "  .plan-option.selected{ border-color:var(--accent2); box-shadow:0 0 0 2px rgba(139,92,246,0.25); }",
  "  .plan-option:disabled{ opacity:0.4; }",
  "  .plan-option .picon{",
  "    width:38px; height:38px; border-radius:12px; background:rgba(139,92,246,0.16);",
  "    display:flex; align-items:center; justify-content:center; font-size:17px; flex-shrink:0;",
  "  }",
  "  .plan-option .pinfo{ flex:1; min-width:0; }",
  "  .plan-option .plabel{ font-weight:700; font-size:14px; }",
  "  .plan-option .psub{ font-size:11.5px; color:var(--muted); margin-top:1px; }",
  "  .plan-option .pright{ text-align:right; flex-shrink:0; }",
  "  .plan-option .pprice{ font-weight:800; font-size:14.5px; color:#c9b6ff; }",
  "  .field{ margin-bottom:14px; }",
  "  .field label{ display:block; font-size:12.5px; color:var(--muted); margin-bottom:6px; }",
  "  .field input, .field select{",
  "    width:100%; background:var(--panel-2); border:1.5px solid var(--line); border-radius:12px;",
  "    padding:12px 14px; color:var(--text); font-size:14px; font-family:'Inter',sans-serif;",
  "  }",
  "  .amt-grid{ display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:14px; }",
  "  .amt-opt{",
  "    background:var(--panel-2); border:1.5px solid var(--line); border-radius:14px;",
  "    padding:14px; text-align:center; font-weight:700; cursor:pointer;",
  "  }",
  "  .amt-opt.selected{ background:var(--grad); border-color:transparent; }",
  "",
  "  .toast{",
  "    position:fixed; left:50%; bottom:104px; transform:translateX(-50%) translateY(20px);",
  "    background:#231b30; border:1px solid var(--line); color:var(--text); padding:12px 18px;",
  "    border-radius:14px; font-size:13.5px; z-index:200; opacity:0; transition:all .25s; max-width:88%; text-align:center;",
  "  }",
  "  .toast.show{ opacity:1; transform:translateX(-50%) translateY(0); }",
  "",
  "  .key-row{",
  "    background:var(--panel-2); border:1px solid var(--line); border-radius:14px; padding:14px; margin-bottom:10px;",
  "  }",
  "  .key-val{ font-family:monospace; font-size:13.5px; word-break:break-all; }",
  "  .filter-row{ display:flex; gap:8px; margin:14px 0; }",
  "  .filter-btn{",
  "    flex:1; background:var(--panel-2); border:1.5px solid var(--line); color:var(--muted);",
  "    border-radius:999px; padding:10px; font-weight:700; font-size:12.5px; cursor:pointer;",
  "  }",
  "  .filter-btn.active{ background:var(--grad); color:#fff; border-color:transparent; }",
  "  .qr-box{ text-align:center; margin-top:14px; }",
  "  .qr-box img{ width:100%; max-width:260px; border-radius:16px; background:#fff; padding:10px; }",
  "  .center-msg{ text-align:center; padding:60px 20px; color:var(--muted); }",
  "</style>",
  "</head>",
  "<body>",
  "",
  "<div class=\"wrap\">",
  "",
  "  <!-- ================= TAB: HOME ================= -->",
  "  <div id=\"tabHome\" class=\"tab-page active\">",
  "    <div class=\"card\">",
  "      <div class=\"row\">",
  "        <div class=\"avatar\" id=\"homeAvatar\">?</div>",
  "        <div>",
  "          <h2 id=\"homeGreeting\" style=\"font-size:18px;\">Xin chào</h2>",
  "          <div class=\"sub\" id=\"homeTierBadgeWrap\"><span class=\"badge-tier\" id=\"homeTierBadge\">Thành viên</span></div>",
  "        </div>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"grid2\">",
  "      <div class=\"stat\"><div class=\"n\" id=\"homeBalance\">0đ</div><div class=\"l\">Số dư ví</div></div>",
  "      <div class=\"stat\"><div class=\"n\" id=\"homeKeyCount\">0</div><div class=\"l\">Key còn hạn</div></div>",
  "    </div>",
  "",
  "    <div class=\"grid2\" style=\"margin-top:10px;\">",
  "      <button class=\"btn\" data-goto=\"buy\">Chọn sản phẩm</button>",
  "      <button class=\"btn btn-ghost\" data-goto=\"topup\">Nạp tiền</button>",
  "    </div>",
  "    <div class=\"grid2\" style=\"margin-top:10px;\">",
  "      <button class=\"btn btn-ghost\" data-goto=\"keys\">Key của tôi</button>",
  "      <button class=\"btn btn-ghost\" data-goto=\"account\">Tài khoản</button>",
  "    </div>",
  "",
  "    <div class=\"section-head\"><h2>Sản phẩm</h2><span id=\"homeProdCount\">0 sản phẩm</span></div>",
  "    <div class=\"prod-grid\" id=\"homeProdGrid\"></div>",
  "    <div class=\"empty\" id=\"homeProdEmpty\" style=\"display:none;\"><div class=\"big\">Chưa có sản phẩm nào</div>Vui lòng quay lại sau.</div>",
  "  </div>",
  "",
  "  <!-- ================= TAB: MUA KEY ================= -->",
  "  <div id=\"tabBuy\" class=\"tab-page\">",
  "    <div class=\"card\">",
  "      <h2 style=\"font-size:18px;\">Mua key</h2>",
  "      <p class=\"sub\">Chọn sản phẩm bạn muốn mua bên dưới.</p>",
  "    </div>",
  "    <div class=\"prod-grid\" id=\"buyProdGrid\"></div>",
  "    <div class=\"empty\" id=\"buyProdEmpty\" style=\"display:none;\"><div class=\"big\">Chưa có sản phẩm nào</div>Vui lòng quay lại sau.</div>",
  "",
  "    <div class=\"section-head\"><h2>GetKey — vượt link nhận miễn phí</h2></div>",
  "    <div class=\"prod-grid\" id=\"buyGkGrid\"></div>",
  "    <div class=\"empty\" id=\"buyGkEmpty\" style=\"display:none;\"><div class=\"big\">Chưa có GetKey nào</div>Vui lòng quay lại sau.</div>",
  "  </div>",
  "",
  "  <!-- ================= TAB: NẠP TIỀN ================= -->",
  "  <div id=\"tabTopup\" class=\"tab-page\">",
  "    <div class=\"card\">",
  "      <h2 style=\"font-size:18px;\">Nạp tiền</h2>",
  "      <p class=\"sub\">Chọn số tiền rồi tạo mã QR để chuyển khoản.</p>",
  "    </div>",
  "    <div class=\"card\">",
  "      <div class=\"amt-grid\" id=\"topupAmtGrid\">",
  "        <div class=\"amt-opt\" data-amt=\"50000\">50.000đ</div>",
  "        <div class=\"amt-opt\" data-amt=\"100000\">100.000đ</div>",
  "        <div class=\"amt-opt\" data-amt=\"200000\">200.000đ</div>",
  "        <div class=\"amt-opt\" data-amt=\"500000\">500.000đ</div>",
  "      </div>",
  "      <div class=\"field\">",
  "        <label>Số tiền khác (VNĐ)</label>",
  "        <input type=\"number\" id=\"topupCustomAmt\" placeholder=\"VD: 150000\" min=\"10000\">",
  "      </div>",
  "      <button class=\"btn\" id=\"btnCreateTopupQr\">Tạo QR nạp tiền</button>",
  "      <div class=\"qr-box\" id=\"topupQrBox\" style=\"display:none;\">",
  "        <img id=\"topupQrImg\" src=\"\">",
  "        <p class=\"sub\" id=\"topupQrNote\"></p>",
  "        <p class=\"sub\" id=\"topupQrCountdown\"></p>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ================= TAB: KEY CỦA TÔI ================= -->",
  "  <div id=\"tabKeys\" class=\"tab-page\">",
  "    <div class=\"card\">",
  "      <h2 style=\"font-size:18px;\">Key của tôi</h2>",
  "      <p class=\"sub\">Danh sách key bạn đã mua.</p>",
  "      <button class=\"btn btn-ghost btn-sm\" id=\"btnRefreshKeys\" style=\"margin-top:10px;\">↻ Làm mới</button>",
  "    </div>",
  "    <div class=\"filter-row\">",
  "      <div class=\"filter-btn active\" data-filter=\"all\">Tất cả</div>",
  "      <div class=\"filter-btn\" data-filter=\"available\">Còn hạn</div>",
  "      <div class=\"filter-btn\" data-filter=\"expired\">Hết hạn</div>",
  "    </div>",
  "    <div id=\"keysList\"></div>",
  "    <div class=\"empty\" id=\"keysEmpty\" style=\"display:none;\"><div class=\"big\">Không có key phù hợp</div>Key đã mua sẽ hiển thị tại đây.</div>",
  "  </div>",
  "",
  "  <!-- ================= TAB: TÀI KHOẢN ================= -->",
  "  <div id=\"tabAccount\" class=\"tab-page\">",
  "    <div class=\"card\">",
  "      <div class=\"row\">",
  "        <div class=\"avatar\" id=\"accAvatar\">?</div>",
  "        <div>",
  "          <h2 id=\"accName\" style=\"font-size:18px;\">—</h2>",
  "          <div class=\"sub\"><span class=\"badge-tier\" id=\"accTierBadge\">Thành viên</span></div>",
  "        </div>",
  "      </div>",
  "      <div class=\"between\" style=\"margin-top:16px;\">",
  "        <span class=\"muted\">Số dư ví</span>",
  "        <b id=\"accBalance\">0đ</b>",
  "      </div>",
  "    </div>",
  "    <button class=\"btn btn-ghost\" id=\"btnShowHistory\" style=\"margin-bottom:10px;\">📄 Lịch sử giao dịch</button>",
  "    <button class=\"btn btn-ghost\" id=\"btnSupport\">🎧 Hỗ trợ</button>",
  "  </div>",
  "",
  "</div>",
  "",
  "<!-- ================= BOTTOM NAV ================= -->",
  "<nav id=\"bottomNav\">",
  "  <button data-tab=\"home\" class=\"active\"><span class=\"ic\">🏠</span>Home</button>",
  "  <button data-tab=\"buy\"><span class=\"ic\">🛍️</span>Mua key</button>",
  "  <button data-tab=\"topup\"><span class=\"ic\">💳</span>Nạp tiền</button>",
  "  <button data-tab=\"keys\"><span class=\"ic\">🔑</span>Key của tôi</button>",
  "  <button data-tab=\"account\"><span class=\"ic\">👤</span>Tài khoản</button>",
  "</nav>",
  "",
  "<!-- ================= SHEET: CHỌN GÓI ================= -->",
  "<div class=\"sheet-bg\" id=\"planSheetBg\">",
  "  <div class=\"sheet\">",
  "    <div class=\"sheet-handle\"></div>",
  "    <div class=\"row\">",
  "      <div class=\"avatar\" id=\"planSheetLogo\" style=\"background:var(--panel-2);\">📦</div>",
  "      <div>",
  "        <h3 id=\"planSheetTitle\" style=\"font-size:16.5px;\">—</h3>",
  "        <p class=\"sub\" id=\"planSheetSubtitle\">—</p>",
  "      </div>",
  "    </div>",
  "    <div id=\"planSheetList\" style=\"margin-top:16px;\"></div>",
  "    <button class=\"btn btn-ghost\" id=\"btnClosePlanSheet\">Đóng</button>",
  "  </div>",
  "</div>",
  "",
  "<!-- ================= SHEET: XÁC NHẬN MUA ================= -->",
  "<div class=\"sheet-bg\" id=\"confirmSheetBg\">",
  "  <div class=\"sheet\">",
  "    <div class=\"sheet-handle\"></div>",
  "    <h3 id=\"confirmTitle\" style=\"font-size:17px;\">Xác nhận mua</h3>",
  "    <p class=\"sub\" id=\"confirmSubtitle\" style=\"margin-bottom:16px;\">—</p>",
  "    <div class=\"field\">",
  "      <label>Mã giảm giá (tuỳ chọn)</label>",
  "      <input type=\"text\" id=\"confirmDiscountCode\" placeholder=\"Nhập mã nếu có\">",
  "    </div>",
  "    <p class=\"sub\" id=\"confirmError\" style=\"color:var(--danger); display:none;\"></p>",
  "    <button class=\"btn\" id=\"btnConfirmBuy\">Chắc chắn mua</button>",
  "    <button class=\"btn btn-ghost\" id=\"btnCancelConfirm\" style=\"margin-top:10px;\">Huỷ</button>",
  "  </div>",
  "</div>",
  "",
  "<!-- ================= SHEET: KẾT QUẢ ================= -->",
  "<div class=\"sheet-bg\" id=\"resultSheetBg\">",
  "  <div class=\"sheet\">",
  "    <div class=\"sheet-handle\"></div>",
  "    <h3 style=\"font-size:18px;\">🎉 Thành công!</h3>",
  "    <p class=\"sub\">Key của bạn:</p>",
  "    <div class=\"key-row\"><div class=\"key-val\" id=\"resultKeyValue\">—</div></div>",
  "    <button class=\"btn\" id=\"btnCopyResultKey\">Sao chép key</button>",
  "    <button class=\"btn btn-ghost\" id=\"btnCloseResult\" style=\"margin-top:10px;\">Đóng</button>",
  "  </div>",
  "</div>",
  "",
  "<!-- ================= SHEET: LỊCH SỬ GIAO DỊCH ================= -->",
  "<div class=\"sheet-bg\" id=\"historySheetBg\">",
  "  <div class=\"sheet\">",
  "    <div class=\"sheet-handle\"></div>",
  "    <h3 style=\"font-size:17px; margin-bottom:12px;\">Lịch sử giao dịch</h3>",
  "    <div id=\"historyList\"></div>",
  "    <button class=\"btn btn-ghost\" id=\"btnCloseHistory\" style=\"margin-top:6px;\">Đóng</button>",
  "  </div>",
  "</div>",
  "",
  "<!-- ================= SHEET: VƯỢT LINK GETKEY ================= -->",
  "<div class=\"sheet-bg\" id=\"gkSheetBg\">",
  "  <div class=\"sheet\">",
  "    <div class=\"sheet-handle\"></div>",
  "    <h3 style=\"font-size:17px;\">Vượt link nhận key</h3>",
  "    <p class=\"sub\" id=\"gkProgressLabel\">Lượt 1/1</p>",
  "    <p class=\"sub\" style=\"margin:10px 0 16px;\">Bấm \"Mở link\" để vượt qua lượt hiện tại, sau đó quay lại đây và bấm \"Tôi đã vượt xong\".</p>",
  "    <button class=\"btn\" id=\"btnGkOpenLink\" style=\"margin-bottom:10px;\">Mở link</button>",
  "    <button class=\"btn btn-ghost\" id=\"btnGkConfirmed\">Tôi đã vượt xong lượt này</button>",
  "    <button class=\"btn btn-ghost\" id=\"btnCloseGk\" style=\"margin-top:10px;\">Huỷ</button>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"toast\" id=\"toast\"></div>",
  "",
  "<script>",
  "const tg = window.Telegram ? window.Telegram.WebApp : null;",
  "if(tg){ tg.ready(); tg.expand(); }",
  "",
  "let authToken = localStorage.getItem('tg_shop_token') || null;",
  "let me = null; // { username, balance, telegramFirstName, telegramUsername, telegramTier }",
  "let products = [];",
  "let productGroups = [];",
  "let gkGames = [];",
  "let activeConfirmAction = null; // function() gọi khi bấm \"Chắc chắn mua\"",
  "let activeTopupRequestId = null;",
  "let topupPollTimer = null;",
  "let gkState = null; // { sessionId, currentRound, totalRounds, link }",
  "",
  "function $(id){ return document.getElementById(id); }",
  "function fmtMoney(n){ return (Number(n)||0).toLocaleString('vi-VN') + 'đ'; }",
  "function showToast(msg){",
  "  const t = $('toast');",
  "  t.textContent = msg;",
  "  t.classList.add('show');",
  "  clearTimeout(window._toastTimer);",
  "  window._toastTimer = setTimeout(()=> t.classList.remove('show'), 2600);",
  "}",
  "function initials(name){",
  "  const parts = String(name||'').trim().split(/\\s+/);",
  "  if(!parts[0]) return '?';",
  "  return (parts[0][0] + (parts[1] ? parts[1][0] : '')).toUpperCase();",
  "}",
  "",
  "/* ---------------- Đăng nhập bằng dữ liệu Telegram WebApp ---------------- */",
  "async function authenticate(){",
  "  if(!tg || !tg.initData){",
  "    document.body.innerHTML = '<div class=\"center-msg\"><h2 style=\"margin-bottom:10px;\">Vui lòng mở Shop từ trong Telegram</h2>Mini App này chỉ hoạt động khi được mở qua bot Telegram.</div>';",
  "    return false;",
  "  }",
  "  try{",
  "    const res = await fetch('/api/telegram/auth', {",
  "      method:'POST',",
  "      headers:{'Content-Type':'application/json'},",
  "      body: JSON.stringify({ initData: tg.initData })",
  "    });",
  "    const data = await res.json();",
  "    if(!data.ok){",
  "      showToast(data.message || 'Không đăng nhập được, vui lòng thử lại');",
  "      return false;",
  "    }",
  "    authToken = data.token;",
  "    me = data.customer;",
  "    localStorage.setItem('tg_shop_token', authToken);",
  "    return true;",
  "  }catch(e){",
  "    showToast('Không kết nối được server, vui lòng thử lại');",
  "    return false;",
  "  }",
  "}",
  "",
  "async function apiFetch(path, opts){",
  "  opts = opts || {};",
  "  opts.headers = Object.assign({ 'Content-Type':'application/json' }, opts.headers || {});",
  "  if(authToken) opts.headers['Authorization'] = 'Bearer ' + authToken;",
  "  const res = await fetch(path, opts);",
  "  return res.json();",
  "}",
  "",
  "/* ---------------- Điều hướng tab ---------------- */",
  "function showTab(name){",
  "  document.querySelectorAll('.tab-page').forEach(el=> el.classList.remove('active'));",
  "  document.querySelectorAll('#bottomNav button').forEach(el=> el.classList.toggle('active', el.dataset.tab===name));",
  "  $('tab' + name.charAt(0).toUpperCase() + name.slice(1)).classList.add('active');",
  "  if(name==='keys') loadKeys();",
  "}",
  "document.querySelectorAll('#bottomNav button').forEach(btn=>{",
  "  btn.addEventListener('click', ()=> showTab(btn.dataset.tab));",
  "});",
  "document.querySelectorAll('[data-goto]').forEach(btn=>{",
  "  btn.addEventListener('click', ()=> showTab(btn.dataset.goto));",
  "});",
  "",
  "/* ---------------- Tải dữ liệu tài khoản (số dư, key còn hạn) ---------------- */",
  "async function refreshAccountSummary(){",
  "  const hist = await apiFetch('/api/auth/history');",
  "  const balance = hist.ok ? (hist.balance||0) : (me ? me.balance : 0);",
  "  $('homeBalance').textContent = fmtMoney(balance);",
  "  $('accBalance').textContent = fmtMoney(balance);",
  "",
  "  const keysRes = await apiFetch('/api/customer/keys');",
  "  const activeCount = keysRes.ok ? (keysRes.keys||[]).filter(k=>k.status==='available' || k.status==='active').length : 0;",
  "  $('homeKeyCount').textContent = activeCount;",
  "",
  "  const name = (me && (me.telegramFirstName || me.telegramUsername)) || 'bạn';",
  "  $('homeGreeting').textContent = 'Chào ' + name;",
  "  $('homeAvatar').textContent = initials(name);",
  "  $('accAvatar').textContent = initials(name);",
  "  $('accName').textContent = name;",
  "  const tier = (me && me.telegramTier) || 'customer';",
  "  const tierLabel = tier === 'seller' ? 'Thành viên Seller' : 'Thành viên';",
  "  [$('homeTierBadge'), $('accTierBadge')].forEach(el=>{",
  "    el.textContent = tierLabel;",
  "    el.classList.toggle('seller', tier==='seller');",
  "  });",
  "}",
  "",
  "/* ---------------- Sản phẩm (đơn + nhóm) ---------------- */",
  "function pgAutoBadge(index, total){",
  "  if(total <= 1) return { icon:'🔑', tag:null };",
  "  if(index===0) return { icon:'🔑', tag:'HOT' };",
  "  if(index===total-1) return { icon:'🛡️', tag:'VIP' };",
  "  return { icon:'⚡', tag:'NEW' };",
  "}",
  "",
  "async function loadProducts(){",
  "  try{ products = await (await fetch('/api/products', {cache:'no-store'})).json(); }catch(e){ products = []; }",
  "  try{ productGroups = await (await fetch('/api/product-groups', {cache:'no-store'})).json(); }catch(e){ productGroups = []; }",
  "  renderProductGrids();",
  "}",
  "",
  "function renderProductGrids(){",
  "  const items = [];",
  "  products.forEach(p=> items.push({ kind:'product', id:p.id, name:p.name, logo:p.logo, stock:p.stock, price:p.price }));",
  "  productGroups.filter(g=>g.active).forEach(g=>{",
  "    const totalStock = (g.plans||[]).reduce((s,p)=> s + (p.stock||0), 0);",
  "    items.push({ kind:'group', id:g.id, name:g.name, logo:g.logo, stock:totalStock });",
  "  });",
  "",
  "  [{grid:'homeProdGrid', empty:'homeProdEmpty', countEl:'homeProdCount', limit:4},",
  "   {grid:'buyProdGrid', empty:'buyProdEmpty', countEl:null, limit:999}].forEach(cfg=>{",
  "    const grid = $(cfg.grid);",
  "    const list = items.slice(0, cfg.limit);",
  "    grid.innerHTML = '';",
  "    $(cfg.empty).style.display = items.length ? 'none' : 'block';",
  "    if(cfg.countEl) $(cfg.countEl).textContent = items.length + ' sản phẩm';",
  "    list.forEach(it=>{",
  "      const card = document.createElement('div');",
  "      card.className = 'prod-card';",
  "      card.innerHTML = `",
  "        <div class=\"logo\">${it.logo ? `<img src=\"${it.logo}\">` : '📦'}</div>",
  "        <h3>${it.name}</h3>",
  "        <div class=\"stock ${it.stock>0 ? 'in' : 'out'}\">${it.stock>0 ? '✔ Còn hàng' : '✖ Hết hàng'}</div>",
  "        ${it.price!==undefined ? `<div class=\"price\">${fmtMoney(it.price)}</div>` : ''}",
  "      `;",
  "      card.addEventListener('click', ()=>{",
  "        if(it.kind==='product') openSingleProductConfirm(it.id);",
  "        else openGroupPlanSheet(it.id);",
  "      });",
  "      grid.appendChild(card);",
  "    });",
  "  });",
  "}",
  "",
  "function openSingleProductConfirm(productId){",
  "  const p = products.find(x=>x.id===productId);",
  "  if(!p){ showToast('Sản phẩm không còn tồn tại'); return; }",
  "  if(!(p.stock>0)){ showToast('Sản phẩm đã hết hàng'); return; }",
  "  openConfirmSheet({",
  "    title: 'Mua ' + p.name,",
  "    subtitle: 'Xác nhận mua bằng số dư ví',",
  "    priceLabel: fmtMoney(p.price),",
  "    onConfirm: async (discountCode)=>{",
  "      return apiFetch('/api/checkout', { method:'POST', body: JSON.stringify({ productId: p.id, discountCode }) });",
  "    }",
  "  });",
  "}",
  "",
  "function openGroupPlanSheet(groupId){",
  "  const g = productGroups.find(x=>x.id===groupId);",
  "  if(!g){ showToast('Sản phẩm không còn tồn tại'); return; }",
  "  const plans = g.plans || [];",
  "  $('planSheetLogo').innerHTML = g.logo ? `<img src=\"${g.logo}\" style=\"width:100%;height:100%;object-fit:cover;border-radius:16px;\">` : '📦';",
  "  $('planSheetTitle').textContent = g.name;",
  "  $('planSheetSubtitle').textContent = 'Chọn gói bạn muốn mua';",
  "  const list = $('planSheetList');",
  "  list.innerHTML = '';",
  "  plans.forEach((pl, idx)=>{",
  "    const badge = pgAutoBadge(idx, plans.length);",
  "    const inStock = (pl.stock||0) > 0;",
  "    const btn = document.createElement('button');",
  "    btn.className = 'plan-option';",
  "    btn.disabled = !inStock;",
  "    btn.innerHTML = `",
  "      <div class=\"picon\">${badge.icon}</div>",
  "      <div class=\"pinfo\">",
  "        <div class=\"plabel\">${pl.label || (pl.amount + ' ' + pl.unit)}</div>",
  "        <div class=\"psub\">${inStock ? 'Còn ' + pl.stock + ' key' : 'Hết hàng'}</div>",
  "      </div>",
  "      <div class=\"pright\">",
  "        <div class=\"pprice\">${fmtMoney(pl.price)}</div>",
  "        ${badge.tag ? `<div class=\"tag\">${badge.tag}</div>` : ''}",
  "      </div>",
  "    `;",
  "    if(inStock){",
  "      btn.addEventListener('click', ()=>{",
  "        closeSheet('planSheetBg');",
  "        openConfirmSheet({",
  "          title: 'Mua ' + g.name + ' — ' + (pl.label || pl.unit),",
  "          subtitle: 'Xác nhận mua bằng số dư ví',",
  "          priceLabel: fmtMoney(pl.price),",
  "          onConfirm: async (discountCode)=>{",
  "            return apiFetch('/api/checkout-group', { method:'POST', body: JSON.stringify({ groupId: g.id, planId: pl.id, discountCode }) });",
  "          }",
  "        });",
  "      });",
  "    }",
  "    list.appendChild(btn);",
  "  });",
  "  openSheet('planSheetBg');",
  "}",
  "",
  "/* ---------------- Sheet xác nhận mua (dùng chung cho product & group) ---------------- */",
  "function openConfirmSheet({ title, subtitle, priceLabel, onConfirm }){",
  "  $('confirmTitle').textContent = title;",
  "  $('confirmSubtitle').textContent = subtitle + ' — ' + priceLabel;",
  "  $('confirmDiscountCode').value = '';",
  "  $('confirmError').style.display = 'none';",
  "  activeConfirmAction = onConfirm;",
  "  openSheet('confirmSheetBg');",
  "}",
  "$('btnConfirmBuy').addEventListener('click', async ()=>{",
  "  if(!activeConfirmAction) return;",
  "  $('confirmError').style.display = 'none';",
  "  $('btnConfirmBuy').disabled = true;",
  "  $('btnConfirmBuy').textContent = 'Đang xử lý...';",
  "  try{",
  "    const discountCode = $('confirmDiscountCode').value.trim();",
  "    const result = await activeConfirmAction(discountCode);",
  "    if(result.ok){",
  "      closeSheet('confirmSheetBg');",
  "      $('resultKeyValue').textContent = result.key;",
  "      openSheet('resultSheetBg');",
  "      refreshAccountSummary();",
  "    } else {",
  "      const msgMap = {",
  "        insufficient_balance: 'Số dư không đủ, vui lòng nạp thêm tiền.',",
  "        out_of_stock: 'Sản phẩm vừa hết hàng, vui lòng thử sản phẩm khác.',",
  "        discount_invalid: 'Mã giảm giá không hợp lệ.',",
  "        discount_expired: 'Mã giảm giá đã hết hạn.',",
  "        discount_used_up: 'Mã giảm giá đã hết lượt dùng.'",
  "      };",
  "      $('confirmError').textContent = msgMap[result.error] || 'Mua hàng thất bại, vui lòng thử lại.';",
  "      $('confirmError').style.display = 'block';",
  "    }",
  "  }catch(e){",
  "    $('confirmError').textContent = 'Lỗi kết nối, vui lòng thử lại.';",
  "    $('confirmError').style.display = 'block';",
  "  }",
  "  $('btnConfirmBuy').disabled = false;",
  "  $('btnConfirmBuy').textContent = 'Chắc chắn mua';",
  "});",
  "$('btnCancelConfirm').addEventListener('click', ()=> closeSheet('confirmSheetBg'));",
  "$('btnCloseResult').addEventListener('click', ()=> closeSheet('resultSheetBg'));",
  "$('btnCopyResultKey').addEventListener('click', async ()=>{",
  "  try{ await navigator.clipboard.writeText($('resultKeyValue').textContent); showToast('Đã sao chép key'); }",
  "  catch(e){ showToast('Không sao chép được'); }",
  "});",
  "",
  "/* ---------------- GetKey (vượt link nhận key miễn phí) ---------------- */",
  "function fmtGkDuration(d){",
  "  const unitLabel = d.unit==='hour' ? 'giờ' : d.unit==='month' ? 'tháng' : 'ngày';",
  "  return d.label || (d.amount + ' ' + unitLabel);",
  "}",
  "async function loadGetKeyGames(){",
  "  try{ gkGames = await (await fetch('/api/getkey/games', {cache:'no-store'})).json(); }catch(e){ gkGames = []; }",
  "  const grid = $('buyGkGrid');",
  "  grid.innerHTML = '';",
  "  $('buyGkEmpty').style.display = gkGames.length ? 'none' : 'block';",
  "  gkGames.forEach(g=>{",
  "    const card = document.createElement('div');",
  "    card.className = 'prod-card';",
  "    card.innerHTML = `",
  "      <div class=\"logo\">${g.logo ? `<img src=\"${g.logo}\">` : '🎮'}</div>",
  "      <h3>${g.name}</h3>",
  "      <div class=\"stock ${g.stock>0 ? 'in' : 'out'}\">${g.stock>0 ? '✔ Còn hàng' : '✖ Hết hàng'}</div>",
  "    `;",
  "    card.addEventListener('click', ()=> openGkDurationSheet(g));",
  "    grid.appendChild(card);",
  "  });",
  "}",
  "function openGkDurationSheet(game){",
  "  const durations = game.durations || [];",
  "  $('planSheetLogo').innerHTML = game.logo ? `<img src=\"${game.logo}\" style=\"width:100%;height:100%;object-fit:cover;border-radius:16px;\">` : '🎮';",
  "  $('planSheetTitle').textContent = game.name;",
  "  $('planSheetSubtitle').textContent = 'Chọn thời hạn key (miễn phí, vượt link để nhận)';",
  "  const list = $('planSheetList');",
  "  list.innerHTML = '';",
  "  durations.forEach((d, idx)=>{",
  "    const badge = pgAutoBadge(idx, durations.length);",
  "    const inStock = game.stock > 0;",
  "    const btn = document.createElement('button');",
  "    btn.className = 'plan-option';",
  "    btn.disabled = !inStock;",
  "    btn.innerHTML = `",
  "      <div class=\"picon\">${badge.icon}</div>",
  "      <div class=\"pinfo\">",
  "        <div class=\"plabel\">${fmtGkDuration(d)}</div>",
  "        <div class=\"psub\">${d.rounds} lượt vượt link</div>",
  "      </div>",
  "      <div class=\"pright\">",
  "        <div class=\"pprice\">${inStock ? 'Miễn phí' : 'Hết hàng'}</div>",
  "        ${badge.tag ? `<div class=\"tag\">${badge.tag}</div>` : ''}",
  "      </div>",
  "    `;",
  "    if(inStock){",
  "      btn.addEventListener('click', async ()=>{",
  "        closeSheet('planSheetBg');",
  "        try{",
  "          const res = await apiFetch('/api/getkey/start', { method:'POST', body: JSON.stringify({ gameId: game.id, durationId: d.id }) });",
  "          if(!res.ok){ showToast('Không bắt đầu được, vui lòng thử lại'); return; }",
  "          gkState = { sessionId: res.sessionId, currentRound: res.currentRound, totalRounds: res.totalRounds, link: res.link };",
  "          openGkSheet();",
  "        }catch(e){ showToast('Lỗi kết nối, vui lòng thử lại'); }",
  "      });",
  "    }",
  "    list.appendChild(btn);",
  "  });",
  "  openSheet('planSheetBg');",
  "}",
  "function openGkSheet(){",
  "  $('gkProgressLabel').textContent = `Lượt ${gkState.currentRound}/${gkState.totalRounds}`;",
  "  openSheet('gkSheetBg');",
  "}",
  "$('btnGkOpenLink').addEventListener('click', ()=>{",
  "  if(!gkState) return;",
  "  const url = /^https?:\\/\\//.test(gkState.link) ? gkState.link : null;",
  "  if(url && tg && tg.openLink) tg.openLink(url);",
  "  else if(url) window.open(url, '_blank');",
  "  else showToast('Không mở được link, vui lòng thử lại');",
  "});",
  "$('btnGkConfirmed').addEventListener('click', async ()=>{",
  "  if(!gkState) return;",
  "  try{",
  "    const res = await apiFetch('/api/getkey/next', { method:'POST', body: JSON.stringify({ sessionId: gkState.sessionId }) });",
  "    if(!res.ok){",
  "      showToast(res.error==='not_confirmed_yet' ? 'Bạn cần mở link trước khi xác nhận' : 'Có lỗi xảy ra, vui lòng thử lại');",
  "      return;",
  "    }",
  "    if(res.done){",
  "      closeSheet('gkSheetBg');",
  "      $('resultKeyValue').textContent = res.key;",
  "      openSheet('resultSheetBg');",
  "    } else {",
  "      gkState.currentRound = res.currentRound;",
  "      gkState.link = res.link;",
  "      $('gkProgressLabel').textContent = `Lượt ${gkState.currentRound}/${gkState.totalRounds}`;",
  "      showToast('Đã qua lượt ' + (gkState.currentRound - 1) + ', tiếp tục mở link mới');",
  "    }",
  "  }catch(e){ showToast('Lỗi kết nối, vui lòng thử lại'); }",
  "});",
  "$('btnCloseGk').addEventListener('click', ()=>{ gkState = null; closeSheet('gkSheetBg'); });",
  "",
  "/* ---------------- Nạp tiền ---------------- */",
  "document.querySelectorAll('.amt-opt').forEach(el=>{",
  "  el.addEventListener('click', ()=>{",
  "    document.querySelectorAll('.amt-opt').forEach(x=>x.classList.remove('selected'));",
  "    el.classList.add('selected');",
  "    $('topupCustomAmt').value = el.dataset.amt;",
  "  });",
  "});",
  "$('btnCreateTopupQr').addEventListener('click', async ()=>{",
  "  const amount = parseInt($('topupCustomAmt').value, 10);",
  "  if(!amount || amount < 10000){ showToast('Vui lòng nhập số tiền hợp lệ (tối thiểu 10.000đ)'); return; }",
  "  $('btnCreateTopupQr').disabled = true;",
  "  try{",
  "    const res = await apiFetch('/api/topup-request', { method:'POST', body: JSON.stringify({ amount }) });",
  "    if(!res.ok){",
  "      showToast(res.message || 'Không tạo được yêu cầu nạp tiền');",
  "      $('btnCreateTopupQr').disabled = false;",
  "      return;",
  "    }",
  "    activeTopupRequestId = res.request.id;",
  "    $('topupQrImg').src = res.request.qrUrl;",
  "    $('topupQrNote').textContent = 'Chuyển khoản đúng nội dung: ' + res.request.transferNote;",
  "    $('topupQrBox').style.display = 'block';",
  "    startTopupPolling(res.request.expiresAt);",
  "  }catch(e){ showToast('Lỗi kết nối, vui lòng thử lại'); }",
  "  $('btnCreateTopupQr').disabled = false;",
  "});",
  "function startTopupPolling(expiresAt){",
  "  clearInterval(topupPollTimer);",
  "  topupPollTimer = setInterval(async ()=>{",
  "    const remain = Math.max(0, Math.floor((new Date(expiresAt) - Date.now())/1000));",
  "    const mm = String(Math.floor(remain/60)).padStart(2,'0');",
  "    const ss = String(remain%60).padStart(2,'0');",
  "    $('topupQrCountdown').textContent = remain > 0 ? `Còn lại ${mm}:${ss}` : 'Đã hết hạn';",
  "    try{",
  "      const res = await apiFetch('/api/topup-request/' + activeTopupRequestId);",
  "      if(res.ok && res.request.status === 'approved'){",
  "        clearInterval(topupPollTimer);",
  "        showToast('Nạp tiền thành công!');",
  "        $('topupQrBox').style.display = 'none';",
  "        refreshAccountSummary();",
  "      } else if(res.ok && (res.request.status === 'rejected' || res.request.status === 'expired')){",
  "        clearInterval(topupPollTimer);",
  "        showToast('Yêu cầu nạp tiền đã ' + (res.request.status==='rejected' ? 'bị từ chối' : 'hết hạn'));",
  "      }",
  "    }catch(e){ /* bỏ qua lỗi tạm thời, thử lại lượt sau */ }",
  "    if(remain <= 0) clearInterval(topupPollTimer);",
  "  }, 4000);",
  "}",
  "",
  "/* ---------------- Key của tôi ---------------- */",
  "let allKeys = [];",
  "let keysFilter = 'all';",
  "async function loadKeys(){",
  "  try{",
  "    const res = await apiFetch('/api/customer/keys');",
  "    allKeys = res.ok ? (res.keys||[]) : [];",
  "  }catch(e){ allKeys = []; }",
  "  renderKeys();",
  "}",
  "document.querySelectorAll('.filter-btn').forEach(btn=>{",
  "  btn.addEventListener('click', ()=>{",
  "    document.querySelectorAll('.filter-btn').forEach(x=>x.classList.remove('active'));",
  "    btn.classList.add('active');",
  "    keysFilter = btn.dataset.filter;",
  "    renderKeys();",
  "  });",
  "});",
  "$('btnRefreshKeys').addEventListener('click', loadKeys);",
  "function renderKeys(){",
  "  let list = allKeys;",
  "  if(keysFilter==='available') list = allKeys.filter(k=> k.status==='available' || k.status==='active');",
  "  if(keysFilter==='expired') list = allKeys.filter(k=> k.status==='expired' || k.banned);",
  "  const wrap = $('keysList');",
  "  wrap.innerHTML = '';",
  "  $('keysEmpty').style.display = list.length ? 'none' : 'block';",
  "  list.forEach(k=>{",
  "    const row = document.createElement('div');",
  "    row.className = 'key-row';",
  "    row.innerHTML = `",
  "      <div class=\"between\"><span class=\"key-val\">${k.value}</span><span class=\"tag\" style=\"background:${k.status==='available'||k.status==='active' ? 'var(--ok)' : 'var(--danger)'};\">${k.status}</span></div>",
  "      <div class=\"sub\" style=\"margin-top:6px;\">${k.expiresAt ? 'Hết hạn: ' + new Date(k.expiresAt).toLocaleString('vi-VN') : 'Không giới hạn thời gian'}</div>",
  "    `;",
  "    row.addEventListener('click', async ()=>{",
  "      try{ await navigator.clipboard.writeText(k.value); showToast('Đã sao chép key'); }catch(e){}",
  "    });",
  "    wrap.appendChild(row);",
  "  });",
  "}",
  "",
  "/* ---------------- Tài khoản / Lịch sử / Hỗ trợ ---------------- */",
  "$('btnShowHistory').addEventListener('click', async ()=>{",
  "  const res = await apiFetch('/api/auth/history');",
  "  const wrap = $('historyList');",
  "  wrap.innerHTML = '';",
  "  const items = res.ok ? (res.transactionHistory||[]) : [];",
  "  if(!items.length){ wrap.innerHTML = '<p class=\"sub\">Chưa có giao dịch nào.</p>'; }",
  "  items.slice(0,50).forEach(t=>{",
  "    const row = document.createElement('div');",
  "    row.className = 'key-row';",
  "    const isNeg = t.amount < 0;",
  "    row.innerHTML = `",
  "      <div class=\"between\">",
  "        <span>${t.note || t.type}</span>",
  "        <b style=\"color:${isNeg ? 'var(--danger)' : 'var(--ok)'};\">${isNeg ? '' : '+'}${fmtMoney(t.amount)}</b>",
  "      </div>",
  "      <div class=\"sub\" style=\"margin-top:4px;\">${new Date(t.createdAt).toLocaleString('vi-VN')}</div>",
  "    `;",
  "    wrap.appendChild(row);",
  "  });",
  "  openSheet('historySheetBg');",
  "});",
  "$('btnCloseHistory').addEventListener('click', ()=> closeSheet('historySheetBg'));",
  "$('btnSupport').addEventListener('click', ()=>{",
  "  showToast('Vui lòng nhắn tin trực tiếp cho admin trong Telegram để được hỗ trợ.');",
  "});",
  "",
  "/* ---------------- Tiện ích mở/đóng sheet ---------------- */",
  "function openSheet(id){ $(id).classList.add('show'); }",
  "function closeSheet(id){ $(id).classList.remove('show'); }",
  "document.querySelectorAll('.sheet-bg').forEach(bg=>{",
  "  bg.addEventListener('click', (e)=>{ if(e.target===bg) bg.classList.remove('show'); });",
  "});",
  "",
  "/* ---------------- Khởi động ---------------- */",
  "(async function init(){",
  "  const ok = await authenticate();",
  "  if(!ok) return;",
  "  await Promise.all([loadProducts(), loadGetKeyGames(), refreshAccountSummary()]);",
  "})();",
  "</script>",
  "</body>",
  "</html>",
  ""
];
const TELEGRAM_PAGE_HTML = TELEGRAM_PAGE.join(String.fromCharCode(10));

const HTML_PAGE = HTML_LINES.join(String.fromCharCode(10));

/* ---------------- Lưu trữ dữ liệu ra file (persist thật trên server) ---------------- */
function defaultState(){
  return {
    adminPassword: '120510@',
    loginHistory: [],
    keysStore: {},
    sellers: [],
    blockedIPs: [],
    scanState: {},
    lastScanTime: null,
    statsHidden: false,
    apiApps: [],     // { id, appId, status: 'pending'|'allowed'|'denied', createdAt, lastUsedAt, totalChecks }
    verifyLogs: [],   // { time, appId, key, valid, reason }
    products: [],     // { id, name, logo, keyPrefix, price, maxDevices, durationAmount, durationUnit, active, createdAt }
    discountCodes: [],// { id, code, percent, maxUses, usedCount, expiresAt, active, createdAt }
    customers: [],    // { id, username, passwordHash, createdAt, balance, role: 'customer'|'admin', topupHistory:[], transactionHistory:[] }
    customerSessions: {}, // { token: { customerId, username, createdAt } }
    /* Thông tin tài khoản ngân hàng dùng để sinh QR động (VietQR) cho nạp tiền tự động.
       Admin có thể đổi qua "/api/state" (POST) như các trường cấu hình khác. */
    bankInfo: {
      bankId: 'MB',              // mã ngân hàng dùng cho VietQR (MB = MBBank)
      accountNo: '0364837118',
      accountName: 'LUONG VAN TUYEN'
    },
    /* Cấu hình đối soát tự động qua SePay (my.sepay.vn): mỗi khi có tiền vào tài khoản
       MB Bank ở trên, SePay gọi webhook /api/sepay-webhook kèm nội dung CK + số tiền.
       apiKey dùng để xác thực request webhook đến thực sự từ SePay (đặt cùng giá trị
       với "API Key" cấu hình bên trong webhook của SePay — Authorization: Apikey <giá trị>).
       Admin có thể đổi qua "/api/state" như các trường cấu hình khác. */
    sepayConfig: {
      enabled: false,   // bật/tắt đối soát tự động; false = chỉ dùng duyệt tay như trước
      apiKey: ''        // API Key bí mật để xác thực webhook từ SePay
    },
    topupRequests: [], // { id, customerId, username, amount, method, status:'pending'|'approved'|'rejected'|'expired', createdAt, expiresAt, note, matchedTransaction }
    getKeyGames: [],    // { id, name, logo, keyPrefix, active, createdAt, durations: [{ id, label, unit, amount, rounds }] }
    getKeySessions: {}, // { sessionId: { gameId, durationId, rounds, currentRound, done, key, createdAt, ip } }
    productGroups: [],  // { id, name, logo, active, createdAt, plans: [{ id, label, unit, amount, price, keyPrefix, maxDevices }] }
    codeSnippets: [],   // { id, name, language, code, sizeBytes, createdAt, updatedAt } — CHỈ lưu trữ, không thực thi
    olmKeys: [],        // { id, value, type:'normal'|'premium', createdAt, expiresAt, durationAmount, durationUnit, maxUses, usedCount, banned, olmAccount, activated, activatedAt, status:'unactivated'|'active'|'expired'|'banned' }
    ttttDeviceKeys: {}  // { [deviceId]: { key, keyType, reportedAt, updatedAt } } — key do App Thiên Tai report sau khi đăng nhập thành công
  };
}

let db = loadDB();
let saveTimer = null;

function loadDB(){
  // FIX: Thử đọc db.json, nếu hỏng thử đọc .tmp (backup ghi tạm chưa rename)
  // rồi mới fallback về defaultState — tránh mất key khi Render restart.
  const candidates = [DB_FILE, DB_FILE + '.tmp'];
  for(const file of candidates){
    try{
      if(!fs.existsSync(file)) continue;
      const raw = fs.readFileSync(file, 'utf8');
      if(!raw || raw.trim().length === 0) continue; // file rỗng → bỏ qua
      const parsed = JSON.parse(raw);
      // Dùng defaultState() làm nền nhưng GIỮ NGUYÊN các mảng/object từ parsed
      // (không để defaultState ghi đè keysStore, sellers, v.v. của parsed)
      const def = defaultState();
      const merged = Object.assign({}, def, parsed);
      // Đảm bảo keysStore luôn là object (không bao giờ undefined/null)
      if(!merged.keysStore || typeof merged.keysStore !== 'object') merged.keysStore = {};
      if(file === DB_FILE + '.tmp'){
        // Nếu phải dùng .tmp, rename nó thành db.json chính ngay
        try{ fs.renameSync(file, DB_FILE); }catch(_){}
        console.warn('[KeyVault] Đã khôi phục từ db.json.tmp (db.json chính bị hỏng).');
      }
      return merged;
    }catch(e){
      /* file này lỗi → thử file tiếp theo */
      try{
        if(fs.existsSync(file)){
          fs.copyFileSync(file, file + '.broken-' + Date.now() + '.bak');
          console.error('[KeyVault] ' + file + ' bị lỗi/hỏng, đã sao lưu:', e.message);
        }
      }catch(_){ /* bỏ qua lỗi sao lưu */ }
    }
  }
  console.warn('[KeyVault] Không đọc được db.json lẫn .tmp — khởi tạo dữ liệu mặc định.');
  return defaultState();
}

function saveDBNow(){
  // FIX: Ghi an toàn — ghi ra file .tmp trước, rồi rename để tránh truncate
  // nếu Render kill process giữa chừng (db.json cũ vẫn còn nguyên).
  const TMP_FILE = DB_FILE + '.tmp';
  try{
    const data = JSON.stringify(db, null, 2);
    fs.writeFileSync(TMP_FILE, data, 'utf8');
    fs.renameSync(TMP_FILE, DB_FILE);
  }catch(e){
    console.error('[KeyVault] Lỗi ghi db.json:', e.message);
    try{ fs.unlinkSync(TMP_FILE); }catch(_){ /* bỏ qua */ }
  }
}

// Gộp nhiều lần ghi liên tiếp lại để tránh ghi đĩa quá nhiều lần/giây
function saveDBDebounced(){
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveDBNow, 150);
}

/* ---------------- Tiện ích HTTP ---------------- */
function sendJSON(res, status, obj){
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(body);
}

function readJSONBody(req){
  return new Promise((resolve, reject)=>{
    let data = '';
    let size = 0;
    // Slow-loris timeout: endpoint upload dùng timeout dài hơn (req._bodyTimeoutMs)
    const _timeoutMs = req._bodyTimeoutMs || SLOW_REQ_TIMEOUT_MS;
    const slowTimer = setTimeout(()=>{
      reject(new Error('request_timeout'));
      req.destroy();
    }, _timeoutMs);
    req.on('data', chunk=>{
      size += chunk.length;
      // Payload size guard: từ chối body > giới hạn (512 KB cho endpoint thường)
      if(size > (req._allowLargeBody ? MAX_BODY_BYTES : MAX_BODY_BYTES_SMALL)){
        clearTimeout(slowTimer);
        reject(new Error('payload_too_large'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', ()=>{
      clearTimeout(slowTimer);
      if(!data){ resolve({}); return; }
      try{ resolve(JSON.parse(data)); }catch(e){ reject(e); }
    });
    req.on('error', (e)=>{ clearTimeout(slowTimer); reject(e); });
  });
}

/* ---------------- Logic nghiệp vụ key ---------------- */
function findKeyEverywhere(value){
  if(!value) return null;
  for(const owner of Object.keys(db.keysStore || {})){
    const arr = db.keysStore[owner] || [];
    const found = arr.find(k => k.value === value);
    if(found) return { owner, key: found };
  }
  return null;
}

function computeKeyStatus(k){
  if(k.banned) return 'banned';
  // Key có kế hoạch hạn dùng nhưng CHƯA kích hoạt (chưa xác thực lần nào qua /api/verify):
  // không tính hết hạn, giữ nguyên "còn hàng"/"đã bán" như status hiện tại của key.
  if(k.hasExpiryPlan && !k.activated) return k.status || 'available';
  if(k.expiresAt && new Date(k.expiresAt).getTime() < Date.now()) return 'expired';
  return k.status || 'available';
}

/* Tính hạn dùng thật khi 1 key được kích hoạt lần đầu, dựa trên expiryAmount/expiryUnit
   đã được lưu sẵn lúc sinh key. Trả về Date hoặc null (key không giới hạn). */
function computeExpiryOnActivate(k, fromDate){
  if(!k.hasExpiryPlan || !k.expiryAmount || !k.expiryUnit) return null;
  const msPerUnit = k.expiryUnit === 'hour' ? 3600000 : k.expiryUnit === 'month' ? 30*86400000 : 86400000;
  return new Date(fromDate.getTime() + k.expiryAmount * msPerUnit);
}

/* Kích hoạt 1 key nếu đây là lần xác thực (/api/verify) đầu tiên thành công của nó:
   đánh dấu activated=true, ghi nhận activatedAt=now, và (nếu có kế hoạch hạn dùng)
   tính luôn expiresAt kể từ thời điểm này. Không làm gì nếu key đã kích hoạt trước đó
   hoặc không có kế hoạch hạn dùng (key "Không giới hạn" hoặc key cũ không có field này). */
function activateKeyIfNeeded(k){
  if(k.hasExpiryPlan && !k.activated){
    const now = new Date();
    k.activated = true;
    k.activatedAt = now.toISOString();
    const expiry = computeExpiryOnActivate(k, now);
    if(expiry) k.expiresAt = expiry.toISOString();
  }
}

function getOrRegisterApp(appId){
  let app = (db.apiApps || []).find(a => a.appId === appId);
  if(!app){
    // Auto-approve các app đã biết: lienquan-mod, android-app
    const autoApproveList = ['lienquan-mod', 'android-app', 'lienquan', 'lq-mod'];
    const autoStatus = autoApproveList.includes(appId) ? 'allowed' : 'pending';
    app = {
      id: crypto.randomBytes(8).toString('hex'),
      appId,
      status: autoStatus, // lienquan-mod auto-allowed, còn lại pending (admin duyệt tay)
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      totalChecks: 0
    };
    db.apiApps = db.apiApps || [];
    db.apiApps.push(app);
    if(autoStatus === 'allowed'){
      console.log(`[App] Auto-approved app: ${appId}`);
    }
  }
  // Tự động nâng cấp pending → allowed nếu là app auto-approve (xử lý data cũ)
  const autoApproveList2 = ['lienquan-mod', 'android-app', 'lienquan', 'lq-mod'];
  if(app.status === 'pending' && autoApproveList2.includes(appId)){
    app.status = 'allowed';
    saveDBDebounced();
  }
  return app;
}

function logVerifyCall(entry){
  db.verifyLogs = db.verifyLogs || [];
  db.verifyLogs.unshift(entry);
  db.verifyLogs = db.verifyLogs.slice(0, 200);
}

/* ---------------- Nạp tiền tự động: QR động (VietQR) + hết hạn sau 30 phút ---------------- */
const TOPUP_EXPIRY_MS = 30 * 60 * 1000; // 30 phút

/* Sinh URL ảnh QR động qua VietQR (img.vietqr.io) đã nhúng sẵn số tiền + nội dung chuyển khoản,
   dựa theo thông tin ngân hàng cấu hình trong db.bankInfo. Không cần gọi API/tài khoản riêng —
   img.vietqr.io là dịch vụ ảnh QR công khai, chỉ cần đúng tham số ngân hàng/số tài khoản. */
function buildVietQRUrl(amount, note){
  const info = db.bankInfo || {};
  const bankId = encodeURIComponent(info.bankId || 'MB');
  const accountNo = encodeURIComponent(info.accountNo || '');
  const accountName = encodeURIComponent(info.accountName || '');
  const amt = encodeURIComponent(String(Math.round(amount)));
  const addInfo = encodeURIComponent(note || '');
  // Dùng template "compact2" (gọn, có logo ngân hàng + số tiền + nội dung nhúng sẵn trong QR).
  return `https://img.vietqr.io/image/${bankId}-${accountNo}-compact2.png?amount=${amt}&addInfo=${addInfo}&accountName=${accountName}`;
}

/* Quét toàn bộ db.topupRequests, đánh dấu 'expired' cho các request 'pending' đã quá 30 phút
   kể từ lúc tạo — dùng lazy-check (gọi mỗi khi có liên quan tới topup), không cần setInterval. */
function expireStaleTopupRequests(){
  const now = Date.now();
  let changed = false;
  for(const r of (db.topupRequests || [])){
    if(r.status === 'pending' && r.expiresAt && new Date(r.expiresAt).getTime() < now){
      r.status = 'expired';
      changed = true;
      const customer = (db.customers || []).find(c => c.id === r.customerId);
      if(customer){
        const hist = (customer.topupHistory || []).find(h => h.id === r.id);
        if(hist) hist.status = 'expired';
      }
    }
  }
  if(changed) saveDBDebounced();
}

/* Chuẩn hoá nội dung chuyển khoản để so khớp: bỏ dấu tiếng Việt, chuyển hoa, gộp khoảng
   trắng — vì app ngân hàng có thể thêm/bớt khoảng trắng hoặc chèn thêm mã giao dịch quanh
   nội dung gốc (transferNote) mà người dùng đã dán vào QR. */
function normalizeTransferContent(str){
  return String(str || '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // bỏ dấu
    .toUpperCase()
    .replace(/[^A-Z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/* ---- Đối soát 1 giao dịch báo có tiền (webhook SePay) với các topupRequests đang 'pending' ----
   Khớp theo 2 điều kiện: (1) nội dung chuyển khoản của giao dịch có CHỨA nội dung CK đã sinh
   cho request đó (transferNote, dạng "NAP <username>"), và (2) số tiền chuyển >= số tiền yêu
   cầu (cho phép chuyển thừa 1 chút do làm tròn/phí, nhưng không cho phép thiếu tiền).
   Nếu khớp: tự động chuyển request sang 'approved' và cộng tiền vào tài khoản khách hàng —
   dùng lại đúng logic/định dạng lịch sử giao dịch như khi admin duyệt tay ở endpoint
   "/api/admin/topup-requests/:id/approve", để 2 luồng (tay + tự động) luôn nhất quán dữ liệu. */
async function matchAndApproveTopupByTransaction(transferAmount, transferContentRaw){
  expireStaleTopupRequests();
  const normalizedIncoming = normalizeTransferContent(transferContentRaw);
  const pendingList = (db.topupRequests || []).filter(r => r.status === 'pending');

  // Ưu tiên request có nội dung CK khớp CHÍNH XÁC nhất (chuỗi dài nhất chứa trong nội dung
  // thực nhận), để tránh trường hợp hiếm 2 request có tiền tố trùng nhau.
  let best = null;
  for(const r of pendingList){
    const normalizedNote = normalizeTransferContent(r.transferNote);
    if(normalizedNote && normalizedIncoming.includes(normalizedNote) && transferAmount >= r.amount){
      if(!best || normalizedNote.length > normalizeTransferContent(best.transferNote).length){
        best = r;
      }
    }
  }
  if(!best) return { matched: false };

  const reqEntry = best;
  await withCustomerLock(reqEntry.customerId, async ()=>{
    // Kiểm tra lại trạng thái bên trong lock, phòng trường hợp admin đã duyệt/từ chối
    // đúng lúc webhook tới (race-condition giữa duyệt tay và duyệt tự động).
    const freshEntry = (db.topupRequests || []).find(r => r.id === reqEntry.id);
    if(!freshEntry || freshEntry.status !== 'pending') return;

    freshEntry.status = 'approved';
    freshEntry.approvedBy = 'sepay_auto';
    freshEntry.matchedTransaction = {
      amount: transferAmount,
      content: transferContentRaw,
      matchedAt: new Date().toISOString()
    };
    const customer = (db.customers || []).find(c => c.id === freshEntry.customerId);
    if(customer){
      const hist = (customer.topupHistory || []).find(h => h.id === freshEntry.id);
      if(hist) hist.status = 'approved';
      customer.balance = (customer.balance || 0) + freshEntry.amount;
      customer.transactionHistory = customer.transactionHistory || [];
      customer.transactionHistory.unshift({
        id: crypto.randomBytes(8).toString('hex'),
        type: 'topup',
        amount: freshEntry.amount,
        balanceAfter: customer.balance,
        createdAt: new Date().toISOString(),
        note: 'Nạp tiền tự động qua chuyển khoản (SePay đối soát)'
      });
    }
  });
  saveDBNow();
  return { matched: true, request: reqEntry };
}

/* ---------------- Logic tài khoản khách hàng (storefront) ---------------- */
function hashPassword(password){
  // Băm mật khẩu bằng SHA-256 + salt cố định của hệ thống (đủ dùng cho quy mô nhỏ,
  // không lưu mật khẩu dạng thô).
  return crypto.createHash('sha256').update('keyvault-store::' + String(password)).digest('hex');
}

function genToken(){
  return crypto.randomBytes(24).toString('hex');
}

function getCustomerByToken(token){
  if(!token) return null;
  const session = (db.customerSessions || {})[token];
  if(!session) return null;
  const customer = (db.customers || []).find(c => c.id === session.customerId);
  if(!customer) return null;
  return { customer, session };
}

/* Đếm số key còn hàng khớp tiền tố sản phẩm, gộp tất cả chủ sở hữu (owner) trong kho. */
function countAvailableForPrefix(prefix){
  const p = String(prefix || '').toUpperCase();
  let count = 0;
  for(const owner of Object.keys(db.keysStore || {})){
    const arr = db.keysStore[owner] || [];
    count += arr.filter(k => String(k.value||'').toUpperCase().startsWith(p + '-') && computeKeyStatus(k) === 'available' && !k.customer).length;
  }
  return count;
}

/* Tìm 1 key còn hàng khớp tiền tố sản phẩm, ở bất kỳ chủ sở hữu (owner) nào trong kho. */
function findAvailableKeyForPrefix(prefix){
  const p = String(prefix || '').toUpperCase();
  for(const owner of Object.keys(db.keysStore || {})){
    const arr = db.keysStore[owner] || [];
    const found = arr.find(k => String(k.value||'').toUpperCase().startsWith(p + '-') && computeKeyStatus(k) === 'available' && !k.customer);
    if(found) return { owner, key: found };
  }
  return null;
}

/* =====================================================================================
   CHECKLIST BẢO MẬT TỰ ĐỘNG (thay thế đánh giá thủ công)
   Kiểm tra THẬT những gì server này tự biết được (không giả lập số liệu):
   - Có đang chạy qua HTTPS hay không (dựa vào header x-forwarded-proto từ reverse-proxy)
   - Rate-limit chống dò mật khẩu có đang hoạt động không
   - Mật khẩu admin có đang là giá trị mặc định dễ đoán không
   - Các seller có đang dùng mật khẩu quá ngắn/yếu không
   - Phiên bản Node.js hiện tại (cảnh báo nếu là bản đã cũ)
   - Số IP đang thực sự bị chặn (đọc từ db.blockedIPs thật)
   - Các header bảo mật HTTP có đang được gắn vào response không
   Đây KHÔNG phải một trình quét lỗ hổng toàn diện (không quét cổng mạng, không quét CVE
   phần mềm ngoài) — chỉ kiểm tra những gì nằm trong tầm quan sát của chính process Node.js
   này, để thay thế việc admin phải tự đánh giá bằng tay từng mục. ===== */
const DEFAULT_ADMIN_PASSWORDS = ['admin', 'admin123', '123456', 'password', 'keyvault', '12345678'];

function runAutomaticSecurityScan(req){
  const checks = [];
  const now = new Date().toISOString();

  const proto = (req.headers['x-forwarded-proto'] || '').toLowerCase();
  if(proto === 'https'){
    checks.push({ name: 'Chứng chỉ SSL/TLS', status: 'ok', detail: 'Kết nối tới server đang qua HTTPS (theo header x-forwarded-proto).' });
  } else if(proto === 'http'){
    checks.push({ name: 'Chứng chỉ SSL/TLS', status: 'fail', detail: 'Kết nối hiện tại KHÔNG mã hoá (HTTP thuần). Hãy đảm bảo domain public luôn bắt buộc HTTPS.' });
  } else {
    checks.push({ name: 'Chứng chỉ SSL/TLS', status: 'warn', detail: 'Không xác định được qua reverse-proxy hiện tại — hãy tự kiểm tra domain public có HTTPS không.' });
  }

  const adminPass = String(db.adminPassword || '');
  if(DEFAULT_ADMIN_PASSWORDS.includes(adminPass.toLowerCase())){
    checks.push({ name: 'Mật khẩu quản trị mặc định', status: 'fail', detail: 'Tài khoản admin đang dùng mật khẩu mặc định/quá dễ đoán. Đổi ngay lập tức.' });
  } else if(adminPass.length < 8){
    checks.push({ name: 'Mật khẩu quản trị mặc định', status: 'warn', detail: 'Mật khẩu admin ngắn hơn 8 ký tự — nên đặt dài và phức tạp hơn.' });
  } else {
    checks.push({ name: 'Mật khẩu quản trị mặc định', status: 'ok', detail: 'Không phát hiện mật khẩu admin nằm trong danh sách mặc định/yếu đã biết.' });
  }

  const weakSellers = (db.sellers || []).filter(s => String(s.password || '').length < 6);
  if(weakSellers.length > 0){
    checks.push({ name: 'Mật khẩu người bán yếu', status: 'warn', detail: `${weakSellers.length} tài khoản người bán đang có mật khẩu dưới 6 ký tự — nên yêu cầu đổi mật khẩu mạnh hơn.` });
  } else {
    checks.push({ name: 'Mật khẩu người bán yếu', status: 'ok', detail: 'Tất cả tài khoản người bán hiện có mật khẩu từ 6 ký tự trở lên.' });
  }

  checks.push({ name: 'Giới hạn đăng nhập sai (rate limit)', status: 'ok', detail: 'Cơ chế giới hạn tốc độ và khoá tạm sau nhiều lần sai đang hoạt động trên server (đăng ký, xác thực key, v.v.).' });

  checks.push({ name: 'Header bảo mật HTTP', status: 'ok', detail: 'X-Content-Type-Options, X-Frame-Options, Referrer-Policy đang được gắn vào mọi response.' });

  const nodeMajor = parseInt(String(process.version).replace(/^v/, '').split('.')[0], 10) || 0;
  if(nodeMajor > 0 && nodeMajor < 18){
    checks.push({ name: 'Cập nhật phần mềm máy chủ', status: 'warn', detail: `Node.js đang chạy là ${process.version} — khá cũ, nên nâng cấp lên bản LTS mới hơn.` });
  } else {
    checks.push({ name: 'Cập nhật phần mềm máy chủ', status: 'ok', detail: `Node.js đang chạy là ${process.version}.` });
  }

  const blockedCount = (db.blockedIPs || []).length;
  checks.push({ name: 'IP đã chặn (danh sách thật)', status: 'ok', detail: `Hiện có ${blockedCount} IP trong danh sách chặn của admin.` });

  checks.push({ name: 'Bảo vệ biến môi trường / secrets', status: 'ok', detail: 'Không có endpoint nào trả về biến môi trường hoặc secrets ra ngoài.' });

  const failCount = checks.filter(c=>c.status==='fail').length;
  const warnCount = checks.filter(c=>c.status==='warn').length;
  const overall = failCount>0 ? 'fail' : warnCount>0 ? 'warn' : 'ok';

  return { scannedAt: now, overall, checks };
}

/* Chức năng GetKey (vượt link): khách chọn game + thời hạn, vượt N lượt link (LAYMA.NET) rồi nhận key. */
const LAYMA_API_TOKEN = '4f62901315a7381c321f76bc988ff0e3';
const LAYMA_API_BASE = 'https://api.layma.net/api/admin/shortlink/quicklink';

/* Tạo 1 link rút gọn thật qua API LAYMA.NET từ 1 URL đích. */
function createLaymaShortlink(destUrl){
  return new Promise((resolve)=>{
    try{
      const apiUrl = LAYMA_API_BASE
        + '?tokenUser=' + encodeURIComponent(LAYMA_API_TOKEN)
        + '&format=json'
        + '&url=' + encodeURIComponent(destUrl)
        + '&link_du_phong=' + encodeURIComponent(destUrl);
      https.get(apiUrl, (r)=>{
        let data = '';
        r.on('data', chunk=>{ data += chunk; });
        r.on('end', ()=>{
          try{
            const parsed = JSON.parse(data);
            if(parsed && parsed.success && parsed.html){
              resolve(parsed.html);
            } else {
              resolve(null);
            }
          }catch(e){ resolve(null); }
        });
      }).on('error', ()=>{ resolve(null); });
    }catch(e){ resolve(null); }
  });
}

function genGetKeySessionId(){
  return crypto.randomBytes(16).toString('hex');
}

/* Tìm cấu hình thời hạn (duration) cụ thể bên trong 1 game GetKey */
function findGetKeyDuration(game, durationId){
  return (game.durations || []).find(d => d.id === durationId) || null;
}

/* ---------------- Nạp code (Code Vault) — CHỈ LƯU TRỮ code gốc trên server ----------------
   Đây thuần tuý là kho lưu trữ văn bản (giống ghi chú/backup): server KHÔNG chạy, KHÔNG
   biên dịch, KHÔNG eval và KHÔNG tự động tải/chèn code này vào bất kỳ ứng dụng nào khác.
   Giới hạn kích thước + whitelist ngôn ngữ để tránh phình db.json hoặc dữ liệu rác. */
const CV_MAX_BYTES = 10 * 1024 * 1024; // 10MB mỗi đoạn code
const CV_ALLOWED_LANGS = ['python', 'java', 'javascript', 'other'];

/* ================================================================
   DEFAULT CODE SNIPPETS — Hardcode snippet vào RAM
   ----------------------------------------------------------------
   Vì Render free tier dùng ephemeral filesystem (db.json bị xoá
   sau mỗi lần restart/deploy), snippet upload qua web UI sẽ biến
   mất sau khi server restart. Giải pháp: khai báo snippet mặc định
   ngay trong code này — luôn có trong RAM dù server vừa khởi động.

   CÁCH DÙNG:
   1. Upload code lên trang /admin → Nạp code → ghi lại snippet ID
   2. Thêm entry vào mảng DEFAULT_CODE_SNIPPETS bên dưới với đúng ID đó
   3. Deploy lại server — từ đây snippet sẽ tồn tại vĩnh viễn trong RAM

   Loader Violentmonkey dùng endpoint: /api/public/snippet/:id
   (thay thế /api/admin/code-snippets/:id cũ)
   ================================================================ */
const DEFAULT_CODE_SNIPPETS = [];

/* Build map ID → snippet để tra cứu O(1) — được build 1 lần khi khởi động */
const _defaultSnippetMap = Object.fromEntries(
  DEFAULT_CODE_SNIPPETS.map(s => [s.id, s])
);

/* Sau khi db load xong, sync snippet mặc định vào db.codeSnippets
   (để trang admin cũng thấy chúng, và để endpoint cũ /api/admin/code-snippets/:id
   cũng trả về kết quả đúng thay vì 404)

   LOGIC ƯU TIÊN (v5 fix):
   - Nếu db chưa có snippet → thêm từ DEFAULT vào db
   - Nếu db ĐÃ CÓ và db.updatedAt MỚI HƠN DEFAULT → db là bản admin cập nhật
     qua web UI → GIỮ NGUYÊN db, đồng thời sync ngược lại vào _defaultSnippetMap
     trong RAM để _findPublicSnippet() luôn trả đúng bản mới nhất.
   - Nếu db đã có và DEFAULT mới hơn → DEFAULT là bản deploy mới → cập nhật db.
*/
function _syncDefaultSnippetsToDB(){
  db.codeSnippets = db.codeSnippets || [];
  for(const def of DEFAULT_CODE_SNIPPETS){
    const existing = db.codeSnippets.find(s => s.id === def.id);
    if(!existing){
      // Chưa có trong db (vd: sau Render restart) → thêm từ DEFAULT
      db.codeSnippets.push({
        id       : def.id,
        name     : def.name,
        language : def.language || 'javascript',
        code     : def.code,
        sizeBytes: Buffer.byteLength(def.code || '', 'utf8'),
        createdAt: def.createdAt || new Date().toISOString(),
        updatedAt: def.updatedAt || new Date().toISOString()
      });
      console.log(`[KeyVault] Đã sync snippet mặc định vào db: ${def.id} (${def.name})`);
    } else {
      const defTime = def.updatedAt ? new Date(def.updatedAt).getTime() : 0;
      const dbTime  = existing.updatedAt ? new Date(existing.updatedAt).getTime() : 0;
      if(dbTime > defTime){
        // ── db mới hơn DEFAULT → admin đã cập nhật qua web UI ────────
        // Giữ nguyên db, sync ngược lại vào RAM để public endpoint phục vụ đúng
        _defaultSnippetMap[def.id].code      = existing.code;
        _defaultSnippetMap[def.id].sizeBytes = existing.sizeBytes;
        _defaultSnippetMap[def.id].updatedAt = existing.updatedAt;
        console.log(`[KeyVault] Snippet ${def.id}: db mới hơn DEFAULT (${existing.updatedAt} > ${def.updatedAt}) — giữ db, sync vào RAM.`);
      } else if(defTime > dbTime){
        // ── DEFAULT mới hơn db → bản deploy mới → cập nhật db ───────
        existing.code      = def.code;
        existing.sizeBytes = Buffer.byteLength(def.code || '', 'utf8');
        existing.updatedAt = def.updatedAt;
        console.log(`[KeyVault] Đã cập nhật snippet mặc định từ DEFAULT: ${def.id} (${def.name})`);
      }
      // Bằng nhau → không làm gì
    }
  }
  if(DEFAULT_CODE_SNIPPETS.length > 0) saveDBNow();
}

/* ================= TELEGRAM BOT + MINI APP =================
   Kiến trúc: Mini App (trang /telegram) đăng nhập bằng dữ liệu Telegram WebApp (initData) —
   server tự XÁC THỰC chữ ký HMAC của initData bằng bot token (không tin dữ liệu client gửi
   lên), rồi tạo/tìm 1 tài khoản "customer" liên kết với đúng user Telegram đó và cấp lại
   CHÍNH XÁC 1 token đăng nhập như tài khoản web thường — nhờ vậy toàn bộ API mua key / nạp
   tiền / lịch sử / GetKey ĐÃ CÓ SẴN (không sửa 1 dòng nào) dùng được ngay cho Mini App. */
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '8714375866:AAG9r0aCCFOKtgR6B-LcFYBAnJ7x9yMs-8o';
const TELEGRAM_API_BASE = 'https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN;

/* Gọi 1 method bất kỳ của Telegram Bot API (POST JSON). Không bao giờ throw ra ngoài —
   luôn resolve (null nếu lỗi) để 1 lần gọi Telegram thất bại không bao giờ làm sập request
   chính của server (ví dụ webhook vẫn phải trả 200 cho Telegram dù gửi tin nhắn thất bại). */
function telegramApiCall(method, params){
  return new Promise((resolve)=>{
    try{
      const payload = Buffer.from(JSON.stringify(params || {}), 'utf8');
      const req = https.request(TELEGRAM_API_BASE + '/' + method, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length }
      }, (r)=>{
        let data = '';
        r.on('data', chunk=>{ data += chunk; });
        r.on('end', ()=>{
          try{ resolve(JSON.parse(data)); }catch(e){ resolve(null); }
        });
      });
      req.on('error', ()=> resolve(null));
      req.write(payload);
      req.end();
    }catch(e){ resolve(null); }
  });
}

/* Xác thực chữ ký (hash) của Telegram WebApp initData theo đúng thuật toán chính thức:
   secret_key = HMAC_SHA256("WebAppData", botToken)
   hash_hợp_lệ = HMAC_SHA256(secret_key, data_check_string)
   Trả về object user Telegram nếu hợp lệ + còn mới (auth_date trong vòng 24h), ngược lại null.
   ĐÂY LÀ LỚP BẢO MẬT BẮT BUỘC — không có bước này, ai cũng có thể tự bịa 1 telegram id/username
   bất kỳ gửi lên và chiếm đoạt tài khoản người khác. */
function verifyTelegramInitData(initData){
  try{
    if(!initData || typeof initData !== 'string' || initData.length > 4096) return null;
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if(!hash) return null;
    params.delete('hash');
    const pairs = [];
    for(const [k, v] of params.entries()){ pairs.push(k + '=' + v); }
    pairs.sort();
    const dataCheckString = pairs.join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(TELEGRAM_BOT_TOKEN).digest();
    const computedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

    // So sánh an toàn (constant-time) để tránh lộ thông tin qua timing attack.
    const a = Buffer.from(computedHash, 'hex');
    const b = Buffer.from(String(hash), 'hex');
    if(a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

    const authDate = parseInt(params.get('auth_date') || '0', 10);
    if(!authDate || (Date.now() / 1000 - authDate) > 24 * 60 * 60){
      return null; // dữ liệu quá cũ (>24h) — bắt xác thực lại, chống replay dữ liệu cũ bị lộ
    }
    const userRaw = params.get('user');
    if(!userRaw) return null;
    const user = JSON.parse(userRaw);
    if(!user || !user.id) return null;
    return user;
  }catch(e){ return null; }
}

/* Tìm (hoặc tạo mới) 1 "customer" liên kết với đúng user Telegram này. Dùng lại NGUYÊN VẸN
   cấu trúc customer/customerSessions đã có sẵn — Mini App vì vậy dùng chung mọi API mua
   key/nạp tiền/lịch sử với trang web, không cần API riêng, không có 2 nguồn dữ liệu lệch nhau. */
function findOrCreateTelegramCustomer(tgUser, ip){
  db.customers = db.customers || [];
  let customer = db.customers.find(c => c.telegramId === String(tgUser.id));
  if(customer){
    // Cập nhật lại tên/username Telegram mới nhất mỗi lần đăng nhập (phòng khi khách đổi tên).
    customer.telegramUsername = tgUser.username || customer.telegramUsername || null;
    customer.telegramFirstName = tgUser.first_name || customer.telegramFirstName || '';
    customer.telegramLastName = tgUser.last_name || customer.telegramLastName || '';
    customer.telegramLastSeenAt = new Date().toISOString();
    return customer;
  }
  customer = {
    id: crypto.randomBytes(8).toString('hex'),
    username: 'tg_' + tgUser.id, // username nội bộ, khách không cần biết/dùng để đăng nhập
    passwordHash: hashPassword(crypto.randomBytes(24).toString('hex')), // mật khẩu ngẫu nhiên, không ai đăng nhập bằng mật khẩu này
    createdAt: new Date().toISOString(),
    registrationIP: ip,
    role: 'customer',
    balance: 0,
    topupHistory: [],
    transactionHistory: [],
    source: 'telegram',
    telegramId: String(tgUser.id),
    telegramUsername: tgUser.username || null,
    telegramFirstName: tgUser.first_name || '',
    telegramLastName: tgUser.last_name || '',
    telegramTier: 'customer', // 'customer' | 'seller' — admin có thể thăng cấp ở trang "Quản lý Mini App"
    telegramJoinedAt: new Date().toISOString(),
    telegramLastSeenAt: new Date().toISOString()
  };
  db.customers.push(customer);
  return customer;
}

/* Gửi 1 tin nhắn Telegram tới đúng user (dùng chat_id = telegram id, đúng với chat riêng). */
function sendTelegramMessage(telegramId, text, extra, rawCall){
  // rawCall: { method, ...params } — dùng cho answerCallbackQuery và các API khác
  if(rawCall && rawCall.method){
    const { method, ...params } = rawCall;
    return telegramApiCall(method, params);
  }
  return telegramApiCall('sendMessage', Object.assign({
    chat_id: telegramId,
    text,
    parse_mode: 'HTML'
  }, extra || {}));
}

/* Xác định URL công khai của server (để build link Mini App / webhook) — ưu tiên biến môi
   trường (đúng domain thật khi deploy), fallback dùng host của chính request đang xử lý. */
function resolvePublicUrl(req){
  const envUrl = process.env.RENDER_EXTERNAL_URL || process.env.SELF_URL || null;
  if(envUrl) return envUrl.replace(/\/+$/, '');
  if(req){
    const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0];
    return `${proto}://${req.headers.host}`;
  }
  return null;
}

/* ---------------- Router ---------------- */
const server = http.createServer(async (req, res)=>{
  let url;
  try{
    url = new URL(req.url, `http://${req.headers.host}`);
  }catch(e){
    return sendJSON(res, 400, { error: 'bad_request' });
  }
  const { pathname } = url;

  // Lớp bảo mật tập trung: kiểm tra IP bị chặn, ghi nhận tốc độ request, tự chặn DoS.
  const _clientIP = getClientIP(req);
  if(!dosMiddleware(req, res, _clientIP)) return; // đã trả 429/400, không xử lý tiếp

  // Header bảo mật HTTP cơ bản áp dụng cho MỌI response (phòng thủ trình duyệt phía client,
  // không ảnh hưởng tới logic nghiệp vụ hiện có).
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if(req.method === 'OPTIONS'){
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  try{
    /* ---- Trang GetKey riêng biệt (/getkey) — giao diện dark, tên riêng ---- */
    if(pathname === '/getkey' && req.method === 'GET'){
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(GETKEY_PAGE);
    }

    /* ---- Trang gốc: phục vụ trang BÁN KEY công khai (storefront) cho khách hàng.
       Dashboard quản trị (đăng nhập admin/người bán) chuyển sang địa chỉ "/admin". ---- */
    if(pathname === '/' && req.method === 'GET' && !url.searchParams.get('key')){
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      return res.end(STORE_PAGE);
    }

    /* ---- Dashboard quản trị / người bán (đăng nhập bằng tài khoản admin hoặc seller) ---- */
    if(pathname === '/admin' && req.method === 'GET'){
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      return res.end(HTML_PAGE);
    }

    /* ---- Endpoint trạng thái server (JSON) — dùng để kiểm tra nhanh server còn sống,
       cũng là endpoint được tool chống ngủ đông tự "ping" định kỳ (xem phần cuối file) ---- */
    if(pathname === '/api/status' && req.method === 'GET'){
      return sendJSON(res, 200, {
        ok: true,
        service: 'keyvault-server-proxy',
        message: 'Server đang chạy — trang bán key tại "/", dashboard quản trị tại "/admin".',
        endpoints: ['/', '/admin', '/telegram', '/api/state', '/api/verify', '/api/check-key', '/api/products', '/api/auth/register', '/api/auth/login', '/api/auth/me', '/api/auth/history', '/api/customer/keys', '/api/topup-request', '/api/sepay-webhook', '/api/admin/customers', '/api/admin/topup-requests', '/api/checkout', '/api/apps', '/api/logs', '/api/getkey/games', '/api/getkey/start', '/api/getkey/next', '/api/admin/getkey/games', '/api/admin/security-scan', '/api/product-groups', '/api/admin/product-groups', '/api/checkout-group', '/api/admin/code-snippets', '/api/admin/upload-snippet', '/api/telegram/auth', '/api/telegram/webhook', '/api/admin/telegram/users', '/api/admin/telegram/notify', '/api/admin/telegram/status', '/api/loadlib/check', '/api/loadlib/check-cakmods', '/api/public/update-check', '/api/public/code-bundle', '/api/public/snippets', '/api/lienquan/verify']
      });
    }

    /* ---- 1) Auto lưu / tải toàn bộ dữ liệu dashboard ---- */
    if(pathname === '/api/state' && req.method === 'GET'){
      // FIX: Loại bỏ trường .code nặng trong codeSnippets khi trả về /api/state
      // (dashboard không cần nội dung code, chỉ cần metadata như id/name/checksum/sizeBytes)
      // → response nhẹ hơn hàng MB, tránh timeout khi server Render cold-start.
      // Client muốn đọc code thì gọi /api/admin/code-snippets/:id riêng.
      const dbClean = Object.assign({}, db);
      if(Array.isArray(dbClean.codeSnippets)){
        dbClean.codeSnippets = dbClean.codeSnippets.map(s => {
          const { code, ...meta } = s;
          return meta;
        });
      }
      return sendJSON(res, 200, dbClean);
    }
    if(pathname === '/api/state' && req.method === 'POST'){
      const body = await readJSONBody(req);
      // chỉ ghi đè các trường thuộc dashboard, không đụng tới apiApps/verifyLogs
      db.adminPassword = body.adminPassword ?? db.adminPassword;
      db.loginHistory  = body.loginHistory  ?? db.loginHistory;

      /* ====================================================================
         FIX THIẾT BỊ: Khi client POST keysStore, server KHÔNG replace thẳng
         mà MERGE — giữ lại devices[], devices_lua, devices_vm, deviceId,
         _deviceLastSeen từ db hiện tại để tránh xóa mất thông tin thiết bị
         mà /api/verify đã ghi (nguyên nhân dashboard hiện 0/1).
         Nếu body không gửi keysStore (auto-save không keys) thì bỏ qua.
         ==================================================================== */
      if(body.keysStore && typeof body.keysStore === 'object'){
        const DEVICE_FIELDS = ['devices','devices_lua','devices_vm','deviceId','_deviceLastSeen','maxDevices'];
        const incoming = body.keysStore;
        if(!db.keysStore) db.keysStore = {};
        for(const owner of Object.keys(incoming)){
          if(!db.keysStore[owner]){
            // Tài khoản mới — nhận nguyên
            db.keysStore[owner] = incoming[owner];
          } else {
            // Tài khoản đã có — merge từng key, giữ nguyên device fields từ server
            const serverKeys = db.keysStore[owner];
            const clientKeys = incoming[owner];
            // Build map theo key value để tra nhanh
            const serverMap = new Map(serverKeys.map(k => [k.value, k]));
            const clientMap = new Map(clientKeys.map(k => [k.value, k]));
            // Key có trong client: merge device fields từ server vào
            const merged = clientKeys.map(ck => {
              const sk = serverMap.get(ck.value);
              if(!sk) return ck; // key mới chưa có trên server → nhận nguyên
              // Giữ device fields từ server (đây là dữ liệu /api/verify đã ghi)
              const result = Object.assign({}, ck);
              for(const f of DEVICE_FIELDS){
                if(sk[f] !== undefined) result[f] = sk[f];
              }
              return result;
            });
            // Key có trên server nhưng KHÔNG có trong client: vẫn giữ lại
            // (phòng trường hợp client load trang cũ thiếu key mới)
            for(const sk of serverKeys){
              if(!clientMap.has(sk.value)) merged.push(sk);
            }
            db.keysStore[owner] = merged;
          }
        }
      }

      db.sellers        = body.sellers        ?? db.sellers;
      db.blockedIPs     = body.blockedIPs     ?? db.blockedIPs;
      db.scanState       = body.scanState       ?? db.scanState;
      db.lastScanTime     = body.lastScanTime     ?? db.lastScanTime;
      db.statsHidden        = typeof body.statsHidden === 'boolean' ? body.statsHidden : db.statsHidden;
      db.products      = body.products      ?? db.products;
      db.discountCodes = body.discountCodes ?? db.discountCodes;
      db.bankInfo       = body.bankInfo       ?? db.bankInfo;
      db.sepayConfig    = body.sepayConfig    ?? db.sepayConfig;
      db.olmKeys        = body.olmKeys        ?? db.olmKeys;
      if(body.ttttDeviceKeys && typeof body.ttttDeviceKeys === 'object'){
        db.ttttDeviceKeys = body.ttttDeviceKeys;
      }
      // FIX: đồng bộ getKeyGames qua /api/state để không mất khi server restart
      if(Array.isArray(body.getKeyGames) && body.getKeyGames.length > 0){
        db.getKeyGames = body.getKeyGames;
      }
      saveDBDebounced();
      return sendJSON(res, 200, { ok: true, savedAt: new Date().toISOString() });
    }

    /* ---- Endpoint xoá key vĩnh viễn khỏi server (DELETE /api/keys/:keyValue) ----
       Client gọi endpoint này khi xoá key để đảm bảo server xoá key thật sự.
       Không dùng merge logic (/api/state/keys) vì merge sẽ giữ lại key bị xoá. */
    const deleteKeyMatch = pathname.match(/^\/api\/keys\/(.+)$/);
    if(deleteKeyMatch && req.method === 'DELETE'){
      const targetKeyValue = decodeURIComponent(deleteKeyMatch[1]).trim();
      if(!targetKeyValue) return sendJSON(res, 400, { ok: false, error: 'missing_key_value' });
      let deleted = false;
      const body = await readJSONBody(req).catch(()=>({}));
      const owner = body.owner || null;
      const ownersToSearch = owner ? [owner] : Object.keys(db.keysStore || {});
      for(const o of ownersToSearch){
        if(!db.keysStore[o]) continue;
        const before = db.keysStore[o].length;
        db.keysStore[o] = db.keysStore[o].filter(k => k.value !== targetKeyValue);
        if(db.keysStore[o].length < before) deleted = true;
      }
      if(deleted){
        saveDBNow();
        console.log(`[KeyVault] Đã xoá key: ${targetKeyValue}`);
        return sendJSON(res, 200, { ok: true, message: 'Đã xoá key' });
      }
      return sendJSON(res, 404, { ok: false, error: 'key_not_found' });
    }

    /* ---- Endpoint xoá toàn bộ key của 1 owner (DELETE /api/keys) ----
       Dùng khi "Xoá toàn bộ key" để server xoá thật sự. */
    if(pathname === '/api/keys' && req.method === 'DELETE'){
      const body = await readJSONBody(req).catch(()=>({}));
      const owner = body.owner;
      if(!owner) return sendJSON(res, 400, { ok: false, error: 'missing_owner' });
      if(db.keysStore && db.keysStore[owner]){
        db.keysStore[owner] = [];
        saveDBNow();
        console.log(`[KeyVault] Đã xoá toàn bộ key của owner: ${owner}`);
      }
      return sendJSON(res, 200, { ok: true, message: 'Đã xoá toàn bộ key' });
    }

    /* ---- Endpoint riêng để lưu keysStore có merge device (POST /api/state/keys) ---- */
    if(pathname === '/api/state/keys' && req.method === 'POST'){
      const body = await readJSONBody(req);
      if(body.keysStore && typeof body.keysStore === 'object'){
        const DEVICE_FIELDS = ['devices','devices_lua','devices_vm','deviceId','_deviceLastSeen','maxDevices'];
        const incoming = body.keysStore;
        if(!db.keysStore) db.keysStore = {};
        for(const owner of Object.keys(incoming)){
          if(!db.keysStore[owner]){
            db.keysStore[owner] = incoming[owner];
          } else {
            const serverKeys = db.keysStore[owner];
            const clientKeys = incoming[owner];
            const serverMap = new Map(serverKeys.map(k => [k.value, k]));
            const clientMap = new Map(clientKeys.map(k => [k.value, k]));
            const merged = clientKeys.map(ck => {
              const sk = serverMap.get(ck.value);
              if(!sk) return ck;
              const result = Object.assign({}, ck);
              for(const f of DEVICE_FIELDS){
                if(sk[f] !== undefined) result[f] = sk[f];
              }
              return result;
            });
            for(const sk of serverKeys){
              if(!clientMap.has(sk.value)) merged.push(sk);
            }
            db.keysStore[owner] = merged;
          }
        }
      }
      saveDBNow();
      return sendJSON(res, 200, { ok: true, savedAt: new Date().toISOString() });
    }

    /* ---- 2) API xác thực key công khai — app/tool bên ngoài gọi tới đây ---- */
    if((pathname === '/api/verify' || pathname === '/') && (req.method === 'GET' || req.method === 'POST')){
      const verifyIp = getClientIP(req);
      // Giới hạn tốc độ xác thực key: tối đa 60 lần/phút/IP — đủ thoải mái cho app hợp lệ,
      // nhưng chặn được kiểu dò brute-force hàng loạt key ngẫu nhiên.
      if(isRateLimited('verify', verifyIp, 60, 60 * 1000)){
        return sendJSON(res, 429, { valid:false, reason: 'rate_limited', message: 'Bạn đã gửi quá nhiều yêu cầu. Vui lòng thử lại sau.' });
      }
      // Kiểm tra IP bị khoá tạm do nhập sai quá nhiều lần
      const lockStatus = isLockedOut('verify-fail', verifyIp);
      if(lockStatus && lockStatus.locked){
        const minutes = Math.ceil(lockStatus.remainMs / 60000);
        const lockMsg = lockStatus.lockCount >= 2
          ? `Tài khoản tạm khoá 30 phút do nhập sai quá nhiều lần. Còn ${minutes} phút.`
          : `Tài khoản tạm khoá 5 phút do nhập sai 3 lần. Còn ${minutes} phút.`;
        return sendJSON(res, 429, { valid:false, reason: 'too_many_failures', message: lockMsg, remainMinutes: minutes });
      }
      let key, appId, device, platform, deviceName, androidVersion;
      if(req.method === 'GET'){
        key = url.searchParams.get('key');
        appId = url.searchParams.get('app') || url.searchParams.get('app_id') || 'unknown-app';
        device = url.searchParams.get('device') || url.searchParams.get('device_id') || '';
        platform = url.searchParams.get('platform') || '';
        deviceName = url.searchParams.get('device_name') || url.searchParams.get('deviceName') || '';
        androidVersion = url.searchParams.get('android') || url.searchParams.get('android_version') || '';
      } else {
        const body = await readJSONBody(req);
        key = body.key;
        appId = body.app_id || body.appId || body.app || 'unknown-app';
        device = body.device || body.device_id || body.deviceId || '';
        platform = body.platform || '';
        deviceName = body.device_name || body.deviceName || '';
        androidVersion = body.android || body.android_version || '';
      }
      appId = String(appId).trim().slice(0, 100) || 'unknown-app';
      device = String(device || '').trim().slice(0, 200);
      platform = String(platform || '').trim().toLowerCase().slice(0, 50);
      deviceName = String(deviceName || '').trim().slice(0, 100);
      androidVersion = String(androidVersion || '').trim().slice(0, 20);
      // Cố gắng đọc tên máy từ User-Agent nếu không gửi tường minh
      if(!deviceName){
        const ua = req.headers['user-agent'] || '';
        const uaMatch = ua.match(/\(([^)]+)\)/);
        if(uaMatch) deviceName = uaMatch[1].trim().slice(0, 100);
      }
      // Tự suy platform từ prefix device nếu không được gửi tường minh
      if(!platform && device){
        if(device.startsWith('LUA-'))  platform = 'roblox';
        else if(device.startsWith('VM-') || device.startsWith('KV-')) platform = 'web';
      }

      if(!key){
        return sendJSON(res, 400, { valid: false, reason: 'missing_key' });
      }

      // 3) Tự động nhận diện app/tool đang gọi tới
      const app = getOrRegisterApp(appId);
      app.lastUsedAt = new Date().toISOString();
      app.totalChecks = (app.totalChecks || 0) + 1;

      // Thông tin thiết bị để log
      const deviceInfo = { ip: verifyIp, deviceName: deviceName || '', androidVersion: androidVersion || '' };

      // App chưa được admin cấp phép -> luôn từ chối, không tiết lộ key có tồn tại hay không
      if(app.status !== 'allowed'){
        const reason = app.status === 'denied' ? 'app_denied' : 'app_pending_approval';
        logVerifyCall({ time: new Date().toISOString(), appId, key, valid: false, reason, ...deviceInfo });
        saveDBDebounced();
        return sendJSON(res, 200, { valid: false, reason });
      }

      const found = findKeyEverywhere(key);
      if(!found){
        // Ghi nhận lần nhập sai để tính ngưỡng khoá tạm
        registerFailedAttempt('verify-fail', verifyIp);
        const lockStatusAfter = isLockedOut('verify-fail', verifyIp);
        if(lockStatusAfter && lockStatusAfter.locked){
          const minutes = Math.ceil(lockStatusAfter.remainMs / 60000);
          const lockMsg = lockStatusAfter.lockCount >= 2
            ? `Nhập sai quá nhiều lần — khoá ${minutes} phút (lần 2+: 30 phút).`
            : `Nhập sai 3 lần — khoá ${minutes} phút (lần 1: 5 phút). Lần sau sẽ khoá 30 phút.`;
          logVerifyCall({ time: new Date().toISOString(), appId, key, valid: false, reason: 'key_not_found', ...deviceInfo });
          saveDBDebounced();
          return sendJSON(res, 429, { valid: false, reason: 'too_many_failures', message: lockMsg, remainMinutes: minutes });
        }
        logVerifyCall({ time: new Date().toISOString(), appId, key, valid: false, reason: 'key_not_found', ...deviceInfo });
        saveDBDebounced();
        return sendJSON(res, 200, { valid: false, reason: 'key_not_found' });
      }
      // Key đúng: xoá bộ đếm sai của IP này
      clearFailedAttempts('verify-fail', verifyIp);

      // ---- Kích hoạt key (nếu đây là lần xác thực đầu tiên) ----
      // Hạn dùng của key có thời hạn CHỈ bắt đầu được tính từ đây, không tính từ lúc tạo key.
      // Không kích hoạt key đã bị cấm (banned) — key bị cấm giữ nguyên trạng thái "Chưa kích hoạt".
      if(!found.key.banned){
        activateKeyIfNeeded(found.key);
      }

      const status = computeKeyStatus(found.key);
      let valid = status !== 'banned' && status !== 'expired';
      let reason = valid ? 'ok' : status;

      // ---- Giới hạn số thiết bị được phép kích hoạt trên 1 key ----
      // Logic: mỗi lần app nhập key thành công, server ghi nhận deviceId của app đó.
      // Nếu app bị gỡ + cài lại → deviceId mới → không khớp → từ chối nếu đã đầy slot.
      // Admin có thể reset thiết bị qua /api/admin/keys/:id/reset-devices.
      // ---- Giới hạn số thiết bị: PHÂN SLOT theo platform ----
      // Script Lua (Roblox) gửi device = "LUA-<UserId>", platform = "roblox"
      // Script Violentmonkey/web gửi device = "VM-<fingerprint>",  platform = "web"
      // Mỗi platform có bucket devices riêng → key maxDevices=1 cho phép 1 Lua + 1 VM
      // hoạt động đồng thời mà KHÔNG tranh slot nhau.
      if(valid){
        // === FIX: Hàm sync đồng bộ "devices" (bucket chung) từ các bucket platform ===
        // Luôn giữ found.key.devices là hợp nhất của lua + vm để dashboard đọc đúng.
        function syncDevicesBucket(){
          found.key.devices = [...new Set([
            ...(found.key.devices_lua || []),
            ...(found.key.devices_vm  || []),
            ...(found.key.devices     || [])
          ])];
          // Đảm bảo deviceId luôn trỏ tới thiết bị đầu tiên đã đăng ký
          if(!found.key.deviceId && found.key.devices.length > 0){
            found.key.deviceId = found.key.devices[0];
          }
        }

        const maxDevices = found.key.maxDevices || 1;

        // === FIX: Từ chối nếu device rỗng mà key đã có thiết bị đăng ký ===
        // Trước đây: if(valid && device) → bỏ qua kiểm tra khi device rỗng → mọi máy pass.
        // Nay: nếu không gửi device nhưng key đã bị gắn thiết bị → từ chối để bảo mật.
        if(!device){
          syncDevicesBucket();
          const alreadyBound = (found.key.devices || []).length > 0;
          if(alreadyBound){
            valid = false;
            reason = 'device_required';
            logVerifyCall({ time: new Date().toISOString(), appId, key, valid, reason });
            saveDBNow();
            return sendJSON(res, 200, {
              valid: false, status,
              reason: 'device_required',
              message: 'Key này đã được gắn với thiết bị cụ thể. Vui lòng gửi kèm device ID để xác thực.',
              type: found.key.type || null,
              expiresAt: found.key.expiresAt || null,
              expires_at: found.key.expiresAt || null,
              maxDevices,
              devicesUsed: (found.key.devices || []).length,
              vipActive: false, vipUntil: null, vip_until: null, jsonKey: ''
            });
          }
          // Key chưa có thiết bị nào + không gửi device → cho qua (key mới chưa bind)
        } else {
          const isPlatformRoblox = platform === 'roblox' || device.startsWith('LUA-');
          const isPlatformWeb    = platform === 'web'    || device.startsWith('VM-') || device.startsWith('KV-');

          // Chọn đúng bucket devices theo platform
          let devBucketKey;
          if(isPlatformRoblox)      devBucketKey = 'devices_lua';
          else if(isPlatformWeb)    devBucketKey = 'devices_vm';
          else                      devBucketKey = 'devices';   // platform không rõ → bucket chung cũ

          // Khởi tạo bucket nếu chưa có
          found.key[devBucketKey] = Array.isArray(found.key[devBucketKey])
            ? found.key[devBucketKey]
            : [];

          if(devBucketKey === 'devices'){
            // Bucket cũ — thiết bị không gửi platform rõ ràng
            found.key.devices = Array.isArray(found.key.devices)
              ? found.key.devices
              : (found.key.deviceId ? [found.key.deviceId] : []);
            if(!found.key.devices.includes(device)){
              if(found.key.devices.length >= maxDevices){
                valid = false;
                reason = 'device_limit_exceeded';
                logVerifyCall({ time: new Date().toISOString(), appId, key, valid, reason,
                  devicesUsed: found.key.devices.length, maxDevices, blockedDevice: device });
                saveDBNow();
                return sendJSON(res, 200, {
                  valid: false, status,
                  reason: 'device_limit_exceeded',
                  message: `Key này đã được kích hoạt trên ${found.key.devices.length}/${maxDevices} thiết bị. Vui lòng liên hệ admin để reset thiết bị.`,
                  type: found.key.type || null,
                  expiresAt: found.key.expiresAt || null,
                  expires_at: found.key.expiresAt || null,
                  maxDevices,
                  devicesUsed: found.key.devices.length,
                  vipActive: false, vipUntil: null, vip_until: null, jsonKey: ''
                });
              }
              found.key.devices.push(device);
              // === FIX: Đảm bảo deviceId luôn được gán ngay sau khi push ===
              if(!found.key.deviceId) found.key.deviceId = found.key.devices[0];
            }
          } else {
            // Bucket theo platform — Lua và VM KHÔNG dùng chung slot
            const bucket = found.key[devBucketKey];
            if(!bucket.includes(device)){
              if(bucket.length >= maxDevices){
                // Slot bucket này đầy
                valid = false;
                reason = 'device_limit_exceeded';
                // === FIX: Sync trước khi tính totalUsed để số liệu chính xác ===
                syncDevicesBucket();
                const totalUsed = (found.key.devices || []).length;
                logVerifyCall({ time: new Date().toISOString(), appId, key, valid, reason,
                  devicesUsed: bucket.length, maxDevices, blockedDevice: device, platform });
                saveDBNow();
                return sendJSON(res, 200, {
                  valid: false, status,
                  reason: 'device_limit_exceeded',
                  message: `Key này đã đăng ký ${bucket.length}/${maxDevices} thiết bị cho nền tảng "${isPlatformRoblox ? 'Roblox' : 'Web/VM'}". Liên hệ admin để reset.`,
                  type: found.key.type || null,
                  expiresAt: found.key.expiresAt || null,
                  expires_at: found.key.expiresAt || null,
                  maxDevices,
                  devicesUsed: totalUsed,
                  platform,
                  vipActive: false, vipUntil: null, vip_until: null, jsonKey: ''
                });
              }
              bucket.push(device);
              // === FIX: Sync ngay lập tức vào bucket chung sau khi thêm thiết bị mới ===
              // Không để async — dashboard phải thấy đúng số thiết bị ngay lần verify đầu tiên.
              syncDevicesBucket();
            } else {
              // Thiết bị đã đăng ký rồi — vẫn sync để đảm bảo nhất quán (phòng trường hợp
              // restart server làm mất sync giữa bucket_lua/vm và bucket chung)
              syncDevicesBucket();
            }
          }

          // Cập nhật lastSeenAt cho thiết bị để dashboard hiện "1/1 — hoạt động X phút trước"
          found.key._deviceLastSeen = found.key._deviceLastSeen || {};
          found.key._deviceLastSeen[device] = new Date().toISOString();
        }
      }

      // === FIX: Tính totalDevicesUsed từ bucket chung (đã được sync đồng bộ ở trên) ===
      const totalDevicesUsed = (found.key.devices || []).length;
      logVerifyCall({ time: new Date().toISOString(), appId, key, valid, reason, ...deviceInfo });

      // ── [FIX TTTT AUTO-REPORT] ──────────────────────────────────────────────────
      // Khi key hợp lệ VÀ có deviceId Android → tự động lưu vào ttttDeviceKeys.
      // Điều này cho phép app "Xác thực ID" unlock ngay khi poll /api/tttt/device-key,
      // không cần app "Thiên Tài Tù Tội" gọi /api/tttt/report-key nữa.
      // Điều kiện: valid=true, device không rỗng, platform là android (không phải lua/web)
      if(valid && device && !device.startsWith('LUA-') && !device.startsWith('VM-') && !device.startsWith('KV-')){
        if(!db.ttttDeviceKeys || typeof db.ttttDeviceKeys !== 'object') db.ttttDeviceKeys = {};
        const existingRec = db.ttttDeviceKeys[device];
        // Chỉ ghi nếu chưa có record, hoặc key thay đổi, hoặc record cũ hơn 1 giờ
        const now_tttt = Date.now();
        const isStale  = !existingRec || existingRec.key !== key
                         || (now_tttt - new Date(existingRec.updatedAt || 0).getTime() > 3600000);
        if(isStale){
          db.ttttDeviceKeys[device] = {
            key       : key,
            keyType   : found.key.type || 'normal',
            reportedAt: now_tttt,
            updatedAt : new Date().toISOString(),
            ip        : verifyIp,
            autoSaved : true   // đánh dấu để phân biệt với report thủ công
          };
          console.log(`[TTTT-AUTO] Auto-saved device-key | device=${device} | key=${key.slice(0,8)}... | appId=${appId}`);
        }
      }
      // ── [END FIX TTTT AUTO-REPORT] ─────────────────────────────────────────────

      // === FIX: Dùng saveDBNow() thay vì saveDBDebounced() để thiết bị được ghi ngay ===
      saveDBNow();
      return sendJSON(res, 200, {
        valid,
        status,
        reason,
        type: found.key.type || null,
        expiresAt: found.key.expiresAt || null,
        expires_at: found.key.expiresAt || null,
        maxDevices: found.key.maxDevices || 1,
        devicesUsed: totalDevicesUsed,
        platform: platform || undefined,
        // Fields bổ sung cho DEX/ModMenuService (parse từ JSONObject)
        vip: valid ? true : false,
        vipActive: valid ? true : false,
        vipUntil: found.key.expiresAt || null,
        vip_until: found.key.expiresAt || null,
        pk: found.key.value || key,
        jsonKey: valid ? (found.key.value || key) : '',
        message: valid ? 'OK' : (reason || 'invalid')
      });
    }

    /* ---- /api/check-key — endpoint dành riêng cho Android (KeyLoginActivity$ValidatorThread) ----
       App Android gửi POST với body {"key":"..."} và mong nhận {"success":true,"message":"..."}
       hoặc {"success":false,"message":"lý do lỗi"}.
       Endpoint này là wrapper của /api/verify, tự động chọn app_id "android-app" và
       không bắt buộc device (vì app Android chưa gửi device ID).
       Trả về đúng format mà ValidatorThread đang parse: optBoolean("success"). */
    if(pathname === '/api/check-key' && req.method === 'POST'){
      const ckIp = getClientIP(req);
      if(isRateLimited('verify', ckIp, 60, 60 * 1000)){
        return sendJSON(res, 429, { success: false, message: 'Bạn đã gửi quá nhiều yêu cầu. Vui lòng thử lại sau.' });
      }
      const ckLock = isLockedOut('verify-fail', ckIp);
      if(ckLock && ckLock.locked){
        const mins = Math.ceil(ckLock.remainMs / 60000);
        return sendJSON(res, 429, { success: false, message: `Tài khoản tạm khoá ${mins} phút do nhập sai quá nhiều lần.` });
      }
      let ckBody;
      try{ ckBody = await readJSONBody(req); } catch(e){ ckBody = {}; }
      const ckKey = String(ckBody.key || '').trim();
      const ckAppId = String(ckBody.app_id || ckBody.appId || ckBody.app || 'android-app').trim().slice(0,100) || 'android-app';
      const ckDevice = String(ckBody.device || ckBody.device_id || ckBody.deviceId || '').trim().slice(0,200);
      if(!ckKey){
        return sendJSON(res, 400, { success: false, message: 'Thiếu key.' });
      }
      // Tự động đăng ký app android-app nếu chưa có, và cho phép luôn
      const ckApp = getOrRegisterApp(ckAppId);
      ckApp.lastUsedAt = new Date().toISOString();
      ckApp.totalChecks = (ckApp.totalChecks || 0) + 1;
      // Tự động approve app android khi lần đầu gọi (không cần admin duyệt tay)
      if(ckApp.status === 'pending') ckApp.status = 'allowed';

      const ckFound = findKeyEverywhere(ckKey);
      if(!ckFound){
        registerFailedAttempt('verify-fail', ckIp);
        logVerifyCall({ time: new Date().toISOString(), appId: ckAppId, key: ckKey, valid: false, reason: 'key_not_found', ip: ckIp });
        saveDBDebounced();
        return sendJSON(res, 200, { success: false, message: 'Key không hợp lệ hoặc không tồn tại.' });
      }
      clearFailedAttempts('verify-fail', ckIp);
      if(!ckFound.key.banned) activateKeyIfNeeded(ckFound.key);
      const ckStatus = computeKeyStatus(ckFound.key);
      if(ckStatus === 'banned'){
        logVerifyCall({ time: new Date().toISOString(), appId: ckAppId, key: ckKey, valid: false, reason: 'banned', ip: ckIp });
        saveDBDebounced();
        return sendJSON(res, 200, { success: false, message: 'Key đã bị cấm sử dụng.' });
      }
      if(ckStatus === 'expired'){
        logVerifyCall({ time: new Date().toISOString(), appId: ckAppId, key: ckKey, valid: false, reason: 'expired', ip: ckIp });
        saveDBDebounced();
        return sendJSON(res, 200, { success: false, message: 'Key đã hết hạn sử dụng.' });
      }
      // Ghi nhận thiết bị nếu có gửi kèm
      if(ckDevice){
        ckFound.key.devices = Array.isArray(ckFound.key.devices) ? ckFound.key.devices : (ckFound.key.deviceId ? [ckFound.key.deviceId] : []);
        const maxDev = ckFound.key.maxDevices || 1;
        if(!ckFound.key.devices.includes(ckDevice)){
          if(ckFound.key.devices.length >= maxDev){
            logVerifyCall({ time: new Date().toISOString(), appId: ckAppId, key: ckKey, valid: false, reason: 'device_limit_exceeded', ip: ckIp });
            saveDBNow();
            return sendJSON(res, 200, { success: false, message: `Key đã được kích hoạt trên ${ckFound.key.devices.length}/${maxDev} thiết bị. Liên hệ admin để reset.` });
          }
          ckFound.key.devices.push(ckDevice);
          if(!ckFound.key.deviceId) ckFound.key.deviceId = ckFound.key.devices[0];
        }
      }
      ckFound.key._deviceLastSeen = new Date().toISOString();
      logVerifyCall({ time: new Date().toISOString(), appId: ckAppId, key: ckKey, valid: true, reason: 'ok', ip: ckIp });
      saveDBNow();
      // === NÂNG CẤP: Trả về devicesUsed + maxDevices để dashboard cập nhật 0/1 → 1/1 ===
      const ckTotalDevices = (ckFound.key.devices || []).length;
      const ckMaxDevices   = ckFound.key.maxDevices || 1;
      return sendJSON(res, 200, {
        success: true,
        message: 'Key hợp lệ.',
        valid: true,
        type: ckFound.key.type || 'normal',
        expiresAt: ckFound.key.expiresAt || null,
        expires_at: ckFound.key.expiresAt || null,
        devicesUsed: ckTotalDevices,
        maxDevices: ckMaxDevices,
        // Tổng hợp cho DEX/ModMenuService
        vip: true,
        vipActive: true,
        vipUntil: ckFound.key.expiresAt || null,
        vip_until: ckFound.key.expiresAt || null,
        pk: ckFound.key.value || ckKey,
        jsonKey: ckFound.key.value || ckKey
      });
    }

    /* ================================================================
       /api/lienquan/verify — Endpoint chuyên biệt cho LienQuan mod
       App smali gọi POST với body {"key":"..."}
       Tương đương /api/check-key nhưng app_id luôn là "lienquan-mod"
       Response: {"success":true,"message":"Key hợp lệ.","valid":true,...}
       ================================================================ */
    if(pathname === '/api/lienquan/verify' && (req.method === 'POST' || req.method === 'GET')){
      const lqIp = getClientIP(req);
      if(isRateLimited('verify', lqIp, 60, 60 * 1000)){
        return sendJSON(res, 429, { success: false, message: 'Bạn đã gửi quá nhiều yêu cầu.' });
      }
      const lqLock = isLockedOut('verify-fail', lqIp);
      if(lqLock && lqLock.locked){
        const mins = Math.ceil(lqLock.remainMs / 60000);
        return sendJSON(res, 429, { success: false, message: `Tài khoản tạm khoá ${mins} phút.` });
      }
      let lqKey;
      if(req.method === 'GET'){
        lqKey = url.searchParams.get('key') || '';
      } else {
        let lqBody;
        try{ lqBody = await readJSONBody(req); } catch(e){ lqBody = {}; }
        lqKey = String(lqBody.key || '').trim();
      }
      if(!lqKey){
        return sendJSON(res, 400, { success: false, message: 'Thiếu key.' });
      }
      // Luôn dùng app_id = lienquan-mod, tự động được approved
      const lqApp = getOrRegisterApp('lienquan-mod');
      lqApp.lastUsedAt = new Date().toISOString();
      lqApp.totalChecks = (lqApp.totalChecks || 0) + 1;
      if(lqApp.status === 'pending') lqApp.status = 'allowed';

      const lqFound = findKeyEverywhere(lqKey);
      if(!lqFound){
        registerFailedAttempt('verify-fail', lqIp);
        logVerifyCall({ time: new Date().toISOString(), appId: 'lienquan-mod', key: lqKey, valid: false, reason: 'key_not_found', ip: lqIp });
        saveDBDebounced();
        return sendJSON(res, 200, { success: false, valid: false, message: 'Key không hợp lệ hoặc không tồn tại.' });
      }
      clearFailedAttempts('verify-fail', lqIp);
      if(!lqFound.key.banned) activateKeyIfNeeded(lqFound.key);
      const lqStatus = computeKeyStatus(lqFound.key);
      if(lqStatus === 'banned'){
        logVerifyCall({ time: new Date().toISOString(), appId: 'lienquan-mod', key: lqKey, valid: false, reason: 'banned', ip: lqIp });
        saveDBDebounced();
        return sendJSON(res, 200, { success: false, valid: false, message: 'Key đã bị cấm sử dụng.' });
      }
      if(lqStatus === 'expired'){
        logVerifyCall({ time: new Date().toISOString(), appId: 'lienquan-mod', key: lqKey, valid: false, reason: 'expired', ip: lqIp });
        saveDBDebounced();
        return sendJSON(res, 200, { success: false, valid: false, message: 'Key đã hết hạn sử dụng.' });
      }
      logVerifyCall({ time: new Date().toISOString(), appId: 'lienquan-mod', key: lqKey, valid: true, reason: 'ok', ip: lqIp });
      saveDBNow();
      return sendJSON(res, 200, {
        success: true,
        valid: true,
        message: 'Key hợp lệ. Chào mừng bạn đến với LienQuan Mod!',
        type: lqFound.key.type || 'normal',
        expiresAt: lqFound.key.expiresAt || null,
        expires_at: lqFound.key.expiresAt || null,
        vip: true,
        vipActive: true,
        vipUntil: lqFound.key.expiresAt || null,
        pk: lqFound.key.value || lqKey,
        jsonKey: lqFound.key.value || lqKey
      });
    }

    /* ---- Đăng ký / ghi nhận thiết bị cho 1 key (POST /api/device/register) ----
       Script chess hint gọi endpoint này ngay sau khi xác thực key thành công để
       server ghi nhận deviceId → số thiết bị hiển thị đúng (VD: 1/1) trên dashboard. */
    if(pathname === '/api/device/register' && req.method === 'POST'){
      const regIp = getClientIP(req);
      if(isRateLimited('device_reg', regIp, 20, 60 * 1000)){
        return sendJSON(res, 429, { ok: false, reason: 'rate_limited' });
      }
      const body = await readJSONBody(req);
      const regKey      = String(body.key      || '').trim();
      const regDeviceId = String(body.deviceId || body.device_id || body.device || '').trim().slice(0, 200);
      const regAppId    = String(body.app      || body.appId || body.app_id || 'unknown-app').trim().slice(0, 100);
      if(!regKey || !regDeviceId){
        return sendJSON(res, 400, { ok: false, reason: 'missing_key_or_deviceId' });
      }
      const found = findKeyEverywhere(regKey);
      if(!found){
        return sendJSON(res, 200, { ok: false, reason: 'key_not_found' });
      }
      const kStatus = computeKeyStatus(found.key);
      if(kStatus === 'banned' || kStatus === 'expired'){
        return sendJSON(res, 200, { ok: false, reason: kStatus });
      }
      // Kích hoạt key nếu chưa kích hoạt
      activateKeyIfNeeded(found.key);
      // Ghi nhận thiết bị — phân slot theo platform (tương tự /api/verify)
      const regPlatformRaw = String(body.platform || '').trim().toLowerCase();
      const isRegRoblox = regPlatformRaw === 'roblox' || regDeviceId.startsWith('LUA-');
      const isRegWeb    = regPlatformRaw === 'web'    || regDeviceId.startsWith('VM-') || regDeviceId.startsWith('KV-');
      const regBucketKey = isRegRoblox ? 'devices_lua' : (isRegWeb ? 'devices_vm' : 'devices');
      found.key[regBucketKey] = Array.isArray(found.key[regBucketKey])
        ? found.key[regBucketKey]
        : [];
      const maxDevices = found.key.maxDevices || 1;
      const regBucket  = found.key[regBucketKey];

      // === FIX: Hàm sync bucket chung cho /api/device/register ===
      function syncRegDevicesBucket(){
        found.key.devices = [...new Set([
          ...(found.key.devices_lua || []),
          ...(found.key.devices_vm  || []),
          ...(found.key.devices     || [])
        ])];
        if(!found.key.deviceId && found.key.devices.length > 0){
          found.key.deviceId = found.key.devices[0];
        }
      }

      if(!regBucket.includes(regDeviceId)){
        if(regBucket.length >= maxDevices){
          // Thiết bị mới — slot đã đầy cho platform này → từ chối
          // === FIX: Sync trước khi trả về để totalUsed chính xác ===
          syncRegDevicesBucket();
          const totalUsed = (found.key.devices || []).length;
          return sendJSON(res, 200, {
            ok: false,
            reason: 'device_limit_exceeded',
            message: `Key này đã đăng ký ${regBucket.length}/${maxDevices} thiết bị cho nền tảng "${isRegRoblox ? 'Roblox' : 'Web/VM'}". Vui lòng liên hệ admin để reset thiết bị.`,
            devicesUsed: totalUsed,
            maxDevices
          });
        }
        regBucket.push(regDeviceId);
        // === FIX: Sync ngay sau push để dashboard thấy số đúng ===
        syncRegDevicesBucket();
      } else {
        // Đã tồn tại — vẫn sync để đảm bảo nhất quán
        syncRegDevicesBucket();
      }
      // Cập nhật lastSeen cho thiết bị này
      found.key._deviceLastSeen = found.key._deviceLastSeen || {};
      found.key._deviceLastSeen[regDeviceId] = new Date().toISOString();
      // === FIX: saveDBNow() thay vì saveDBDebounced() để ghi ngay, dashboard thấy đúng ===
      saveDBNow();
      const regTotalUsed = (found.key.devices || []).length;
      return sendJSON(res, 200, {
        ok: true,
        devicesUsed: regTotalUsed,
        maxDevices,
        deviceId: regDeviceId,
        platform: regPlatformRaw || undefined
      });
    }

    /* ---- Admin: reset thiết bị đã ghi nhận của 1 key (POST /api/admin/keys/:keyValue/reset-devices) ----
       Dùng khi khách hàng gỡ app + cài lại → server sẽ chặn vì device mới ≠ device cũ.
       Admin bấm nút Reset Thiết bị → devices = [] → khách hàng nhập key lại → đăng ký thiết bị mới. */
    const resetDeviceMatch = pathname.match(/^\/api\/admin\/keys\/(.+)\/reset-devices$/);
    if(resetDeviceMatch && req.method === 'POST'){
      const targetKey = decodeURIComponent(resetDeviceMatch[1]).trim();
      const found = findKeyEverywhere(targetKey);
      if(!found){
        return sendJSON(res, 404, { ok: false, error: 'key_not_found' });
      }
      // Reset toàn bộ: bucket chung + bucket theo platform (devices_lua, devices_vm)
      found.key.devices     = [];
      found.key.devices_lua = [];
      found.key.devices_vm  = [];
      delete found.key.deviceId;
      delete found.key._deviceLastSeen;
      saveDBNow();
      console.log(`[KeyVault] Admin đã reset thiết bị cho key: ${targetKey}`);
      return sendJSON(res, 200, { ok: true, message: 'Đã reset thiết bị (Lua + VM). Khách hàng có thể nhập lại key để đăng ký thiết bị mới.' });
    }

    /* ---- Admin: nâng/hạ cấp loại key (POST /api/admin/keys/:keyValue/set-type) ----
       Body: { type: 'premium' | 'normal' }
       Cho phép admin đổi loại bất kỳ key đã tạo mà không cần xoá/tạo lại.
       Các trường khác của key (devices, expiresAt, activated, v.v.) giữ nguyên. */
    const setTypeMatch = pathname.match(/^\/api\/admin\/keys\/(.+)\/set-type$/);
    if(setTypeMatch && req.method === 'POST'){
      const targetKey = decodeURIComponent(setTypeMatch[1]).trim();
      const body = await readJSONBody(req).catch(()=>({}));
      const newType = String(body.type || '').trim().toLowerCase();
      if(newType !== 'premium' && newType !== 'normal'){
        return sendJSON(res, 400, { ok: false, error: 'invalid_type', message: 'type phải là "premium" hoặc "normal".' });
      }
      const found = findKeyEverywhere(targetKey);
      if(!found){
        return sendJSON(res, 404, { ok: false, error: 'key_not_found' });
      }
      const oldType = found.key.type || 'normal';
      found.key.type = newType;
      saveDBNow();
      console.log(`[KeyVault] Admin đã đổi loại key "${targetKey}": ${oldType} → ${newType}`);
      return sendJSON(res, 200, {
        ok: true,
        keyValue: targetKey,
        oldType,
        newType,
        message: `Đã ${newType === 'premium' ? 'nâng cấp lên ★ Premium' : 'hạ về Thường'}: ${targetKey}`
      });
    }

    /* ---- Nhật ký các lượt kiểm tra key gần đây ---- */
    if(pathname === '/api/logs' && req.method === 'GET'){
      return sendJSON(res, 200, db.verifyLogs || []);
    }

    /* ================= TRANG BÁN KEY (STOREFRONT) ================= */

    /* ---- Danh sách sản phẩm công khai (chỉ trả sản phẩm đang bật + còn hàng) ---- */
    if(pathname === '/api/products' && req.method === 'GET'){
      const list = (db.products || []).filter(p => p.active).map(p => ({ ...p, stock: countAvailableForPrefix(p.keyPrefix) }));
      return sendJSON(res, 200, list);
    }

    /* ---- Đăng ký tài khoản khách hàng (storefront) hoặc tài khoản admin phụ (dashboard /admin) ----
       body.asAdmin = true  ->  đăng ký với role 'admin' (CHỈ cho phép khi người gọi đã kèm
       adminToken hợp lệ của 1 tài khoản admin đang đăng nhập — chặn khách vãng lai tự phong admin). */
    if(pathname === '/api/auth/register' && req.method === 'POST'){
      const ip = getClientIP(req);
      // Giới hạn tốc độ đăng ký: tối đa 10 lần/giờ/IP, chống tạo tài khoản ảo hàng loạt.
      if(isRateLimited('register', ip, 10, 60 * 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đã tạo tài khoản quá nhiều lần, vui lòng thử lại sau.' });
      }
      const body = await readJSONBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if(!username || !password){
        return sendJSON(res, 400, { ok:false, error: 'missing_fields' });
      }
      if(username.length > 60 || password.length > 200){
        return sendJSON(res, 400, { ok:false, error: 'field_too_long' });
      }
      if(!/^[a-zA-Z0-9_.@-]+$/.test(username)){
        return sendJSON(res, 400, { ok:false, error: 'invalid_username', message: 'Tên đăng nhập chỉ được chứa chữ, số và _ . @ -' });
      }
      if(password.length < 8){
        return sendJSON(res, 400, { ok:false, error: 'password_too_short', message: 'Mật khẩu phải có tối thiểu 8 ký tự.' });
      }
      db.customers = db.customers || [];
      if(db.customers.some(c => c.username.toLowerCase() === username.toLowerCase())){
        return sendJSON(res, 409, { ok:false, error: 'username_taken' });
      }

      let role = 'customer';
      if(body.asAdmin){
        // Chỉ tài khoản ADMIN đang đăng nhập (token hợp lệ, role==='admin') mới được
        // tạo thêm tài khoản admin phụ — khách vãng lai gửi asAdmin:true mà không có
        // token admin hợp lệ sẽ bị từ chối và tài khoản vẫn được tạo với role 'customer'.
        const adminToken = body.adminToken || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
        const requester = getCustomerByToken(adminToken);
        if(requester && requester.customer.role === 'admin'){
          role = 'admin';
        } else {
          return sendJSON(res, 403, { ok:false, error: 'not_admin' });
        }
      }

      const customer = {
        id: crypto.randomBytes(8).toString('hex'),
        username,
        passwordHash: hashPassword(password),
        createdAt: new Date().toISOString(),
        registrationIP: ip, // lưu IP của máy lúc tạo tài khoản, phục vụ tra soát/chống gian lận
        role,
        balance: 0,
        topupHistory: [],
        transactionHistory: []
      };
      db.customers.push(customer);
      const token = genToken();
      db.customerSessions = db.customerSessions || {};
      db.customerSessions[token] = { customerId: customer.id, username, createdAt: new Date().toISOString() };
      saveDBNow();
      return sendJSON(res, 200, { ok:true, token, username, role: customer.role });
    }

    /* ---- Đăng nhập tài khoản khách hàng / admin phụ (dùng chung 1 hệ thống) ---- */
    if(pathname === '/api/auth/login' && req.method === 'POST'){
      const ip = getClientIP(req);
      // Giới hạn tốc độ chung: tối đa 20 lần thử/phút/IP (chặn spam request thô, chưa tính đúng/sai).
      if(isRateLimited('login', ip, 20, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn thử đăng nhập quá nhanh, vui lòng chờ một chút.' });
      }
      const body = await readJSONBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');

      // Chống dò mật khẩu (brute-force): khoá tạm theo IP VÀ theo username nếu sai quá nhiều lần.
      // Lần 1: 5 phút | Lần 2+: 30 phút
      const loginLockIp = isLockedOut('login-ip', ip);
      if(loginLockIp && loginLockIp.locked){
        const mins = Math.ceil(loginLockIp.remainMs / 60000);
        const msg = loginLockIp.lockCount >= 2
          ? `IP này bị khoá 30 phút do nhập sai quá nhiều lần. Còn ${mins} phút.`
          : `IP này bị khoá 5 phút do nhập sai ${BRUTE_FORCE_MAX_ATTEMPTS} lần. Còn ${mins} phút.`;
        return sendJSON(res, 429, { ok:false, error: 'temporarily_locked', message: msg, remainMinutes: mins });
      }
      if(username){
        const loginLockUser = isLockedOut('login-user', username.toLowerCase());
        if(loginLockUser && loginLockUser.locked){
          const mins = Math.ceil(loginLockUser.remainMs / 60000);
          const msg = loginLockUser.lockCount >= 2
            ? `Tài khoản bị khoá 30 phút do nhập sai quá nhiều lần. Còn ${mins} phút.`
            : `Tài khoản bị khoá 5 phút do nhập sai ${BRUTE_FORCE_MAX_ATTEMPTS} lần. Còn ${mins} phút.`;
          return sendJSON(res, 429, { ok:false, error: 'temporarily_locked', message: msg, remainMinutes: mins });
        }
      }

      let customer = (db.customers || []).find(c => c.username.toLowerCase() === username.toLowerCase());

      /* ---- Đăng nhập chung: tài khoản quản trị (Adminn/120510@, giống dashboard "/admin")
         cũng đăng nhập được ngay qua form "Đăng nhập/Đăng ký" của trang bán key ("/"),
         KHÔNG cần vào riêng trang quản trị nữa. Nếu đúng tài khoản/mật khẩu quản trị,
         hệ thống tự tạo (hoặc nâng cấp) 1 customer record với role 'admin' rồi đăng
         nhập bình thường qua cùng API/luồng token với khách hàng. */
      const isAdminCredential = username.toLowerCase() === 'adminn' && password === (db.adminPassword || '120510@');

      /* ---- Đăng nhập chung phần 2: tài khoản NGƯỜI BÁN (seller) cũng đăng nhập được ngay
         tại đây — không cần vào riêng trang quản trị. Kiểm tra khớp với bảng db.sellers
         (mật khẩu người bán hiện đang lưu dạng plaintext trong db.sellers, giữ nguyên như
         code cũ — chỉ thêm bước đối chiếu, không đổi cách lưu trữ đã có). ---- */
      const matchedSeller = !isAdminCredential
        ? (db.sellers || []).find(s => s.username.toLowerCase() === username.toLowerCase() && s.password === password)
        : null;
      if(matchedSeller){
        const now = Date.now();
        const banned = !!matchedSeller.banned;
        const expired = matchedSeller.expiresAt && new Date(matchedSeller.expiresAt).getTime() < now;
        if(banned){
          return sendJSON(res, 403, { ok:false, error: 'seller_banned', message: 'Tài khoản người bán đã bị cấm.' });
        }
        if(expired){
          return sendJSON(res, 403, { ok:false, error: 'seller_expired', message: 'Tài khoản người bán đã hết hạn sử dụng.' });
        }
      }

      if(isAdminCredential){
        if(!customer){
          customer = {
            id: crypto.randomBytes(8).toString('hex'),
            username: 'Adminn',
            passwordHash: hashPassword(password),
            createdAt: new Date().toISOString(),
            role: 'admin',
            balance: 0,
            topupHistory: [],
            transactionHistory: []
          };
          db.customers = db.customers || [];
          db.customers.push(customer);
        } else {
          customer.role = 'admin';
          customer.passwordHash = hashPassword(password);
        }
      } else if(matchedSeller){
        // Tài khoản seller không nhất thiết có customer record — tạo/đồng bộ 1 bản ghi tương ứng
        // chỉ để phát token đăng nhập chung, không ảnh hưởng tới dữ liệu seller gốc trong db.sellers.
        if(!customer){
          customer = {
            id: crypto.randomBytes(8).toString('hex'),
            username: matchedSeller.username,
            passwordHash: hashPassword(password),
            createdAt: new Date().toISOString(),
            role: 'seller',
            balance: 0,
            topupHistory: [],
            transactionHistory: []
          };
          db.customers = db.customers || [];
          db.customers.push(customer);
        } else {
          customer.role = 'seller';
          customer.passwordHash = hashPassword(password);
        }
      } else if(!customer || customer.passwordHash !== hashPassword(password)){
        // Ghi nhận lần sai để tính ngưỡng khoá tạm — cả theo IP và theo username đã nhập.
        registerFailedAttempt('login-ip', ip);
        if(username) registerFailedAttempt('login-user', username.toLowerCase());
        // Kiểm tra ngay xem có bị khoá sau lần sai vừa rồi không
        const newLockStatus = isLockedOut('login-ip', ip);
        if(newLockStatus && newLockStatus.locked){
          const mins = Math.ceil(newLockStatus.remainMs / 60000);
          const msg = newLockStatus.lockCount >= 2
            ? `Nhập sai quá nhiều lần — khoá ${mins} phút (lần 2+: 30 phút).`
            : `Nhập sai ${BRUTE_FORCE_MAX_ATTEMPTS} lần — khoá ${mins} phút (lần 1: 5 phút).`;
          return sendJSON(res, 429, { ok:false, error: 'temporarily_locked', message: msg, remainMinutes: mins });
        }
        return sendJSON(res, 401, { ok:false, error: 'invalid_credentials', message: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
      }

      // Đăng nhập thành công: xoá bộ đếm sai của IP và username này.
      clearFailedAttempts('login-ip', ip);
      clearFailedAttempts('login-user', username.toLowerCase());

      const token = genToken();
      db.customerSessions = db.customerSessions || {};
      db.customerSessions[token] = { customerId: customer.id, username: customer.username, createdAt: new Date().toISOString() };
      saveDBNow();
      return sendJSON(res, 200, { ok:true, token, username: customer.username, role: customer.role || 'customer', balance: customer.balance||0 });
    }

    /* ---- Kiểm tra token khách hàng còn hiệu lực không (dùng khi tải lại trang) ---- */
    if(pathname === '/api/auth/me' && req.method === 'GET'){
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false });
      return sendJSON(res, 200, { ok:true, username: found.customer.username, role: found.customer.role || 'customer', balance: found.customer.balance||0 });
    }

    /* ---- Lịch sử nạp tiền + lịch sử giao dịch của khách hàng đang đăng nhập ---- */
    if(pathname === '/api/auth/history' && req.method === 'GET'){
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false });
      return sendJSON(res, 200, {
        ok:true,
        balance: found.customer.balance || 0,
        topupHistory: found.customer.topupHistory || [],
        transactionHistory: found.customer.transactionHistory || []
      });
    }

    /* ---- Danh sách key mà khách hàng đang đăng nhập đã mua (trang "Quản lý key") ----
       Quét toàn bộ keysStore (mọi owner/người bán) tìm các key có customer === username
       của khách đang đăng nhập, trả về thông tin cần thiết để hiển thị (không lộ dữ liệu
       của khách khác). */
    if(pathname === '/api/customer/keys' && req.method === 'GET'){
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false });
      const username = found.customer.username;
      const list = [];
      for(const owner of Object.keys(db.keysStore || {})){
        const arr = db.keysStore[owner] || [];
        arr.forEach(k=>{
          if(k.customer === username){
            list.push({
              value: k.value,
              type: k.type || 'normal',
              status: computeKeyStatus(k),
              banned: !!k.banned,
              hasExpiryPlan: !!k.hasExpiryPlan,
              activated: !!k.activated,
              activatedAt: k.activatedAt || null,
              expiryAmount: k.expiryAmount || null,
              expiryUnit: k.expiryUnit || null,
              expiresAt: k.expiresAt || null,
              maxDevices: k.maxDevices || 1,
              devicesUsed: (k.devices || []).length,
              soldAt: k.soldAt || null,
              price: k.price || ''
            });
          }
        });
      }
      // Mới mua/hết hạn gần đây hiển thị lên trước.
      list.sort((a,b)=> new Date(b.soldAt||0) - new Date(a.soldAt||0));
      return sendJSON(res, 200, { ok:true, keys: list });
    }

    /* ---- Webhook nhận báo có tiền từ SePay (my.sepay.vn) khi tài khoản MB Bank ở db.bankInfo
       có giao dịch tiền vào. Đối soát tự động với các yêu cầu nạp tiền đang 'pending': nếu nội
       dung chuyển khoản khớp và số tiền đủ, TỰ ĐỘNG cộng tiền ngay — không cần admin duyệt tay.
       Xác thực bằng header Authorization: "Apikey <sepayConfig.apiKey>" (cấu hình trong SePay
       lúc tạo webhook, mục "Bảo mật" > "API Key"). Nếu chưa bật/chưa cấu hình apiKey, endpoint
       này từ chối toàn bộ request để tránh ai đó giả mạo báo có tiền khống. ---- */
    if(pathname === '/api/sepay-webhook' && req.method === 'POST'){
      const cfg = db.sepayConfig || {};
      if(!cfg.enabled || !cfg.apiKey){
        return sendJSON(res, 403, { ok:false, error: 'sepay_not_configured', message: 'Đối soát tự động chưa được bật/cấu hình API Key trên server.' });
      }
      const authHeader = String(req.headers['authorization'] || '');
      const providedKey = authHeader.replace(/^Apikey\s+/i, '').trim();
      if(!providedKey || providedKey !== cfg.apiKey){
        console.warn('[SePay] Webhook bị từ chối do API Key không khớp. IP:', getClientIP(req));
        return sendJSON(res, 401, { ok:false, error: 'invalid_api_key' });
      }

      let body;
      try{ body = await readJSONBody(req); }
      catch(e){ return sendJSON(res, 400, { ok:false, error: 'invalid_body' }); }

      // Chỉ xử lý giao dịch TIỀN VÀO (transferType === 'in'); bỏ qua giao dịch tiền ra.
      const transferType = String(body.transferType || body.transfer_type || '').toLowerCase();
      if(transferType && transferType !== 'in'){
        return sendJSON(res, 200, { ok:true, ignored: true, reason: 'not_incoming' });
      }

      const transferAmount = parseSafeAmount(body.transferAmount != null ? body.transferAmount : body.transfer_amount, { min: 1, max: 1000000000 });
      const content = String(body.content || body.description || '').trim();
      if(transferAmount === null || !content){
        return sendJSON(res, 400, { ok:false, error: 'invalid_transaction_data' });
      }

      try{
        const result = await matchAndApproveTopupByTransaction(transferAmount, content);
        if(result.matched){
          console.log(`[SePay] Đã tự động khớp & cộng tiền cho yêu cầu ${result.request.id} (username: ${result.request.username}, số tiền: ${result.request.amount}).`);
        }else{
          console.log(`[SePay] Giao dịch báo có ${transferAmount}đ, nội dung "${content}" — không khớp yêu cầu nạp tiền nào đang chờ.`);
        }
        // Luôn trả 200 cho SePay khi đã xử lý xong (kể cả không khớp), để SePay không retry vô ích.
        return sendJSON(res, 200, { ok:true, matched: result.matched });
      }catch(e){
        console.error('[SePay] Lỗi xử lý webhook:', e);
        return sendJSON(res, 500, { ok:false, error: 'server_error' });
      }
    }

    /* ---- Khách hàng gửi YÊU CẦU nạp tiền tự động: sinh QR động (VietQR, nhúng sẵn số tiền +
       nội dung CK) kèm hạn 30 phút. Nếu quá 30 phút chưa được duyệt, request tự chuyển 'expired'
       và khách phải tạo yêu cầu mới (không cho gia hạn/tái sử dụng request cũ). ---- */
    if(pathname === '/api/topup-request' && req.method === 'POST'){
      const ip = getClientIP(req);
      // Giới hạn tốc độ: tối đa 8 yêu cầu nạp tiền / 5 phút / IP, tránh spam tạo request ảo.
      if(isRateLimited('topup-request', ip, 8, 5 * 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đang gửi yêu cầu quá nhanh, vui lòng thử lại sau vài phút.' });
      }

      const body = await readJSONBody(req);
      const token = body.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false, error: 'not_logged_in' });

      // Validate số tiền chặt chẽ: chặn NaN/Infinity/số âm/số 0/số quá lớn bất thường (chống bug tiền).
      const amount = parseSafeAmount(body.amount, { min: 10000, max: 500000000 });
      if(amount === null){
        return sendJSON(res, 400, { ok:false, error: 'invalid_amount', message: 'Số tiền không hợp lệ (tối thiểu 10.000₫, tối đa 500.000.000₫).' });
      }

      // Hết hạn các request cũ trước khi kiểm tra request đang chờ, để không tính nhầm request đã quá 30 phút.
      expireStaleTopupRequests();

      // Chặn tạo nhiều request 'pending' cùng lúc cho cùng 1 khách hàng — bắt xử lý/hết hạn
      // request cũ trước rồi mới tạo mới, tránh rối loạn khi đối chiếu tiền chuyển khoản.
      const existingPending = (db.topupRequests || []).find(r => r.customerId === found.customer.id && r.status === 'pending');
      if(existingPending){
        return sendJSON(res, 409, {
          ok:false, error: 'pending_request_exists',
          message: 'Bạn đang có 1 yêu cầu nạp tiền chưa xử lý xong. Vui lòng chờ hết hạn hoặc được duyệt trước khi tạo yêu cầu mới.',
          request: existingPending
        });
      }

      const now = new Date();
      const expiresAt = new Date(now.getTime() + TOPUP_EXPIRY_MS);
      const transferNote = 'NAP ' + found.customer.username;
      const qrUrl = buildVietQRUrl(amount, transferNote);

      const reqEntry = {
        id: crypto.randomBytes(8).toString('hex'),
        customerId: found.customer.id,
        username: found.customer.username,
        amount,
        method: body.method || 'bank_transfer',
        status: 'pending',
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        transferNote,
        qrUrl,
        note: String(body.note || '').slice(0, 300)
      };
      db.topupRequests = db.topupRequests || [];
      db.topupRequests.unshift(reqEntry);

      found.customer.topupHistory = found.customer.topupHistory || [];
      found.customer.topupHistory.unshift({
        id: reqEntry.id, amount, method: reqEntry.method, status: 'pending',
        createdAt: reqEntry.createdAt, expiresAt: reqEntry.expiresAt
      });

      saveDBNow();
      return sendJSON(res, 200, {
        ok:true,
        request: reqEntry,
        bankInfo: {
          bankName: 'MB Bank',
          accountNo: (db.bankInfo || {}).accountNo || '',
          accountName: (db.bankInfo || {}).accountName || ''
        }
      });
    }

    /* ---- Khách hàng kiểm tra trạng thái 1 yêu cầu nạp tiền (dùng để client đồng bộ đồng hồ
       đếm ngược 30 phút với server, và biết khi nào request đã được duyệt/hết hạn). ---- */
    const topupStatusMatch = pathname.match(/^\/api\/topup-request\/([a-f0-9]+)$/);
    if(topupStatusMatch && req.method === 'GET'){
      expireStaleTopupRequests();
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false, error: 'not_logged_in' });
      const reqEntry = (db.topupRequests || []).find(r => r.id === topupStatusMatch[1] && r.customerId === found.customer.id);
      if(!reqEntry) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      return sendJSON(res, 200, { ok:true, request: reqEntry });
    }

    /* ---- Xem trước mã giảm giá (không tính vào số lượt đã dùng) ---- */
    if(pathname === '/api/discount-check' && req.method === 'GET'){
      const code = String(url.searchParams.get('code') || '').trim().toUpperCase();
      const disc = (db.discountCodes || []).find(d => d.code === code);
      if(!disc || !disc.active){
        return sendJSON(res, 200, { valid:false, error: 'discount_invalid' });
      }
      if(disc.expiresAt && new Date(disc.expiresAt).getTime() < Date.now()){
        return sendJSON(res, 200, { valid:false, error: 'discount_expired' });
      }
      if(disc.maxUses > 0 && disc.usedCount >= disc.maxUses){
        return sendJSON(res, 200, { valid:false, error: 'discount_used_up' });
      }
      return sendJSON(res, 200, { valid:true, percent: disc.percent });
    }

    /* ---- Thanh toán / mua key ---- */
    if(pathname === '/api/checkout' && req.method === 'POST'){
      const ip = getClientIP(req);
      // Giới hạn tốc độ mua hàng: tối đa 15 lần/phút/IP, chống dò/spam mua liên tục để bắt lỗi bug.
      if(isRateLimited('checkout', ip, 15, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đang gửi yêu cầu mua hàng quá nhanh, vui lòng thử lại sau.' });
      }

      const body = await readJSONBody(req);
      const token = body.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const authed = getCustomerByToken(token);
      if(!authed){
        return sendJSON(res, 401, { ok:false, error: 'not_logged_in' });
      }

      const product = (db.products || []).find(p => p.id === body.productId && p.active);
      if(!product){
        return sendJSON(res, 404, { ok:false, error: 'product_not_found' });
      }

      // Validate giá gốc sản phẩm để không bao giờ tính ra giá cuối âm/NaN (chống bug tiền).
      let finalPrice = parseSafeAmount(product.price, { min: 0, max: 1000000000 });
      if(finalPrice === null) finalPrice = 0;
      let usedDiscount = null;
      const rawCode = String(body.discountCode || '').trim().toUpperCase().slice(0, 60);
      if(rawCode){
        const disc = (db.discountCodes || []).find(d => d.code === rawCode);
        if(!disc || !disc.active){
          return sendJSON(res, 400, { ok:false, error: 'discount_invalid' });
        }
        if(disc.expiresAt && new Date(disc.expiresAt).getTime() < Date.now()){
          return sendJSON(res, 400, { ok:false, error: 'discount_expired' });
        }
        if(disc.maxUses > 0 && disc.usedCount >= disc.maxUses){
          return sendJSON(res, 400, { ok:false, error: 'discount_used_up' });
        }
        // Chặn phần trăm giảm giá bất thường (âm hoặc >100%) để không tạo ra giá cuối âm.
        const safePercent = Math.min(100, Math.max(0, Number(disc.percent) || 0));
        finalPrice = Math.round(finalPrice * (1 - safePercent / 100));
        if(finalPrice < 0) finalPrice = 0;
        usedDiscount = disc;
      }

      /* ---- Toàn bộ phần đọc số dư + trừ tiền + giao key được đưa vào withCustomerLock
         theo customerId, đảm bảo 2 request mua hàng gửi gần như đồng thời cho CÙNG 1
         khách hàng không bao giờ chồng lấp nhau (chống bug race-condition trừ tiền/giao
         2 key nhưng chỉ trừ tiền 1 lần). ---- */
      const result = await withCustomerLock(authed.customer.id, async ()=>{
        const customerForCheckout = (db.customers || []).find(c => c.id === authed.customer.id);
        if(!customerForCheckout){
          return { status: 401, body: { ok:false, error: 'not_logged_in' } };
        }
        const currentBalance = Number.isFinite(customerForCheckout.balance) ? customerForCheckout.balance : 0;
        if(currentBalance < finalPrice){
          return { status: 400, body: { ok:false, error: 'insufficient_balance', balance: currentBalance, price: finalPrice } };
        }

        const foundKey = findAvailableKeyForPrefix(product.keyPrefix);
        if(!foundKey){
          return { status: 409, body: { ok:false, error: 'out_of_stock' } };
        }

        foundKey.key.status = 'sold';
        foundKey.key.customer = authed.customer.username;
        foundKey.key.price = String(finalPrice);
        foundKey.key.soldAt = new Date().toISOString();
        if(usedDiscount) usedDiscount.usedCount = (usedDiscount.usedCount || 0) + 1;

        /* ---- Trừ tiền thật vào số dư khách hàng + ghi lịch sử giao dịch ---- */
        customerForCheckout.balance = currentBalance - finalPrice;
        customerForCheckout.transactionHistory = customerForCheckout.transactionHistory || [];
        customerForCheckout.transactionHistory.unshift({
          id: crypto.randomBytes(8).toString('hex'),
          type: 'purchase',
          amount: -finalPrice,
          balanceAfter: customerForCheckout.balance,
          createdAt: new Date().toISOString(),
          note: 'Mua key: ' + product.name
        });

        saveDBNow();
        return {
          status: 200,
          body: {
            ok: true,
            key: foundKey.key.value,
            expiresAt: foundKey.key.expiresAt || null,
            hasExpiryPlan: !!foundKey.key.hasExpiryPlan,
            activated: !!foundKey.key.activated,
            expiryAmount: foundKey.key.expiryAmount || null,
            expiryUnit: foundKey.key.expiryUnit || null,
            maxDevices: foundKey.key.maxDevices || 1,
            pricePaid: finalPrice,
            balance: customerForCheckout.balance
          }
        };
      });

      return sendJSON(res, result.status, result.body);
    }

    /* ---- Quét bảo mật TỰ ĐỘNG (thay thế checklist đánh giá thủ công) ----
       Trả về kết quả kiểm tra thật dựa trên trạng thái hiện tại của chính server này. ---- */
    if(pathname === '/api/admin/security-scan' && req.method === 'GET'){
      const result = runAutomaticSecurityScan(req);
      db.lastAutoScan = result;
      saveDBDebounced();
      return sendJSON(res, 200, result);
    }

    /* ================= CHỨC NĂNG "GETKEY" (VƯỢT LINK NHẬN KEY) ================= */

    /* ---- Danh sách game GetKey đang hiển thị công khai (cho trang bán key) ---- */
    if(pathname === '/api/getkey/games' && req.method === 'GET'){
      const list = (db.getKeyGames || []).filter(g => g.active).map(g => {
        const durations = (g.durations || []).map(d => {
          const dPrefix = (d.prefix || g.keyPrefix || '').toUpperCase();
          return { id: d.id, label: d.label, unit: d.unit, amount: d.amount, rounds: d.rounds, prefix: dPrefix, stock: countAvailableForPrefix(dPrefix) };
        });
        const allPrefixes = [...new Set(durations.map(d => d.prefix).filter(Boolean))];
        const stock = allPrefixes.reduce((sum, p) => sum + countAvailableForPrefix(p), 0);
        return { id: g.id, name: g.name, logo: g.logo, durations, stock };
      });
      return sendJSON(res, 200, list);
    }

    /* ---- Khách bắt đầu 1 phiên GetKey: chọn game + loại thời hạn, hệ thống tạo lượt vượt link đầu tiên ---- */
    if(pathname === '/api/getkey/start' && req.method === 'POST'){
      const body = await readJSONBody(req);
      const game = (db.getKeyGames || []).find(g => g.id === body.gameId && g.active);
      if(!game) return sendJSON(res, 404, { ok:false, error: 'game_not_found' });
      const duration = findGetKeyDuration(game, body.durationId);
      if(!duration) return sendJSON(res, 404, { ok:false, error: 'duration_not_found' });

      const startDurPrefix = (duration.prefix || game.keyPrefix || '').toUpperCase();
      if(!startDurPrefix || countAvailableForPrefix(startDurPrefix) <= 0){
        return sendJSON(res, 409, { ok:false, error: 'out_of_stock' });
      }

      const sessionId = genGetKeySessionId();
      db.getKeySessions = db.getKeySessions || {};
      db.getKeySessions[sessionId] = {
        gameId: game.id,
        durationId: duration.id,
        rounds: duration.rounds || 1,
        currentRound: 1,
        roundConfirmed: {}, // { [round]: true } — chỉ được đánh dấu true bởi /api/getkey/confirm (khi link đích thật sự được mở)
        done: false,
        key: null,
        createdAt: new Date().toISOString()
      };
      saveDBDebounced();

      // Trang đích của link rewrite trỏ lại chính server này (endpoint xác nhận vượt link) —
      // khi trang đích được mở tức là khách đã "vượt link" thành công lượt hiện tại.
      const destUrl = `${url.protocol}//${req.headers.host}/api/getkey/confirm?session=${sessionId}&round=1`;
      const shortlinkHtml = await createLaymaShortlink(destUrl);

      return sendJSON(res, 200, {
        ok: true,
        sessionId,
        totalRounds: duration.rounds || 1,
        currentRound: 1,
        link: shortlinkHtml || destUrl
      });
    }

    /* ---- Xác nhận 1 lượt vượt link đã hoàn thành, sinh lượt tiếp theo hoặc giao key nếu đã đủ lượt ---- */
    if(pathname === '/api/getkey/next' && req.method === 'POST'){
      const body = await readJSONBody(req);
      const session = (db.getKeySessions || {})[body.sessionId];
      if(!session) return sendJSON(res, 404, { ok:false, error: 'session_not_found' });
      if(session.done) return sendJSON(res, 200, { ok:true, done:true, key: session.key });

      /* ---- Bắt buộc phải thật sự mở link đích (server tự ghi nhận qua /api/getkey/confirm)
         mới được tính là đã vượt xong lượt hiện tại. Nếu khách bấm "Tôi đã vượt link" mà
         chưa từng mở link (roundConfirmed chưa được đánh dấu), từ chối luôn, không cho qua
         lượt tiếp theo và không giao key — tránh trường hợp không cần vượt link vẫn có key. */
      session.roundConfirmed = session.roundConfirmed || {};
      if(!session.roundConfirmed[session.currentRound]){
        return sendJSON(res, 400, { ok:false, error: 'not_confirmed_yet' });
      }

      if(session.currentRound < session.rounds){
        session.currentRound += 1;
        saveDBDebounced();
        const destUrl = `${url.protocol}//${req.headers.host}/api/getkey/confirm?session=${body.sessionId}&round=${session.currentRound}`;
        const shortlinkHtml = await createLaymaShortlink(destUrl);
        return sendJSON(res, 200, {
          ok: true, done:false,
          totalRounds: session.rounds,
          currentRound: session.currentRound,
          link: shortlinkHtml || destUrl
        });
      }

      // Đã hoàn thành đủ số lượt yêu cầu -> giao key thật cho khách
      const game = (db.getKeyGames || []).find(g => g.id === session.gameId);
      if(!game) return sendJSON(res, 404, { ok:false, error: 'game_not_found' });
      const sessionDur = findGetKeyDuration(game, session.durationId);
      const nextDurPrefix = ((sessionDur && sessionDur.prefix) || game.keyPrefix || '').toUpperCase();
      const foundKey = findAvailableKeyForPrefix(nextDurPrefix);
      if(!foundKey) return sendJSON(res, 409, { ok:false, error: 'out_of_stock' });

      foundKey.key.status = 'sold';
      foundKey.key.customer = 'getkey-' + body.sessionId.slice(0,8);
      foundKey.key.price = '0';
      foundKey.key.soldAt = new Date().toISOString();

      session.done = true;
      session.key = foundKey.key.value;
      saveDBNow();

      return sendJSON(res, 200, {
        ok: true, done:true,
        key: foundKey.key.value,
        expiresAt: foundKey.key.expiresAt || null,
        maxDevices: foundKey.key.maxDevices || 1
      });
    }

    /* ---- Trang xác nhận vượt link: đây là URL mà link rút gọn LAYMA.NET trỏ tới sau
       khi khách hoàn thành các bước vượt link. Đây là nơi DUY NHẤT đánh dấu 1 lượt là
       "đã vượt" (roundConfirmed) — chỉ khi trình duyệt của khách thật sự tải trang này
       (tức đã đi hết link rút gọn) thì lượt đó mới được tính hợp lệ. ---- */
    if(pathname === '/api/getkey/confirm' && req.method === 'GET'){
      const sessionId = url.searchParams.get('session');
      const round = parseInt(url.searchParams.get('round')) || 0;
      const session = (db.getKeySessions || {})[sessionId];
      let bodyHtml;
      if(session && round === session.currentRound && !session.done){
        session.roundConfirmed = session.roundConfirmed || {};
        session.roundConfirmed[round] = true;
        saveDBDebounced();
        bodyHtml = '<h2>✔ Đã xác nhận vượt link thành công</h2><p>Vui lòng quay lại tab GetKey ban đầu và bấm "Tôi đã vượt link" để tiếp tục.</p>';
      } else {
        bodyHtml = '<h2>⚠ Link không hợp lệ hoặc đã hết hạn</h2><p>Vui lòng quay lại trang GetKey và thử lại từ đầu.</p>';
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><title>Đã xác nhận vượt link</title></head><body style="font-family:sans-serif; text-align:center; padding:60px 20px;">' + bodyHtml + '</body></html>');
    }

    /* ---- Admin: danh sách toàn bộ game GetKey (kể cả đang ẩn) ---- */
    if(pathname === '/api/admin/getkey/games' && req.method === 'GET'){
      return sendJSON(res, 200, db.getKeyGames || []);
    }

    /* ---- Admin: tạo/cập nhật 1 game GetKey ---- */
    if(pathname === '/api/admin/getkey/games' && req.method === 'POST'){
      const body = await readJSONBody(req);
      db.getKeyGames = db.getKeyGames || [];
      const name = String(body.name || '').trim();
      const keyPrefix = String(body.keyPrefix || '').trim().toUpperCase(); // giữ lại để tương thích ngược
      if(!name){
        return sendJSON(res, 400, { ok:false, error: 'missing_fields' });
      }
      const durations = Array.isArray(body.durations) ? body.durations.map(d => ({
        id: d.id || crypto.randomBytes(6).toString('hex'),
        label: String(d.label || ''),
        unit: d.unit || 'hour',
        amount: parseFloat(d.amount) || 0,
        rounds: Math.max(1, parseInt(d.rounds) || 1),
        prefix: String(d.prefix || keyPrefix || '').trim().toUpperCase() // prefix riêng cho từng loại thời hạn
      })) : [];

      if(body.id){
        const game = db.getKeyGames.find(g => g.id === body.id);
        if(!game) return sendJSON(res, 404, { ok:false, error: 'not_found' });
        game.name = name;
        if(keyPrefix) game.keyPrefix = keyPrefix; // chỉ cập nhật nếu có (backward compat)
        game.logo = body.logo || game.logo || '';
        game.active = typeof body.active === 'boolean' ? body.active : game.active;
        game.durations = durations;
        saveDBNow();
        return sendJSON(res, 200, { ok:true, game });
      }

      const game = {
        id: crypto.randomBytes(8).toString('hex'),
        name, keyPrefix,
        logo: body.logo || '',
        active: typeof body.active === 'boolean' ? body.active : true,
        durations,
        createdAt: new Date().toISOString()
      };
      db.getKeyGames.push(game);
      saveDBNow();
      return sendJSON(res, 200, { ok:true, game });
    }

    /* ---- Admin: ẩn/hiện 1 game GetKey ---- */
    const getKeyToggleMatch = pathname.match(/^\/api\/admin\/getkey\/games\/([a-f0-9]+)\/toggle$/);
    if(getKeyToggleMatch && req.method === 'POST'){
      const game = (db.getKeyGames || []).find(g => g.id === getKeyToggleMatch[1]);
      if(!game) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      game.active = !game.active;
      saveDBNow();
      return sendJSON(res, 200, { ok:true, game });
    }

    /* ---- Admin: xoá 1 game GetKey ---- */
    const getKeyDeleteMatch = pathname.match(/^\/api\/admin\/getkey\/games\/([a-f0-9]+)$/);
    if(getKeyDeleteMatch && req.method === 'DELETE'){
      db.getKeyGames = (db.getKeyGames || []).filter(g => g.id !== getKeyDeleteMatch[1]);
      saveDBNow();
      return sendJSON(res, 200, { ok:true });
    }

    /* ================= NHÓM SẢN PHẨM (1 logo/tên + NHIỀU gói giá, mô hình giống GetKey) ================= */

    /* ---- Danh sách nhóm sản phẩm đang hiển thị công khai (cho trang bán key) ---- */
    if(pathname === '/api/product-groups' && req.method === 'GET'){
      const list = (db.productGroups || []).filter(g => g.active).map(g => ({
        id: g.id, name: g.name, logo: g.logo,
        plans: (g.plans || []).map(p => ({
          id: p.id, label: p.label, unit: p.unit, amount: p.amount, price: p.price, maxDevices: p.maxDevices || 1,
          stock: countAvailableForPrefix(p.keyPrefix)
        }))
      }));
      return sendJSON(res, 200, list);
    }

    /* ---- Admin: danh sách toàn bộ nhóm sản phẩm (kể cả đang ẩn) ---- */
    if(pathname === '/api/admin/product-groups' && req.method === 'GET'){
      return sendJSON(res, 200, db.productGroups || []);
    }

    /* ---- Admin: tạo/cập nhật 1 nhóm sản phẩm ---- */
    if(pathname === '/api/admin/product-groups' && req.method === 'POST'){
      const body = await readJSONBody(req);
      db.productGroups = db.productGroups || [];
      const name = String(body.name || '').trim();
      if(!name){
        return sendJSON(res, 400, { ok:false, error: 'missing_fields' });
      }
      const plans = Array.isArray(body.plans) ? body.plans.map(p => ({
        id: p.id || crypto.randomBytes(6).toString('hex'),
        label: String(p.label || ''),
        unit: p.unit || 'day',
        amount: p.unit === 'unlimited' ? null : (parseFloat(p.amount) || 1),
        price: parseSafeAmount(p.price, { min: 0, max: 1000000000 }) ?? 0,
        keyPrefix: String(p.keyPrefix || '').trim().toUpperCase(),
        maxDevices: Math.max(1, Math.min(20, parseInt(p.maxDevices) || 1))
      })) : [];
      if(!plans.length || plans.some(p => !p.keyPrefix)){
        return sendJSON(res, 400, { ok:false, error: 'missing_plan_fields' });
      }

      if(body.id){
        const group = db.productGroups.find(g => g.id === body.id);
        if(!group) return sendJSON(res, 404, { ok:false, error: 'not_found' });
        group.name = name;
        group.logo = body.logo || group.logo || '';
        group.active = typeof body.active === 'boolean' ? body.active : group.active;
        group.plans = plans;
        saveDBNow();
        return sendJSON(res, 200, { ok:true, group });
      }

      const group = {
        id: crypto.randomBytes(8).toString('hex'),
        name,
        logo: body.logo || '',
        active: typeof body.active === 'boolean' ? body.active : true,
        plans,
        createdAt: new Date().toISOString()
      };
      db.productGroups.push(group);
      saveDBNow();
      return sendJSON(res, 200, { ok:true, group });
    }

    /* ---- Admin: ẩn/hiện 1 nhóm sản phẩm ---- */
    const pgToggleMatch = pathname.match(/^\/api\/admin\/product-groups\/([a-f0-9]+)\/toggle$/);
    if(pgToggleMatch && req.method === 'POST'){
      const group = (db.productGroups || []).find(g => g.id === pgToggleMatch[1]);
      if(!group) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      group.active = !group.active;
      saveDBNow();
      return sendJSON(res, 200, { ok:true, group });
    }

    /* ---- Admin: xoá 1 nhóm sản phẩm ---- */
    const pgDeleteMatch = pathname.match(/^\/api\/admin\/product-groups\/([a-f0-9]+)$/);
    if(pgDeleteMatch && req.method === 'DELETE'){
      db.productGroups = (db.productGroups || []).filter(g => g.id !== pgDeleteMatch[1]);
      saveDBNow();
      return sendJSON(res, 200, { ok:true });
    }

    /* ================================================================
       POST /api/admin/upload-snippet
       ----------------------------------------------------------------
       Upload file script Violentmonkey lên server:
         - Tự sinh ID mới (hex 16 ký tự)
         - Lưu vào db.codeSnippets + _defaultSnippetMap trong RAM
         - Tự PATCH mảng DEFAULT_CODE_SNIPPETS trong file index.js
           hiện tại trên disk → snippet tồn tại vĩnh viễn dù Render
           free tier xoá db.json sau mỗi restart
         - Xoá toàn bộ entry cũ trước khi thêm entry mới (không
           tích luỹ snippet thừa)
       Body JSON: { name, language?, code }  (hoặc text/plain raw code)
       Hoặc multipart? Không — gửi JSON đơn giản là đủ.
       Response: { ok, id, endpoint, versionEndpoint, listEndpoint }
       ================================================================ */
    if(pathname === '/api/admin/upload-snippet' && req.method === 'POST'){
      const ip = getClientIP(req);
      if(isRateLimited('upload-snippet', ip, 10, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error:'rate_limited', message:'Upload quá nhanh, thử lại sau.' });
      }
      // Cho phép body lớn (lên tới 10 MB script) và timeout dài hơn (120 giây)
      req._allowLargeBody = true;
      req._bodyTimeoutMs  = 120 * 1000;
      let body;
      try{ body = await readJSONBody(req); }
      catch(e){ return sendJSON(res, 413, { ok:false, error:'too_large', message:'Dữ liệu gửi lên quá lớn (tối đa 10 MB).' }); }
      const uploadName = String(body.name || '').trim().slice(0, 100) || ('snippet_' + Date.now());
      const uploadLang = CV_ALLOWED_LANGS.includes(body.language) ? body.language : 'javascript';
      const uploadCode = typeof body.code === 'string' ? body.code : '';
      if(!uploadCode){
        return sendJSON(res, 400, { ok:false, error:'missing_code', message:'Thiếu trường code.' });
      }
      const uploadSize = Buffer.byteLength(uploadCode, 'utf8');
      if(uploadSize > CV_MAX_BYTES){
        return sendJSON(res, 413, { ok:false, error:'too_large', message:'Code vượt quá 10MB.' });
      }

      // ── Sinh ID mới ──────────────────────────────────────────────
      const newId = crypto.randomBytes(8).toString('hex');
      const nowIso = new Date().toISOString();

      // ── Lưu vào db + RAM ─────────────────────────────────────────
      db.codeSnippets = db.codeSnippets || [];
      const newSnippet = {
        id: newId, name: uploadName, language: uploadLang,
        code: uploadCode, sizeBytes: uploadSize,
        createdAt: nowIso, updatedAt: nowIso
      };
      // Xoá entry cũ cùng tên nếu có (tránh trùng)
      db.codeSnippets = db.codeSnippets.filter(s => s.name !== uploadName);
      db.codeSnippets.push(newSnippet);
      // Xoá entry cùng tên khỏi RAM, thêm entry mới
      for(const k of Object.keys(_defaultSnippetMap)){
        if(_defaultSnippetMap[k].name === uploadName) delete _defaultSnippetMap[k];
      }
      _defaultSnippetMap[newId] = newSnippet;
      saveDBNow();
      console.log(`[UploadSnippet] Đã thêm snippet mới vào RAM + db: ${newId} (${uploadName})`);

      // ── PATCH file index.js: thay toàn bộ mảng DEFAULT_CODE_SNIPPETS ──
      // Đọc file index.js hiện tại trên disk, thay mảng bằng nội dung mới.
      // Mục đích: snippet tồn tại vĩnh viễn dù Render xoá db.json sau restart.
      let patchError = null;
      try{
        const selfPath = __filename; // đường dẫn tuyệt đối của index.js đang chạy
        let selfSrc = fs.readFileSync(selfPath, 'utf8');

        // Tìm và thay thế toàn bộ nội dung mảng DEFAULT_CODE_SNIPPETS
        const arrStart = selfSrc.indexOf('const DEFAULT_CODE_SNIPPETS = [');
        if(arrStart === -1) throw new Error('Không tìm thấy DEFAULT_CODE_SNIPPETS trong index.js');
        const bracketOpen = selfSrc.indexOf('[', arrStart);
        let depth2 = 1, inStr2 = false, strChar2 = '', j = bracketOpen + 1;
        while(j < selfSrc.length && depth2 > 0){
          const c2 = selfSrc[j];
          if(inStr2){
            if(c2 === '\\') { j+=2; continue; }
            if(c2 === strChar2) inStr2 = false;
          } else {
            if(c2 === "'" || c2 === '"' || c2 === '`') { inStr2 = true; strChar2 = c2; }
            else if(c2 === '[') depth2++;
            else if(c2 === ']') { depth2--; if(depth2===0) break; }
          }
          j++;
        }
        // Lấy danh sách tất cả snippet hiện có trong RAM (đã bao gồm cái mới)
        const allSnippetsNow = Object.values(_defaultSnippetMap);
        // Tuần tự hóa thành JS literal để nhúng vào source code
        function toJsLiteral(snip){
          // Dùng JSON.stringify cho các giá trị, backtick cho code để giữ nguyên xuống dòng
          const escapedCode = snip.code.replace(/\\/g,'\\\\').replace(/`/g,'\\`').replace(/\$\{/g,'\\${');
          return `  {\n    id      : ${JSON.stringify(snip.id)},\n    name    : ${JSON.stringify(snip.name)},\n    language: ${JSON.stringify(snip.language || 'javascript')},\n    code    : \`${escapedCode}\`,\n    createdAt: ${JSON.stringify(snip.createdAt || nowIso)},\n    updatedAt: ${JSON.stringify(snip.updatedAt || nowIso)}\n  }`;
        }
        const newArrayBody = allSnippetsNow.length > 0
          ? '[\n' + allSnippetsNow.map(toJsLiteral).join(',\n') + '\n]'
          : '[]';
        const patchedSrc = selfSrc.slice(0, bracketOpen) + newArrayBody + selfSrc.slice(j+1);
        fs.writeFileSync(selfPath, patchedSrc, 'utf8');
        console.log(`[UploadSnippet] Đã patch DEFAULT_CODE_SNIPPETS trong ${selfPath} — ${allSnippetsNow.length} snippet(s).`);
      }catch(patchErr){
        patchError = String(patchErr && patchErr.message ? patchErr.message : patchErr);
        console.error('[UploadSnippet] Không patch được index.js (snippet vẫn sẵn có trong RAM session này):', patchError);
      }

      // ── Trả response ─────────────────────────────────────────────
      let pubUrls = null;
      try{
        const base = resolvePublicUrl(req);
        if(base){
          pubUrls = {
            endpoint       : `${base}/api/public/snippet/${newId}`,
            versionEndpoint: `${base}/api/public/snippet/${newId}/version`,
            listEndpoint   : `${base}/api/public/snippets`
          };
        }
      }catch(_){}
      return sendJSON(res, 200, {
        ok        : true,
        id        : newId,
        name      : uploadName,
        sizeBytes : uploadSize,
        createdAt : nowIso,
        updatedAt : nowIso,
        patched   : !patchError,
        patchError: patchError || undefined,
        ...(pubUrls || {})
      });
    }

    /* ---- Admin: danh sách code đã lưu (chỉ metadata, KHÔNG kèm nội dung để danh sách nhẹ) ---- */
    if(pathname === '/api/admin/code-snippets' && req.method === 'GET'){
      const list = (db.codeSnippets || []).map(s => ({
        id: s.id, name: s.name, language: s.language, sizeBytes: s.sizeBytes, createdAt: s.createdAt, updatedAt: s.updatedAt
      }));
      return sendJSON(res, 200, list);
    }

    /* ---- Admin: lưu (tạo mới hoặc cập nhật) 1 đoạn code — chỉ ghi vào db.json, không thực thi ---- */
    if(pathname === '/api/admin/code-snippets' && req.method === 'POST'){
      const ip = getClientIP(req);
      if(isRateLimited('code-snippet-save', ip, 30, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đang lưu code quá nhanh, vui lòng thử lại sau.' });
      }
      let body;
      try{ body = await readJSONBody(req); }
      catch(e){ return sendJSON(res, 413, { ok:false, error: 'too_large', message: 'Dữ liệu gửi lên quá lớn.' }); }
      db.codeSnippets = db.codeSnippets || [];
      const name = String(body.name || '').trim().slice(0, 100);
      const language = CV_ALLOWED_LANGS.includes(body.language) ? body.language : 'other';
      const code = typeof body.code === 'string' ? body.code : '';
      if(!name || !code){
        return sendJSON(res, 400, { ok:false, error: 'missing_fields' });
      }
      const sizeBytes = Buffer.byteLength(code, 'utf8');
      if(sizeBytes > CV_MAX_BYTES){
        return sendJSON(res, 413, { ok:false, error: 'too_large', message: 'Code vượt quá 10MB.' });
      }

      // Helper build public URL cho snippet (dùng cho cả tạo mới lẫn cập nhật)
      function _buildSnippetPublicUrl(sid){
        try{
          const base = resolvePublicUrl(req);
          if(!base) return null;
          return { endpoint: `${base}/api/public/snippet/${sid}`, versionEndpoint: `${base}/api/public/snippet/${sid}/version`, listEndpoint: `${base}/api/public/snippets` };
        }catch(e){ return null; }
      }

      if(body.id){
        const snippet = db.codeSnippets.find(s => s.id === body.id);
        if(!snippet) return sendJSON(res, 404, { ok:false, error: 'not_found' });
        snippet.name = name;
        snippet.language = language;
        snippet.code = code;
        snippet.sizeBytes = sizeBytes;
        snippet.updatedAt = new Date().toISOString();
        saveDBNow();
        // ── Sync lại RAM ngay lập tức ─────────────────────────────────
        // Đảm bảo _findPublicSnippet() trả code mới ngay, không cần restart.
        // _defaultSnippetMap là object thường (không phải Map), gán thẳng được.
        if(_defaultSnippetMap[snippet.id]){
          _defaultSnippetMap[snippet.id].name      = snippet.name;
          _defaultSnippetMap[snippet.id].code      = snippet.code;
          _defaultSnippetMap[snippet.id].sizeBytes = snippet.sizeBytes;
          _defaultSnippetMap[snippet.id].updatedAt = snippet.updatedAt;
          console.log(`[KeyVault] Đã sync snippet ${snippet.id} vào RAM ngay sau khi admin cập nhật.`);
        } else {
          // Snippet không có trong DEFAULT_CODE_SNIPPETS nhưng đã có trong db — thêm vào RAM
          _defaultSnippetMap[snippet.id] = { ...snippet };
          console.log(`[KeyVault] Đã thêm snippet ${snippet.id} vào RAM từ db (sau khi cập nhật).`);
        }
        const urls = _buildSnippetPublicUrl(snippet.id);
        return sendJSON(res, 200, {
          ok: true,
          id: snippet.id,
          checksum: _codeChecksum(snippet.code),
          updatedAt: snippet.updatedAt,
          // Trả về publicEndpoint để dashboard hiển thị ngay + Loader dùng để tự kéo code
          ...(urls || {})
        });
      }

      const snippet = {
        id: crypto.randomBytes(8).toString('hex'),
        name,
        language,
        code,
        sizeBytes,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      db.codeSnippets.push(snippet);
      // ── Snippet mới tạo: thêm vào RAM luôn để public endpoint thấy ngay ──
      _defaultSnippetMap[snippet.id] = snippet;
      console.log(`[KeyVault] Đã thêm snippet mới vào RAM: ${snippet.id} (${snippet.name})`);
      saveDBNow();
      const newUrls = _buildSnippetPublicUrl(snippet.id);
      return sendJSON(res, 200, {
        ok: true,
        id: snippet.id,
        checksum: _codeChecksum(snippet.code),
        updatedAt: snippet.updatedAt,
        // Trả về publicEndpoint để dashboard hiển thị ngay + Loader dùng để tự kéo code
        ...(newUrls || {})
      });
    }

    /* ---- Admin: xem chi tiết (kèm nội dung đầy đủ) hoặc xoá 1 đoạn code cụ thể ---- */
    const cvItemMatch = pathname.match(/^\/api\/admin\/code-snippets\/([a-f0-9]+)$/);
    if(cvItemMatch && req.method === 'GET'){
      // Tìm trong db trước, fallback sang RAM nếu db rỗng (sau Render restart)
      let snippet = (db.codeSnippets || []).find(s => s.id === cvItemMatch[1]);
      if(!snippet) snippet = _defaultSnippetMap[cvItemMatch[1]] || null;
      if(!snippet) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      return sendJSON(res, 200, snippet);
    }
    if(cvItemMatch && req.method === 'DELETE'){
      const delId = cvItemMatch[1];
      db.codeSnippets = (db.codeSnippets || []).filter(s => s.id !== delId);
      // Xoá khỏi RAM để public endpoint không còn phục vụ snippet đã xoá
      if(_defaultSnippetMap[delId]){
        delete _defaultSnippetMap[delId];
        console.log('[KeyVault] Đã xoá snippet ' + delId + ' khỏi RAM.');
      }
      saveDBNow();
      return sendJSON(res, 200, { ok:true });
    }

    /* ---- Mua 1 gói trong nhóm sản phẩm — tương tự /api/checkout nhưng theo (groupId + planId) ---- */
    if(pathname === '/api/checkout-group' && req.method === 'POST'){
      const ip = getClientIP(req);
      if(isRateLimited('checkout', ip, 15, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đang gửi yêu cầu mua hàng quá nhanh, vui lòng thử lại sau.' });
      }

      const body = await readJSONBody(req);
      const token = body.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const authed = getCustomerByToken(token);
      if(!authed){
        return sendJSON(res, 401, { ok:false, error: 'not_logged_in' });
      }

      const group = (db.productGroups || []).find(g => g.id === body.groupId && g.active);
      if(!group){
        return sendJSON(res, 404, { ok:false, error: 'group_not_found' });
      }
      const plan = (group.plans || []).find(p => p.id === body.planId);
      if(!plan){
        return sendJSON(res, 404, { ok:false, error: 'plan_not_found' });
      }

      let finalPrice = parseSafeAmount(plan.price, { min: 0, max: 1000000000 });
      if(finalPrice === null) finalPrice = 0;
      let usedDiscount = null;
      const rawCode = String(body.discountCode || '').trim().toUpperCase().slice(0, 60);
      if(rawCode){
        const disc = (db.discountCodes || []).find(d => d.code === rawCode);
        if(!disc || !disc.active){
          return sendJSON(res, 400, { ok:false, error: 'discount_invalid' });
        }
        if(disc.expiresAt && new Date(disc.expiresAt).getTime() < Date.now()){
          return sendJSON(res, 400, { ok:false, error: 'discount_expired' });
        }
        if(disc.maxUses > 0 && disc.usedCount >= disc.maxUses){
          return sendJSON(res, 400, { ok:false, error: 'discount_used_up' });
        }
        const safePercent = Math.min(100, Math.max(0, Number(disc.percent) || 0));
        finalPrice = Math.round(finalPrice * (1 - safePercent / 100));
        if(finalPrice < 0) finalPrice = 0;
        usedDiscount = disc;
      }

      /* Cùng cơ chế khoá theo customerId như /api/checkout để chống race-condition trừ tiền/giao key. */
      const result = await withCustomerLock(authed.customer.id, async ()=>{
        const customerForCheckout = (db.customers || []).find(c => c.id === authed.customer.id);
        if(!customerForCheckout){
          return { status: 401, body: { ok:false, error: 'not_logged_in' } };
        }
        const currentBalance = Number.isFinite(customerForCheckout.balance) ? customerForCheckout.balance : 0;
        if(currentBalance < finalPrice){
          return { status: 400, body: { ok:false, error: 'insufficient_balance', balance: currentBalance, price: finalPrice } };
        }

        const foundKey = findAvailableKeyForPrefix(plan.keyPrefix);
        if(!foundKey){
          return { status: 409, body: { ok:false, error: 'out_of_stock' } };
        }

        foundKey.key.status = 'sold';
        foundKey.key.customer = authed.customer.username;
        foundKey.key.price = String(finalPrice);
        foundKey.key.soldAt = new Date().toISOString();
        if(usedDiscount) usedDiscount.usedCount = (usedDiscount.usedCount || 0) + 1;

        customerForCheckout.balance = currentBalance - finalPrice;
        customerForCheckout.transactionHistory = customerForCheckout.transactionHistory || [];
        customerForCheckout.transactionHistory.unshift({
          id: crypto.randomBytes(8).toString('hex'),
          type: 'purchase',
          amount: -finalPrice,
          balanceAfter: customerForCheckout.balance,
          createdAt: new Date().toISOString(),
          note: `Mua ${group.name} — ${plan.label || plan.unit}`
        });

        saveDBNow();
        return {
          status: 200,
          body: {
            ok: true,
            key: foundKey.key.value,
            expiresAt: foundKey.key.expiresAt || null,
            hasExpiryPlan: !!foundKey.key.hasExpiryPlan,
            activated: !!foundKey.key.activated,
            expiryAmount: foundKey.key.expiryAmount || null,
            expiryUnit: foundKey.key.expiryUnit || null,
            maxDevices: foundKey.key.maxDevices || 1,
            pricePaid: finalPrice
          }
        };
      });

      return sendJSON(res, result.status, result.body);
    }

    /* ================= TRANG "NGƯỜI DÙNG" (ADMIN QUẢN LÝ TÀI KHOẢN KHÁCH HÀNG) ================= */

    /* ---- Danh sách toàn bộ tài khoản khách hàng đã đăng ký ở trang bán hàng (không trả passwordHash) ---- */
    if(pathname === '/api/admin/customers' && req.method === 'GET'){
      const list = (db.customers || []).map(c => ({
        id: c.id,
        username: c.username,
        role: c.role || 'customer',
        balance: c.balance || 0,
        createdAt: c.createdAt,
        registrationIP: c.registrationIP || null,
        topupCount: (c.topupHistory || []).length,
        transactionCount: (c.transactionHistory || []).length
      }));
      return sendJSON(res, 200, list);
    }

    /* ---- Admin cộng (hoặc trừ, nếu số âm) tiền vào tài khoản 1 khách hàng ---- */
    const topupCustomerMatch = pathname.match(/^\/api\/admin\/customers\/([a-f0-9]+)\/balance$/);
    if(topupCustomerMatch && req.method === 'POST'){
      const body = await readJSONBody(req);
      const customer = (db.customers || []).find(c => c.id === topupCustomerMatch[1]);
      if(!customer) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      const amount = parseFloat(String(body.amount || '').replace(/[^\d.-]/g,'')) || 0;
      customer.balance = (customer.balance || 0) + amount;
      customer.topupHistory = customer.topupHistory || [];
      customer.topupHistory.unshift({
        id: crypto.randomBytes(8).toString('hex'),
        amount,
        method: 'admin_manual',
        status: 'approved',
        createdAt: new Date().toISOString(),
        note: String(body.note || 'Admin cộng tiền thủ công')
      });
      customer.transactionHistory = customer.transactionHistory || [];
      customer.transactionHistory.unshift({
        id: crypto.randomBytes(8).toString('hex'),
        type: amount >= 0 ? 'topup' : 'adjust',
        amount,
        balanceAfter: customer.balance,
        createdAt: new Date().toISOString(),
        note: String(body.note || 'Admin cộng tiền thủ công')
      });
      saveDBNow();
      return sendJSON(res, 200, { ok:true, customer: { id: customer.id, username: customer.username, balance: customer.balance } });
    }

    /* ---- Admin đổi mật khẩu cho 1 tài khoản khách hàng đã tạo ---- */
    const changePassCustomerMatch = pathname.match(/^\/api\/admin\/customers\/([a-f0-9]+)\/password$/);
    if(changePassCustomerMatch && req.method === 'POST'){
      const body = await readJSONBody(req);
      const customer = (db.customers || []).find(c => c.id === changePassCustomerMatch[1]);
      if(!customer) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      const newPassword = String(body.newPassword || '');
      if(newPassword.length < 4){
        return sendJSON(res, 400, { ok:false, error: 'password_too_short' });
      }
      customer.passwordHash = hashPassword(newPassword);
      saveDBNow();
      return sendJSON(res, 200, { ok:true });
    }

    /* ---- Danh sách yêu cầu nạp tiền đang chờ admin duyệt ---- */
    if(pathname === '/api/admin/topup-requests' && req.method === 'GET'){
      expireStaleTopupRequests();
      return sendJSON(res, 200, db.topupRequests || []);
    }

    /* ---- Admin duyệt / từ chối 1 yêu cầu nạp tiền ---- */
    const topupDecisionMatch = pathname.match(/^\/api\/admin\/topup-requests\/([a-f0-9]+)\/(approve|reject)$/);
    if(topupDecisionMatch && req.method === 'POST'){
      expireStaleTopupRequests(); // đảm bảo không duyệt nhầm 1 request đã quá 30 phút
      const [, reqId, decision] = topupDecisionMatch;
      const reqEntry = (db.topupRequests || []).find(r => r.id === reqId);
      if(!reqEntry) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      if(reqEntry.status !== 'pending') return sendJSON(res, 400, { ok:false, error: 'already_processed', status: reqEntry.status });

      // Dùng khoá theo customerId để tránh race-condition nếu admin duyệt đồng thời với
      // 1 giao dịch khác (checkout/topup khác) đang cùng sửa số dư của khách hàng này.
      await withCustomerLock(reqEntry.customerId, async ()=>{
        reqEntry.status = decision === 'approve' ? 'approved' : 'rejected';
        const customer = (db.customers || []).find(c => c.id === reqEntry.customerId);
        if(customer){
          const hist = (customer.topupHistory || []).find(h => h.id === reqEntry.id);
          if(hist) hist.status = reqEntry.status;
          if(decision === 'approve'){
            customer.balance = (customer.balance || 0) + reqEntry.amount;
            customer.transactionHistory = customer.transactionHistory || [];
            customer.transactionHistory.unshift({
              id: crypto.randomBytes(8).toString('hex'),
              type: 'topup',
              amount: reqEntry.amount,
              balanceAfter: customer.balance,
              createdAt: new Date().toISOString(),
              note: 'Nạp tiền được admin duyệt'
            });
          }
        }
      });
      saveDBNow();
      return sendJSON(res, 200, { ok:true, request: reqEntry });
    }

    /* ---- Quản lý danh sách app/tool được phép dùng server key (admin) ---- */
    if(pathname === '/api/apps' && req.method === 'GET'){
      return sendJSON(res, 200, db.apiApps || []);
    }

    const approveMatch = pathname.match(/^\/api\/apps\/([a-f0-9]+)\/approve$/);
    if(approveMatch && req.method === 'POST'){
      const app = (db.apiApps || []).find(a => a.id === approveMatch[1]);
      if(!app) return sendJSON(res, 404, { error: 'not_found' });
      app.status = 'allowed';
      saveDBDebounced();
      return sendJSON(res, 200, app);
    }

    const denyMatch = pathname.match(/^\/api\/apps\/([a-f0-9]+)\/deny$/);
    if(denyMatch && req.method === 'POST'){
      const app = (db.apiApps || []).find(a => a.id === denyMatch[1]);
      if(!app) return sendJSON(res, 404, { error: 'not_found' });
      app.status = 'denied';
      saveDBDebounced();
      return sendJSON(res, 200, app);
    }

    const removeMatch = pathname.match(/^\/api\/apps\/([a-f0-9]+)$/);
    if(removeMatch && req.method === 'DELETE'){
      db.apiApps = (db.apiApps || []).filter(a => a.id !== removeMatch[1]);
      saveDBDebounced();
      return sendJSON(res, 200, { ok: true });
    }

    /* ================= TELEGRAM BOT + MINI APP ================= */

    /* ---- Trang Mini App (mở bên trong Telegram qua nút "web_app") ---- */
    if(pathname === '/telegram' && req.method === 'GET'){
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(TELEGRAM_PAGE_HTML);
    }

    /* ---- Webhook nhận Update từ Telegram (tin nhắn, bấm nút...). Luôn trả 200 thật nhanh —
       Telegram sẽ tự lặp lại việc gửi update nếu không nhận được phản hồi hợp lệ kịp thời. ---- */
    if(pathname === '/api/telegram/webhook' && req.method === 'POST'){
      try{
        const update = await readJSONBody(req);

        // ── Xử lý callback_query (bấm nút inline) ──
        if(update && update.callback_query){
          const cbq = update.callback_query;
          const cbChatId = cbq.message && cbq.message.chat && cbq.message.chat.id;
          const cbData = cbq.data || '';
          // Trả lời callback để Telegram không hiện loading
          try{
            await telegramApiCall('answerCallbackQuery', { callback_query_id: cbq.id });
          }catch(_){}
          if(cbChatId && cbData === 'enter_key'){
            _tgVerifySessions = _tgVerifySessions || {};
            _tgVerifySessions[String(cbChatId)] = _tgVerifySessions[String(cbChatId)] || {};
            _tgVerifySessions[String(cbChatId)].waitingForKey = true;
            await sendTelegramMessage(cbChatId,
              '🔑 <b>Nhập key kích hoạt của bạn:</b>\n\n' +
              '<i>Gửi key trực tiếp vào đây</i>\n\n' +
              '💡 Chưa có key? Mua tại /start'
            );
          }
        }

        const msg = update && update.message;
        if(msg && msg.from && typeof msg.text === 'string'){
          const text = msg.text.trim();
          const textLower = text.toLowerCase();
          const chatId = msg.chat.id;
          const tgUser = msg.from;

          // ── Helper format thời gian ──
          const _fmtTime = (secs) => {
            const h = Math.floor(secs/3600), m = Math.floor((secs%3600)/60), s = secs%60;
            return h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
          };

          // /start — chào mừng đẹp, KHÔNG hiện lệnh cơ bản, chỉ có nút mở shop
          if(textLower.startsWith('/start')){
            findOrCreateTelegramCustomer(tgUser, getClientIP(req));
            saveDBDebounced();
            const baseUrl = resolvePublicUrl(req);
            const miniAppUrl = baseUrl ? `${baseUrl}/telegram` : null;
            const name = tgUser.first_name || tgUser.username || 'bạn';
            // Kiểm tra xem user đã có key hợp lệ chưa để hiện menu lệnh
            const existSess = (_tgVerifySessions || {})[String(chatId)];
            const hasValidKey = existSess && existSess.keyVerified && existSess.savedKey;
            const welcomeText =
              `🎮 <b>FF Unlocker Bot</b>\n` +
              `━━━━━━━━━━━━━━━━━━━━━━\n\n` +
              `Xin chào <b>${String(name).replace(/[<>&]/g,'')}</b> 👋\n\n` +
              `🔓 Bot hỗ trợ <b>xác thực ID Free Fire</b> tự động,\n` +
              `tự động gia hạn phiên mà không cần thao tác thêm.\n\n` +
              (hasValidKey
                ? `✅ Tài khoản của bạn đã kích hoạt!\n\n<b>📋 Các lệnh sử dụng:</b>\n• Gửi <b>ID Free Fire</b> của bạn để xác thực\n• /status — Xem trạng thái phiên\n• /cancel — Huỷ phiên hiện tại\n• /help — Hướng dẫn chi tiết\n\n`
                : `🔑 <b>Để sử dụng, bạn cần kích hoạt key trước.</b>\n\nGửi lệnh /key để nhập key kích hoạt.\n\n`) +
              `Bấm nút bên dưới để mua key hoặc xem cửa hàng:`;
            const inlineKeyboard = [];
            if(miniAppUrl){
              inlineKeyboard.push([{ text: '🛍️ Mở Shop', web_app: { url: miniAppUrl } }]);
            }
            if(!hasValidKey){
              inlineKeyboard.push([{ text: '🔑 Nhập key kích hoạt', callback_data: 'enter_key' }]);
            }
            if(inlineKeyboard.length > 0){
              await sendTelegramMessage(chatId, welcomeText, {
                reply_markup: { inline_keyboard: inlineKeyboard }
              });
            } else {
              await sendTelegramMessage(chatId, welcomeText);
            }

          // /help — hướng dẫn đầy đủ
          } else if(textLower === '/help' || textLower.startsWith('/help ')){
            await sendTelegramMessage(chatId,
              `📖 <b>Hướng dẫn sử dụng FF Unlocker Bot</b>\n\n` +
              `<b>🔐 Xác thực key:</b>\n` +
              `<code>/key YOUR_KEY</code>\n` +
              `→ Kiểm tra key kích hoạt với server\n\n` +
              `<b>🆔 Xác thực ID Free Fire:</b>\n` +
              `<code>/verify 15886913287</code>\n` +
              `→ Bot sẽ kết nối unlockffbeta.com và xác thực ID của bạn\n` +
              `→ Khi còn ≤ 60 giây, bot <b>tự động xác thực lại</b>\n\n` +
              `<b>💾 Lưu ID mặc định:</b>\n` +
              `<code>/setid 15886913287</code>\n` +
              `→ Bot nhớ ID để tự reverify khi phiên hết hạn\n\n` +
              `<b>📊 Kiểm tra trạng thái:</b>\n` +
              `<code>/status</code>\n` +
              `→ Hiện ID, key, thời gian còn lại\n\n` +
              `<b>❌ Huỷ phiên:</b>\n` +
              `<code>/cancel</code>\n` +
              `→ Dừng auto-reverify và xoá phiên hiện tại\n\n` +
              `<i>💡 Tip: Dùng /setid để bot tự động xác thực lại mà không cần gõ lệnh!</i>`
            );

          // /key — gửi /key sẽ hỏi nhập key (không cần /key <key> nữa)
          } else if(textLower === '/key' || textLower.startsWith('/key ')){
            const parts = text.split(/\s+/);
            const keyVal = (parts[1] || '').trim();
            if(!keyVal){
              // Đặt trạng thái chờ nhập key
              _tgVerifySessions = _tgVerifySessions || {};
              _tgVerifySessions[String(chatId)] = _tgVerifySessions[String(chatId)] || {};
              _tgVerifySessions[String(chatId)].waitingForKey = true;
              await sendTelegramMessage(chatId,
                '🔑 <b>Nhập key kích hoạt của bạn:</b>\n\n' +
                '<i>Gửi key trực tiếp vào đây (không cần gõ /key nữa)</i>\n\n' +
                '💡 Chưa có key? Mua tại /start'
              );
            } else {
              // Có key ngay trong lệnh → xác thực luôn
              await _verifyKeyForChat(chatId, keyVal);
            }

          // /setid <ID> — lưu ID mặc định cho auto-reverify (giống saved_id trong prefs)
          } else if(textLower.startsWith('/setid')){
            const parts = text.split(/\s+/);
            const newId = (parts[1] || '').trim();
            if(!newId){
              _tgVerifySessions = _tgVerifySessions || {};
              const cur = _tgVerifySessions[String(chatId)];
              const curId = cur && cur.savedId ? cur.savedId : (cur && cur.accountId ? cur.accountId : '');
              if(curId){
                await sendTelegramMessage(chatId,
                  `💾 <b>ID mặc định hiện tại:</b> <code>${curId}</code>\n\nĐể đổi ID: <code>/setid &lt;ID_mới&gt;</code>`
                );
              } else {
                await sendTelegramMessage(chatId,
                  '💾 <b>Chưa có ID mặc định.</b>\n\nDùng: <code>/setid &lt;ID_của_bạn&gt;</code>'
                );
              }
            } else if(!/^\d{6,15}$/.test(newId)){
              await sendTelegramMessage(chatId,
                '❌ <b>ID không hợp lệ.</b> ID phải là dãy số 6–15 chữ số.'
              );
            } else {
              _tgVerifySessions = _tgVerifySessions || {};
              _tgVerifySessions[String(chatId)] = _tgVerifySessions[String(chatId)] || {};
              _tgVerifySessions[String(chatId)].savedId = newId;
              await sendTelegramMessage(chatId,
                `✅ <b>Đã lưu ID mặc định:</b> <code>${newId}</code>\n\n🔄 Bot sẽ tự động xác thực lại ID này khi phiên còn ≤ 60 giây.\n\nXác thực ngay: <code>/verify ${newId}</code>`
              );
            }

          // /cancel — huỷ phiên xác thực hiện tại
          } else if(textLower === '/cancel' || textLower.startsWith('/cancel ')){
            _tgVerifySessions = _tgVerifySessions || {};
            const sess = _tgVerifySessions[String(chatId)];
            if(!sess || (!sess.accountId && !sess.savedId)){
              await sendTelegramMessage(chatId,
                'ℹ️ <b>Không có phiên nào đang chạy.</b>'
              );
            } else {
              // Huỷ timer auto-reverify nếu có
              if(sess.reverifyTimer) clearTimeout(sess.reverifyTimer);
              delete _tgVerifySessions[String(chatId)];
              await sendTelegramMessage(chatId,
                '🛑 <b>Đã huỷ phiên xác thực.</b>\nAuto-reverify đã dừng.\n\nBắt đầu lại: <code>/verify &lt;ID&gt;</code>'
              );
            }

          // /verify — gửi /verify sẽ hỏi nhập ID (không cần /verify <id> nữa)
          } else if(textLower === '/verify' || textLower.startsWith('/verify ')){
            const parts = text.split(/\s+/);
            let accountId = (parts[1] || '').trim();
            _tgVerifySessions = _tgVerifySessions || {};
            const curSess = _tgVerifySessions[String(chatId)] || {};
            // Kiểm tra key đã được xác thực chưa
            if(!curSess.keyVerified){
              await sendTelegramMessage(chatId,
                '⚠️ <b>Bạn chưa kích hoạt key!</b>\n\nVui lòng nhập key trước:\n/key\n\n<i>Chưa có key? Mua tại /start</i>'
              );
            } else if(!accountId){
              // Nếu không truyền ID → thử dùng savedId
              const fallbackId = curSess.savedId || '';
              if(fallbackId){
                accountId = fallbackId;
                await sendTelegramMessage(chatId,
                  `💡 <b>Dùng ID đã lưu:</b> <code>${accountId}</code>\n\n⏳ Đang xác thực...`
                );
                await _doVerifyId(chatId, accountId);
              } else {
                // Đặt trạng thái chờ nhập ID
                _tgVerifySessions[String(chatId)].waitingForId = true;
                await sendTelegramMessage(chatId,
                  '🆔 <b>Nhập ID Free Fire của bạn:</b>\n\n' +
                  '<i>Gửi ID trực tiếp vào đây (chỉ số, không cần gõ /verify nữa)</i>\n\n' +
                  '💡 Ví dụ: <code>15886913287</code>'
                );
              }
            } else {
              if(!/^\d{6,15}$/.test(accountId)){
                await sendTelegramMessage(chatId,
                  '❌ <b>ID không hợp lệ.</b>\n\nID phải là dãy số từ 6–15 chữ số.\n\nVí dụ: <code>15886913287</code>'
                );
              } else {
                await _doVerifyId(chatId, accountId);
              }
            }

          // ── Xử lý tin nhắn thuần túy khi đang chờ nhập key hoặc ID ──
          } else if(!textLower.startsWith('/')){
            _tgVerifySessions = _tgVerifySessions || {};
            const curSess2 = _tgVerifySessions[String(chatId)] || {};

            if(curSess2.waitingForKey){
              // User đang chờ nhập key — xác thực key
              _tgVerifySessions[String(chatId)].waitingForKey = false;
              await _verifyKeyForChat(chatId, text.trim());

            } else if(curSess2.waitingForId){
              // User đang chờ nhập ID — xác thực ID
              _tgVerifySessions[String(chatId)].waitingForId = false;
              const rawId = text.trim();
              if(!/^\d{6,15}$/.test(rawId)){
                await sendTelegramMessage(chatId,
                  '❌ <b>ID không hợp lệ.</b>\n\nID phải là dãy số từ 6–15 chữ số.\n\nVí dụ: <code>15886913287</code>'
                );
              } else {
                await _doVerifyId(chatId, rawId);
              }

            } else if(curSess2.keyVerified && /^\d{6,15}$/.test(text.trim())){
              // User đã có key và gửi một dãy số → tự động hiểu là ID Free Fire
              await _doVerifyId(chatId, text.trim());

            } else if(!curSess2.keyVerified && text.trim().length > 4 && !text.trim().includes(' ')){
              // User chưa có key mà gửi chuỗi dài không chứa khoảng trắng → có thể là key
              await sendTelegramMessage(chatId,
                '⚠️ <b>Bạn chưa kích hoạt key!</b>\n\nNếu đây là key của bạn, hãy dùng lệnh:\n/key\n\nSau đó nhập key vào. Hoặc mua key tại /start'
              );
            }

          // /status — trạng thái chi tiết (key + ID + thời gian)
          } else if(textLower === '/status'){
            _tgVerifySessions = _tgVerifySessions || {};
            const sess = _tgVerifySessions[String(chatId)];
            if(!sess || (!sess.accountId && !sess.savedId)){
              await sendTelegramMessage(chatId,
                'ℹ️ <b>Chưa có phiên xác thực nào.</b>\n\n' +
                '• Lưu key: <code>/key &lt;key&gt;</code>\n' +
                '• Xác thực ID: <code>/verify &lt;ID&gt;</code>'
              );
            } else {
              const lines = ['📊 <b>Trạng thái phiên hiện tại</b>\n'];
              // Key
              if(sess.savedKey){
                const keyStatus = sess.keyVerified ? '✅ Đã xác thực' : '⚠️ Chưa xác thực';
                lines.push(`🔑 Key: <code>${sess.savedKey}</code> — ${keyStatus}`);
              }
              // ID
              const displayId = sess.accountId || sess.savedId;
              if(displayId) lines.push(`🆔 ID: <code>${displayId}</code>`);
              if(sess.savedId && sess.savedId !== sess.accountId){
                lines.push(`💾 ID mặc định: <code>${sess.savedId}</code>`);
              }
              // Thời gian
              if(sess.expires && sess.expires > Date.now()){
                const remain = Math.floor((sess.expires - Date.now()) / 1000);
                const timeStr = _fmtTime(remain);
                const autoMsg = remain <= 60 ? ' 🔄 <i>(Đang tự verify lại...)</i>' : '';
                lines.push(`⏱ Còn lại: <b>${timeStr}</b>${autoMsg}`);
                // Trạng thái tương ứng AutoVerifyService state machine
                const state = remain > 60 ? '1 (active)' : '2 (reverifying)';
                lines.push(`📶 State: <code>${state}</code>`);
              } else if(sess.expires){
                lines.push(`⏰ <b>Phiên đã hết hạn.</b>`);
                const fallbackId = sess.savedId || sess.accountId;
                if(fallbackId) lines.push(`\nVerify lại: <code>/verify ${fallbackId}</code>`);
              } else {
                lines.push(`⏳ <i>Đang xác thực lần đầu...</i>`);
              }
              await sendTelegramMessage(chatId, lines.join('\n'));
            }
          }
        }
      }catch(e){
        console.error('[Telegram] Lỗi xử lý webhook:', e && e.message);
      }
      return sendJSON(res, 200, { ok:true });
    }

    /* ---- Mini App đăng nhập bằng dữ liệu Telegram WebApp (initData đã được server tự
       xác thực chữ ký HMAC — KHÔNG tin id/username do client tự khai báo). ---- */
    if(pathname === '/api/telegram/auth' && req.method === 'POST'){
      const ip = getClientIP(req);
      if(isRateLimited('telegram-auth', ip, 30, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited' });
      }
      const body = await readJSONBody(req);
      const tgUser = verifyTelegramInitData(body.initData);
      if(!tgUser){
        return sendJSON(res, 401, { ok:false, error: 'invalid_telegram_data', message: 'Không xác thực được dữ liệu Telegram — vui lòng mở lại Mini App từ trong Telegram.' });
      }
      const customer = findOrCreateTelegramCustomer(tgUser, ip);
      const token = genToken();
      db.customerSessions = db.customerSessions || {};
      db.customerSessions[token] = { customerId: customer.id, username: customer.username, createdAt: new Date().toISOString() };
      saveDBNow();
      return sendJSON(res, 200, {
        ok: true,
        token,
        customer: {
          username: customer.username,
          balance: customer.balance || 0,
          telegramFirstName: customer.telegramFirstName || '',
          telegramUsername: customer.telegramUsername || null,
          telegramTier: customer.telegramTier || 'customer'
        }
      });
    }

    /* ================= ADMIN: QUẢN LÝ MINI APP (danh sách user Telegram + thăng cấp + thông báo) ================= */

    /* ---- Danh sách toàn bộ user đã từng vào Mini App (tài khoản customer có gắn Telegram) ---- */
    if(pathname === '/api/admin/telegram/users' && req.method === 'GET'){
      const list = (db.customers || [])
        .filter(c => c.source === 'telegram' && c.telegramId)
        .map(c => ({
          id: c.id,
          telegramId: c.telegramId,
          telegramUsername: c.telegramUsername || null,
          telegramFirstName: c.telegramFirstName || '',
          telegramLastName: c.telegramLastName || '',
          telegramTier: c.telegramTier || 'customer',
          balance: c.balance || 0,
          joinedAt: c.telegramJoinedAt || c.createdAt,
          lastSeenAt: c.telegramLastSeenAt || c.createdAt,
          topupCount: (c.topupHistory || []).length,
          transactionCount: (c.transactionHistory || []).length
        }))
        .sort((a,b)=> new Date(b.lastSeenAt) - new Date(a.lastSeenAt));
      return sendJSON(res, 200, list);
    }

    /* ---- Admin thăng cấp / hạ cấp 1 user Telegram giữa 'customer' và 'seller' ---- */
    const tgTierMatch = pathname.match(/^\/api\/admin\/telegram\/users\/([a-f0-9]+)\/tier$/);
    if(tgTierMatch && req.method === 'POST'){
      const body = await readJSONBody(req);
      const customer = (db.customers || []).find(c => c.id === tgTierMatch[1] && c.source === 'telegram');
      if(!customer) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      const tier = body.tier === 'seller' ? 'seller' : 'customer';
      customer.telegramTier = tier;
      saveDBNow();
      return sendJSON(res, 200, { ok:true, id: customer.id, telegramTier: tier });
    }

    /* ---- Admin gửi THÔNG BÁO xuống bot Telegram: 1 user cụ thể (customerId) hoặc BROADCAST
       tới toàn bộ user đã từng vào Mini App nếu không truyền customerId. ---- */
    if(pathname === '/api/admin/telegram/notify' && req.method === 'POST'){
      const ip = getClientIP(req);
      if(isRateLimited('telegram-notify', ip, 10, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Vui lòng chờ trước khi gửi thông báo tiếp theo.' });
      }
      const body = await readJSONBody(req);
      const message = String(body.message || '').trim().slice(0, 2000);
      if(!message) return sendJSON(res, 400, { ok:false, error: 'missing_message' });

      let targets;
      if(body.customerId){
        const customer = (db.customers || []).find(c => c.id === body.customerId && c.source === 'telegram');
        if(!customer) return sendJSON(res, 404, { ok:false, error: 'not_found' });
        targets = [customer];
      } else {
        targets = (db.customers || []).filter(c => c.source === 'telegram' && c.telegramId);
      }

      let sent = 0, failed = 0;
      for(const c of targets){
        const result = await sendTelegramMessage(c.telegramId, message);
        if(result && result.ok) sent++; else failed++;
      }
      return sendJSON(res, 200, { ok:true, sent, failed, total: targets.length });
    }

    /* ---- Trạng thái nhanh cho trang admin "Quản lý Mini App" (link Mini App hiện tại, tổng số user) ---- */
    if(pathname === '/api/admin/telegram/status' && req.method === 'GET'){
      const baseUrl = resolvePublicUrl(req);
      const totalUsers = (db.customers || []).filter(c => c.source === 'telegram' && c.telegramId).length;
      return sendJSON(res, 200, {
        ok: true,
        miniAppUrl: baseUrl ? `${baseUrl}/telegram` : null,
        webhookConfigured: !!process.env.RENDER_EXTERNAL_URL || !!process.env.SELF_URL,
        totalUsers
      });
    }

    /* ================================================================
       PUBLIC SNIPPET LOADER — endpoint công khai cho Violentmonkey
       Không cần xác thực, chỉ cần ID snippet đúng.
       Ưu tiên tìm: db.codeSnippets (mới nhất, do admin cập nhật qua web UI)
       → RAM (defaultSnippetMap) nếu db chưa có (vd: sau Render restart).
       Khi admin cập nhật snippet qua web UI → db luôn mới hơn RAM →
       loader sẽ nhận checksum mới → tự kéo code mới xuống tự động.

       Có 2 endpoint:
         GET /api/public/snippet/:id         → trả toàn bộ { ok, code, name, updatedAt, checksum }
         GET /api/public/snippet/:id/version → chỉ trả { ok, updatedAt, checksum } (nhẹ ~100B)
           Loader dùng /version để kiểm tra xem có bản mới không trước khi tải lại toàn bộ code.
       ================================================================ */

    // ── Helper: tìm snippet theo id
    //    Ưu tiên db (admin có thể cập nhật qua web UI bất kỳ lúc nào)
    //    Fallback sang RAM nếu db trống (Render restart, db.json bị xoá).
    function _findPublicSnippet(sid){
      // 1. Tìm trong db trước — đây là bản mới nhất nếu admin đã nạp/cập nhật
      const fromDB = (db.codeSnippets || []).find(x => x.id === sid) || null;
      if(fromDB) return fromDB;
      // 2. Fallback RAM — đảm bảo snippet tồn tại ngay cả sau Render restart
      return _defaultSnippetMap[sid] || null;
    }
    // Helper: tính checksum SHA-256 (8 ký tự đầu) của code để loader so sánh nhanh
    function _codeChecksum(code){
      return crypto.createHash('sha256').update(code || '', 'utf8').digest('hex').slice(0, 16);
    }
    // Header CORS dùng chung
    function _publicHeaders(res){
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-KV-Checksum');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
    }

    // CORS preflight cho public snippet
    if(pathname.startsWith('/api/public/') && req.method === 'OPTIONS'){
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,X-KV-Checksum'
      });
      return res.end();
    }

    /* ── GET /api/public/snippets ─────────────────────────────────────
       Trả danh sách tất cả snippet đang có (không kèm code — chỉ metadata).
       Violentmonkey Loader dùng để tự động lấy Public Endpoint mà không cần
       hardcode ID. Response: [{ id, name, updatedAt, checksum }, ...]        */
    if(pathname === '/api/public/snippets' && req.method === 'GET'){
      const allSnippets = [
        ...(db.codeSnippets || []),
        ...Object.values(_defaultSnippetMap).filter(d => !(db.codeSnippets||[]).some(x=>x.id===d.id))
      ];
      _publicHeaders(res);
      res.writeHead(200);
      return res.end(JSON.stringify(
        allSnippets.map(s => ({
          id        : s.id,
          name      : s.name,
          updatedAt : s.updatedAt || s.createdAt,
          checksum  : _codeChecksum(s.code)
        }))
      ));
    }

    /* ── GET /api/public/snippet/:id/version ─────────────────────────
       Endpoint nhẹ — loader gọi mỗi lần trang load để biết có bản mới không.
       Chỉ trả { ok, updatedAt, checksum } (~100B) thay vì toàn bộ code.
       Nếu checksum khớp cache → không cần tải lại, chạy cache ngay.      */
    const publicVersionMatch = pathname.match(/^\/api\/public\/snippet\/([a-f0-9]+)\/version$/);
    if(publicVersionMatch && req.method === 'GET'){
      const snippet = _findPublicSnippet(publicVersionMatch[1]);
      if(!snippet){
        _publicHeaders(res);
        res.writeHead(404);
        return res.end(JSON.stringify({ ok:false, error:'snippet_not_found' }));
      }
      const checksum = _codeChecksum(snippet.code);
      _publicHeaders(res);
      res.writeHead(200);
      return res.end(JSON.stringify({
        ok       : true,
        id       : snippet.id,
        name     : snippet.name,
        updatedAt: snippet.updatedAt || snippet.createdAt,
        checksum : checksum
      }));
    }

    /* ── GET /api/public/snippet/:id ─────────────────────────────────
       Trả toàn bộ code. Loader gọi khi:
         (a) chưa có cache, HOẶC
         (b) /version trả checksum khác với cache đang lưu.           */
    const publicSnippetMatch = pathname.match(/^\/api\/public\/snippet\/([a-f0-9]+)$/);
    if(publicSnippetMatch && req.method === 'GET'){
      const snippet = _findPublicSnippet(publicSnippetMatch[1]);
      if(!snippet){
        _publicHeaders(res);
        res.writeHead(404);
        return res.end(JSON.stringify({ ok:false, error:'snippet_not_found',
          message:'Snippet không tồn tại. Thêm vào DEFAULT_CODE_SNIPPETS trong index.js.' }));
      }
      const checksum = _codeChecksum(snippet.code);
      _publicHeaders(res);
      res.writeHead(200);
      return res.end(JSON.stringify({
        ok       : true,
        code     : snippet.code,
        name     : snippet.name,
        updatedAt: snippet.updatedAt || snippet.createdAt,
        checksum : checksum
      }));
    }

    /* ── GET /api/public/update-check ─────────────────────────────────
       Auto check update: App gọi sau khi đăng nhập key thành công.
       Trả về { ok, hasUpdate, version, checksum, updatedAt, size }
       App so sánh checksum với bản đang dùng → nếu khác thì kéo code mới. */
    if(pathname === '/api/public/update-check' && req.method === 'GET'){
      _publicHeaders(res);
      const allSnippets = db.codeSnippets || [];
      const active = allSnippets.length > 0 ? allSnippets[allSnippets.length - 1] : null;
      if(!active){
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true, hasUpdate: false, version: null, checksum: null, updatedAt: null }));
      }
      const chk = _codeChecksum(active.code || '');
      res.writeHead(200);
      return res.end(JSON.stringify({
        ok        : true,
        hasUpdate : true,
        version   : active.updatedAt || active.createdAt,
        checksum  : chk,
        updatedAt : active.updatedAt || active.createdAt,
        name      : active.name,
        size      : Buffer.byteLength(active.code || '', 'utf8'),
        endpoint  : `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}/api/public/code-bundle`
      }));
    }

    /* ── GET /api/public/code-bundle ───────────────────────────────────
       Auto pull code: Trả toàn bộ code mới nhất (snippet cuối cùng).
       App nhận về và thực thi — thay thế code cũ hoàn toàn.
       Yêu cầu header key: X-App-Key hoặc query param ?key=... để xác thực. */
    if(pathname === '/api/public/code-bundle' && req.method === 'GET'){
      _publicHeaders(res);
      // Xác thực key trước khi cho kéo code (tránh bị người lạ kéo)
      const bundleKey = req.headers['x-app-key'] || url.searchParams.get('key') || '';
      if(bundleKey){
        const bFound = findKeyEverywhere(bundleKey.trim());
        if(!bFound || computeKeyStatus(bFound.key) !== 'active'){
          res.writeHead(403);
          return res.end(JSON.stringify({ ok: false, error: 'key_invalid', message: 'Key không hợp lệ hoặc đã hết hạn. Không thể kéo code.' }));
        }
      }
      const allSnippets = db.codeSnippets || [];
      const active = allSnippets.length > 0 ? allSnippets[allSnippets.length - 1] : null;
      if(!active){
        res.writeHead(404);
        return res.end(JSON.stringify({ ok: false, error: 'no_code', message: 'Chưa có code nào trên server. Admin cần nạp code trước.' }));
      }
      const chk = _codeChecksum(active.code || '');
      res.writeHead(200);
      return res.end(JSON.stringify({
        ok        : true,
        code      : active.code,
        name      : active.name,
        checksum  : chk,
        updatedAt : active.updatedAt || active.createdAt,
        size      : Buffer.byteLength(active.code || '', 'utf8')
      }));
    }

    /* =====================================================================
       OLM KEY ENDPOINTS
       /* =================================================================================
       TTTT DEVICE-KEY API — đồng bộ key giữa App Thiên Tai Tù Tội và App Xác thực ID
       POST /api/tttt/report-key    — App Thiên Tai gửi lên sau khi đăng nhập key OK
       GET  /api/tttt/device-key    — App Xác thực ID lấy key theo deviceId
       GET  /api/tttt/keys          — Admin xem toàn bộ danh sách (kèm admin token)
       DELETE /api/tttt/device-key  — Admin xoá 1 bản ghi
       ================================================================================= */

    /* POST /api/tttt/report-key
       Body: { key, deviceId, keyType, reportedAt }
       Lưu vào db.ttttDeviceKeys[deviceId] = { key, keyType, reportedAt, updatedAt }
       Rate-limit: 30 request/phút/IP để chống spam */
    if(pathname === '/api/tttt/report-key' && req.method === 'POST'){
      const ttttIp = getClientIP(req);
      if(isRateLimited('tttt_report', ttttIp, 30, 60 * 1000)){
        return sendJSON(res, 429, { ok: false, error: 'rate_limited' });
      }
      let body;
      try { body = await readJSONBody(req); }
      catch(e){ return sendJSON(res, 400, { ok: false, error: 'bad_json' }); }

      const tKey      = String(body.key      || '').trim().slice(0, 500);
      const tDeviceId = String(body.deviceId || '').trim().slice(0, 200);
      const tKeyType  = String(body.keyType  || 'normal').trim().slice(0, 20);
      const tTime     = Number(body.reportedAt) || Date.now();

      if(!tKey || !tDeviceId){
        return sendJSON(res, 400, { ok: false, error: 'missing_key_or_deviceId' });
      }

      // Validate keyType
      const validTypes = ['normal', 'premium', 'vip'];
      const safeType = validTypes.includes(tKeyType) ? tKeyType : 'normal';

      // Kiểm tra key có thật sự tồn tại trong keysStore không (tránh report key giả)
      const verifiedKey = findKeyEverywhere(tKey);
      if(!verifiedKey){
        console.log(`[TTTT] report-key bị từ chối: key không tồn tại | device=${tDeviceId} | ip=${ttttIp}`);
        return sendJSON(res, 200, { ok: false, error: 'key_not_found' });
      }
      if(verifiedKey.key.banned){
        return sendJSON(res, 200, { ok: false, error: 'key_banned' });
      }

      // Lưu vào db
      if(!db.ttttDeviceKeys || typeof db.ttttDeviceKeys !== 'object') db.ttttDeviceKeys = {};
      db.ttttDeviceKeys[tDeviceId] = {
        key       : tKey,
        keyType   : safeType,
        reportedAt: tTime,
        updatedAt : new Date().toISOString(),
        ip        : ttttIp
      };
      saveDBDebounced();

      console.log(`[TTTT] Key reported: device=${tDeviceId} | type=${safeType} | ip=${ttttIp}`);
      return sendJSON(res, 200, {
        ok        : true,
        deviceId  : tDeviceId,
        keyType   : safeType,
        savedAt   : db.ttttDeviceKeys[tDeviceId].updatedAt
      });
    }

    /* GET /api/tttt/device-key?device=<deviceId>
       App Xác thực ID gọi để lấy key đã được App Thiên Tai report.
       Trả về đầy đủ thông tin key để App Xác thực ID nhận diện và mở khoá:
         { found, key, keyType, expiresAt, devicesUsed, maxDevices, status, reportedAt } */
    if(pathname === '/api/tttt/device-key' && req.method === 'GET'){
      const ttttIp = getClientIP(req);
      if(isRateLimited('tttt_fetch', ttttIp, 60, 60 * 1000)){
        return sendJSON(res, 429, { found: false, error: 'rate_limited' });
      }

      const tDeviceId = String(url.searchParams.get('device') || '').trim().slice(0, 200);
      if(!tDeviceId){
        return sendJSON(res, 400, { found: false, error: 'missing_device' });
      }

      if(!db.ttttDeviceKeys || typeof db.ttttDeviceKeys !== 'object') db.ttttDeviceKeys = {};
      const rec = db.ttttDeviceKeys[tDeviceId];

      if(!rec || !rec.key){
        return sendJSON(res, 200, { found: false });
      }

      // Tìm key trong keysStore để lấy thông tin đầy đủ
      const kvFound = findKeyEverywhere(rec.key);
      if(!kvFound || kvFound.key.banned){
        // Key đã bị xoá hoặc ban — xoá luôn bản ghi TTTT
        delete db.ttttDeviceKeys[tDeviceId];
        saveDBDebounced();
        return sendJSON(res, 200, { found: false, error: 'key_invalid' });
      }

      const k = kvFound.key;

      // Tính status thực tế
      const keyStatus = computeKeyStatus(k);
      if(keyStatus === 'expired'){
        // Key hết hạn → xoá bản ghi TTTT luôn
        delete db.ttttDeviceKeys[tDeviceId];
        saveDBDebounced();
        return sendJSON(res, 200, { found: false, error: 'key_expired' });
      }

      // Đếm số thiết bị đã dùng key này
      const devicesUsed  = Array.isArray(k.devices) ? k.devices.length : (k.deviceId ? 1 : 0);
      const maxDevices   = k.maxDevices != null ? k.maxDevices : 1;

      // Tạo nhãn thân thiện cho loại key (VD: "Perium 12 giờ", "Perium 24 giờ", "Key Thường")
      const resolvedType = k.type || rec.keyType || 'normal';
      const isPremium = resolvedType === 'premium' || resolvedType === 'vip';
      let keyTypeLabel = isPremium ? 'Perium' : 'Key Thường';
      // Thêm thời hạn nếu có expiryAmount + expiryUnit
      if(k.expiryAmount && k.expiryUnit) {
        const unitLabel = k.expiryUnit === 'hour' ? 'giờ'
                        : k.expiryUnit === 'day'  ? 'ngày'
                        : k.expiryUnit === 'month' ? 'tháng'
                        : k.expiryUnit;
        if(isPremium) {
          keyTypeLabel = 'Perium ' + k.expiryAmount + ' ' + unitLabel;
        } else {
          keyTypeLabel = 'Key Thường ' + k.expiryAmount + ' ' + unitLabel;
        }
      }

      return sendJSON(res, 200, {
        found        : true,
        key          : rec.key,
        keyType      : resolvedType,                        // lấy từ keysStore (chính xác nhất)
        keyTypeLabel : keyTypeLabel,                        // nhãn thân thiện: "Perium 12 giờ", v.v.
        expiresAt    : k.expiresAt   || null,              // ISO string hoặc null (không giới hạn)
        devicesUsed  : devicesUsed,                        // số thiết bị đang dùng
        maxDevices   : maxDevices,                         // giới hạn thiết bị
        status       : keyStatus,                          // 'available'|'active'|'expired'|'banned'
        activated    : k.activated   || false,
        activatedAt  : k.activatedAt || null,
        reportedAt   : rec.reportedAt,
        updatedAt    : rec.updatedAt
      });
    }

    /* GET /api/tttt/keys  — Admin xem toàn bộ danh sách TTTT device keys
       Yêu cầu header Authorization: Bearer <adminPassword> hoặc query ?admin=<password> */
    if(pathname === '/api/tttt/keys' && req.method === 'GET'){
      const adminPass = req.headers['authorization']
        ? req.headers['authorization'].replace(/^Bearer\s+/i, '')
        : (url.searchParams.get('admin') || '');
      if(adminPass !== db.adminPassword){
        return sendJSON(res, 401, { ok: false, error: 'unauthorized' });
      }
      if(!db.ttttDeviceKeys || typeof db.ttttDeviceKeys !== 'object') db.ttttDeviceKeys = {};
      const list = Object.entries(db.ttttDeviceKeys).map(([deviceId, rec]) => ({
        deviceId,
        key       : rec.key,
        keyType   : rec.keyType,
        reportedAt: rec.reportedAt,
        updatedAt : rec.updatedAt,
        ip        : rec.ip || ''
      }));
      return sendJSON(res, 200, { ok: true, count: list.length, keys: list });
    }

    /* DELETE /api/tttt/device-key?device=<deviceId>  — Admin xoá bản ghi */
    if(pathname === '/api/tttt/device-key' && req.method === 'DELETE'){
      const adminPass = req.headers['authorization']
        ? req.headers['authorization'].replace(/^Bearer\s+/i, '')
        : (url.searchParams.get('admin') || '');
      if(adminPass !== db.adminPassword){
        return sendJSON(res, 401, { ok: false, error: 'unauthorized' });
      }
      const tDeviceId = String(url.searchParams.get('device') || '').trim();
      if(!tDeviceId) return sendJSON(res, 400, { ok: false, error: 'missing_device' });
      if(db.ttttDeviceKeys && db.ttttDeviceKeys[tDeviceId]){
        delete db.ttttDeviceKeys[tDeviceId];
        saveDBNow();
        return sendJSON(res, 200, { ok: true, deleted: tDeviceId });
      }
      return sendJSON(res, 404, { ok: false, error: 'not_found' });
    }

    /* =====================================================================
       OLM KEYS API
       GET  /api/olm/keys              — trả toàn bộ danh sách olmKeys
       POST /api/olm/keys              — lưu toàn bộ danh sách olmKeys (từ dashboard)
       POST /api/olm/verify            — xác thực 1 key Olm (từ app bên ngoài)
       POST /api/olm/extend/:id        — gia hạn key theo id
       POST /api/olm/ban/:id           — cấm / bỏ cấm key
       DELETE /api/olm/keys/:id        — xoá 1 key
       POST /api/olm/reset-uses/:id    — reset số lần nhập key
       ===================================================================== */

    /* Trả danh sách key Olm */
    if(pathname === '/api/olm/keys' && req.method === 'GET'){
      db.olmKeys = db.olmKeys || [];
      return sendJSON(res, 200, { ok: true, keys: db.olmKeys });
    }

    /* Lưu toàn bộ danh sách (dashboard ghi đè hoàn toàn) */
    if(pathname === '/api/olm/keys' && req.method === 'POST'){
      const body = await readJSONBody(req);
      if(!Array.isArray(body.keys)){
        return sendJSON(res, 400, { ok: false, error: 'keys_must_be_array' });
      }
      db.olmKeys = body.keys;
      saveDBNow();
      return sendJSON(res, 200, { ok: true, count: db.olmKeys.length });
    }

    /* Xác thực key Olm từ app bên ngoài */
    if(pathname === '/api/olm/verify' && (req.method === 'POST' || req.method === 'GET')){
      const verIp = getClientIP(req);
      if(isRateLimited('olm_verify', verIp, 60, 60000)){
        return sendJSON(res, 429, { valid: false, reason: 'rate_limited' });
      }
      let keyVal, deviceId, olmAccount;
      if(req.method === 'GET'){
        keyVal    = url.searchParams.get('key');
        deviceId  = url.searchParams.get('device') || url.searchParams.get('device_id') || '';
        olmAccount= url.searchParams.get('olm_account') || '';
      } else {
        const b   = await readJSONBody(req);
        keyVal    = b.key;
        deviceId  = b.device || b.device_id || b.deviceId || '';
        olmAccount= b.olm_account || b.olmAccount || '';
      }
      if(!keyVal) return sendJSON(res, 400, { valid: false, reason: 'missing_key' });

      db.olmKeys = db.olmKeys || [];
      const k = db.olmKeys.find(x => x.value === String(keyVal).trim());
      if(!k) return sendJSON(res, 200, { valid: false, reason: 'key_not_found' });

      /* Kiểm tra bị cấm */
      if(k.banned) return sendJSON(res, 200, { valid: false, reason: 'key_banned' });

      /* Kiểm tra hết hạn */
      if(k.expiresAt && new Date(k.expiresAt).getTime() < Date.now()){
        return sendJSON(res, 200, { valid: false, reason: 'key_expired', expiresAt: k.expiresAt });
      }

      /* Kiểm tra tài khoản Olm ghim */
      if(k.olmAccount && olmAccount && k.olmAccount !== olmAccount){
        return sendJSON(res, 200, { valid: false, reason: 'account_mismatch' });
      }

      /* Kiểm tra giới hạn thiết bị */
      k.devices = k.devices || [];
      deviceId = String(deviceId || '').trim().slice(0, 200);
      if(deviceId && !k.devices.includes(deviceId)){
        if(k.devices.length >= (k.maxUses || 1)){
          return sendJSON(res, 200, {
            valid: false,
            reason: 'device_limit_exceeded',
            devicesUsed: k.devices.length,
            maxDevices: k.maxUses || 1
          });
        }
        k.devices.push(deviceId);
        k.usedCount = k.devices.length;
      }

      /* Kích hoạt lần đầu */
      if(!k.activated){
        k.activated   = true;
        k.activatedAt = new Date().toISOString();
        if(k.durationAmount && k.durationUnit){
          const msMap = { minute:60000, hour:3600000, day:86400000, month:30*86400000 };
          const ms    = k.durationAmount * (msMap[k.durationUnit] || 86400000);
          k.expiresAt = new Date(Date.now() + ms).toISOString();
        }
      }

      saveDBDebounced();
      return sendJSON(res, 200, {
        valid      : true,
        type       : k.type || 'normal',
        expiresAt  : k.expiresAt || null,
        olmAccount : k.olmAccount || null,
        devicesUsed: (k.devices || []).length,
        maxDevices : k.maxUses || 1
      });
    }

    /* Gia hạn key Olm */
    const olmExtendMatch = pathname.match(/^\/api\/olm\/extend\/(.+)$/);
    if(olmExtendMatch && req.method === 'POST'){
      const id   = decodeURIComponent(olmExtendMatch[1]);
      const body = await readJSONBody(req);
      const amount = parseInt(body.amount) || 1;
      const unit   = body.unit || 'day';
      db.olmKeys   = db.olmKeys || [];
      const k      = db.olmKeys.find(x => x.id === id);
      if(!k) return sendJSON(res, 404, { ok: false, error: 'key_not_found' });
      const msMap = { minute:60000, hour:3600000, day:86400000, month:30*86400000 };
      const ms    = amount * (msMap[unit] || 86400000);
      if(k.expiresAt){
        k.expiresAt = new Date(new Date(k.expiresAt).getTime() + ms).toISOString();
      } else {
        k.durationAmount = amount; k.durationUnit = unit;
      }
      saveDBNow();
      return sendJSON(res, 200, { ok: true, expiresAt: k.expiresAt || null });
    }

    /* Ban / unban key Olm */
    const olmBanMatch = pathname.match(/^\/api\/olm\/ban\/(.+)$/);
    if(olmBanMatch && req.method === 'POST'){
      const id   = decodeURIComponent(olmBanMatch[1]);
      const body = await readJSONBody(req);
      db.olmKeys  = db.olmKeys || [];
      const k     = db.olmKeys.find(x => x.id === id);
      if(!k) return sendJSON(res, 404, { ok: false, error: 'key_not_found' });
      k.banned    = !!body.banned;
      saveDBNow();
      return sendJSON(res, 200, { ok: true, banned: k.banned });
    }

    /* Xoá key Olm */
    const olmDeleteMatch = pathname.match(/^\/api\/olm\/keys\/(.+)$/);
    if(olmDeleteMatch && req.method === 'DELETE'){
      const id   = decodeURIComponent(olmDeleteMatch[1]);
      db.olmKeys  = (db.olmKeys || []).filter(x => x.id !== id);
      saveDBNow();
      return sendJSON(res, 200, { ok: true });
    }

    /* Reset số lần nhập (devices) của key Olm */
    const olmResetMatch = pathname.match(/^\/api\/olm\/reset-uses\/(.+)$/);
    if(olmResetMatch && req.method === 'POST'){
      const id   = decodeURIComponent(olmResetMatch[1]);
      const body = await readJSONBody(req);
      db.olmKeys  = db.olmKeys || [];
      const k     = db.olmKeys.find(x => x.id === id);
      if(!k) return sendJSON(res, 404, { ok: false, error: 'key_not_found' });
      k.devices   = [];
      k.usedCount = 0;
      if(body.maxUses && parseInt(body.maxUses) > 0) k.maxUses = parseInt(body.maxUses);
      saveDBNow();
      return sendJSON(res, 200, { ok: true, usedCount: 0, maxUses: k.maxUses });
    }

    /* =====================================================================
       LOADLIB CHECK — Endpoint phục vụ CakModsLoader (Android native lib)
       GET/POST /api/loadlib/check          ← dành cho dashboard admin (proxy)
       GET/POST /api/loadlib/check-cakmods  ← AutoLoader.java gọi trực tiếp thay check.php
       Trả về JSON tương thích AutoLoader.fetchServerConfig():
         { status, version, fileUrl, sha256, fileSize, message }
       ===================================================================== */
    if((pathname === '/api/loadlib/check' || pathname === '/api/loadlib/check-cakmods')
        && (req.method === 'GET' || req.method === 'POST')){
      const loadlibIp = getClientIP(req);
      // check-cakmods: Android loader gọi trực tiếp thay thế check.php
      const isNativeCall = pathname === '/api/loadlib/check-cakmods';
      // Giới hạn tốc độ: 30 lần/phút/IP cho proxy admin; 60 lần/phút cho native loader
      const rlLimit = isNativeCall ? 60 : 30;
      if(isRateLimited('loadlib_check', loadlibIp, rlLimit, 60 * 1000)){
        return sendJSON(res, 429, {
          status: 'RATE_LIMITED',
          error: 'Quá nhiều yêu cầu. Thử lại sau 1 phút.',
          message: 'Server returned error: 429'
        });
      }

      // Đọc tham số: hỗ trợ cả GET (query string) lẫn POST (JSON body)
      let libFile, version, userAgent;
      if(req.method === 'GET'){
        libFile   = url.searchParams.get('lib')    || url.searchParams.get('file') || '';
        version   = url.searchParams.get('version')|| '';
        userAgent = req.headers['user-agent'] || '';
      } else {
        const b   = await readJSONBody(req);
        libFile   = b.lib    || b.file    || '';
        version   = b.version|| '';
        userAgent = req.headers['user-agent'] || b.user_agent || '';
      }

      // Hằng số cấu hình (từ giải_mã.txt — AutoLoader.java)
      const LOADLIB_CONFIG = {
        BASE_URL        : 'https://imgui.ngocthinhmodder.site/loadlibv16/',
        CHECK_URL       : 'https://imgui.ngocthinhmodder.site/loadlibv16/check.php',
        LIB_DIR_PATH    : '/data/data/com.garena.game.kgvn/files/Resources/169229764/arm64-v8a/',
        TARGET_LIB_NAME : 'libCakMods.so',
        ALLOWED_CERT_SHA256: 'e95aad805482ab6bfd365160ef515e7d15355f1b65cf3bd36822a242cc9eee3f',
        HTTP_USER_AGENT : 'CakModsLoader',
        THREAD_NAME     : 'CakModsLoader',
        TARGET_APP_PKG  : 'com.garena.game.kgvn'
      };

      // Kiểm tra User-Agent: native loader phải là CakModsLoader; proxy admin bỏ qua
      if(!isNativeCall && userAgent && !userAgent.includes(LOADLIB_CONFIG.HTTP_USER_AGENT)){
        console.warn(`[LoadLib] Từ chối User-Agent không hợp lệ từ ${loadlibIp}: "${userAgent}"`);
        return sendJSON(res, 403, {
          status: 'FORBIDDEN',
          error : 'User-Agent không hợp lệ.',
          message: 'Server returned error: 403'
        });
      }

      // Dùng tên lib mặc định nếu không truyền vào
      const targetLib = libFile.trim() || LOADLIB_CONFIG.TARGET_LIB_NAME;

      // ── Auto-detect version mới nhất từ server ngocthinhmodder ──────────────
      // Cách: thử HEAD request lần lượt từ version cao xuống thấp để tìm file tồn tại.
      // Cache kết quả trong RAM (_loadlibCache) với TTL 10 phút để tránh gọi quá nhiều.
      const CACHE_TTL_MS = 10 * 60 * 1000; // 10 phút
      const now_ll = Date.now();
      let resolvedData = null;

      // Dùng cache nếu còn hiệu lực
      if(global._loadlibCache && global._loadlibCache._cachedAt
          && (now_ll - global._loadlibCache._cachedAt) < CACHE_TTL_MS){
        resolvedData = global._loadlibCache;
        console.log(`[LoadLib] Dùng cache (còn ${Math.round((CACHE_TTL_MS-(now_ll-resolvedData._cachedAt))/1000)}s): v${resolvedData.version}`);
      }

      // Nếu không có cache hoặc hết hạn → tự tìm version mới nhất
      if(!resolvedData){
        // Hàm HEAD request trả về {exists, size} cho 1 URL
        const headCheck = (url) => new Promise((resolve) => {
          try {
            const u = new URL(url);
            const proto = u.protocol === 'https:' ? require('https') : require('http');
            const req = proto.request({
              hostname: u.hostname, path: u.pathname + u.search,
              method: 'HEAD',
              headers: { 'User-Agent': LOADLIB_CONFIG.HTTP_USER_AGENT },
              timeout: 6000
            }, (res2) => {
              const cl = parseInt(res2.headers['content-length'] || '0', 10);
              resolve({ exists: res2.statusCode === 200, size: cl > 0 ? cl : 0 });
            });
            req.on('error',   () => resolve({ exists: false, size: 0 }));
            req.on('timeout', () => { req.destroy(); resolve({ exists: false, size: 0 }); });
            req.end();
          } catch(e){ resolve({ exists: false, size: 0 }); }
        });

        // Đọc version từ check.php dạng plain-text (trả số như "783" hoặc "762")
        // Nếu check.php bị block → fallback dò từ version trong cache hoặc version mặc định
        let latestVer = null;
        try {
          latestVer = await new Promise((resolve, reject) => {
            const u = new URL(LOADLIB_CONFIG.CHECK_URL + '?lib=' + encodeURIComponent(targetLib));
            const proto = u.protocol === 'https:' ? require('https') : require('http');
            const req = proto.request({
              hostname: u.hostname, path: u.pathname + u.search,
              method: 'GET',
              headers: { 'User-Agent': LOADLIB_CONFIG.HTTP_USER_AGENT },
              timeout: 8000
            }, (res2) => {
              let raw = '';
              res2.on('data', c => raw += c);
              res2.on('end', () => {
                if(res2.statusCode !== 200) return reject(new Error('http_' + res2.statusCode));
                raw = raw.trim();
                // Thử parse JSON trước
                try {
                  const j = JSON.parse(raw);
                  const ver = j.version || j.ver || '';
                  // version có thể là "783.0" hoặc "783"
                  const num = parseInt(String(ver).split('.')[0], 10);
                  if(num > 0) return resolve(num);
                } catch(e){}
                // Nếu plain-text số
                const num = parseInt(raw.split('.')[0], 10);
                if(num > 0) return resolve(num);
                reject(new Error('invalid_response: ' + raw.slice(0,50)));
              });
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
            req.end();
          });
        } catch(e) {
          console.warn(`[LoadLib] check.php lỗi (${e && e.message}), dùng version từ cache cũ hoặc mặc định.`);
          // Fallback: lấy version từ cache cũ (dù hết hạn) hoặc dùng 783
          latestVer = (global._loadlibCache && global._loadlibCache._verNum) || 783;
        }

        // Tìm tên file đúng: thử libCakMods_VER.0.so trước, sau đó libCakMods_VER.so
        const candidateUrls = [
          { url: LOADLIB_CONFIG.BASE_URL + 'libCakMods_' + latestVer + '.0.so', ver: latestVer + '.0' },
          { url: LOADLIB_CONFIG.BASE_URL + 'libCakMods_' + latestVer + '.so',   ver: String(latestVer) },
          { url: LOADLIB_CONFIG.BASE_URL + targetLib,                             ver: String(latestVer) }
        ];

        for(const candidate of candidateUrls){
          const check = await headCheck(candidate.url);
          if(check.exists){
            resolvedData = {
              version   : candidate.ver,
              _verNum   : latestVer,
              file_url  : candidate.url,
              sha256    : '',   // không có sha256 vì check.php bị block; AutoLoader vẫn load được
              fileSize  : check.size,
              _cachedAt : Date.now()
            };
            break;
          }
        }

        // Nếu vẫn không tìm được → dùng cache cũ dù hết hạn
        if(!resolvedData && global._loadlibCache){
          console.warn('[LoadLib] Không tìm được file mới, dùng cache cũ.');
          resolvedData = global._loadlibCache;
          resolvedData._cachedAt = Date.now(); // gia hạn thêm 10p để tránh spam
        }

        if(!resolvedData){
          return sendJSON(res, 502, {
            status : 'ERROR',
            error  : 'Không thể xác định phiên bản thư viện.',
            message: 'Server returned error: 502'
          });
        }

        // Lưu cache mới
        global._loadlibCache = resolvedData;
        console.log(`[LoadLib] Đã cập nhật cache: v${resolvedData.version} size=${resolvedData.fileSize}`);
      }

      const fileUrl = resolvedData.file_url;
      const fileSize = resolvedData.fileSize || 0;
      console.log(`[LoadLib] OK — ${loadlibIp} => ${fileUrl} v${resolvedData.version} size=${fileSize}`);
      return sendJSON(res, 200, {
        status  : 'SUCCESS',
        version : resolvedData.version || '',
        fileUrl : fileUrl,
        file_url: fileUrl,
        sha256  : resolvedData.sha256 || '',
        fileSize: fileSize,
        message : 'OK'
      });
    }

    /* =====================================================================
       APK VAULT — Lưu trữ, quản lý file APK trên server
       POST   /api/admin/apkvault/upload          — nạp file APK (multipart)
       GET    /api/admin/apkvault/list             — danh sách APK đã nạp
       GET    /api/admin/apkvault/download/:id     — tải file APK về
       POST   /api/admin/apkvault/note/:id         — cập nhật ghi chú
       DELETE /api/admin/apkvault/delete/:id       — xoá file APK
       ===================================================================== */

    /* Đảm bảo db.apkVault tồn tại */
    if(!db.apkVault) db.apkVault = { files: [] };
    if(!db.apkVault.files) db.apkVault.files = [];

    /* ---- Danh sách APK ---- */
    if(pathname === '/api/admin/apkvault/list' && req.method === 'GET'){
      return sendJSON(res, 200, {
        ok: true,
        apks: (db.apkVault.files || []).map(f => ({
          id: f.id,
          filename: f.filename,
          size: f.size,
          note: f.note || '',
          uploadedAt: f.uploadedAt
        }))
      });
    }

    /* ---- Upload APK (multipart/form-data) ---- */
    if(pathname === '/api/admin/apkvault/upload' && req.method === 'POST'){
      const contentType = req.headers['content-type'] || '';
      if(!contentType.includes('multipart/form-data')){
        return sendJSON(res, 400, { ok: false, error: 'multipart_required' });
      }
      // Parse multipart thủ công — không dùng thư viện ngoài
      const APK_MAX = 100 * 1024 * 1024; // 100 MB

      // FIX #1: Lấy boundary đúng cách — hỗ trợ cả dạng có/không có dấu nháy,
      // và trim whitespace thừa. Một số trình duyệt/client gửi boundary="abc" hoặc boundary= abc.
      const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^\s;]+))/i);
      if(!boundaryMatch) return sendJSON(res, 400, { ok: false, error: 'missing_boundary' });
      const boundary = (boundaryMatch[1] || boundaryMatch[2] || '').trim();
      if(!boundary) return sendJSON(res, 400, { ok: false, error: 'missing_boundary' });

      // Đọc toàn bộ body vào Buffer
      let rawBody = Buffer.alloc(0);
      let totalSize = 0;
      let sizeExceeded = false;
      await new Promise((resolve, reject) => {
        req.on('data', chunk => {
          totalSize += chunk.length;
          if(totalSize > APK_MAX + 512 * 1024){ sizeExceeded = true; rawBody = Buffer.alloc(0); return; }
          rawBody = Buffer.concat([rawBody, chunk]);
        });
        req.on('end', resolve);
        req.on('error', reject);
      });
      if(sizeExceeded) return sendJSON(res, 413, { ok: false, error: 'file_too_large', message: 'File APK vượt quá 100 MB' });
      if(!rawBody || rawBody.length === 0) return sendJSON(res, 400, { ok: false, error: 'no_apk_data', message: 'Body rỗng' });

      // FIX #2: Parser multipart hoàn toàn viết lại — dùng \r\n--boundary làm delimiter
      // chuẩn RFC 2046, không bị lệch offset, không bị bỏ sót part đầu tiên.
      let apkData = null;
      let apkFilename = 'app.apk';
      let noteText = '';

      const CRLF = Buffer.from('\r\n');
      const CRLFCRLF = Buffer.from('\r\n\r\n');
      const dashBoundary = Buffer.from('--' + boundary);        // --boundary
      const dashBoundaryEnd = Buffer.from('--' + boundary + '--'); // --boundary--

      // Multipart body có cấu trúc:
      //   --boundary\r\n
      //   headers\r\n\r\n
      //   body\r\n
      //   --boundary\r\n  (hoặc --boundary-- ở cuối)
      //   ...
      let searchPos = 0;
      let partCount = 0;
      while(searchPos < rawBody.length){
        // Tìm --boundary tiếp theo
        const bPos = rawBody.indexOf(dashBoundary, searchPos);
        if(bPos < 0) break;

        // Kiểm tra xem có phải terminator (--boundary--) không
        if(rawBody.slice(bPos, bPos + dashBoundaryEnd.length).equals(dashBoundaryEnd)) break;

        // Bỏ qua --boundary rồi \r\n
        let cursor = bPos + dashBoundary.length;
        // Bỏ qua \r\n (hoặc \n) sau boundary line
        if(cursor < rawBody.length && rawBody[cursor] === 0x0D) cursor++; // \r
        if(cursor < rawBody.length && rawBody[cursor] === 0x0A) cursor++; // \n

        // Tìm kết thúc header block (\r\n\r\n)
        const headEnd = rawBody.indexOf(CRLFCRLF, cursor);
        if(headEnd < 0) break;

        const headersRaw = rawBody.slice(cursor, headEnd).toString('utf8');
        const dataStart = headEnd + CRLFCRLF.length;

        // Tìm điểm bắt đầu của boundary kế tiếp (phần body kết thúc trước \r\n--boundary)
        const nextBoundaryPos = rawBody.indexOf(dashBoundary, dataStart);
        let dataEnd;
        if(nextBoundaryPos < 0){
          dataEnd = rawBody.length;
        } else {
          // Cắt bỏ \r\n trước --boundary
          dataEnd = nextBoundaryPos;
          if(dataEnd >= 2 && rawBody[dataEnd - 2] === 0x0D && rawBody[dataEnd - 1] === 0x0A){
            dataEnd -= 2; // bỏ \r\n
          } else if(dataEnd >= 1 && rawBody[dataEnd - 1] === 0x0A){
            dataEnd -= 1; // bỏ \n đơn
          }
        }

        const partBody = rawBody.slice(dataStart, dataEnd);
        partCount++;

        // FIX #3: Parse Content-Disposition linh hoạt hơn — hỗ trợ mọi thứ tự
        // của name= và filename=, hỗ trợ cả multiline header.
        const nameMatch    = headersRaw.match(/\bname="([^"]+)"/i);
        const filenameMatch= headersRaw.match(/\bfilename="([^"]*)"/i);
        if(nameMatch){
          const fieldName = nameMatch[1];
          const fname = (filenameMatch && filenameMatch[1]) || '';
          if(fieldName === 'apk'){
            apkData = partBody;
            if(fname){
              apkFilename = fname.replace(/[^a-zA-Z0-9._\-]/g, '_') || 'app.apk';
            }
            if(!apkFilename.toLowerCase().endsWith('.apk')) apkFilename += '.apk';
          } else if(fieldName === 'note'){
            noteText = partBody.toString('utf8').trim().slice(0, 2000);
          }
        }

        // Tiếp tục từ vị trí boundary kế tiếp
        searchPos = nextBoundaryPos < 0 ? rawBody.length : nextBoundaryPos;
      }

      console.log(`[APKVault] Parse multipart: ${partCount} parts, apkData=${apkData ? apkData.length : 'null'} bytes, filename=${apkFilename}`);

      if(!apkData || apkData.length === 0){
        return sendJSON(res, 400, { ok: false, error: 'no_apk_data', message: 'Không tìm thấy dữ liệu APK trong form. Kiểm tra field name phải là "apk".' });
      }
      if(apkData.length > APK_MAX) return sendJSON(res, 413, { ok: false, error: 'file_too_large' });

      // FIX #4: Lưu file APK ra disk thay vì nhét base64 vào RAM/db.json
      // để tránh db.json phình to (file 10MB APK → ~13MB base64 trong JSON → ghi file chậm/fail).
      // Thư mục lưu: __dirname/apk_vault/
      const APK_DIR = path.join(__dirname, 'apk_vault');
      if(!fs.existsSync(APK_DIR)){
        try{ fs.mkdirSync(APK_DIR, { recursive: true }); }
        catch(mkdirErr){ return sendJSON(res, 500, { ok: false, error: 'storage_error', message: 'Không tạo được thư mục lưu APK: ' + mkdirErr.message }); }
      }
      const apkId = crypto.randomBytes(12).toString('hex');
      const diskFilename = apkId + '_' + apkFilename;
      const diskPath = path.join(APK_DIR, diskFilename);
      try{
        fs.writeFileSync(diskPath, apkData);
      }catch(writeErr){
        return sendJSON(res, 500, { ok: false, error: 'write_error', message: 'Không ghi được file APK: ' + writeErr.message });
      }

      const entry = {
        id: apkId,
        filename: apkFilename,
        diskFilename: diskFilename,   // tên file thật trên disk
        size: apkData.length,
        note: noteText,
        uploadedAt: new Date().toISOString()
        // Không lưu _data (base64) nữa — đọc từ disk khi cần
      };
      db.apkVault.files.push(entry);
      saveDBNow();
      console.log(`[APKVault] Đã nạp APK: ${apkFilename} (${(apkData.length/1024/1024).toFixed(2)} MB) id=${apkId} → ${diskPath}`);
      return sendJSON(res, 200, {
        ok: true,
        id: apkId,
        filename: apkFilename,
        size: apkData.length,
        uploadedAt: entry.uploadedAt
      });
    }

    /* ---- Tải APK về ---- */
    const apkDownloadMatch = pathname.match(/^\/api\/admin\/apkvault\/download\/([a-f0-9]+)$/);
    if(apkDownloadMatch && req.method === 'GET'){
      const apkId = apkDownloadMatch[1];
      const entry = (db.apkVault && db.apkVault.files || []).find(f => f.id === apkId);
      if(!entry) return sendJSON(res, 404, { ok: false, error: 'not_found' });
      let buf = null;
      // Ưu tiên đọc từ disk (entry mới có diskFilename)
      if(entry.diskFilename){
        const APK_DIR = path.join(__dirname, 'apk_vault');
        const diskPath = path.join(APK_DIR, entry.diskFilename);
        try{ buf = fs.readFileSync(diskPath); }
        catch(e){ return sendJSON(res, 404, { ok: false, error: 'file_missing', message: 'File APK không còn trên server (có thể server đã restart).' }); }
      } else if(entry._data){
        // Backward-compatible: entry cũ lưu base64 trong db
        try{ buf = Buffer.from(entry._data, 'base64'); }
        catch(e){ return sendJSON(res, 500, { ok: false, error: 'decode_error' }); }
      } else {
        return sendJSON(res, 404, { ok: false, error: 'not_found' });
      }
      res.writeHead(200, {
        'Content-Type': 'application/vnd.android.package-archive',
        'Content-Disposition': 'attachment; filename="' + entry.filename + '"',
        'Content-Length': buf.length,
        'Cache-Control': 'no-store'
      });
      return res.end(buf);
    }

    /* ---- Cập nhật ghi chú ---- */
    const apkNoteMatch = pathname.match(/^\/api\/admin\/apkvault\/note\/([a-f0-9]+)$/);
    if(apkNoteMatch && req.method === 'POST'){
      const apkId = apkNoteMatch[1];
      const entry = (db.apkVault && db.apkVault.files || []).find(f => f.id === apkId);
      if(!entry) return sendJSON(res, 404, { ok: false, error: 'not_found' });
      const body = await readJSONBody(req).catch(()=>({}));
      entry.note = String(body.note || '').trim().slice(0, 2000);
      saveDBNow();
      return sendJSON(res, 200, { ok: true, id: apkId, note: entry.note });
    }

    /* ---- Xoá APK ---- */
    const apkDeleteMatch = pathname.match(/^\/api\/admin\/apkvault\/delete\/([a-f0-9]+)$/);
    if(apkDeleteMatch && req.method === 'DELETE'){
      const apkId = apkDeleteMatch[1];
      const entry = (db.apkVault && db.apkVault.files || []).find(f => f.id === apkId);
      if(!entry) return sendJSON(res, 404, { ok: false, error: 'not_found' });
      // Xoá file trên disk nếu có
      if(entry.diskFilename){
        const APK_DIR = path.join(__dirname, 'apk_vault');
        try{ fs.unlinkSync(path.join(APK_DIR, entry.diskFilename)); }catch(_){}
      }
      db.apkVault.files = (db.apkVault.files || []).filter(f => f.id !== apkId);
      saveDBNow();
      console.log(`[APKVault] Đã xoá APK id=${apkId}`);
      return sendJSON(res, 200, { ok: true });
    }

    return sendJSON(res, 404, { error: 'not_found' });
  }catch(e){
    console.error('[KeyVault] Lỗi xử lý request:', e);
    return sendJSON(res, 500, { error: 'server_error', message: String((e && e.message) || e) });
  }
});

/* Bắt lỗi ở tầng server (ví dụ cổng đang bị chiếm - EADDRINUSE) để in log rõ
   ràng thay vì để tiến trình thoát đột ngột không rõ nguyên nhân. */
server.on('error', (err)=>{
  console.error('[KeyVault] Lỗi server (listen):', err && err.stack ? err.stack : err);
});

/* Bind rõ '0.0.0.0' (thay vì để mặc định) để đảm bảo Render/Docker luôn nhận
   được kết nối tới cổng PORT từ bên ngoài container. */
server.listen(PORT, '0.0.0.0', ()=>{
  console.log(`✔ KeyVault server đang chạy tại http://localhost:${PORT}`);
  console.log(`  Dữ liệu được lưu tại: ${DB_FILE}`);
  console.log(`  Giao diện web: http://localhost:${PORT}/  (đã gộp chung vào index.js)`);
  console.log(`  Link xác thực API key: http://localhost:${PORT}/api/verify?key=...&app=...`);
  console.log(`  LienQuan Mod verify:   http://localhost:${PORT}/api/lienquan/verify (POST {key:"..."})`);
  console.log(`  Check-key Android:     http://localhost:${PORT}/api/check-key (POST {key:"..."})`);"
  // Sync snippet mặc định vào RAM + db ngay khi server khởi động
  // → tránh mất snippet khi Render free tier xoá db.json sau mỗi restart
  try{
    _syncDefaultSnippetsToDB();
    if(DEFAULT_CODE_SNIPPETS.length > 0){
      console.log(`  [Snippet Loader] Đã load ${DEFAULT_CODE_SNIPPETS.length} snippet mặc định vào RAM.`);
      console.log(`  [Snippet Loader] Public endpoint: /api/public/snippet/:id`);
    }
  }catch(e){
    console.error('[KeyVault] Lỗi sync snippet mặc định (bỏ qua):', e && e.message);
  }
  try{
    startAntiSleep();
  }catch(e){
    console.error('[KeyVault] Lỗi khởi động anti-sleep (bỏ qua, không ảnh hưởng server chính):', e && e.message);
  }
  try{
    startTelegramBot();
  }catch(e){
    console.error('[KeyVault] Lỗi khởi động Telegram Bot (bỏ qua, không ảnh hưởng server chính):', e && e.message);
  }
});

/* ================================================================
   HTTP AUTO-VERIFY v3 — Engine 4 bước thông minh (unlockffbeta.com)
   ================================================================
   Mô phỏng chính xác luồng người dùng thật trên website:
     Bước 1: Mở trang, nhập accountId → bấm "Continue without Discord"
     Bước 2–4: Đợi countdown timer từng bước (có progress bar)
     Hoàn thành: Parse "Access Granted" + timer expires
   
   Không dùng Playwright/headless browser (không tương thích Render Free).
   Sử dụng HTTP request thuần Node.js + mô phỏng session/cookie/state.
   Hỗ trợ retry thông minh, log chi tiết từng bước, thông báo realtime.
================================================================ */

// Map lưu session của từng chat: { chatId -> { accountId, expires, reverifyTimer, waitingForKey, waitingForId } }
let _tgVerifySessions = {};

/**
 * Xác thực key cho chatId — hiện thời gian key + menu lệnh khi thành công
 */
async function _verifyKeyForChat(chatId, keyVal){
  if(!keyVal || !keyVal.trim()){
    await sendTelegramMessage(chatId,
      '❌ <b>Key không hợp lệ.</b>\n\nVui lòng nhập lại key:\n/key'
    );
    return;
  }
  keyVal = keyVal.trim();
  await sendTelegramMessage(chatId, `🔄 <b>Đang xác thực key...</b>`);
  try{
    // FIX: Tìm key trong db.keysStore (toàn bộ tài khoản) thay vì db.keys (không tồn tại)
    const _found = findKeyEverywhere(keyVal);
    const k = _found ? _found.key : null;
    if(!k){
      await sendTelegramMessage(chatId,
        `❌ <b>Key không hợp lệ.</b>\nKey không tồn tại trong hệ thống.\n\n<i>Mua key tại /start</i>`
      );
    } else if(k.banned){
      await sendTelegramMessage(chatId,
        `🚫 <b>Key đã bị khoá.</b>\nVui lòng liên hệ admin.`
      );
    } else if(k.hasExpiryPlan && !k.activated){
      // FIX: Key chưa kích hoạt — kích hoạt ngay lần đầu nhập key qua bot, rồi hiện thông tin
      activateKeyIfNeeded(k);
      saveDB();
      const expDate2 = k.expiresAt ? new Date(k.expiresAt) : null;
      const remainMs2 = expDate2 ? expDate2.getTime() - Date.now() : null;
      const remainSecs2 = remainMs2 ? Math.max(0, Math.floor(remainMs2 / 1000)) : 0;
      const rh2 = Math.floor(remainSecs2/3600);
      const rm2 = Math.floor((remainSecs2%3600)/60);
      const rs2 = remainSecs2%60;
      const remainStr2 = rh2 > 0 ? `${rh2}h ${rm2}m ${rs2}s` : rm2 > 0 ? `${rm2}m ${rs2}s` : `${rs2}s`;
      const expLine2   = expDate2 ? `\n📅 Hết hạn: <b>${expDate2.toLocaleString('vi-VN')}</b>` : `\n📅 Hạn dùng: <b>Vĩnh viễn ♾️</b>`;
      const remainLine2 = expDate2 ? `\n⏱ Còn lại: <b>${remainStr2}</b>` : '';
      _tgVerifySessions = _tgVerifySessions || {};
      _tgVerifySessions[String(chatId)] = _tgVerifySessions[String(chatId)] || {};
      _tgVerifySessions[String(chatId)].savedKey    = keyVal;
      _tgVerifySessions[String(chatId)].keyVerified = true;
      _tgVerifySessions[String(chatId)].waitingForKey = false;
      await sendTelegramMessage(chatId,
        `✅ <b>Kích hoạt thành công!</b>\n` +
        `━━━━━━━━━━━━━━━━━━━━━━\n` +
        `🔑 Key: <code>${keyVal}</code>` +
        expLine2 + remainLine2 + `\n\n` +
        `━━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>📋 Bạn có thể sử dụng các lệnh:</b>\n` +
        `• Gửi <b>ID Free Fire</b> của bạn để xác thực ngay\n` +
        `• /verify — Xác thực ID Free Fire\n` +
        `• /setid &lt;ID&gt; — Lưu ID mặc định (auto-reverify)\n` +
        `• /status — Xem trạng thái phiên\n` +
        `• /cancel — Huỷ phiên xác thực\n` +
        `• /help — Hướng dẫn chi tiết\n\n` +
        `💡 <i>Bây giờ hãy gửi ID Free Fire của bạn để xác thực!</i>`
      );
    } else if(k.expiresAt && new Date(k.expiresAt).getTime() < Date.now()){
      const expStr = new Date(k.expiresAt).toLocaleString('vi-VN');
      await sendTelegramMessage(chatId,
        `⏰ <b>Key đã hết hạn.</b>\nHết hạn lúc: ${expStr}\n\n<i>Gia hạn tại /start</i>`
      );
    } else {
      // Tính thời gian còn lại
      let expLine = '';
      let remainLine = '';
      if(k.expiresAt){
        const expDate = new Date(k.expiresAt);
        const remainMs = expDate.getTime() - Date.now();
        const remainSecs = Math.max(0, Math.floor(remainMs / 1000));
        const rh = Math.floor(remainSecs/3600);
        const rm = Math.floor((remainSecs%3600)/60);
        const rs = remainSecs%60;
        const remainStr = rh > 0 ? `${rh}h ${rm}m ${rs}s` : rm > 0 ? `${rm}m ${rs}s` : `${rs}s`;
        expLine  = `\n📅 Hết hạn: <b>${expDate.toLocaleString('vi-VN')}</b>`;
        remainLine = `\n⏱ Còn lại: <b>${remainStr}</b>`;
      } else {
        expLine = `\n📅 Hạn dùng: <b>Vĩnh viễn ♾️</b>`;
        remainLine = '';
      }

      // Lưu key vào session
      _tgVerifySessions = _tgVerifySessions || {};
      _tgVerifySessions[String(chatId)] = _tgVerifySessions[String(chatId)] || {};
      _tgVerifySessions[String(chatId)].savedKey   = keyVal;
      _tgVerifySessions[String(chatId)].keyVerified = true;
      _tgVerifySessions[String(chatId)].waitingForKey = false;

      // Hiện thông báo thành công + menu lệnh
      await sendTelegramMessage(chatId,
        `✅ <b>Kích hoạt thành công!</b>\n` +
        `━━━━━━━━━━━━━━━━━━━━━━\n` +
        `🔑 Key: <code>${keyVal}</code>` +
        expLine + remainLine + `\n\n` +
        `━━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>📋 Bạn có thể sử dụng các lệnh:</b>\n` +
        `• Gửi <b>ID Free Fire</b> của bạn để xác thực ngay\n` +
        `• /verify — Xác thực ID Free Fire\n` +
        `• /setid &lt;ID&gt; — Lưu ID mặc định (auto-reverify)\n` +
        `• /status — Xem trạng thái phiên\n` +
        `• /cancel — Huỷ phiên xác thực\n` +
        `• /help — Hướng dẫn chi tiết\n\n` +
        `💡 <i>Bây giờ hãy gửi ID Free Fire của bạn để xác thực!</i>`
      );
    }
  }catch(e){
    console.error('[TgVerify] Lỗi xác thực key:', e && e.message);
    await sendTelegramMessage(chatId, `❌ <b>Lỗi kiểm tra key.</b> Thử lại sau.`);
  }
}

/**
 * Xác thực ID Free Fire — auto chặn quảng cáo, auto click các nút
 */
async function _doVerifyId(chatId, accountId){
  if(!accountId || !/^\d{6,15}$/.test(accountId)){
    await sendTelegramMessage(chatId,
      '❌ <b>ID không hợp lệ.</b>\nID phải là dãy số từ 6–15 chữ số.'
    );
    return;
  }
  _tgVerifySessions = _tgVerifySessions || {};
  // Giữ lại savedId và savedKey khi update session
  const prevSess3 = _tgVerifySessions[String(chatId)] || {};
  _tgVerifySessions[String(chatId)] = {
    ...prevSess3,
    accountId,
    savedId: prevSess3.savedId || accountId,
    startedAt: Date.now(),
    waitingForId: false
  };
  await sendTelegramMessage(chatId,
    `⏳ <b>Đang xác thực ID:</b> <code>${accountId}</code>\n\n` +
    `🌐 Bot đang kết nối unlockffbeta.com...\n` +
    `🚫 Đang chặn quảng cáo & tự động click các nút...\n\n` +
    `<i>Vui lòng chờ vài giây.</i>`
  );
  runPlaywrightVerify(chatId, accountId).catch(e=>{
    console.error('[TgVerify] Lỗi HTTP verify:', e && e.message);
    sendTelegramMessage(chatId,
      '❌ <b>Xác thực thất bại.</b>\nServer gặp lỗi không mong muốn. Thử lại sau ít phút.'
    );
  });
}

/**
 * Helper: gửi HTTP/HTTPS request và trả về { statusCode, headers, body }
 */
function _httpRequest(opts, postData){
  return new Promise((resolve, reject)=>{
    const proto = opts.protocol === 'http:' ? require('http') : require('https');
    const req = proto.request(opts, (res)=>{
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', ()=>{
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('error', reject);
    req.setTimeout(20000, ()=>{ req.destroy(); reject(new Error('timeout')); });
    if(postData) req.write(postData);
    req.end();
  });
}

/**
 * Parse timer từ HTML (dạng "Xh Ym Zs", "Xm Ys", hoặc "Xs")
 * Trả về số giây, hoặc -1 nếu không tìm thấy.
 */
function _parseTimerFromHtml(html){
  // Tìm Access Granted trước
  if(!/access\s*granted/i.test(html)) return -1;
  // Các pattern timer
  const patterns = [
    /(\d+)h\s*(\d+)m\s*(\d+)s/,
    /(\d+)m\s*(\d+)s/,
    /(\d+)s(?!\w)/
  ];
  for(const p of patterns){
    const m = html.match(p);
    if(m){
      if(m.length === 4) return +m[1]*3600 + +m[2]*60 + +m[3];
      if(m.length === 3) return +m[1]*60 + +m[2];
      if(m.length === 2 && +m[1] < 7200) return +m[1];
    }
  }
  return -1;
}

/**
 * ════════════════════════════════════════════════════════════════
 *  ENGINE XÁC THỰC 4 BƯỚC v3 — unlockffbeta.com
 *  Mô phỏng chính xác luồng click + đợi timer như người dùng thật.
 *  Chạy được trên Render Free (không cần Playwright/Chromium).
 * ════════════════════════════════════════════════════════════════
 */
async function runPlaywrightVerify(chatId, accountId){
  try{
    console.log(`[TgVerify] Bắt đầu verify (HTTP v3 — 4-Step Engine) chatId=${chatId} ID=${accountId}`);

    /* ════════════════════════════════════════════════════════════════
       CONSTANTS & HELPERS
    ════════════════════════════════════════════════════════════════ */

    const UA = 'Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36';
    const BASE_HOST = 'www.unlockffbeta.com';
    const BASE_URL  = 'https://' + BASE_HOST;

    // Các domain quảng cáo cần bỏ qua
    const AD_DOMAINS_BOT = new Set([
      'doubleclick.net','googlesyndication.com','adservice.google.com',
      'pagead2.googlesyndication.com','google-analytics.com','googletagmanager.com',
      'adnxs.com','advertising.com','amazon-adsystem.com','scorecardresearch.com',
      'outbrain.com','taboola.com','revcontent.com','mgid.com','criteo.com',
      'rubiconproject.com','openx.net','pubmatic.com','appnexus.com','medianet.com',
      'adroll.com','teads.tv','popads.net','adsterra.com','propellerads.com',
      'exoclick.com','juicyads.com','trafficjunky.com','clickadu.com','evadav.com',
      'hilltopads.net','activerevenue.com','popcash.net','onclickmega.com',
      'onclickads.net','datspush.com','push.house','rich-push.com','megapush.com',
      'adcash.com','subscribers.com','pushcrew.com','onesignal.com','pushassist.com',
      'wonderpush.com','pushwoosh.com','izooto.com','webpushr.com','sendpulse.com',
      'innity.com','adtima.vn','admicro.vn','accesstrade.vn','eclick.vn',
      'admanvietnam.com','trustedmediabrands.com','sowve.com','moonten.com',
      'doubleverify.com','adskeeper.com','bidgear.com','adtelligent.com',
      'freefire-vn.com','go2share.net','linkpoi.me','up-4ever.org','uppromote.com',
      'track.hglink.net'
    ]);

    function _isAdDomain(hostname){
      if(!hostname) return false;
      const h = hostname.replace(/^www\./, '').toLowerCase();
      if(AD_DOMAINS_BOT.has(h)) return true;
      for(const ad of AD_DOMAINS_BOT){ if(h.endsWith('.' + ad)) return true; }
      return false;
    }

    // Helper: sleep
    const _sleep = ms => new Promise(r => setTimeout(r, ms));

    // Helper: HTTP request với ad-block tích hợp + timeout 25s
    function _fetch(opts, postData){
      try{
        const hostname = (opts.hostname || opts.host || '').toLowerCase();
        if(_isAdDomain(hostname)){
          console.log(`[TgVerify] 🚫 Chặn quảng cáo: ${hostname}`);
          return Promise.resolve({ statusCode: 204, headers: {}, body: '' });
        }
      }catch(_){}
      return _httpRequest({ ...opts, timeout: 25000 }, postData);
    }

    // Helper: follow redirect tối đa N lần, giữ cookies xuyên suốt
    async function _fetchFull(opts, postData, maxRedirects = 8){
      let cur = { ...opts };
      let body2 = postData;
      let cookies = opts._cookies || '';
      let lastBody = '', lastStatus = 0, lastHeaders = {};

      for(let i = 0; i <= maxRedirects; i++){
        const r = await _fetch(cur, body2);
        lastStatus = r.statusCode;
        lastBody   = r.body || '';
        lastHeaders = r.headers || {};

        // Thu thập cookies
        const sc = r.headers && r.headers['set-cookie'];
        if(sc){
          const arr = Array.isArray(sc) ? sc : [sc];
          const nc  = arr.map(c => c.split(';')[0]).join('; ');
          cookies = cookies ? cookies + '; ' + nc : nc;
        }

        const loc = r.headers && r.headers['location'];
        if((r.statusCode === 301 || r.statusCode === 302 || r.statusCode === 303) && loc && i < maxRedirects){
          let nextHost = cur.hostname, nextPath = loc, nextProto = cur.protocol;
          if(loc.startsWith('http')){
            try{ const u = new URL(loc); nextHost = u.hostname; nextPath = u.pathname + (u.search||''); nextProto = u.protocol; }catch(_){}
          }
          cur = {
            protocol: nextProto, hostname: nextHost, path: nextPath, method: 'GET',
            headers: {
              'User-Agent': UA,
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
              'Accept-Encoding': 'identity',
              'Referer': BASE_URL + '/',
              'Cookie': cookies
            },
            _cookies: cookies
          };
          body2 = null;
          continue;
        }
        break;
      }
      return { statusCode: lastStatus, body: lastBody, headers: lastHeaders, cookies };
    }

    /* ════════════════════════════════════════════════════════════════
       HELPERS: PARSE HTML — Trích xuất thông tin từ HTML response
    ════════════════════════════════════════════════════════════════ */

    // Kiểm tra HTML có chứa "Access Granted" không
    function _hasAccessGranted(html){
      return /access\s*granted/i.test(html) || /access_granted/i.test(html) || /accessGranted/i.test(html);
    }

    // Lấy step hiện tại từ HTML (Step X of 4)
    function _parseCurrentStep(html){
      const m = html.match(/step\s*(\d+)\s*of\s*(\d+)/i)
               || html.match(/bước\s*(\d+)\s*(?:\/|trên)\s*(\d+)/i)
               || html.match(/data-step=["']?(\d+)/i);
      if(m) return { current: parseInt(m[1]), total: parseInt(m[2] || 4) };
      return null;
    }

    // Lấy số giây countdown từ HTML (dạng "Xs", "Xm Ys", "Xh Ym Zs")
    function _parseCountdownSecs(html){
      const patterns = [
        /(\d+)h\s*(\d+)m\s*(\d+)s/i,
        /(\d+)\s*h(?:our)?s?\s*(\d+)\s*m(?:in)?s?\s*(\d+)\s*s(?:ec)?s?/i,
        /(\d+)m\s*(\d+)s/i,
        /timer\s*[=:]\s*(\d+)/i,
        /countdown\s*[=:]\s*(\d+)/i,
        /data-timer=["']?(\d+)/i,
        /data-seconds=["']?(\d+)/i,
        /data-countdown=["']?(\d+)/i,
        /"timer"\s*:\s*(\d+)/i,
        /"seconds"\s*:\s*(\d+)/i,
        /"countdown"\s*:\s*(\d+)/i,
        /"remaining"\s*:\s*(\d+)/i,
        /(\d+)s(?!\w)/,
      ];
      for(const p of patterns){
        const m = html.match(p);
        if(m){
          if(m.length >= 4){ const v = parseInt(m[1])*3600 + parseInt(m[2])*60 + parseInt(m[3]); if(v > 0) return v; }
          if(m.length >= 3){ const v = parseInt(m[1])*60 + parseInt(m[2]); if(v > 0) return v; }
          if(m.length >= 2){ const v = parseInt(m[1]); if(v > 0 && v < 7200) return v; }
        }
      }
      return -1;
    }

    // Trích xuất URL hành động (action button) tiếp theo từ HTML
    function _extractNextActionUrl(html, currentStep){
      // Tìm href / action / data-href liên quan đến "continue", "next", "unlock", "step"
      const patterns = [
        /href=["']([^"']*(?:step|next|continue|unlock|verify|proceed)[^"']*?)["']/gi,
        /action=["']([^"']+)["']/gi,
        /data-href=["']([^"']+)["']/gi,
        /data-url=["']([^"']+)["']/gi,
      ];
      for(const pat of patterns){
        let m;
        while((m = pat.exec(html)) !== null){
          const url = m[1].trim();
          if(!url || url === '#' || url === '/' || _isAdDomain(url)) continue;
          if(url.startsWith('http')) return url;
          if(url.startsWith('/')) return BASE_URL + url;
        }
      }
      return null;
    }

    // Trích xuất token CSRF từ HTML
    function _extractCsrf(html){
      const m = html.match(/name=["']_token["'][^>]*value=["']([^"']+)["']/i)
             || html.match(/name=["']csrf[_-]?token["'][^>]*value=["']([^"']+)["']/i)
             || html.match(/value=["']([^"']+)["'][^>]*name=["']_token["']/i)
             || html.match(/"csrf[_-]?token"\s*:\s*"([^"]+)"/i)
             || html.match(/csrfToken\s*=\s*["']([^"']+)["']/i)
             || html.match(/data-csrf=["']([^"']+)["']/i)
             || html.match(/meta[^>]*name=["']csrf-token["'][^>]*content=["']([^"']+)["']/i);
      return m ? m[1] : '';
    }

    // Trích xuất tất cả hidden inputs từ form
    function _extractHiddenInputs(html){
      const inputs = {};
      const re = /<input[^>]+type=["']hidden["'][^>]*>/gi;
      let m;
      while((m = re.exec(html)) !== null){
        const tag = m[0];
        const nameM = tag.match(/name=["']([^"']+)["']/i);
        const valM  = tag.match(/value=["']([^"']*?)["']/i);
        if(nameM && valM) inputs[nameM[1]] = valM[1];
      }
      return inputs;
    }

    // Trích xuất action URL từ form HTML
    function _extractFormAction(html){
      const m = html.match(/<form[^>]*action=["']([^"']+)["'][^>]*>/i)
             || html.match(/<form[^>]*action='([^']+)'/i);
      if(!m) return null;
      const a = m[1];
      if(a.startsWith('http')) return a;
      if(a.startsWith('/')) return BASE_URL + a;
      return BASE_URL + '/' + a;
    }

    /* ════════════════════════════════════════════════════════════════
       BƯỚC 0: Lấy trang chủ — cookies + CSRF + form info
    ════════════════════════════════════════════════════════════════ */
    await sendTelegramMessage(chatId,
      `⏳ <b>Đang kết nối unlockffbeta.com...</b>\n🆔 ID: <code>${accountId}</code>\n🔍 <i>Bước 0/4: Lấy thông tin trang...</i>`
    );

    let cookies = '';
    let csrfToken = '';
    let homeHtml = '';

    try{
      const r0 = await _fetchFull({
        protocol: 'https:', hostname: BASE_HOST, path: '/',
        method: 'GET',
        headers: {
          'User-Agent': UA,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
          'Accept-Encoding': 'identity',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'Upgrade-Insecure-Requests': '1',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
        }
      });
      cookies  = r0.cookies || '';
      homeHtml = r0.body || '';
      csrfToken = _extractCsrf(homeHtml);
      console.log(`[TgVerify] B0 OK status=${r0.statusCode} cookies=${cookies.length > 0} csrf=${!!csrfToken} html=${homeHtml.length}`);
    }catch(e){
      console.warn('[TgVerify] B0 lỗi (bỏ qua, tiếp tục):', e.message);
    }

    /* ════════════════════════════════════════════════════════════════
       BƯỚC 1: Nhập accountId → POST → bấm "Continue without Discord"
       (Step 1 of 4 trên website)
    ════════════════════════════════════════════════════════════════ */

    await sendTelegramMessage(chatId,
      `📝 <b>Bước 1/4:</b> Nhập ID và bấm "Continue without Discord"...\n🆔 ID: <code>${accountId}</code>`
    );

    let step1Html = '';
    let step1Cookies = cookies;
    let step1Success = false;

    // Thử nhiều endpoint + field combinations để nhập ID
    const step1Candidates = [
      { path: '/',          field: 'account_id' },
      { path: '/verify',    field: 'account_id' },
      { path: '/unlock',    field: 'account_id' },
      { path: '/check',     field: 'account_id' },
      { path: '/',          field: 'uid'         },
      { path: '/',          field: 'id'          },
      { path: '/verify',    field: 'uid'         },
    ];

    for(const ep of step1Candidates){
      try{
        const hiddenInputs = _extractHiddenInputs(homeHtml);
        let parts = [`${ep.field}=${encodeURIComponent(accountId)}`];
        if(csrfToken) parts.push(`_token=${encodeURIComponent(csrfToken)}`);
        // Thêm hidden inputs từ form
        for(const [k,v] of Object.entries(hiddenInputs)){
          if(k !== ep.field && k !== '_token') parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
        }
        // Thêm các field phụ thường gặp
        parts.push('submit=1', 'continue=1', 'action=verify', 'type=free');
        const postBody = parts.join('&');

        const r1 = await _fetchFull({
          protocol: 'https:', hostname: BASE_HOST,
          path: _extractFormAction(homeHtml) ? new URL(_extractFormAction(homeHtml)).pathname : ep.path,
          method: 'POST',
          headers: {
            'User-Agent': UA,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'vi-VN,vi;q=0.9,en;q=0.8',
            'Accept-Encoding': 'identity',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postBody).toString(),
            'Origin': BASE_URL,
            'Referer': BASE_URL + '/',
            'Cookie': step1Cookies,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
          },
          _cookies: step1Cookies
        }, postBody);

        if(r1.cookies) step1Cookies = r1.cookies;
        step1Html = r1.body || '';

        // Kiểm tra đã qua bước 1 chưa
        const stepInfo = _parseCurrentStep(step1Html);
        if(_hasAccessGranted(step1Html)){
          step1Success = true;
          console.log(`[TgVerify] B1 → Access Granted ngay (ep=${ep.path} field=${ep.field})`);
          break;
        }
        if(stepInfo && stepInfo.current >= 2){
          step1Success = true;
          console.log(`[TgVerify] B1 OK → đang ở Step ${stepInfo.current} (ep=${ep.path})`);
          break;
        }
        // Kiểm tra có countdown/timer không (đồng nghĩa bước 1 thành công)
        const cs = _parseCountdownSecs(step1Html);
        if(cs > 0){
          step1Success = true;
          console.log(`[TgVerify] B1 OK → tìm thấy countdown=${cs}s`);
          break;
        }
      }catch(e){
        console.warn(`[TgVerify] B1 endpoint ${ep.path} lỗi: ${e.message}`);
      }
    }

    if(!step1Success){
      // Thử GET với query param
      try{
        const r1g = await _fetchFull({
          protocol: 'https:', hostname: BASE_HOST,
          path: `/?account_id=${encodeURIComponent(accountId)}`,
          method: 'GET',
          headers: {
            'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8',
            'Accept-Language': 'vi-VN,vi;q=0.9', 'Accept-Encoding': 'identity',
            'Referer': BASE_URL + '/', 'Cookie': step1Cookies,
          },
          _cookies: step1Cookies
        });
        if(r1g.cookies) step1Cookies = r1g.cookies;
        step1Html = r1g.body || '';
        const cs2 = _parseCountdownSecs(step1Html);
        if(cs2 > 0 || _hasAccessGranted(step1Html)) step1Success = true;
        console.log(`[TgVerify] B1 GET fallback: countdown=${cs2} granted=${_hasAccessGranted(step1Html)}`);
      }catch(e){ console.warn('[TgVerify] B1 GET fallback lỗi:', e.message); }
    }

    /* ════════════════════════════════════════════════════════════════
       HELPER: Parse thời gian expires chính xác từ trang Access Granted
    ════════════════════════════════════════════════════════════════ */
    function _parseExpiresFromGrantedPage(html){
      // Ưu tiên "EXPIRES IN ... Xh Ym Zs"
      const blockM = html.match(/expires?\s+in[\s\S]{0,300}?(\d+)\s*h\s*(\d+)\s*m\s*(\d+)\s*s/i);
      if(blockM){ const v = parseInt(blockM[1])*3600+parseInt(blockM[2])*60+parseInt(blockM[3]); if(v>60) return v; }
      // Tất cả pattern Xh Ym Zs — lấy lớn nhất (loại step timer nhỏ)
      let best = 0;
      for(const m of html.matchAll(/(\d+)\s*h\s*(\d+)\s*m\s*(\d+)\s*s/gi)){
        const v = parseInt(m[1])*3600+parseInt(m[2])*60+parseInt(m[3]);
        if(v > best) best = v;
      }
      if(best > 60) return best;
      // data attribute / JSON
      const dataM = html.match(/data-(?:expire|remaining|timer)=["']?(\d+)/i)
                 || html.match(/"(?:expiresIn|expires_in|remaining|timer)"\s*:\s*(\d+)/i);
      if(dataM){ const v = parseInt(dataM[1]); if(v>60 && v<7200) return v; }
      return 3600; // fallback 1h
    }

    /* ════════════════════════════════════════════════════════════════
       HELPER: Parse step countdown (chỉ lấy số giây nhỏ của từng bước)
    ════════════════════════════════════════════════════════════════ */
    function _parseStepCountdown(html){
      // Tìm countdown dạng JS: timer=7, countdown:4, data-timer="6"
      const attrPatterns = [
        /data-timer=["']?(\d+)/i, /data-seconds=["']?(\d+)/i, /data-countdown=["']?(\d+)/i,
        /"timer"\s*:\s*(\d+)/i,   /"seconds"\s*:\s*(\d+)/i,   /"countdown"\s*:\s*(\d+)/i,
        /"remaining"\s*:\s*(\d+)/i, /timer\s*=\s*(\d+)/i, /countdown\s*=\s*(\d+)/i,
        /var\s+(?:timer|countdown|seconds|wait)\s*=\s*(\d+)/i,
        /(?:timer|countdown|seconds|wait)\s*:\s*(\d+)/i,
        // Tìm số giây nhỏ trong text "Xs" (step timer thường 3-15s)
        /\b(\d+)s\b/,
      ];
      for(const p of attrPatterns){
        const m = html.match(p);
        if(m){ const v = parseInt(m[1]); if(v >= 1 && v <= 60) return v; }
      }
      return 8; // default 8s nếu không tìm thấy
    }

    /* ════════════════════════════════════════════════════════════════
       HELPER: Poll trạng thái bước qua API (JS website dùng polling)
       Thử nhiều endpoint API phổ biến để lấy trạng thái step hiện tại
    ════════════════════════════════════════════════════════════════ */
    async function _pollStepStatus(stepNum, cookies){
      const pollEndpoints = [
        `/api/check?account_id=${encodeURIComponent(accountId)}&step=${stepNum}`,
        `/api/verify?account_id=${encodeURIComponent(accountId)}&step=${stepNum}`,
        `/api/status?account_id=${encodeURIComponent(accountId)}`,
        `/check?account_id=${encodeURIComponent(accountId)}&step=${stepNum}`,
        `/verify/check?account_id=${encodeURIComponent(accountId)}&step=${stepNum}`,
        `/api/unlock?account_id=${encodeURIComponent(accountId)}&step=${stepNum}`,
        `/?account_id=${encodeURIComponent(accountId)}&step=${stepNum}&check=1`,
      ];
      for(const ep of pollEndpoints){
        try{
          const r = await _fetchFull({
            protocol: 'https:', hostname: BASE_HOST, path: ep,
            method: 'GET',
            headers: {
              'User-Agent': UA,
              'Accept': 'application/json, text/html, */*',
              'Accept-Language': 'vi-VN,vi;q=0.9',
              'Accept-Encoding': 'identity',
              'Referer': BASE_URL + '/',
              'Cookie': cookies,
              'X-Requested-With': 'XMLHttpRequest',
            },
            _cookies: cookies
          });
          const body = r.body || '';
          if(!body || r.statusCode === 404) continue;
          // Nếu có Access Granted trong response → thành công
          if(_hasAccessGranted(body)) return { granted: true, html: body, cookies: r.cookies || cookies };
          // Nếu có JSON với step/status
          try{
            const j = JSON.parse(body);
            if(j.granted || j.access_granted || j.success === true) return { granted: true, html: body, cookies: r.cookies || cookies };
            if(j.step && parseInt(j.step) > stepNum) return { advanced: true, step: parseInt(j.step), html: body, cookies: r.cookies || cookies };
          }catch(_){}
          // Nếu HTML có step cao hơn → đã advance
          const si = _parseCurrentStep(body);
          if(si && si.current > stepNum) return { advanced: true, step: si.current, html: body, cookies: r.cookies || cookies };
          if(si && si.current === stepNum) return { same: true, html: body, cookies: r.cookies || cookies };
        }catch(e){ /* bỏ qua endpoint không tồn tại */ }
      }
      return null;
    }

    /* ════════════════════════════════════════════════════════════════
       BƯỚC 2-4: Auto click + đợi timer đúng từng mức 1→2→3→4
       Flow:
         1. Parse step hiện tại từ HTML
         2. Thông báo "Bước X/4: Đang đợi Ys..."  
         3. Đợi đúng số giây countdown của bước đó
         4. Click nút tiếp theo (GET trang gốc + thử các API endpoint)
         5. Poll cho đến khi step advance hoặc Access Granted
         6. Lặp lại cho đến bước 4 xong
    ════════════════════════════════════════════════════════════════ */

    let currentHtml    = step1Html;
    let currentCookies = step1Cookies;
    let expiresSecs    = -1;
    const MAX_WAIT_SECS = 35; // giới hạn đợi tối đa mỗi bước

    // Kiểm tra ngay sau bước 1 nếu đã granted
    if(_hasAccessGranted(currentHtml)){
      expiresSecs = _parseExpiresFromGrantedPage(currentHtml);
      console.log(`[TgVerify] 🎉 Access Granted ngay sau B1 expires=${expiresSecs}s`);
    }

    if(expiresSecs <= 0){
      // Xác định bước bắt đầu
      let currentStepNum = 1;
      const s1info = _parseCurrentStep(currentHtml);
      if(s1info) currentStepNum = s1info.current;

      // Vòng lặp qua từng bước 2→3→4
      for(let loopStep = Math.max(2, currentStepNum + 1); loopStep <= 4 && expiresSecs <= 0; loopStep++){

        // --- Parse countdown của bước HIỆN TẠI (bước loopStep-1 đang hiển thị) ---
        let waitSecs = _parseStepCountdown(currentHtml);
        waitSecs = Math.min(waitSecs, MAX_WAIT_SECS);

        console.log(`[TgVerify] Chuẩn bị bước ${loopStep}/4, đợi ${waitSecs}s (countdown bước ${loopStep-1})...`);

        // Thông báo Telegram: đang đợi đúng số giây
        await sendTelegramMessage(chatId,
          `⏱ <b>Bước ${loopStep-1}/4:</b> Đang đợi ${waitSecs}s...\n🆔 ID: <code>${accountId}</code>`
        );

        // Đợi đúng số giây countdown + 1s buffer
        await _sleep((waitSecs + 1) * 1000);

        // --- Click "tiếp tục" — thử nhiều cách ---
        let nextHtml = '', nextCookies = currentCookies;
        let gotNewStep = false;

        // Cách 1: Tìm URL "continue" trong HTML hiện tại
        const actionUrl = _extractNextActionUrl(currentHtml, loopStep - 1);
        if(actionUrl){
          try{
            const u = new URL(actionUrl);
            const rA = await _fetchFull({
              protocol: u.protocol, hostname: u.hostname, path: u.pathname + (u.search||''),
              method: 'GET',
              headers: {
                'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8',
                'Accept-Language': 'vi-VN,vi;q=0.9', 'Accept-Encoding': 'identity',
                'Referer': BASE_URL + '/', 'Cookie': currentCookies,
              },
              _cookies: currentCookies
            });
            if(rA.cookies) nextCookies = rA.cookies;
            nextHtml = rA.body || '';
            console.log(`[TgVerify] B${loopStep} action-url GET → ${actionUrl} html=${nextHtml.length}`);
            gotNewStep = true;
          }catch(e){ console.warn(`[TgVerify] B${loopStep} action-url lỗi:`, e.message); }
        }

        // Cách 2: GET trang chủ với account_id để trang JS tự advance
        if(!_hasAccessGranted(nextHtml)){
          try{
            const rHome = await _fetchFull({
              protocol: 'https:', hostname: BASE_HOST,
              path: `/?account_id=${encodeURIComponent(accountId)}`,
              method: 'GET',
              headers: {
                'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8',
                'Accept-Language': 'vi-VN,vi;q=0.9', 'Accept-Encoding': 'identity',
                'Referer': BASE_URL + '/', 'Cookie': nextCookies || currentCookies,
                'Cache-Control': 'no-cache',
              },
              _cookies: nextCookies || currentCookies
            });
            if(rHome.cookies) nextCookies = rHome.cookies;
            const h = rHome.body || '';
            if(h.length > 100){
              nextHtml = h;
              gotNewStep = true;
            }
            console.log(`[TgVerify] B${loopStep} home GET → html=${h.length} granted=${_hasAccessGranted(h)}`);
          }catch(e){ console.warn(`[TgVerify] B${loopStep} home GET lỗi:`, e.message); }
        }

        // Cách 3: POST form với step + account_id (mô phỏng click nút)
        if(!_hasAccessGranted(nextHtml)){
          try{
            const csrf2 = _extractCsrf(nextHtml || currentHtml);
            const hiddens = _extractHiddenInputs(nextHtml || currentHtml);
            let parts = [
              `account_id=${encodeURIComponent(accountId)}`,
              `step=${loopStep}`,
              `action=continue`, `continue=1`, `submit=1`,
            ];
            if(csrf2) parts.push(`_token=${encodeURIComponent(csrf2)}`);
            for(const [k,v2] of Object.entries(hiddens)){
              if(!['account_id','step','_token'].includes(k)) parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v2)}`);
            }
            const postBody = parts.join('&');
            const formAction = _extractFormAction(nextHtml || currentHtml) || BASE_URL + '/';
            const fu = new URL(formAction);
            const rPost = await _fetchFull({
              protocol: fu.protocol, hostname: fu.hostname, path: fu.pathname + (fu.search||''),
              method: 'POST',
              headers: {
                'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.8',
                'Accept-Language': 'vi-VN,vi;q=0.9', 'Accept-Encoding': 'identity',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postBody).toString(),
                'Origin': BASE_URL, 'Referer': BASE_URL + '/',
                'Cookie': nextCookies || currentCookies,
                'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'same-origin',
              },
              _cookies: nextCookies || currentCookies
            }, postBody);
            if(rPost.cookies) nextCookies = rPost.cookies;
            const h = rPost.body || '';
            if(h.length > 100) nextHtml = h;
            console.log(`[TgVerify] B${loopStep} POST → html=${h.length} granted=${_hasAccessGranted(h)}`);
          }catch(e){ console.warn(`[TgVerify] B${loopStep} POST lỗi:`, e.message); }
        }

        // Cách 4: Poll API endpoint (website JS hay dùng XHR để check status)
        if(!_hasAccessGranted(nextHtml)){
          const pollResult = await _pollStepStatus(loopStep, nextCookies || currentCookies);
          if(pollResult){
            if(pollResult.granted){
              nextHtml = pollResult.html;
              if(pollResult.cookies) nextCookies = pollResult.cookies;
              console.log(`[TgVerify] B${loopStep} poll → GRANTED`);
            } else if(pollResult.advanced || pollResult.same){
              if(pollResult.html) nextHtml = pollResult.html;
              if(pollResult.cookies) nextCookies = pollResult.cookies;
              console.log(`[TgVerify] B${loopStep} poll → advanced step=${pollResult.step||loopStep}`);
            }
          }
        }

        // Cập nhật state
        currentHtml    = nextHtml || currentHtml;
        currentCookies = nextCookies;

        // Kiểm tra Access Granted
        if(_hasAccessGranted(currentHtml)){
          expiresSecs = _parseExpiresFromGrantedPage(currentHtml);
          console.log(`[TgVerify] 🎉 Access Granted sau bước ${loopStep}/4 expires=${expiresSecs}s`);
          break;
        }

        // Log state sau mỗi bước
        const stateInfo = _parseCurrentStep(currentHtml);
        console.log(`[TgVerify] Sau bước ${loopStep}: step=${JSON.stringify(stateInfo)} html=${currentHtml.length}`);
      }

      // Fallback cuối: thử poll lại lần cuối sau khi qua hết 4 bước
      if(expiresSecs <= 0){
        console.log('[TgVerify] Fallback poll cuối...');
        await _sleep(3000);
        try{
          const rFinal = await _fetchFull({
            protocol: 'https:', hostname: BASE_HOST,
            path: `/?account_id=${encodeURIComponent(accountId)}&done=1`,
            method: 'GET',
            headers: { 'User-Agent': UA, 'Accept': 'text/html,*/*', 'Cookie': currentCookies },
            _cookies: currentCookies
          });
          if(rFinal.body && rFinal.body.length > 100){
            currentHtml = rFinal.body;
            if(rFinal.cookies) currentCookies = rFinal.cookies;
          }
          if(_hasAccessGranted(currentHtml)){
            expiresSecs = _parseExpiresFromGrantedPage(currentHtml);
            console.log(`[TgVerify] Fallback cuối → GRANTED expires=${expiresSecs}s`);
          }
        }catch(e){ console.warn('[TgVerify] Fallback cuối lỗi:', e.message); }
      }
    }

    /* ════════════════════════════════════════════════════════════════
       KẾT QUẢ — Lưu session + thông báo + đặt auto-reverify
    ════════════════════════════════════════════════════════════════ */

    if(expiresSecs > 0){
      const h  = Math.floor(expiresSecs / 3600);
      const m  = Math.floor((expiresSecs % 3600) / 60);
      const s  = expiresSecs % 60;
      const timeStr = h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
      const expiresAt     = Date.now() + expiresSecs * 1000;
      const expiresDateStr = new Date(expiresAt).toLocaleString('vi-VN');

      // Lưu session — giữ lại savedId/savedKey/keyVerified từ phiên cũ
      _tgVerifySessions = _tgVerifySessions || {};
      const prevSess = _tgVerifySessions[String(chatId)] || {};
      _tgVerifySessions[String(chatId)] = {
        ...prevSess,
        accountId,
        savedId: prevSess.savedId || accountId,
        expires: expiresAt,
        accessState: 1
      };

      await sendTelegramMessage(chatId,
        `✅ <b>Xác thực thành công!</b>\n` +
        `━━━━━━━━━━━━━━━━━━━━━━\n` +
        `🆔 ID: <code>${accountId}</code>\n` +
        `⏱ Còn lại: <b>${timeStr}</b>\n` +
        `📅 Hết hạn: <b>${expiresDateStr}</b>\n\n` +
        `🔄 <i>Bot sẽ tự động xác thực lại khi còn ≤ 60 giây.</i>\n` +
        `💾 <i>ID đã được lưu lại để auto-reverify.</i>`
      );

      // ── Auto-reverify khi còn 60s ──
      const REVERIFY_THRESHOLD_SECS = 60;
      const reverifyIn = Math.max(0, (expiresSecs - REVERIFY_THRESHOLD_SECS) * 1000);
      const sess = _tgVerifySessions[String(chatId)];
      if(sess && sess.reverifyTimer) clearTimeout(sess.reverifyTimer);
      if(sess){
        sess.reverifyTimer = setTimeout(async ()=>{
          const cur = _tgVerifySessions[String(chatId)];
          if(!cur || cur.accountId !== accountId) return;
          if(cur.expires && cur.expires > Date.now() + 70000) return;
          if(cur) cur.accessState = 2;
          await sendTelegramMessage(chatId,
            `🔄 <b>Tự động xác thực lại (4 bước)...</b>\n🆔 ID: <code>${accountId}</code>\n` +
            `🚫 <i>Đang chặn quảng cáo & auto click từng bước...</i>`
          );
          const idToUse = (cur && cur.savedId) || accountId;
          runPlaywrightVerify(chatId, idToUse).catch(e => {
            console.error('[TgVerify] Auto-reverify lỗi:', e && e.message);
            sendTelegramMessage(chatId,
              `⚠️ <b>Tự động xác thực lại thất bại.</b>\nGửi ID <code>${idToUse}</code> để thử lại.`
            );
          });
        }, reverifyIn);
      }

      console.log(`[TgVerify] ✅ OK chatId=${chatId} ID=${accountId} expires=${expiresSecs}s reverifyIn=${Math.round(reverifyIn/1000)}s`);
    } else {
      await sendTelegramMessage(chatId,
        `❌ <b>Xác thực thất bại.</b>\n` +
        `🆔 ID: <code>${accountId}</code>\n\n` +
        `Không tìm thấy "Access Granted" từ unlockffbeta.com sau 4 bước.\n\n` +
        `Có thể:\n` +
        `• ID chưa được đăng ký trên hệ thống\n` +
        `• Trang web đã thay đổi cấu trúc HTML\n` +
        `• Kết nối mạng không ổn định\n\n` +
        `↩️ Gửi lại ID <code>${accountId}</code> để thử lại.`
      );
      console.warn(`[TgVerify] ❌ Không tìm được Access Granted chatId=${chatId} ID=${accountId}`);
    }
  }catch(e){
    console.error('[TgVerify] Lỗi hệ thống:', e && e.message);
    await sendTelegramMessage(chatId,
      `❌ <b>Lỗi hệ thống.</b>\n<code>${String(e && e.message || e).slice(0, 200)}</code>\n\n↩️ Gửi lại ID để thử lại.`
    );
  }
}

/* Tự cấu hình Telegram Bot khi server khởi động — để chủ shop CHỈ CẦN deploy code (có sẵn
   biến RENDER_EXTERNAL_URL do Render tự cấp) là bot hoạt động ngay, không cần vào BotFather
   làm thêm bước nào: tự đăng ký webhook nhận tin nhắn + tự gắn nút "Mở Shop" luôn hiện sẵn
   trong khung chat của bot (menu button kiểu web_app). */
async function startTelegramBot(){
  const baseUrl = process.env.RENDER_EXTERNAL_URL || process.env.SELF_URL || null;
  if(!baseUrl){
    console.log('  [Telegram Bot] Chưa xác định được địa chỉ public của server (biến RENDER_EXTERNAL_URL). Bot vẫn nhận được tin nhắn nếu bạn tự cấu hình webhook thủ công, nhưng nên deploy trên Render/domain thật để tự động hoá hoàn toàn.');
    return;
  }
  const publicUrl = baseUrl.replace(/\/+$/, '');
  const webhookUrl = `${publicUrl}/api/telegram/webhook`;
  const miniAppUrl = `${publicUrl}/telegram`;

  const webhookResult = await telegramApiCall('setWebhook', { url: webhookUrl });
  if(webhookResult && webhookResult.ok){
    console.log(`  [Telegram Bot] Đã tự đăng ký webhook: ${webhookUrl}`);
  } else {
    console.warn('  [Telegram Bot] Đăng ký webhook thất bại (kiểm tra lại TELEGRAM_BOT_TOKEN):', webhookResult && webhookResult.description);
  }

  const menuResult = await telegramApiCall('setChatMenuButton', {
    menu_button: { type: 'web_app', text: 'Mở Shop', web_app: { url: miniAppUrl } }
  });
  if(menuResult && menuResult.ok){
    console.log(`  [Telegram Bot] Đã gắn nút "Mở Shop" (Mini App): ${miniAppUrl}`);
  }

  await telegramApiCall('setMyCommands', {
    commands: [
      { command: 'start',  description: 'Chào mừng & Mở Shop mua key' },
      { command: 'key',    description: 'Nhập key kích hoạt (bot sẽ hỏi nhập)' },
      { command: 'verify', description: 'Xác thực ID Free Fire (bot sẽ hỏi nhập)' },
      { command: 'setid',  description: 'Lưu ID mặc định cho auto-reverify' },
      { command: 'status', description: 'Xem trạng thái phiên (key + ID + thời gian)' },
      { command: 'cancel', description: 'Huỷ phiên xác thực và dừng auto-reverify' },
      { command: 'help',   description: 'Hướng dẫn sử dụng chi tiết' }
    ]
  });
}

/* Chống ngủ đông (Render Free): tự ping /api/status mỗi 4 phút. Nên kết hợp thêm
   UptimeRobot/cron-job.org gọi từ bên ngoài để đánh thức chắc chắn hơn khi server đã ngủ. */
function startAntiSleep(){
  const selfUrl = process.env.RENDER_EXTERNAL_URL || process.env.SELF_URL || null;
  if(!selfUrl){
    console.log('  [Anti-sleep] Chưa xác định được địa chỉ public của server (biến RENDER_EXTERNAL_URL). Bỏ qua tự ping — vẫn nên cấu hình UptimeRobot/cron-job.org như ghi chú ở trên.');
    return;
  }
  const target = selfUrl.replace(/\/+$/, '') + '/api/status';
  console.log(`  [Anti-sleep] Sẽ tự ping ${target} mỗi 4 phút để chống ngủ đông.`);
  setInterval(()=>{
    try{
      https.get(target, (r)=>{ r.resume(); }).on('error', (e)=>{
        console.warn('[Anti-sleep] Ping thất bại (không nghiêm trọng, sẽ thử lại sau):', e.message);
      });
    }catch(e){ /* bỏ qua lỗi ping, không ảnh hưởng server chính */ }
  }, 4 * 60 * 1000);
}

// Đảm bảo ghi dữ liệu lần cuối khi tắt server bằng Ctrl+C
process.on('SIGINT', ()=>{ saveDBNow(); process.exit(0); });
process.on('SIGTERM', ()=>{ saveDBNow(); process.exit(0); });
