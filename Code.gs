/*****************************************************************
 * EduFlow LMS — Backend Google Apps Script (Code.gs)
 * Single-file backend untuk index.html (frontend EduFlow LMS).
 *
 * SETUP (sekali saja):
 *   1. Buat Spreadsheet kosong → copy ID dari URL.
 *   2. Buat Folder Drive kosong → copy ID dari URL.
 *   3. File → Project properties → Script properties, isi:
 *        SHEET_ID       = <id spreadsheet>
 *        DRIVE_ID       = <id folder drive>
 *        HMAC_SECRET    = <string acak panjang, samakan dgn frontend>
 *        JWT_SECRET     = <string acak panjang, hanya di server>
 *        MIDTRANS_KEY   = (opsional)
 *        XENDIT_KEY     = (opsional)
 *        STRIPE_KEY     = (opsional)
 *        PAYPAL_KEY     = (opsional)
 *        MODE           = sandbox  (atau "live")
 *   4. Run → doSetup  (sekali, untuk buat sheet + 3 default user).
 *   5. Deploy → New deployment → Web app:
 *        Execute as: Me
 *        Who has access: Anyone
 *      → Copy URL Web App → tempel ke `GAS_URL` di index.html.
 *
 * DEFAULT USERS:
 *   admin@lms.com       / Admin123!
 *   instruktur@lms.com  / Instruktur123!
 *   peserta@lms.com     / Peserta123!
 *
 * SECURITY:
 *   - Semua request wajib membawa HMAC-SHA256 signature.
 *   - Login mengembalikan JWT-like token (HS256) berisi {uid, role, exp}.
 *   - Password disimpan sbg PBKDF2(SHA-256, 10000 iter, salt 16B).
 *   - Rate-limit login: max 5 percobaan / email / 10 menit.
 *   - File upload divalidasi MIME whitelist, disimpan di subfolder Drive.
 *****************************************************************/

const SP = PropertiesService.getScriptProperties();
const SHEET_ID    = SP.getProperty('SHEET_ID');
const DRIVE_ID    = SP.getProperty('DRIVE_ID');
const HMAC_SECRET = SP.getProperty('HMAC_SECRET') || 'CHANGE_ME_HMAC';
const JWT_SECRET  = SP.getProperty('JWT_SECRET')  || 'CHANGE_ME_JWT';
const MODE        = SP.getProperty('MODE') || 'sandbox';

const SHEETS = [
  'users','courses','categories','instructors','transactions','coupons',
  'reviews','threads','calendar','notifications','affiliates','memberships',
  'broadcasts','materials','modules','quizzes','assignments','submissions',
  'enrollments','settings','login_attempts','audit_log'
];

const ALLOWED_MIME = [
  'application/pdf',
  'video/mp4','video/webm','video/ogg','video/quicktime',
  'audio/mpeg','audio/mp3','audio/wav','audio/ogg','audio/webm',
  'image/jpeg','image/png','image/webp','image/gif','image/svg+xml',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation', // pptx
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  // docx
  'application/msword',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',         // xlsx
  'application/vnd.ms-excel',
  'text/plain','text/csv'
];
const MIME_TO_SUBFOLDER = (mime) => {
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'audio';
  if (mime.startsWith('image/')) return 'image';
  if (mime === 'application/pdf') return 'pdf';
  if (mime.indexOf('word') >= 0 || mime.indexOf('presentation') >= 0 || mime.indexOf('sheet') >= 0) return 'doc';
  return 'other';
};

/* ============================================================
 * ENTRY POINT
 * ============================================================ */
function doPost(e){
  try {
    const raw = e.postData.contents;
    const body = JSON.parse(raw || '{}');
    // HMAC verification (kecuali action publik)
    if (!['ping'].includes(body.action)) {
      if (!verifyHmac_(raw, e.parameter && e.parameter.sig)) {
        // fallback: signature bisa juga di-embed dalam body.sig
        if (!body.sig || !verifyHmac_(JSON.stringify({action:body.action, data:body.data, ts:body.ts}), body.sig)) {
          return json_({ok:false, msg:'Invalid signature'});
        }
      }
    }
    const action = body.action;
    const data   = body.data || {};
    const ctx    = { token: body.token, ip: (e.parameter && e.parameter.ip) || '' };

    const handler = HANDLERS[action];
    if (!handler) return json_({ok:false, msg:'Unknown action: '+action});
    const out = handler(data, ctx);
    return json_(out);
  } catch(err){
    return json_({ok:false, msg:String(err && err.message || err)});
  }
}

function doGet(e){
  // health check
  return json_({ok:true, service:'EduFlow LMS Backend', mode:MODE, time:Date.now()});
}

function json_(obj){
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

/* ============================================================
 * HMAC + JWT
 * ============================================================ */
function hmac_(str, secret){
  const bytes = Utilities.computeHmacSha256Signature(str, secret || HMAC_SECRET);
  return Utilities.base64EncodeWebSafe(bytes).replace(/=+$/,'');
}
function verifyHmac_(raw, sig){
  if (!sig) return false;
  const expected = hmac_(raw);
  return timingSafeEqual_(expected, sig);
}
function timingSafeEqual_(a,b){
  if (!a || !b || a.length !== b.length) return false;
  let r = 0;
  for (let i=0; i<a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function jwtIssue_(payload, ttlSec){
  ttlSec = ttlSec || 3600*8; // 8 jam
  const header  = b64u_(JSON.stringify({alg:'HS256', typ:'JWT'}));
  const claims  = Object.assign({}, payload, { iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+ttlSec });
  const body    = b64u_(JSON.stringify(claims));
  const sig     = hmac_(header+'.'+body, JWT_SECRET);
  return header+'.'+body+'.'+sig;
}
function jwtVerify_(token){
  if (!token) return null;
  const p = String(token).split('.');
  if (p.length !== 3) return null;
  const expected = hmac_(p[0]+'.'+p[1], JWT_SECRET);
  if (!timingSafeEqual_(expected, p[2])) return null;
  try {
    const claims = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(p[1])).getDataAsString());
    if (claims.exp && claims.exp*1000 < Date.now()) return null;
    return claims;
  } catch(e){ return null; }
}
function b64u_(str){
  return Utilities.base64EncodeWebSafe(Utilities.newBlob(str).getBytes()).replace(/=+$/,'');
}

/* ============================================================
 * PBKDF2-like password hash (10k iter SHA-256)
 * ============================================================ */
function hashPw_(password, saltHex){
  const salt = saltHex || randomHex_(16);
  let h = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt+password);
  for (let i=0;i<9999;i++) h = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, h);
  return 'pbk$10000$'+salt+'$'+Utilities.base64Encode(h);
}
function verifyPw_(password, stored){
  if (!stored || stored.indexOf('pbk$') !== 0) {
    // legacy plaintext (migrasi)
    return password === stored;
  }
  const parts = stored.split('$'); // pbk, iter, salt, hash
  const test  = hashPw_(password, parts[2]);
  return timingSafeEqual_(test, stored);
}
function randomHex_(n){
  let s='';
  const a = Math.random().toString(16).slice(2)+Math.random().toString(16).slice(2);
  for (let i=0;i<n*2;i++) s += a[(Math.random()*a.length)|0];
  return s;
}

/* ============================================================
 * SHEET HELPERS
 * ============================================================ */
function ss_(){ return SpreadsheetApp.openById(SHEET_ID); }
function sheet_(name){
  const s = ss_();
  let sh = s.getSheetByName(name);
  if (!sh) sh = s.insertSheet(name);
  return sh;
}
function readAll_(name){
  const sh = sheet_(name);
  const last = sh.getLastRow();
  if (last < 2) return [];
  const range = sh.getRange(1,1,last,sh.getLastColumn()).getValues();
  const headers = range[0];
  const out = [];
  for (let i=1;i<range.length;i++){
    const row = range[i];
    const obj = {};
    headers.forEach((h,j)=>{
      const v = row[j];
      // try parse JSON-like
      if (typeof v === 'string' && (v.startsWith('{')||v.startsWith('['))){
        try { obj[h] = JSON.parse(v); } catch(e){ obj[h] = v; }
      } else obj[h] = v;
    });
    out.push(obj);
  }
  return out;
}
function writeAll_(name, rows){
  const sh = sheet_(name);
  sh.clear();
  if (!rows || !rows.length) { sh.appendRow(['id']); return; }
  const headers = Object.keys(rows.reduce((a,r)=>(Object.keys(r).forEach(k=>a[k]=1),a), {}));
  sh.appendRow(headers);
  const data = rows.map(r => headers.map(h => {
    const v = r[h];
    if (v && typeof v === 'object') return JSON.stringify(v);
    return v == null ? '' : v;
  }));
  if (data.length) sh.getRange(2,1,data.length,headers.length).setValues(data);
}
function upsertRow_(name, row, key){
  key = key || 'id';
  const rows = readAll_(name);
  const ix = rows.findIndex(r => String(r[key]) === String(row[key]));
  if (ix >= 0) rows[ix] = Object.assign({}, rows[ix], row);
  else rows.push(row);
  writeAll_(name, rows);
  return row;
}
function deleteRow_(name, id){
  const rows = readAll_(name).filter(r => String(r.id) !== String(id));
  writeAll_(name, rows);
}

/* ============================================================
 * SETUP
 * ============================================================ */
function doSetup(){
  if (!SHEET_ID || !DRIVE_ID) throw new Error('Set SHEET_ID & DRIVE_ID di Script Properties dulu.');
  SHEETS.forEach(n => sheet_(n));
  // create subfolders di Drive
  const root = DriveApp.getFolderById(DRIVE_ID);
  ['pdf','video','audio','image','doc','other'].forEach(sub=>{
    const it = root.getFoldersByName(sub);
    if (!it.hasNext()) root.createFolder(sub);
  });
  // default users
  const users = readAll_('users');
  const defaults = [
    {email:'admin@lms.com',      name:'Administrator', role:'admin',      pw:'Admin123!'},
    {email:'instruktur@lms.com', name:'Instruktur',    role:'instructor', pw:'Instruktur123!'},
    {email:'peserta@lms.com',    name:'Peserta',       role:'student',    pw:'Peserta123!'}
  ];
  defaults.forEach(d=>{
    if (!users.find(u=>String(u.email).toLowerCase()===d.email)){
      users.push({
        id:'u_'+Utilities.getUuid().slice(0,8),
        name:d.name, email:d.email, role:d.role,
        password: hashPw_(d.pw),
        status:'active', joinedAt: Date.now(),
        mustChangePw: true,
        enrolled:[], wishlist:[]
      });
    }
  });
  writeAll_('users', users);
  audit_('system','doSetup','OK');
  return 'OK — default users dibuat, sheet + folder siap.';
}

function audit_(uid, action, detail){
  const sh = sheet_('audit_log');
  sh.appendRow([new Date(), uid||'', action||'', detail||'']);
}

/* ============================================================
 * RATE LIMIT (login)
 * ============================================================ */
function checkRate_(email){
  const cache = CacheService.getScriptCache();
  const key = 'LOGIN_'+String(email||'').toLowerCase();
  const n = parseInt(cache.get(key)||'0',10);
  if (n >= 5) return false;
  cache.put(key, String(n+1), 600); // 10 menit
  return true;
}
function resetRate_(email){
  CacheService.getScriptCache().remove('LOGIN_'+String(email||'').toLowerCase());
}

/* ============================================================
 * HANDLERS
 * ============================================================ */
const HANDLERS = {

  ping(){ return {ok:true, time:Date.now(), mode:MODE}; },

  /* ---- AUTH ---- */
  login(data){
    const email = String(data.email||'').trim().toLowerCase();
    const pw    = String(data.password||'');
    if (!email || !pw) return {ok:false, msg:'Email & password wajib'};
    if (!checkRate_(email)) return {ok:false, msg:'Terlalu banyak percobaan. Coba lagi nanti.'};
    const users = readAll_('users');
    const u = users.find(x => String(x.email).toLowerCase() === email);
    if (!u || !verifyPw_(pw, u.password)) {
      audit_(email,'login_fail','');
      return {ok:false, msg:'Email atau password salah'};
    }
    if (u.status === 'inactive') return {ok:false, msg:'Akun dinonaktifkan'};
    resetRate_(email);
    const token = jwtIssue_({uid:u.id, role:u.role, email:u.email});
    audit_(u.id,'login_ok','');
    // jangan kirim password ke klien
    const safe = Object.assign({}, u); delete safe.password;
    return {ok:true, token, user:safe};
  },

  register(data){
    const name  = String(data.name||'').trim().slice(0,80);
    const email = String(data.email||'').trim().toLowerCase().slice(0,120);
    const pw    = String(data.password||'');
    if (!/^\S+@\S+\.\S+$/.test(email)) return {ok:false, msg:'Email tidak valid'};
    if (pw.length < 8) return {ok:false, msg:'Password minimal 8 karakter'};
    const users = readAll_('users');
    if (users.find(u=>String(u.email).toLowerCase()===email)) return {ok:false, msg:'Email sudah terdaftar'};
    const u = {
      id:'u_'+Utilities.getUuid().slice(0,8),
      name, email, role:'student',
      password: hashPw_(pw),
      status:'active', joinedAt:Date.now(),
      enrolled:[], wishlist:[]
    };
    users.push(u);
    writeAll_('users', users);
    const token = jwtIssue_({uid:u.id, role:u.role, email:u.email});
    const safe = Object.assign({}, u); delete safe.password;
    audit_(u.id,'register','');
    return {ok:true, token, user:safe};
  },

  changePassword(data, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims) return {ok:false, msg:'Sesi tidak valid'};
    const users = readAll_('users');
    const u = users.find(x=>x.id===claims.uid);
    if (!u) return {ok:false, msg:'User tidak ditemukan'};
    if (!verifyPw_(String(data.oldPassword||''), u.password)) return {ok:false, msg:'Password lama salah'};
    if (String(data.newPassword||'').length < 8) return {ok:false, msg:'Password baru minimal 8 karakter'};
    u.password = hashPw_(data.newPassword);
    u.mustChangePw = false;
    writeAll_('users', users);
    audit_(u.id,'change_pw','');
    return {ok:true};
  },

  /* ---- SYNC (data entities) ---- */
  syncPull(_, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims) return {ok:false, msg:'Unauthorized'};
    const data = {};
    SHEETS.filter(n=>!['login_attempts','audit_log'].includes(n)).forEach(n=>{
      let rows = readAll_(n);
      if (n === 'users') {
        // jangan kirim hash password ke klien
        rows = rows.map(r => { const c = Object.assign({},r); delete c.password; return c; });
      }
      data[n] = rows;
    });
    return {ok:true, data};
  },

  syncPush(data, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims || claims.role !== 'admin') return {ok:false, msg:'Hanya admin'};
    Object.keys(data||{}).forEach(k=>{
      if (SHEETS.includes(k) && Array.isArray(data[k])){
        if (k === 'users'){
          // merge: jaga hash password lama jika klien tidak mengirim
          const cur = readAll_('users');
          const merged = data[k].map(nu=>{
            const old = cur.find(x=>x.id===nu.id);
            if (old && !nu.password) nu.password = old.password;
            else if (nu.password && nu.password.indexOf('pbk$')!==0) nu.password = hashPw_(nu.password);
            return nu;
          });
          writeAll_('users', merged);
        } else writeAll_(k, data[k]);
      }
    });
    audit_(claims.uid,'syncPush', Object.keys(data||{}).join(','));
    return {ok:true};
  },

  /* ---- CRUD generic (per-entity) ---- */
  upsert(data, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims) return {ok:false, msg:'Unauthorized'};
    if (!SHEETS.includes(data.entity)) return {ok:false, msg:'Entity tidak dikenal'};
    // admin-only entities
    const adminOnly = ['users','instructors','settings','coupons','memberships','transactions'];
    if (adminOnly.includes(data.entity) && claims.role !== 'admin') return {ok:false, msg:'Hanya admin'};
    upsertRow_(data.entity, data.row);
    return {ok:true};
  },
  remove(data, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims || claims.role !== 'admin') return {ok:false, msg:'Hanya admin'};
    if (!SHEETS.includes(data.entity)) return {ok:false, msg:'Entity tidak dikenal'};
    deleteRow_(data.entity, data.id);
    return {ok:true};
  },

  /* ---- FILES ---- */
  uploadFile(data, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims) return {ok:false, msg:'Unauthorized'};
    const mime = String(data.mime||'application/octet-stream');
    if (ALLOWED_MIME.indexOf(mime) < 0 && !mime.startsWith('image/') && !mime.startsWith('video/') && !mime.startsWith('audio/')){
      return {ok:false, msg:'Tipe file tidak diizinkan: '+mime};
    }
    if (!data.base64) return {ok:false, msg:'Konten kosong'};
    const bytes = Utilities.base64Decode(data.base64);
    const blob  = Utilities.newBlob(bytes, mime, data.filename || 'file');
    const root  = DriveApp.getFolderById(DRIVE_ID);
    const subName = MIME_TO_SUBFOLDER(mime);
    let sub;
    const it = root.getFoldersByName(subName);
    sub = it.hasNext() ? it.next() : root.createFolder(subName);
    const file = sub.createFile(blob);
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    audit_(claims.uid,'upload', file.getId()+' '+mime+' '+blob.getBytes().length);
    return {ok:true, data:{
      fileId: file.getId(),
      url: 'https://drive.google.com/uc?export=download&id='+file.getId(),
      viewUrl: 'https://drive.google.com/file/d/'+file.getId()+'/view',
      size: blob.getBytes().length,
      mime: mime,
      type: subName
    }};
  },
  deleteFile(data, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims) return {ok:false, msg:'Unauthorized'};
    try {
      DriveApp.getFileById(data.fileId).setTrashed(true);
      audit_(claims.uid,'delete_file', data.fileId);
      return {ok:true};
    } catch(e){ return {ok:false, msg:String(e)}; }
  },

  /* ---- PAYMENT (manual confirm / refund) ---- */
  confirmPayment(data, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims || claims.role !== 'admin') return {ok:false, msg:'Hanya admin'};
    const rows = readAll_('transactions');
    const ix = rows.findIndex(r=>r.id===data.id);
    if (ix < 0) return {ok:false, msg:'TRX tidak ditemukan'};
    rows[ix].status = 'success';
    rows[ix].confirmedAt = Date.now();
    writeAll_('transactions', rows);
    // auto-enroll
    const users = readAll_('users');
    const u = users.find(x=>x.id===rows[ix].userId);
    if (u){
      u.enrolled = u.enrolled || [];
      if (!u.enrolled.find(e=>e.courseId===rows[ix].courseId))
        u.enrolled.push({courseId:rows[ix].courseId, progress:0, completedModules:[]});
      writeAll_('users', users);
    }
    return {ok:true};
  },
  refundPayment(data, ctx){
    const claims = jwtVerify_(ctx.token);
    if (!claims || claims.role !== 'admin') return {ok:false, msg:'Hanya admin'};
    const rows = readAll_('transactions');
    const ix = rows.findIndex(r=>r.id===data.id);
    if (ix < 0) return {ok:false, msg:'TRX tidak ditemukan'};
    rows[ix].status = 'refund';
    rows[ix].refundedAt = Date.now();
    writeAll_('transactions', rows);
    return {ok:true};
  }
};
