/* ============================================================
 * EDUFLOW LMS — Konfigurasi Backend
 * Edit file ini SETELAH deploy Google Apps Script (Code.gs).
 *
 * Langkah:
 *  1. Buka Apps Script (script.google.com) → New project → paste isi Code.gs.
 *  2. Project Settings → Script properties, isi:
 *       SHEET_ID, DRIVE_ID, HMAC_SECRET, JWT_SECRET, MODE (sandbox/live)
 *  3. Run → doSetup (1x). Authorize akses Sheets+Drive.
 *  4. Deploy → New deployment → Web app → Execute as: Me, Access: Anyone.
 *  5. Copy URL Web App → tempel di GAS_URL bawah ini.
 *  6. Pastikan HMAC_SECRET di bawah SAMA dengan Script properties HMAC_SECRET.
 * ============================================================ */
window.EDUFLOW_CONFIG = {
  // Contoh: "https://script.google.com/macros/s/AKfycb.../exec"
  GAS_URL: "",
  HMAC_SECRET: "CHANGE_ME_HMAC"
};
