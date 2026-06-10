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
  GAS_URL: "https://script.google.com/macros/s/AKfycby84QQsju4xMShna06diPNYQPdxGuF6gT_M6Mvlz_JojZW6njygSxNCE2XZwd3a8C_Rww/exec",
  HMAC_SECRET: "8f7c2d91b5e4a8f36c7e2b1d9a4f5c8e7d3b6a9c2f1e8d4b7c5a9e2f6d8b1c4"
};
