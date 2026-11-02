#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filetype_gui.py
------------------------------------------------------------------------
رابط گرافیکی دوزبانه (فارسی/انگلیسی) برای تشخیص و اصلاح پسوند واقعی فایل‌ها.

جریان کار:
    ۱. مسیر (فایل یا پوشه) را انتخاب می‌کنید.
    ۲. حالت را انتخاب می‌کنید:
        - «فقط گزارش» (پیش‌فرض): فقط جدول و گزارش ساخته می‌شود و هیچ فایلی
          تغییر نمی‌کند.
        - اجرای واقعی: پسوندهای قطعاً اشتباه اصلاح می‌شوند و لاگ Undo
          ساخته می‌شود. قبل از هر تغییری، یک پنجره‌ی تأیید با تعداد
          فایل‌ها و پیش‌نمایش «نام قبلی → نام جدید» نمایش داده می‌شود؛
          تا کاربر تأیید نکند، هیچ فایلی تغییر نمی‌کند.
    ۳. دکمه‌ی «شروع» را می‌زنید؛ کار در پس‌زمینه انجام می‌شود و پنجره
       آزاد می‌ماند.

دوزبانگی:
    - در اولین اجرا زبان از زبان سیستم حدس زده می‌شود (فارسی یا انگلیسی).
    - از ترکیب پایینِ عنوان پنجره قابل تغییر است و انتخاب کاربر در
      ~/.extension_fixer.json ذخیره می‌شود و اجرای بعدی همان را می‌آورد.

اجرا:
    python filetype_gui.py        (یا دابل‌کلیک روی run.bat در ویندوز)

پیش‌نیاز: فقط پایتون استاندارد (Tkinter). فایل filetype_core.py باید
کنار همین فایل باشد.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox, scrolledtext

from filetype_core import (
    analyze_file, collect_files,
    build_rename_plan, apply_rename_plan, start_undo_log, undo_rename_plan,
    is_protected_root,
)

APP_NAME = "ExtensionFixer"
SETTINGS_PATH = Path.home() / ".extension_fixer.json"
LOG_DIR = Path.home() / ".extension_fixer_logs"
MAX_ROWS = 5000          # سقف ردیف‌های جدول (لیست کامل در فایل گزارش است)

# فونت رابط — در شروع برنامه با ensure_ui_font() برای هر پلتفرم تنظیم می‌شود
# (ویندوز: Segoe UI که فارسی را کامل دارد؛ لینوکس: اولین فونت فارسی‌دار موجود)
UI_FONT_FAMILY = "Segoe UI"
REPORT_FONT_FAMILY = "Consolas"
_font_ready = False


def ensure_ui_font(root):
    """یک بار در شروع: انتخاب فونت مناسب هر پلتفرم.
    ویندوز: Segoe UI (پشتیبانی کامل فارسی) + Consolas برای گزارش.
    بقیه‌ی سیستم‌ها: اولین فونت موجود که فارسی را پشتیبانی می‌کند."""
    global UI_FONT_FAMILY, REPORT_FONT_FAMILY, _font_ready
    if _font_ready:
        return
    _font_ready = True
    if sys.platform.startswith("win"):
        return
    try:
        import tkinter.font as tkfont
        fams = set(tkfont.families(root))
        for name in ("Vazirmatn", "Noto Naskh Arabic", "Noto Sans Arabic",
                     "FreeSerif", "FreeSans", "DejaVu Sans"):
            if name in fams:
                UI_FONT_FAMILY = name
                break
        for name in ("DejaVu Sans Mono", "Liberation Mono", "FreeMono", "Courier"):
            if name in fams:
                REPORT_FONT_FAMILY = name
                break
    except Exception:
        pass


# ----------------------------------------------------------------------------
# زبان سیستم + ذخیره/خواندن تنظیمات
# ----------------------------------------------------------------------------

def detect_system_language():
    """زبان سیستم را حدس می‌زند؛ فارسی -> fa، غیر از آن -> en.
    نکته: locale.getdefaultlocale() از پایتون ۳.۱۱ منسوخ (deprecated) شده؛
    به‌جای آن از API ویندوز و متغیرهای محیطی استفاده می‌کنیم."""
    # ویندوز: زبان رابط کاربری سیستم از API خود ویندوز
    try:
        import ctypes
        lang_id = ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0xFF
        if lang_id == 0x29:  # 0x0429 = Persian
            return "fa"
    except Exception:
        pass
    # سایر سیستم‌ها: متغیرهای محیطی استاندارد
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        value = os.environ.get(var) or ""
        if value.lower().startswith("fa"):
            return "fa"
    return "en"


def load_settings():
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_settings(settings):
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def resource_path(name):
    """مسیر فایل‌های همراه برنامه؛ هم در حالت سورس و هم داخل EXE (PyInstaller)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    p = base / "assets" / name
    return str(p) if p.exists() else None


# ----------------------------------------------------------------------------
# ترجمه‌ها (فارسی / انگلیسی)
# ----------------------------------------------------------------------------

T = {
    "fa": {
        "lang_name": "فارسی",
        "app_title": "پسوندیاب | ExtensionFixer",
        "app_subtitle": "تشخیص و اصلاح پسوند واقعی فایل‌ها بر اساس امضای محتوا (Magic Number)",
        "path_label": "مسیر:",
        "browse_file": "انتخاب فایل...",
        "browse_folder": "انتخاب پوشه...",
        "recursive": "پیمایش زیرپوشه‌ها",
        "include_text": "اصلاح موارد پرریسک (احتمالی/ناشناخته)",
        "dry_run": "فقط گزارش — بدون تغییر نام",
        "run_report": "▶  شروع بررسی (بدون تغییر)",
        "run_fix": "▶  شروع بررسی و اصلاح",
        "undo": "↩  بازگردانی آخرین اصلاح",
        "open_report": "باز کردن فایل گزارش...",
        "tab_table": "جدول فایل‌ها",
        "tab_report": "گزارش نهایی",
        "status_ready": "آماده. یک فایل یا پوشه انتخاب کنید و «شروع» را بزنید.",
        "status_running": "در حال بررسی... (در اجرای واقعی، قبل از هر تغییری یک تأییدیه با پیش‌نمایش نمایش داده می‌شود)",
        "status_scanning": "در حال بررسی... {n} فایل بررسی شد",
        "status_scan_done": "بررسی {n} فایل تمام شد. در حال ساخت لیست اصلاحات...",
        "status_fixing": "در حال اصلاح... {i} از {n} فایل",
        "status_done": "پایان کار — {total} فایل بررسی شد | {mismatch} پسوند اشتباه پیدا شد | {fixed} فایل اصلاح شد | گزارش در تب «گزارش نهایی» و فایل: {file}",
        "status_done_dry": "پایان بررسی (حالت گزارش) — {total} فایل بررسی شد | {fixable} مورد قابل اصلاح | برای اصلاح واقعی، تیک «فقط گزارش» را بردارید و دوباره «شروع» را بزنید",
        "status_cancelled": "لغو شد — {total} فایل بررسی شد و هیچ فایلی تغییر نکرد ({fixable} مورد قابل اصلاح بود)",
        "report_placeholder": "هنوز اجرایی انجام نشده. بعد از پایان کار، گزارش کامل اینجا نمایش داده می‌شود.",
        "report_running": "در حال اجرا... این تب بعد از پایان کار پر می‌شود.",
        "warn_title": "هشدار",
        "warn_no_path": "لطفاً ابتدا یک فایل یا پوشه انتخاب کنید.",
        "error_title": "خطا",
        "err_path_missing": "مسیر «{path}» وجود ندارد.",
        "err_protected_root": "مسیر «{path}» ریشه‌ی درایو یا پوشه‌ی سیستمی است و اجرای واقعی (تغییر نام) روی آن مسدود شده است.\n\nیک پوشه‌ی دیگر انتخاب کنید، یا گزینه‌ی «فقط گزارش» را روشن بگذارید.",
        "err_scan_title": "خطا در اسکن",
        "err_undo_title": "خطا در بازگردانی",
        "col_name": "نام فایل",
        "col_stated": "پسوند فعلی",
        "col_detected": "پسوند واقعی",
        "col_type": "نوع واقعی",
        "col_confidence": "اطمینان",
        "col_result": "نتیجه",
        "col_size": "حجم",
        "col_path": "مسیر فعلی",
        "conf_certain": "قطعی",
        "conf_probable": "احتمالی (کانتینر)",
        "conf_text": "حدس متنی",
        "conf_unknown": "نامشخص",
        "conf_error": "خطا",
        "res_no_change": "بدون تغییر",
        "res_fixed": "اصلاح شد",
        "res_fixed_dup": "اصلاح شد (نام تکراری بود)",
        "res_ready": "آماده اصلاح (اجرای واقعی)",
        "res_review": "نیاز به بررسی دستی",
        "res_error": "خطا در تغییر نام",
        "res_missing": "فایل دیگر پیدا نشد",
        "res_read_error": "خطا در خواندن",
        "no_ext": "—",
        "rows_truncated": "(نمایش {shown} ردیف اول از {total} ردیف — لیست کامل در فایل گزارش)",
        "undo_confirm_title": "تأیید بازگردانی",
        "undo_confirm": "آخرین عملیات اصلاح پسوند به‌طور کامل بازگردانده شود؟",
        "undo_none_title": "بازگردانی",
        "undo_none": "هیچ لاگ بازگردانی‌ای پیدا نشد. هنوز اصلاحی انجام نشده است.",
        "undo_pick_prev": "لاگی برای این نشست وجود ندارد. یک لاگ بازگردانی قبلی باز شود؟",
        "undo_pick_title": "انتخاب فایل لاگ بازگردانی",
        "undo_result": "{restored} فایل به نام قبلی بازگردانده شد.",
        "undo_missing": "{n} مورد بازگردانی نشد (تغییری انجام نشده بود یا فایل یافت نشد).",
        "undo_errors": "{n} خطا (احتمالاً نام قبلی اکنون اشغال است).",
        "undo_done_status": "بازگردانی انجام شد. برای دیدن وضعیت فعلی فایل‌ها، دوباره «شروع» را بزنید.",
        "report_none_title": "گزارشی موجود نیست",
        "report_none": "هنوز اجرایی کامل نشده که گزارشی تولید شده باشد.",
        "open_path_title": "مسیر فایل",
        "rep_title": "گزارش بررسی و اصلاح پسوند فایل‌ها — ExtensionFixer",
        "rep_mode_report": "حالت اجرا: فقط گزارش (هیچ فایلی تغییر نکرد)",
        "rep_mode_fix": "حالت اجرا: اجرای واقعی (نام فایل‌ها اصلاح شد)",
        "rep_mode_cancelled": "حالت اجرا: اجرای واقعی — لغو شد توسط کاربر (هیچ فایلی تغییر نکرد)",
        "rep_path": "مسیر بررسی‌شده",
        "rep_recursive": "پیمایش زیرپوشه‌ها",
        "rep_include_text": "شامل موارد پرریسک (احتمالی/ناشناخته)",
        "rep_yes": "بله",
        "rep_no": "خیر",
        "rep_time": "زمان اجرا",
        "rep_duration": "مدت زمان کل",
        "rep_scan_time": "بررسی",
        "rep_fix_time": "اصلاح",
        "rep_summary": "خلاصه",
        "rep_total": "کل فایل‌های بررسی‌شده",
        "rep_correct": "پسوند درست داشتند (بدون تغییر)",
        "rep_mismatch": "پسوند اشتباه/ناقص شناسایی شد",
        "rep_fixed_total": "اصلاح شد",
        "rep_fixed_plain": "عادی",
        "rep_fixed_dup": "با شماره (تصادم نام)",
        "rep_ready_total": "آماده اصلاح (در حالت گزارش)",
        "rep_review": "نیاز به بررسی دستی دارد",
        "rep_review_note": "(تشخیص احتمالی/متنی بود یا پسوند فعلی شناخته‌شده نیست؛ برای اصلاح، گزینه‌ی «موارد پرریسک» را فعال کنید)",
        "rep_apply_errors": "خطا هنگام تغییر نام",
        "rep_missing": "هنگام اصلاح دیگر پیدا نشد",
        "rep_unknown": "نوع فایل قابل‌تشخیص نبود (دست‌نخورده)",
        "rep_read_errors": "خطا هنگام خواندن فایل",
        "rep_undo_log": "لاگ بازگردانی (برای بازگردانی کامل)",
        "rep_nothing": "— (چیزی اصلاح نشد)",
        "rep_sec_fixed": "فایل‌های اصلاح‌شده (پسوند قبلی -> پسوند جدید)",
        "rep_sec_ready": "فایل‌های آماده‌ی اصلاح (پسوند فعلی -> پسوند پیشنهادی)",
        "rep_sec_review": "فایل‌هایی که نیاز به بررسی دستی دارند (تشخیص احتمالی/متنی یا پسوند ناشناخته)",
        "rep_sec_apply_errors": "خطاهای تغییر نام",
        "rep_sec_read_errors": "خطاهای خواندن فایل",
        "rep_none_items": "(موردی نیست)",
        "rep_more": "... و {n} مورد دیگر (فایل گزارش کامل را ببینید)",
        "rep_truncated_ui": "... (متن در برنامه بریده شد؛ نسخه‌ی کامل در فایل گزارش است)",
        "hours": "ساعت",
        "minutes": "دقیقه",
        "seconds": "ثانیه",
        "hms": "{h} ساعت و {m} دقیقه و {s} ثانیه",
        "ms": "{m} دقیقه و {s} ثانیه",
        "s_only": "{s} ثانیه",
        "confirm_title": "تأیید اصلاح واقعی",
        "confirm_msg": "پسوند {n} فایل اصلاح شود؟\nنام فایل‌ها واقعاً تغییر خواهد کرد (با «بازگردانی» قابل برگشت است).",
        "confirm_more": "... و {n} مورد دیگر",
    },
    "en": {
        "lang_name": "English",
        "app_title": "ExtensionFixer — Fix Real File Extensions",
        "app_subtitle": "Detect and fix real file extensions by content signature (magic number)",
        "path_label": "Path:",
        "browse_file": "Browse file...",
        "browse_folder": "Browse folder...",
        "recursive": "Include subfolders",
        "include_text": "Also fix risky items (probable/unknown)",
        "dry_run": "Report only — don't rename",
        "run_report": "▶  Start scan (no changes)",
        "run_fix": "▶  Start scan & fix",
        "undo": "↩  Undo last fix",
        "open_report": "Open report file...",
        "tab_table": "File table",
        "tab_report": "Final report",
        "status_ready": "Ready. Pick a file or folder and press Start.",
        "status_running": "Scanning... (in a real run, one confirmation with a preview is shown before anything is renamed)",
        "status_scanning": "Scanning... {n} files checked so far",
        "status_scan_done": "Checked {n} files. Building the fix list...",
        "status_fixing": "Fixing... {i} of {n} files",
        "status_done": "Done — {total} files checked | {mismatch} wrong extensions found | {fixed} files fixed | report in the “Final report” tab and file: {file}",
        "status_done_dry": "Scan finished (report mode) — {total} files checked | {fixable} fixable items | to actually fix them, untick “Report only” and press Start again",
        "status_cancelled": "Cancelled — {total} files checked, nothing was renamed ({fixable} were fixable)",
        "report_placeholder": "No run yet. The full report will appear here after it finishes.",
        "report_running": "Running... this tab will be filled when it finishes.",
        "warn_title": "Warning",
        "warn_no_path": "Please pick a file or folder first.",
        "error_title": "Error",
        "err_path_missing": "The path “{path}” does not exist.",
        "err_protected_root": "“{path}” is a drive root or a system folder, so a real run (renaming) is blocked there.\n\nPick another folder, or keep “Report only” ticked.",
        "err_scan_title": "Scan error",
        "err_undo_title": "Undo error",
        "col_name": "File name",
        "col_stated": "Stated ext",
        "col_detected": "Real ext",
        "col_type": "Real type",
        "col_confidence": "Confidence",
        "col_result": "Result",
        "col_size": "Size",
        "col_path": "Current path",
        "conf_certain": "Certain",
        "conf_probable": "Probable (container)",
        "conf_text": "Text guess",
        "conf_unknown": "Unknown",
        "conf_error": "Error",
        "res_no_change": "No change",
        "res_fixed": "Fixed",
        "res_fixed_dup": "Fixed (duplicate name)",
        "res_ready": "Ready to fix (real run)",
        "res_review": "Needs manual review",
        "res_error": "Rename failed",
        "res_missing": "File no longer found",
        "res_read_error": "Read error",
        "no_ext": "—",
        "rows_truncated": "(showing first {shown} of {total} rows — full list is in the report file)",
        "undo_confirm_title": "Confirm undo",
        "undo_confirm": "Restore the whole last fix operation?",
        "undo_none_title": "Undo",
        "undo_none": "No undo log was found. Nothing has been fixed so far.",
        "undo_pick_prev": "No undo log from this session. Open a previous undo log file?",
        "undo_pick_title": "Pick an undo log file",
        "undo_result": "{restored} files restored to their previous names.",
        "undo_missing": "{n} items were not restored (nothing was changed or the file was not found).",
        "undo_errors": "{n} errors (the previous name is probably occupied now).",
        "undo_done_status": "Undo finished. Press Start again to see the current state of the files.",
        "report_none_title": "No report yet",
        "report_none": "No run has finished yet, so there is no report file.",
        "open_path_title": "File path",
        "rep_title": "ExtensionFixer — Scan & Fix Report",
        "rep_mode_report": "Mode: report only (nothing was renamed)",
        "rep_mode_fix": "Mode: real run (file names were fixed)",
        "rep_mode_cancelled": "Mode: real run — cancelled by user (nothing was renamed)",
        "rep_path": "Scanned path",
        "rep_recursive": "Include subfolders",
        "rep_include_text": "Include risky items (probable/unknown)",
        "rep_yes": "Yes",
        "rep_no": "No",
        "rep_time": "Run time",
        "rep_duration": "Total duration",
        "rep_scan_time": "scan",
        "rep_fix_time": "fix",
        "rep_summary": "Summary",
        "rep_total": "Total files checked",
        "rep_correct": "Correct extensions (no change)",
        "rep_mismatch": "Wrong/incomplete extensions found",
        "rep_fixed_total": "Fixed",
        "rep_fixed_plain": "plain",
        "rep_fixed_dup": "numbered (name collision)",
        "rep_ready_total": "Ready to fix (report mode)",
        "rep_review": "Need manual review",
        "rep_review_note": "(detection was probable/text, or the current extension is unknown; enable the “risky items” option to fix them)",
        "rep_apply_errors": "Rename errors",
        "rep_missing": "Not found when fixing",
        "rep_unknown": "Unrecognized file types (untouched)",
        "rep_read_errors": "File read errors",
        "rep_undo_log": "Undo log (for full restore)",
        "rep_nothing": "— (nothing was fixed)",
        "rep_sec_fixed": "Fixed files (old ext -> new ext)",
        "rep_sec_ready": "Files ready to fix (current ext -> suggested ext)",
        "rep_sec_review": "Files that need manual review (probable/text detection or unknown extension)",
        "rep_sec_apply_errors": "Rename errors",
        "rep_sec_read_errors": "File read errors",
        "rep_none_items": "(none)",
        "rep_more": "... and {n} more items (see the full report file)",
        "rep_truncated_ui": "... (text truncated in the app; the full version is in the report file)",
        "hours": "hours",
        "minutes": "minutes",
        "seconds": "seconds",
        "hms": "{h} hours, {m} minutes, {s} seconds",
        "ms": "{m} minutes, {s} seconds",
        "s_only": "{s} seconds",
        "confirm_title": "Confirm real fix",
        "confirm_msg": "Fix the extensions of {n} files now?\nFile names will really be renamed (restorable via Undo).",
        "confirm_more": "... and {n} more",
    },
}


# ----------------------------------------------------------------------------
# برنامه
# ----------------------------------------------------------------------------

class FileTypeFixerApp:
    def __init__(self, root):
        self.root = root
        ensure_ui_font(root)
        self.settings = load_settings()
        saved = self.settings.get("language")
        self.lang = saved if saved in ("fa", "en") else detect_system_language()

        self.selected_path = tk.StringVar()
        self.recursive_var = tk.BooleanVar(value=True)
        self.include_text_var = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=True)      # پیش‌فرض: فقط گزارش
        self.status_var = tk.StringVar()

        self.all_results = []
        self._running = False
        self.last_undo_log = None
        self.last_report_path = None
        self._last_data = None      # آخرین نتیجه؛ برای رندر مجدد بعد از تغییر زبان
        self.ui_queue = queue.Queue()
        # مکانیزم تأیید اجرای واقعی: کارگر (thread) منتظر جواب کاربر می‌ماند
        self._confirm_event = threading.Event()
        self._confirm_answer = False

        self._apply_language(self.lang, save=False)
        self.root.after(80, self._poll_queue)

    # ------------------------------------------------------------------
    # زبان
    # ------------------------------------------------------------------
    @property
    def S(self):
        return T[self.lang]

    def _apply_language(self, lang, save=True):
        """تغییر زبان به‌صورت زنده: کل رابط با زبان جدید از نو ساخته می‌شود."""
        self.lang = lang
        if save:
            self.settings["language"] = lang
            save_settings(self.settings)
        for w in self.root.winfo_children():
            w.destroy()
        self._build_ui()
        if self._last_data:
            try:
                self._render_results(self._last_data)
            except Exception:
                pass

    def _on_lang_change(self, _event=None):
        code = "fa" if self.lang_box.get() == T["fa"]["lang_name"] else "en"
        if code != self.lang:
            self._apply_language(code)

    # ------------------------------------------------------------------
    # تم و استایل (ظاهر مدرنِ روشنِ آبی)
    # ------------------------------------------------------------------
    def _setup_styles(self):
        style = ttk.Style()
        BG, CARD = "#F4F6F9", "#FFFFFF"
        ACCENT, ACCENT_DARK = "#2563EB", "#1E50C8"
        FG, MUTED, BORDER = "#1B2430", "#5B6774", "#D9E0E8"
        F = UI_FONT_FAMILY

        style.configure(".", background=BG, foreground=FG, font=(F, 10))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("Card.TLabel", background=CARD, foreground=FG)
        style.configure("Title.TLabel", background=CARD, foreground=FG,
                        font=(F, 15, "bold"))
        style.configure("Subtitle.TLabel", background=CARD, foreground=MUTED,
                        font=(F, 9))
        style.configure("Muted.TLabel", foreground=MUTED)

        style.configure("TButton", background=CARD, foreground=FG,
                        bordercolor=BORDER, lightcolor=CARD, darkcolor=CARD,
                        focuscolor=BORDER, padding=(12, 6), font=(F, 10))
        style.map("TButton",
                  background=[("active", "#EAF0FA"), ("disabled", "#F1F3F6")],
                  foreground=[("disabled", "#9AA5B1")],
                  bordercolor=[("active", ACCENT)])

        style.configure("Accent.TButton", background=ACCENT, foreground="#FFFFFF",
                        bordercolor=ACCENT, focuscolor=ACCENT, padding=(20, 7),
                        font=(F, 10, "bold"))
        style.map("Accent.TButton",
                  background=[("disabled", "#9DBBF5"), ("pressed", ACCENT_DARK),
                              ("active", ACCENT_DARK)],
                  foreground=[("disabled", "#EDF1F7")])

        style.configure("TCheckbutton", background=BG, foreground=FG, focuscolor=BG)
        style.map("TCheckbutton", background=[("active", BG)],
                  foreground=[("disabled", "#9AA5B1")])

        style.configure("TCombobox", fieldbackground="#FFFFFF", background=CARD,
                        arrowcolor=FG, bordercolor=BORDER, lightcolor=BORDER,
                        darkcolor=BORDER)

        style.configure("TNotebook", background=BG, bordercolor=BORDER,
                        tabmargins=(6, 6, 6, 0))
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED,
                        padding=(16, 7), font=(F, 10))
        style.map("TNotebook.Tab", background=[("selected", CARD)],
                  foreground=[("selected", ACCENT)])

        style.configure("Treeview", background="#FFFFFF", fieldbackground="#FFFFFF",
                        foreground=FG, rowheight=26, bordercolor=BORDER,
                        font=(F, 9))
        style.configure("Treeview.Heading", background="#E9EEF5", foreground=FG,
                        font=(F, 9, "bold"), relief="flat", padding=(4, 5))
        style.map("Treeview.Heading", background=[("active", "#E0E7F0")])

        style.configure("Meters.Horizontal.TProgressbar", troughcolor=BORDER,
                        background=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT,
                        bordercolor=BORDER, thickness=8)

    # ------------------------------------------------------------------
    # ساخت رابط
    # ------------------------------------------------------------------
    def _build_ui(self):
        S = self.S
        fa = (self.lang == "fa")
        side_start = "right" if fa else "left"     # جهت خواندن
        side_end = "left" if fa else "right"

        self._setup_styles()
        self.root.title(S["app_title"])
        self.root.geometry("1080x680")
        self.root.minsize(880, 540)
        self.root.configure(background="#F4F6F9")

        # ---------- سربرگ ----------
        header = ttk.Frame(self.root, style="Card.TFrame", padding=(18, 12))
        header.pack(fill="x")

        self._logo_img = None
        logo_file = resource_path("icon.png")
        if logo_file:
            try:
                self._logo_img = tk.PhotoImage(file=logo_file).subsample(12)
                tk.Label(header, image=self._logo_img, background="#FFFFFF",
                         anchor="center").pack(side=side_start, padx=(0, 10))
            except Exception:
                self._logo_img = None

        title_box = ttk.Frame(header, style="Card.TFrame")
        title_box.pack(side=side_start, fill="x", expand=True)
        ttk.Label(title_box, text=S["app_title"], style="Title.TLabel").pack(
            anchor="e" if fa else "w")
        ttk.Label(title_box, text=S["app_subtitle"], style="Subtitle.TLabel").pack(
            anchor="e" if fa else "w")

        lang_box_frame = ttk.Frame(header, style="Card.TFrame")
        lang_box_frame.pack(side=side_end)
        self.lang_box = ttk.Combobox(
            lang_box_frame, state="readonly", width=10,
            values=[T["fa"]["lang_name"], T["en"]["lang_name"]],
            font=(UI_FONT_FAMILY, 10),
        )
        self.lang_box.set(T[self.lang]["lang_name"])
        self.lang_box.pack(side=side_end)
        self.lang_box.bind("<<ComboboxSelected>>", self._on_lang_change)

        # ---------- کارت مسیر ----------
        path_card = ttk.Frame(self.root, style="Card.TFrame", padding=(14, 10))
        path_card.pack(fill="x", padx=12, pady=(10, 0))

        ttk.Button(path_card, text=S["browse_folder"],
                   command=self.browse_folder).pack(side=side_end, padx=4)
        ttk.Button(path_card, text=S["browse_file"],
                   command=self.browse_file).pack(side=side_end, padx=4)
        ttk.Label(path_card, text=S["path_label"]).pack(side=side_start, padx=(0, 8))
        entry = ttk.Entry(path_card, textvariable=self.selected_path,
                          justify="right" if fa else "left")
        entry.pack(side=side_start, fill="x", expand=True, padx=(0 if fa else 0, 6))

        # ---------- گزینه‌ها ----------
        opts = ttk.Frame(self.root, padding=(12, 8, 12, 0))
        opts.pack(fill="x")
        ttk.Checkbutton(opts, text=S["recursive"],
                        variable=self.recursive_var).pack(side=side_start, padx=6)
        ttk.Checkbutton(opts, text=S["dry_run"],
                        variable=self.dry_run_var).pack(side=side_start, padx=6)
        ttk.Checkbutton(opts, text=S["include_text"],
                        variable=self.include_text_var).pack(side=side_start, padx=6)

        # ---------- دکمه‌های اجرا ----------
        run_frame = ttk.Frame(self.root, padding=(12, 8))
        run_frame.pack(fill="x")
        self.run_btn = ttk.Button(run_frame, style="Accent.TButton",
                                  text=S["run_report"] if self.dry_run_var.get() else S["run_fix"],
                                  command=self.start_run)
        self.run_btn.pack(side=side_start, padx=4)
        self.undo_btn = ttk.Button(run_frame, text=S["undo"],
                                   command=self.undo_last_fix, state="disabled")
        self.undo_btn.pack(side=side_start, padx=4)
        ttk.Button(run_frame, text=S["open_report"],
                   command=self.open_report_file).pack(side=side_start, padx=4)
        self.dry_run_var.trace_add("write", lambda *_: self._update_run_label())

        # ---------- نوار وضعیت + پیشرفت (پایین پنجره) ----------
        status_bar = ttk.Frame(self.root, padding=(12, 4))
        status_bar.pack(side="bottom", fill="x")
        ttk.Label(status_bar, textvariable=self.status_var, style="Muted.TLabel",
                  anchor="e" if fa else "w", justify="right" if fa else "left",
                  wraplength=1040).pack(fill="x")
        self.progress = ttk.Progressbar(status_bar, style="Meters.Horizontal.TProgressbar",
                                        mode="indeterminate")

        # ---------- Notebook: جدول نتایج / گزارش نهایی ----------
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=12, pady=(8, 8))

        table_tab = ttk.Frame(notebook)
        report_tab = ttk.Frame(notebook)
        notebook.add(table_tab, text=S["tab_table"])
        notebook.add(report_tab, text=S["tab_report"])

        columns = ("name", "stated", "detected_ext", "detected_type",
                   "confidence", "result", "size", "path")
        headers = {
            "name": S["col_name"], "stated": S["col_stated"],
            "detected_ext": S["col_detected"], "detected_type": S["col_type"],
            "confidence": S["col_confidence"], "result": S["col_result"],
            "size": S["col_size"], "path": S["col_path"],
        }
        widths = {"name": 190, "stated": 80, "detected_ext": 85, "detected_type": 220,
                  "confidence": 85, "result": 170, "size": 75, "path": 250}

        self.tree = ttk.Treeview(table_tab, columns=columns, show="headings",
                                 selectmode="extended")
        for col in columns:
            self.tree.heading(col, text=headers[col])
            anchor = "w" if col in ("path", "name") else "center"
            self.tree.column(col, width=widths[col], anchor=anchor,
                             stretch=(col in ("name", "path")))

        vsb = ttk.Scrollbar(table_tab, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.tag_configure("fixed", background="#DFF7E4")
        self.tree.tag_configure("ready", background="#DDEBFB")
        self.tree.tag_configure("needs_review", background="#FBF3D5")
        self.tree.tag_configure("error", background="#FADBD8")
        self.tree.tag_configure("ok", background="")

        self.tree.bind("<Double-1>", self.on_row_double_click)

        self.report_text = scrolledtext.ScrolledText(
            report_tab, wrap="word",
            font=(REPORT_FONT_FAMILY, 10),
            background="#FFFFFF", relief="flat", padx=10, pady=8)
        self.report_text.pack(fill="both", expand=True)
        self.report_text.insert("1.0", S["report_placeholder"])
        self.report_text.config(state="disabled")

        self.status_var.set(S["status_ready"])

    def _update_run_label(self):
        if getattr(self, "run_btn", None):
            self.run_btn.config(text=self.S["run_report"] if self.dry_run_var.get()
                                else self.S["run_fix"])

    # ------------------------------------------------------------------
    # انتخاب مسیر
    # ------------------------------------------------------------------
    def browse_file(self):
        path = filedialog.askopenfilename(title=self.S["browse_file"])
        if path:
            self.selected_path.set(path)

    def browse_folder(self):
        path = filedialog.askdirectory(title=self.S["browse_folder"])
        if path:
            self.selected_path.set(path)

    # ------------------------------------------------------------------
    # شروع اجرا (در Thread پس‌زمینه)
    # ------------------------------------------------------------------
    def start_run(self):
        if self._running:
            return
        S = self.S
        path_str = self.selected_path.get().strip()
        if not path_str:
            messagebox.showwarning(S["warn_title"], S["warn_no_path"])
            return
        path = Path(path_str)
        if not path.exists():
            messagebox.showerror(S["error_title"], S["err_path_missing"].format(path=path))
            return

        if not self.dry_run_var.get() and is_protected_root(path):
            messagebox.showerror(S["error_title"], S["err_protected_root"].format(path=path))
            return

        self._running = True
        self.run_btn.config(state="disabled")
        self.undo_btn.config(state="disabled")
        self._confirm_event.clear()
        self._confirm_answer = False
        self.status_var.set(S["status_running"])
        self.progress.config(mode="indeterminate")
        self.progress.pack(fill="x", pady=(3, 0))
        self.progress.start(12)

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.all_results = []
        self._set_report_text(S["report_running"])

        thread = threading.Thread(
            target=self._worker,
            args=(path, self.recursive_var.get(),
                  self.include_text_var.get(), self.dry_run_var.get()),
            daemon=True,
        )
        thread.start()

    def _worker(self, path: Path, recursive: bool, include_text: bool, dry_run: bool):
        """کل پایپ‌لاین در Thread پس‌زمینه؛ ارتباط با UI فقط از طریق صف."""
        q = self.ui_queue
        scan_started = time.time()
        results = []
        last_ui = 0.0
        try:
            count = 0
            for f in collect_files(path, recursive):
                count += 1
                try:
                    results.append(analyze_file(f))
                except Exception as e:
                    results.append({
                        "path": str(f), "name": f.name, "size": 0,
                        "stated_extension": f.suffix.lower().lstrip("."),
                        "detected_extension": "error",
                        "detected_type": f"read error: {e}",
                        "confidence": "error", "mismatch": False,
                    })
                now = time.time()
                if now - last_ui > 0.25:
                    last_ui = now
                    q.put(("status", self.S["status_scanning"].format(n=count)))

            scan_seconds = time.time() - scan_started
            q.put(("status", self.S["status_scan_done"].format(n=len(results))))

            plan = build_rename_plan(results, include_risky=include_text)
            # نسخه‌ی کاملِ برنامه برای «گزارش» نگه داشته می‌شود؛ اگر کاربر
            # تأیید را رد کند، exec_plan خالی می‌ماند ولی plan دست‌نخورده
            # می‌ماند تا تعداد «موارد قابل اصلاح» در پیام لغو و گزارش درست باشد.
            exec_plan = []

            apply_results = []
            undo_log_path = None
            fix_started = time.time()
            cancelled = False

            if plan and not dry_run:
                # هیچ تغییری بدون تأیید کاربر انجام نمی‌شود:
                # پنجره‌ی تأیید با تعداد فایل‌ها و پیش‌نمایش old → new نشان داده می‌شود
                q.put(("confirm_request", plan))
                self._confirm_event.wait()
                if not self._confirm_answer:
                    cancelled = True
                else:
                    exec_plan = plan

            if exec_plan and not dry_run:
                # لاگ Undo «قبل» از هر تغییری ساخته می‌شود و پیش از هر
                # تغییر نام، هویت فایل روی دیسک ثبت می‌شود (کرش-سَیف)
                undo_log_path = start_undo_log()
                total = len(exec_plan)
                q.put(("progress_mode", total))
                step = max(1, total // 200)

                def progress_cb(idx, total_n, entry):
                    if idx % step == 0 or idx == total_n:
                        q.put(("status", self.S["status_fixing"].format(i=idx, n=total_n)))
                        q.put(("progress_step", idx))

                apply_results = apply_rename_plan(exec_plan,
                                                  progress_callback=progress_cb,
                                                  undo_log_path=undo_log_path)

                # لاگ به‌صورت افزایشی و بدون بازنویسی کامل شده است؛ اگر
                # هیچ فایلی واقعاً تغییر نکرد، لاگِ بی‌استفاده حذف می‌شود
                if not any(r["status"] in ("renamed", "renamed_with_suffix")
                           for r in apply_results):
                    try:
                        Path(undo_log_path).unlink()
                    except Exception:
                        pass
                    undo_log_path = None

            fix_seconds = time.time() - fix_started
            q.put(("done", {
                "path": str(path), "recursive": recursive,
                "include_text": include_text, "dry_run": dry_run,
                "cancelled": cancelled,
                "results": results, "apply_results": apply_results,
                "plan": plan,
                "undo_log_path": str(undo_log_path) if undo_log_path else None,
                "scan_seconds": scan_seconds, "fix_seconds": fix_seconds,
                "total_seconds": time.time() - scan_started,
            }))
        except Exception as e:
            q.put(("error", self.S["err_scan_title"], str(e)))
            q.put(("done", None))

    # ------------------------------------------------------------------
    # صف پیام‌های UI
    # ------------------------------------------------------------------
    def _poll_queue(self):
        try:
            while True:
                msg = self.ui_queue.get_nowait()
                kind = msg[0]
                if kind == "status":
                    self.status_var.set(msg[1])
                elif kind == "progress_mode":
                    try:
                        self.progress.stop()
                        self.progress.config(mode="determinate",
                                             maximum=max(msg[1], 1), value=0)
                    except Exception:
                        pass
                elif kind == "progress_step":
                    try:
                        self.progress.config(value=msg[1])
                    except Exception:
                        pass
                elif kind == "error":
                    messagebox.showerror(msg[1], msg[2])
                elif kind == "confirm_request":
                    self._show_fix_confirmation(msg[1])
                elif kind == "done":
                    self._finish_run(msg[1])
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    def _show_fix_confirmation(self, plan):
        """پنجره‌ی تأیید اجرای واقعی: تعداد فایل‌ها + پیش‌نمایش old → new."""
        S = self.S
        preview_items = plan[:15]
        lines = [
            f"{Path(p['old_path']).name}  →  {Path(p['new_path']).name}"
            for p in preview_items
        ]
        text = S["confirm_msg"].format(n=len(plan))
        if lines:
            text += "\n\n" + "\n".join(lines)
            if len(plan) > len(preview_items):
                text += "\n" + S["confirm_more"].format(n=len(plan) - len(preview_items))
        # اگر نمایش پنجره خطا بدهد، ترد پس‌زمینه نباید برای همیشه منتظر بماند
        try:
            self._confirm_answer = messagebox.askyesno(S["confirm_title"], text)
        except Exception:
            self._confirm_answer = False
        finally:
            self._confirm_event.set()

    def _finish_run(self, data):
        self._running = False
        try:
            self.progress.stop()
            self.progress.pack_forget()
        except Exception:
            pass
        self.run_btn.config(state="normal")

        if data is None:
            self.status_var.set(self.S["err_scan_title"])
            return
        self._last_data = data
        self._render_results(data)

    # ------------------------------------------------------------------
    # رندر نتایج (جدول + گزارش + وضعیت) — بعد از تغییر زبان هم صدا زده می‌شود
    # ------------------------------------------------------------------
    def _render_results(self, data):
        S = self.S
        results = data["results"]
        apply_results = data["apply_results"]
        plan = data["plan"]
        dry_run = data["dry_run"]

        by_old = {r["old_path"]: r for r in apply_results}
        ready_paths = {p["old_path"] for p in plan}

        final_rows = []
        for r in results:
            fix = by_old.get(r["path"])
            result_text, tag = S["res_no_change"], "ok"
            if fix:
                status = fix["status"]
                if status in ("renamed", "renamed_with_suffix"):
                    new_path = Path(fix["final_path"])
                    r = dict(r)
                    r["path"] = str(new_path)
                    r["name"] = new_path.name
                    r["stated_extension"] = fix["detected_extension"]
                    r["mismatch"] = False
                    result_text = S["res_fixed"] if status == "renamed" else S["res_fixed_dup"]
                    tag = "fixed"
                elif status == "error":
                    result_text, tag = S["res_error"], "error"
                elif status == "skipped_missing":
                    result_text, tag = S["res_missing"], "error"
            elif r["path"] in ready_paths:
                result_text, tag = S["res_ready"], "ready"
            elif r.get("mismatch"):
                result_text, tag = S["res_review"], "needs_review"
            elif r.get("confidence") == "error":
                result_text, tag = S["res_read_error"], "error"
            final_rows.append((r, result_text, tag))

        self.all_results = [r for r, _, _ in final_rows]

        # ---- جدول (با سقف ردیف) ----
        for item in self.tree.get_children():
            self.tree.delete(item)
        conf_map = {"certain": S["conf_certain"], "probable": S["conf_probable"],
                    "text": S["conf_text"],
                    "unknown": S["conf_unknown"], "error": S["conf_error"]}
        for r, result_text, tag in final_rows[:MAX_ROWS]:
            stated = r.get("stated_extension") or ""
            detected = r.get("detected_extension") or ""
            self.tree.insert("", "end", values=(
                r.get("name", ""),
                ("." + stated) if stated else S["no_ext"],
                ("." + detected) if detected and detected not in ("unknown", "error") else S["no_ext"],
                r.get("detected_type", ""),
                conf_map.get(r.get("confidence"), r.get("confidence", "")),
                result_text,
                self._human_size(r.get("size", 0)),
                r.get("path", ""),
            ), tags=(tag,))

        # ---- دکمه‌ی Undo ----
        undo_path = data.get("undo_log_path")
        if undo_path and Path(undo_path).exists():
            self.last_undo_log = undo_path
            self.undo_btn.config(state="normal")
        else:
            self.last_undo_log = None
            self.undo_btn.config(state="disabled")

        # ---- گزارش ----
        report_text, report_file_path = self._build_report(data)
        self.last_report_path = report_file_path
        self._set_report_text(report_text)

        # ---- نوار وضعیت ----
        mismatch_count = sum(1 for r in results if r.get("mismatch"))
        renamed_count = sum(1 for r in apply_results
                            if r["status"] in ("renamed", "renamed_with_suffix"))
        if data.get("cancelled"):
            status = S["status_cancelled"].format(total=len(results), fixable=len(plan))
        elif dry_run:
            status = S["status_done_dry"].format(total=len(results), fixable=len(plan))
        else:
            status = S["status_done"].format(
                total=len(results), mismatch=mismatch_count,
                fixed=renamed_count, file=report_file_path)
        if len(final_rows) > MAX_ROWS:
            status += " " + S["rows_truncated"].format(shown=MAX_ROWS, total=len(final_rows))
        self.status_var.set(status)

    # ------------------------------------------------------------------
    # ساخت متن گزارش + ذخیره در فایل txt
    # ------------------------------------------------------------------
    def _build_report(self, data):
        S = self.S
        results = data["results"]
        apply_results = data["apply_results"]
        plan = data["plan"]
        dry_run = data["dry_run"]
        undo_log_path = data.get("undo_log_path")

        total = len(results)
        mismatches = [r for r in results if r.get("mismatch")]
        analyze_errors = [r for r in results if r.get("confidence") == "error"]
        unknown_type = [r for r in results if r.get("confidence") == "unknown"]
        correct = total - len(mismatches) - len(analyze_errors) - len(unknown_type)

        renamed = [r for r in apply_results if r["status"] in ("renamed", "renamed_with_suffix")]
        renamed_plain = [r for r in apply_results if r["status"] == "renamed"]
        renamed_dup = [r for r in apply_results if r["status"] == "renamed_with_suffix"]
        apply_errors = [r for r in apply_results if r["status"] == "error"]
        apply_missing = [r for r in apply_results if r["status"] == "skipped_missing"]

        plan_paths = {p["old_path"] for p in plan}
        cancelled = bool(data.get("cancelled"))
        ready = list(plan) if (dry_run or cancelled) else []
        needs_review = [r for r in mismatches if r["path"] not in plan_paths]

        def fmt_seconds(s):
            s = int(s)
            h, rem = divmod(s, 3600)
            m, s = divmod(rem, 60)
            if h:
                return S["hms"].format(h=h, m=m, s=s)
            if m:
                return S["ms"].format(m=m, s=s)
            return S["s_only"].format(s=s)

        lines = []
        lines.append("=" * 70)
        lines.append(S["rep_title"])
        lines.append("=" * 70)
        lines.append(f"{S['rep_path']} : {data['path']}")
        if data.get("cancelled"):
            lines.append(S["rep_mode_cancelled"])
        else:
            lines.append(S["rep_mode_fix"] if not dry_run else S["rep_mode_report"])
        lines.append(f"{S['rep_recursive']} : {S['rep_yes'] if data['recursive'] else S['rep_no']}")
        lines.append(f"{S['rep_include_text']} : {S['rep_yes'] if data['include_text'] else S['rep_no']}")
        lines.append(f"{S['rep_time']} : {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"{S['rep_duration']} : {fmt_seconds(data['total_seconds'])}"
                     f"  ({S['rep_scan_time']}: {fmt_seconds(data['scan_seconds'])}"
                     f" | {S['rep_fix_time']}: {fmt_seconds(data['fix_seconds'])})")
        lines.append("")
        lines.append("-" * 70)
        lines.append(S["rep_summary"])
        lines.append("-" * 70)
        lines.append(f"{S['rep_total']} : {total}")
        lines.append(f"{S['rep_correct']} : {correct}")
        lines.append(f"{S['rep_mismatch']} : {len(mismatches)}")
        if not dry_run:
            lines.append(f"  ├─ {S['rep_fixed_total']} : {len(renamed)}")
            lines.append(f"  │    ├─ {S['rep_fixed_plain']} : {len(renamed_plain)}")
            lines.append(f"  │    └─ {S['rep_fixed_dup']} : {len(renamed_dup)}")
            lines.append(f"  ├─ {S['rep_apply_errors']} : {len(apply_errors)}")
            lines.append(f"  ├─ {S['rep_missing']} : {len(apply_missing)}")
            if cancelled:
                lines.append(f"  ├─ {S['rep_ready_total']} : {len(ready)}")
            lines.append(f"  └─ {S['rep_review']} : {len(needs_review)}")
        else:
            lines.append(f"  ├─ {S['rep_ready_total']} : {len(ready)}")
            lines.append(f"  └─ {S['rep_review']} : {len(needs_review)}")
        lines.append(f"      {S['rep_review_note']}")
        lines.append(f"{S['rep_unknown']} : {len(unknown_type)}")
        lines.append(f"{S['rep_read_errors']} : {len(analyze_errors)}")
        lines.append("")
        lines.append(f"{S['rep_undo_log']} : {undo_log_path if undo_log_path else S['rep_nothing']}")
        lines.append("")

        def add_section(title, items, formatter, limit=None):
            lines.append("-" * 70)
            lines.append(f"{title}  ({len(items)})")
            lines.append("-" * 70)
            if not items:
                lines.append(S["rep_none_items"])
            else:
                shown = items if limit is None else items[:limit]
                for it in shown:
                    lines.append(formatter(it))
                if limit is not None and len(items) > limit:
                    lines.append(S["rep_more"].format(n=len(items) - limit))
            lines.append("")

        if not dry_run and renamed:
            add_section(
                S["rep_sec_fixed"],
                renamed,
                lambda r: f"{Path(r['old_path']).name}  ->  {Path(r['final_path']).name}"
                          f"   [{r['detected_type']}]",
                limit=500,
            )
        if (dry_run or cancelled) and ready:
            add_section(
                S["rep_sec_ready"],
                ready,
                lambda p: f"{Path(p['old_path']).name}  ->  {Path(p['new_path']).name}"
                          f"   [{p['detected_type']}]",
                limit=500,
            )
        if needs_review:
            add_section(
                S["rep_sec_review"],
                needs_review,
                lambda r: f"{r['name']}   ({S['col_stated']}: .{r['stated_extension'] or '-'}"
                          f"  →  {S['col_detected']}: .{r['detected_extension']}"
                          f" — {r['detected_type']})   {S['col_path']}: {r['path']}",
                limit=300,
            )
        if apply_errors:
            add_section(
                S["rep_sec_apply_errors"],
                apply_errors,
                lambda r: f"{Path(r['old_path']).name}: {r.get('error_message', '')}",
            )
        if analyze_errors:
            add_section(
                S["rep_sec_read_errors"],
                analyze_errors,
                lambda r: f"{r['name']}: {r.get('detected_type', '')}",
            )

        report_str = "\n".join(lines)

        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            report_path = LOG_DIR / f"report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_str)
        except Exception:
            report_path = Path("(report file could not be saved)")

        return report_str, report_path

    def _set_report_text(self, text):
        self.report_text.config(state="normal")
        self.report_text.delete("1.0", "end")
        max_chars = 200_000
        if len(text) > max_chars:
            text = text[:max_chars] + "\n\n" + self.S["rep_truncated_ui"]
        self.report_text.insert("1.0", text)
        self.report_text.config(state="disabled")

    # ------------------------------------------------------------------
    # باز کردن فایل گزارش / پوشه‌ی فایل
    # ------------------------------------------------------------------
    def open_report_file(self):
        if not self.last_report_path or not Path(self.last_report_path).exists():
            messagebox.showinfo(self.S["report_none_title"], self.S["report_none"])
            return
        self._open_path(str(self.last_report_path))

    def _open_path(self, path):
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except Exception:
            messagebox.showinfo(self.S["open_path_title"], str(path))

    @staticmethod
    def _human_size(n):
        for unit in ["B", "KB", "MB", "GB"]:
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    def on_row_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        values = self.tree.item(item, "values")
        if not values:
            return
        full_path = values[-1]
        folder = os.path.dirname(full_path) or full_path
        self._open_path(folder)

    # ------------------------------------------------------------------
    # بازگردانی (Undo) — تنها اقدامی که یک تأییدیه دارد، چون جداگانه و
    # آگاهانه توسط کاربر فراخوانی می‌شود.
    # اگر در همین نشست اصلاحی انجام نشده باشد، می‌توان یکی از لاگ‌های
    # اجراهای قبلی (فایل‌های undo_*.json در پوشه‌ی لاگ‌ها) را باز کرد.
    # ------------------------------------------------------------------
    def undo_last_fix(self):
        S = self.S
        if not self.last_undo_log:
            # لاگ‌های اجراهای قبلی روی دیسک؟
            previous_logs = []
            try:
                if LOG_DIR.exists():
                    previous_logs = sorted(LOG_DIR.glob("undo_*.json"), reverse=True)
            except Exception:
                previous_logs = []
            if not previous_logs:
                messagebox.showwarning(S["undo_none_title"], S["undo_none"])
                return
            if not messagebox.askyesno(S["undo_none_title"], S["undo_pick_prev"]):
                return
            chosen = filedialog.askopenfilename(
                title=S["undo_pick_title"],
                initialdir=str(LOG_DIR),
                filetypes=[("Undo log", "*.json"), ("All files", "*.*")],
            )
            if not chosen:
                return
            self._do_undo(Path(chosen), from_session=False)
            return
        self._do_undo(Path(self.last_undo_log), from_session=True)

    def _do_undo(self, log_path: Path, from_session: bool):
        S = self.S
        if not messagebox.askyesno(S["undo_confirm_title"], S["undo_confirm"]):
            return
        try:
            results = undo_rename_plan(log_path)
        except Exception as e:
            messagebox.showerror(S["err_undo_title"], str(e))
            return

        restored = sum(1 for r in results if r["status"] == "restored")
        errors = [r for r in results if r["status"] == "error"]
        missing = [r for r in results if r["status"] == "skipped_missing"]

        msg = S["undo_result"].format(restored=restored)
        if missing:
            msg += " | " + S["undo_missing"].format(n=len(missing))
        if errors:
            msg += " | " + S["undo_errors"].format(n=len(errors))
        messagebox.showinfo(S["undo_confirm_title"], msg)

        if from_session:
            self.undo_btn.config(state="disabled")
            self.last_undo_log = None
        self.status_var.set(S["undo_done_status"])


def main():
    root = tk.Tk()
    ensure_ui_font(root)
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    # آیکون پنجره (در ویندوز از .ico، در بقیه‌ی سیستم‌ها از .png)
    ico = resource_path("icon.ico")
    png = resource_path("icon.png")
    try:
        if ico and sys.platform.startswith("win"):
            root.iconbitmap(ico)
        elif png:
            root._icon_ref = tk.PhotoImage(file=png)
            root.iconphoto(True, root._icon_ref)
    except Exception:
        pass

    root._app_ref = FileTypeFixerApp(root)   # نگه داشتن مرجع تا زمان بسته شدن پنجره
    root.mainloop()


if __name__ == "__main__":
    main()
