# -*- coding: utf-8 -*-
"""
filetype_core.py  (engine revision 7)
------------------------------------------------------------------------
موتور تشخیص نوع واقعی فایل بر اساس محتوا (Magic Number / File Signature)
+ تشخیص پیشرفته‌ی زیرنوع‌های ZIP و OLE2 و MP4
+ جدول «خانواده‌ی پسوندها» برای جلوگیری از mismatch کاذب
+ نرمال‌سازی نام‌های مستعار پسوند برای جلوگیری از false mismatch

این ماژول هیچ وابستگی خارجی ندارد (فقط کتابخانه‌ی استاندارد پایتون).

تغییرات نسخه‌ی ۷ نسبت به نسخه‌ی ۶ (مقاوم‌سازی لاگ Undo):
  ۱. لاگ Undo به فرمت JSONL «فقط-افزودنی» (append-only) تبدیل شد؛ پیش از
     هر تغییر نام، هویت فایل مبدا (اندازه + زمان تغییر) با fsync ثبت
     می‌شود و مسیر نهایی واقعی هر موردِ دارای تصادم نام بلافاصله بعد از
     rename اضافه می‌شود. دیگر هیچ‌گاه فایل لاگ بازنویسی نمی‌شود؛ کرش در
     هر لحظه فقط «لاگ ناقص» می‌سازد، نه «لاگ غلط یا از دست رفته».
  ۲. undo_rename_plan پیش از بازگرداندن هر فایل، هویتش را با لاگ
     مقایسه می‌کند (اندازه + mtime)؛ فایلی که بعد از اصلاح تغییر کرده یا
     از نو ساخته شده باشد هرگز دست نمی‌خورد و با "error" گزارش می‌شود.
  ۳. اگر کرش بین rename و ثبت رکورد نهایی رخ داده باشد، Undo واریانت‌های
     «نام (۱)»، «نام (۲)»… را با هویت ثبت‌شده می‌آزماید و فایل واقعی را
     پیدا می‌کند.
  ۴. لاگ‌های نسخه‌ی ۱ (JSON یک‌تکه) هم همچنان خوانده می‌شوند.
  ۵. collect_files برای «تک‌فایل انتخاب‌شده» هم symlink را رد می‌کند و
     is_protected_root در صورت خطای resolve()، مسیر را «محافظت‌شده» فرض
     می‌کند (fail-safe).

تغییرات نسخه‌ی ۶ نسبت به نسخه‌ی ۵:
  ۱. امضاهای ASCII (GIF89a، RIFF…WAVE/WEBP/AVI ، FORM…AIFF، ustar،
     !<arch>، BZh91AY&SY) روی فایل متنیِ ساده هم تطبیق می‌کردند و فایل
     متنی به gif/wav/tar/deb/bz2 تغییر نام می‌گرفت؛ حالا اگر کل هدر متن
     ساده باشد، این امضاها اصلاً تطبیق داده نمی‌شوند (همین قانون برای
     torrent هم هست). torrent واقعی چون bencode است، همیشه probable است.
  ۲. ext_family(): پسوندهای «عضو» خانواده (opus/heic/m4v/oga و…) که به
    ‌عنوان زیرنوع تشخیص داده می‌شوند، قبلاً خانواده‌شان پیدا نمی‌شد و
     فایل oga/heif/mka به‌اشتباه تغییر نام می‌گرفت؛ حالا عضویت در همه‌ی
     خانواده‌ها بررسی می‌شود.

تغییرات نسخه‌ی ۵ نسبت به نسخه‌ی ۴ (رفع مثبت‌های کاذب):
  ۱. امضاهای ضعیف اعتبارسنجی ساختاری شدند: فایل متنی‌ای که با «ID3,»
     یا «BZhang» یا «OTTO» یا «MSCF» شروع می‌شود دیگر mp3/bz2/otf/cab
     تشخیص داده نمی‌شود. MP3/AAC با بررسی هدر فریم (و فریم بعدی)، و
     ICO/CUR/TTF/OTF/PSD/FLAC/FLV/CAB/BZ2/GZ/OGG/WASM/PDF/ftyp/PE با
     بررسی فیلدهای هدر تأیید می‌شوند.
  ۲. ZIP: ساختارهای مبهم (JAR/WAR و APK بدون classes.dex) دیگر «قطعی»
     نیستند و یک zip معمولی را به jar/war تغییر نام نمی‌دهند؛ kmz فقط
     وقتی doc.kml در ریشه باشد.
  ۳. [Content_Types].xml با سقف حجم خوانده می‌شود (ایمنی در برابر zip bomb).
  ۴. is_protected_root(): ریشه‌ی درایو و پوشه‌های سیستمی برای اجرای واقعی
     مسدودند.
  ۵. JSON خالی ({} و []) و JSONهای بزرگ‌تر درست تشخیص داده می‌شوند.

تغییرات نسخه‌ی ۴ نسبت به نسخه‌ی ۳:
  ۱. جدول EXTENSION_FAMILIES: اگر پسوند فعلی عضو «خانواده»ی نوع
     تشخیص‌داده‌شده باشد (مثلاً dll/sys برای امضای EXE، یا cr2/nef/dng
     برای امضای TIFF، یا webm برای Matroska، یا opus برای OGG، یا
     whl/vsix/nupkg/cbz برای ZIP و ...)، دیگر mismatch حساب نمی‌شود.
  ۲. پارس واقعی ساختار OLE2 (خواندن FAT و دایرکتوری Compound File،
     نه جست‌وجوی زیررشته‌ای): استریم‌ها با «نام دقیق entry» تشخیص داده
     می‌شوند؛ بنابراین سند Word که کلمه‌ی Book در متنش دارد دیگر xls
     تشخیص داده نمی‌شود و xlsهایی که استریم Workbookشان دور از ۱۶KB
     اول است هم درست تشخیص داده می‌شوند. فایل OLE با زیرنوع نامشخص
     (مثل MSI) دیگر به کور، "doc" تغییر نام نمی‌دهد.
  ۳. تشخیص‌های متنی (json/xml/html/svg/csv و...) همیشه confidence="text"
     هستند و به‌طور پیش‌فرض دست‌نخورده می‌مانند (قبلاً certain بودند).
  ۴. فقط پسوندهای «شناخته‌شده» اصلاح می‌شوند؛ اگر پسوند فعلی فایل در
     دنیای امضاها/خانواده‌ها نباشد (مثل .xyz)، فقط گزارش می‌شود.
     (فایل‌های بدون پسوند طبق تصمیم کاربر در اجرای واقعی پسوند می‌گیرند.)
  ۵. زیرنوع ZIP از [Content_Types].xml خوانده می‌شود؛ نسخه‌های
     ماکرو-دار و قالب و اسلایدشو (xlsm/docm/dotx/ppsx/...) دیگر به
     xlsx/docx/... تغییر نام نمی‌دهند.
  ۶. زیرنوع OGG از هدر خوانده می‌شود (OpusHead/Vorbis/Theora).

تغییرات نسخه‌ی ۳ نسبت به نسخه‌ی ۲:
  ۱. رفع باگ with_suffix: دیگر بخشی از نام فایل (مثل «Mr. Smith» یا
     «backup 2024.01») هنگام اصلاح از بین نمی‌رود؛ اگر پسوند فعلی معتبر
     نباشد، پسوند جدید «اضافه» می‌شود نه اینکه جایگزین نام شود.
  ۲. پشتیبانی از فایل‌های بدون پسوند: در اجرای واقعی پسوند درست به
     انتهای نام آن‌ها اضافه می‌شود. (فایل‌های مخفیِ بدون پسوند مثل
     .gitignore هرگز دست نمی‌خورند.)
  ۳. لاگ Undo «قبل» از شروع تغییر نام‌ها روی دیسک نوشته می‌شود
     (flush + fsync) تا در صورت قطع برق/کرش، بازگردانی کامل ممکن باشد.
  ۴. collect_files پوشه‌های سیستمی/زباله (Windows، Program Files،
     $RECYCLE.BIN، node_modules، .git و ...) و symlinkها را رد می‌کند.
  ۵. تفکیک Java Class از Mach-O Universal Binary (هر دو با CAFEBABE
     شروع می‌شوند) و افزودن AVIF به خانواده‌ی ftyp.
  ۶. اعتبارسنجی هدر BMP (حذف مثبت کاذب روی متن‌های عادی) و پشتیبانی
     BOM/UTF-16 در تشخیص فایل‌های متنی + تشخیص SVG بدون اعلان <?xml.
"""

import json
import os
import re
import time
import platform
import zipfile
from pathlib import Path

__version__ = "1.0.0"   # app version (same as the README badge)

# ----------------------------------------------------------------------------
# نرمال‌سازی نام‌های مستعار پسوند
# ----------------------------------------------------------------------------

EXTENSION_ALIASES = {
    "jpeg": "jpg",
    "jpe": "jpg",
    "jfif": "jpg",
    "tiff": "tif",
    "htm": "html",
    "xhtml": "html",
    "yml": "yaml",
    "mpeg": "mpg",
    "midi": "mid",
    "3gpp": "3gp",
    "3gpp2": "3g2",
    "m4b": "m4a",
    "heic": "heif",
    "heif": "heif",
    "mif1": "heif",
}


def normalize_ext(ext: str) -> str:
    """نام مستعار پسوند را به شکل استاندارد تبدیل می‌کند تا مقایسه‌ها درست باشد."""
    if not ext:
        return ext
    e = str(ext).lower().lstrip(".")
    return EXTENSION_ALIASES.get(e, e)


# ----------------------------------------------------------------------------
# خانواده‌های پسوند
# ----------------------------------------------------------------------------
# یک امضای بایتی معمولاً به «یک فرمت» اشاره دارد، نه به «یک پسوند واحد».
# مثلاً هر فایل PE (امضای MZ) می‌تواند exe/dll/sys/... باشد و هر فایل
# TIFF-هدر می‌تواند tif/tiff یا RAW دوربین (cr2/nef/arw/dng/...) باشد.
# اگر پسوند فعلی فایل عضو خانواده‌ی نوع تشخیص‌داده‌شده باشد، mismatch
# حساب نمی‌شود و هیچ تغییری انجام نمی‌گیرد.

EXTENSION_FAMILIES = {
    # --- Windows PE (امضای MZ): هر فایل اجرایی/کتابخانه‌ای ویندوز ---
    "exe": {"exe", "dll", "sys", "ocx", "scr", "cpl", "mui", "drv", "efi", "ax"},
    # --- TIFF و RAWهای مبتنی بر TIFF (همه هدر II*\0 یا MM\0* دارند) ---
    "tif": {"tif", "tiff", "cr2", "crw", "nef", "arw", "dng", "pef",
            "erf", "srw", "nrw", "kdc"},
    "cr3": {"cr3"},
    # --- Matroska / WebM (هر دو امضای EBML دارند) ---
    "mkv": {"mkv", "mka", "mks", "webm"},
    # --- خانواده‌ی OGG ---
    "ogg": {"ogg", "oga", "ogv", "opus", "spx"},
    # --- GZIP (tgz و svgz ذاتاً فایل gzip هستند) ---
    "gz": {"gz", "tgz", "svgz"},
    # --- SQLite (خیلی از برنامه‌ها دیتابیس را .db ذخیره می‌کنند) ---
    "sqlite": {"sqlite", "sqlite3", "db", "db3"},
    # --- PDF (فایل‌های Adobe Illustrator هم PDF هستند) ---
    "pdf": {"pdf", "ai"},
    # --- ZIP و همه‌ی فرمت‌های ZIP-Base ---
    "zip": {"zip", "vsix", "nupkg", "whl", "cbz", "cbr", "apk", "jar", "war",
            "ear", "xpi", "epub", "kmz", "odt", "ods", "odp", "odg", "odf",
            "odb", "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx",
            "xltm", "pptx", "ppsx", "pptm", "ppsm", "potx", "potm", "vsdx",
            "3mf", "xapk"},
    "rar": {"rar", "cbr"},
    # --- ELF (لینوکس) ---
    "elf": {"so", "elf", "o", "ko", "axf"},
    # --- خانواده‌ی ISO-BMFF (ftyp) ---
    "mp4": {"mp4", "m4a", "m4v", "m4b", "m4p"},
    "mov": {"mov"},
    "heif": {"heif", "heic", "hif"},
    "avif": {"avif"},
    # --- ASF (WMV/WMA هر دو GUID مشترک دارند) ---
    "wmv": {"wmv", "asf"},
    "wma": {"wma", "asf"},
    # --- Office قدیمی (OLE2) ---
    "doc": {"doc", "dot"},
    "xls": {"xls", "xlt", "xla", "xlm"},
    "ppt": {"ppt", "pot", "pps"},
    "msg": {"msg"},
    "vsd": {"vsd", "vss", "vst", "vdw"},
    "mdb": {"mdb"},
    "accdb": {"accdb"},
    # --- بقیه ---
    "aiff": {"aiff", "aif", "aifc"},
    "bmp": {"bmp", "dib"},
    "wav": {"wav"},
    "iso": {"iso", "img"},
    "ttf": {"ttf"},
    # --- فرمت‌های متنی (فقط وقتی گزینه‌ی پرریسک فعال است اهمیت دارند) ---
    "json": {"json", "geojson", "ipynb", "jsonl", "jsonc", "har"},
    "xml": {"xml", "csproj", "vbproj", "xaml", "resx", "config", "xsl",
            "xslt", "xsd", "rss", "atom", "kml", "gpx", "plist", "bpmn",
            "wsdl", "nuspec", "props", "targets", "admx", "adml"},
    "html": {"html", "htm", "xhtml", "php", "phtml", "jsp", "asp", "aspx",
             "shtml", "vue", "cshtml"},
    "svg": {"svg"},
}

# پسوندهایی که «وعده‌ی فرمت» نمی‌دهند و اصلاح‌شان روی امضای قطعی مجاز است
OPAQUE_EXTS = {"dat", "bin", "tmp", "bak", "old", "file"}

# پسوندهای متنی شناخته‌شده (این‌ها «باینری» حساب نمی‌شوند)
KNOWN_TEXTUAL_EXTS = {
    "txt", "csv", "json", "xml", "html", "svg", "yaml", "yml", "md", "log",
    "ini", "cfg", "conf", "sh", "py", "js", "ts", "pl", "rb", "php", "vue",
    "ipynb", "geojson", "jsonl", "jsonc", "har", "css", "sql", "bat", "ps1",
    "java", "c", "cpp", "h", "hpp", "cs", "go", "rs", "swift", "kt", "tex",
    "toml", "properties",
    # خانواده‌ی XML
    "csproj", "vbproj", "xaml", "resx", "config", "xsl", "xslt", "xsd",
    "rss", "atom", "kml", "gpx", "plist", "bpmn", "wsdl", "nuspec",
    "props", "targets", "admx", "adml",
    # خانواده‌ی HTML
    "phtml", "jsp", "asp", "aspx", "shtml", "cshtml",
}


def ext_family(ext_norm: str):
    """خانواده‌ی یک پسوند نرمال‌شده را برمی‌گرداند (خود پسوند همیشه عضو است).

    پسوند می‌تواند «کلید» خانواده باشد (مثل exe) یا فقط «عضو» آن (مثل
    opus که عضو خانواده‌ی ogg است، یا heic عضو heif، یا m4a عضو mp4).
    نسخه‌های قبلی فقط کلید را پیدا می‌کردند و در نتیجه فایل oga/heif/mka
    که با زیرنوع opus/heic/... تشخیص داده می‌شد، به‌اشتباه «mismatch» و
    تغییر نام می‌گرفت.

    نکته‌ی مهم: خانواده‌ی «zip» مستثناست — اعضای آن (docx/xlsx/jar/epub و…)
    «نام هم‌ارزِ یک فرمت» نیستند، بلکه زیرنوع دقیق‌ترِ یک کانتینر هستند؛
    پس zip واقعی که docx در آن است باید همچنان به docx تغییر نام کند
    (این از وظایف اصلی برنامه است) و فقط جهتِ برعکس محافظت می‌شود:
    فایل docx که زیرنوع دقیقش قابل تشخیص نیست، zip عمومی حساب می‌شود
    (چون docx عضو خانواده‌ی کلید zip است) و تغییر نام نمی‌گیرد."""
    fam = EXTENSION_FAMILIES.get(ext_norm)
    if fam:
        return set(fam) | {ext_norm}
    for key, members in EXTENSION_FAMILIES.items():
        if key != "zip" and ext_norm in members:
            return set(members) | {key}
    return {ext_norm}


def _build_known_extensions():
    """دنیای پسوندهای شناخته‌شده: همه‌ی امضاها + همه‌ی خانواده‌ها + مستعارها."""
    known = set(OPAQUE_EXTS) | set(KNOWN_TEXTUAL_EXTS)
    known.update(EXTENSION_ALIASES.keys())
    known.update(EXTENSION_ALIASES.values())
    for fam in EXTENSION_FAMILIES.values():
        known.update(fam)
    return known


KNOWN_EXTENSIONS = _build_known_extensions()


# ----------------------------------------------------------------------------
# توابع کمکی تطابق بایتی
# ----------------------------------------------------------------------------

def _match_simple(header, offset, magic):
    return header[offset:offset + len(magic)] == magic


def _match_webp(header):
    return header[0:4] == b"RIFF" and header[8:12] == b"WEBP"


def _match_wav(header):
    return header[0:4] == b"RIFF" and header[8:12] == b"WAVE"


def _match_avi(header):
    return header[0:4] == b"RIFF" and header[8:12] == b"AVI "


def _match_tar(header):
    """tar: جادوی ustar + اعتبارسنجی چک‌سام هدر (بایت‌های ۱۴۸-۱۵۵ با
    فیلد چک‌سام به‌عنوان ۸ فاصله شمرده می‌شود). این چک، فایل باینری‌ای
    که تصادفاً «ustar» در آفست ۲۵۷ دارد را حذف می‌کند."""
    if len(header) < 512 or header[257:262] != b"ustar":
        return False
    try:
        stored = header[148:156].decode("ascii", "ignore").strip("\x00 ")
        if not stored:
            return False
        stored_val = int(stored, 8)
    except (ValueError, UnicodeDecodeError):
        return False
    unsigned = sum(header[:148]) + 8 * 0x20 + sum(header[156:512])
    if stored_val == unsigned:
        return True
    signed = sum(b - 256 if b > 127 else b for b in header[:148]) \
        + 8 * 0x20 \
        + sum(b - 256 if b > 127 else b for b in header[156:512])
    return stored_val == signed


def _match_pfb(h):
    """PostScript Type 1 (PFB): سگمنت‌های 0x80 0x01/0x02 با طول ۳۲بیتی."""
    if len(h) < 10 or h[0] != 0x80 or h[1] != 0x01:
        return False
    seg = int.from_bytes(h[2:6], "little")
    return 0 < seg < 0x4000000


def _match_djvu(h):
    """DjVu: AT&TFORM + نوع فرم (DJVU/DJVM/DJV) در آفست ۱۲."""
    return (len(h) >= 16 and h[0:8] == b"AT&TFORM"
            and h[12:16] in (b"DJVU", b"DJVM", b"DJV"))


def _match_ole(header):
    return header[0:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _match_mdb(header):
    return header[4:19] == b"Standard Jet DB"


def _match_accdb(header):
    return header[4:19] == b"Standard ACE DB"


def _match_bmp(header):
    """
    BM + اندازه‌ی هدر DIB در آفست ۱۴ باید یکی از مقادیر استاندارد باشد.
    این چک، فایل‌های متنی‌ای که اتفاقی با «BM» شروع می‌شوند را حذف می‌کند.
    """
    if header[0:2] != b"BM" or len(header) < 18:
        return False
    dib = int.from_bytes(header[14:18], "little")
    return dib in (12, 40, 52, 56, 64, 108, 124)


def _match_java_class(header):
    """CAFEBABE هم مال Java Class است هم Mach-O Universal؛
    نسخه‌ی major در آفست ۶-۷ برای class بین ۴۵ تا ~۹۰ است."""
    if header[0:4] != b"\xca\xfe\xba\xbe" or len(header) < 8:
        return False
    major = int.from_bytes(header[6:8], "big")
    return 45 <= major <= 90


def _match_id3(h):
    """ID3v2: نسخه‌ی major ∈ {2,3,4} و ۴ بایت اندازه «syncsafe» (بیت بالا صفر)."""
    if len(h) < 10 or h[0:3] != b"ID3":
        return False
    if h[3] not in (2, 3, 4) or h[4] == 0xFF:
        return False
    return not any(b & 0x80 for b in h[6:10])


_MP3_BR_V1_L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
_MP3_BR_V2_L3 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
_MP3_SR = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}


def _mp3_frame_len(h, off):
    """طول فریم MP3 (Layer III) در آفست off؛ اگر هدر فریم معتبر نبود 0."""
    if len(h) < off + 4 or h[off] != 0xFF or (h[off + 1] & 0xE0) != 0xE0:
        return 0
    ver = (h[off + 1] >> 3) & 3
    layer = (h[off + 1] >> 1) & 3
    if ver == 1 or layer != 1:          # version رزرو / فقط Layer III
        return 0
    br_idx = h[off + 2] >> 4
    sr_idx = (h[off + 2] >> 2) & 3
    if br_idx in (0, 15) or sr_idx == 3:
        return 0
    bitrate = (_MP3_BR_V1_L3 if ver == 3 else _MP3_BR_V2_L3)[br_idx] * 1000
    pad = (h[off + 2] >> 1) & 1
    return (144 if ver == 3 else 72) * bitrate // _MP3_SR[ver][sr_idx] + pad


def _match_mp3_frames(h):
    """MP3 بدون ID3: هدر فریم اول باید معتبر باشد و فریم بعدی هم سر جایش.
    خروجی: \"certain\" / \"probable\" (فایل خیلی کوتاه) / None."""
    n = _mp3_frame_len(h, 0)
    if not n:
        return None
    if len(h) >= n + 4:
        return "certain" if _mp3_frame_len(h, n) else None
    return "probable"


def _adts_frame_len(h, off):
    if len(h) < off + 7 or h[off] != 0xFF or (h[off + 1] & 0xF6) != 0xF0:
        return 0
    if ((h[off + 2] >> 2) & 0xF) > 12:   # اندیس نرخ نمونه‌برداری نامعتبر
        return 0
    n = ((h[off + 3] & 3) << 11) | (h[off + 4] << 3) | (h[off + 5] >> 5)
    return n if n >= 7 else 0


def _match_aac_adts(h):
    n = _adts_frame_len(h, 0)
    if not n:
        return None
    if len(h) >= n + 7:
        return "certain" if _adts_frame_len(h, n) else None
    return "probable"


def _match_bz2(h):
    return (len(h) >= 10 and h[0:3] == b"BZh"
            and h[3:4].isdigit() and h[3:4] != b"0"
            and h[4:10] in (b"1AY&SY", b"\x17rE8P\x90"))


def _match_gzip(h):
    return len(h) >= 4 and h[0:2] == b"\x1f\x8b" and h[2] == 8 and (h[3] & 0xE0) == 0


def _match_sfnt(h, tag):
    """TrueType/OpenType: numTables و searchRange باید با هم سازگار باشند."""
    if len(h) < 12 or h[0:4] != tag:
        return False
    n = int.from_bytes(h[4:6], "big")
    if not 1 <= n <= 128:
        return False
    return int.from_bytes(h[6:8], "big") == 16 * (1 << (n.bit_length() - 1))


def _match_ttc(h):
    if len(h) < 12 or h[0:4] != b"ttcf":
        return False
    return (h[4:8] in (b"\x00\x01\x00\x00", b"\x00\x02\x00\x00")
            and 1 <= int.from_bytes(h[8:12], "big") <= 256)


def _match_woff(h, tag):
    return (len(h) >= 8 and h[0:4] == tag
            and h[4:8] in (b"\x00\x01\x00\x00", b"OTTO", b"true"))


def _match_ico(h, kind):
    """ICO (kind=1) / CUR (kind=2): تعداد تصاویر و اولین entry دایرکتوری."""
    if len(h) < 22 or h[0:4] != b"\x00\x00" + bytes([kind]) + b"\x00":
        return False
    n = int.from_bytes(h[4:6], "little")
    if not 1 <= n <= 256:
        return False
    e = h[6:22]
    if e[3] != 0:                                   # بایت رزرو
        return False
    if kind == 1:
        if int.from_bytes(e[4:6], "little") not in (0, 1):
            return False
        if int.from_bytes(e[6:8], "little") not in (0, 1, 4, 8, 16, 24, 32):
            return False
    size = int.from_bytes(e[8:12], "little")
    offset = int.from_bytes(e[12:16], "little")
    return size > 0 and offset >= 6 + 16 * n


def _match_psd(h):
    return (len(h) >= 12 and h[0:4] == b"8BPS"
            and int.from_bytes(h[4:6], "big") in (1, 2) and h[6:12] == b"\0" * 6)


def _match_cab(h):
    return (len(h) >= 36 and h[0:4] == b"MSCF" and h[4:8] == b"\0\0\0\0"
            and h[12:16] == b"\0\0\0\0" and h[20:24] == b"\0\0\0\0"
            and h[24:26] == b"\x03\x01")


def _match_flac(h):
    return len(h) >= 8 and h[0:4] == b"fLaC" and (h[4] & 0x7F) == 0 and h[5:8] == b"\x00\x00\x22"


def _match_flv(h):
    return (len(h) >= 9 and h[0:4] == b"FLV\x01" and (h[4] & 0xFA) == 0
            and h[5:9] == b"\x00\x00\x00\x09")


def _match_wasm(h):
    return h[0:8] == b"\x00asm\x01\x00\x00\x00"


def _match_ogg(h):
    return len(h) >= 5 and h[0:4] == b"OggS" and h[4] == 0


def _match_pdf(h):
    return re.match(rb"%PDF-\d\.\d", h[:8]) is not None


def _match_jpeg(h):
    return len(h) >= 4 and h[0:3] == b"\xff\xd8\xff" and h[3] >= 0xC0


def _match_ftyp(h):
    if len(h) < 12 or h[4:8] != b"ftyp":
        return False
    size = int.from_bytes(h[0:4], "big")
    return 12 <= size <= 1024 and all(0x20 <= b < 0x7F for b in h[8:12])


def _match_pe(h):
    """Windows PE: MZ + اشاره‌گر e_lfanew به امضای «PE\\0\\0»."""
    if len(h) < 64 or h[0:2] != b"MZ":
        return False
    off = int.from_bytes(h[0x3C:0x40], "little")
    if off + 4 <= len(h):
        return h[off:off + 4] == b"PE\x00\x00"
    return 0 < off < 0x10000000        # خارج از هدر خوانده‌شده؛ منطقی است


def _match_torrent(header):
    if not header.startswith(b"d"):
        return False
    return b"4:info" in header[:2048] or b"8:announce" in header[:2048]


ASF_GUID = b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"
ASF_VIDEO_STREAM_GUID = b"\xc9\xef\x19\xbc\xa6\x9e\xd1\x11\x8e\xe6\x00\xc0\x4f\xd9\xba\x98"
ASF_AUDIO_STREAM_GUID = b"\xcb\xaa\x78\x96\xa3\x8e\xcf\x11\x8b\xae\x00\xd0\xf6\xca\x92\x24"


def _match_asf(header):
    return header[0:16] == ASF_GUID


# ----------------------------------------------------------------------------
# زیرنوع OLE2 (doc/xls/ppt/msg/vsd) با پارس واقعی ساختار Compound File
# ----------------------------------------------------------------------------
#
# نکته‌ی مهم: فایل‌های OLE2 (doc/xls/ppt/msi/...) «دایرکتوری» دارند؛
# نام استریم‌ها به‌صورت entry های ۱۲۸ بایتی با نام UTF-16LE ذخیره می‌شوند.
# روش غلطِ قدیمی، جست‌وجوی زیررشته‌ای در بایت‌های خام بود که دو مشکل داشت:
#   ۱. فقط ۱۶ کیلوبایت اول خوانده می‌شد، ولی نام استریم‌ها (مثلاً
#      «Workbook» در یک xls چند صد کیلوبایتی) معمولاً جای دیگری است؛
#   ۲. سند Word که در متنش کلمه‌ی «Book» دارد، xls تشخیص داده می‌شد.
# روش درست: خواندن زنجیره‌ی FAT و سکتورهای دایرکتوری و تطبیق «نام دقیق»
# entry ها. این روش از موقعیت استریم در فایل مستقل است و فقط روی نام‌های
# واقعی دایرکتوری کار می‌کند.

_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_CFB_ENDOFCHAIN = 0xFFFFFFFE
_CFB_FREESECT = 0xFFFFFFFF
_CFB_FATSECT = 0xFFFFFFFD
_CFB_DIFSECT = 0xFFFFFFFC


def _read_cfb_sector(f, sec: int, ssz: int):
    # MS-CFB: sector N lives at (N + 1) * sector_size.
    # For 512-byte sectors this is the same as 512 + N*512; for 4096-byte
    # sectors the old code started reading at 512 and shifted everything.
    f.seek((sec + 1) * ssz)
    return f.read(ssz)


def read_cfb_directory_names(path) -> list:
    """
    نام‌های تمام entry های دایرکتوری یک فایل OLE2 (Compound File) را
    برمی‌گرداند. اگر ساختار قابل پارس نباشد، None برمی‌گرداند.
    فقط سکتورهای FAT/DIFAT/دایرکتوری خوانده می‌شوند، نه کل فایل؛
    پس برای فایل‌های چند صد مگابایتی هم سریع است.
    """
    try:
        if os.path.getsize(path) < 512:
            return None
        with open(path, "rb") as f:
            header = f.read(512)
            if len(header) < 512 or header[0:8] != _CFB_MAGIC:
                return None
            sector_shift = int.from_bytes(header[30:32], "little")
            if sector_shift not in (9, 12):        # 512 یا 4096 بایت
                return None
            ssz = 1 << sector_shift
            num_fat = int.from_bytes(header[44:48], "little")
            first_dir = int.from_bytes(header[48:52], "little")
            first_difat = int.from_bytes(header[68:72], "little")
            if first_dir >= _CFB_ENDOFCHAIN:
                return None

            # DIFAT: ۱۰۹ شماره‌ی اول در خودِ هدر است، بقیه در زنجیره‌ی DIFAT
            fat_sectors = []
            for i in range(109):
                v = int.from_bytes(header[76 + 4 * i: 80 + 4 * i], "little")
                if v < _CFB_DIFSECT:
                    fat_sectors.append(v)
            sec = first_difat
            guard = 0
            while sec < _CFB_DIFSECT and guard < 100_000:
                guard += 1
                data = _read_cfb_sector(f, sec, ssz)
                if len(data) < ssz:
                    return None
                for i in range((ssz // 4) - 1):
                    v = int.from_bytes(data[4 * i: 4 * i + 4], "little")
                    if v < _CFB_DIFSECT:
                        fat_sectors.append(v)
                sec = int.from_bytes(data[ssz - 4: ssz], "little")
            if num_fat:
                fat_sectors = fat_sectors[:num_fat]

            # خواندن FAT
            fat = []
            for s in fat_sectors:
                data = _read_cfb_sector(f, s, ssz)
                if len(data) < ssz:
                    return None
                fat.extend(int.from_bytes(data[4 * i: 4 * i + 4], "little")
                           for i in range(ssz // 4))
            if not fat:
                return None

            # زنجیره‌ی سکتورهای دایرکتوری
            dir_data = b""
            sec = first_dir
            seen = set()
            while sec < _CFB_ENDOFCHAIN and sec not in seen:
                seen.add(sec)
                if sec >= len(fat):
                    break
                data = _read_cfb_sector(f, sec, ssz)
                if len(data) < ssz:
                    return None
                dir_data += data
                sec = fat[sec]

            # پارس entry های ۱۲۸ بایتی دایرکتوری
            names = []
            for off in range(0, len(dir_data) - 127, 128):
                e = dir_data[off: off + 128]
                name_len = int.from_bytes(e[64:66], "little")
                etype = e[66]
                if etype in (1, 2, 5) and 0 < name_len <= 64 and name_len % 2 == 0:
                    try:
                        name = e[:name_len].decode("utf-16-le").rstrip("\x00")
                    except Exception:
                        continue
                    if name and all(ch >= " " for ch in name):
                        names.append(name)
            return names if names else None
    except Exception:
        return None


def detect_ole_subtype(path):
    """
    زیرنوع فایل OLE2 را از «نام دقیق استریم‌های دایرکتوری» تشخیص می‌دهد.
    خروجی: (پسوند یا None، نام نوع، سطح اطمینان)
      - زیرنوع مشخص شد   -> (ext، نام، "certain")
      - OLE هست ولی زیرنوع شناخته نشد (مثل MSI)
                         -> (None، نام، "probable")  ← هرگز تغییر نام نمی‌دهد
    """
    names = read_cfb_directory_names(path)
    if not names:
        return None, "OLE2 Compound File (Unspecified subtype)", "probable"

    # Outlook .msg استریم‌های اختصاصی خودش را دارد
    if any(n.startswith("__substg1.0_") or n.startswith("__nameid_version1.0")
           or n.startswith("__recip_version1.0") for n in names):
        return "msg", "Outlook Message (.msg)", "certain"
    if "PowerPoint Document" in names:
        return "ppt", "PowerPoint Presentation (Legacy .ppt)", "certain"
    # فقط نام دقیق entry؛ «Book» نام استریم Excel 4/5 است. جست‌وجوی
    # زیررشته‌ای اینجا ممنوع است (متن Word حاوی Book می‌باخت!)
    if "Workbook" in names or "Book" in names:
        return "xls", "Excel Spreadsheet (Legacy .xls)", "certain"
    if "WordDocument" in names:
        return "doc", "Word Document (Legacy .doc)", "certain"
    if "VisioDocument" in names:
        return "vsd", "Visio Drawing (VSD)", "certain"
    return None, "OLE2 Compound File (MS Office / MSI / Unspecified)", "probable"


# ----------------------------------------------------------------------------
# زیرنوع OGG (Opus/Vorbis/Theora)
# ----------------------------------------------------------------------------

def detect_ogg_subtype(header):
    """OggS + نامکد کدک در ابتدای فایل؛ اگر کدک شناخته نشد، عمومی/احتمالی.
    در فایل‌های واقعی OGG، بسته‌ی اول بعد از هدر ۲۷+۱ بایتی صفحه می‌آید
    (معمولاً آفست ۲۸)؛ برای اطمینان در ۶۴ بایت اول جست‌وجو می‌کنیم."""
    head = header[:64]
    if b"OpusHead" in head:
        return "opus", "Opus Audio (OGG)", "certain"
    if b"\x01vorbis" in head:
        return "ogg", "OGG Audio (Vorbis)", "certain"
    if b"\x80theora" in head:
        return "ogv", "OGG Video (Theora)", "certain"
    return "ogg", "OGG Media (Unspecified codec)", "probable"


# ----------------------------------------------------------------------------
# زیرنوع ftyp (خانواده‌ی MP4)
# ----------------------------------------------------------------------------

def detect_ftyp_subtype(header):
    brand = header[8:12].decode("ascii", errors="ignore").strip().lower()
    if brand == "qt":
        return "mov", "QuickTime Video (MOV)"
    if brand.startswith("m4v"):
        return "m4v", "M4V Video"
    if brand.startswith("m4a"):
        return "m4a", "M4A Audio (AAC)"
    if brand.startswith("m4b"):
        return "m4a", "M4B Audiobook (AAC)"
    if brand.startswith("3gp"):
        return "3gp", "3GPP Video"
    if brand.startswith("3g2"):
        return "3g2", "3GPP2 Video"
    if brand in ("avif", "avis"):
        return "avif", "AVIF Image"
    if brand in ("heic", "heix", "heim", "heis"):
        return "heic", "HEIC Image (HEIF)"
    if brand in ("hevc", "hevx", "hevm", "hevs"):
        return "heic", "HEIC Image Sequence (HEIF)"
    if brand in ("mif1", "msf1"):
        return "heif", "HEIF Image"
    if brand in ("crx", "cr3"):
        return "cr3", "Canon RAW Image (CR3)"
    return "mp4", "MP4 Video Container"


def detect_asf_subtype(path):
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
    except Exception:
        return "wmv", "Windows Media (ASF Container)"
    has_video = ASF_VIDEO_STREAM_GUID in data
    has_audio = ASF_AUDIO_STREAM_GUID in data
    if has_video:
        return "wmv", "Windows Media Video (WMV)"
    if has_audio:
        return "wma", "Windows Media Audio (WMA)"
    return "wmv", "Windows Media (ASF Container)"


# ----------------------------------------------------------------------------
# زیرنوع ZIP (apk/docx/xlsx/pptx/vsdx/jar/war/xpi/kmz/odt/...)
# ----------------------------------------------------------------------------

_ZIP_MIME_MAP = {
    b"application/epub+zip": ("epub", "EPUB E-Book"),
    b"application/vnd.oasis.opendocument.text": ("odt", "OpenDocument Text (ODT)"),
    b"application/vnd.oasis.opendocument.spreadsheet": ("ods", "OpenDocument Spreadsheet (ODS)"),
    b"application/vnd.oasis.opendocument.presentation": ("odp", "OpenDocument Presentation (ODP)"),
    b"application/vnd.oasis.opendocument.graphics": ("odg", "OpenDocument Drawing (ODG)"),
    b"application/vnd.oasis.opendocument.formula": ("odf", "OpenDocument Formula (ODF)"),
    b"application/vnd.oasis.opendocument.database": ("odb", "OpenDocument Database (ODB)"),
    # legacy OpenOffice.org 1.x formats
    b"application/vnd.sun.xml.writer": ("sxw", "OpenOffice.org Writer (SXW)"),
    b"application/vnd.sun.xml.calc": ("sxc", "OpenOffice.org Calc (SXC)"),
    b"application/vnd.sun.xml.impress": ("sxi", "OpenOffice.org Impress (SXI)"),
    b"application/vnd.sun.xml.draw": ("sxd", "OpenOffice.org Draw (SXD)"),
    b"application/vnd.sun.xml.math": ("sxm", "OpenOffice.org Math (SXM)"),
}

# بخش اصلی هر برنامه‌ی OOXML و نگاشتِ (عادی، ماکرو، قالب، ماکرو+قالب، اسلایدشو، ماکرو+اسلایدشو)
_OOXML_APPS = {
    "/word/document.xml": ("docx", "docm", "dotx", "dotm", None, None),
    "/xl/workbook.xml": ("xlsx", "xlsm", "xltx", "xltm", None, None),
    "/ppt/presentation.xml": ("pptx", "pptm", "potx", "potm", "ppsx", "ppsm"),
}
_OOXML_NAMES = {
    "/word/document.xml": {
        "docx": "Word Document (OOXML)", "docm": "Word Macro-Enabled Document (DOCM)",
        "dotx": "Word Template (DOTX)", "dotm": "Word Macro-Enabled Template (DOTM)"},
    "/xl/workbook.xml": {
        "xlsx": "Excel Spreadsheet (OOXML)", "xlsm": "Excel Macro-Enabled Workbook (XLSM)",
        "xltx": "Excel Template (XLTX)", "xltm": "Excel Macro-Enabled Template (XLTM)"},
    "/ppt/presentation.xml": {
        "pptx": "PowerPoint Presentation (OOXML)", "pptm": "PowerPoint Macro-Enabled Presentation (PPTM)",
        "potx": "PowerPoint Template (POTX)", "potm": "PowerPoint Macro-Enabled Template (POTM)",
        "ppsx": "PowerPoint Slide Show (PPSX)", "ppsm": "PowerPoint Macro-Enabled Slide Show (PPSM)"},
}


_ZIP_MEMBER_LIMIT = 1024 * 1024      # ۱ مگابایت؛ جلوگیری از zip bomb


def _read_zip_member(z, name, limit=_ZIP_MEMBER_LIMIT):
    """عضو کوچک zip را با سقف حجم می‌خواند؛ اگر بزرگ‌تر از سقف بود None."""
    try:
        info = z.getinfo(name)
        if info.file_size > limit:
            return None
        with z.open(info) as f:
            return f.read(limit)
    except Exception:
        return None


def _detect_ooxml_subtype(z):
    """
    از [Content_Types].xml زیرنوت دقیق OOXML را درمی‌آورد تا فایل‌های
    ماکرو-دار و قالب‌ها و اسلایدشوها (xlsm/docm/dotx/ppsx/...) به اشتباه
    xlsx/docx/... تشخیص داده نشوند.
    """
    raw = _read_zip_member(z, "[Content_Types].xml")
    if raw is None:
        return None
    ct = raw.decode("utf-8", "replace")

    types = {}
    for m in re.finditer(r'PartName="([^"]+)"\s+ContentType="([^"]+)"', ct):
        types[m.group(1)] = m.group(2)
    for m in re.finditer(r'ContentType="([^"]+)"\s+PartName="([^"]+)"', ct):
        types.setdefault(m.group(2), m.group(1))

    for part, (plain, macro, template, macro_template, show, macro_show) in _OOXML_APPS.items():
        mt = types.get(part)
        if not mt:
            continue
        mt = mt.lower()
        has_macro = "macroenabled" in mt
        has_template = "template" in mt
        has_show = "slideshow" in mt
        if has_macro and has_show:
            ext = macro_show
        elif has_macro and has_template:
            ext = macro_template
        elif has_macro:
            ext = macro
        elif has_show:
            ext = show
        elif has_template:
            ext = template
        else:
            ext = plain
        if ext:
            return ext, _OOXML_NAMES[part][ext]
    return None


def _detect_manifest_subtype(z):
    """Subtype of ODF/OpenOffice from the media-type of the "/" entry in
    META-INF/manifest.xml (attribute order does not matter)."""
    raw = _read_zip_member(z, "META-INF/manifest.xml")
    if raw is None:
        return None
    s = raw.decode("utf-8", "replace")
    for m in re.finditer(r"<manifest:file-entry\b[^>]*>", s):
        tag = m.group(0)
        if re.search(r'full-path\s*=\s*"/"', tag) is None:
            continue
        mt = re.search(r'media-type\s*=\s*"([^"]*)"', tag)
        if mt:
            key = mt.group(1).strip().lower().encode("ascii", "ignore")
            if key in _ZIP_MIME_MAP:
                return _ZIP_MIME_MAP[key]
    return None


def detect_zip_subtype(path):
    """خروجی: (پسوند، نام نوع، سطح اطمینان).

    فقط ساختارهای بدون ابهام «certain» هستند (OOXML، ODF، EPUB، APK واقعی،
    VSIX، WHL، XPI، KMZ با doc.kml در ریشه). ساختارهایی که یک zip معمولیِ
    پروژه هم می‌تواند داشته باشد (META-INF/MANIFEST.MF، WEB-INF/web.xml،
    AndroidManifest.xml بدون classes.dex) فقط «ZIP / probable» برمی‌گردانند،
    تا یک zip معمولی هرگز به jar/war/apk تغییر نام نگیرد.
    """
    hint = None
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())

            if "AndroidManifest.xml" in names:
                if "classes.dex" in names or "resources.arsc" in names:
                    return "apk", "Android Package (APK)", "certain"
                hint = "Android project layout"

            # OOXML: زیرنوع دقیق از [Content_Types].xml (ماکرو/قالب/اسلایدشو)
            if "[Content_Types].xml" in names:
                sub = _detect_ooxml_subtype(z)
                if sub:
                    return sub[0], sub[1], "certain"

            if "word/document.xml" in names:
                return "docx", "Word Document (OOXML)", "certain"
            if "xl/workbook.xml" in names:
                return "xlsx", "Excel Spreadsheet (OOXML)", "certain"
            if "ppt/presentation.xml" in names:
                return "pptx", "PowerPoint Presentation (OOXML)", "certain"
            if "visio/document.xml" in names:
                return "vsdx", "Visio Drawing (VSDX)", "certain"
            if "install.rdf" in names:
                return "xpi", "Firefox Extension (XPI)", "certain"
            if "extension.vsixmanifest" in names:
                return "vsix", "Visual Studio / VS Code Extension (VSIX)", "certain"
            if any(n.endswith(".dist-info/WHEEL") for n in names):
                return "whl", "Python Wheel Package", "certain"
            if "doc.kml" in names:                       # فقط در ریشه (طبق مشخصات KMZ)
                return "kmz", "Google Earth KMZ", "certain"

            if "mimetype" in names:
                mt = _read_zip_member(z, "mimetype", 1024)
                if mt is not None:
                    mt = mt.strip()
                    if mt in _ZIP_MIME_MAP:
                        ext, name = _ZIP_MIME_MAP[mt]
                        return ext, name, "certain"

            # legacy OpenOffice 1.x (and ODF without a mimetype entry):
            # the doc type lives in META-INF/manifest.xml; these used to be
            # reported as a generic zip (and renamed to .zip in risky mode!)
            if "content.xml" in names and "META-INF/manifest.xml" in names:
                sub = _detect_manifest_subtype(z)
                if sub:
                    return sub[0], sub[1], "certain"

            if "WEB-INF/web.xml" in names:
                hint = "Java web app layout"
            elif "META-INF/MANIFEST.MF" in names and hint is None:
                hint = "Java archive layout"
    except Exception:
        pass
    if hint:
        return "zip", f"ZIP Archive ({hint})", "probable"
    return "zip", "ZIP Archive", "probable"


# ----------------------------------------------------------------------------
# پایگاه امضاها
# ترتیب مهم است: امضاهای طولانی‌تر/خاص‌تر باید قبل از امضاهای عمومی‌تر بیایند
# (مثلاً MDB باید قبل از TTF چک شود چون هر دو با 00 01 00 00 شروع می‌شوند)
# ----------------------------------------------------------------------------

# امضاهایی که بخش متمایزِ آن‌ها کامل ASCII است (مثل «GIF89a»، «RIFF....WAVE»،
# «ustar» در tar، «!<arch>» در deb، «BZh91AY&SY» در bz2). این امضاها روی یک
# فایل «متن ساده» هم می‌توانند تطبیق کنند؛ پس اگر کل هدر فایل متن به نظر برسد،
# نتیجه به «probable» تنزل می‌کند و دیگر به‌طور پیش‌فرض تغییر نام نمی‌دهد.
# (فایل‌های واقعی این فرمت‌ها بلافاصله بعد از هدر بایت باینری دارند و
# is_probably_text آن‌ها را متن حساب نمی‌کند.)
_ASCII_MAGIC_EXTS = {"gif", "webp", "wav", "avi", "aiff", "tar", "deb",
                     "iso", "bz2", "djvu"}

SIGNATURES = [
    # ---------------- تصاویر ----------------
    {"match": lambda h, p: _match_simple(h, 0, b"\x89PNG\r\n\x1a\n"), "ext": "png", "name": "PNG Image"},
    {"match": lambda h, p: _match_jpeg(h), "ext": "jpg", "name": "JPEG Image"},
    {"match": lambda h, p: _match_simple(h, 0, b"GIF87a") or _match_simple(h, 0, b"GIF89a"), "ext": "gif", "name": "GIF Image"},
    {"match": lambda h, p: _match_bmp(h), "ext": "bmp", "name": "Bitmap Image"},
    {"match": lambda h, p: _match_simple(h, 0, b"II*\x00"), "ext": "tif", "name": "TIFF Image / Camera RAW (LE)", "confidence": "probable"},
    {"match": lambda h, p: _match_simple(h, 0, b"MM\x00*"), "ext": "tif", "name": "TIFF Image / Camera RAW (BE)", "confidence": "probable"},
    {"match": lambda h, p: _match_psd(h), "ext": "psd", "name": "Photoshop Document (PSD)"},
    {"match": lambda h, p: _match_ico(h, 2), "ext": "cur", "name": "Windows Cursor (CUR)"},
    {"match": lambda h, p: _match_ico(h, 1), "ext": "ico", "name": "Icon File"},
    {"match": lambda h, p: _match_webp(h), "ext": "webp", "name": "WEBP Image"},
    {"match": lambda h, p: _match_simple(h, 0, b"<?xml") and b"<svg" in h, "ext": "svg", "name": "SVG Image"},

    # ---------------- اسناد ----------------
    {"match": lambda h, p: _match_pdf(h), "ext": "pdf", "name": "PDF Document"},
    {"match": lambda h, p: _match_simple(h, 0, b"{\\rtf1"), "ext": "rtf", "name": "RTF Document"},
    # MDB/ACCDB باید قبل از OLE عمومی و قبل از TTF بررسی شوند
    {"match": lambda h, p: _match_mdb(h), "ext": "mdb", "name": "Microsoft Access Database (MDB)"},
    {"match": lambda h, p: _match_accdb(h), "ext": "accdb", "name": "Microsoft Access Database (ACCDB)"},
    {"match": lambda h, p: _match_ole(h), "ext": "doc", "name": "Legacy MS Office Compound File", "ole_special": True},

    # ---------------- آرشیوها / بسته‌ها ----------------
    {"match": lambda h, p: _match_simple(h, 0, b"PK\x03\x04") or _match_simple(h, 0, b"PK\x05\x06"), "ext": "zip", "name": "ZIP Archive", "zip_special": True},
    {"match": lambda h, p: _match_simple(h, 0, b"Rar!\x1a\x07\x00") or _match_simple(h, 0, b"Rar!\x1a\x07\x01\x00"), "ext": "rar", "name": "RAR Archive"},
    {"match": lambda h, p: _match_gzip(h), "ext": "gz", "name": "GZIP Archive"},
    {"match": lambda h, p: _match_simple(h, 0, b"7z\xbc\xaf\x27\x1c"), "ext": "7z", "name": "7-Zip Archive"},
    {"match": lambda h, p: _match_bz2(h), "ext": "bz2", "name": "BZIP2 Archive"},
    {"match": lambda h, p: _match_simple(h, 0, b"\xfd7zXZ\x00"), "ext": "xz", "name": "XZ Archive"},
    {"match": lambda h, p: _match_djvu(h), "ext": "djvu", "name": "DjVu Document"},
    {"match": lambda h, p: _match_simple(h, 0, b"\x28\xb5\x2f\xfd"), "ext": "zst", "name": "Zstandard Archive (ZST)"},
    {"match": lambda h, p: _match_simple(h, 0, b"\x04\x22\x4d\x18"), "ext": "lz4", "name": "LZ4 Compressed Data"},
    {"match": lambda h, p: _match_tar(h), "ext": "tar", "name": "TAR Archive"},
    {"match": lambda h, p: _match_simple(h, 0, b"!<arch>\ndebian-binary"), "ext": "deb", "name": "Debian Package"},
    {"match": lambda h, p: _match_simple(h, 0, b"\xed\xab\xee\xdb"), "ext": "rpm", "name": "RPM Package"},
    {"match": lambda h, p: _match_cab(h), "ext": "cab", "name": "Windows CAB Archive"},
    {"match": lambda h, p: len(h) >= 32774 and h[32769:32774] == b"CD001", "ext": "iso", "name": "ISO 9660 Disc Image"},
    {"match": lambda h, p: _match_torrent(h), "ext": "torrent", "name": "BitTorrent File", "confidence": "probable"},
    # (فایل torrent ذاتاً bencode/متنی است؛ «4:info» می‌تواند در متن ساده
    #  هم بیاید، پس هرگز «قطعی» حساب نمی‌شود.)

    # ---------------- اجرایی / باینری ----------------
    {"match": lambda h, p: _match_pe(h), "ext": "exe", "name": "Windows Executable / Library (EXE/DLL/SYS)", "confidence": "probable"},
    {"match": lambda h, p: _match_simple(h, 0, b"\x7fELF"), "ext": "elf", "name": "Linux Executable (ELF)"},
    {"match": lambda h, p: _match_simple(h, 0, b"\xfe\xed\xfa\xce") or _match_simple(h, 0, b"\xfe\xed\xfa\xcf") or _match_simple(h, 0, b"\xcf\xfa\xed\xfe") or _match_simple(h, 0, b"\xce\xfa\xed\xfe"), "ext": "macho", "name": "Mach-O Binary (macOS)"},
    # Java Class قبل از Mach-O Universal چک می‌شود (هر دو CAFEBABE دارند)
    {"match": lambda h, p: _match_java_class(h), "ext": "class", "name": "Java Class File"},
    {"match": lambda h, p: h[0:4] == b"\xca\xfe\xba\xbe", "ext": "macho", "name": "Mach-O Universal Binary (Fat)"},
    {"match": lambda h, p: _match_wasm(h), "ext": "wasm", "name": "WebAssembly Binary"},

    # ---------------- صوت / تصویر (مالتی‌مدیا) ----------------
    {"match": lambda h, p: _match_id3(h), "ext": "mp3", "name": "MP3 Audio (ID3)"},
    {"match": lambda h, p: _match_mp3_frames(h), "ext": "mp3", "name": "MP3 Audio"},
    {"match": lambda h, p: _match_aac_adts(h), "ext": "aac", "name": "AAC Audio (ADTS)"},
    {"match": lambda h, p: _match_ogg(h), "ext": "ogg", "name": "OGG Media", "ogg_special": True},
    {"match": lambda h, p: _match_flac(h), "ext": "flac", "name": "FLAC Audio"},
    {"match": lambda h, p: _match_wav(h), "ext": "wav", "name": "WAV Audio"},
    {"match": lambda h, p: _match_simple(h, 0, b"FORM") and h[8:12] in (b"AIFF", b"AIFC"), "ext": "aiff", "name": "AIFF Audio"},
    {"match": lambda h, p: _match_avi(h), "ext": "avi", "name": "AVI Video"},
    {"match": lambda h, p: _match_asf(h), "ext": "wmv", "name": "Windows Media (ASF)", "asf_special": True},
    {"match": lambda h, p: _match_ftyp(h), "ext": "mp4", "name": "MP4 Video Container", "ftyp_special": True},
    {"match": lambda h, p: _match_simple(h, 0, b"\x1a\x45\xdf\xa3"), "ext": "mkv", "name": "Matroska Video (MKV/WEBM)", "confidence": "probable"},
    {"match": lambda h, p: _match_flv(h), "ext": "flv", "name": "Flash Video"},

    # ---------------- فونت ----------------
    {"match": lambda h, p: _match_ttc(h), "ext": "ttc", "name": "TrueType Collection (TTC)"},
    {"match": lambda h, p: _match_sfnt(h, b"OTTO"), "ext": "otf", "name": "OpenType Font"},
    {"match": lambda h, p: _match_woff(h, b"wOFF"), "ext": "woff", "name": "WOFF Font"},
    {"match": lambda h, p: _match_woff(h, b"wOF2"), "ext": "woff2", "name": "WOFF2 Font"},
    {"match": lambda h, p: _match_sfnt(h, b"\x00\x01\x00\x00"), "ext": "ttf", "name": "TrueType Font"},

    # ---------------- داده / دیتابیس ----------------
    {"match": lambda h, p: _match_pfb(h), "ext": "pfb", "name": "PostScript Type 1 Font (PFB)", "confidence": "probable"},
    {"match": lambda h, p: _match_simple(h, 0, b"SQLite format 3\x00"), "ext": "sqlite", "name": "SQLite Database"},
]

# پسوندهای «باینری شناخته‌شده» — برای تشخیص موارد مشکوکِ متنی
# (مثلاً فایل متنی‌ای که پسوند .mp3 دارد)
# دنیای شناخته‌شده‌ها با پسوندهای خودِ امضاها و زیرنوع‌ها کامل می‌شود
_SIGNATURE_EXTS = {s["ext"] for s in SIGNATURES}
_SUBTYPE_EXTS = {
    # زیرنوع‌های ZIP
    "apk", "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm",
    "pptx", "ppsx", "pptm", "ppsm", "potx", "potm", "vsdx", "jar", "war",
    "xpi", "vsix", "whl", "kmz", "epub", "odt", "ods", "odp", "odg", "odf",
    "odb",
    # زیرنوع‌های OLE2
    "msg", "xls", "ppt", "vsd",
    # زیرنوع‌های ftyp / ASF / OGG
    "mov", "m4v", "m4a", "heic", "avif", "cr3", "wmv", "wma", "opus", "ogv",
}
KNOWN_EXTENSIONS |= _SIGNATURE_EXTS | _SUBTYPE_EXTS
KNOWN_BINARY_EXTS = KNOWN_EXTENSIONS - KNOWN_TEXTUAL_EXTS

SHEBANG_MAP = {
    b"#!/bin/bash": ("sh", "Shell Script (bash)"),
    b"#!/bin/sh": ("sh", "Shell Script (sh)"),
    b"#!/usr/bin/env python": ("py", "Python Script"),
    b"#!/usr/bin/python": ("py", "Python Script"),
    b"#!/usr/bin/env node": ("js", "Node.js Script"),
    b"#!/usr/bin/perl": ("pl", "Perl Script"),
}


def read_header(path, size=32800):
    """۳۲۸۰۰ بایت اول را می‌خواند تا آفست ISO (32769) هم پوشش داده شود."""
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except Exception:
        return b""


# ----------------------------------------------------------------------------
# تشخیص فایل متنی (با پشتیبانی BOM / UTF-16)
# ----------------------------------------------------------------------------

_TEXT_ALLOWED_CONTROLS = set("\t\n\v\f\r")


def _decode_possible_text(data: bytes):
    """UTF-8 (با BOM) یا UTF-16 (با BOM)؛ در صورت شکست، Latin-1 تک‌بایتی.
    فایل‌های متنی قدیمی با انکودینگ ISO-8859-1 / Windows-1252 (که UTF-8
    نیستند) قبلاً «نامشخص» تشخیص داده می‌شدند؛ حالا با Latin-1 خوانده
    می‌شوند. Latin-1 هرگز خطا نمی‌دهد؛ بایت‌های کنترلی باینریِ واقعی
    در is_probably_text رد می‌شوند، پس ریسک مثبت کاذب عملاً صفر است."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16"), True
        except Exception:
            pass
    try:
        return data.decode("utf-8-sig"), True
    except UnicodeDecodeError:
        return data.decode("latin-1"), True


def is_probably_text(data: bytes) -> bool:
    if not data:
        return False
    text, ok = _decode_possible_text(data[:16384])
    if not ok:
        return False
    for ch in text:
        o = ord(ch)
        if o == 0x7F:
            return False
        if o < 32 and ch not in _TEXT_ALLOWED_CONTROLS:
            return False
    return True


_JSON_FULL_PARSE_LIMIT = 4 * 1024 * 1024      # تا ۴MB کامل پارس می‌شود
_JSON_START_RE = re.compile(r'^\s*(\{\s*("|\})|\[\s*("|\{|\[|\]|-?\d|true|false|null))')


def _looks_like_json(path: Path, text: str) -> bool:
    """فایل‌های تا ۴MB کامل پارس می‌شوند (شیء/آرایه، حتی خالی)؛ برای فایل‌های
    بزرگ‌تر فقط شکل ابتدای فایل بررسی می‌شود."""
    try:
        if path.stat().st_size <= _JSON_FULL_PARSE_LIMIT:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig", errors="replace"))
            return isinstance(data, (dict, list))
    except Exception:
        return False
    return bool(_JSON_START_RE.match(text))


def detect_text_subtype(header: bytes, path: Path):
    """تشخیص دقیق‌تر فرمت‌های متنی رایج (بر پایه‌ی محتوا، نه فقط پسوند)."""
    text, ok = _decode_possible_text(header)
    if not ok:
        return "txt", "Plain Text"
    stripped = text.strip()
    lower = stripped.lower()

    for sig, (ext, name) in SHEBANG_MAP.items():
        if stripped.startswith(sig.decode("ascii", "ignore")):
            return ext, name

    if stripped.startswith("{") or stripped.startswith("["):
        if _looks_like_json(path, stripped):
            return "json", "JSON Data"

    if lower.startswith("<?xml"):
        if "<svg" in lower:
            return "svg", "SVG Image"
        return "xml", "XML Document"
    if lower.startswith("<svg") or lower.startswith("<!doctype svg"):
        return "svg", "SVG Image"
    if lower.startswith("<!doctype html") or "<html" in lower[:500]:
        return "html", "HTML Document"

    lines = [l for l in stripped.splitlines() if l.strip()][:10]
    if len(lines) >= 2:
        comma_counts = [l.count(",") for l in lines]
        if comma_counts[0] > 0 and len(set(comma_counts)) == 1:
            return "csv", "CSV Data"

    if stripped.startswith("#!"):
        return "sh", "Script File (shebang)"

    return "txt", "Plain Text"


def detect_real_type(path: Path):
    """
    خروجی: (پسوند_واقعی، نام_نوع، سطح_اطمینان)
    سطح اطمینان: certain | probable | text | unknown
      - certain  : امضای بایتی واقعی + زیرنوع مشخص (PNG، DOCX، XLS، MP4 و ...)
      - probable : امضای بایتی هست ولی زیرنوع دقیق نامعلوم است
                   (ZIP عمومی، MZ، TIFF، EBML/MKV، OGG عمومی، OLE2 نامشخص)
      - text     : فقط از روی «شکل متن» حدس زده شده (json/xml/html/csv و ...)
    """
    header = read_header(path)
    if not header:
        return None, "Empty or Unreadable File", "unknown"

    for sig in SIGNATURES:
        try:
            matched = sig["match"](header, path)
            if matched:
                if sig.get("zip_special"):
                    ext, name, conf = detect_zip_subtype(path)
                    return ext, name, conf
                if sig.get("ole_special"):
                    ext, name, conf = detect_ole_subtype(path)
                    return ext, name, conf
                if sig.get("ogg_special"):
                    ext, name, conf = detect_ogg_subtype(header)
                    return ext, name, conf
                if sig.get("ftyp_special"):
                    ext, name = detect_ftyp_subtype(header)
                    return ext, name, "certain"
                if sig.get("asf_special"):
                    ext, name = detect_asf_subtype(path)
                    return ext, name, "certain"
                # بعضی matcherها خودشان سطح اطمینان را برمی‌گردانند (MP3/AAC)
                conf = matched if isinstance(matched, str) else sig.get("confidence", "certain")
                # محافظ متنِ امضاهای ASCII: فایل متنی که اتفاقی با «GIF89a»،
                # «RIFF....WAVE»، «ustar»، «BZh91AY&SY»، «d4:info» و… شروع شود
                # اصلاً با این امضا تطبیق داده نمی‌شود (تنزل به probable کافی
                # نبود: فایل «بدون پسوند» در حالت پیش‌فرض و فایل .txt در حالت
                # پرریسک همچنان تغییر نام می‌گرفتند). فایل واقعیِ این فرمت‌ها
                # بلافاصله بعد از هدر بایت باینری دارد و متن حساب نمی‌شود.
                if ((sig["ext"] in _ASCII_MAGIC_EXTS or sig["ext"] == "torrent")
                        and is_probably_text(header)):
                    continue
                return sig["ext"], sig["name"], conf
        except Exception:
            continue

    if is_probably_text(header):
        ext, name = detect_text_subtype(header, path)
        # تشخیص‌های متنی هرگز «قطعی» نیستند؛ فقط با گزینه‌ی پرریسک اصلاح می‌شوند
        return ext, name, "text"

    return None, "Unknown / Unrecognized Binary Format", "unknown"


def analyze_file(path: Path):
    path = Path(path)
    stated_ext_raw = path.suffix.lower().lstrip(".")
    real_ext, type_name, confidence = detect_real_type(path)

    # مقایسه بعد از نرمال‌سازی alias و «با آگاهی از خانواده‌ی پسوندها»
    stated_norm = normalize_ext(stated_ext_raw)
    real_norm = normalize_ext(real_ext) if real_ext else None

    # فایل مخفی بدون پسوند (مثل .gitignore) هرگز تغییر نام نمی‌گیرد؛
    # پس در گزارش هم «پسوند اشتباه» حساب نمی‌شود.
    is_hidden_noext = path.name.startswith(".") and not stated_ext_raw

    mismatch = False
    if (real_norm is not None and not is_hidden_noext
            and confidence in ("certain", "probable", "text")):
        if not stated_norm:
            # فایل بدون پسوند: هر تشخیصی به این معناست که پسوند کم دارد
            mismatch = True
        elif confidence == "text":
            # حدس متنی فقط وقتی مشکوک است که پسوند فعلی «باینری شناخته‌شده» باشد
            # (index.php با محتوای HTML مشکوک نیست؛ report.mp3 با محتوای متنی هست)
            mismatch = stated_norm in KNOWN_BINARY_EXTS
        else:
            # certain/probable: پسوند فعلی باید عضو خانواده‌ی نوع واقعی باشد
            # (dll/sys برای امضای EXE، cr2/nef برای TIFF، webm برای Matroska، ...)
            mismatch = stated_norm not in ext_family(real_norm)

    # پسوند فعلی در دنیای امضاها/خانواده‌ها شناخته‌شده است؟
    # اگر نه (مثل .xyz)، به‌طور پیش‌فرض فقط گزارش می‌شود و تغییر نام نمی‌دهد.
    stated_known = (not stated_norm) or (stated_norm in KNOWN_EXTENSIONS)

    try:
        size = path.stat().st_size
    except Exception:
        size = 0

    return {
        "path": str(path),
        "name": path.name,
        "size": size,
        "stated_extension": stated_ext_raw,   # "" یعنی بدون پسوند
        "detected_extension": real_ext or "unknown",
        "detected_type": type_name,
        "confidence": confidence,
        "mismatch": mismatch,
        "stated_known": stated_known,
    }


# ----------------------------------------------------------------------------
# پیمایش فایل‌ها (با رد کردن پوشه‌های سیستمی/زباله و symlinkها)
# ----------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", ".svn", ".hg", ".idea", ".vscode",
    "node_modules", "__pycache__",
    "venv", ".venv", "env",
    "$recycle.bin", "system volume information",
    "windows", "program files", "program files (x86)", "appdata",
    ".extension_fixer_logs", ".filetype_fixer_logs",
    "__macosx",
}


def _is_within(p: Path, base: Path) -> bool:
    try:
        p.relative_to(base)
        return True
    except ValueError:
        return False


def is_protected_root(path) -> bool:
    """آیا مسیر، ریشه‌ی درایو یا داخل یک پوشه‌ی سیستمی است؟
    (SKIP_DIRS فقط زیرپوشه‌ها را رد می‌کند؛ این تابع برای خودِ مسیر انتخاب‌شده
    است و GUI با آن اجرای واقعی را روی پوشه‌های سیستمی مسدود می‌کند.)"""
    try:
        p = Path(path).resolve()
    except Exception:
        # fail-safe: اگر resolve ممکن نشد، مسیر را «محافظت‌شده» فرض کن
        return True
    if p == Path(p.anchor):
        return True
    if os.name == "nt":
        bases = [os.environ.get(v) for v in (
            "SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)",
            "ProgramW6432", "ProgramData")]
    else:
        bases = ["/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64",
                 "/proc", "/run", "/sbin", "/sys", "/usr", "/System"]
    for b in bases:
        if not b:
            continue
        try:
            if _is_within(p, Path(b).resolve()):
                return True
        except Exception:
            continue
    return False


def collect_files(root: Path, recursive: bool):
    root = Path(root)

    if root.is_file():
        # تک‌فایل انتخاب‌شده هم مثل اسکن پوشه، symlink نباشد
        if not root.is_symlink():
            yield root
        return
    if not root.is_dir():
        return

    if not recursive:
        try:
            for p in sorted(root.iterdir()):
                if p.is_file() and not p.is_symlink():
                    yield p
        except Exception:
            pass
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # پوشه‌های سیستمی/زباله و symlinkها (junctionها) را پیمایش نکن
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in SKIP_DIRS
            and not os.path.islink(os.path.join(dirpath, d))
        ]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            if p.is_file():
                yield p


# ============================================================================
# اصلاح خودکار پسوند (Rename Engine)
# ----------------------------------------------------------------------------
# هدف: فقط فایل‌هایی که پسوندشان «با اطمینان بالا» اشتباه است اصلاح شوند،
# بدون کوچک‌ترین ریسک از دست رفتن یا رونویسی داده. خطوط دفاعی اصلی:
#   ۱. مقایسه با «خانواده‌ی پسوندها»: dll/sys برای امضای EXE، cr2/nef برای
#      TIFF، webm برای Matroska و ... هرگز mismatch حساب نمی‌شوند.
#   ۲. تشخیص‌های احتمالی (کانتینر عمومی) و متنی و پسوندهای ناشناخته
#      به‌طور پیش‌فرض دست‌نخورده می‌مانند؛ فقط با گزینه‌ی صریح کاربر
#      (include_risky=True) اصلاح می‌شوند.
#   ۳. هرگز هیچ فایلی رونویسی (overwrite) نمی‌شود؛ در صورت تصادم نام، یک
#      شمارنده‌ی یکتا به نام فایل اضافه می‌شود.
#   ۴. لاگ Undo فقط-افزودنی (JSONL) است: پیش از هر تغییر نام، هویت فایل
#      (اندازه + mtime) با fsync ثبت و مسیر نهایی واقعی بلافاصله بعد از
#      rename افزوده می‌شود؛ Undo پیش از برگرداندن، هویت را می‌سنجد تا
#      حتی در صورت کرش وسط کار، هرگز فایل اشتباهی بازگردانی نشود.
# ============================================================================

# اطمینان‌هایی که به‌طور پیش‌فرض "امن برای اصلاح خودکار" در نظر گرفته می‌شوند
SAFE_CONFIDENCES = {"certain"}
# اطمینان‌های اختیاری (حدسی) — فقط با گزینه‌ی «اصلاح موارد پرریسک»
RISKY_CONFIDENCES = {"probable", "text"}


def _is_valid_extension_suffix(suffix: str) -> bool:
    """آیا آخرین بخش نام، یک پسوند واقعی و معتبر به نظر می‌رسد؟
    پسوند باید حرف داشته باشد؛ «01» در «backup 2024.01» پسوند نیست و
    نباید جایگزین شود (در این حالت پسوند جدید به انتهای نام اضافه می‌شود)."""
    s = suffix.lstrip(".")
    return (bool(s) and len(s) <= 6 and s.isascii() and s.isalnum()
            and any(c.isalpha() for c in s))


def compute_target_path(old_path: Path, detected_ext: str) -> Path:
    """
    مسیر مقصد امن را می‌سازد:
      - photo.txt        (پسوند معتبر)      -> photo.png      (جایگزینی)
      - Mr. Smith        (پسوند نامعتبر)    -> Mr. Smith.png  (اضافه شدن)
      - عکس123           (بدون پسوند)       -> عکس123.png     (اضافه شدن)
      - photo.png.txt    (پسوند تکراری)     -> photo.png      (حذف اضافی)
    """
    name = old_path.name
    suffix = old_path.suffix
    stem = name[: len(name) - len(suffix)] if suffix else name

    # photo.png.txt -> photo.png  (بخش قبل از پسوند فعلی خودش پسوند واقعی است)
    parts = stem.rsplit(".", 1)
    if len(parts) == 2 and parts[0] and normalize_ext(parts[1]) == normalize_ext(detected_ext):
        return old_path.with_name(f"{parts[0]}.{detected_ext}")

    if suffix and _is_valid_extension_suffix(suffix):
        return old_path.with_name(f"{stem}.{detected_ext}")
    # پسوند فعلی معتبر نیست (فاصله/نقطه‌های زیاد/...) یا اصلاً پسوندی نیست
    return old_path.with_name(f"{name}.{detected_ext}")


def build_rename_plan(results, include_risky: bool = False):
    """
    از خروجی analyze_file() یک "برنامه‌ی اصلاح" می‌سازد.
    فقط ردیف‌هایی انتخاب می‌شوند که:
      - mismatch == True  (پسوند فعلی با نوع واقعی فایل فرق دارد)
      - detected_extension مقدار معتبر دارد (نه None/"unknown")
      - و یکی از این موارد:
          * confidence == "certain" و پسوند فعلی شناخته‌شده است، یا
            فایل اصلاً پسوند ندارد (پسوند جدید اضافه می‌شود)
          * فایل بدون پسوند است و تشخیص "probable" است (کانتینر عمومی
            مثل ZIP/MZ/TIFF — طبق تصمیم کاربر پسوند می‌گیرد)
          * include_risky=True: همه‌ی موارد پرریسک هم شامل می‌شود
            (تشخیص‌های احتمالی/متنی و پسوندهای ناشناخته)

    فایل‌های مخفیِ بدون پسوند (مثل .gitignore) هرگز دست نمی‌خورند.

    خروجی: لیستی از دیکشنری‌ها با کلیدهای:
      old_path, new_path, detected_extension, detected_type,
      confidence, was_extensionless
    """
    plan = []
    for r in results:
        if not r.get("mismatch"):
            continue
        confidence = r.get("confidence")
        if confidence not in ("certain", "probable", "text"):
            continue
        ext = r.get("detected_extension")
        if not ext or ext == "unknown":
            continue

        old_path = Path(r["path"])
        was_extensionless = not old_path.suffix

        # فایل مخفی بدون پسوند (.gitignore و امثالش) -> دست نزن
        if was_extensionless and old_path.name.startswith("."):
            continue

        if not include_risky:
            if was_extensionless:
                # بدون پسوند: certain همیشه، probable هم مجاز است
                # (تصمیم کاربر: فایل‌های بدون پسوند در اجرای واقعی پسوند می‌گیرند)
                # حدس‌های متنی (text) فقط با گزینه‌ی پرریسک
                if confidence not in ("certain", "probable"):
                    continue
            elif confidence == "certain":
                # پسوند فعلی باید در دنیای شناخته‌شده‌ها باشد (مثلاً .dat/.png/.jpg)
                # پسوندهای ناشناخته (مثل .xyz) فقط گزارش می‌شوند
                if not r.get("stated_known", True):
                    continue
            else:
                # probable/text روی فایلِ پسوند-دار: فقط با گزینه‌ی پرریسک
                continue

        plan.append({
            "old_path": str(old_path),
            "new_path": str(compute_target_path(old_path, ext)),
            "detected_extension": ext,
            "detected_type": r.get("detected_type", ""),
            "confidence": confidence,
            "was_extensionless": was_extensionless,
        })
    return plan


def _unique_target(path: Path, reserved: set) -> Path:
    """
    اگر مسیر مقصد از قبل روی دیسک وجود داشته باشد یا در همین دسته قبلاً
    رزرو شده باشد، با افزودن " (1)"، " (2)"، ... یک نام یکتا و امن می‌سازد.
    هرگز هیچ فایلی رونویسی نمی‌شود.
    """
    if not path.exists() and str(path).lower() not in reserved:
        return path

    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    i = 1
    while True:
        candidate = parent / f"{stem} ({i}){suffix}"
        if not candidate.exists() and str(candidate).lower() not in reserved:
            return candidate
        i += 1


def apply_rename_plan(plan, progress_callback=None, undo_log_path=None):
    """
    برنامه‌ی اصلاح را واقعاً روی دیسک اجرا می‌کند.
    برای هر آیتم یکی از این وضعیت‌ها ثبت می‌شود:
      renamed              -> با موفقیت اصلاح شد (final_path == new_path پیشنهادی)
      renamed_with_suffix  -> با موفقیت اصلاح شد اما به دلیل تصادم نام،
                               یک شماره به انتهای نام اضافه شد
      skipped_missing      -> فایل مبدا دیگر روی دیسک وجود ندارد
      error                -> خطای سیستمی هنگام تغییر نام (قفل بودن فایل،
                               نبود دسترسی و ...)

    اگر undo_log_path داده شود، پیش از هر تغییر نام یک رکورد «start»
    (شامل اندازه و زمان فایل مبدا) و در صورت تصادم نام، بلافاصله بعد از
    rename یک رکورد «final» (با مسیر نهایی واقعی) به لاگ افزوده می‌شود؛
    به این ترتیب لاگ همیشه با دیسک همگام می‌ماند و کرش وسط کار هم
    بازگردانیِ درست را ممکن می‌کند.

    خروجی: لیست نتایج (برای گزارش به کاربر).
    """
    reserved = set()
    results = []
    total = len(plan)

    for idx, item in enumerate(plan, start=1):
        old_path = Path(item["old_path"])
        proposed_new = Path(item["new_path"])
        entry = dict(item)

        if not old_path.exists():
            entry["status"] = "skipped_missing"
            entry["final_path"] = None
            results.append(entry)
        else:
            final_path = _unique_target(proposed_new, reserved)
            try:
                if undo_log_path:
                    log_rename_start(undo_log_path, old_path, proposed_new)
                old_path.rename(final_path)
                reserved.add(str(final_path).lower())
                entry["status"] = "renamed" if final_path == proposed_new else "renamed_with_suffix"
                entry["final_path"] = str(final_path)
                if undo_log_path and final_path != proposed_new:
                    log_rename_final(undo_log_path, old_path, final_path)
            except Exception as e:
                entry["status"] = "error"
                entry["final_path"] = None
                entry["error_message"] = str(e)
            results.append(entry)

        if progress_callback:
            try:
                progress_callback(idx, total, entry)
            except Exception:
                pass

    return results


# مشخصه‌ی هویت فایل: اندازه باید دقیقاً یکی باشد و زمان تغییر حداکثر
# ۲ ثانیه فرق کند (فایل‌سیستم‌هایی با دقت پایین مثل FAT).
_UNDO_MTIME_TOLERANCE_NS = 2_000_000_000


def start_undo_log(log_dir=None, log_path=None) -> Path:
    """
    یک لاگ Undo جدید (فرمت JSONL — هر رکورد در یک خط) می‌سازد و مسیرش را
    برمی‌گرداند. لاگ به‌صورت «فقط-افزودنی» (append-only) تکمیل می‌شود:
      - پیش از هر تغییر نام: رکورد "start" با هویت فایل مبدا (اندازه + mtime)
      - پس از هر تغییر نامِ دارای پسوند تصادم: رکورد "final" با مسیر واقعی
    چون هیچ‌گاه فایل لاگ بازنویسی نمی‌شود، کرش در هر لحظه فقط به معنای
    «لاگ ناقص» است، نه «لاگ از دست رفته یا غلط».
    """
    if log_dir is None:
        log_dir = Path.home() / ".extension_fixer_logs"
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    if log_path is None:
        log_path = log_dir / f"undo_{time.strftime('%Y%m%d_%H%M%S')}.json"
    log_path = Path(log_path)

    meta = {
        "format": "extension_fixer_undo",
        "version": 2,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform.platform(),
    }
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(meta, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return log_path


def _append_undo_record(log_path, record) -> None:
    """یک رکورد را به انتهای لاگ JSONL می‌افزاید (flush + fsync)."""
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        # اگر نوشتن لاگ ممکن نشد، اجرا متوقف نمی‌شود؛ فقط بازگردانیِ همین
        # مورد ممکن نخواهد بود.
        pass


def log_rename_start(log_path, old_path, proposed_new) -> None:
    """پیش از تغییر نام: هویت فایل مبدا (اندازه + زمان تغییر) ثبت می‌شود."""
    try:
        st = Path(old_path).stat()
        size, mtime_ns = st.st_size, st.st_mtime_ns
    except OSError:
        size, mtime_ns = None, None
    _append_undo_record(log_path, {
        "t": "start",
        "old_path": str(old_path),
        "new_path": str(proposed_new),
        "size": size,
        "mtime_ns": mtime_ns,
    })


def log_rename_final(log_path, old_path, final_path) -> None:
    """پس از تغییر نامِ دارای پسوند تصادم: مسیر نهایی واقعی ثبت می‌شود."""
    _append_undo_record(log_path, {
        "t": "final",
        "old_path": str(old_path),
        "new_path": str(final_path),
    })


def _file_identity_matches(path, size, mtime_ns) -> bool:
    """آیا فایلِ روی دیسک همان فایلی است که در لاگ ثبت شده؟
    (اندازه باید دقیقاً یکی باشد و زمان تغییر حداکثر ۲ ثانیه فرق کند.
    لاگ‌های قدیمیِ بدون هویت، به همین تابع وارد نمی‌شوند.)"""
    if size is None and mtime_ns is None:
        return True          # هویتی ثبت نشده (فرمت نسخه‌ی ۱)
    try:
        st = Path(path).stat()
    except OSError:
        return False
    if size is not None and st.st_size != size:
        return False
    if mtime_ns is not None and abs(st.st_mtime_ns - mtime_ns) > _UNDO_MTIME_TOLERANCE_NS:
        return False
    return True


def undo_rename_plan(log_path: Path):
    """
    یک لاگ Undo را می‌خواند و فایل‌ها را دقیقاً به نام قبلی‌شان برمی‌گرداند.

    امنیت:
      - هویت هر فایل (اندازه + زمان تغییرِ ثبت‌شده هنگام اصلاح) بررسی
        می‌شود؛ اگر فایلِ مقصد تغییر کرده، حذف شده یا از نو ساخته شده
        باشد، آن مورد دست‌نخورده با وضعیت "error" گزارش می‌شود.
      - اگر نام قبلی اکنون اشغال باشد، آن مورد هم "error" می‌شود.
      - خطای یک فایل مانع بازگردانی بقیه نمی‌شود.
      - اگر فایل هنوز با نام اصلی و با همان هویت وجود داشته باشد، یعنی
        تغییر نامی انجام نشده و آن مورد رد می‌شود (skipped_missing).
      - لاگ‌های نسخه‌ی ۱ (JSON یک‌تکه، بدون هویت) هم پشتیبانی می‌شوند.
      - اگر برنامه بین rename و ثبت رکورد "final" بسته شده باشد،
        واریانت‌های «نام (۱)»، «نام (۲)»… با هویت آزموده می‌شوند.
    """
    log_path = Path(log_path)
    text = log_path.read_text(encoding="utf-8")

    starts, finals, order = {}, {}, []
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict) and isinstance(data.get("entries"), list):
        # فرمت نسخه‌ی ۱ (بدون هویت فایل)
        for e in data["entries"]:
            op, np = e.get("old_path"), e.get("new_path")
            if op and np and op not in starts:
                order.append(op)
                starts[op] = {"new_path": np, "size": None, "mtime_ns": None}
    else:
        # فرمت نسخه‌ی ۲: JSONL
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue          # خط ناقص (مثلاً به‌خاطر قطع برق) — رد شود
            if not isinstance(rec, dict):
                continue
            op = rec.get("old_path")
            if not op:
                continue
            if rec.get("t") == "start":
                if op not in starts:
                    order.append(op)
                    starts[op] = {"new_path": rec.get("new_path"),
                                  "size": rec.get("size"),
                                  "mtime_ns": rec.get("mtime_ns")}
            elif rec.get("t") == "final":
                finals[op] = rec.get("new_path")

    results = []
    for op in reversed(order):
        start = starts[op]
        original_path = Path(op)
        final = finals.get(op)
        current_path = Path(final if final is not None else start["new_path"])
        size, mtime_ns = start["size"], start["mtime_ns"]
        has_identity = size is not None or mtime_ns is not None
        result = {"current_path": str(current_path), "restore_to": str(original_path)}

        if current_path.exists() and _file_identity_matches(current_path, size, mtime_ns):
            # فایلِ مقصد همان فایلِ ثبت‌شده در لاگ است
            if original_path.exists():
                result["status"] = "error"
                result["error_message"] = "original name is already occupied by another file"
            else:
                try:
                    current_path.rename(original_path)
                    result["status"] = "restored"
                except Exception as e:
                    result["status"] = "error"
                    result["error_message"] = str(e)
        elif final is not None:
            # تغییر نامِ دارای پسوند انجام شده ولی فایلِ مقصد عوض/حذف شده است
            result["status"] = "error"
            result["error_message"] = "destination file is missing or was modified after the rename"
        elif not has_identity:
            # لاگ نسخه‌ی ۱ بدون هویت و فایلِ مقصد موجود نیست: رفتار قدیمی
            result["status"] = "skipped_missing"
        elif original_path.exists() and _file_identity_matches(original_path, size, mtime_ns):
            # فایل هنوز با نام اصلی خودش و با همان هویت وجود دارد:
            # یعنی تغییر نامی هرگز انجام نشده
            result["status"] = "skipped_missing"
        else:
            # احتمالاً کرش بین rename و ثبت رکورد final رخ داده است؛
            # واریانت‌های «نام (۱)»، «نام (۲)» … را با هویت می‌آزماییم
            alt = None
            for i in range(1, 21):
                cand = current_path.with_name(
                    f"{current_path.stem} ({i}){current_path.suffix}")
                if _file_identity_matches(cand, size, mtime_ns):
                    alt = cand
                    break
            if alt is not None and not original_path.exists():
                try:
                    alt.rename(original_path)
                    result["current_path"] = str(alt)
                    result["status"] = "restored"
                except Exception as e:
                    result["status"] = "error"
                    result["error_message"] = str(e)
            else:
                result["status"] = "error"
                result["error_message"] = "file identity could not be verified; nothing was changed"
        results.append(result)

    return results
