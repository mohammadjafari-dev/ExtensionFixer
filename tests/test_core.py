# -*- coding: utf-8 -*-
"""
Tests for filetype_core.py  (standard library only)

Run from the project root:
    python -m unittest discover -s tests -v
"""
import bz2
import gzip
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import filetype_core as core  # noqa: E402


# ---------------------------------------------------------------------------
# Builders for minimal but structurally valid sample files
# ---------------------------------------------------------------------------

def mp3_frames(n=3):
    frame = b"\xff\xfb\x90\x00" + b"\x00" * (417 - 4)       # MPEG1 L3, 128 kbps, 44.1 kHz
    return frame * n


def aac_frames(n=3):
    length = 100
    hdr = bytes([0xFF, 0xF1, 0x50, 0x80, length >> 3 & 0xFF,
                 ((length & 7) << 5) | 0x1F, 0xFC])
    return (hdr + b"\x00" * (length - 7)) * n


def ico_bytes():
    entry = b"\x10\x10\x00\x00" + b"\x01\x00" + b"\x20\x00" + (40).to_bytes(4, "little") + (22).to_bytes(4, "little")
    return b"\x00\x00\x01\x00\x01\x00" + entry + b"\x00" * 40


def sfnt(tag):
    return tag + b"\x00\x03\x00\x20\x00\x01\x00\x10" + b"\x00" * 64


def pe_bytes():
    h = bytearray(256)
    h[0:2] = b"MZ"
    h[0x3C:0x40] = (0x80).to_bytes(4, "little")
    h[0x80:0x84] = b"PE\x00\x00"
    return bytes(h)


def ogg_opus():
    return b"OggS\x00\x02" + b"\x00" * 20 + b"\x01\x13" + b"OpusHead\x01\x02" + b"\x00" * 20


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"x" * 64
MP4 = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2" + b"\x00" * 32
CAB = b"MSCF" + b"\0" * 4 + (100).to_bytes(4, "little") + b"\0" * 4 + (44).to_bytes(4, "little") + b"\0" * 4 + b"\x03\x01" + b"\0" * 40
FLV = b"FLV\x01\x05\x00\x00\x00\x09" + b"\x00" * 20
FLAC = b"fLaC\x00\x00\x00\x22" + b"\x00" * 34
PSD = b"8BPS\x00\x01" + b"\x00" * 6 + b"\x00" * 30
WASM = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 8

# (bytes, expected extension, expected confidence)
VALID_SAMPLES = {
    "png": (PNG, "png", "certain"),
    "jpg": (JPG, "jpg", "certain"),
    "pdf": (PDF, "pdf", "certain"),
    "mp3_bare": (mp3_frames(), "mp3", "certain"),
    "mp3_id3": (b"ID3\x03\x00\x00\x00\x00\x00\x00" + mp3_frames(), "mp3", "certain"),
    "aac": (aac_frames(), "aac", "certain"),
    "ico": (ico_bytes(), "ico", "certain"),
    "ttf": (sfnt(b"\x00\x01\x00\x00"), "ttf", "certain"),
    "otf": (sfnt(b"OTTO"), "otf", "certain"),
    "psd": (PSD, "psd", "certain"),
    "flac": (FLAC, "flac", "certain"),
    "flv": (FLV, "flv", "certain"),
    "cab": (CAB, "cab", "certain"),
    "bz2": (bz2.compress(b"hello world " * 50), "bz2", "certain"),
    "gz": (gzip.compress(b"hello world " * 50), "gz", "certain"),
    "wasm": (WASM, "wasm", "certain"),
    "mp4": (MP4, "mp4", "certain"),
    "opus": (ogg_opus(), "opus", "certain"),
    "exe": (pe_bytes(), "exe", "probable"),
}

# Plain text files that merely START like a binary signature
TEXT_LOOKALIKES = {
    "ids.csv": b"ID3,name\n1,a\n2,b\n",
    "names.txt": b"BZhang is a surname\nmore text\n",
    "note.txt": b"OTTO MEETING NOTES\nagenda\n",
    "fix.md": b"MSCF report\nsecond line\n",
    "psd.txt": b"8BPS is a magic number\n",
    "flac.txt": b"fLaC lossless audio\n",
    "mz.txt": b"MZ was here\nand here\n",
    "ogg.txt": b"OggS container\n",
    "flv.txt": b"FLV\x01 text\n",
    "ftyp.txt": b"abcdftypefghi jklmn\n",
}


def make_zip(path, files):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


class TmpDirCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="extfix_test_"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, data):
        p = self.dir / name
        p.write_bytes(data)
        return p

    def default_plan_target(self, path):
        plan = core.build_rename_plan([core.analyze_file(path)])
        return Path(plan[0]["new_path"]).name if plan else None


class TestDetection(TmpDirCase):
    def test_valid_samples_are_detected(self):
        for key, (data, ext, conf) in VALID_SAMPLES.items():
            with self.subTest(sample=key):
                real, _name, c = core.detect_real_type(self.write("sample.bin", data))
                self.assertEqual((real, c), (ext, conf))

    def test_text_lookalikes_are_not_binary(self):
        for name, data in TEXT_LOOKALIKES.items():
            with self.subTest(file=name):
                p = self.write(name, data)
                _real, _n, conf = core.detect_real_type(p)
                self.assertNotEqual(conf, "certain")
                self.assertIsNone(self.default_plan_target(p),
                                  "default (safe) mode must not rename a text file")

    def test_random_binary_prefixes_are_not_certain(self):
        # old code treated these 2-4 byte prefixes as certain
        for data in (b"\xff\xfb" + b"\x00" * 10,            # fake MP3 sync
                     b"\x00\x00\x01\x00" + b"\x00" * 40,     # fake ICO
                     b"\x00\x01\x00\x00" + b"\x00" * 40,     # fake TTF
                     b"\xff\xd8\xff\x00" + b"\x00" * 40):    # fake JPEG
            with self.subTest(prefix=data[:4].hex()):
                p = self.write("blob.dat", data)
                self.assertNotEqual(core.detect_real_type(p)[2], "certain")
                self.assertIsNone(self.default_plan_target(p))

    def test_json_variants(self):
        for name, data in (("a.txt", b"{}"), ("b.txt", b"[]"),
                           ("c.txt", b'{"a": 1}'),
                           ("big.txt", b'{"k":"' + b"x" * 5_000_000 + b'"}')):
            with self.subTest(file=name):
                self.assertEqual(core.detect_real_type(self.write(name, data))[0], "json")

    def test_hidden_extensionless_file_is_not_a_mismatch(self):
        p = self.write(".gitignore", b"*.pyc\n")
        r = core.analyze_file(p)
        self.assertFalse(r["mismatch"])
        self.assertIsNone(self.default_plan_target(p))

    def test_empty_file(self):
        r = core.analyze_file(self.write("empty.jpg", b""))
        self.assertFalse(r["mismatch"])


class TestZipSubtypes(TmpDirCase):
    CT_DOCX = ('<Types><Override PartName="/word/document.xml" ContentType="application/'
               'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
    CT_XLSM = ('<Types><Override PartName="/xl/workbook.xml" ContentType="application/'
               'vnd.ms-excel.sheet.macroEnabled.main+xml"/></Types>')

    def test_docx_and_macro_xlsx(self):
        p = make_zip(self.dir / "a.zip", {"[Content_Types].xml": self.CT_DOCX, "word/document.xml": "<x/>"})
        self.assertEqual(core.detect_zip_subtype(p)[0], "docx")
        p = make_zip(self.dir / "b.zip", {"[Content_Types].xml": self.CT_XLSM, "xl/workbook.xml": "<x/>"})
        self.assertEqual(core.detect_zip_subtype(p)[0], "xlsm")

    def test_odt_by_mimetype(self):
        p = make_zip(self.dir / "c.zip", {"mimetype": "application/vnd.oasis.opendocument.text"})
        self.assertEqual(core.detect_zip_subtype(p)[:1], ("odt",))

    def test_real_apk_is_certain(self):
        p = make_zip(self.dir / "d.zip", {"AndroidManifest.xml": "x", "classes.dex": "x"})
        self.assertEqual(core.detect_zip_subtype(p)[0::2], ("apk", "certain"))

    def test_ambiguous_layouts_stay_zip(self):
        cases = {
            "jar-layout": {"META-INF/MANIFEST.MF": "m", "src/A.java": "x"},
            "war-layout": {"WEB-INF/web.xml": "x", "index.html": "x"},
            "android-src": {"AndroidManifest.xml": "x", "res/a.xml": "x"},
            "gis-bundle": {"data/a.kml": "<kml/>", "data/b.shp": "x"},
            "plain": {"a.txt": "hi"},
        }
        for name, files in cases.items():
            with self.subTest(layout=name):
                p = make_zip(self.dir / f"{name}.zip", files)
                ext, _n, conf = core.detect_zip_subtype(p)
                self.assertEqual((ext, conf), ("zip", "probable"))
                self.assertIsNone(self.default_plan_target(p))

    def test_kmz_requires_root_doc_kml(self):
        p = make_zip(self.dir / "e.zip", {"doc.kml": "<kml/>"})
        self.assertEqual(core.detect_zip_subtype(p)[0], "kmz")

    def test_oversized_content_types_is_ignored(self):
        big = "<Types>" + " " * (2 * 1024 * 1024) + "</Types>"
        p = make_zip(self.dir / "bomb.zip", {"[Content_Types].xml": big})
        self.assertEqual(core.detect_zip_subtype(p)[0], "zip")

    def test_zip_named_docx_is_not_flagged_and_zip_content_is_renamed(self):
        p = make_zip(self.dir / "report.zip", {"[Content_Types].xml": self.CT_DOCX, "word/document.xml": "<x/>"})
        self.assertEqual(self.default_plan_target(p), "report.docx")
        q = make_zip(self.dir / "ok.docx", {"[Content_Types].xml": self.CT_DOCX, "word/document.xml": "<x/>"})
        self.assertFalse(core.analyze_file(q)["mismatch"])


class TestMismatchLogic(TmpDirCase):
    def test_wrong_extensions_are_fixed(self):
        cases = {"a.txt": PNG, "b.mp3": JPG, "c.jpg": PDF}
        expected = {"a.txt": "a.png", "b.mp3": "b.jpg", "c.jpg": "c.pdf"}
        for name, data in cases.items():
            with self.subTest(file=name):
                self.assertEqual(self.default_plan_target(self.write(name, data)), expected[name])

    def test_aliases_and_families_are_not_mismatches(self):
        ok = {"photo.jpeg": JPG, "photo.JPG": JPG, "lib.dll": pe_bytes(), "app.exe": pe_bytes(),
              "raw.cr2": b"II*\x00" + b"\x00" * 60, "song.mp3": VALID_SAMPLES["mp3_id3"][0]}
        for name, data in ok.items():
            with self.subTest(file=name):
                self.assertFalse(core.analyze_file(self.write(name, data))["mismatch"])

    def test_name_handling(self):
        self.assertEqual(self.default_plan_target(self.write("photo.png.txt", PNG)), "photo.png")
        self.assertEqual(self.default_plan_target(self.write("noext", PNG)), "noext.png")
        self.assertIsNone(self.default_plan_target(self.write("x.xyz", PNG)))     # unknown ext -> report only
        self.assertIsNone(self.default_plan_target(self.write(".gitignore", PNG)))  # hidden, extensionless

    def test_risky_mode_handles_odd_names(self):
        p = self.write("backup 2024.01", PNG)
        plan = core.build_rename_plan([core.analyze_file(p)], include_risky=True)
        self.assertEqual(Path(plan[0]["new_path"]).name, "backup 2024.01.png")


class TestTextGuardsAndFamilies(TmpDirCase):
    """v6: امضاهای ASCII و اعضای خانواده‌ها"""

    def test_ascii_magic_text_lookalikes_are_not_renamed(self):
        cases = {
            "gif_notes.txt": b"GIF89a is the GIF header magic\nplain text\n",
            "riff_wave.txt": b"RIFF2024WAVE stores PCM audio\nmore\n",
            "riff_webp.txt": b"RIFF2024WEBP image notes\nmore\n",
            "form_aiff.txt": b"FORM2024AIFF audio notes\nmore\n",
            "tar_doc.txt": b"x" * 257 + b"ustar\nplain text\n",
            "deb_notes.txt": b"!<arch>\ndebian-binary is a deb marker\n",
            "bz2_doc.txt": b"BZh91AY&SY block header description\n",
        }
        for name, data in cases.items():
            with self.subTest(file=name):
                p = self.write(name, data)
                _ext, _n, conf = core.detect_real_type(p)
                self.assertNotEqual(conf, "certain")
                self.assertIsNone(self.default_plan_target(p))

    def test_text_with_torrent_like_start_is_not_a_torrent(self):
        p = self.write("doc.txt", b"d4:info4:name8:announce8:tracker...\nnotes\n")
        self.assertNotEqual(core.detect_real_type(p)[0], "torrent")
        self.assertIsNone(self.default_plan_target(p))

    def test_real_torrent_is_probable_only(self):
        data = (b"d8:announce20:http://t.example/ann4:infod6:lengthi5e4:name1:a"
                b"12:piece lengthi16384e6:pieces20:" + bytes(range(1, 21)) + b"ee")
        p = self.write("old.dat", data)
        self.assertEqual(core.detect_real_type(p)[0::2], ("torrent", "probable"))
        self.assertIsNone(self.default_plan_target(p))

    def test_extensionless_text_lookalikes_are_never_renamed(self):
        # regression: extensionless files used to get ".gif/.wav/.torrent" in default mode
        cases = {
            "NOTES": b"GIF89a is the GIF header magic\nplain text\n",
            "README": b"RIFF2024WAVE stores PCM audio\nmore\n",
            "LOG": b"d4:info4:name8:announce8:tracker...\nnotes\n",
            "TARBALL": b"x" * 257 + b"ustar\nplain text\n",
        }
        for name, data in cases.items():
            for risky in (False, True):
                with self.subTest(file=name, risky=risky):
                    r = core.analyze_file(self.write(name, data))
                    plan = core.build_rename_plan([r], include_risky=risky)
                    renamed_to = [Path(i["new_path"]).suffix for i in plan]
                    self.assertNotIn(renamed_to[0] if renamed_to else None,
                                     (".gif", ".wav", ".torrent", ".tar"))

    def test_txt_lookalike_is_not_renamed_even_in_risky_mode(self):
        r = core.analyze_file(self.write("gif_notes.txt", b"GIF89a is the GIF header magic\nplain\n"))
        for item in core.build_rename_plan([r], include_risky=True):
            self.assertNotEqual(Path(item["new_path"]).suffix, ".gif")

    def test_real_ascii_magic_files_stay_certain(self):
        gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00"
               b"\xff\xff\xff\x00\x00\x00\x2c" + b"\x00" * 8 + b"\x3b")
        wav = (b"RIFF$\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00"
               b"\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00")
        samples = (("real.gif", gif, "gif"),
                   ("real.wav", wav, "wav"),
                   ("real.bz2", bz2.compress(b"bin\x00ary" * 100), "bz2"))
        for name, data, ext in samples:
            with self.subTest(file=name):
                real, _n, conf = core.detect_real_type(self.write(name, data))
                self.assertEqual((real, conf), (ext, "certain"))

    def test_member_extensions_resolve_to_family(self):
        # محتوای Opus داخل فایل .oga: همان خانواده‌ی OGG است، mismatch نیست
        opus = b"OggS\x00\x02" + b"\x00" * 20 + b"\x01\x13" + b"OpusHead\x01\x02" + b"\x00" * 20
        self.assertFalse(core.analyze_file(self.write("voice.oga", opus))["mismatch"])
        self.assertFalse(core.analyze_file(self.write("voice.opus", opus))["mismatch"])
        # محتوای HEIC داخل فایل .heif
        heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x02\x00heicmif1" + b"\x00" * 32
        self.assertFalse(core.analyze_file(self.write("photo.heif", heic))["mismatch"])


class TestV7Fixes(TmpDirCase):
    """v7: latin-1، OpenOffice 1.x، tar checksum، امضاهای جدید"""

    def test_latin1_html_is_text_not_unknown(self):
        # real-world ISO-8859-1 HTML (DocBook-generated docs)
        data = (b'<html><head><meta http-equiv="Content-Type" '
                b'content="text/html; charset=ISO-8859-1"><title>Chap\xa01</title>'
                b'</head><body><p>R\xe9sum\xe9 page</p></body></html>')
        p = self.write("page.html", data)
        real, _n, conf = core.detect_real_type(p)
        self.assertEqual((real, conf), ("html", "text"))
        self.assertFalse(core.analyze_file(p)["mismatch"])
        # extensionless latin-1 text: risky mode -> .html, default -> untouched
        q = self.write("notes", data)
        self.assertIsNone(self.default_plan_target(q))
        plan = core.build_rename_plan([core.analyze_file(q)], include_risky=True)
        self.assertEqual(Path(plan[0]["new_path"]).suffix, ".html")

    def test_latin1_binary_stays_unknown(self):
        # binary with control bytes must NOT become "text"
        data = b"\x89\x50\x00\x01" + bytes(range(0, 32)) * 4
        p = self.write("blob.bin", data)
        self.assertEqual(core.detect_real_type(p)[2], "unknown")

    def test_openoffice1x_sxd_by_manifest(self):
        # old OpenOffice 1.x zip has no mimetype entry; type is in the manifest
        manifest = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
                    '<manifest:file-entry manifest:full-path="/" '
                    'manifest:media-type="application/vnd.sun.xml.draw"/>'
                    '<manifest:file-entry manifest:full-path="content.xml" '
                    'manifest:media-type="text/xml"/></manifest:manifest>')
        p = make_zip(self.dir / "draw.zip", {
            "content.xml": "<x/>", "styles.xml": "<x/>",
            "META-INF/manifest.xml": manifest})
        self.assertEqual(core.detect_zip_subtype(p)[0::2], ("sxd", "certain"))
        # a real SXD named .zip is renamed to .sxd; a .sxd is left alone
        q = make_zip(self.dir / "plan.zip", {
            "content.xml": "<x/>", "styles.xml": "<x/>",
            "META-INF/manifest.xml": manifest})
        self.assertEqual(self.default_plan_target(q), "plan.sxd")
        with open(q, "rb") as fh:
            p2 = self.write("keep.sxd", fh.read())
        self.assertFalse(core.analyze_file(p2)["mismatch"])

    def test_real_tar_certain_and_fake_ustar_rejected(self):
        import tarfile, io as _io
        buf = _io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            ti = tarfile.TarInfo("hello.txt")
            payload = b"payload data " * 40
            ti.size = len(payload)
            tf.addfile(ti, _io.BytesIO(payload))
        p = self.write("arch.bin", buf.getvalue())
        self.assertEqual(core.detect_real_type(p)[0::2], ("tar", "certain"))
        # binary file with "ustar" at 257 but a broken checksum -> not tar
        fake = bytearray(1024)
        fake[257:262] = b"ustar"
        q = self.write("fake.dat", bytes(fake))
        self.assertNotEqual(core.detect_real_type(q)[0], "tar")

    def test_new_signatures(self):
        cases = {
            "doc.bin": (b"AT&TFORM\x00\x00\x00\x00DJVU" + b"\x00" * 40, "djvu", "certain"),
            "font.pfb": (b"\x80\x01\x20\x00\x00\x00" + b"%" * 40, "pfb", "probable"),
            "mac.bin": (b"\xce\xfa\xed\xfe" + b"\x00" * 40, "macho", "certain"),
        }
        for name, (data, ext, conf) in cases.items():
            with self.subTest(file=name):
                self.assertEqual(core.detect_real_type(self.write(name, data))[0::2],
                                 (ext, conf))

    def test_djvu_text_lookalike_not_detected(self):
        p = self.write("note.txt", b"AT&TFORM explained in text form\nplain\n")
        real, _n, conf = core.detect_real_type(p)
        self.assertNotEqual(real, "djvu")
        self.assertIsNone(self.default_plan_target(p))

    def test_cfb_4096_sector_offset(self):
        # minimal Compound File with 4096-byte sectors (MS-CFB: sector N
        # lives at (N+1)*4096); old code read sectors at 512 + N*4096.
        import struct
        ssz = 4096
        buf = bytearray(ssz * 3 + 512)
        buf[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        struct.pack_into("<H", buf, 30, 12)          # sector shift = 4096
        struct.pack_into("<I", buf, 44, 1)           # 1 FAT sector
        struct.pack_into("<I", buf, 48, 1)           # first dir sector = 1
        struct.pack_into("<I", buf, 68, 0xFFFFFFFE)  # no DIFAT chain
        struct.pack_into("<I", buf, 76, 0)           # DIFAT[0] -> FAT at sector 0
        fat = bytearray(ssz)
        struct.pack_into("<I", fat, 0, 0xFFFFFFFD)   # FATSECT
        struct.pack_into("<I", fat, 4, 0xFFFFFFFE)   # dir chain end
        buf[4096:8192] = fat
        entry = bytearray(128)
        name = "Root Entry".encode("utf-16-le") + b"\x00\x00"
        entry[0:len(name)] = name
        struct.pack_into("<H", entry, 64, len(name))
        entry[66] = 5                                 # root storage
        buf[8192:8320] = entry
        p = self.write("ole4096.dat", bytes(buf))
        names = core.read_cfb_directory_names(p)
        self.assertEqual(names, ["Root Entry"])
        ext, _t, conf = core.detect_ole_subtype(p)
        self.assertEqual((ext, conf), (None, "probable"))


class TestRenameAndUndo(TmpDirCase):
    def test_roundtrip_and_no_overwrite(self):
        a = self.write("a.txt", PNG)
        self.write("a.png", b"existing file - must survive")
        b = self.write("b.mp3", JPG)
        results = [core.analyze_file(p) for p in (a, b)]
        plan = core.build_rename_plan(results)
        log = core.start_undo_log(log_dir=self.dir / "logs")
        core.apply_rename_plan(plan, undo_log_path=log)

        self.assertEqual((self.dir / "a.png").read_bytes(), b"existing file - must survive")
        self.assertTrue((self.dir / "a (1).png").exists())
        self.assertTrue((self.dir / "b.jpg").exists())

        undone = core.undo_rename_plan(log)
        self.assertTrue(all(u["status"] == "restored" for u in undone))
        self.assertEqual(sorted(p.name for p in self.dir.iterdir() if p.is_file()),
                         ["a.png", "a.txt", "b.mp3"])

    def test_undo_refuses_modified_destination(self):
        # بعد از اصلاح، فایلِ مقصد ویرایش شود؛ Undo نباید به آن دست بزند
        a = self.write("a.txt", PNG)
        plan = core.build_rename_plan([core.analyze_file(a)])
        log = core.start_undo_log(log_dir=self.dir / "logs")
        core.apply_rename_plan(plan, undo_log_path=log)
        self.assertTrue((self.dir / "a.png").exists())

        (self.dir / "a.png").write_bytes(b"tampered content with a different size")
        undone = core.undo_rename_plan(log)
        self.assertEqual(undone[0]["status"], "error")
        self.assertTrue((self.dir / "a.png").read_bytes().startswith(b"tampered"))
        self.assertFalse((self.dir / "a.txt").exists())

    def test_undo_ignores_recreated_file_with_same_name(self):
        a = self.write("a.txt", PNG)
        plan = core.build_rename_plan([core.analyze_file(a)])
        log = core.start_undo_log(log_dir=self.dir / "logs")
        core.apply_rename_plan(plan, undo_log_path=log)
        (self.dir / "a.png").unlink()
        (self.dir / "a.png").write_bytes(b"brand new unrelated file")
        undone = core.undo_rename_plan(log)
        self.assertEqual(undone[0]["status"], "error")
        self.assertEqual((self.dir / "a.png").read_bytes(), b"brand new unrelated file")

    def test_undo_after_crash_with_suffix(self):
        # شبیه‌سازی کرش بین rename و ثبت رکورد final: لاگ فقط رکورد start
        # (با نام پیشنهادی) دارد ولی فایل واقعاً به "x (1).png" رفته است.
        # Undo باید فایل واقعی را برگرداند و فایل بی‌ربطِ x.png را دست نزند.
        x = self.write("x.txt", PNG)
        self.write("x.png", b"unrelated occupier - must survive")
        plan = core.build_rename_plan([core.analyze_file(x)])
        log = core.start_undo_log(log_dir=self.dir / "logs")
        core.log_rename_start(log, Path(plan[0]["old_path"]), Path(plan[0]["new_path"]))
        os.rename(x, self.dir / "x (1).png")     # تغییر نام واقعی بدون رکورد final

        undone = core.undo_rename_plan(log)
        self.assertEqual(undone[0]["status"], "restored")
        self.assertEqual(undone[0]["current_path"], str(self.dir / "x (1).png"))
        self.assertTrue((self.dir / "x.txt").exists())
        self.assertEqual((self.dir / "x.png").read_bytes(),
                         b"unrelated occupier - must survive")
        self.assertFalse((self.dir / "x (1).png").exists())

    def test_undo_when_rename_never_happened(self):
        # رکورد start ثبت شده ولی rename انجام نشده (خطا/کرش قبل از rename)
        x = self.write("x.txt", PNG)
        plan = core.build_rename_plan([core.analyze_file(x)])
        log = core.start_undo_log(log_dir=self.dir / "logs")
        core.log_rename_start(log, Path(plan[0]["old_path"]), Path(plan[0]["new_path"]))
        undone = core.undo_rename_plan(log)
        self.assertEqual(undone[0]["status"], "skipped_missing")
        self.assertTrue((self.dir / "x.txt").exists())

    def test_undo_supports_v1_log_format(self):
        a = self.write("a.txt", PNG)
        log = self.dir / "logs" / "undo_v1.json"
        log.parent.mkdir(exist_ok=True)
        log.write_text(json.dumps({
            "created_at": "2026-01-01 10:00:00",
            "entries": [{"old_path": str(a), "new_path": str(self.dir / "a.png")}],
        }, ensure_ascii=False), encoding="utf-8")
        os.rename(a, self.dir / "a.png")
        undone = core.undo_rename_plan(log)
        self.assertEqual(undone[0]["status"], "restored")
        self.assertTrue((self.dir / "a.txt").exists())

    def test_undo_tolerates_torn_log_line(self):
        # خطِ نیمه‌نوشته در انتهای لاگ (قطع برق وسط نوشتن) نباید Undo را بشکند
        a = self.write("a.txt", PNG)
        plan = core.build_rename_plan([core.analyze_file(a)])
        log = core.start_undo_log(log_dir=self.dir / "logs")
        core.apply_rename_plan(plan, undo_log_path=log)
        with open(log, "a", encoding="utf-8") as f:
            f.write('{"t": "start", "old_pa')
        undone = core.undo_rename_plan(log)
        self.assertEqual(undone[0]["status"], "restored")
        self.assertTrue((self.dir / "a.txt").exists())


class TestProtectedRoot(TmpDirCase):
    def test_roots(self):
        self.assertTrue(core.is_protected_root(Path(Path.cwd().anchor)))
        if os.name != "nt":
            self.assertTrue(core.is_protected_root("/usr/lib"))
        self.assertFalse(core.is_protected_root(self.dir))

    def test_failsafe_when_resolve_errors(self):
        # اگر resolve() خطا بدهد، مسیر باید «محافظت‌شده» فرض شود (fail-safe)
        original_resolve = Path.resolve

        def broken_resolve(self, strict=False):
            raise RuntimeError("simulated resolve failure")

        Path.resolve = broken_resolve
        try:
            self.assertTrue(core.is_protected_root("C:\\some\\path"))
        finally:
            Path.resolve = original_resolve


class TestCollectFiles(TmpDirCase):
    def test_skips_junk_dirs(self):
        (self.dir / "node_modules").mkdir()
        (self.dir / "node_modules" / "x.png").write_bytes(PNG)
        (self.dir / "keep").mkdir()
        (self.dir / "keep" / "y.png").write_bytes(PNG)
        names = {p.name for p in core.collect_files(self.dir, recursive=True)}
        self.assertEqual(names, {"y.png"})

    def test_single_file_symlink_is_skipped(self):
        target = self.write("real.png", PNG)
        link = self.dir / "link.png"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("creating symlinks is not permitted on this system")
        listed = list(core.collect_files(link, recursive=False))
        self.assertEqual(listed, [])
        listed_dir = list(core.collect_files(self.dir, recursive=True))
        self.assertEqual([p.name for p in listed_dir], ["real.png"])


if __name__ == "__main__":
    unittest.main()
