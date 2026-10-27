"""Unit tests for file_server.py.

Run with:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import file_server as fs  # noqa: E402


class ParseRangeTests(unittest.TestCase):
    def test_explicit_range(self):
        self.assertEqual(fs.parse_range("bytes=0-9", 100), (0, 9))

    def test_open_ended_range(self):
        self.assertEqual(fs.parse_range("bytes=50-", 100), (50, 99))

    def test_suffix_range(self):
        self.assertEqual(fs.parse_range("bytes=-10", 100), (90, 99))

    def test_end_clamped_to_size(self):
        self.assertEqual(fs.parse_range("bytes=90-500", 100), (90, 99))

    def test_multi_range_ignored(self):
        self.assertIsNone(fs.parse_range("bytes=0-1,5-6", 100))

    def test_malformed_ignored(self):
        self.assertIsNone(fs.parse_range("items=0-1", 100))

    def test_unsatisfiable(self):
        with self.assertRaises(ValueError):
            fs.parse_range("bytes=100-", 100)
        with self.assertRaises(ValueError):
            fs.parse_range("bytes=-0", 100)


class NormalizePathTests(unittest.TestCase):
    def test_root(self):
        self.assertEqual(fs.normalize_url_path("/"), "")

    def test_nested(self):
        self.assertEqual(fs.normalize_url_path("/a/b%20c.pdf"), "a/b c.pdf")

    def test_traversal_collapses_inside_root(self):
        self.assertEqual(fs.normalize_url_path("/../../etc/passwd"), "etc/passwd")

    def test_hidden_rejected(self):
        self.assertIsNone(fs.normalize_url_path("/.env"))
        self.assertIsNone(fs.normalize_url_path("/docs/.git/config"))

    def test_backslash_and_nul_rejected(self):
        self.assertIsNone(fs.normalize_url_path("/a%5Cb"))
        self.assertIsNone(fs.normalize_url_path("/a%00b"))


class ContentDispositionTests(unittest.TestCase):
    def test_unicode_filename(self):
        header = fs.content_disposition("naïve.pdf", attachment=True)
        self.assertTrue(header.startswith("attachment; "))
        self.assertIn("filename*=UTF-8''na%C3%AFve.pdf", header)
        self.assertIn('filename="na_ve.pdf"', header)

    def test_inline(self):
        self.assertTrue(fs.content_disposition("a.pdf", False).startswith("inline"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name) / "files"
        (root / "docs" / "sub").mkdir(parents=True)
        (root / "media").mkdir()
        (root / "docs" / "report.pdf").write_bytes(b"%PDF-1.4 0123456789")
        (root / "docs" / "evil.html").write_text("<script>alert(1)</script>")
        (root / "docs" / "naïve.txt").write_text("hi", encoding="utf-8")
        (root / "media" / "clip.bin").write_bytes(bytes(range(256)) * 400)
        (root / ".secret").write_text("nope")
        outside = Path(cls.tmp.name) / "outside.txt"
        outside.write_text("outside")
        os.symlink(outside, root / "escape.txt")
        os.symlink(outside, root / "docs" / "ok-link-outside.txt")

        cls.server = fs.FileServer(("127.0.0.1", 0), root)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, path, method="GET", headers=None):
        req = urllib.request.Request(self.base + path, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def test_listing_root(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"docs/", body)
        self.assertNotIn(b".secret", body)

    def test_listing_subdirectory(self):
        status, _, body = self.request("/docs/")
        self.assertEqual(status, 200)
        self.assertIn(b'href="/docs/report.pdf"', body)
        self.assertIn(b'href="/"', body)  # parent link
        self.assertNotIn(b'href="/docs/.secret"', body)

    def test_pdf_inline_and_download(self):
        status, headers, body = self.request("/docs/report.pdf")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/pdf")
        self.assertTrue(headers["Content-Disposition"].startswith("inline"))
        self.assertEqual(body, b"%PDF-1.4 0123456789")
        _, headers, _ = self.request("/docs/report.pdf?download=1")
        self.assertTrue(headers["Content-Disposition"].startswith("attachment"))

    def test_directory_redirect(self):
        opener = urllib.request.build_opener(_NoRedirect)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            opener.open(self.base + "/docs", timeout=5)
        self.assertEqual(ctx.exception.code, 301)
        self.assertEqual(ctx.exception.headers["Location"], "/docs/")

    def test_range_request(self):
        status, headers, body = self.request("/docs/report.pdf", headers={"Range": "bytes=0-3"})
        self.assertEqual(status, 206)
        self.assertEqual(body, b"%PDF")
        self.assertEqual(headers["Content-Range"], "bytes 0-3/19")

    def test_unsatisfiable_range(self):
        status, headers, _ = self.request("/docs/report.pdf", headers={"Range": "bytes=999-"})
        self.assertEqual(status, HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
        self.assertEqual(headers["Content-Range"], "bytes */19")

    def test_large_binary_range_matches(self):
        full = self.request("/media/clip.bin")[2]
        status, _, part = self.request("/media/clip.bin", headers={"Range": "bytes=100-299"})
        self.assertEqual(status, 206)
        self.assertEqual(part, full[100:300])

    def test_conditional_304(self):
        _, headers, _ = self.request("/docs/report.pdf")
        status, _, body = self.request("/docs/report.pdf", headers={"If-None-Match": headers["ETag"]})
        self.assertEqual(status, 304)
        self.assertEqual(body, b"")

    def test_html_forced_to_attachment(self):
        _, headers, _ = self.request("/docs/evil.html")
        self.assertTrue(headers["Content-Disposition"].startswith("attachment"))
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_hidden_and_escaping_paths_404(self):
        for path in ["/.secret", "/escape.txt", "/../../etc/passwd",
                     "/%2e%2e/%2e%2e/etc/passwd", "/missing.pdf"]:
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_symlink_inside_root_to_outside_blocked(self):
        self.assertEqual(self.request("/docs/ok-link-outside.txt")[0], 404)

    def test_unicode_filename(self):
        status, _, body = self.request("/docs/na%C3%AFve.txt")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hi")

    def test_head_has_no_body(self):
        status, headers, body = self.request("/docs/report.pdf", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Length"], "19")
        self.assertEqual(body, b"")

    def test_write_methods_rejected(self):
        for method in ["POST", "PUT", "DELETE"]:
            with self.subTest(method=method):
                self.assertEqual(self.request("/docs/report.pdf", method=method)[0], 405)


class ContainmentTests(unittest.TestCase):
    """The server must never expose anything outside the public folder."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        cls.public = base / "public"
        cls.public.mkdir()
        cls.secret_dir = base / "private"
        cls.secret_dir.mkdir()
        (cls.secret_dir / "passwd.txt").write_text("TOP SECRET")
        (cls.public / "ok.txt").write_text("public")
        (cls.public / "subdir").mkdir()
        (cls.public / "subdir" / "inside.txt").write_text("inside")
        # Every kind of escape hatch an attacker might use.
        os.symlink(cls.secret_dir, cls.public / "linkdir")              # dir symlink out
        os.symlink(cls.secret_dir / "passwd.txt", cls.public / "linkfile")  # file symlink out
        os.symlink("../private/passwd.txt", cls.public / "relative.txt")    # relative escape
        os.symlink(cls.public / "ok.txt", cls.public / "linkok.txt")        # link inside is also refused
        os.mkfifo(cls.public / "pipe.fifo")                              # special file
        (cls.public / "<img src=x onerror=1>.txt").write_text("x")        # markup in filenames
        cls.server = fs.FileServer(("127.0.0.1", 0), cls.public)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=3) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_symlinked_directory_cannot_be_traversed(self):
        self.assertEqual(self.get("/linkdir/passwd.txt")[0], 404)
        self.assertEqual(self.get("/linkdir/")[0], 404)

    def test_symlinked_file_cannot_be_read(self):
        status, body = self.get("/linkfile")
        self.assertEqual(status, 404)
        self.assertNotIn(b"TOP SECRET", body)

    def test_relative_symlink_escape_blocked(self):
        status, body = self.get("/relative.txt")
        self.assertEqual(status, 404)
        self.assertNotIn(b"TOP SECRET", body)

    def test_symlink_inside_public_also_refused(self):
        # Simplest rule: no symlink is followed, even ones that stay inside.
        self.assertEqual(self.get("/linkok.txt")[0], 404)

    def test_fifo_is_never_opened(self):
        self.assertEqual(self.get("/pipe.fifo")[0], 404)

    def test_listing_hides_symlinks_and_special_files(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"ok.txt", body)
        self.assertIn(b"subdir/", body)
        for hidden in (b"linkdir", b"linkfile", b"relative.txt", b"linkok.txt", b"pipe.fifo"):
            self.assertNotIn(hidden, body)

    def test_regular_nested_file_still_served(self):
        self.assertEqual(self.get("/subdir/inside.txt"), (200, b"inside"))

    def test_path_escape_attempts_return_404(self):
        for path in ["/../private/passwd.txt", "/..%2Fprivate%2Fpasswd.txt",
                     "/subdir/../../private/passwd.txt", "/%2e%2e/private/passwd.txt",
                     "/subdir/..%5c..%5cprivate", "/%00ok.txt", "/ok.txt/..",
                     "/ok.txt/inside.txt"]:
            with self.subTest(path=path):
                status, body = self.get(path)
                self.assertNotEqual(status, 200)
                self.assertNotIn(b"TOP SECRET", body)

    def test_server_code_and_templates_not_reachable(self):
        # Even if the code lived under the public folder, paths to it are
        # unreachable from the root, and dotfiles are never served.
        for path in ["/../file_server.py", "/../templates/page.html", "/../tests/test_file_server.py"]:
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 404)

    def test_listing_escapes_filenames(self):
        status, body = self.get("/")
        self.assertIn(b"&lt;img src=x onerror=1&gt;.txt", body)
        self.assertNotIn(b"<img src=x onerror=1>", body)

    def test_refuses_to_serve_internal_directories(self):
        # Equal to, containing, or inside the code/templates/tests paths.
        for bad in [fs.PROGRAM_DIR, fs.PROGRAM_DIR.parent, fs.TEMPLATE_DIR,
                    fs.TESTS_DIR, fs.TEMPLATE_DIR / "."]:
            with self.subTest(root=str(bad)):
                with self.assertRaises(ValueError):
                    fs.FileServer(("127.0.0.1", 0), bad).server_close()

    def test_allows_public_folder_next_to_code(self):
        # The default ./files folder sits inside the project and must not be refused.
        self.assertFalse(fs._overlaps_internal(fs.PROGRAM_DIR / "files"))
        self.assertFalse(fs._overlaps_internal(fs.PROGRAM_DIR.parent / "public"))

    def test_templates_load_and_have_placeholders(self):
        self.assertIn("$body", fs._TEMPLATES["page.html"].template)
        self.assertIn("$rows", fs._TEMPLATES["listing.html"].template)
        self.assertIn("body {", fs.STYLE_CSS)


if __name__ == "__main__":
    unittest.main()
