#!/usr/bin/env python3
"""
file_server.py - a simple, professional file download server.

Serves PDFs, media files and any other documents from one public folder with:

  * Browsable directory listings (folders first, sizes, dates, breadcrumbs)
  * Inline viewing by default, forced downloads with ``?download=1``
  * HTTP Range requests (resumable downloads and media seeking)
  * ETag / Last-Modified validation with 304 responses
  * HTML rendered from templates/ (no HTML inside Python code)
  * Zero third-party dependencies (Python 3.8+ standard library only)

Security model
--------------
Only the public folder given with --directory can ever be read.

  * Request paths are normalised before touching the disk: ``..``, encoded
    separators, backslashes and NUL bytes are rejected or collapsed.
  * Every path is walked one component at a time from an open file descriptor
    for the public folder, using O_NOFOLLOW. No component may be a symbolic
    link, so links cannot lead outside the public folder, and there is no
    check-then-open race.
  * Dotfiles and dot-directories are never opened or listed.
  * Only regular files and directories are served (no FIFOs, devices, sockets).
  * The file size and timestamps come from the same descriptor that is read.
  * The server refuses to start if the public folder contains its own code
    and templates directory.
  * Active content (HTML/SVG/XML) is always sent as a download, never rendered.
  * The server is read-only: write methods return 405.

Requires a POSIX system (Linux or macOS).

Usage:
    python3 file_server.py --directory ./files --port 8000
"""

from __future__ import annotations

import argparse
import datetime
import html
import logging
import mimetypes
import os
import posixpath
import re
import socket
import stat
import sys
import urllib.parse
from email.utils import formatdate, parsedate_to_datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from typing import Dict, List, Optional, Tuple

__version__ = "1.1.0"
LOG = logging.getLogger("file_server")

PROGRAM_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = PROGRAM_DIR / "templates"
TESTS_DIR = PROGRAM_DIR / "tests"
CHUNK_SIZE = 64 * 1024

# Paths that must never be inside (or contain) the public folder.
INTERNAL_PATHS = (PROGRAM_DIR / "file_server.py", TEMPLATE_DIR, TESTS_DIR)


def _overlaps_internal(root: Path) -> bool:
    """True if ``root`` is, contains, or sits inside one of INTERNAL_PATHS."""
    for internal in INTERNAL_PATHS:
        if root == internal or root in internal.parents or internal in root.parents:
            return True
    return False

if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
    raise RuntimeError("file_server requires a POSIX system (Linux or macOS)")

# Flags for every open() on the public tree. O_NOFOLLOW makes the kernel refuse
# to follow a symlink; O_NONBLOCK stops a FIFO from blocking the open call.
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)

# Types that are not always present in the system MIME database.
EXTRA_TYPES = {
    ".pdf": "application/pdf",
    ".epub": "application/epub+zip",
    ".mkv": "video/x-matroska",
    ".webm": "video/webm",
    ".m4a": "audio/mp4",
    ".flac": "audio/flac",
    ".opus": "audio/ogg",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".md": "text/markdown; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}

# Types that can run script if rendered by the browser. These are always sent
# as attachments so that a malicious file cannot execute on this origin.
ACTIVE_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/xml",
    "application/xml",
}

DOWNLOAD_TRUE = {"1", "true", "yes"}


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #
def _read_template(name: str) -> str:
    return (TEMPLATE_DIR / name).read_text(encoding="utf-8")


_TEMPLATES: Dict[str, Template] = {
    name: Template(_read_template(name))
    for name in ("page.html", "listing.html", "row.html", "error.html")
}
STYLE_CSS = _read_template("style.css")


def render(name: str, **values: str) -> str:
    """Fill templates/<name>. Every value must already be HTML-escaped."""
    return _TEMPLATES[name].substitute(values)


# --------------------------------------------------------------------------- #
# Path handling
# --------------------------------------------------------------------------- #
def guess_type(name: str) -> str:
    """Return the Content-Type for a file name."""
    suffix = posixpath.splitext(name)[1].lower()
    if suffix in EXTRA_TYPES:
        return EXTRA_TYPES[suffix]
    ctype, _ = mimetypes.guess_type(name)
    return ctype or "application/octet-stream"


def human_size(num: int) -> str:
    """Format a byte count as a short human-readable string."""
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} B"  # pragma: no cover - unreachable


def content_disposition(filename: str, attachment: bool) -> str:
    """Build a Content-Disposition header with an ASCII fallback and RFC 5987 name."""
    disposition = "attachment" if attachment else "inline"
    fallback = "".join(c if 32 <= ord(c) < 127 and c not in '"\\' else "_" for c in filename)
    quoted = urllib.parse.quote(filename, safe="")
    return f"{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{quoted}"


def parse_range(header: str, size: int) -> Optional[Tuple[int, int]]:
    """
    Parse a single-range ``Range: bytes=`` header.

    Returns (start, end) inclusive, or None if the header should be ignored
    (malformed or multi-range, which the server then answers with the full file).
    Raises ValueError if the range is syntactically valid but unsatisfiable.
    """
    match = re.fullmatch(r"\s*bytes=(\d*)-(\d*)\s*", header)
    if not match:
        return None
    first, last = match.groups()
    if first == "" and last == "":
        return None
    if first == "":  # suffix range: last N bytes
        suffix = int(last)
        if suffix == 0:
            raise ValueError("empty suffix range")
        return max(size - suffix, 0), size - 1
    start = int(first)
    if start >= size:
        raise ValueError("range start beyond end of file")
    end = min(int(last), size - 1) if last else size - 1
    if end < start:
        raise ValueError("range end before start")
    return start, end


def normalize_url_path(raw_path: str) -> Optional[str]:
    """
    Turn a raw request path into a clean relative path such as ``docs/report.pdf``.

    Returns None for paths that contain NUL bytes, backslashes, or any hidden
    (dot) segment. The empty string denotes the root.
    """
    decoded = urllib.parse.unquote(raw_path)
    if "\x00" in decoded or "\\" in decoded:
        return None
    normalized = posixpath.normpath("/" + decoded).lstrip("/")
    if normalized == ".":
        normalized = ""
    if any(part.startswith(".") for part in normalized.split("/") if part):
        return None
    return normalized


def open_public(root: Path, parts: List[str]) -> Optional[Tuple[int, os.stat_result]]:
    """
    Open ``root/parts[0]/.../parts[-1]`` without following any symbolic link.

    Each component is opened relative to the descriptor of its parent with
    O_NOFOLLOW, so the walk can never leave ``root``, even if the tree is
    modified while the server runs. Returns ``(fd, stat)`` for a regular file
    or directory, or None if the path does not exist or is not servable.
    The caller owns the returned descriptor and must close it.
    """
    chain: List[int] = []
    try:
        chain.append(os.open(root, _OPEN_FLAGS))
        for part in parts:
            if part in ("", ".", "..") or "/" in part or "\x00" in part:
                return None
            if not stat.S_ISDIR(os.fstat(chain[-1]).st_mode):
                return None  # an intermediate component is a file
            chain.append(os.open(part, _OPEN_FLAGS, dir_fd=chain[-1]))
        st = os.fstat(chain[-1])
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            return None  # FIFO, socket, device, etc.
        return chain.pop(), st
    except OSError:
        return None  # missing, symlink (ELOOP), permission denied, ...
    finally:
        for fd in chain:
            os.close(fd)


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #
class FileServer(ThreadingHTTPServer):
    """Threaded HTTP server that serves files below ``root`` and nothing else."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, root, title: str = "File Downloads"):
        root_path = Path(root).resolve()
        if not root_path.is_dir():
            raise ValueError(f"{root} is not a directory")
        if _overlaps_internal(root_path):
            raise ValueError(
                f"refusing to serve {root_path}: it contains or lies inside the server's "
                "own code, templates or tests. Use a dedicated public folder such as ./files."
            )
        self.root = root_path
        self.title = title
        super().__init__(address, FileRequestHandler)

    def server_bind(self):
        # Make the bound address visible in logs and avoid hostname lookups.
        super().server_bind()
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = port


class FileRequestHandler(BaseHTTPRequestHandler):
    server: FileServer  # for type checkers
    server_version = f"file_server/{__version__}"

    # ----- dispatch ------------------------------------------------------- #
    def do_GET(self):
        self._dispatch(send_body=True)

    def do_HEAD(self):
        self._dispatch(send_body=False)

    def do_POST(self):
        self._send_error(HTTPStatus.METHOD_NOT_ALLOWED, "Read-only server")

    do_PUT = do_DELETE = do_PATCH = do_POST

    def _dispatch(self, send_body: bool):
        try:
            self._handle(send_body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            LOG.debug("Client disconnected during %s %s", self.command, self.path)
        except Exception:  # noqa: BLE001 - never leak tracebacks to clients
            LOG.exception("Unhandled error for %s %s", self.command, self.path)
            try:
                self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error")
            except OSError:
                pass

    def _handle(self, send_body: bool):
        raw_path, _, query = self.path.partition("?")
        raw_path = raw_path.split("#", 1)[0]
        if not raw_path.startswith("/"):
            return self._send_error(HTTPStatus.NOT_FOUND, "Not found")

        rel = normalize_url_path(raw_path)
        if rel is None:
            return self._send_error(HTTPStatus.NOT_FOUND, "Not found")

        names = [part for part in rel.split("/") if part]
        opened = open_public(self.server.root, names)
        if opened is None:
            return self._send_error(HTTPStatus.NOT_FOUND, "Not found")

        fd, st = opened
        if stat.S_ISDIR(st.st_mode):
            # Canonical directory URLs end in "/" so relative links work.
            if not raw_path.endswith("/"):
                os.close(fd)
                target = "/" + urllib.parse.quote(rel) + "/"
                if query:
                    target += "?" + query
                return self._redirect(target)
            return self._send_listing(fd, rel, send_body)

        force = urllib.parse.parse_qs(query).get("download", ["0"])[0].lower() in DOWNLOAD_TRUE
        return self._send_file(fd, st, names[-1], send_body, force)

    # ----- responses ------------------------------------------------------ #
    def _common_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
            "frame-ancestors 'self'; base-uri 'none'; form-action 'none'",
        )

    def _redirect(self, location: str):
        self.send_response(HTTPStatus.MOVED_PERMANENTLY)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self._common_headers()
        self.end_headers()

    def _render_page(self, title: str, body: str, footer: str) -> bytes:
        return render(
            "page.html",
            page_title=html.escape(title),
            heading=html.escape(self.server.title),
            style=STYLE_CSS,
            body=body,
            footer=html.escape(footer),
        ).encode("utf-8")

    def _send_html(self, status, page: bytes, send_body: bool):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-cache")
        self._common_headers()
        self.end_headers()
        if send_body:
            self.wfile.write(page)

    def _send_error(self, status: HTTPStatus, message: str):
        body = render("error.html", message=html.escape(message))
        page = self._render_page(
            f"{status.value} {status.phrase} - {self.server.title}",
            body,
            f"Served by file_server {__version__}",
        )
        self._send_html(status, page, send_body=self.command != "HEAD")

    def _send_listing(self, fd: int, rel: str, send_body: bool):
        # ``fd`` is an open directory. Entries are inspected with lstat relative
        # to it, so symlinks, FIFOs and other special files are never listed.
        try:
            entries = []
            for name in os.listdir(fd):
                if name.startswith("."):
                    continue
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    entries.append((name, True, st))
                elif stat.S_ISREG(st.st_mode):
                    entries.append((name, False, st))
        except OSError:
            return self._send_error(HTTPStatus.FORBIDDEN, "Directory not readable")
        finally:
            os.close(fd)

        entries.sort(key=lambda e: (not e[1], e[0].lower()))
        base = "/" + (urllib.parse.quote(rel) + "/" if rel else "")

        rows = []
        if rel:
            parent_rel = posixpath.dirname(rel)
            parent = "/" + (urllib.parse.quote(parent_rel) + "/" if parent_rel else "")
            rows.append(render("row.html", badge="DIR", href=parent, label="..",
                               size="", modified="", action=""))
        for name, is_dir, st in entries:
            href = base + urllib.parse.quote(name) + ("/" if is_dir else "")
            action = "" if is_dir else (
                f'<a class="btn" href="{html.escape(href)}?download=1">Download</a>'
            )
            rows.append(render(
                "row.html",
                badge=_badge(name, is_dir),
                href=html.escape(href),
                label=html.escape(name + ("/" if is_dir else "")),
                size="" if is_dir else human_size(st.st_size),
                modified=_format_time(st.st_mtime),
                action=action,
            ))

        crumbs = ['<a href="/">Home</a>']
        accumulated = ""
        for segment in [s for s in rel.split("/") if s]:
            accumulated += "/" + urllib.parse.quote(segment)
            crumbs.append(f'<a href="{accumulated}/">{html.escape(segment)}</a>')

        empty = '<div class="empty">This folder is empty.</div>' if not entries else ""
        body = render(
            "listing.html",
            crumbs=" / ".join(crumbs),
            rows="\n".join(rows),
            empty=empty,
        )
        title = f"/{rel} - {self.server.title}" if rel else self.server.title
        page = self._render_page(
            title, body,
            f"{len(entries)} item(s) \u00b7 Served by file_server {__version__}",
        )
        self._send_html(HTTPStatus.OK, page, send_body)

    def _send_file(self, fd: int, st: os.stat_result, name: str,
                   send_body: bool, force_download: bool):
        # The descriptor is opened by open_public(); reading through it means
        # the bytes served are exactly the file that was validated.
        with os.fdopen(fd, "rb") as handle:
            size = st.st_size
            etag = f'"{st.st_mtime_ns:x}-{size:x}"'
            last_modified = formatdate(st.st_mtime, usegmt=True)

            # Conditional requests -> 304 Not Modified.
            if_none_match = self.headers.get("If-None-Match")
            if if_none_match is not None:
                tags = [t.strip() for t in if_none_match.split(",")]
                if "*" in tags or etag in tags:
                    return self._send_not_modified(etag, last_modified)
            elif self.headers.get("If-Modified-Since"):
                try:
                    since = parsedate_to_datetime(self.headers["If-Modified-Since"]).timestamp()
                    if int(st.st_mtime) <= int(since):
                        return self._send_not_modified(etag, last_modified)
                except (TypeError, ValueError, OverflowError):
                    pass

            # Byte ranges (resumable downloads, media seeking).
            start, end, status = 0, size - 1, HTTPStatus.OK
            range_header = self.headers.get("Range")
            if_range = self.headers.get("If-Range")
            if_range_ok = if_range is None or if_range in (etag, last_modified)
            if range_header and size > 0 and if_range_ok:
                try:
                    parsed = parse_range(range_header, size)
                except ValueError:
                    self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.send_header("Content-Length", "0")
                    self._common_headers()
                    self.end_headers()
                    return
                if parsed is not None:
                    start, end = parsed
                    status = HTTPStatus.PARTIAL_CONTENT

            length = end - start + 1 if size > 0 else 0
            ctype = guess_type(name)
            attachment = force_download or ctype.split(";")[0] in ACTIVE_TYPES

            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Last-Modified", last_modified)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Disposition", content_disposition(name, attachment))
            if status == HTTPStatus.PARTIAL_CONTENT:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self._common_headers()
            self.end_headers()

            if send_body and length > 0:
                handle.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = handle.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)

    def _send_not_modified(self, etag: str, last_modified: str):
        self.send_response(HTTPStatus.NOT_MODIFIED)
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", last_modified)
        self._common_headers()
        self.end_headers()

    # ----- logging -------------------------------------------------------- #
    def log_message(self, format: str, *args):  # noqa: A002 - stdlib signature
        LOG.info("%s - %s", self.address_string(), format % args)


def _badge(name: str, is_dir: bool) -> str:
    if is_dir:
        return "DIR"
    ext = posixpath.splitext(name)[1].lstrip(".")
    return html.escape(ext[:4].upper()) if ext else "FILE"


def _format_time(timestamp: float) -> str:
    return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Serve PDFs, media and files for download over HTTP.",
    )
    parser.add_argument("-d", "--directory", default="files",
                        help="public folder to serve (default: ./files, created if missing)")
    parser.add_argument("-H", "--host", default="0.0.0.0",
                        help="interface to bind (default: 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, default=8000,
                        help="TCP port to listen on (default: 8000)")
    parser.add_argument("-t", "--title", default="File Downloads",
                        help="title shown in the page header")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable debug logging")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = Path(args.directory)
    if not root.exists():
        root.mkdir(parents=True)
        LOG.info("Created directory %s", root.resolve())
    if not root.is_dir():
        LOG.error("%s is not a directory", root)
        return 2

    if not 0 <= args.port <= 65535:
        LOG.error("Port must be between 0 and 65535")
        return 2

    try:
        server = FileServer((args.host, args.port), root, title=args.title)
    except ValueError as exc:  # unsafe or invalid public folder
        LOG.error("%s", exc)
        return 2
    except OSError as exc:  # bind failure
        LOG.error("Cannot bind to %s:%s: %s", args.host, args.port, exc)
        return 1

    host, port = server.server_address[:2]
    LOG.info("Serving %s at http://%s:%s/ (Ctrl+C to stop)", server.root, host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
