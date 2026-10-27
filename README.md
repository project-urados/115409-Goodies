# file_server

A small, dependency-free Python 3 web server for publishing PDFs, media and
other files for download. It uses only the standard library.

## Features

- Browsable, professional directory listings (folders first, sizes, dates, breadcrumbs, dark mode)
- Inline viewing in the browser by default; `?download=1` forces a download
- HTTP `Range` requests, so downloads can resume and media can seek
- `ETag` / `Last-Modified` caching with `304 Not Modified`
- Security: path traversal blocked, symlinks cannot escape the root, dotfiles are hidden,
  HTML/SVG/XML is always sent as an attachment, read-only (write methods return 405),
  security headers (`nosniff`, CSP, frame options)

## Project layout

```
file_server.py        server code (standard library only)
templates/            HTML, CSS and listing templates (edit these to restyle)
  page.html  listing.html  row.html  error.html  style.css
tests/                unit and HTTP tests
files/                default public folder (put your downloads here)
requirements.txt      no third-party packages needed
```

## Security model

Only the public folder passed with `--directory` can be read.

- Paths are normalised first: `..`, encoded separators, backslashes and NUL bytes are rejected.
- The file tree is walked one component at a time using `O_NOFOLLOW`, so no symbolic link
  is ever followed and nothing outside the public folder can be opened.
- Dotfiles, FIFOs, sockets and devices are never opened or listed.
- The server refuses to start if the public folder is, contains, or lies inside its own
  code, `templates/` or `tests/`.
- Requires a POSIX system (Linux or macOS).

## Quick start

```bash
python3 file_server.py --directory ./files --port 8000
```

Put files in `./files` (created automatically if missing), then open
`http://localhost:8000/`.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --directory` | `files` | Directory to serve |
| `-H, --host` | `0.0.0.0` | Interface to bind (use `127.0.0.1` for local only) |
| `-p, --port` | `8000` | TCP port |
| `-t, --title` | `File Downloads` | Title shown in the header |
| `-v, --verbose` | off | Debug logging |

Direct link for a forced download: `http://localhost:8000/docs/report.pdf?download=1`

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Installation

No third-party packages are required. `requirements.txt` documents this.

## Notes for production

This server is intended for internal use or light public distribution. For
heavy traffic, HTTPS, or authentication, place it behind a reverse proxy
(nginx, Caddy) that handles TLS and access control.
