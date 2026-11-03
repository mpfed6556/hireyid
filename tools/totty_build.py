#!/usr/bin/env python3
"""Build the Yossi site (index.html at the repo root).

Everything is public except <section ... data-private> blocks (the photo story,
the video and the songs), which are encrypted together with the media files.

Page content, photos, video and audio are all encrypted with AES-256-GCM
(key from PBKDF2-SHA256 of the password), so nothing personal is readable in
the public repo without it. The password is case-insensitive ("Totty").

Build:
  python3 tools/totty_build.py build content.html \
      --img PORTRAIT=portrait.jpg --img VPOSTER=poster.jpg \
      --media video=video.mp4 --media audio=audio.mp3

  {{NAME}} placeholders in content.html are replaced with the images inline.
  Each --media file is written to media/<name>.bin (encrypted) and loaded
  into any <video>/<audio data-media="<name>"> element after unlock. With
  --plain-media it is copied as-is (e.g. media/video.mp4) and streamed directly.

Recover the editable source from the published page:
  python3 tools/totty_build.py extract <out-dir>

Requires: pip install cryptography
"""
import argparse, base64, json, mimetypes, os, re
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PASSWORD = os.environ.get("TOTTY_PASSWORD", "Totty")
ITERATIONS = 250_000
ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "totty"
OUT = SITE / "index.html"
SHELL = Path(__file__).resolve().parent / "totty_shell.html"
MARK = re.compile(r'<script id="payload" type="application/json">(.*?)</script>', re.S)
b64e = lambda b: base64.b64encode(b).decode()


def derive(salt: bytes) -> AESGCM:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return AESGCM(kdf.derive(PASSWORD.strip().lower().encode()))


def pairs(items):
    return [tuple(i.split("=", 1)) for i in items or []]


PRIV = re.compile(r'<section id="(\w+)"([^>]*?)\sdata-private([^>]*)>(.*?)</section>', re.S)
PUB = re.compile(r'<!--PUBLIC-->(.*?)<!--/PUBLIC-->', re.S)


def split_private(html):
    """Pull the data-private sections out; leave a placeholder with the section's heading."""
    parts = {}
    def cut(m):
        sid, before, after, inner = m.groups()
        parts[sid] = inner
        h = re.search(r'<h2[^>]*>(.*?)</h2>', inner, re.S)
        title = h.group(1).strip() if h else ''
        return (f'<section id="{sid}"{before}{after} data-lock="{sid}">'
                f'<h2>{title}</h2><div class="lock-slot"></div></section>')
    return PRIV.sub(cut, html), parts


def build(a):
    html = Path(a.content).read_text(encoding="utf-8")
    for name, path in pairs(a.img):
        mime = mimetypes.guess_type(path)[0] or "image/jpeg"
        html = html.replace("{{%s}}" % name, f"data:{mime};base64," + b64e(Path(path).read_bytes()))
    public, parts = split_private(html)
    salt = os.urandom(16)
    aes = derive(salt)
    media = {}
    (SITE / "media").mkdir(parents=True, exist_ok=True)
    for old in (SITE / "media").iterdir():
        old.unlink()
    for name, path in pairs(a.media):
        mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if a.plain_media:
            fname = f"{name}{Path(path).suffix}"
            (SITE / "media" / fname).write_bytes(Path(path).read_bytes())
            media[name] = {"file": f"media/{fname}", "type": mime, "plain": True}
            continue
        iv = os.urandom(12)
        (SITE / "media" / f"{name}.bin").write_bytes(aes.encrypt(iv, Path(path).read_bytes(), None))
        media[name] = {"file": f"media/{name}.bin", "iv": b64e(iv), "type": mime}
    iv = os.urandom(12)
    secret = json.dumps({"parts": parts}).encode("utf-8")
    payload = json.dumps({"salt": b64e(salt), "iv": b64e(iv), "iter": ITERATIONS,
                          "ct": b64e(aes.encrypt(iv, secret, None)), "media": media})
    page = SHELL.read_text(encoding="utf-8").replace("{{PUBLIC}}", "<!--PUBLIC-->" + public + "<!--/PUBLIC-->")
    OUT.write_text(page.replace("{{PAYLOAD}}", payload), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB), locked: {', '.join(parts) or 'none'}, media: {', '.join(media) or 'none'}")


def extract(a):
    page = OUT.read_text(encoding="utf-8")
    p = json.loads(MARK.search(page).group(1))
    aes = derive(base64.b64decode(p["salt"]))
    out = Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
    parts = json.loads(aes.decrypt(base64.b64decode(p["iv"]), base64.b64decode(p["ct"]), None))["parts"]
    def put(m):
        sid, before, after = m.group(1), m.group(2), m.group(3)
        return f'<section id="{sid}"{before}{after} data-private>{parts.get(sid, "")}</section>'
    html = re.sub(r'<section id="(\w+)"([^>]*?) data-lock="\w+"([^>]*)><h2>.*?</h2><div class="lock-slot"></div></section>', put, PUB.search(page).group(1), flags=re.S)
    (out / "content.html").write_text(html, encoding="utf-8")
    for name, m in p.get("media", {}).items():
        ext = {"video/mp4": ".mp4", "audio/mp4": ".m4a", "audio/mpeg": ".mp3"}.get(m["type"]) or mimetypes.guess_extension(m["type"]) or ".bin"
        raw = (SITE / m["file"]).read_bytes()
        data = raw if m.get("plain") else aes.decrypt(base64.b64decode(m["iv"]), raw, None)
        (out / f"{name}{ext}").write_bytes(data)
    print(f"extracted to {out} (images are inline data URIs in content.html)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("content")
    b.add_argument("--img", action="append"); b.add_argument("--media", action="append")
    b.add_argument("--plain-media", action="store_true",
                   help="store media unencrypted with normal extensions (most compatible)")
    e = sub.add_parser("extract"); e.add_argument("out_dir")
    a = ap.parse_args()
    (build if a.cmd == "build" else extract)(a)
