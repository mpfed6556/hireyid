#!/usr/bin/env python3
"""Build the password-protected Yossi presentation page at totty/index.html.

Page content, photos, video and audio are all encrypted with AES-256-GCM
(key from PBKDF2-SHA256 of the password), so nothing personal is readable in
the public repo without it. The password is case-insensitive ("Totty").

Build:
  python3 tools/totty_build.py build content.html \
      --img PORTRAIT=portrait.jpg --img VPOSTER=poster.jpg \
      --media video=video.mp4 --media audio=audio.mp3

  {{NAME}} placeholders in content.html are replaced with the images inline.
  Each --media file is written to totty/media/<name>.bin and loaded into
  any <video>/<audio data-media="<name>"> element after unlock.

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


def build(a):
    html = Path(a.content).read_text(encoding="utf-8")
    for name, path in pairs(a.img):
        mime = mimetypes.guess_type(path)[0] or "image/jpeg"
        html = html.replace("{{%s}}" % name, f"data:{mime};base64," + b64e(Path(path).read_bytes()))
    salt = os.urandom(16)
    aes = derive(salt)
    media = {}
    (SITE / "media").mkdir(parents=True, exist_ok=True)
    for name, path in pairs(a.media):
        iv = os.urandom(12)
        (SITE / "media" / f"{name}.bin").write_bytes(aes.encrypt(iv, Path(path).read_bytes(), None))
        media[name] = {"file": f"media/{name}.bin", "iv": b64e(iv),
                       "type": mimetypes.guess_type(path)[0] or "application/octet-stream"}
    iv = os.urandom(12)
    payload = json.dumps({"salt": b64e(salt), "iv": b64e(iv), "iter": ITERATIONS,
                          "ct": b64e(aes.encrypt(iv, html.encode("utf-8"), None)), "media": media})
    OUT.write_text(SHELL.read_text(encoding="utf-8").replace("{{PAYLOAD}}", payload), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB), media: {', '.join(media) or 'none'}")


def extract(a):
    p = json.loads(MARK.search(OUT.read_text(encoding="utf-8")).group(1))
    aes = derive(base64.b64decode(p["salt"]))
    out = Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "content.html").write_bytes(aes.decrypt(base64.b64decode(p["iv"]), base64.b64decode(p["ct"]), None))
    for name, m in p.get("media", {}).items():
        ext = mimetypes.guess_extension(m["type"]) or ".bin"
        data = aes.decrypt(base64.b64decode(m["iv"]), (SITE / m["file"]).read_bytes(), None)
        (out / f"{name}{ext}").write_bytes(data)
    print(f"extracted to {out} (images are inline data URIs in content.html)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("content")
    b.add_argument("--img", action="append"); b.add_argument("--media", action="append")
    e = sub.add_parser("extract"); e.add_argument("out_dir")
    a = ap.parse_args()
    (build if a.cmd == "build" else extract)(a)
