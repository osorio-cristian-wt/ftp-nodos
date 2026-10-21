#!/usr/bin/env python3
"""ztftp - transferencia de archivos liviana entre nodos de ZeroTier.

Cada nodo corre un demonio (`ztftp serve`). Desde cualquier nodo:

    ztftp cp ORIGEN DESTINO        (cada lado es `ruta` local o `nodo:ruta`)

`nodo` es una IP de ZeroTier o un alias definido en ~/.ztftp.json.
Solo biblioteca estandar. ZeroTier ya cifra el trafico, asi que el protocolo
solo agrega autenticacion mutua por secreto compartido (HMAC) e integridad
(SHA-256 por archivo).
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

DEFAULT_PORT = 9777
CHUNK = 1 << 20
TIMEOUT = 30
MAX_MSG = 64 << 20
PART = ".ztftp-part"


class ZtError(Exception):
    pass


# ---------------------------------------------------------------- protocolo

def send_msg(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(CHUNK, n - len(buf)))
        if not chunk:
            raise ConnectionError("conexion cerrada por el otro nodo")
        buf += chunk
    return bytes(buf)


def recv_msg(sock):
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    if n > MAX_MSG:
        raise ZtError("mensaje demasiado grande")
    return json.loads(recv_exact(sock, n))


def recv_final(sock, cb=None):
    """Lee mensajes hasta el resultado; los `progress` van al callback."""
    while True:
        msg = recv_msg(sock)
        if "progress" in msg:
            if cb:
                cb(msg["progress"], msg.get("total", 0))
            continue
        if not msg.get("ok"):
            raise ZtError(msg.get("error", "error remoto"))
        return msg


def _mac(token, *parts):
    return hmac.new(token.encode(), b"".join(parts), hashlib.sha256).hexdigest()


def auth_server(sock, token):
    nonce = secrets.token_bytes(16)
    send_msg(sock, {"challenge": nonce.hex()})
    msg = recv_msg(sock)
    cnonce = bytes.fromhex(msg.get("cnonce", ""))
    if not hmac.compare_digest(msg.get("mac", ""), _mac(token, b"c", nonce, cnonce)):
        send_msg(sock, {"ok": False, "error": "token invalido"})
        return False
    send_msg(sock, {"ok": True, "mac": _mac(token, b"s", nonce, cnonce)})
    return True


def auth_client(sock, token):
    nonce = bytes.fromhex(recv_msg(sock)["challenge"])
    cnonce = secrets.token_bytes(16)
    send_msg(sock, {"cnonce": cnonce.hex(), "mac": _mac(token, b"c", nonce, cnonce)})
    msg = recv_msg(sock)
    if not msg.get("ok"):
        raise ZtError(msg.get("error", "autenticacion rechazada"))
    if not hmac.compare_digest(msg["mac"], _mac(token, b"s", nonce, cnonce)):
        raise ZtError("el servidor no conoce el token (nodo falso?)")


def send_file(sock, path, size, cb=None):
    h = hashlib.sha256()
    sent = 0
    with open(path, "rb") as f:
        while sent < size:
            chunk = f.read(min(CHUNK, size - sent))
            if not chunk:
                raise ZtError("el archivo cambio durante la transferencia")
            h.update(chunk)
            sock.sendall(chunk)
            sent += len(chunk)
            if cb:
                cb(sent, size)
    sock.sendall(h.digest())


def recv_file(sock, f, size, cb=None):
    h = hashlib.sha256()
    got = 0
    while got < size:
        chunk = sock.recv(min(CHUNK, size - got))
        if not chunk:
            raise ConnectionError("conexion cerrada a mitad de archivo")
        h.update(chunk)
        f.write(chunk)
        got += len(chunk)
        if cb:
            cb(got, size)
    return hmac.compare_digest(recv_exact(sock, 32), h.digest())


# ------------------------------------------------------------------ cliente

def connect(host, port, token):
    sock = socket.create_connection((host, port), timeout=TIMEOUT)
    try:
        auth_client(sock, token)
    except Exception:
        sock.close()
        raise
    return sock


def dest_path(dest, name):
    """Si dest es un directorio (o termina en separador) le agrega el nombre."""
    if dest.endswith(("/", "\\")) or os.path.isdir(dest):
        return os.path.join(dest, name)
    return dest


def is_inside(root, full):
    try:
        return os.path.commonpath([os.path.normcase(root), os.path.normcase(full)]) \
            == os.path.normcase(root)
    except ValueError:  # otra unidad en Windows
        return False


def manifest(path):
    """Describe un archivo o directorio a transferir (rutas relativas con /)."""
    if os.path.isfile(path):
        return {"name": os.path.basename(path), "isdir": False, "dirs": [],
                "files": [["", os.path.getsize(path)]]}
    if not os.path.isdir(path):
        raise ZtError("no existe: " + path)
    dirs, files = [], []
    for cur, subdirs, names in os.walk(path):
        subdirs.sort()
        rel = os.path.relpath(cur, path).replace(os.sep, "/")
        prefix = "" if rel == "." else rel + "/"
        dirs += [prefix + d for d in subdirs]
        files += [[prefix + n, os.path.getsize(os.path.join(cur, n))]
                  for n in sorted(names)
                  if not n.endswith(PART) and os.path.isfile(os.path.join(cur, n))]
    return {"name": os.path.basename(os.path.abspath(path)) or "raiz",
            "isdir": True, "dirs": dirs, "files": files}


def tree_total(man):
    return sum(size for _, size in man["files"])


def tree_path(base, rel, root=None):
    """base + rel (con /); no puede escapar de base ni, con root, de root."""
    if not rel:
        target = base
    else:
        base_abs = os.path.abspath(base)
        target = os.path.abspath(os.path.join(base_abs, *rel.split("/")))
        if target == base_abs or not is_inside(base_abs, target):
            raise ZtError("ruta invalida en la transferencia: " + rel)
    return resolve(root, target) if root else target


def _tree_cb(cb, done, total):
    return (lambda n, _t: cb(done + n, total)) if cb else None


def send_tree(sock, base, man, cb=None, root=None):
    total, done = tree_total(man), 0
    for rel, size in man["files"]:
        send_file(sock, tree_path(base, rel, root), size, _tree_cb(cb, done, total))
        done += size


def recv_tree(sock, base, man, cb=None, root=None):
    total, done = tree_total(man), 0
    os.makedirs(base if man["isdir"] else os.path.dirname(base), exist_ok=True)
    for d in man["dirs"]:
        os.makedirs(tree_path(base, d, root), exist_ok=True)
    for rel, size in man["files"]:
        target = tree_path(base, rel, root)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        tmp = target + PART
        try:
            with open(tmp, "wb") as f:
                ok = recv_file(sock, f, size, _tree_cb(cb, done, total))
            if not ok:
                raise ZtError("checksum no coincide en " + (rel or target))
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        done += size


def client_put(host, port, token, local, remote, cb=None, root=None):
    man = manifest(local)
    with connect(host, port, token) as s:
        send_msg(s, dict(man, op="put", path=remote))
        recv_final(s)
        send_tree(s, local, man, cb, root)
        return recv_final(s)


def client_get(host, port, token, remote, local, cb=None):
    with connect(host, port, token) as s:
        send_msg(s, {"op": "get", "path": remote})
        man = recv_final(s)
        dest = dest_path(local, man["name"])
        recv_tree(s, dest, man, cb)
        return {"path": dest, "size": tree_total(man), "files": len(man["files"])}


def client_push(host, port, token, remote, dst_host, dst_port, dst_path, cb=None):
    """Pide al nodo `host` que envie su archivo directo a `dst_host`."""
    with connect(host, port, token) as s:
        send_msg(s, {"op": "push", "path": remote, "host": dst_host,
                     "port": dst_port, "dest": dst_path})
        return recv_final(s, cb)


def client_ls(host, port, token, remote):
    with connect(host, port, token) as s:
        send_msg(s, {"op": "ls", "path": remote})
        return recv_final(s)


# ----------------------------------------------------------------- servidor

def resolve(root, p):
    """Resuelve p dentro de root; rechaza cualquier escape (.., symlinks)."""
    full = p if os.path.isabs(p) else os.path.join(root, p)
    full = os.path.realpath(full)
    if not is_inside(root, full):
        raise ZtError("ruta fuera de la raiz del nodo: " + p)
    return full


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(TIMEOUT)
        who = self.client_address[0]
        try:
            if not auth_server(s, self.server.token):
                log(f"{who}: token invalido")
                return
            req = recv_msg(s)
            op = req.get("op")
            fn = getattr(self, "op_" + str(op), None)
            if fn is None:
                raise ZtError(f"operacion desconocida: {op}")
            fn(s, req, who)
        except ZtError as e:
            log(f"{who}: error: {e}")
            try:
                send_msg(s, {"ok": False, "error": str(e)})
            except OSError:
                pass
        except (OSError, ValueError) as e:
            log(f"{who}: {type(e).__name__}: {e}")
            try:
                send_msg(s, {"ok": False, "error": f"{type(e).__name__}: {e}"})
            except OSError:
                pass

    def op_ls(self, s, req, who):
        full = resolve(self.server.root, req.get("path") or ".")
        if not os.path.isdir(full):
            raise ZtError("no es un directorio: " + req.get("path", ""))
        entries = []
        for e in sorted(os.scandir(full), key=lambda e: (not e.is_dir(), e.name.lower())):
            try:
                entries.append({"name": e.name, "dir": e.is_dir(),
                                "size": 0 if e.is_dir() else e.stat().st_size})
            except OSError:
                pass
        send_msg(s, {"ok": True, "path": full, "entries": entries})

    def op_get(self, s, req, who):
        root = self.server.root
        full = resolve(root, req["path"] or ".")
        man = manifest(full)
        send_msg(s, dict(man, ok=True))
        log(f"{who}: GET {full} ({len(man['files'])} archivos, {tree_total(man)} bytes)")
        send_tree(s, full, man, root=root)

    def op_put(self, s, req, who):
        root = self.server.root
        path = req["path"]
        base = resolve(root, dest_path(
            path if os.path.isabs(path) else os.path.join(root, path), req["name"]))
        send_msg(s, {"ok": True})
        recv_tree(s, base, req, root=root)
        size, n = tree_total(req), len(req["files"])
        log(f"{who}: PUT {base} ({n} archivos, {size} bytes)")
        send_msg(s, {"ok": True, "path": base, "size": size, "files": n})

    def op_push(self, s, req, who):
        root = self.server.root
        full = resolve(root, req["path"] or ".")
        last = [0.0]

        def forward(done, total):
            now = time.monotonic()
            if now - last[0] > 0.25 or done == total:
                last[0] = now
                send_msg(s, {"progress": done, "total": total})

        log(f"{who}: PUSH {full} -> {req['host']}:{req['dest']}")
        r = client_put(req["host"], req["port"], self.server.token,
                       full, req["dest"], forward, root=root)
        send_msg(s, r)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, file=sys.stderr, flush=True)


def zerotier_ips():
    exe = shutil.which("zerotier-cli")
    if not exe:
        raise ZtError("no encuentro zerotier-cli; usa --bind IP")
    try:
        out = subprocess.run([exe, "-j", "listnetworks"], capture_output=True,
                             text=True, timeout=10, check=True).stdout
        nets = json.loads(out)
    except (subprocess.SubprocessError, ValueError) as e:
        raise ZtError(f"zerotier-cli fallo ({e}); usa --bind IP")
    ips = [a.split("/")[0] for n in nets if n.get("status") == "OK"
           for a in n.get("assignedAddresses", []) if ":" not in a]
    if not ips:
        raise ZtError("no hay redes ZeroTier activas con IPv4; usa --bind IP")
    return ips


def cmd_serve(args, cfg):
    root = os.path.realpath(os.path.expanduser(args.root or cfg.get("root") or "~"))
    if not os.path.isdir(root):
        raise ZtError("la raiz no existe: " + root)
    cfg_bind = cfg.get("bind")
    binds = args.bind or ([cfg_bind] if isinstance(cfg_bind, str) else cfg_bind) or zerotier_ips()
    servers = []
    for ip in binds:
        srv = Server((ip, args.port), Handler)
        srv.token, srv.root = cfg["token"], root
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        log(f"escuchando en {ip}:{args.port}  raiz={root}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


# ------------------------------------------------------------------- config

def config_path():
    return os.environ.get("ZTFTP_CONFIG") or os.path.join(os.path.expanduser("~"), ".ztftp.json")


def load_config():
    path = config_path()
    try:
        with open(path) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        raise ZtError(f"no hay config en {path}; corre `ztftp init` (o copia la de otro nodo)")
    if not cfg.get("token"):
        raise ZtError(f"falta 'token' en {path}")
    cfg.setdefault("port", DEFAULT_PORT)
    cfg.setdefault("nodes", {})
    return cfg


def cmd_init(args, cfg):
    """Crea la config, o actualiza la existente con las opciones dadas."""
    path = config_path()
    created = not os.path.exists(path)
    cfg = {}
    if not created:
        with open(path) as f:
            cfg = json.load(f)
    if args.token:
        cfg["token"] = args.token
    cfg.setdefault("token", secrets.token_hex(16))
    cfg.setdefault("port", DEFAULT_PORT)
    nodes = cfg.setdefault("nodes", {})
    if args.port:
        cfg["port"] = args.port
    if args.root:
        cfg["root"] = args.root
    if args.bind:
        cfg["bind"] = args.bind
    for item in args.node or []:
        name, _, ip = item.partition("=")
        if not name or not ip:
            raise ZtError(f"--node espera NOMBRE=IP, recibi: {item}")
        nodes[name] = ip
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"{'creado' if created else 'actualizado'} {path}")
    if created and not args.token:
        print("Copia ESE archivo a los demas nodos (mismo token), o usa `init --token ...` en cada uno.")


# ---------------------------------------------------------------------- cli

def parse_loc(s, cfg):
    """-> (host|None, path). host None = local."""
    if re.match(r"^[A-Za-z]:[\\/]", s) or ":" not in s:
        return None, s
    host, path = s.split(":", 1)
    return cfg["nodes"].get(host, host), path


def fmt_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


class Progress:
    def __init__(self):
        self.t0 = time.monotonic()
        self.last = 0.0
        self.shown = False

    def __call__(self, done, total):
        now = time.monotonic()
        if now - self.last < 0.2 and done != total:
            return
        self.last = now
        rate = done / max(now - self.t0, 1e-6)
        pct = f"{done * 100 // total:3d}%" if total else "  ?%"
        print(f"\r{pct} {fmt_size(done)}/{fmt_size(total)}  {fmt_size(rate)}/s   ",
              end="", file=sys.stderr, flush=True)
        self.shown = True

    def end(self):
        if self.shown:
            print(file=sys.stderr)


def cmd_cp(args, cfg):
    port = args.port or cfg["port"]
    token = cfg["token"]
    (shost, spath), (dhost, dpath) = parse_loc(args.origen, cfg), parse_loc(args.destino, cfg)
    prog = Progress()
    t0 = time.monotonic()
    try:
        if shost is None and dhost is None:
            raise ZtError("origen y destino son locales; usa cp")
        elif dhost is None:
            r = client_get(shost, port, token, spath, dpath, prog)
        elif shost is None:
            r = client_put(dhost, port, token, spath, dpath, prog)
        else:
            r = client_push(shost, port, token, spath, dhost, port, dpath, prog)
    finally:
        prog.end()
    dt = max(time.monotonic() - t0, 1e-6)
    n = r.get("files", 1)
    extra = f", {n} archivos" if n != 1 else ""
    print(f"ok: {r['path']} ({fmt_size(r['size'])}{extra} en {dt:.1f}s)")


def cmd_ls(args, cfg):
    host, path = parse_loc(args.destino, cfg)
    if host is None:
        raise ZtError("usa nodo:ruta (ej. pc1:.)")
    r = client_ls(host, args.port or cfg["port"], cfg["token"], path)
    print(r["path"])
    for e in r["entries"]:
        print(f"  {'<dir>' if e['dir'] else fmt_size(e['size']):>9}  {e['name']}{'/' if e['dir'] else ''}")


def cmd_complete(args, cfg):
    """Candidatos de autocompletado para la palabra dada (uso interno)."""
    global TIMEOUT
    TIMEOUT = 2
    word = args.word
    try:
        if ":" not in word or re.match(r"^[A-Za-z]:[\\/]", word):
            for name in sorted(cfg["nodes"]):
                if name.lower().startswith(word.lower()):
                    print(name + ":")
            return
        alias, path = word.split(":", 1)
        cut = max(path.rfind("/"), path.rfind("\\")) + 1
        dirpart, prefix = path[:cut], path[cut:]
        r = client_ls(cfg["nodes"].get(alias, alias), cfg["port"], cfg["token"], dirpart or ".")
    except (ZtError, OSError):
        return
    for e in r["entries"]:
        if e["name"].lower().startswith(prefix.lower()):
            print(f"{alias}:{dirpart}{e['name']}{'/' if e['dir'] else ''}")


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(prog="ztftp", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="crea o actualiza ~/.ztftp.json (token nuevo si no existe)")
    p.add_argument("--token", help="usar este token compartido en vez de generar uno")
    p.add_argument("--node", action="append", metavar="NOMBRE=IP", help="agrega un alias de nodo")
    p.add_argument("--root", help="directorio raiz que expone el demonio")
    p.add_argument("--bind", action="append", metavar="IP", help="IP de ZeroTier donde escucha el demonio")
    p.add_argument("--port", type=int)
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("serve", help="demonio del nodo")
    p.add_argument("--root", help="directorio raiz expuesto (default: 'root' de la config, o el home)")
    p.add_argument("--bind", action="append", help="IP donde escuchar (default: IPs de ZeroTier)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.set_defaults(fn=cmd_serve)
    p = sub.add_parser("cp", help="copia ORIGEN a DESTINO (ruta o nodo:ruta)")
    p.add_argument("origen")
    p.add_argument("destino")
    p.add_argument("--port", type=int)
    p.set_defaults(fn=cmd_cp)
    p = sub.add_parser("ls", help="lista un directorio remoto: nodo:ruta")
    p.add_argument("destino")
    p.add_argument("--port", type=int)
    p.set_defaults(fn=cmd_ls)
    p = sub.add_parser("_complete", help=argparse.SUPPRESS)
    p.add_argument("word", nargs="?", default="")
    p.set_defaults(fn=cmd_complete)
    args = ap.parse_args()
    try:
        cfg = None if args.cmd == "init" else load_config()
        if args.cmd == "serve" and args.port == DEFAULT_PORT:
            args.port = cfg["port"]
        args.fn(args, cfg)
    except (ZtError, OSError) as e:
        sys.exit(f"ztftp: {e}")


if __name__ == "__main__":
    main()
