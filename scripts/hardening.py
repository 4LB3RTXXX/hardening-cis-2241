#!/usr/bin/env python3
"""
hardening.py - Auditoria y hardening CIS para R1-2241, SW1-2241 (Cisco IOS)
y FGT-CIS-LAB (FortiGate)

Uso:
    python scripts/hardening.py --audit                    # informe SIN aplicar reglas
    python scripts/hardening.py --apply                    # aplica reglas e informe postumo
    python scripts/hardening.py --audit --equipos R1-2241  # solo algunos equipos
"""
import argparse
import os
import re
from datetime import datetime

from conexion import conectar

EQUIPOS = [
    {"nombre": "R1-2241", "ip": "10.22.41.1", "tipo": "router"},
    {"nombre": "SW1-2241", "ip": "10.22.41.2", "tipo": "switch"},
    {"nombre": "FGT-CIS-LAB", "ip": "10.22.41.3", "tipo": "firewall"},
]

ENABLE_SECRET = "<contrasena-enable>"
BANNER = "Acceso autorizado solamente. Toda actividad es monitoreada y registrada."


def bloques(run):
    """Divide la running-config en bloques (encabezado, [lineas hijas])."""
    res = []
    actual = None
    for linea in run.splitlines():
        if linea.startswith(" "):
            if actual is not None:
                actual[1].append(linea.strip())
        elif linea.strip() and not linea.startswith("!"):
            actual = (linea.strip(), [])
            res.append(actual)
        else:
            actual = None
    return res


# ---------- Reglas Cisco: check() devuelve la lista de pendientes ([] = cumple) ----------

def chk_enable_secret(run):
    return [] if re.search(r"^enable secret [589] ", run, re.M) else ["enable secret"]


def chk_pwd_encryption(run):
    return [] if re.search(r"^service password-encryption", run, re.M) else ["service password-encryption"]


def chk_vty_ssh(run):
    pend = []
    for h, b in bloques(run):
        if h.startswith("line vty") and "transport input ssh" not in b:
            pend.append(h)
    return pend


def chk_exec_timeout(run):
    pend = []
    for h, b in bloques(run):
        if h.startswith("line con") or h.startswith("line vty"):
            ok = False
            for l in b:
                m = re.match(r"exec-timeout (\d+) (\d+)", l)
                if m:
                    seg = int(m.group(1)) * 60 + int(m.group(2))
                    if 0 < seg <= 600:
                        ok = True
            if not ok:
                pend.append(h)
    return pend


def chk_banner(run):
    return [] if re.search(r"^banner (login|motd|exec) ", run, re.M) else ["banner login"]


def chk_http(run):
    pend = []
    if re.search(r"^ip http server", run, re.M):
        pend.append("no ip http server")
    if re.search(r"^ip http secure-server", run, re.M):
        pend.append("no ip http secure-server")
    return pend


def chk_no_pad(run):
    return [] if re.search(r"^no service pad", run, re.M) else ["no service pad"]


def chk_timestamps(run):
    pend = []
    if not re.search(r"^service timestamps log datetime msec", run, re.M):
        pend.append("service timestamps log datetime msec")
    if not re.search(r"^service timestamps debug datetime msec", run, re.M):
        pend.append("service timestamps debug datetime msec")
    return pend


def chk_source_route(run):
    return [] if re.search(r"^no ip source-route", run, re.M) else ["no ip source-route"]


def chk_proxy_arp(run):
    pend = []
    for h, b in bloques(run):
        if h.startswith("interface") and any(l.startswith("ip address") for l in b):
            if "no ip proxy-arp" not in b:
                pend.append(h)
    return pend


# ---------- Reglas FortiGate ----------

def seccion(run, nombre):
    m = re.search(r"### " + re.escape(nombre) + r"\n(.*?)(?=\n### |\Z)", run, re.S)
    return m.group(1) if m else ""


def numero(texto, clave):
    m = re.search(r"^\s*set " + re.escape(clave) + r" (\d+)", texto, re.M)
    return int(m.group(1)) if m else None


def chk_fw_timeout(run):
    v = numero(seccion(run, "system global"), "admintimeout")
    return [] if v is not None and v <= 5 else [f"admintimeout actual: {v}"]


def chk_fw_lockout(run):
    g = seccion(run, "system global")
    umbral = numero(g, "admin-lockout-threshold")
    dur = numero(g, "admin-lockout-duration")
    ok = umbral is not None and umbral <= 3 and dur is not None and dur >= 900
    return [] if ok else [f"umbral={umbral}, duracion={dur}"]


def chk_fw_banner(run):
    g = seccion(run, "get system global")
    return [] if re.search(r"^\s*pre-login-banner\s*:\s*enable", g, re.M) else ["pre-login-banner desactivado"]


def chk_fw_password(run):
    s = seccion(run, "system password-policy")
    activa = re.search(r"^\s*set status enable", s, re.M) is not None
    largo = numero(s, "minimum-length")
    ok = activa and (largo is None or largo >= 8)
    return [] if ok else [f"politica activa={activa}, largo minimo={largo}"]


def chk_fw_acceso(run):
    s = seccion(run, "system interface")
    pend = []
    for nombre, cuerpo in re.findall(r'edit "([^"]+)"(.*?)\n\s*next', s, re.S):
        m = re.search(r"^\s*set allowaccess (.*)$", cuerpo, re.M)
        if not m:
            continue
        tokens = m.group(1).split()
        if "http" in tokens or "telnet" in tokens:
            nuevos = [t for t in tokens if t not in ("http", "telnet")]
            pend.append(f"{nombre} -> allowaccess {' '.join(nuevos)}")
    return pend


def chk_fw_tls(run):
    g = seccion(run, "system global")
    m = re.search(r"^\s*set admin-https-ssl-versions (.*)$", g, re.M)
    if not m:
        return []
    tokens = m.group(1).split()
    viejos = [t for t in tokens if t in ("tlsv1-0", "tlsv1-1")]
    return [f"versiones: {' '.join(tokens)}"] if viejos else []


def fix_fw_acceso(pend):
    cmds = []
    for item in pend:
        nombre, resto = item.split(" -> allowaccess ", 1)
        cmds += ["config system interface", f'edit "{nombre}"',
                 f"set allowaccess {resto}", "next", "end"]
    return cmds


REGLAS = [
    {"id": "R01", "titulo": "Contrasena enable con hash (enable secret)", "aplica": "cisco",
     "check": chk_enable_secret,
     "fix": lambda p: [f"enable secret {ENABLE_SECRET}"]},
    {"id": "R02", "titulo": "Cifrado de contrasenas (service password-encryption)", "aplica": "cisco",
     "check": chk_pwd_encryption,
     "fix": lambda p: ["service password-encryption"]},
    {"id": "R03", "titulo": "Solo SSH en lineas vty (transport input ssh)", "aplica": "cisco",
     "check": chk_vty_ssh,
     "fix": lambda p: [c for h in p for c in (h, "transport input ssh")]},
    {"id": "R04", "titulo": "Exec-timeout de 5 min en consola y vty", "aplica": "cisco",
     "check": chk_exec_timeout,
     "fix": lambda p: [c for h in p for c in (h, "exec-timeout 5 0")]},
    {"id": "R05", "titulo": "Banner de aviso legal", "aplica": "cisco",
     "check": chk_banner,
     "fix": lambda p: [f"banner login # {BANNER} #"]},
    {"id": "R06", "titulo": "Servidor HTTP/HTTPS deshabilitado", "aplica": "cisco",
     "check": chk_http,
     "fix": lambda p: list(p)},
    {"id": "R07", "titulo": "Servicio PAD deshabilitado (no service pad)", "aplica": "cisco",
     "check": chk_no_pad,
     "fix": lambda p: ["no service pad"]},
    {"id": "R08", "titulo": "Timestamps en logs y debug (datetime msec)", "aplica": "cisco",
     "check": chk_timestamps,
     "fix": lambda p: list(p)},
    {"id": "R09", "titulo": "Source routing deshabilitado (no ip source-route)", "aplica": "router",
     "check": chk_source_route,
     "fix": lambda p: ["no ip source-route"]},
    {"id": "R10", "titulo": "Proxy ARP deshabilitado en interfaces", "aplica": "router",
     "check": chk_proxy_arp,
     "fix": lambda p: [c for h in p for c in (h, "no ip proxy-arp")]},
    {"id": "F01", "titulo": "FortiGate: admintimeout de 5 min o menos", "aplica": "firewall",
     "check": chk_fw_timeout,
     "fix": lambda p: ["config system global", "set admintimeout 5", "end"]},
    {"id": "F02", "titulo": "FortiGate: bloqueo tras 3 intentos fallidos (15 min)", "aplica": "firewall",
     "check": chk_fw_lockout,
     "fix": lambda p: ["config system global", "set admin-lockout-threshold 3",
                       "set admin-lockout-duration 900", "end"]},
    {"id": "F03", "titulo": "FortiGate: banner previo al login activado", "aplica": "firewall",
     "check": chk_fw_banner,
     "fix": lambda p: ["config system global", "set pre-login-banner enable", "end"]},
    {"id": "F04", "titulo": "FortiGate: politica de contrasenas activa", "aplica": "firewall",
     "check": chk_fw_password,
     "fix": lambda p: ["config system password-policy", "set status enable",
                       "set minimum-length 12", "end"]},
    {"id": "F05", "titulo": "FortiGate: sin HTTP ni Telnet en administracion", "aplica": "firewall",
     "check": chk_fw_acceso,
     "fix": fix_fw_acceso},
    {"id": "F06", "titulo": "FortiGate: sin TLS 1.0/1.1 en administracion web", "aplica": "firewall",
     "check": chk_fw_tls,
     "fix": lambda p: ["config system global",
                       "set admin-https-ssl-versions tlsv1-2 tlsv1-3", "end"]},
]


def aplica_a(regla, tipo):
    if regla["aplica"] == "cisco":
        return tipo in ("router", "switch")
    return regla["aplica"] == tipo


def leer_config(conn, tipo):
    if tipo == "firewall":
        partes = []
        for sec in ("system global", "system password-policy", "system interface"):
            salida = conn.send_command(f"show full-configuration {sec}", read_timeout=60)
            partes.append(f"### {sec}\n{salida}")
        partes.append("### get system global\n" + conn.send_command("get system global", read_timeout=60))
        partes.append("### show\n" + conn.send_command("show", read_timeout=120))
        return "\n".join(partes)
    return conn.send_command("show running-config", read_timeout=60)


def auditar(conn, tipo):
    run = leer_config(conn, tipo)
    resultados = []
    for r in REGLAS:
        if not aplica_a(r, tipo):
            continue
        pend = r["check"](run)
        resultados.append({"regla": r, "ok": not pend, "pend": pend})
    return resultados, run


def aplicar(conn, resultados, tipo):
    cmds = []
    for x in resultados:
        if not x["ok"]:
            cmds += x["regla"]["fix"](x["pend"])
    if cmds:
        conn.send_config_set(cmds)
        if tipo != "firewall":
            conn.save_config()
    return cmds


def resumen(resultados):
    ok = sum(1 for x in resultados if x["ok"])
    total = len(resultados)
    return f"  Cumplimiento: {ok}/{total} ({round(100 * ok / total)}%)"


def lineas_resultados(resultados):
    L = []
    for x in resultados:
        estado = "CUMPLE   " if x["ok"] else "NO CUMPLE"
        L.append(f"  [{estado}] {x['regla']['id']} {x['regla']['titulo']}")
        if not x["ok"]:
            L.append(f"             pendiente: {', '.join(x['pend'])}")
    L.append(resumen(resultados))
    return L


def guardar(ruta, texto):
    with open(ruta, "w") as f:
        f.write(texto)


def main():
    p = argparse.ArgumentParser(description="Auditoria y hardening CIS (Cisco IOS y FortiGate)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--audit", action="store_true", help="Solo informe, no aplica reglas")
    g.add_argument("--apply", action="store_true", help="Aplica reglas y genera informe postumo")
    p.add_argument("--equipos", nargs="*", help="Nombres de los equipos a procesar (por defecto, todos)")
    args = p.parse_args()
    modo = "apply" if args.apply else "audit"
    equipos = [e for e in EQUIPOS if not args.equipos or e["nombre"] in args.equipos]

    os.makedirs("informes", exist_ok=True)
    os.makedirs("running-configs", exist_ok=True)
    ahora = datetime.now()
    sello = ahora.strftime("%Y%m%d_%H%M%S")

    L = []
    L.append("=" * 70)
    L.append("INFORME DE HARDENING CIS")
    L.append(f"Fecha y hora: {ahora.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"Modo: {'APLICAR REGLAS + INFORME POSTUMO' if modo == 'apply' else 'AUDITORIA (no se aplica ninguna regla)'}")
    L.append("=" * 70)

    for eq in equipos:
        L.append("")
        L.append(f"Equipo: {eq['nombre']} ({eq['ip']}) - tipo: {eq['tipo']}")
        L.append("-" * 70)
        try:
            conn = conectar(eq["ip"], eq["tipo"])
        except Exception as e:
            L.append(f"  ERROR de conexion: {e}")
            continue

        antes, run_antes = auditar(conn, eq["tipo"])
        if modo == "audit":
            guardar(f"running-configs/{eq['nombre']}_audit.cfg", run_antes)
            L.append("RESULTADO DE LA AUDITORIA:")
            L += lineas_resultados(antes)
        else:
            guardar(f"running-configs/{eq['nombre']}_antes.cfg", run_antes)
            L.append("ESTADO INICIAL (antes de aplicar):")
            L += lineas_resultados(antes)
            cmds = aplicar(conn, antes, eq["tipo"])
            L.append("")
            L.append("COMANDOS APLICADOS:")
            L += [f"    {c}" for c in cmds] if cmds else ["    (ninguno, ya cumplia todo)"]
            despues, run_despues = auditar(conn, eq["tipo"])
            guardar(f"running-configs/{eq['nombre']}_despues.cfg", run_despues)
            L.append("")
            L.append("ESTADO FINAL (informe postumo):")
            L += lineas_resultados(despues)
        conn.disconnect()

    texto = "\n".join(L) + "\n"
    print(texto)
    ruta = f"informes/informe_{modo}_{sello}.txt"
    guardar(ruta, texto)
    print(f"Informe guardado en: {ruta}")


if __name__ == "__main__":
    main()
