
#!/usr/bin/env python3
"""
hardening.py - Auditoria y hardening CIS (Cisco IOS) para R1-2241 y SW1-2241

Uso:
    python hardening.py --audit    # genera informe SIN aplicar ninguna regla
    python hardening.py --apply    # aplica las reglas y genera informe postumo
"""
import argparse
import os
import re
from datetime import datetime

from conexion import conectar

EQUIPOS = [
    {"nombre": "R1-2241", "ip": "10.22.41.1", "tipo": "router"},
    {"nombre": "SW1-2241", "ip": "10.22.41.2", "tipo": "switch"},
]

ENABLE_SECRET = "Enable2241!"
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


# ---------- Reglas: check() devuelve la lista de pendientes ([] = cumple) ----------

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


REGLAS = [
    {"id": "R01", "titulo": "Contrasena enable con hash (enable secret)", "aplica": "ambos",
     "check": chk_enable_secret,
     "fix": lambda p: [f"enable secret {ENABLE_SECRET}"]},
    {"id": "R02", "titulo": "Cifrado de contrasenas (service password-encryption)", "aplica": "ambos",
     "check": chk_pwd_encryption,
     "fix": lambda p: ["service password-encryption"]},
    {"id": "R03", "titulo": "Solo SSH en lineas vty (transport input ssh)", "aplica": "ambos",
     "check": chk_vty_ssh,
     "fix": lambda p: [c for h in p for c in (h, "transport input ssh")]},
    {"id": "R04", "titulo": "Exec-timeout de 5 min en consola y vty", "aplica": "ambos",
     "check": chk_exec_timeout,
     "fix": lambda p: [c for h in p for c in (h, "exec-timeout 5 0")]},
    {"id": "R05", "titulo": "Banner de aviso legal", "aplica": "ambos",
     "check": chk_banner,
     "fix": lambda p: [f"banner login # {BANNER} #"]},
    {"id": "R06", "titulo": "Servidor HTTP/HTTPS deshabilitado", "aplica": "ambos",
     "check": chk_http,
     "fix": lambda p: list(p)},
    {"id": "R07", "titulo": "Servicio PAD deshabilitado (no service pad)", "aplica": "ambos",
     "check": chk_no_pad,
     "fix": lambda p: ["no service pad"]},
    {"id": "R08", "titulo": "Timestamps en logs y debug (datetime msec)", "aplica": "ambos",
     "check": chk_timestamps,
     "fix": lambda p: list(p)},
    {"id": "R09", "titulo": "Source routing deshabilitado (no ip source-route)", "aplica": "router",
     "check": chk_source_route,
     "fix": lambda p: ["no ip source-route"]},
    {"id": "R10", "titulo": "Proxy ARP deshabilitado en interfaces", "aplica": "router",
     "check": chk_proxy_arp,
     "fix": lambda p: [c for h in p for c in (h, "no ip proxy-arp")]},
]


def auditar(conn, tipo):
    run = conn.send_command("show running-config", read_timeout=60)
    resultados = []
    for r in REGLAS:
        if r["aplica"] not in ("ambos", tipo):
            continue
        pend = r["check"](run)
        resultados.append({"regla": r, "ok": not pend, "pend": pend})
    return resultados, run


def aplicar(conn, resultados):
    cmds = []
    for x in resultados:
        if not x["ok"]:
            cmds += x["regla"]["fix"](x["pend"])
    if cmds:
        conn.send_config_set(cmds)
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
    p = argparse.ArgumentParser(description="Auditoria y hardening CIS (Cisco IOS)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--audit", action="store_true", help="Solo informe, no aplica reglas")
    g.add_argument("--apply", action="store_true", help="Aplica reglas y genera informe postumo")
    args = p.parse_args()
    modo = "apply" if args.apply else "audit"

    os.makedirs("informes", exist_ok=True)
    os.makedirs("running-configs", exist_ok=True)
    ahora = datetime.now()
    sello = ahora.strftime("%Y%m%d_%H%M%S")

    L = []
    L.append("=" * 70)
    L.append("INFORME DE HARDENING CIS - CISCO IOS")
    L.append(f"Fecha y hora: {ahora.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"Modo: {'APLICAR REGLAS + INFORME POSTUMO' if modo == 'apply' else 'AUDITORIA (no se aplica ninguna regla)'}")
    L.append("=" * 70)

    for eq in EQUIPOS:
        L.append("")
        L.append(f"Equipo: {eq['nombre']} ({eq['ip']}) - tipo: {eq['tipo']}")
        L.append("-" * 70)
        try:
            conn = conectar(eq["ip"])
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
            cmds = aplicar(conn, antes)
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
