# 🛡️ Hardening CIS de Router, Switch y Firewall con Script de Auditoría Automatizado

**Albert Euclides Garcia — Matrícula 2025-2241 (`20252241`)**

![Cisco](https://img.shields.io/badge/Cisco-IOS%20%2F%20IOSvL2-1BA0D7?style=for-the-badge&logo=cisco&logoColor=white) ![Fortinet](https://img.shields.io/badge/Fortinet-FortiGate%207.0.9-EE3124?style=for-the-badge&logo=fortinet&logoColor=white) ![CIS](https://img.shields.io/badge/CIS-Benchmark-0B5394?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-Netmiko-3776AB?style=for-the-badge&logo=python&logoColor=white) ![GNS3](https://img.shields.io/badge/Emulador-GNS3-009639?style=for-the-badge)

> Un router Cisco, un switch Cisco y un firewall FortiGate se **endurecen** (hardening) siguiendo recomendaciones del **CIS Benchmark**. Un servidor Ubuntu ejecuta un **script en Python** que audita los tres equipos, genera un informe sin tocar nada (`--audit`) o aplica las reglas y genera un informe póstumo (`--apply`).

---

## 📺 Video de Demostración

> [**Ver demostración en YouTube →**](ENLACE-DE-YOUTUBE-PENDIENTE)

---

## 📑 Tabla de Contenido

1. [Propósito del Laboratorio](#-propósito-del-laboratorio)
2. [Cumplimiento de Requisitos](#-cumplimiento-de-requisitos)
3. [Direccionamiento IP basado en la matrícula](#-direccionamiento-ip-basado-en-la-matrícula)
4. [Parámetros Usados](#-parámetros-usados)
5. [Documentación de la Red](#-documentación-de-la-red)
6. [Recomendaciones CIS Aplicadas](#-recomendaciones-cis-aplicadas)
7. [Funcionamiento del Script](#-funcionamiento-del-script)
8. [Validación de la Implementación](#-validación-de-la-implementación)
9. [Scripts](#-scripts)
10. [Estructura del Repositorio](#-estructura-del-repositorio)

---

## 🎯 Propósito del Laboratorio

Demostrar cómo **reducir la superficie de ataque** de los equipos de una red (router, switch y firewall) aplicando recomendaciones del **CIS Benchmark**, y cómo **automatizar** su verificación:

- Se parte de un router, un switch y un firewall con configuración básica y **algunas opciones inseguras abiertas a propósito** (por ejemplo, Telnet y HTTP de administración en el firewall).
- Un **script de auditoría** revisa en cada equipo un conjunto de recomendaciones y marca cada una como `CUMPLE` o `NO CUMPLE`.
- El mismo script puede **aplicar** las reglas que no se cumplen y generar un **informe póstumo** que compara el estado antes y después.
- Las reglas aplicadas se **prueban** con comprobaciones reales: puertos bloqueados, banner visible, tiempos de inactividad, política de contraseñas y diferencias entre las configuraciones antes y después.

---

## ✅ Cumplimiento de Requisitos

| Requisito                                                      | Implementado con                                                                                                           |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Repositorio de GitHub con documentación profesional            | Este repositorio                                                                                                           |
| Video demostrativo al principio del repositorio                | Sección [Video de Demostración](#-video-de-demostración)                                                                   |
| Documentación con imágenes y diagramas                         | Carpeta `image/` y diagramas Mermaid en [Documentación de la Red](#-documentación-de-la-red)                               |
| Propósito del laboratorio                                      | Sección [Propósito del Laboratorio](#-propósito-del-laboratorio)                                                           |
| Todos los scripts utilizados                                   | Carpeta [`scripts/`](scripts)                                                                                              |
| Running-configs                                                | Carpeta [`running-configs/`](running-configs), con la configuración de antes y después de cada equipo                      |
| Red con router, switch y firewall                              | `R1-2241` (router Cisco 7200), `SW1-2241` (switch Cisco IOSvL2) y `FGT-CIS-LAB` (firewall FortiGate 7.0.9)                 |
| Herramienta de análisis basada en el CIS Benchmark             | Script `hardening.py` en modo `--audit`: 10 reglas en el router, 8 en el switch y 6 en el firewall                         |
| Aplicar recomendaciones para hacer hardening                   | Script `hardening.py` en modo `--apply`                                                                                    |
| Documentar las recomendaciones aplicadas y por qué             | Sección [Recomendaciones CIS Aplicadas](#-recomendaciones-cis-aplicadas)                                                   |
| Probar las recomendaciones aplicadas                           | Sección [Validación de la Implementación](#-validación-de-la-implementación)                                               |
| Script que escanea los equipos buscando las reglas elegidas    | `hardening.py`                                                                                                             |
| Posibilidad de crear informe sin aplicar reglas                | `python scripts/hardening.py --audit`                                                                                      |
| Posibilidad de aplicar reglas y generar informe póstumo        | `python scripts/hardening.py --apply`                                                                                      |
| Entregables: repositorio, video en YouTube y archivo TXT       | Enlaces en el archivo TXT de entrega                                                                                       |

---

## 🧮 Direccionamiento IP basado en la matrícula

Mi matrícula es **2025-2241** (`20252241`). Tomé sus últimos cuatro dígitos, `2241`, separados en dos pares, **`22`** y **`41`**:

| Dígitos de la matrícula | Dónde se usan                     | Ejemplo        |
| ----------------------- | --------------------------------- | -------------- |
| `22` → segundo octeto   | Red privada de la infraestructura | 10.**22**.41.0 |
| `41` → tercer octeto    | Red privada de la infraestructura | 10.22.**41**.0 |

Una sola red LAN compartida por todos los equipos:

| Segmento | Prefijo | Máscara       | Hosts útiles | Red        | Rango utilizable          | Broadcast    |
| -------- | ------- | ------------- | ------------ | ---------- | ------------------------- | ------------ |
| LAN      | /24     | 255.255.255.0 | 254          | 10.22.41.0 | 10.22.41.1 – 10.22.41.254 | 10.22.41.255 |

| Dispositivo                           | Interfaz                      | IP                       | Asignación                                          |
| ------------------------------------- | ----------------------------- | ------------------------ | --------------------------------------------------- |
| R1-2241 (router)                      | FastEthernet0/0               | 10.22.41.1/24            | Estática                                            |
| SW1-2241 (switch)                     | VLAN 1 (SVI)                  | 10.22.41.2/24            | Estática                                            |
| FGT-CIS-LAB (firewall)                | port1                         | 10.22.41.3/24            | Estática                                            |
| Ubuntu auditor (`zabbix-2241`)        | ens3                          | 10.22.41.50/24           | DHCP, entregada por el router                       |
| PC de administración (Windows)        | VMware Network Adapter VMnet1 | 10.22.41.210/24          | Estática, usada para conectarse por SSH al Ubuntu   |

---

## 🧩 Parámetros Usados

| Parámetro                       | Valor                                                                                                              |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Router                          | Cisco 7200, IOS 15.2(4)S6 (`R1-2241`)                                                                              |
| Switch                          | Cisco IOSvL2, IOS 15.2 (`SW1-2241`)                                                                                |
| Firewall                        | FortiGate VM, FortiOS 7.0.9 (`FGT-CIS-LAB`)                                                                        |
| Equipo auditor                  | Ubuntu Server 26.04 como nodo QEMU de GNS3 (`zabbix-2241`), reutilizado de una práctica anterior                   |
| Lenguaje y librerías            | Python 3.14, Netmiko 4.8.0, Paramiko 3.5.1                                                                         |
| Emulador                        | GNS3 con GNS3 VM sobre VMware Workstation                                                                          |
| Enlace con la PC de admin       | Nodo `Cloud` con la interfaz `eth0` de la GNS3 VM ↔ `VMware Network Adapter VMnet1` en Windows                     |
| Acceso de administración        | Cisco: usuario local con privilegio 15 y SSH versión 2. FortiGate: usuario `admin` por SSH                         |
| Benchmark de referencia         | CIS Benchmark para Cisco IOS y CIS Benchmark para FortiGate                                                        |
| Informes generados              | Carpeta `informes/`, con fecha y hora en el nombre y dentro del informe                                            |

> Las contraseñas del laboratorio no se publican en este repositorio y aparecen como `<contrasena-del-laboratorio>`, `<contrasena-enable>`, `<contrasena-firewall>` o `<hash>`.

---

## 📡 Documentación de la Red

### Topología

![Topología](image/01-topologia-gns3.png)

### Conexiones físicas

| Origen                              | Destino                                                     |
| ----------------------------------- | ----------------------------------------------------------- |
| `R1-2241` FastEthernet0/0           | `SW1-2241` GigabitEthernet0/0                               |
| `SW1-2241` GigabitEthernet0/1       | Ubuntu auditor e0 (`ens3`)                                  |
| `SW1-2241` GigabitEthernet0/2       | `FGT-CIS-LAB` port1                                         |
| `SW1-2241` GigabitEthernet1/3       | `Cloud` eth0 (acceso desde la PC de administración)         |

Conectividad del Ubuntu auditor con los equipos:

![Red del Ubuntu](image/02-ubuntu-red.png)

### Diagrama lógico

```mermaid
flowchart LR
    AUD["Ubuntu auditor (zabbix-2241)<br/>ens3: 10.22.41.50/24<br/>Python + Netmiko<br/>hardening.py"] -- "e0 ↔ Gi0/1" --- SW1["SW1-2241<br/>Switch Cisco IOSvL2<br/>VLAN 1: 10.22.41.2/24"]
    SW1 -- "Gi0/0 ↔ Fa0/0" --- R1["R1-2241<br/>Router Cisco 7200<br/>Fa0/0: 10.22.41.1/24"]
    SW1 -- "Gi0/2 ↔ port1" --- FW["FGT-CIS-LAB<br/>FortiGate 7.0.9<br/>port1: 10.22.41.3/24"]
    SW1 -- "Gi1/3 ↔ eth0" --- CLD["Cloud<br/>GNS3 VM eth0 (Solo host)"]
    CLD --- PC["PC de administración<br/>VMnet1: 10.22.41.210/24<br/>PowerShell: SSH al auditor"]
```

### Diagrama del flujo del script

```mermaid
flowchart TD
    A["Inicio: python scripts/hardening.py"] --> B{"¿Modo?"}
    B -- "--audit" --> C["Conectar por SSH a los equipos (R1, SW1, FGT)"]
    C --> D["Leer la configuración y evaluar cada regla"]
    D --> E["Generar informe: CUMPLE / NO CUMPLE"]
    E --> Z["Guardar informe y configuración"]
    B -- "--apply" --> F["Conectar por SSH a los equipos"]
    F --> G["Auditar estado inicial y guardar configuración antes"]
    G --> H["Aplicar comandos de las reglas que no cumplen"]
    H --> I["Guardar: write memory en Cisco, automático en FortiOS"]
    I --> J["Auditar de nuevo: informe póstumo"]
    J --> Z
```

### Diagrama de interacción durante `--apply`

```mermaid
sequenceDiagram
    participant U as Administrador
    participant S as hardening.py (Ubuntu)
    participant E as R1-2241 / SW1-2241 / FGT-CIS-LAB
    U->>S: python scripts/hardening.py --apply
    S->>E: SSH (Netmiko: cisco_ios o fortinet)
    S->>E: Leer la configuración
    E-->>S: Configuración inicial
    S->>S: Evalúa las reglas (estado inicial)
    S->>E: Comandos de configuración de las reglas pendientes
    S->>E: Guardar configuración
    S->>E: Leer la configuración
    E-->>S: Configuración final
    S->>S: Evalúa las reglas de nuevo (informe póstumo)
    S-->>U: Informe en pantalla y en informes/
```

---

## 🔒 Recomendaciones CIS Aplicadas

### Router y switch Cisco (R01 a R10)

Las dos últimas (R09 y R10) solo aplican al router, porque son funciones de capa 3.

| ID  | Recomendación                                   | Comando que se aplica                                 | Equipos      | Por qué se aplicó                                                                                                         |
| --- | ----------------------------------------------- | ----------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------- |
| R01 | Contraseña de modo privilegiado con hash        | `enable secret <contrasena-enable>`                   | Router y SW  | Protege el modo privilegiado con un hash, no con una contraseña legible en la configuración.                              |
| R02 | Cifrado de contraseñas en la configuración      | `service password-encryption`                         | Router y SW  | Evita que las contraseñas de las líneas queden en texto claro al ver o respaldar la configuración.                        |
| R03 | Solo SSH en las líneas vty                      | `transport input ssh`                                 | Router y SW  | Telnet envía las credenciales en texto plano; SSH las cifra.                                                              |
| R04 | Cierre de sesiones inactivas                    | `exec-timeout 5 0` en `line con 0` y `line vty`       | Router y SW  | Una sesión administrativa abandonada es un acceso abierto; a los 5 minutos de inactividad se cierra.                      |
| R05 | Banner de aviso legal                           | `banner login # <texto> #`                            | Router y SW  | Advierte que el acceso es solo para personal autorizado y que la actividad se registra.                                   |
| R06 | Servidor HTTP/HTTPS deshabilitado               | `no ip http server` y `no ip http secure-server`      | Router y SW  | Un servicio web de administración innecesario es superficie de ataque adicional.                                          |
| R07 | Servicio PAD deshabilitado                      | `no service pad`                                      | Router y SW  | PAD es un servicio heredado que no se usa y no debe estar expuesto.                                                       |
| R08 | Marcas de tiempo en logs y depuración           | `service timestamps log datetime msec` y `debug`      | Router y SW  | Sin hora exacta no se pueden correlacionar eventos durante una investigación.                                             |
| R09 | Enrutamiento por origen deshabilitado           | `no ip source-route`                                  | Router       | Impide que el emisor dicte la ruta del paquete, técnica usada para evadir controles.                                      |
| R10 | Proxy ARP deshabilitado en interfaces con IP    | `no ip proxy-arp`                                     | Router       | Evita que el router responda ARP en nombre de otros hosts, lo que facilita la suplantación y expone la topología.         |

### Firewall FortiGate (F01 a F06)

| ID  | Recomendación                                        | Comando que se aplica                                              | Por qué se aplicó                                                                                                              |
| --- | ---------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| F01 | Cierre de sesión del administrador a los 5 minutos   | `set admintimeout 5`                                               | Una sesión de administración abierta sin uso es un acceso disponible para cualquiera con acceso al equipo.                     |
| F02 | Bloqueo tras 3 intentos fallidos durante 15 minutos  | `set admin-lockout-threshold 3` y `set admin-lockout-duration 900` | Frena los ataques de fuerza bruta contra el inicio de sesión del administrador.                                                |
| F03 | Banner previo al inicio de sesión                    | `set pre-login-banner enable`                                      | Muestra el aviso legal de acceso autorizado antes de pedir credenciales, igual que el banner de los equipos Cisco.             |
| F04 | Política de contraseñas con largo mínimo de 12       | `set status enable` y `set minimum-length 12` en `password-policy` | Obliga a usar contraseñas más largas. En la práctica, el FortiGate pidió cambiar la contraseña de `admin` al siguiente acceso. |
| F05 | Sin HTTP ni Telnet en el acceso de administración    | `set allowaccess ping https ssh` en `port1`                        | HTTP y Telnet envían las credenciales en texto plano; solo se conserva ping, HTTPS y SSH.                                      |
| F06 | Sin TLS 1.0 ni 1.1 en la administración web          | Verificada: `admin-https-ssl-versions` solo con TLS 1.2 y 1.3      | Las versiones antiguas de TLS tienen debilidades conocidas. FortiOS 7.0.9 ya las trae deshabilitadas, y el script lo verifica. |

**Notas:**

- **Tipo de hash en Cisco:** en este IOS (15.2) la regla R01 deja el `enable secret` como tipo 5 (MD5 con sal). Versiones más nuevas permiten tipo 9 (scrypt), que es más fuerte.
- **Algoritmos SSH antiguos en Cisco:** el IOS emulado solo ofrece intercambio de claves con SHA-1, que las versiones nuevas de Paramiko (5.x) ya no incluyen. Por eso el proyecto fija **Paramiko 3.5.1** en [`requirements.txt`](requirements.txt).
- **Reglas del FortiGate que no se pudieron usar:** se evaluó `strong-crypto` y los parámetros `ssh-cbc-cipher`, `ssh-hmac-md5` y `ssh-kex-sha1`, pero el FortiOS 7.0.9 del laboratorio responde `command parse error` al configurarlos. Por eso se reemplazaron por el banner previo al inicio de sesión (F03).
- **Guardado de la configuración:** en Cisco el script ejecuta `write memory`; en FortiOS la configuración se guarda automáticamente al cerrar cada bloque con `end`.

---

## 🔬 Funcionamiento del Script

`scripts/hardening.py` se ejecuta desde el Ubuntu auditor, que tiene conectividad SSH con `R1-2241`, `SW1-2241` y `FGT-CIS-LAB`. Usa Netmiko con el controlador `cisco_ios` para el router y el switch, y `fortinet` para el firewall. En Cisco revisa la `running-config` con expresiones regulares; en el FortiGate lee las secciones `system global`, `system password-policy` y `system interface`.

| Modo      | Qué hace                                                                                                              | Qué genera                                                                                  |
| --------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `--audit` | **No cambia nada.** Evalúa cada regla y marca `CUMPLE` o `NO CUMPLE`.                                                 | Informe en `informes/informe_audit_<fecha>.txt` y copia de la configuración                 |
| `--apply` | Evalúa, aplica solo los comandos de las reglas que no cumplen, guarda y vuelve a evaluar.                             | Informe póstumo en `informes/informe_apply_<fecha>.txt` y las configs `*_antes.cfg` y `*_despues.cfg` |

La opción `--equipos` limita la ejecución a algunos equipos, por ejemplo `--equipos FGT-CIS-LAB`.

Cada informe incluye la **fecha y la hora** de la ejecución, el cumplimiento por equipo y, en el modo `--apply`, la lista exacta de comandos aplicados.

**Resultados obtenidos:**

| Equipo        | Cumplimiento antes | Cumplimiento después |
| ------------- | ------------------ | -------------------- |
| `R1-2241`     | 2/10 (20%)         | 10/10 (100%)         |
| `SW1-2241`    | 2/8 (25%)          | 8/8 (100%)           |
| `FGT-CIS-LAB` | 1/6 (17%)          | 6/6 (100%)           |

---

## ✅ Validación de la Implementación

### Router y switch Cisco

**Prueba 1 — Auditoría inicial (antes):** el router cumple 2 de 10 reglas y el switch 2 de 8, sin aplicar ningún cambio.

![Informe de auditoría antes](image/03-informe-audit-antes.png)

**Prueba 2 — Aplicación de reglas:** estado inicial, comandos aplicados y estado final de cada equipo.

![Informe de aplicación](image/04-informe-apply.png)

**Prueba 3 — Auditoría final (después):** una nueva auditoría confirma el 100% de cumplimiento en el router y el switch.

![Informe de auditoría después](image/05-informe-audit-despues.png)

**Prueba 4 — Puertos cerrados y diferencias de configuración:** Telnet (23) y HTTP (80) rechazan la conexión, y `diff` muestra las líneas que cambiaron entre `*_antes.cfg` y `*_despues.cfg`.

![Pruebas de puertos y diff](image/06-pruebas-puertos-diff.png)

**Prueba 5 — Configuración final del router:**

![Show del router](image/07-show-router.png)

**Prueba 6 — Configuración final del switch:**

![Show del switch](image/08-show-switch.png)

### Firewall FortiGate

**Prueba 7 — Auditoría inicial del FortiGate:** cumple solo 1 de 6 reglas, y los puertos 23 (Telnet) y 80 (HTTP) están abiertos.

![Auditoría inicial del FortiGate](image/09-fw-audit-antes.png)

**Prueba 8 — Aplicación de reglas en el FortiGate:** del 1/6 inicial al 6/6 final, con la lista de comandos aplicados.

![Aplicación en el FortiGate](image/10-fw-apply.png)

**Prueba 9 — Puertos bloqueados en el FortiGate:** Telnet y HTTP ya no responden.

![Puertos bloqueados del FortiGate](image/11-fw-pruebas-puertos.png)

**Prueba 10 — Auditoría final de los tres equipos:** router 10/10, switch 8/8 y firewall 6/6.

![Auditoría final de los tres equipos](image/12-auditoria-final-3-equipos.png)

**Prueba 11 — Configuración final del FortiGate:** tiempo de inactividad, bloqueo por intentos fallidos, banner previo, política de contraseñas y acceso de administración de `port1`.

![Show del FortiGate](image/13-show-firewall.png)

---

## 📜 Scripts

La carpeta [`scripts/`](scripts) contiene todo lo usado en el laboratorio. Las configuraciones de los equipos están en [`running-configs/`](running-configs).

| Script                                                                              | Dónde se ejecuta                                | Qué contiene                                                                    |
| ----------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------- |
| [`01-R1-2241-ssh-base.txt`](scripts/01-R1-2241-ssh-base.txt)                         | Consola de `R1-2241`                            | Usuario local y SSH versión 2, base necesaria para que el script entre          |
| [`02-SW1-2241-ssh-base.txt`](scripts/02-SW1-2241-ssh-base.txt)                       | Consola de `SW1-2241`                           | Usuario local y SSH versión 2 en el switch                                      |
| [`03-ubuntu-auditor-instalacion.txt`](scripts/03-ubuntu-auditor-instalacion.txt)     | Consola del Ubuntu auditor                      | Python, entorno virtual y librerías                                             |
| [`04-ejecucion-y-pruebas.txt`](scripts/04-ejecucion-y-pruebas.txt)                   | Ubuntu auditor, consolas de R1, SW1 y FortiGate | Ejecución del script, pruebas de puertos, `diff` y comandos `show`              |
| [`05-FGT-CIS-LAB-base.txt`](scripts/05-FGT-CIS-LAB-base.txt)                         | Consola de `FGT-CIS-LAB`                        | Configuración base del FortiGate con opciones inseguras abiertas a propósito    |
| [`conexion.py`](scripts/conexion.py)                                                 | Ubuntu auditor (módulo importado)               | Conexión SSH con Netmiko a los equipos Cisco y al FortiGate                     |
| [`hardening.py`](scripts/hardening.py)                                               | Ubuntu auditor                                  | Auditoría y aplicación de las reglas CIS, con informes                          |

**Uso:**

```bash
pip install -r requirements.txt
python scripts/hardening.py --audit                        # informe sin aplicar reglas
python scripts/hardening.py --apply                        # aplica reglas e informe póstumo
python scripts/hardening.py --apply --equipos FGT-CIS-LAB  # solo el firewall
```

> Las contraseñas del laboratorio se reemplazaron por marcadores como `<contrasena-del-laboratorio>`. Para ejecutar el script hay que sustituirlos por los valores reales.

---

## 📁 Estructura del Repositorio

```
README.md
requirements.txt
image/
├── 01-topologia-gns3.png
├── 02-ubuntu-red.png
├── 03-informe-audit-antes.png
├── 04-informe-apply.png
├── 05-informe-audit-despues.png
├── 06-pruebas-puertos-diff.png
├── 07-show-router.png
├── 08-show-switch.png
├── 09-fw-audit-antes.png
├── 10-fw-apply.png
├── 11-fw-pruebas-puertos.png
├── 12-auditoria-final-3-equipos.png
└── 13-show-firewall.png

informes/
└── informes de auditoría y de aplicación, con la fecha y la hora en el nombre

running-configs/
├── R1-2241_antes.cfg
├── R1-2241_despues.cfg
├── SW1-2241_antes.cfg
├── SW1-2241_despues.cfg
├── FGT-CIS-LAB_antes.cfg
└── FGT-CIS-LAB_despues.cfg

scripts/
├── 01-R1-2241-ssh-base.txt
├── 02-SW1-2241-ssh-base.txt
├── 03-ubuntu-auditor-instalacion.txt
├── 04-ejecucion-y-pruebas.txt
├── 05-FGT-CIS-LAB-base.txt
├── conexion.py
└── hardening.py
```
