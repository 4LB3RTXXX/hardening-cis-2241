
import paramiko
from netmiko import ConnectHandler


def habilitar(preferidos, info, algoritmos):
    actuales = list(getattr(paramiko.Transport, preferidos, ()))
    disponibles = getattr(paramiko.Transport, info, {})
    for alg in algoritmos:
        if alg in disponibles and alg not in actuales:
            actuales.append(alg)
    setattr(paramiko.Transport, preferidos, tuple(actuales))


# El IOS de GNS3 solo ofrece algoritmos SHA-1 antiguos
habilitar("_preferred_kex", "_kex_info", [
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
])
habilitar("_preferred_keys", "_key_info", ["ssh-rsa"])
habilitar("_preferred_ciphers", "_cipher_info", ["aes128-cbc", "aes256-cbc"])

USUARIO = "admin-local"
PASSWORD = "<contrasena-del-laboratorio>"
FW_USUARIO = "admin"
FW_PASSWORD = "<contrasena-firewall>"


def conectar(ip, tipo="router"):
    if tipo == "firewall":
        return ConnectHandler(
            device_type="fortinet",
            host=ip,
            username=FW_USUARIO,
            password=FW_PASSWORD,
            conn_timeout=30,
        )
    conn = ConnectHandler(
        device_type="cisco_ios",
        host=ip,
        username=USUARIO,
        password=PASSWORD,
        secret=PASSWORD,
    )
    conn.enable()
    return conn
