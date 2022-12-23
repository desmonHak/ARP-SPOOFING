# ARP-SPOOFING:
este es un script que hize en python usando scapy, basicamente suplanta la direcion IP's objetivo por la del atacante dejando a los objetivos sin conexion a internet lo cual es util en lugares como ciber cafes donde ofrezcan conexion gratuita y valla lenta

# Instalacion:
sudo python3 -m pip install scapy

# Para windows habilitar colores ANSI por consola mediante:
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1


# Ejecucion:
sudo python3 exec.py --help

maqueta;         sudo python3 exec.py -r [rango de red] -g [puerta de enlaze]<br >
ejemplo pratico; sudo python3 exec.py -r 192.168.1.1/24 -g 192.168.1.1
