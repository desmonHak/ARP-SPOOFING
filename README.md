# ARP-SPOOFING:

----

este es un script que hize en python usando scapy, basicamente suplanta la direcion IP's objetivo por la del atacante dejando a los objetivos sin conexion a internet lo cual es util en lugares como ciber cafes donde ofrezcan conexion gratuita y valla lenta

Instalacion:
```bash
sudo python3 -m pip install scapy
```

Para habilitar colores ANSI por consola en windows use:
```batch
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

Ejecucion:
```bash
sudo python3 exec.py --help
```

maqueta:
```bash
sudo python3 exec.py -r [rango de red] -g [puerta de enlaze]<br >
```

ejemplo pratico
```bash
sudo python3 exec.py -r 192.168.1.1/24 -g 192.168.1.1
```
----
