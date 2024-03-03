# ARP-SPOOFING:

----

Este es un script en python usa scapy. Permite suplantar las direciones IP's de varios objetivos por la del atacante dejando a estos sin conexion a internet.

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
