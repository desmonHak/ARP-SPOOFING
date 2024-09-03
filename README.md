# ARP-SPOOFING:

----

Este es un script en ``python`` usa ``scapy``. Permite suplantar las direciones IP's de varios objetivos usando el protocolo ARP, y suplantando la mac del atacante en todos los dispositivos de la red que se indique. Usar esta herramienta, puede generar un fload arp.

Instalacion:
```bash
sudo python3 -m pip install scapy colorama
```

En caso de estar en windows instale WinPcap en el siguiente enlaze: https://www.winpcap.org/install/. De esta manera evitara el siguiente error:
```python
  File "C:\Users\desmon0xff\AppData\Local\Programs\Python\Python311\Lib\site-packages\scapy\arch\windows\__init__.py", line 1019, in __init__
    raise RuntimeError(
RuntimeError: Sniffing and sending packets is not available at layer 2: winpcap is not installed. You may use conf.L3socket orconf.L3socket6 to access layer 3
```

Para habilitar colores ANSI por consola en windows use:
```batch
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

Ejecucion:
```bash
sudo python3 exec.py -h
```

maqueta:
```bash
sudo python3 exec.py -r [rango de red] -g [puerta de enlaze]
```

ejemplo pratico
```bash
sudo python3 exec.py -r 192.168.1.1/24 -g 192.168.1.1
```
----
