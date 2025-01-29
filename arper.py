from multiprocessing import Process
from scapy.all import (ARP, Ether,conf,get_if_hwaddr,
                       send,sniff, sndrcv, srp, wrpcap)
import os
import sys
import time

# Função auxiliar para obter endereço MAC de qualquer maquina.
def get_mac(target_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op= "who-has", pdst=target_ip)
    resp, _ = srp(packet,timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

#Classe para envenenar, capturar e restaurar as configurações de redes
class Arper:
    def __init__(self, victim, gateway, interface='en0'):
        pass

    def run(self):
        pass

    def poison (self):
        pass

    def sniff(self, count = 200):
        pass

    def restore(self):
        pass

if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()