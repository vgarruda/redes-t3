from iputils import *
import ipaddress
import struct

IPPROTO_TCP = 6 

class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)
            ttl = ttl - 1
            if ttl != 0:
                aux=4<<4
                ihl=5
                src_addr = str2addr(src_addr)
                dst_addr = str2addr(dst_addr)
                soma = 0
                datagrama = struct.pack('!BBHHHBBH',  aux+ihl, dscp+ecn,20+len(datagrama), identification, flags+frag_offset, ttl, proto, soma)+src_addr+dst_addr
                soma = calc_checksum(datagrama[:4*ihl])    
                datagrama = struct.pack('!BBHHHBBH',  aux+ihl, dscp+ecn,20+len(datagrama), identification, flags+frag_offset, ttl, proto, soma)+src_addr+dst_addr
                datagrama = datagrama+payload
                self.enlace.enviar(datagrama, next_hop) 

    def _next_hop(self, dest_addr):
        vet = []        
        if len(self.tabela_encaminhamento) == 0:
            return None 
        else:
            for ip in self.tabela_encaminhamento:
                if ipaddress.ip_address(dest_addr) in ipaddress.ip_network(ip[0]):
                    vet.append((ipaddress.ip_network(ip[0]), ipaddress.ip_address(ip[1])))
            if len(vet)>0:
                max = -1
                ender = 0
                for n, a in vet:
                    if int(n.prefixlen) >= max:
                        max = int(n.prefixlen)
                        ender=a
                return str(ender)
  
    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        cont=0
        self.identification = cont + 1
        next_hop = self._next_hop(dest_addr)
        aux=4<<4
        ihl=5
        identification = self.identification    
        ttl = 64
        proto = 6
        dscp = 0 
        flags = 0
        frag_offset = 0
        ecn = 0
        src_addr = str2addr(self.meu_endereco) 
        dst_addr = str2addr(dest_addr)
        soma = 0
        datagrama = struct.pack('!BBHHHBBH',  aux+ihl, dscp+ecn,20+len(segmento), identification, flags+frag_offset, ttl, proto, soma)+src_addr+dst_addr
        soma = calc_checksum(datagrama[:4   *ihl])    
        datagrama = struct.pack('!BBHHHBBH',  aux+ihl, dscp+ecn,20+len(segmento), identification, flags+frag_offset, ttl, proto, soma)+src_addr+dst_addr
        datagrama = datagrama+segmento
        self.enlace.enviar(datagrama, next_hop)
