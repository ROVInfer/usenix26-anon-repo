
from collections import defaultdict, Counter
import os
import sys
from traceutils.ixps import create_peeringdb
import socket
import struct
import json
import ipaddress

method = 'RIB-MATCH'

class IP2AS:
    def __init__(self, date):
        self.pref_asns = {}
        self.private_networks = [ipaddress.ip_network(elem) for elem in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]
        if method == 'RIB-MATCH':
            fin_fn = f'../sample_output/pref_origins_{date}.json' #这个里面有错误，有的AS可能错误地宣告了私有地址，导致后续tracerout IP2AS的时候出问题。使用IsPrivateIP()函数修正
            #fin_fn = f'../sample_input/{date[:12]}.json'
            if os.path.exists(fin_fn):
                with open(fin_fn, 'r') as rf: self.pref_asns = json.load(rf)
            else:
                ori_fn = f'../sample_input/{date[:12]}.pfx2as'
                if not os.path.exists(ori_fn):
                    try:
                        os.system(f'wget -O {ori_fn}.gz https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/{date[:4]}/{date[4:6]}/routeviews-rv2-{date[:8]}-{date[8:12]}.pfx2as.gz')
                        os.system(f'gunzip {ori_fn}.gz')
                    except Exception as e:
                        print(f'[ERROR] cannot get pref-asns fn to local: {e}')
                        sys.exit()
                with open(ori_fn, 'r') as rf:
                    for line in rf:
                        pre_pref, preflen, origins = line.strip('\n').split('\t')
                        if int(preflen) > 24: continue
                        if ',' in origins: continue
                        self.pref_asns[pre_pref+'/'+preflen] = origins.split('_')
                with open(fin_fn, 'w') as wf:
                    json.dump(self.pref_asns, wf, indent=1)

        self.ixp_asns = list()
        with open(f'../sample_input/{date[:6]}01.as-rel.txt', 'r') as rf:
            for line in rf:
                if line.startswith('# IXP ASes'):
                    self.ixp_asns = line.split(':')[-1].strip('').split(' ')
                    break
                
        self.ixp_ip2as = {}
        self.ixp_nets = set()
        ixp_ip2as_fn = f'../sample_output/ixp_ip2as_{date[:4]}_{date[4:6]}_{date[6:8]}.json'
        ixp_nets_fn = f'../sample_output/ixp_nets_{date[:4]}_{date[4:6]}_{date[6:8]}.json'
        if os.path.exists(ixp_ip2as_fn) and os.path.exists(ixp_nets_fn):
            with open(ixp_ip2as_fn, 'r') as rf:
                self.ixp_ip2as = json.load(rf)                    
            with open(ixp_nets_fn, 'r') as rf:
                self.ixp_nets = set(json.load(rf))
        else:
            ixp_fn = f'../sample_input/peeringdb_{date[:4]}_{date[4:6]}_{date[6:8]}.json'
            if not os.path.exists(ixp_fn):
                try:
                    url = f'https://publicdata.caida.org/datasets/peeringdb-v2/{date[:4]}/{date[4:6]}/peeringdb_2_dump_{date[:4]}_{date[4:6]}_{date[6:8]}.json'
                    os.system(f'wget -O {ixp_fn} {url}')
                except Exception as e:
                    print(f'[ERROR] cannot get ixp fn to local: {e}')
                    sys.exit()
            with open(ixp_fn, 'r') as rf:
                data = json.load(rf)
                ix_map = {}
                # if 'ix' in data and 'data' in data['ix']:
                #     for ix_entry in data['ix']['data']:
                #         ix_map[ix_entry['id']] = ix_entry['name']
                for elem in data['netixlan']['data']:
                    #如果是通过rs连接的，rs可能会部署ROV，这里需要加rs
                    #格式：'-'+IXPID+'
                    if elem['is_rs_peer']:
                        self.ixp_ip2as[elem['ipaddr4']] = '-'+str(elem['ix_id'])+'+'+str(elem['asn'])
                    else:
                        self.ixp_ip2as[elem['ipaddr4']] = '+'+str(elem['asn'])
                for elem in data['ixpfx']['data']:
                    if ':' not in elem['prefix']: self.ixp_nets.add(elem['prefix'])
            with open(ixp_ip2as_fn, 'w') as wf:
                json.dump(self.ixp_ip2as, wf, indent=1)
            with open(ixp_nets_fn, 'w') as wf:
                json.dump(list(self.ixp_nets), wf)
    
    def IsPrivateIP(self, ip):
        return any(ipaddress.ip_address(ip) in priv_net for priv_net in self.private_networks)
    
    def MapIP2AS(self, ip, with_pref=False):
        if self.IsPrivateIP(ip): return []
        if method == 'RIB-MATCH':
            if ip in self.ixp_ip2as:
                asn = self.ixp_ip2as[ip]
                if asn.strip('-') in self.ixp_asns:
                    #print(f'[NOTE] ip {ip} is an ixp addr in PDB but maps to an ixp AS {asn[1:]}')
                    if not with_pref: return ['-1'] #IXP AS，不参与
                    else: return ['', '-1']
                if not with_pref: return [asn]
                else: return ['', asn]
            
            try:
                ip_int = socket.ntohl(struct.unpack("I",socket.inet_aton(ip))[0])
                for preflen in range(31, 7, -1):
                    mask = ~(1 << (31 - preflen))
                    ip_int = ip_int & mask
                    if preflen <= 24:
                        pref = str(socket.inet_ntoa(struct.pack('I',socket.htonl(ip_int)))) + '/' + str(preflen)
                        if pref in self.ixp_nets: #先判断在不在IXP中
                            if not with_pref: return ['-1'] #表明这是一个IXP hop，具体归属AS和是否route-server接口未知
                            else: return [pref, '-1']
                        if pref in self.pref_asns:
                            if any(asn in self.ixp_asns for asn in self.pref_asns[pref]):
                                if not with_pref: return ['-1'] #IXP ASN 忽略，同时表明上一跳和下一跳通过IXP 连接
                                else: return [pref, '-1']
                            if not with_pref: return self.pref_asns[pref]
                            else: return [pref, self.pref_asns[pref]]
            except Exception as e:
                print(e)
                sys.exit()
            if not with_pref: return []
            else: return ['', []]
    