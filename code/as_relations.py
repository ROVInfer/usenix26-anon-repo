
import os
import requests
import json
from collections import defaultdict, Counter
from bs4 import BeautifulSoup

asn_relation_decodes = {0: 'PEER', 1: 'PROVIDER', -1: 'CUSTOMER'}
tier1_asns = {'3356', '1299', '174', '2914', '6453', '6461', '6762', '3491', '5511', '12956', '3257', '7018', '701', '3320', '6830', '209', '1273', '9002', '6939'}
#前16个是真正的tier-1，后面三个是大型ISP

class AS_Relations:
    def __init__(self, date):
        as_rel_fn = f'../sample_input/{date[:6]}01.as-rel.txt'
        as_rel_hela_fn = f'../sample_input/as_rel_hela.txt'
        ppdc_fn = f'../sample_input/{date[:6]}01.ppdc-ases.txt'
        url_dir = 'https://publicdata.caida.org/datasets/as-relationships/serial-1/'
        
        for para in [[as_rel_fn, f'{date[:6]}01.as-rel.txt.bz2'], [ppdc_fn, f'{date[:6]}01.ppdc-ases.txt.bz2']]:
            wfn, url_file = para
            if not os.path.exists(wfn):
                if os.system(f'wget -O {wfn}.bz2 {url_dir}{url_file}'):
                    print(f'[ERROR] download {url_dir}{url_file} failed.')                    
                if os.system(f'bzip2 -d {wfn}.bz2'):
                    print(f'[ERROR] bzip2 -d {wfn}.bz2 failed.')                    
        self.as_relations = defaultdict(defaultdict)
        if os.path.exists(as_rel_fn):
            with open(as_rel_fn, 'r') as rf:
                for line in rf:
                    if line.startswith('#'): continue
                    asn1, asn2, relation = line.strip('\n').split('|')
                    #不能记录单向的关系，因为有时候要求某个AS的providers/customers等，还是需要直接以每个AS为索引
                    self.as_relations[asn1][asn2] = int(relation)
                    self.as_relations[asn2][asn1] = int(relation) * -1  #0: peer, 1: provider, -1: customer
        else: print(f'NOTE! {as_rel_fn} not exist')
        if os.path.exists(as_rel_hela_fn):
            with open(as_rel_hela_fn, 'r') as rf:
                for line in rf:
                    asn1, asn2, relation = line.strip('\n').split('|')
                    if asn1 not in self.as_relations or asn2 not in self.as_relations[asn1]:
                        self.as_relations[asn1][asn2] = int(relation)
                        self.as_relations[asn2][asn1] = int(relation) * -1
        #else: print(f'NOTE! {as_rel_hela_fn} not exist')
        self.as_ppdc = defaultdict()
        if os.path.exists(ppdc_fn):
            with open(ppdc_fn, 'r') as rf:
                for line in rf:
                    if line.startswith('#'): continue
                    elems = line.strip('\n').split(' ')
                    self.as_ppdc[elems[0]] = elems[1:]
        else: print(f'NOTE! {ppdc_fn} not exist')
        
        as_org_url_dir = 'https://publicdata.caida.org/datasets/as-organizations/'
        response = requests.get(as_org_url_dir)
        soup = BeautifulSoup(response.text, "html.parser")
        hrefs = [a['href'] for a in soup.find_all('a', href=True) if a['href'].endswith('jsonl.gz')]
        href = max([href for href in hrefs if href[:6] <= date[:6]]) #20250401.as-org2info.jsonl.gz
        as_org_fn = f'../sample_input/{href[:6]}01.as-org2info.jsonl'
        if not os.path.exists(as_org_fn):
            if os.system(f'wget -O {as_org_fn}.gz {as_org_url_dir}{href}'):
                print(f'[ERROR] download {as_org_url_dir}{href} failed.')
            if os.system(f'gunzip {as_org_fn}.gz'):
                print(f'[ERROR] gunzip {as_org_fn}.gz failed.')
            
        self.as_orgid = {}
        self.orgid_asns = defaultdict(set)
        if os.path.exists(as_org_fn):
            with open(as_org_fn, 'r') as rf:
                for line in rf:
                    try:
                        data = json.loads(line.strip('\n'))
                    except Exception as e:
                        print(f'error: {e}')
                        continue
                    if 'asn' not in data: continue
                    asn, orgid = data['asn'], data['organizationId']
                    self.as_orgid[asn] = orgid
                    self.orgid_asns[orgid].add(asn)
        else: print(f'NOTE! {as_org_fn} not exist')
                
    def GetASRelation(self, asn1, asn2):
        if asn1 == asn2: return 'SAME'
        if asn1 in self.as_relations and asn2 in self.as_relations[asn1]:
            return asn_relation_decodes[self.as_relations[asn1][asn2]]
        else:
            return 'UNKNOWN'
        
    def GetProviders(self, asn1):
        ret = set()
        if asn1 not in self.as_relations: return ret
        for asn2, relation in self.as_relations[asn1].items():
            if relation == 1: ret.add(asn2)
        return ret
        
    def GetPeers(self, asn1):
        ret = set()
        if asn1 not in self.as_relations: return ret
        for asn2, relation in self.as_relations[asn1].items():
            if relation == 0: ret.add(asn2)
        return ret
    
    def GetCC(self, asn):
        return self.as_ppdc.get(asn, [])
    
    def GetCCSize(self, asn):
        return len(self.as_ppdc.get(asn, []))
    
    def CheckSibling(self, asn1, asn2):
        return (asn1 in self.as_orgid) and (asn2 in self.as_orgid) and (self.as_orgid[asn1] == self.as_orgid[asn2])
        
    def GetAllSiblings(self, asn):
        if asn not in self.as_orgid: return set()
        return {elem for elem in self.orgid_asns[self.as_orgid[asn]] if elem != asn}
    
    def GetASRelationIncludeSibling(self, asn1, asn2):
        if asn1 == asn2: return 'SAME'
        if self.CheckSibling(asn1, asn2): return 'SIBLING'
        return self.GetASRelation(asn1, asn2)
