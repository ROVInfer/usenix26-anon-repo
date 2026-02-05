
import re
import os
import json
import msgpack
import requests
import radix
from collections import defaultdict, Counter
from bs4 import BeautifulSoup
from multiprocessing import Pool
from glob import glob
import sys
import ipaddress
from datetime import datetime, timedelta
from config_para import config_para

def DriftTime5Min(given_time, before=True):
    dt = datetime.strptime(given_time, '%Y%m%d%H%M%S')
    new_dt = dt + timedelta(minutes=-5) if before else dt + timedelta(minutes=5)
    new_time = new_dt.strftime('%Y%m%d%H%M%S')
    return new_time[:-3] + '000'

def DownloadGivenLinkROAFromJosephine(link):
    given_time = ''.join(re.findall(r'\d+', link))
    wfn, url = None, None
    if True:
        wfn = f'{config_para.input_dir}/roa/{given_time}.msgpack'
        if os.path.exists(wfn): return wfn
        url = f'https://josephine.sobornost.net/rpkidata/{given_time[:4]}/{given_time[4:6]}/{given_time[6:8]}/' + link
    os.system(f'wget {url}')
    os.system(f'tar -xzvf {link}')
    rec = defaultdict(list)
    tmp_dir = link.split('.')[0]
    cur_fn = tmp_dir + '/output/rpki-client.json'
    with open(cur_fn, 'r') as rf:
        data = json.load(rf)
        for elem in data['roas']: #for cur_asn, cur_maxlen in self.roa[cur_pref]
            pref = elem['prefix']
            if ':' in pref: continue
            origin = elem['asn'] if isinstance(elem['asn'], int) else elem['asn'].strip('AS')
            rec[pref].append([origin, elem['maxLength']])
    with open(wfn, "wb") as wf:
        msgpack.dump(rec, wf)
    if tmp_dir: os.system(f'rm -rf {tmp_dir}')
    if link: os.system(f'rm -f {link}')
    return wfn

def DownloadSpecTimeROAFromJosephine(given_time): #{year}{month}{day}{hour}{minute}{second}
    url = None
    if True:
        url = f'https://josephine.sobornost.net/rpkidata/{given_time[:4]}/{given_time[4:6]}/{given_time[6:8]}/'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    for a in soup.find_all('a', href=True):
        b = a['href']
        c = 1
    links = [a['href'] for a in soup.find_all('a', href=True) if \
                (a['href'][-3:] == 'tgz') and \
                (given_time[:-3] in ''.join(re.findall(r'\d+', a['href'])))]
    if links: 
        return DownloadGivenLinkROAFromJosephine(links[0])
    else:
        return None

class ROATree:
    def __init__(self, given_time, construct_rtree=True):
        existed_fns = glob(f'{config_para.input_dir}/roa/{given_time[:10]}*.msgpack')
        fn = str(existed_fns[0]) if existed_fns else DownloadSpecTimeROAFromJosephine(given_time)
        if not fn:
            #print(f'no josephine date for {given_time}')
            print(f'not enough ripe date for {given_time}')
            self.construct_flag = False
            return
        
        self.construct_flag = True
        self.roa = {}
        if construct_rtree:
            self.rtree = radix.Radix()
            with open(fn, 'rb') as f:
                self.roa = msgpack.unpackb(f.read())
                for pref in self.roa.keys():
                    self.rtree.add(pref)
                
    def GetCoveringROAs(self, pref):
        ret = {}
        covering = {node.prefix for node in self.rtree.search_covering(pref)}
        for elem in covering:
            ret[elem] = self.roa[elem]
        return ret
    
    def Validate(self, pref, origin):
        flag = 'unknown'
        covering = {node.prefix for node in self.rtree.search_covering(pref)}
        if covering:
            pref_len = int(pref.split('/')[-1])
            for cur_pref in covering:
                for cur_asn, cur_maxlen in self.roa[cur_pref]:
                    #print(f'cover: {cur_pref}, {cur_asn}, {cur_maxlen}')
                    if (not isinstance(cur_maxlen, int)) and (not cur_maxlen.isdigit()): cur_maxlen = 24
                    if int(cur_maxlen) < pref_len:flag = 'invalid' #没有覆盖
                    elif origin == str(cur_asn):
                        flag = 'valid'
                        break
                    else: flag = 'invalid'
                if flag == 'valid': break
        return flag
    
    def ValidateOrigin(self, pref, origin):
        flag = 'unknown'
        covering = {node.prefix for node in self.rtree.search_covering(pref)}
        roa_val = []
        if covering:
            pref_len = int(pref.split('/')[-1])
            for cur_pref in covering:
                for cur_asn, cur_maxlen in self.roa[cur_pref]:
                    if origin == str(cur_asn):
                        flag = 'valid'
                        break
                    else:
                        flag = 'invalid'
                        roa_val.append([cur_pref, cur_asn, int(cur_maxlen)])
                if flag == 'valid': break
        if flag == 'invalid': return [flag, roa_val]
        else: return [flag, []]
        
    def ValidateExactPref(self, pref, origin):
        flag = 'unknown'
        if pref in self.roa:
            for cur_asn, cur_maxlen in self.roa[pref]:
                if origin == str(cur_asn):
                    flag = 'valid'
                    break
                else: flag = 'invalid'
        return flag
    
def CalROACovered():
    rtree = ROATree('20250424000')
    with open(f'{config_para.output_dir}/pref_origins_20250424000000.json', 'r') as rf:
        pref_origins = json.load(rf)
        prefs = set()
        covered_prefs = set()
        invalid_prefs = set()
        for pref, origins in pref_origins.items():
            if int(pref.split('/')[-1]) > 24: continue
            prefs.add(pref)
            for origin in origins:
                flag = rtree.Validate(pref, origin)
                if flag != 'unknown':
                    covered_prefs.add(pref)
                    if flag == 'invalid':
                        invalid_prefs.add(pref)
        invalid_subprefs = set()
        for pref in invalid_prefs:
            form_pref = ipaddress.IPv4Network(pref, strict=True)
            for prefix_len in range(form_pref.prefixlen - 1, 0, -1):
                parpref = str(form_pref.supernet(new_prefix=prefix_len))
                parpref_origins = pref_origins.get(parpref, [])                
                for parpref_origin in parpref_origins:
                    if rtree.Validate(parpref, parpref_origin) != 'invalid': #存在合法父前缀
                        invalid_subprefs.add(pref)
                        break
                if pref in invalid_subprefs: break
        print(f'total prefixes: {len(prefs)}')
        print(f'covered prefs: {len(covered_prefs)}, invalid prefs: {len(invalid_prefs)}')
        print(f'invalid_subpref #: {len(invalid_subprefs)}')
