import heapq
import json
from collections import defaultdict
from multiprocessing import Pool
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict, Counter

def PrepareGraph(d, filepath, flag):
    print(f'begin to load graph. flag: {flag}')
    all_rels = {'PROVIDER', 'PEER', 'CUSTOMER'}
    
    rov_asn_intf_status = defaultdict(defaultdict)
    with open('../data/rov_intfs_20250804080000.json', 'r') as rf:
        data = json.load(rf)
        for elem in data:
            asn, rel = elem.split('-')
            rov_asn_intf_status[asn][rel] = 'rov'
    with open('../data/nonrov_intfs_20250804080000.json', 'r') as rf:
        data = json.load(rf)
        for elem in data:
            asn, rel = elem.split('-')
            if asn in rov_asn_intf_status:
                rov_asn_intf_status[asn][rel] = 'nonrov'
    
    rov_intfs = set()
    if flag == 'inferred':
        for asn, val in rov_asn_intf_status.items():
            for rel, status in val.items():
                if status == 'rov': rov_intfs.add((asn, rel))
    elif flag == 'supplemented':
        for asn, val in rov_asn_intf_status.items():
            for rel in all_rels:
                if rel not in val or val[rel] == 'rov': rov_intfs.add((asn, rel))
    elif flag == 'uniform':
        for asn, val in rov_asn_intf_status.items():
            for rel in all_rels: rov_intfs.add((asn, rel))
    
    graph = []
    with open(filepath, "r") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            a, b, rel = line.strip().split("|")

            if rel == '0':
                # peer-peer
                # if (a, 'PEER') not in rov_intfs: graph.append((a, b, '0'))
                # if (b, 'PEER') not in rov_intfs: graph.append((b, a, '0'))
                ###########逻辑改了！(a, 'PEER') not in rov_intfs 意味着a 可以接收来自b的宣告！
                ###########那么将graph定义为b 可以向a发送宣告（默认接收）
                if (a, 'PEER') not in rov_intfs: graph.append((b, a, '0'))
                if (b, 'PEER') not in rov_intfs: graph.append((a, b, '0'))
            elif rel == '-1':
                # a 是 provider，b 是 customer
                # if (a, 'CUSTOMER') not in rov_intfs: graph.append((a, b, '-1'))
                # if (b, 'PROVIDER') not in rov_intfs: graph.append((b, a, '1'))
                if (a, 'CUSTOMER') not in rov_intfs: graph.append((b, a, '1'))
                if (b, 'PROVIDER') not in rov_intfs: graph.append((a, b, '-1'))
    
    print(f'graph loaded')
    with open(f'../sample_output/sim_graph_{flag}.txt', 'w') as wf:
        for elem in graph:
            wf.write(' '.join(elem)+'\n')

if __name__ == "__main__":
    d = 5
    flags = ['inferred', 'supplemented', 'uniform']
    caida_file = "../sample_input/20250801.as-rel.txt"  # 替换为你的CAIDA文件路径
    for flag in flags:
        PrepareGraph(d, caida_file, flag)
        