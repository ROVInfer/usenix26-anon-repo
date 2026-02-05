
import ipaddress
import random
import subprocess
import re
from collections import defaultdict, Counter

def PickRandomIPs(subnet, k=20, excludes=set()):
    net = ipaddress.IPv4Network(subnet, strict=False)
    hosts = {str(elem) for elem in net.hosts()}
    hosts = hosts - excludes
    return random.sample(hosts, min(k, len(hosts)))

def GetLiveIPs(prefs, pref_group={}):
    # #不用nmap，直接traceroute .1看看效果
    # done_group = set()
    # pref_liveips = defaultdict(list)  #最终返回数据
    # for pref in prefs:
    #     if pref_group and (pref_group[pref] in done_group): continue
    #     pref_liveips[pref] = [pref[:pref.rindex('.')]+'.1']
    #     if pref_group: done_group.add(pref_group[pref])
    # return pref_liveips
    
    group_prefs = defaultdict(list)
    for pref, group in pref_group.items(): group_prefs[group].append(pref)
    if not pref_group: group_prefs = {pref:[pref] for pref in prefs}
    
    pref_liveips = defaultdict(list)  #最终返回数据
    iter = 0
    print(f'total prefs: {len(pref_group)}, total groups: {len(group_prefs)}')
    tmp = [len(val) for val in group_prefs.values()]
    print(f'group prefs num counter: {Counter(tmp)}')
    while True:
        print(f'turn {iter}: done_groups: {len(pref_liveips)}')
        #每个group选一个pref出来检测
        to_check_prefs = []        
        for group, prefs in group_prefs.items():
            to_check_prefs.append(prefs[0])
            group_prefs[group] = prefs[1:] if len(prefs) > 1 else []
        group_prefs = {group:prefs for group, prefs in group_prefs.items() if prefs}
        tmp = [len(val) for val in group_prefs.values() if val]
        print(f'group prefs num counter: {Counter(tmp)}')
        print(f'to_check_prefs: {len(to_check_prefs)}')
        if not to_check_prefs: break #没有可检测的pref, 退出
        
        #逐次抽检
        excludes = defaultdict(set)
        for k in [10, 30, 50, 80, 80]: #每次抽检liveip的数量
            if not to_check_prefs: break
            ip_pref = {} #指针
            for pref in to_check_prefs:
                tmp = PickRandomIPs(pref, k, excludes[pref])
                excludes[pref].update(tmp)
                for elem in tmp: ip_pref[elem] = pref
            print(f'check {k} ips per subnet, total: {len(ip_pref)}')
            try:
                result = subprocess.run(
                    ["nmap", "-sn", "-n", "--min-parallelism", "20", "--max-parallelism", "100"] + list(ip_pref.keys()),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                liveips = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", result.stdout)
                if not liveips: continue
                check_prefs_num = len(to_check_prefs)
                for liveip in liveips: #处理找到的livip
                    pref = ip_pref[liveip]
                    if pref in to_check_prefs: to_check_prefs.remove(pref) #从to_check_prefs中删除
                    pref_liveips[pref].append(liveip) #最终结果
                    if pref_group[pref] in group_prefs: del group_prefs[pref_group[pref]]
                print(f'check_prefs: {check_prefs_num}, {len(to_check_prefs)} have no liveips')
            except Exception as e:
                print(f'Error: {e}')
        iter += 1        
    print(f'find {len(pref_liveips)} prefs that have liveips')
    return pref_liveips

def GetNumLiveIPs(prefs, num):
    res = set()
    prefs_no_liveip = 0
    for pref in prefs:
        to_search_prefs = [pref]
        net = ipaddress.ip_network(pref)
        if net.prefixlen < 24:
            to_search_prefs = net.subnets(new_prefix=24)
        for to_search_pref in to_search_prefs:
            to_search_pref = str(to_search_pref)
            print(f'pref {pref}, to_search_pref: {to_search_pref}: to_get {num} IPs')
            if num <= 0: return res
            try:
                result = subprocess.run(
                    ["nmap", "-sn", "-n", "-T5", " --max-retries", "1", "--host-timeout", "30s", "--min-parallelism", "20", "--max-parallelism", "100"] + [to_search_pref],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                liveips = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", result.stdout)
                print(f'to_search_pref {to_search_pref}: get {len(liveips)} IPs')
                if liveips:
                    if len(liveips) > num: res.update(liveips[:num])
                    else: res.update(liveips)
                    num -= len(liveips)
                    print(f'num: {num}')
                if len(liveips) == 0: 
                    prefs_no_liveip += 1
                    if prefs_no_liveip >= 20: return res
                    break #没有liveIP的/24子前缀，不再检查同一前缀下的其它/24前缀
            except Exception as e:
                print(f'Error: {e}')
    return res




