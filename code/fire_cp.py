
import argparse
import os
import json
from datetime import datetime
from collections import defaultdict, Counter
from get_BGP_info_from_local import GetValidAndInvalidRoutesOfHijackers, PreWorkGetFullVPsAndPrefOrigins
from config_para import config_para
from as_relations import AS_Relations
from use_roa import ROATree
import ipaddress
import sys
from glob import glob

calculate_time = '20250804080000'

def GetAllInvalids(given_time, rtree=None):
    try:
        if os.path.exists(f'../sample_output/all_invalids_{given_time}.json'): return
        if not rtree: rtree = ROATree(given_time)
        
        invalid_pref_origin = defaultdict(defaultdict)
        pref_origins = None
        with open(f'../sample_output/pref_origins_{given_time}.json', 'r') as rf:
            pref_origins = json.load(rf)
            for pref, origins in pref_origins.items():
                if int(pref.split('/')[-1]) > 24: continue
                moas = (len(origins) > 1)
                for origin in origins:
                    if rtree.Validate(pref, origin) == 'invalid':
                        invalid_pref_origin[pref][origin] = moas
        print(f'invalid prefs#: {len(invalid_pref_origin)}')
        with open(f'../sample_output/all_invalids_{given_time}.json', 'w') as wf:
            json.dump(invalid_pref_origin, wf, indent=1) #invalid_pref_origin[pref][origin] = moas
        return pref_origins, invalid_pref_origin
    except Exception as e:
        print(e)

def GetInvalidSubprefs(given_time, rtree=None):
    #if os.path.exists(f'../sample_output/invalid_subpref_valid_parpref_{given_time}.json'): return
    
    pref_origins, invalid_pref_origin = None, None
    if os.path.exists(f'../sample_output/all_invalids_{given_time}.json'):
        with open(f'../sample_output/all_invalids_{given_time}.json', 'r') as rf:
            invalid_pref_origin = json.load(rf)
        with open(f'../sample_output/pref_origins_{given_time}.json', 'r') as rf:
            pref_origins = json.load(rf)
    else:
        pref_origins, invalid_pref_origin = GetAllInvalids(given_time, rtree)        
    
    try:
        invalid_uni_pref_origin = {} #没有别的AS竞争等长前缀，但有可能有别的AS竞争父子前缀
        invalid_subpref_with_valid_parprefs = {}
        for pref, val in invalid_pref_origin.items(): #invalid_pref_origin[pref][origin] = moas
            if any(subval for subval in val.values()): continue #要求invalid pref没有MOAS
            cur_origin = list(val.keys())[0]
            invalid_uni_pref_origin[pref] = cur_origin
            form_pref = ipaddress.IPv4Network(pref, strict=True)
            parpref_origins = None
            #检查父前缀
            for prefix_len in range(form_pref.prefixlen - 1, 0, -1):
                parpref = str(form_pref.supernet(new_prefix=prefix_len))
                parpref_origins = pref_origins.get(parpref, [])
                if parpref_origins: #存在宣告的最长父前缀
                    #为简化问题，这里要求parpref也没有MOAS
                    if (len(parpref_origins) == 1) and (parpref not in invalid_pref_origin): #存在合法父前缀
                        invalid_subpref_with_valid_parprefs[pref] = [parpref, parpref_origins[0]]
                    break
        print(f'invalid_uni_pref_origin #: {len(invalid_uni_pref_origin)}')
        with open(f'../sample_output/invalid_subpref_valid_parpref_{given_time}.json', 'w') as wf:
            json.dump(invalid_subpref_with_valid_parprefs, wf)
        with open(f'../sample_output/invalid_uni_pref_origin_{given_time}.json', 'w') as wf:
            json.dump(invalid_uni_pref_origin, wf, indent=1)
    except ValueError as e:
        raise ValueError(f"invalid prefs: {pref}") from e

def GetROVSegsFromValidRoutesOfHijacker(given_time): #先找相交点（因为双平面也要用），最后再摘出full VP相关的
    # if os.path.exists(f'../sample_output/possib_rov_seg_from_ihrd_cp_{given_time}.json') and \
    #     os.path.exists(f'../sample_output/rov_segs_from_ihrd_cp_{given_time}.json') and \
    #     os.path.exists(f'../sample_output/full_vp_valid_routes_without_invalid_route_intersect_{given_time}.json'): return
        
    as_rels = AS_Relations(given_time)
    
    invalid_pref_coverasn_intfs = defaultdict(lambda:defaultdict(set))
    with open(f'../sample_output/invalid_uni_pref_routes_{given_time}.json', 'r') as rf:
        data = json.load(rf)  #invalid_subpref_routes[pref] = [routes]
        for pref, routes in data.items():
            for route in routes:
                route_list = route.split(' ')
                for i, asn in enumerate(route_list[:-1]):
                    prev_rel = as_rels.GetASRelation(route_list[i-1], asn) if i != 0 else 'PEER'
                    succ_rel = as_rels.GetASRelation(asn, route_list[i+1])
                    invalid_pref_coverasn_intfs[pref][asn].add((prev_rel, succ_rel))
    invalid_subprefs = None
    with open(f'../sample_output/invalid_subpref_valid_parpref_{given_time}.json', 'r') as rf:
        data = json.load(rf) #invalid_subpref_valid_parpref[pref] = [parpref, parpref_origins[0]]
        invalid_subprefs = set(data.keys())
    
    full_vps = set()
    with open(f'../sample_output/full_vps_{given_time}.json', 'r') as rf:
        data = json.load(rf) #full_vps[asn] = [[full-vp, rc]]
        for val in data.values():
            for full_vp, rc in val: full_vps.add(full_vp)
    
    full_vp_all_invalid_routes = set()
    #要求不仅合法非法前缀路径上的AS相交，而且交点的接口类型要相同  
    rov_segs = set()
    possib_rov_seg_dst_subpref = defaultdict(set) #为下一步数据平面探测做准备
    full_vp_valid_routes_without_invalid_route_intersect = {} #data[vp] = [[valid_routes], [not_seen_invalid_prefs]]
    with open(f'../sample_output/hijacker_valid_routes_invalid_prefs_{given_time}.json', 'r') as rf:
        data = json.load(rf) #data[vp] = [[valid_routes], [not_seen_invalid_prefs]]
        for vp, val in data.items():
            for valid_routes, not_seen_invalid_prefs in val:
                related_asn_intf_pref = defaultdict(lambda:defaultdict(set))
                for pref in not_seen_invalid_prefs:
                    for asn, intfs in invalid_pref_coverasn_intfs[pref].items():
                        for intf in intfs: related_asn_intf_pref[asn][intf].add(pref)
                for route in valid_routes:
                    if not (route and route[0].isdigit()): continue
                    route_list = route.strip(' ').split(' ')
                    find_invalid_route_intersect = False
                    for i, asn in enumerate(route_list[:-1]):
                        if asn in related_asn_intf_pref: #有交叉点                            
                            prev_rel = as_rels.GetASRelation(route_list[i-1], asn) if i != 0 else 'PEER'
                            succ_rel = as_rels.GetASRelation(asn, route_list[i+1])
                            intf = (prev_rel, succ_rel)
                            if intf in related_asn_intf_pref[asn]: #接口也匹配
                                find_invalid_route_intersect = True
                                if i == 0:
                                    break #别的VP看到的，从第一跳就开始传invalid路由了，这时过滤掉
                                route_seg = ' '.join(route_list[:i])
                                if vp in full_vps: #FULL VP！从纯控制平面判定ROV seg
                                    rov_segs.add(route_seg + ' ' + prev_rel)
                                else: #不是full VP, 还需要结合数据平面探测
                                    subprefs = related_asn_intf_pref[asn][intf] & invalid_subprefs
                                    #只有subpref 可以用数据平面探测！
                                    if subprefs:
                                        possib_rov_seg_dst_subpref[route_seg + ' ' + prev_rel].update(subprefs)
                                break
                    if (vp in full_vps):
                        full_vp_all_invalid_routes.add(route)
                        if not find_invalid_route_intersect:
                            if vp not in full_vp_valid_routes_without_invalid_route_intersect:
                                full_vp_valid_routes_without_invalid_route_intersect[vp] = [[], not_seen_invalid_prefs]
                            full_vp_valid_routes_without_invalid_route_intersect[vp][0].append(route)
    
    print(f'full_vp_all_invalid_routes: {len(full_vp_all_invalid_routes)}')
    not_found_intersection_routes = {route for val in full_vp_valid_routes_without_invalid_route_intersect.values() for route in val[0]}
    print(f'not_found_intersection_routes: {len(not_found_intersection_routes)}')
    
    res = rov_segs
    asns = {asn for r in res for asn in r.split(' ')[:-1]}
    print(f'rov segs cover asns #: {len(asns)}')
    with open(f'../sample_output/rov_segs_from_ihrd_cp_{given_time}.json', 'w') as wf:
        json.dump(list(res), wf, indent=1) #注意，这里把ROV路径段最后一跳与下一跳的接口类型也记录了
    with open(f'../sample_output/possib_rov_seg_from_ihrd_cp_{given_time}.json', 'w') as wf:
        rec = {key:list(val) for key, val in possib_rov_seg_dst_subpref.items()}
        json.dump(rec, wf, indent=1)
    with open(f'../sample_output/full_vp_valid_routes_without_invalid_route_intersect_{given_time}.json', 'w') as wf:
        json.dump(full_vp_valid_routes_without_invalid_route_intersect, wf, indent=1)

def GroupValidInvalidPrefsOfSameHijacker(given_time):
    # if os.path.exists(f'../sample_output/hijacker_invalid_subprefs_valid_prefs_{given_time}.json') and \
    #     os.path.exists(f'../sample_output/hijacker_invalid_uni_prefs_valid_prefs_{given_time}.json'): return
    
    invalid_pref_origin = None
    with open(f'../sample_output/all_invalids_{given_time}.json', 'r') as rf:
        invalid_pref_origin = json.load(rf) #invalid_pref_origin[pref][origin] = moas
    pref_origins = {}
    origin_prefs = defaultdict(set)
    with open(f'../sample_output/pref_origins_{given_time}.json', 'r') as rf:
        pref_origins = json.load(rf)
        for pref, origins in pref_origins.items():
            if len(origins) == 1: origin_prefs[origins[0]].add(pref) #只关注uni-origin

    origin_invalid_subprefs_valid_prefs = {}
    with open(f'../sample_output/invalid_subpref_valid_parpref_{given_time}.json', 'r') as rf:
        data = json.load(rf) #invalid_subpref_valid_parpref[pref] = [parpref, parpref_origin]
        for invalid_subpref in data.keys():
            origin = pref_origins[invalid_subpref][0] #提前要求了invalid_subpref是uni-origin
            if origin not in origin_invalid_subprefs_valid_prefs:
                origin_invalid_subprefs_valid_prefs[origin] = [[], []]
            origin_invalid_subprefs_valid_prefs[origin][0].append(invalid_subpref)
        for origin in origin_invalid_subprefs_valid_prefs:
            for other_pref in origin_prefs.get(origin, set()): #origin_prefs里的都是uni-origin
                if other_pref not in invalid_pref_origin: #other_pref是合法前缀
                    origin_invalid_subprefs_valid_prefs[origin][1].append(other_pref)
    origin_invalid_uni_prefs_valid_prefs = {}
    with open(f'../sample_output/invalid_uni_pref_origin_{given_time}.json', 'r') as rf:
        data = json.load(rf) #invalid_uni_pref_origin[pref] = origin
        for invalid_uni_pref, origin in data.items():
            if origin not in origin_invalid_uni_prefs_valid_prefs:
                origin_invalid_uni_prefs_valid_prefs[origin] = [[], []]
            origin_invalid_uni_prefs_valid_prefs[origin][0].append(invalid_uni_pref)
        for origin in origin_invalid_uni_prefs_valid_prefs:
            for other_pref in origin_prefs.get(origin, set()): #origin_prefs里的都是uni-origin
                if other_pref not in invalid_pref_origin: #other_pref是合法前缀
                    origin_invalid_uni_prefs_valid_prefs[origin][1].append(other_pref)
    print(f'origin_invalid_subprefs_valid_prefs #: {len(origin_invalid_subprefs_valid_prefs)}')
    print(f'origin_invalid_uni_prefs_valid_prefs #: {len(origin_invalid_uni_prefs_valid_prefs)}')
    with open(f'../sample_output/hijacker_invalid_subprefs_valid_prefs_{given_time}.json', 'w') as wf:
        json.dump(origin_invalid_subprefs_valid_prefs, wf, indent=1)
    with open(f'../sample_output/hijacker_invalid_uni_prefs_valid_prefs_{given_time}.json', 'w') as wf:
        json.dump(origin_invalid_uni_prefs_valid_prefs, wf, indent=1)
        
def MainFunc():
    global calculate_time
    # cur_dt = datetime.now()
    # calculate_dt = datetime(cur_dt.year, cur_dt.month, cur_dt.day, int(cur_dt.hour/8)*8, 0, 0)
    # calculate_time = calculate_dt.strftime('%Y%m%d%H%M%S')
    # print(f'run-time: {calculate_time}')
    DEBUG = False #True #
    
    if DEBUG:
        pass
    else:
        PreWorkGetFullVPsAndPrefOrigins(calculate_time)
        GetInvalidSubprefs(calculate_time) #获取所有的invalid prefs，以及invalid subprefs
        GroupValidInvalidPrefsOfSameHijacker(calculate_time) #获取和invalid subpref同一源AS的valid prefs
        GetValidAndInvalidRoutesOfHijackers(calculate_time)
        GetROVSegsFromValidRoutesOfHijacker(calculate_time)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="FIRE Control Plane Inference")
    
    parser.add_argument('--input_dir', type=str, default='../sample_input', 
                        help='Directory containing inputs')
    parser.add_argument('--output_dir', type=str, default='../sample_output',
                        help='Directory to save outputs')
    args = parser.parse_args()

    BASE_DIR = args.output_dir
    if not BASE_DIR.endswith('/'): BASE_DIR += '/'
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)

    config_para.input_dir = args.input_dir
    config_para.output_dir = args.output_dir
    
    MainFunc()


