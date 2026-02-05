
import argparse
from get_BGP_info_from_local import config_para, GetMustPassHopsOfHijackerPrefs, GetValidRoutesFromFullVPsAndAllInvalidRoutes
from use_nmap import GetLiveIPs, GetNumLiveIPs
from fire_cp import calculate_time
from as_relations import AS_Relations, tier1_asns
from use_atlas import FetecAllCurrentConnectedASNProbes, LauchTracerouteTasks, ResolveTracerouteRes, atlas_para, GetMyTraceMsmIdsInSpecTime, FetchMsmResult, Create1TracerouteTask
import os
import json
from collections import defaultdict, Counter
from glob import glob
import numpy as np
import ipaddress
from datetime import datetime
from config_para import config_para

def GetPrefLiveIPs(done_fns, subpref_origin, wfn):
    already_origin_subpref_liveips = defaultdict(defaultdict)
    for fn in done_fns:
        with open(fn, 'r') as rf:
            data = json.load(rf)
            for subpref, liveips in data.items():
                if subpref in subpref_origin:
                    already_origin_subpref_liveips[subpref_origin[subpref]][subpref] = liveips
                
    subpref_liveips = None
    if os.path.exists(wfn):
        with open(wfn, 'r') as rf: subpref_liveips = json.load(rf)
    else:
        done_subpref_liveips = {}
        to_do_subpref_origin = {}
        for subpref, origin in subpref_origin.items():
            if origin in already_origin_subpref_liveips:
                done_subpref_liveips.update(already_origin_subpref_liveips[origin])
            else: to_do_subpref_origin[subpref] = origin
        subpref_liveips = GetLiveIPs(to_do_subpref_origin.keys(), to_do_subpref_origin)
        subpref_liveips.update(done_subpref_liveips)
        with open(wfn, 'w') as wf:
            json.dump(subpref_liveips, wf, indent=1)
    return subpref_liveips   

def FilterParSubPrefsWithAmbiguousRoutes(given_time): #如果parpref-origin(subpref-origin)出现在subpref-paths(parpref-paths)上，则过滤
    if os.path.exists(f'{config_para.output_dir}/filtered_parpref_subprefs_{given_time}'):
        with open(f'{config_para.output_dir}/filtered_parpref_subprefs_{given_time}', 'r') as rf:
            filtered_parpref_subprefs = json.load(rf)
            with open(f'{config_para.output_dir}/invalid_subpref_routes_{given_time}.json', 'r') as rf:
                data = json.load(rf)  #subpref_routes[pref] = [routes]
                subpref_routes = {key:set(val) for key, val in data.items()}
                return filtered_parpref_subprefs, subpref_routes #subpref_routes后面还要用，返回该值
    
    parpref_routes = defaultdict(set)
    with open(f'{config_para.output_dir}/full_vp_parpref_routes_{given_time}.json', 'r') as rf:
        data = json.load(rf) #parpref_routes[vp][pref] = [routes]
        for val in data.values():
            for pref, routes in val.items(): parpref_routes[pref].update(routes)
    subpref_routes = None
    with open(f'{config_para.output_dir}/invalid_subpref_routes_{given_time}.json', 'r') as rf:
        data = json.load(rf)  #subpref_routes[pref] = [routes]
        subpref_routes = {key:set(val) for key, val in data.items()}        
    parpref_subprefs = defaultdict(set)
    with open(f'{config_para.output_dir}/invalid_subpref_valid_parpref_{given_time}.json', 'r') as rf:
        data = json.load(rf) #invalid_subpref_valid_parpref[subpref] = [parpref, parpref_origins[0]]
        for subpref, val in data.items():
            parpref_subprefs[val[0]].add(subpref)
            
    parpref_origin = {pref: list(routes)[0].split(' ')[-1] for pref, routes in parpref_routes.items()}
    subpref_origin = {pref: list(routes)[0].split(' ')[-1] for pref, routes in subpref_routes.items()}
    parpref_covered_asns = {pref: {asn for route in routes for asn in route.split(' ')} for pref, routes in parpref_routes.items()}
    subpref_covered_asns = {pref: {asn for route in routes for asn in route.split(' ')} for pref, routes in subpref_routes.items()}
    
    filtered_parpref_subprefs = defaultdict(set)
    for parpref, subprefs in parpref_subprefs.items():
        if parpref not in parpref_routes:
            #print(f'[NOTE] parpref {parpref} not in parpref_routes!') #可能的原因：之前收集parpref是从所有VP宣告的源AS收集的，当前集合里只有full-VP的宣告（但同样表明full-VP可能并不一定转发的前缀）
            continue
        for subpref in subprefs:                
            if subpref not in subpref_routes:
                print(f'[ERROR] subpref {parpref} not in subpref_routes!') #不应该出现这个情况，属于BUG，这里会抛出异常退出
            if (parpref_origin[parpref] not in subpref_covered_asns[subpref]) and \
                (subpref_origin[subpref] not in parpref_covered_asns[parpref]): #父前缀源AS不在子前缀路径上（且反之）
                    filtered_parpref_subprefs[parpref].add(subpref)
                    
    tmp = sum([len(val) for val in filtered_parpref_subprefs.values()])
    print(f'filtered_subprefs: {tmp}')
    with open(f'{config_para.output_dir}/filtered_parpref_subprefs_{given_time}', 'w') as wf:
        rec = {key:list(val) for key, val in filtered_parpref_subprefs.items()}
        json.dump(rec, wf, indent=1) #filtered_parpref_subprefs[parpref].add(subpref)
    return rec, subpref_routes #subpref_routes后面还要用，返回该值
                
def FindInvalidSubprefValidPrefCommonHops(given_time, debug=False):
    if os.path.exists(f'{config_para.output_dir}/invalid_subpref_farthest_common_hop_valid_prefs_{given_time}.json'): return
    
    filtered_parpref_subprefs, invalid_subpref_routes = FilterParSubPrefsWithAmbiguousRoutes(given_time)
    #filtered_parpref_subprefs[parpref].add(subpref)
    #concerned_parprefs = set(filtered_parpref_subprefs.keys())
    concerned_subprefs = {subpref for val in filtered_parpref_subprefs.values() for subpref in val}
    concerned_origins = {list(invalid_subpref_routes[subpref])[0].split(' ')[-1] for subpref in concerned_subprefs}
    GetMustPassHopsOfHijackerPrefs(given_time, list(concerned_origins), debug)
    
    origin_pref_must_pass_hops = None
    with open(f'{config_para.output_dir}/hijacker_pref_must_pass_hops_{given_time}.json', 'r') as rf:
        origin_pref_must_pass_hops = json.load(rf) #origin_pref_must_pass_hops[origin][pref] = [hops]
    
    invalid_subpref_valid_pref_common_hops = defaultdict(lambda:defaultdict(set))
    with open(f'{config_para.output_dir}/hijacker_invalid_subprefs_valid_prefs_{given_time}.json', 'r') as rf:
        data = json.load(rf) #origin_invalid_subprefs_valid_prefs[origin] = [[invalid_prefs], [valid_prefs]]
        for origin, val in data.items():
            if origin not in concerned_origins: continue
            pref_must_pass_hops = origin_pref_must_pass_hops.get(origin, None)
            if not pref_must_pass_hops: continue
            invalid_subprefs, valid_prefs = val
            valid_prefs = set(valid_prefs) & set(pref_must_pass_hops.keys())
            for invalid_subpref in invalid_subprefs:
                if invalid_subpref not in concerned_subprefs: continue
                if invalid_subpref not in pref_must_pass_hops: continue
                invalid_subpref_must_pass_hops = set(pref_must_pass_hops[invalid_subpref])
                for valid_pref in valid_prefs:
                    common_hops = set(pref_must_pass_hops[valid_pref]) & invalid_subpref_must_pass_hops
                    if common_hops:
                        invalid_subpref_valid_pref_common_hops[invalid_subpref][valid_pref].update(common_hops)
    
    invalid_subpref_farthest_common_hop_valid_prefs = defaultdict(lambda:defaultdict(list))
    debug_data = set()
    origin_farthest_common_hop_distance_c = Counter()
    for invalid_subpref, val in invalid_subpref_valid_pref_common_hops.items():
        # if invalid_subpref == "109.244.176.0/21":
        #     a = 1
        invalid_subpref_one_route_lists = [route.split(' ') for route in invalid_subpref_routes[invalid_subpref] if ' ' in route]
        for valid_pref, common_hops in val.items():
            for route_list in invalid_subpref_one_route_lists: #这个是为了检查数据正确性，没有实际作用
                if any(x not in route_list for x in common_hops):
                    debug_data.add((invalid_subpref, ' '.join(common_hops), ' '.join(route_list)))
                    continue
            common_hop = sorted(common_hops, key=lambda x:invalid_subpref_one_route_lists[0].index(x))[0]
            invalid_subpref_farthest_common_hop_valid_prefs[invalid_subpref][common_hop].append(valid_pref)
        for common_hop in invalid_subpref_farthest_common_hop_valid_prefs[invalid_subpref]:
            tmp = len(invalid_subpref_one_route_lists[0]) - 1 - invalid_subpref_one_route_lists[0].index(common_hop)
            origin_farthest_common_hop_distance_c[tmp] += 1
    for invalid_subpref, subval, route in debug_data:
        print(f'[ERROR] invalid_subpref: {invalid_subpref}, subval: {subval}, route_list: {route}')

    print(f'invalid_subpref_that_has_common_hop: {len(invalid_subpref_farthest_common_hop_valid_prefs)}')
    valid_prefs_num = sum([len(subval) for val in invalid_subpref_farthest_common_hop_valid_prefs.values() for subval in val.values()])
    print(f'valid_prefs_num: {valid_prefs_num}')
    print(f'origin_farthest_common_hop_distance_c: {origin_farthest_common_hop_distance_c}')
    with open(f'{config_para.output_dir}/invalid_subpref_farthest_common_hop_valid_prefs_{given_time}.json', 'w') as wf:
        json.dump(invalid_subpref_farthest_common_hop_valid_prefs, wf, indent=1)

def SelProbesForASNNotPassTier1(as_relations, asn, probe_info):
    res = []
    asn_providers = as_relations.GetProviders(asn)
    asn_peers = as_relations.GetPeers(asn)
    for probe, val in probe_info.items():
        probe_providers, probe_peers = val
        if probe in tier1_asns: continue
        if as_relations.CheckSibling(asn, probe): continue #siblings路线可能会有复杂的情形？先不用
        if as_relations.GetASRelation(asn, probe) != 'UNKNOWN': res.append(probe)
        else:
            if (asn_providers & probe_providers).difference(tier1_asns) or \
                (asn_providers & probe_peers).difference(tier1_asns) or \
                (asn_peers & probe_providers).difference(tier1_asns): res.append(probe)
    return res

def SelProbesForASNNotPassTier1_v2(as_relations, asn, probe_info):
    asn_providers = as_relations.GetProviders(asn).difference(tier1_asns)
    asn_peers = as_relations.GetPeers(asn).difference(tier1_asns)
    asn_providers_cc = {c for p in asn_providers for c in as_relations.GetCC(p) if c != p}
    asn_peers_cc = {c for p in asn_peers for c in as_relations.GetCC(p) if c != p}
    fin_cc = (asn_providers_cc | asn_peers_cc)
    res = list(set(probe_info.keys()) & fin_cc)
    if set(res) & tier1_asns:
        #print(f'asn: {asn}, res & tier1_asns: {set(res) & tier1_asns}')
        pass
    #print(f'asn: {asn}, asn_providers: {len(asn_providers)}, asn_peers: {len(asn_peers)}, asn_providers_cc: {len(asn_providers_cc)}, asn_peers_cc: {len(asn_peers_cc)}, fin_cc: {len(fin_cc)}, res: {len(res)}')
    return res

def DesignAtlasTasks_Step1(given_time):
    if os.path.exists(f'{config_para.output_dir}/find_subpref_liveip_tasks_{given_time}.json'): return
                        
    if os.path.exists(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_{given_time}.json'): 
        with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_{given_time}.json', 'r') as rf:
            tasks = json.load(rf) #tasks[origin][common_hop] = [list(liveIPs), list(probes)]
            tasks_num = sum([len(subval[1]) for val in tasks.values() for subval in val.values()])
            tmp = []
            probes_per_ip = Counter()
            for val in tasks.values():
                for subval in val.values():
                    probes_per_ip[int(len(subval[1])/len(subval[0]))] += 1
                    tmp.append([len(subval[0]), len(subval[1])])
            s = sorted(probes_per_ip.items(), key=lambda x:x[0], reverse=True)
            print(f'tasks_num: {tasks_num}')
            print(f'probes_per_ip: {s}')
            print(f'tmp: {tmp}')
            return
    
    # 1. 先过滤可以进行数据平面路径比较的invalid_subprefs
    #该函数里用到的数据hh里已准备好
    filtered_parpref_subprefs, subpref_routes = FilterParSubPrefsWithAmbiguousRoutes(given_time) 
    concerned_invalid_subprefs = {subpref for subprefs in filtered_parpref_subprefs.values() for subpref in subprefs}
    #filtered_parpref_subprefs[parpref].add(subpref)
    
    # 2. 读取核心数据
    concerned, subpref_origin = None, None
    with open(f'{config_para.output_dir}/invalid_subpref_farthest_common_hop_valid_prefs_{given_time}.json', 'r') as rf:
        data = json.load(rf) #invalid_subpref_farthest_common_hop_valid_prefs[invalid_subpref][common_hop].append(valid_pref)
        concerned = {subpref:data[subpref] for subpref in data if subpref in concerned_invalid_subprefs}
        subpref_origin = {subpref:list(subpref_routes[subpref])[0].split(' ')[-1] for subpref in concerned}
    
    # 3. 先选取probe（根据probe的数量决定要获取的liveIP的数量）
    probes = FetecAllCurrentConnectedASNProbes(True)
    as_relations = AS_Relations(given_time)
    # probe_info 应该不用，这里先留着
    probe_info = {} #这里先找出所有probes的providers和peers，用于加速
    for probe in probes:
        probe = str(probe)
        probe_info[probe] = []#[as_relations.GetProviders(probe), as_relations.GetPeers(probe)]
    
    origin_common_hop_subprefs = defaultdict(lambda:defaultdict(set))
    origin_common_hop_sel_probes = defaultdict(lambda:defaultdict(set))
    for subpref, val in concerned.items():
        origin = subpref_origin[subpref]
        for common_hop, valid_prefs in val.items():
            if common_hop in tier1_asns: continue
            #sel_probes = SelProbesForASNNotPassTier1(as_relations, common_hop, probe_info)
            #print(f'subpref: {subpref}, origin: {subpref_origin[subpref]}')
            sel_probes = SelProbesForASNNotPassTier1_v2(as_relations, common_hop, probe_info)
            # if sel_probes:
            #     for valid_pref in valid_prefs: valid_pref_group[valid_pref] = subpref_group[subpref]
            #     subpref_common_hop_sel_probes[subpref][common_hop] = sel_probes
            # 不需要subpref_common_hop_sel_probes[subpref][common_hop] = sel_probes这个数据结构，
            # 只需要subpref_sel_probes[subpref].update(sel_probes) 这个就可以
            origin_common_hop_sel_probes[origin][common_hop] = list(sel_probes)
            origin_common_hop_subprefs[origin][common_hop].add(subpref)    
    groups = defaultdict(defaultdict)
    grouped_prefs = set()
    for origin, val in origin_common_hop_subprefs.items():
        s = sorted(val.items(), key=lambda x:len(x[1]), reverse=True)
        for common_hop, subprefs in s:
            to_be_group_subprefs = subprefs.difference(grouped_prefs)
            if to_be_group_subprefs:
                groups[origin][common_hop] = [subprefs, origin_common_hop_sel_probes[origin][common_hop]]
                grouped_prefs.update(to_be_group_subprefs)
    group_num = sum([len(val) for val in groups.values()])
    print(f'measured origins: {len(groups)}')
    print(f'group_num: {group_num}')
    ### statics ###
    avg = np.mean([len(subval[1]) for val in groups.values() for subval in val.values()])
    print(f'avg probe per group: {avg}')
    total_probes = {probe for val in groups.values() for subval in val.values() for probe in subval[1]}
    print(f'total probes: {len(total_probes)}')
    stat_c = Counter()
    for probe in total_probes:
        cc_size = as_relations.GetCCSize(probe)
        if probe in tier1_asns: stat_c['tier-1'] += 1
        elif cc_size > 50: stat_c['largeISP'] += 1
        elif cc_size > 1: stat_c['smallISP'] += 1
        else: stat_c['stub'] += 1
    print(f'stat_c: {stat_c}')
    
    # 3. 选有liveip的invalid_subprefs，这里先记录，放在多台机器上去测
    #groups[origin][common_hop] = [subprefs, probes]
    find_liveip_tasks = []
    for origin, val in groups.items():
        for common_hop, subval in val.items():
            find_liveip_tasks.append([origin, common_hop, list(subval[0]), list(subval[1])])
    with open(f'{config_para.output_dir}/find_subpref_liveip_tasks_{given_time}.json', 'w') as wf:
        json.dump(find_liveip_tasks, wf, indent=1)
    print(f'find liveips task units: {len(find_liveip_tasks)}')
    # c = [[elem[2], elem[3]] for elem in find_liveip_tasks]
    # print(f'tasks: {c}')
            
def GetPrefLiveIPForTasks(given_time, task_idx, subpref_flag=True):
    TASKS_PER_MACHINE = 100
    res = defaultdict(defaultdict) if subpref_flag else defaultdict(lambda:defaultdict(list))
    fn = f'{config_para.output_dir}/find_subpref_liveip_tasks_{given_time}.json' if subpref_flag else \
        f'{config_para.output_dir}/find_validpref_liveip_tasks_{given_time}.json'
    with open(fn, 'r') as rf:
        data = json.load(rf)
        print(len(data))
        for origin, common_hop, subprefs, probes in data[task_idx:(task_idx+TASKS_PER_MACHINE)]:
            need_ip_num = int(len(probes) / 25) + 1
            liveIPs = GetNumLiveIPs(subprefs, need_ip_num)
            if liveIPs:
                if subpref_flag: res[origin][common_hop] = [list(liveIPs), list(probes)]
                else: res[origin][common_hop].append([list(liveIPs), list(probes)])
    wfn = f'{config_para.output_dir}/subpref_liveips_{task_idx}_{given_time}.json' if subpref_flag else f'{config_para.output_dir}/validpref_liveips_{task_idx}_{given_time}.json'
    with open(wfn, 'w') as wf:
        json.dump(res, wf, indent=1)
    
def DesignAtlasTasks_Step2(given_time):
    if os.path.exists(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_{given_time}.json'): return
    
    tasks = defaultdict(defaultdict)
    liveip_dir = config_para.sample_mid_dir if config_para.sample_mid_dir else config_para.output_dir
    for fn in glob(f'{liveip_dir}/subpref_liveips_*_{given_time}.json'):
        with open(fn, 'r') as rf:
            data = json.load(rf)
            for origin, val in data.items():
                for common_hop, subval in val.items():
                    tasks[origin][common_hop] = subval
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_{given_time}.json', 'w') as wf:
        json.dump(tasks, wf, indent=1)
    targets_num = sum([len(val) for val in tasks.values()])
    prefs_num = sum([len(subval[0]) for val in tasks.values() for subval in val.values()])
    tasks_num = sum([len(subval[1]) for val in tasks.values() for subval in val.values()])
    probes_per_ip = [len(subval[1])/len(subval[0]) for val in tasks.values() for subval in val.values()]
    print(f'prefs_num: {prefs_num}, targets_num: {targets_num}, tasks_num: {tasks_num}')
    print(f'avg probes_per_ip: {np.mean(probes_per_ip)}, max probes_per_ip: {np.max(probes_per_ip)}')
    
def AssignAtlasTasksForSubprefs(given_time):
    if os.path.exists(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_key_0_{given_time}.json'): return

    remains, tasks = None, None
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_{given_time}.json', 'r') as rf:
        remains = json.load(rf) #tasks[origin][common_hop] = [list(liveIPs), list(probes)]
    
    for i, atlas_key in enumerate(atlas_para.my_keys):
        liveip_probes = {}
        left_credits = atlas_para.MAX_TASKS_PER_KEY
        tasks = remains
        remains = defaultdict(defaultdict)
        for origin, val in tasks.items():
            if left_credits <= 0:
                remains[origin] = val
                continue
            for common_hop, subval in val.items():
                if left_credits <= 0:
                    remains[origin][common_hop] = subval
                    continue
                liveips, probes = subval
                probe_start, probe_end = 0, 0
                for liveip in liveips:
                    if probe_start >= len(probes): break
                    probe_end = min(probe_start+atlas_para.MAX_PROBES_PER_DST_ONCE, len(probes))
                    if probe_end - probe_start > left_credits:
                        probe_end = probe_start + left_credits
                    liveip_probes[liveip] = [probes[probe_start:probe_end], origin, common_hop]
                    left_credits -= (probe_end - probe_start)
                    probe_start = probe_end
                    if left_credits <= 0: break
                if probe_start < len(probes):
                    remains[origin][common_hop] = [liveips, probes[probe_start:]]
        task_num = sum([len(val[0]) for val in liveip_probes.values()])
        print(f'cur tasks for key {i}: {task_num}')
        with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_key_{i}_{given_time}.json', 'w') as wf:
            json.dump(liveip_probes, wf, indent=1)
        
    if len(remains) > 0:
        rec = [[len(subval[0]), len(subval[1])] for val in remains.values() for subval in val.values()]
        print(rec)
        with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_remain_{given_time}', 'w') as wf:
            json.dump(remains, wf, indent=1)
            
def StartTraceroutes(given_time, subpref_flag=True):
    #for key_idx in range(8):
    for key_idx in [0]:
        print(f'seg id: {key_idx}')
    
        rfn = f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_key_{key_idx}_{given_time}.json' if subpref_flag else \
            f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_key_{key_idx}_{given_time}.json'
        w_dir = f'{config_para.output_dir}/atlas_results_fire_dp/backup{key_idx}/' if subpref_flag else \
                f'{config_para.output_dir}/atlas_results_fire_dp_validprefix/backup{key_idx}/'
        with open(rfn, 'r') as rf:
            liveip_probes = json.load(rf) #liveip_probes[liveip] = [probes, origin, common_hop]
            print(f'liveips: {len(liveip_probes)}')
            #LauchTracerouteTasks(liveip_probes, given_time, w_dir, atlas_para.my_keys[key_idx+4], False)#
            LauchTracerouteTasks(liveip_probes, given_time, w_dir, atlas_para.my_keys[key_idx], True)#
    
def CollectTracerouteResults(given_time, subpref_flag=True):
    rec_dir = f'{config_para.output_dir}/atlas_results_fire_dp/' if subpref_flag else \
            f'{config_para.output_dir}/atlas_results_fire_dp_validprefix/'
    start_dt = datetime.strptime('20250706', '%Y%m%d')
    end_dt = datetime.now()
    for i in range(len(atlas_para.my_keys)):
        done_msm_ids = GetMyTraceMsmIdsInSpecTime(atlas_para.my_keys[i], start_dt, end_dt)
        print(f'i: {i}, done_msm_ids#: {len(done_msm_ids)}')
        for msm_id in done_msm_ids:
            FetchMsmResult(msm_id, given_time, rec_dir)
    
def DesignAtlasTasksForValidprefs_Step1(given_time):
    if os.path.exists(f'{config_para.output_dir}/find_validpref_liveip_tasks_{given_time}.json'): return

    #统计分析：目前来看平均每个origin有100个valid-prefs，预测只能挑出3-4个进行traceroute
    #对于每个origin，先把valid-prefs分组，按/16，看能分成几组
    groups = defaultdict(defaultdict)
    all_valid_prefs = set()
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_for_validpref_{given_time}.json', 'r') as rf:
        data = json.load(rf) #origin_valid_pref_tasks[origin][common_hop] = [[valid_prefs], [probes]]
        for origin, val in data.items():
            for common_hop, subval in val.items():
                valid_prefs, probes = subval
                all_valid_prefs.update(valid_prefs)
                group_slash16_prefs = defaultdict(list)
                for valid_pref in valid_prefs:
                    pref_slash16 = valid_pref if int(valid_pref.split('/')[1]) <= 16 else \
                                    str(ipaddress.ip_network(valid_pref, strict=False).supernet(new_prefix=16))
                    group_slash16_prefs[pref_slash16].append(valid_pref)
                if origin not in groups or pref_slash16 not in groups[origin]:
                    groups[origin][common_hop] = [group_slash16_prefs, probes]
    print(f'all_valid_prefs: {len(all_valid_prefs)}')
    pref_slash16_per_origin_common_hop = []
    probes_per_origin_common_hop = []
    for origin, val in groups.items():
        for common_hop, subval in val.items():
            group_slash16_prefs, probes = subval
            pref_slash16_per_origin_common_hop.append(len(group_slash16_prefs))
            probes_per_origin_common_hop.append(len(probes))
    print(f'avg pref_slash16_per_origin: {np.mean(pref_slash16_per_origin_common_hop)}, \
            avg probes_per_origin_common_hop: {np.mean(probes_per_origin_common_hop)}, \
            total probes_per_origin_common_hop: {sum(probes_per_origin_common_hop)}')
    #avg pref_slash16_per_origin: 17.25, avg probes_per_origin_common_hop: 548.5, total probes_per_origin_common_hop: 13164
    #即使每个pref_slash16只选一个liveIP进行traceroute，总tasks也在155185，太多了
    #对于每个origin，如果连续三个pref_slash16 从probe到common_hop的traceroute路径段一致，就不再探测了
    
    #1. 对于每个pref_slash16找和probes数量相关的liveIPs
    find_liveip_tasks = []
    all_groups = set()
    for origin, val in groups.items():
        for common_hop, subval in val.items():
            all_groups.add((origin, common_hop))
            group_slash16_prefs, probes = subval
            for prefs in group_slash16_prefs.values():
                find_liveip_tasks.append([origin, common_hop, list(prefs), list(probes)])
    with open(f'{config_para.output_dir}/find_validpref_liveip_tasks_{given_time}.json', 'w') as wf:
        json.dump(find_liveip_tasks, wf, indent=1)
    print(f'find_validpref_liveip_tasks: {len(find_liveip_tasks)}')
    probes = {probe for elem in find_liveip_tasks for probe in elem[3]}
    print(f'before finding liveips, all groups#: {len(all_groups)}, all probes#: {len(probes)}')

def DesignAtlasTasksForValidPrefs_Step2(given_time):
    if os.path.exists(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_remain_{given_time}.json'): return
    
    all_probes = set()
    groups_withliveips = set()
    origin_common_hop_validprefs_probes = defaultdict(lambda:defaultdict(list))
    liveip_dir = config_para.sample_mid_dir if config_para.sample_mid_dir else config_para.output_dir
    for fn in glob(f'{liveip_dir}/validpref_liveips_*_{given_time}.json'):
        with open(fn, 'r') as rf:
            data = json.load(rf) #res[origin][common_hop].append([list(liveIPs), list(probes)])
            for origin, val in data.items():
                for common_hop, subval in val.items():
                    groups_withliveips.add((origin, common_hop))
                    for liveips, probes in subval:
                        origin_common_hop_validprefs_probes[origin][common_hop].append([liveips, probes])
                        all_probes.update(probes)
    with open(f'{config_para.output_dir}/validpref_liveips_{given_time}.json', 'w') as wf:
        json.dump(origin_common_hop_validprefs_probes, wf, indent=1)        
    print(f'all_probes# that can traceroute valid prefs with liveips: {len(all_probes)}')
        
    #每个(origin, common_hop)组尝试不多于3个[liveips, probes]，根据结果判断是否需要多余的traceroute
    liveip_probes = [] #liveip_probes = [liveip, probes, origin, common_hop]
    remains = []
    SLASH16_NUM_PER_GROUP = 3
    all_probes_liveip = set()
    for origin, val in origin_common_hop_validprefs_probes.items():
        for common_hop, subval in val.items():
            selected_group_ids = set()
            for i, elem in enumerate(subval):
                liveips, probes = elem
                if len(probes) / 25 <= len(liveips):
                    #在这里就把probes分配给liveips。对于subpref是在下一个函数AssignAtlasTasksForSubprefs()中做的，我觉得不如直接分配清楚。在validpref中做了这个改变
                    probe_start, probe_end = 0, 0
                    for liveip in liveips:
                        probe_end = min(probe_start+25, len(probes))
                        liveip_probes.append([liveip, probes[probe_start:probe_end], origin, common_hop])
                        all_probes_liveip.update(probes[probe_start:probe_end])
                        probe_start = probe_end
                        if probe_start >= len(probes): break
                    selected_group_ids.add(i)
                if len(selected_group_ids) >= SLASH16_NUM_PER_GROUP: break
            if len(selected_group_ids) < SLASH16_NUM_PER_GROUP: #没选够三组，放松len(probes) / 25 <= len(liveips)限制，凑够三组
                for i, elem in enumerate(subval):
                    if i in selected_group_ids: continue
                    liveips, probes = elem
                    probe_start, probe_end = 0, 0
                    for liveip in liveips:
                        probe_end = min(probe_start+25, len(probes))
                        liveip_probes.append([liveip, probes[probe_start:probe_end], origin, common_hop])
                        all_probes_liveip.update(probes[probe_start:probe_end])
                        probe_start = probe_end
                        if probe_start >= len(probes): break
                    remains.append([liveip, probes[probe_end:], origin, common_hop])
                    selected_group_ids.add(i)
                    if len(selected_group_ids) >= SLASH16_NUM_PER_GROUP: break
            for i, elem in enumerate(subval):
                if i in selected_group_ids: continue
                liveips, probes = elem
                remains.append([liveip, probes, origin, common_hop])
                    
    print(f'all_probes# that can traceroute valid prefs with liveips after selecting three /16 prefixes: {len(all_probes_liveip)}')
    
    #liveip_probes = [[liveip, probes, origin, common_hop]]
    #每个origin, common_hop最多有三组liveips；每个liveip_probes[liveip]最多有25个probes
    tasks_num = sum([len(elem[1]) for elem in liveip_probes])
    print(f'liveips#: {len(liveip_probes)}, tasks#: {tasks_num}')
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_{given_time}.json', 'w') as wf:
        json.dump(liveip_probes, wf, indent=1)
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_remain_{given_time}.json', 'w') as wf:
        json.dump(remains, wf, indent=1)

def TraceroutesForValidPrefWithoutLiveIP(given_time):
    done_groups = None
    done_probes = None
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_{given_time}.json', 'r') as rf:
        data = json.load(rf) #data = [[liveip, probes, origin, common_hop]]
        done_groups = {(origin, common_hop) for liveip, probes, origin, common_hop in data}
        done_probes = {probe for elem in data for probe in elem[1]}

    all_probes = set()
    tasks_num = 0
    rec_dir = f'{config_para.output_dir}/atlas_results_fire_dp_validprefix_noliveips/'
    with open(f'{config_para.output_dir}/find_validpref_liveip_tasks_{given_time}.json', 'r') as rf:
        data = json.load(rf) #find_liveip_tasks.append([origin, common_hop, prefs, probes])
        for origin, common_hop, prefs, probes in data:
            if (origin, common_hop) in done_groups: continue
            #没有liveIP
            probe_start, probe_end = 0, 0
            probes = list(set(probes).difference(done_probes))
            while probe_start < len(probes):
                for pref in prefs:
                    probe_end = min(probe_start+25, len(probes))
                    ip = pref.split('/')[0]
                    ip = ip[:ip.rindex('.')] + '.1'
                    # tasks很少，直接traceroute，顺序执行
                    msm_id = Create1TracerouteTask(ip, probes[probe_start:probe_end], atlas_para.my_keys[5])
                    if isinstance(msm_id, int) and msm_id > 0:
                        FetchMsmResult(msm_id, given_time, rec_dir)
                    tasks_num += (probe_end-probe_start)
                    probe_start = probe_end
                    all_probes.update(probes)
                    if probe_start >= len(probes): break
    #print(f'{noliveip_probes}')
    print(f'all_probes: {len(all_probes)}')
    
    
def AssignAtlasTasksForValidprefs(given_time):
    if os.path.exists(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_key_0_{given_time}.json'): return
    
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_{given_time}.json', 'r') as rf:
        data = json.load(rf) #data = [[liveip, probes, origin, common_hop]]
    
        all_probes = set()
        for elem in data:
            all_probes.update(elem[1])
        print(f'all_probes# that can traceroute valid prefs with liveips before credit limit: {len(all_probes)}')
        
        atlas_key_idx = 0
        left_credits = atlas_para.MAX_TASKS_PER_KEY
        liveip_probes = {}
        remains = []
        for i, elem in enumerate(data):
            liveip, probes, origin, common_hop = elem
            if left_credits <= len(probes): #不够用
                liveip_probes[liveip] = [probes[:left_credits], origin, common_hop] ##liveip_probes 维持subpref时的设计，为了兼容调用StartTraceroutes
                print(f'cur tasks for key {atlas_key_idx}: {atlas_para.MAX_TASKS_PER_KEY}')
                with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_key_{atlas_key_idx}_{given_time}.json', 'w') as wf:
                    json.dump(liveip_probes, wf, indent=1)
                atlas_key_idx += 1
                if atlas_key_idx >= len(atlas_para.my_keys):
                    remains.append([liveip, probes[left_credits:], origin, common_hop])
                    if i < len(data)-1:
                        remains += data[i+1:]
                else:
                    liveip_probes = {}
                    liveip_probes[liveip] = [probes[left_credits:], origin, common_hop]
                    left_credits = atlas_para.MAX_TASKS_PER_KEY - len(probes) + left_credits
            else:
                liveip_probes[liveip] = [probes, origin, common_hop]
                left_credits -= len(probes)

        all_probes = set()
        for fn in glob(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_key_*_{given_time}.json'):
            with open(fn, 'r') as rf:
                data = json.load(rf)
                for val in data.values():
                    all_probes.update(val[0])
        print(f'all_probes# that can traceroute valid prefs with liveips after credit limit: {len(all_probes)}')
                
        if remains:
            remain_task_num = sum([len(elem[1]) for elem in remains])
            print(f'remain liveips#: {len(remains)}, remain tasks#: {remain_task_num}')
            with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_credits_lack_remain_{given_time}.json', 'w') as wf:
                json.dump(remains, wf, indent=1)
        elif liveip_probes:
            print(f'cur tasks for key {atlas_key_idx}: {atlas_para.MAX_TASKS_PER_KEY-left_credits}')
            with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_key_{atlas_key_idx}_{given_time}.json', 'w') as wf:
                json.dump(liveip_probes, wf, indent=1)
            
def CheckSubprefPathsAndSelParprefAtlasTasks(given_time):
    if os.path.exists(f'{config_para.output_dir}/group_probe_to_invalids_{given_time}.json'): return
    
    if not config_para.sample_mid_dir:
        ResolveTracerouteRes(f'{config_para.output_dir}/atlas_results_fire_dp/', given_time, use_backupdirs=False)
    else:
        if not os.path.exists(f'{config_para.output_dir}/atlas_results_fire_dp/'): os.mkdir(f'{config_para.output_dir}/atlas_results_fire_dp')
        os.system(f'cp {config_para.sample_mid_dir}/atlas_results_fire_dp/{given_time}_resolved.json {config_para.output_dir}/atlas_results_fire_dp/{given_time}_resolved.json')
    
    #先把各个元素串起来
    #1. subpref->parpref_origin
    invalid_subpref_valid_parpref = {}
    with open(f'{config_para.output_dir}/invalid_subpref_valid_parpref_{given_time}.json', 'r') as rf:
        invalid_subpref_valid_parpref = json.load(rf) #invalid_subpref_valid_parpref[subpref] = [parpref, parpref_origin]
            
    #2. (origin, common_hop) -> subprefs
    origin_common_hop_info = defaultdict(defaultdict)
    with open(f'{config_para.output_dir}/find_subpref_liveip_tasks_{given_time}.json', 'r') as rf:
        data = json.load(rf)
        print(len(data))
        for origin, common_hop, subprefs, probes in data:
            origin_common_hop_info[origin][common_hop] = subprefs
            
    liveip_related_info = defaultdict(defaultdict)
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_subprefix_{given_time}.json', 'r') as rf:
        task_rec = json.load(rf) #tasks[origin][common_hop] = [list(liveIPs), list(probes)]
        for origin, val in task_rec.items():
            for common_hop, subval in val.items():
                #liveips, probes = subval
                for liveip in subval[0]:
                    tmp_ip = ipaddress.ip_address(liveip)
                    if origin not in origin_common_hop_info or common_hop not in origin_common_hop_info[origin]: continue
                    for subpref in origin_common_hop_info[origin][common_hop]:
                        tmp_pref = ipaddress.ip_network(subpref, strict=False)
                        if tmp_ip in tmp_pref:
                            parpref_origin = invalid_subpref_valid_parpref[subpref][1]
                            liveip_related_info[liveip] = [subpref, origin, parpref_origin, common_hop]#, probes]               
                            break
    
    invalid_subpref_farthest_common_hop_valid_prefs = None
    with open(f'{config_para.output_dir}/invalid_subpref_farthest_common_hop_valid_prefs_{given_time}.json', 'r') as rf:
        invalid_subpref_farthest_common_hop_valid_prefs = json.load(rf) #invalid_subpref_farthest_common_hop_valid_prefs[invalid_subpref][common_hop].append(valid_pref)
        
    as_rel = AS_Relations(given_time)
    stat = Counter()
    origin_valid_pref_tasks = defaultdict(defaultdict)
    group_probe_to_invalids = defaultdict(lambda:defaultdict(set))
    #debug_valid_pref_liveip_rec = defaultdict(lambda:defaultdict(set))
    nonrov_paths = []
    with open(f'{config_para.output_dir}/atlas_results_fire_dp/{given_time}_resolved.json', 'r') as rf:
        data = json.load(rf) #atlas_res[dst_ip][probe] = [asn_path, multi_resp_in1hop, reach_dst]
        for dst_ip, val in data.items():
            if dst_ip not in liveip_related_info:
                #print(f'[ERROR] atlas_res dst_ip {dst_ip} not in liveip_related_info')
                continue
            subpref, subpref_origin, parpref_origin, common_hop = liveip_related_info[dst_ip]
            for probe, subval in val.items():
                asn_path, multi_resp_in1hop, reach_dst = subval
                asn_path_list = asn_path.split(' ')
                if reach_dst == 'reach-dst': asn_path_list = asn_path_list[:-1]
                if not asn_path_list: continue
                if probe == '*': probe = asn_path_list[0]
                #判断
                if subpref_origin in asn_path_list:
                    if parpref_origin in asn_path_list:
                        stat['reach-both'] += 1
                    else: #到达了非法子前缀源AS，此时只能说数据平面路径是non-rov路径，但是数据平面可能路径不完整，这里舍弃
                        stat['reach-subpref'] += 1
                        group_probe_to_invalids[subpref_origin][common_hop].add(probe)
                        #asn_path_list.reverse()
                        nonrov_paths.append(' '.join(asn_path_list))
                else:
                    if parpref_origin in asn_path_list: #到达了父前缀，说明valid_pref的路径上有rov，需要进一步traceroute valid_pref 获取rov路径
                        stat['reach-parpref'] += 1
                        #invalid_subpref_farthest_common_hop_valid_prefs[invalid_subpref][common_hop].append(valid_pref)
                        if subpref_origin not in origin_valid_pref_tasks or common_hop not in origin_valid_pref_tasks[subpref_origin]:
                            origin_valid_pref_tasks[subpref_origin][common_hop] = [set(), set()]
                        origin_valid_pref_tasks[subpref_origin][common_hop][0].update(invalid_subpref_farthest_common_hop_valid_prefs[subpref][common_hop])
                        origin_valid_pref_tasks[subpref_origin][common_hop][1].add(probe)
                        #debug_valid_pref_liveip_rec[valid_pref_liveip][dst_ip].add(probe)
                    else: stat['reach-none'] += 1
    print(f'stat: {stat}')
    origin_common_hop_num, prefs_num, tasks_num = 0, 0, 0
    rec = defaultdict(defaultdict)
    for origin, val in origin_valid_pref_tasks.items():
        origin_common_hop_num += len(val)
        for common_hop, subval in val.items():
            rec[origin][common_hop] = [list(subval[0]), list(subval[1])]
            prefs_num += len(subval[0])
            tasks_num += len(subval[0])*len(subval[1])
    print(f'origins: {len(origin_valid_pref_tasks)}, origin_common_hop_num: {origin_common_hop_num}, prefs_num: {prefs_num}, tasks_num: {tasks_num}')
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_for_validpref_{given_time}.json', 'w') as wf:
        json.dump(rec, wf, indent=1) #origin_valid_pref_tasks[origin][common_hop] = [[valid_prefs], [probes]]
    rec1 = defaultdict(defaultdict)
    for key, val in group_probe_to_invalids.items():
        for subkey, subval in val.items():
            rec1[key][subkey] = list(subval)
    with open(f'{config_para.output_dir}/group_probe_to_invalids_{given_time}.json', 'w') as wf:
        json.dump(rec1, wf, indent=1)
    with open(f'{config_para.output_dir}/nonrov_segs_from_fire_dp_{given_time}.json', 'w') as wf:
        json.dump(nonrov_paths, wf, indent=1)
    nonrov_asns = {elem for path in nonrov_paths for elem in path.split(' ')}
    print(f'nonrov segs#: {len(nonrov_paths)}, nonrov_asns#: {len(nonrov_asns)}')

def GetValidprefROVPaths(given_time):
    if os.path.exists(f'{config_para.output_dir}/rov_segs_from_fire_dp_{given_time}.json'): return
    
    if not config_para.sample_mid_dir:
        ResolveTracerouteRes(f'{config_para.output_dir}/atlas_results_fire_dp_validprefix/', given_time)#, use_backupdirs=False)
    else:
        if not os.path.exists(f'{config_para.output_dir}/atlas_results_fire_dp_validprefix/'): os.mkdir(f'{config_para.output_dir}/atlas_results_fire_dp_validprefix')
        os.system(f'cp {config_para.sample_mid_dir}/atlas_results_fire_dp_validprefix/{given_time}_resolved.json {config_para.output_dir}/atlas_results_fire_dp_validprefix/{given_time}_resolved.json')
    
    tasks = {}
    with open(f'{config_para.output_dir}/atlas_tasks_design_for_fire_dp_validprefix_{given_time}.json', 'r') as rf:
        data = json.load(rf) #data = [[liveip, probes, origin, common_hop]]
        for liveip, probes, origin, common_hop in data:
            tasks[liveip] = [origin, common_hop]
    
    rec = []
    all_probes = set()
    scr_asns = set()
    with open(f'{config_para.output_dir}/atlas_results_fire_dp_validprefix/{given_time}_resolved.json', 'r') as rf:
        data = json.load(rf) #atlas_res[dst_ip][probe] = [asn_path, multi_resp_in1hop, reach_dst]
        for dst_ip, val in data.items():
            if dst_ip not in tasks: continue
            origin, common_hop = tasks[dst_ip]
            for probe, subval in val.items():
                all_probes.add(probe)
                asn_path, multi_resp_in1hop, reach_dst = subval
                res_path = []
                for i, elem in enumerate(asn_path.split(' ')):
                    if elem == '-1': continue
                    if len(res_path) == 0: scr_asns.add(elem) #just for recording
                    res_path.append(elem)
                    if elem == common_hop: #common_hop，截止（comm_hop保留，用于算前一跳的interface）
                        #res_path.reverse()
                        rec.append(' '.join(res_path))
                        #print(f'asn_path: {asn_path}, res_path: {tmp}, comon_hop: {elem}')
                        res_path = []
                        break
                if len(res_path) > 0: #没有遇到common_hop
                    #print(f'ip: {dst_ip}, origin: {origin}, asn_path: {asn_path}, comon_hop: {common_hop}')
                    #res_path.reverse()
                    rec.append(' '.join(res_path))
                                    
    print(f'probes# that return traceroute: {len(all_probes)}')
    print(f'src_asns#: {len(scr_asns)}')
    asns = {elem for path in rec for elem in path.split(' ')}
    print(f'rov_segs#: {len(rec)}, covered asns#: {len(asns)}')
    with open(f'{config_para.output_dir}/rov_segs_from_fire_dp_{given_time}.json', 'w') as wf:
        json.dump(rec, wf, indent=1)

def MainFunc():
    global calculate_time
    debug = False #True #
    
    if debug:
        pass
    else:
        GetValidRoutesFromFullVPsAndAllInvalidRoutes(calculate_time)
        FindInvalidSubprefValidPrefCommonHops(calculate_time)
        DesignAtlasTasks_Step1(calculate_time)
        if not config_para.sample_mid_dir:
            GetPrefLiveIPForTasks(calculate_time, 0) #在不同的机器上跑，每次拷贝f'{config_para.output_dir}/find_subpref_liveip_tasks_{given_time}.json'文件，修改task_idx值
        DesignAtlasTasks_Step2(calculate_time)
        AssignAtlasTasksForSubprefs(calculate_time)
        if not config_para.sample_mid_dir:
            StartTraceroutes(calculate_time) #在不同的机器上跑，每次改key_idx
            CollectTracerouteResults(calculate_time)
        CheckSubprefPathsAndSelParprefAtlasTasks(calculate_time)
        DesignAtlasTasksForValidprefs_Step1(calculate_time)
        if not config_para.sample_mid_dir:
            GetPrefLiveIPForTasks(calculate_time, 40, False)  #在不同的机器上跑，每次拷贝f'{config_para.output_dir}/find_validpref_liveip_tasks_{given_time}.json'文件，修改task_idx值
        DesignAtlasTasksForValidPrefs_Step2(calculate_time)
        AssignAtlasTasksForValidprefs(calculate_time)
        if not config_para.sample_mid_dir:
            StartTraceroutes(calculate_time, False) #在不同的机器上跑，每次改key_idx
            TraceroutesForValidPrefWithoutLiveIP(calculate_time)
        GetValidprefROVPaths(calculate_time)
        
if __name__ == '__main__':
    # 1. 定义参数解析器
    parser = argparse.ArgumentParser(description="FIRE Control Plane Inference")
    
    # 2. 添加参数
    parser.add_argument('--input_dir', type=str, default='../sample_input', 
                        help='Directory containing inputs')
    parser.add_argument('--output_dir', type=str, default='../sample_output',
                        help='Directory to save outputs')
    parser.add_argument('--sample_mid_dir', type=str, default='', 
                        help='Do not launch active measurement, use existed data')
    #--sample_mid ../sample_mid

    # 3. 解析参数
    args = parser.parse_args()

    # 4. 更新全局路径变量（如果提供了 output_dir）
    BASE_DIR = args.output_dir
    if not BASE_DIR.endswith('/'): BASE_DIR += '/'
    
    # 5. 确保输出目录存在
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)

    # 6. 调用主函数，传入解析到的参数
    config_para.input_dir = args.input_dir
    config_para.output_dir = args.output_dir
    config_para.sample_mid_dir = '../sample_mid'#args.sample_mid_dir
    MainFunc()
    