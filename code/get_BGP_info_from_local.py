
import subprocess
from collections import defaultdict, Counter
from multiprocessing import Pool
from pathlib import Path
from itertools import chain
import json
import os
import ijson
from use_roa import ROATree
from glob import glob
from datetime import datetime
from dateutil.relativedelta import relativedelta
from as_relations import AS_Relations
from datetime import datetime, timedelta
from config_para import config_para

USE_NETDISK = True

def CompressBGPRoute(path): #input path str, output path list
    path_list = path.split(' ')
    if any(not elem.isdigit() for elem in path_list): return []
    res = []
    for elem in path_list:
        #if elem not in res: res.append(elem)  #这里原来写的有BUG，应该重写
        if (not res) or (elem != res[-1]):
            if elem in res: return [] #loop
            res.append(elem)
    return res

def CheckLoopBGPRoute(path): #input path str, output path list
    path_list = path.split(' ')
    if any(not elem.isdigit() for elem in path_list): return []
    res = []
    for elem in path_list:
        #if elem not in res: res.append(elem)  #这里原来写的有BUG，应该重写
        if len(res) > 0 and (elem != res[-1]) and elem in res: return [] #loop
        res.append(elem)
    return res

def GetRIBsFromOneRC(fn, flag, sel_prefs=None, sel_vps=None, other=None):
    print(f'begin to get full VPs from {fn}')
    vp_prefs = defaultdict(lambda:defaultdict(set))
    pref_origins = defaultdict(set)
    pref_routes = defaultdict(set)
    vp_pref_origin = defaultdict(defaultdict)
    invalids_vps = defaultdict(list)
    if sel_prefs: sel_prefs = set(sel_prefs)
    debug_lines = 0
    rc = '.'.join(fn.split('/')[-1].split('.')[:-4]) if 'tmp_rib' in fn else fn.split('/')[-2]
                
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                if sel_vps and (vp not in sel_vps): continue
                if (':' in pref) or (pref == '0.0.0.0/0') or \
                    (sel_prefs and (pref not in sel_prefs)): continue
                if int(pref.split('/')[-1]) > 24: continue
                
                path_list = CompressBGPRoute(path)
                if not path_list: continue
                if 'GET-FULL-VPS' in flag:
                    vp_prefs[vp_asn][vp].add(pref)
                if 'GET-PREF-ORIGINS' in flag:
                    if path_list: pref_origins[pref].add(path_list[-1])
                if 'GET-VP-PREF-ORIGIN' in flag:
                    if path_list: vp_pref_origin[vp][pref] = path_list[-1]
                if 'GET-ROUTES' in flag:
                    if path_list: pref_routes[pref].add(' '.join(path_list))
                if 'GET-INVALID-SEEN-VP' in flag:
                    invalids_vps[pref].append(vp)
                debug_lines += 1
                #if config_para.g_is_demo and debug_lines > 10000: break
    except Exception as e:
        print(e)
        
    full_vps = {}
    for vp_asn, val in vp_prefs.items():
        #for vp, prefs in val.items(): print(len(prefs))
        tmp = [(vp, rc) for vp, prefs in val.items() if len(prefs) > 800000]#other-200000]
        if tmp: full_vps[vp_asn] = tmp
    pref_origins = {key:list(val) for key, val in pref_origins.items()} if pref_origins else {}
    pref_routes = {key:list(val) for key, val in pref_routes.items()} if pref_routes else {}
    ret = {'GET-FULL-VPS': full_vps, 'GET-PREF-ORIGINS': pref_origins, 'GET-ROUTES': pref_routes, 'GET-VP-PREF-ORIGIN': vp_pref_origin, 'GET-INVALID-SEEN-VP': invalids_vps}
    print(f'end to get full VPs from {fn}')
    return ret

def UnionDictSetResults(results):
    data = defaultdict(set)
    for res in results:
        for key, val in res.items():
            data[key] = data[key] | set(val)
    return data

def GetRIBs(fns, flag, sel_prefs=None, sel_vps=None, other=None):
    paras = [(fn, flag, sel_prefs, sel_vps, other) for fn in fns]
    with Pool(processes=30) as pool:
        results = pool.starmap(GetRIBsFromOneRC, paras)
        
        full_vps = UnionDictSetResults([res['GET-FULL-VPS'] for res in results]) if 'GET-FULL-VPS' in flag else {}
        pref_origins = UnionDictSetResults([res['GET-PREF-ORIGINS'] for res in results]) if 'GET-PREF-ORIGINS' in flag else {}
        pref_routes = UnionDictSetResults([res['GET-ROUTES'] for res in results]) if 'GET-ROUTES' in flag else {}
        
        ret = {'GET-FULL-VPS': full_vps, 'GET-PREF-ORIGINS': pref_origins, 'GET-ROUTES': pref_routes}
        return ret #full_vps[vp_asn] = {(vp, rc)}, pref_origins[pref] = {origins}, pref_routes[pref] = {routes}

#这个要求比较复杂，想要一遍过完，需要单写一个函数
def GetValidRoutesFromFullVPsAndAllInvalidRoutesPerFn(fn, full_vps, invalid_subpref_valid_parpref, invalid_pref_origins):
    print(f'begin to get valid parpref routes and invalid routes from {fn}')
    parprefs = {val[0] for val in invalid_subpref_valid_parpref.values()} if full_vps else {}
    subprefs = set(invalid_subpref_valid_parpref.keys())
    
    full_vp_subprefs = defaultdict(set)
    subpref_routes = defaultdict(set)
    full_vp_parpref_routes = defaultdict(lambda:defaultdict(set))
    all_invalid_routes = set() #这个是补丁，应该还可以有更好的处理方法
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                path_list = CompressBGPRoute(path)
                if not path_list: continue
                if pref in subprefs: #有非法宣告                    
                    subpref_routes[pref].add(' '.join(path_list))
                    if vp in full_vps: full_vp_subprefs[vp].add(pref)
                elif (vp in full_vps) and (pref in parprefs): #full VP的合法父前缀宣告
                    full_vp_parpref_routes[vp][pref].add(' '.join(path_list))
                if pref in invalid_pref_origins:
                    if path_list[-1] in invalid_pref_origins[pref]:
                        all_invalid_routes.add(' '.join(path_list))
                #if config_para.g_is_demo and len(subpref_routes) > 10: break
    except Exception as e:
        print(e)
    
    #处理full VP的子前缀和父前缀路由
    for vp, subprefs in full_vp_subprefs.items():
        for subpref in subprefs:
            parpref, _ = invalid_subpref_valid_parpref[subpref]
            #如果full vp能看到非法子前缀，则不再关注它的合法父前缀路由
            if parpref in full_vp_parpref_routes[vp]: del full_vp_parpref_routes[vp][parpref]
            
    ret_full_vp_parpref_routes = defaultdict()
    for vp, val in full_vp_parpref_routes.items():
        ret_full_vp_parpref_routes[vp] = {key:list(subval) for key, subval in val.items()} # 因为要统计VP受HH的影响范围，所以VP信息还要保留，不能只保留pref-routes
    subpref_routes = {key:list(val) for key, val in subpref_routes.items()}
    print(f'get valid parpref routes and invalid routes from {fn} end')
    return [ret_full_vp_parpref_routes, subpref_routes, list(all_invalid_routes)]

def GetValidRoutesFromFullVPsAndAllInvalidRoutes(given_time):
    if os.path.exists(f'{config_para.output_dir}/invalid_subpref_routes_{given_time}.json') and \
        os.path.exists(f'{config_para.output_dir}/full_vp_parpref_routes_{given_time}.json') and \
        os.path.exists(f'{config_para.output_dir}/all_invalid_routes_{given_time}.json'): return
    
    invalid_subpref_valid_parpref = None
    with open(f'{config_para.output_dir}/invalid_subpref_valid_parpref_{given_time}.json', 'r') as rf:
        invalid_subpref_valid_parpref = json.load(rf) #invalid_subpref_valid_parpref[pref] = [parpref, parpref_origins[0]]

    rc_fullvps = defaultdict(set)
    with open(f'{config_para.output_dir}/full_vps_{given_time}.json', 'r') as rf:
        data = json.load(rf) #full_vps[vp_asn] = [[vp, rc]]
        for val in data.values():
            for vp, rc in val: rc_fullvps[rc].add(vp)

    invalid_pref_origins = defaultdict(list)
    with open(f'{config_para.output_dir}/all_invalids_{given_time}.json', 'r') as rf:
        data = json.load(rf)
        for pref, val in data.items():
            for origin in val: invalid_pref_origins[pref].append(origin)
    
    paras = []
    if USE_NETDISK:
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/ripe/')
        fns1 = path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/routeviews/')
        fns2 = path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')
        for fn in chain(fns1, fns2):
            fn = str(fn)
            rc = fn.split('/')[5]
            paras.append((fn, list(rc_fullvps.get(rc, {})), invalid_subpref_valid_parpref, invalid_pref_origins))
    
    with Pool(processes=20) as pool:
        results = pool.starmap(GetValidRoutesFromFullVPsAndAllInvalidRoutesPerFn, paras)
        full_vp_parpref_routes = {}
        all_invalid_routes = set()
        for res in results: 
            full_vp_parpref_routes.update(res[0])
            all_invalid_routes.update(res[2])
        subpref_routes = UnionDictSetResults([res[1] for res in results])
        
        
        with open(f'{config_para.output_dir}/full_vp_parpref_routes_{given_time}.json', 'w') as wf:
            json.dump(full_vp_parpref_routes, wf, indent=1)
        with open(f'{config_para.output_dir}/invalid_subpref_routes_{given_time}.json', 'w') as wf:
            rec = {key:list(val) for key, val in subpref_routes.items()}
            json.dump(rec, wf, indent=1)
        with open(f'{config_para.output_dir}/all_invalid_routes_{given_time}.json', 'w') as wf:
            json.dump(list(all_invalid_routes), wf, indent=1)

def GetValidAndInvalidRoutesOfHijackersPerFn(fn, origin_invalid_prefs_valid_prefs, debug=False):
    print(f'begin to get valid and invalid routes of hijackers from {fn}, debug mode: {debug}')
    invalid_prefs, valid_prefs = set(), set()
    valid_pref_origin = {}
    for origin, val in origin_invalid_prefs_valid_prefs.items():
        tmp_invalid_prefs, tmp_valid_prefs = val
        invalid_prefs.update(tmp_invalid_prefs)
        valid_prefs.update(tmp_valid_prefs)
        for valid_pref in tmp_valid_prefs: valid_pref_origin[valid_pref] = origin
    
    seen_vp_invalid_prefs = defaultdict(set)
    invalid_pref_routes = defaultdict(set)
    vp_hijacker_valid_routes = defaultdict(lambda:defaultdict(set))
    vp_fst_asns = defaultdict(set)
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                path_list = CompressBGPRoute(path)
                if not path_list: continue
                if ' ' not in path: vp_fst_asns[vp].add(path)
                else: vp_fst_asns[vp].add(path[:path.index(' ')])
                if pref in invalid_prefs: #有非法宣告                    
                    invalid_pref_routes[pref].add(' '.join(path_list))
                    seen_vp_invalid_prefs[vp].add(pref)
                elif pref in valid_prefs: #合法宣告
                    #对于合法路径，这里只记录了vp, hijacker和合法路径，因为同Hijakcer源的合法前缀过多
                    vp_hijacker_valid_routes[vp][valid_pref_origin[pref]].add(' '.join(path_list))
                #if config_para.g_is_demo and (len(invalid_pref_routes) > 100): break
    except Exception as e:
        print(e)
    
    vp_valid_routes_not_seen_invalid_prefs = defaultdict(list)
    for vp, val in vp_hijacker_valid_routes.items():
        if len(vp_fst_asns[vp]) > 1: continue #route reflector, 给RC的不是自己的RIB OUT，而是RIB IN。但它们提供的路由（尤其是invalid路由）还有用，留着(invalid_subpref_routes)
        for origin, valid_routes in val.items():
            invalid_prefs, valid_prefs = origin_invalid_prefs_valid_prefs[origin]
            not_seen_invalid_prefs = set(invalid_prefs).difference(seen_vp_invalid_prefs[vp]) if vp in seen_vp_invalid_prefs else set(invalid_prefs)
            if not_seen_invalid_prefs: #有未可见的invalid_prefs
                vp_valid_routes_not_seen_invalid_prefs[vp].append([list(valid_routes), list(not_seen_invalid_prefs)])
            
    invalid_pref_routes = {key:list(val) for key, val in invalid_pref_routes.items()}
    print(f'get valid and invalid routes of hijackers from {fn} end')
    return [vp_valid_routes_not_seen_invalid_prefs, invalid_pref_routes]

def GetValidAndInvalidRoutesOfHijackers(given_time, debug=False): #这里，需要获取所有VP的hijacker的valid和invalid路由，其中FULL VP的用来做纯控制平面判断，其它VP的可以做双平面判断
    # if not debug and os.path.exists(f'{config_para.output_dir}/hijacker_valid_routes_invalid_prefs_{given_time}.json') and \
    #     os.path.exists(f'{config_para.output_dir}/invalid_subpref_routes_{given_time}.json'): return
        
    origin_invalid_subprefs_valid_prefs = None
    with open(f'{config_para.output_dir}/hijacker_invalid_subprefs_valid_prefs_{given_time}.json', 'r') as rf:
        origin_invalid_subprefs_valid_prefs = json.load(rf) #origin_invalid_subprefs_valid_prefs[origin] = [[invalid_subprefs], [valid_prefs]]
    invalid_subprefs = {pref for val in origin_invalid_subprefs_valid_prefs.values() for pref in val[0]} #这一步要调试
    origin_invalid_prefs_valid_prefs = None
    with open(f'{config_para.output_dir}/hijacker_invalid_uni_prefs_valid_prefs_{given_time}.json', 'r') as rf:
        origin_invalid_prefs_valid_prefs = json.load(rf) #origin_invalid_uni_prefs_valid_prefs[origin] = [[invalid_subprefs], [valid_prefs]]

    paras = []
    if USE_NETDISK:
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/ripe/')
        fns1 = path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/routeviews/')
        fns2 = path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')
        for fn in chain(fns1, fns2):
            fn = str(fn)
            #paras.append((fn, origin_invalid_subprefs_valid_prefs, debug))
            paras.append((fn, origin_invalid_prefs_valid_prefs, debug))
    
    with Pool(processes=20) as pool:
        if debug: paras = paras[:2]
        results = pool.starmap(GetValidAndInvalidRoutesOfHijackersPerFn, paras)
        
        # 加入invalid_uni_prefix后改写
        vp_valid_routes_not_seen_invalid_prefs = {}
        for res in results: vp_valid_routes_not_seen_invalid_prefs.update(res[0]) #vp_valid_routes_not_seen_invalid_prefs[vp] = [[valid_routes], [not_seen_invalid_prefs]]
        invalid_pref_routes = UnionDictSetResults([res[1] for res in results])
        
        if debug: return
        with open(f'{config_para.output_dir}/hijacker_valid_routes_invalid_prefs_{given_time}.json', 'w') as wf:
            json.dump(vp_valid_routes_not_seen_invalid_prefs, wf, indent=1)
        invalid_pref_routes = {key:list(val) for key, val in invalid_pref_routes.items()}
        with open(f'{config_para.output_dir}/invalid_uni_pref_routes_{given_time}.json', 'w') as wf:
            json.dump(invalid_pref_routes, wf, indent=1)
        invalid_subpref_routes = {key:val for key, val in invalid_pref_routes.items() if key in invalid_subprefs}
        if not os.path.exists(f'{config_para.output_dir}/invalid_subpref_routes_{given_time}.json'):
            with open(f'{config_para.output_dir}/invalid_subpref_routes_{given_time}.json', 'w') as wf:
                json.dump(invalid_subpref_routes, wf, indent=1)
            
def GetMustPassHopsOfHijackerPrefsPerFn(fn, origins, debug=False):
    print(f'begin to get valid parpref routes and invalid routes from {fn}, debug mode: {debug}')
    
    origin_pref_must_pass_hops = defaultdict(lambda:defaultdict(set))
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                if len(path) == 0: continue #empty path
                path_list = path.split(' ')
                origin = path_list[-1]
                if origin not in origins: continue
                tmp = {elem for elem in path_list if elem != path_list[-1]}
                if tmp:
                    if pref not in origin_pref_must_pass_hops[origin]: origin_pref_must_pass_hops[origin][pref] = tmp
                    else: origin_pref_must_pass_hops[origin][pref] = origin_pref_must_pass_hops[origin][pref] & tmp
                if debug and path_list[0] == '45352':
                    #print(f'path: {path}, must-pass-hops: {origin_pref_must_pass_hops[origin][pref]}')
                    print(f'fn: {fn}, vp: {vp}, vp_asn: {vp_asn}')
    except Exception as e:
        print(e)
    
    ret = {}
    for origin, val in origin_pref_must_pass_hops.items():
        ret[origin] = {pref:list(subval) for pref, subval in val.items()}
    return ret

def GetMustPassHopsOfHijackerPrefs(given_time, origins, debug=False): #这里，需要获取所有VP的hijacker的valid和invalid路由，其中FULL VP的用来做纯控制平面判断，其它VP的可以做双平面判断
    if not debug and os.path.exists(f'{config_para.output_dir}/hijacker_pref_must_pass_hops_{given_time}.json'): return
    
    paras = []
    if USE_NETDISK:
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/ripe/')
        fns1 = path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/routeviews/')
        fns2 = path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')
        for fn in chain(fns1, fns2):
            fn = str(fn)
            paras.append((fn, origins, debug))
    
    with Pool(processes=20) as pool:
        #if debug: paras = paras[:2]
        results = pool.starmap(GetMustPassHopsOfHijackerPrefsPerFn, paras)
        
        origin_pref_must_pass_hops = defaultdict(lambda:defaultdict(set))
        for res in results:
            for origin, val in res.items():
                for pref, hops in val.items():
                    if pref not in origin_pref_must_pass_hops[origin]: origin_pref_must_pass_hops[origin][pref] = set(hops)
                    else: origin_pref_must_pass_hops[origin][pref] = origin_pref_must_pass_hops[origin][pref] & set(hops)
        ret = defaultdict(lambda:defaultdict(list))
        for origin, val in origin_pref_must_pass_hops.items():
            for pref, subval in val.items():
                if subval: ret[origin][pref] = list(subval)
        #if debug: print(f'ret: {ret}')
        if not debug:
            with open(f'{config_para.output_dir}/hijacker_pref_must_pass_hops_{given_time}.json', 'w') as wf:
                json.dump(ret, wf, indent=1)
                
def GetSpecSegInvalidFromOneRC(given_time, given_segs, fn):
    print(f'begin to get triples from {fn}')
    rtree = ROATree(given_time)
    rec = defaultdict(defaultdict)
    #try:
    if True:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                pref, path = elems[5:7]
                if (':' in pref) or (pref == '0.0.0.0/0'): continue                
                path_list = CompressBGPRoute(path)
                c_path = ' '.join(path_list)
                if len(path_list) < 2: continue
                origin = path_list[-1]
                status = rtree.Validate(pref, origin)
                #if status == 'invalid':
                if True:
                    for given_seg in given_segs: 
                        while given_seg in c_path:
                            i = c_path.index(given_seg)
                            if i == 0 or c_path[i-1] == ' ':
                                if i+len(given_seg) == len(c_path) or c_path[i+len(given_seg)] == ' ':
                                    #find
                                    rec[given_seg][' '.join(path_list)] = pref+'|'+origin
                                    break
                            c_path = c_path[i+1:]

    return rec

def GetSpecSegInvalid(given_time, given_segs, fns):
    rtree = ROATree(given_time, False)
    if not rtree.construct_flag: return (None, None)
    
    paras = [(given_time, given_segs, fn) for fn in fns]
    with Pool(processes=20) as pool:
        results = pool.starmap(GetSpecSegInvalidFromOneRC, paras)
        
        rec = defaultdict(defaultdict)
        for res in results:
            for key, val in res.items():
                rec[key].update(val)
        first_asn = given_segs[0].split(' ')[0]
        with open(f'debug_{given_time}_{first_asn}.json', 'w') as wf:
            json.dump(rec, wf, indent=1)

def GetAllTriplesAndTripleInvalidFromOneRC(given_time, fn):
    print(f'begin to get triples from {fn}')
    rtree = ROATree(given_time)
    triples = set()
    triple_invalids = defaultdict(set)
    debug_lines = 0
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                pref, path = elems[5:7]
                if (':' in pref) or (pref == '0.0.0.0/0'): continue                
                path_list = CompressBGPRoute(path)
                if len(path_list) < 2: continue
                origin = path_list[-1]
                status = rtree.Validate(pref, origin)
                if len(path_list) == 2:
                    triples.add(' '.join(path_list))
                    if status == 'invalid': triple_invalids[' '.join(path_list)].add(pref + ' ' + origin)
                for i in range(len(path_list)-2):
                    triple = ' '.join(path_list[i:i+3])
                    triples.add(triple)
                    if status == 'invalid': triple_invalids[triple].add(pref + ' ' + origin)
                debug_lines += 1
                # if debug_lines > 100: break
                #if len(triple_invalids) > 0 or debug_lines > 1000: break
    except Exception as e:
        print(e)

    triple_invalids = {key:list(val) for key, val in triple_invalids.items()}
    #print(f'get triples from {fn} end')
    #print(triple_invalids)
    return [list(triples), triple_invalids]

def GetAllTriplesAndTripleInvalid(given_time, fns):
    rtree = ROATree(given_time, False)
    if not rtree.construct_flag: return (None, None)
    
    paras = [(given_time, fn) for fn in fns]
    with Pool(processes=20) as pool:
        results = pool.starmap(GetAllTriplesAndTripleInvalidFromOneRC, paras)
        
        triples = set()
        for res in results: triples.update(res[0])
        triple_invalids = UnionDictSetResults([res[1] for res in results])
        
        return (triples, triple_invalids)

def GetAllTriplesAndTripleInvalidFromOneRCFullVP(given_time, fn):
    print(f'begin to get triples from {fn}')
    rtree = ROATree(given_time)
    triples = set()
    triple_invalids = defaultdict(set)
    debug_lines = 0
    rc = '.'.join(fn.split('/')[-1].split('.')[:-4]) if 'tmp_rib' in fn else fn.split('/')[-2]
    
    fullvps = set()
    with open(f'{config_para.output_dir}/full_vps_{given_time}.json', 'r') as rf:
        data = json.load(rf)
        for val in data.values():
            for elem in val:
                if elem[1] == rc:
                    fullvps.add(elem[0])
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                if vp not in fullvps: continue
                if (':' in pref) or (pref == '0.0.0.0/0'): continue                
                path_list = CompressBGPRoute(path)
                if len(path_list) < 2: continue
                origin = path_list[-1]
                status = rtree.Validate(pref, origin)
                if len(path_list) == 2:
                    triples.add(' '.join(path_list))
                    if status == 'invalid': triple_invalids[' '.join(path_list)].add(pref + ' ' + origin)
                for i in range(len(path_list)-2):
                    triple = ' '.join(path_list[i:i+3])
                    triples.add(triple)
                    if status == 'invalid': triple_invalids[triple].add(pref + ' ' + origin)
                debug_lines += 1
                # if debug_lines > 100: break
                #if config_para.g_is_demo and (len(triple_invalids) > 0 or debug_lines > 1000): break
    except Exception as e:
        print(e)

    triple_invalids = {key:list(val) for key, val in triple_invalids.items()}
    #print(f'get triples from {fn} end')
    #print(triple_invalids)
    return [list(triples), triple_invalids]

def GetAllTriplesAndTripleInvalidFullVP(given_time, fns):
    rtree = ROATree(given_time, False)
    if not rtree.construct_flag: return (None, None)
    
    paras = [(given_time, fn) for fn in fns]
    with Pool(processes=30) as pool:
        results = pool.starmap(GetAllTriplesAndTripleInvalidFromOneRCFullVP, paras)
        
        triples = set()
        for res in results: triples.update(res[0])
        triple_invalids = UnionDictSetResults([res[1] for res in results])
        
        return (triples, triple_invalids)

def DebugGetSpecRIBsFromOneRC(fn, pref_origin):
    #print(f'{fn} begin')
    rc = fn.split('/')[5] if USE_NETDISK else fn.split('/')[-1].split('_')[0] 
    res = defaultdict(list)
    i = 0
    try:
    #if True:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                decode_line = line.decode('latin-1').rstrip('\n')
                elems = decode_line.split('|')
                if len(elems) < 6: continue
                pref, path = elems[5:7]
                if pref in pref_origin:
                    cal_origin = pref_origin[pref]                    
                    c_path_list = CompressBGPRoute(path)    
                    if not c_path_list: continue                
                    if c_path_list[-1] == cal_origin and '1221' in path:
                        # print(f'pref: {pref}, cal_origin: {cal_origin}')
                        # print(f'c_path_list: {c_path_list}')
                        # print(f'path: {path}')
                        if path.split(' ')[-1] != cal_origin:
                            print(f'compress error. cal_origin: {cal_origin}. Decode line: {decode_line}')
                        else:
                            res[pref].append([rc, decode_line])
                            #print(f'{pref}:{rc}, {decode_line}')
                #if config_para.g_is_demo and i > 500000: return res
                i += 1
    except Exception as e:
        print(f'error: {e}')
    #print(f'{fn} end')
    return res

def DebugGetSpecRIBs():
    given_time = '20250517080000'
    pref_origin = {'89.16.0.0/20': '21502', '92.49.80.0/20': '21502', '109.203.224.0/20': '21502', '109.203.240.0/20': '21502', '217.175.184.0/21': '21502', '156.231.80.0/22': '21859', '204.141.20.0/22': '8029', '204.141.116.0/22': '8029', '36.255.144.0/23': '38566', '102.213.68.0/23': '328988', '194.176.54.0/23': '5522', '5.83.79.0/24': '29119', '23.197.76.0/24': '20940', '43.239.220.0/24': '7643', '43.239.221.0/24': '7643', '45.202.113.0/24': '209242', '61.5.192.0/24': '38742', '61.5.200.0/24': '38742', '61.14.139.0/24': '4637', '89.43.76.0/24': '29119', '104.132.12.0/24': '4637', '123.30.109.0/24': '45899', '154.197.88.0/24': '209242', '185.183.120.0/24': '205820', '185.183.121.0/24': '205820', '186.33.204.0/24': '262182', '187.17.188.0/24': '273457', '194.176.32.0/24': '5522', '194.176.33.0/24': '5522', '194.176.35.0/24': '5522', '194.176.36.0/24': '5522', '202.126.159.0/24': '4637', '203.162.166.0/24': '135905', '209.211.71.0/24': '3356', '212.198.242.0/24': '21502', '212.198.243.0/24': '21502', '212.198.254.0/24': '21502', '212.198.255.0/24': '21502', '213.157.54.0/24': '8393', '222.255.25.0/24': '135905', '97.217.0.0/16': '6167', '97.218.0.0/16': '6167', '97.231.0.0/17': '6167', '97.231.128.0/18': '6167', '174.221.128.0/20': '6167', '174.221.144.0/20': '6167', '174.221.160.0/20': '6167', '174.221.176.0/20': '6167', '71.30.74.0/23': '7029', '203.176.130.0/23': '38235', '203.176.132.0/23': '38235', '203.176.134.0/23': '38235', '23.211.127.0/24': '20940', '76.191.89.0/24': '395442', '115.114.26.0/24': '4755', '121.241.64.0/24': '4755', '121.242.53.0/24': '4755', '152.91.11.0/24': '9555', '152.91.14.0/24': '9555', '154.81.9.0/24': '21859', '156.226.174.0/24': '58212', '156.226.175.0/24': '58212', '158.116.32.0/24': '397183', '195.62.48.0/24': '58212', '195.62.49.0/24': '58212', '203.197.236.0/24': '4755', '203.199.67.0/24': '4755', '203.200.33.0/24': '4755', '207.114.31.0/24': '53302', '208.71.38.0/24': '23462', '208.71.39.0/24': '23462', '209.47.176.0/24': '328867', '218.188.123.0/24': '9304', '35.130.50.0/24': '22677', '35.130.125.0/24': '20115', '47.35.18.0/24': '20115', '68.115.236.0/24': '20115', '68.187.4.0/24': '22677', '68.188.56.0/24': '22677', '68.188.108.0/24': '22677', '68.191.226.0/24': '20115', '71.14.206.0/24': '22677', '71.14.223.0/24': '22677', '75.130.12.0/24': '22677', '75.137.63.0/24': '20115', '75.140.139.0/24': '20115', '97.80.149.0/24': '20115', '97.84.44.0/24': '22677', '97.86.169.0/24': '22677', '97.86.171.0/24': '22677', '97.87.20.0/24': '22677', '97.90.111.0/24': '20115', '97.91.116.0/24': '22677', '97.91.117.0/24': '22677', '97.91.118.0/24': '22677', '97.91.119.0/24': '22677', '199.247.141.0/24': '32815', '205.200.130.0/24': '396084', '209.89.121.0/24': '394347'}
    
    rtree = ROATree(given_time)
    pref_roa = {pref: rtree.GetCoveringROAs(pref) for pref in pref_origin}    
    
    fns = []
    if USE_NETDISK:
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/ripe/')
        fns = [str(fn) for fn in path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')] #bview.20250101.0000.gz        
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/routeviews/')
        fns += [str(fn) for fn in path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')]
    
    paras = [(fn, pref_origin) for fn in fns]
    with Pool(processes=40) as pool:
        results = pool.starmap(DebugGetSpecRIBsFromOneRC, paras)
        
        union_res = defaultdict(list)
        for res in results:
            for pref, val in res.items():
                union_res[pref] += val
        
        rec = []
        for pref, val in union_res.items():
            rec.append({'PREFIX': pref, 'ROA': pref_roa[pref], '[RC,ROUTE]': val})
            
        with open('rec.json', 'w') as wf:
            json.dump(rec, wf, indent=1)

def GetAnnStatusInterfsFromOneRC(fn, given_time, sel_vps, debug_flag):
    rtree = ROATree(given_time) #should be prepared before
    dt = datetime.strptime(given_time, "%Y%m%d%H%M%S")
    prev_30min_time = (dt + timedelta(minutes=-30)).strftime('%Y%m%d%H%M%S')
    next_30min_time = (dt + timedelta(minutes=30)).strftime('%Y%m%d%H%M%S')
    rtree1 = ROATree(prev_30min_time) #should be prepared before
    rtree2 = ROATree(next_30min_time) #should be prepared before
    vp_ann_status_intfs = defaultdict(list)
    rc = fn.split('/')[5] if USE_NETDISK else fn.split('/')[-1].split('_')[0] 
    print(f'GetAnnStatusInterfsFromOneRC {rc} {given_time} begin')
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                if sel_vps and (vp not in sel_vps): continue
                if (':' in pref) or (pref == '0.0.0.0/0'): continue                
                path_list = CompressBGPRoute(path)
                if len(path_list) <= 1: continue                
                origin = path_list[-1]
                status = rtree.Validate(pref, origin)                
                status1 = 'invalid'
                if status != 'invalid': 
                    status, status1 = 'valid', 'valid'
                else: #check if valid using other roas? Check consistency in RPs!
                    tmp_status = rtree1.Validate(pref, origin)
                    if tmp_status != 'invalid': 
                        status1 = 'valid'
                        if debug_flag: print(f'{pref} {origin} valid in prev_roa')
                    else:
                        tmp_status = rtree2.Validate(pref, origin)
                        if tmp_status != 'invalid': 
                            status1 = 'valid'
                            if debug_flag: print(f'{pref} {origin} valid in next_roa')
                vp_ann_status_intfs[vp].append([status, status1, path_list[0], path_list[1]])
                #if config_para.g_is_demo and len(vp_ann_status_intfs) > 0: break
    except Exception as e:
        print(e)
    
    print(f'GetAnnStatusInterfsFromOneRC {rc} {given_time} end')
    return (rc, vp_ann_status_intfs)

#DebugGetSpecRIBs()

def GetFullVPInvalidRatiosFromOneRC(fn, given_time, sel_vps):
    rtree = ROATree(given_time)
    vp_c = defaultdict(Counter)
    rc = fn.split('/')[5] if USE_NETDISK else fn.split('/')[-1].split('_')[0]
    print(f'GetFullVPInvalidRatiosFromOneRC in {rc} begins')
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                if sel_vps and (vp not in sel_vps): continue
                if (':' in pref) or (pref == '0.0.0.0/0'): continue                
                path_list = CompressBGPRoute(path)
                if len(path_list) <= 1: continue
                origin = path_list[-1]
                status = rtree.Validate(pref, origin)
                vp_c[vp][status] += 1
    except Exception as e:
        print(e)
        
    for vp, val in vp_c.items():
        print(f'vp_c[{vp}]: {val}')
    vp_ratio = {vp : val['invalid']/sum(val.values()) for vp, val in vp_c.items()}
    print(f'GetFullVPInvalidRatiosFromOneRC in {rc} ends')
    return vp_ratio

def GetAllRoutesFromOneRC(fn):
    routes = set()
    print(f'GetAllRoutesFromOneRC {fn} begins')
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                if (':' in pref) or (pref == '0.0.0.0/0'): continue                
                path_list = CompressBGPRoute(path)
                if len(path_list) <= 1: continue
                routes.add(' '.join(path_list))
                #if len(vp_ann_status_intfs) > 0: break
    except Exception as e:
        print(e)
        
    print(f'GetAllRoutesFromOneRC {fn} ends')
    return list(routes)

def GetAllRoutes(given_time):
    #given_time = '20250517080000'
    fns = []
    #if USE_NETDISK:
    if True:
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/ripe/')
        fns = [str(fn) for fn in path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')] #bview.20250101.0000.gz        
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/routeviews/')
        fns += [str(fn) for fn in path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')]
    
    with Pool(processes=40) as pool:
        results = pool.map(GetAllRoutesFromOneRC, fns)
        
        rec = set()
        for res in results:
            rec.update(res)
        
        with open(f'{config_para.output_dir}/all_routes_{given_time}.json', 'w') as wf:
            json.dump(list(rec), wf, indent=1)

def GetFULLVPPrefRoutesFromOneRC(fn):
    date = fn.split('.')[-3] + fn.split('.')[-2] + '00'
    rc = '.'.join(fn.split('/')[-1].split('.')[:-4]) if 'tmp_rib' in fn else fn.split('/')[-2]
    rtree = ROATree(date)
    #if os.path.exists(f'{config_para.output_dir}/fullvp_pref_route_{date}_{rc}.json'): return
    
    fullvps = set()
    with open(f'{config_para.output_dir}/full_vps_{date}.json', 'r') as rf:
        data = json.load(rf)
        for val in data.values():
            for elem in val:
                if elem[1] == rc: fullvps.add(elem[0])
    
    res = defaultdict(defaultdict)
    print(f'GetAllRoutesFromOneRC {fn} begins')
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                if vp not in fullvps: continue
                if (':' in pref) or (pref == '0.0.0.0/0'): continue
                if int(pref.split('/')[-1]) > 24: continue
                path_list = CheckLoopBGPRoute(path)
                #path_list = CompressBGPRoute(path)
                if len(set(path_list)) <= 1: continue
                status = rtree.Validate(pref, path_list[-1])
                res[vp][pref] = [' '.join(path_list), status]
    except Exception as e:
        print(e)
        
    with open(f'{config_para.output_dir}/fullvp_pref_route_{date}_{rc}.json', 'w') as wf:
        json.dump(res, wf, indent=1)
    print(f'GetFULLVPPrefRoutesFromOneRC {fn} ends')
    return res

def GetFULLVPPrefRoutes(given_time):
    fns = []
    if USE_NETDISK:
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/ripe/')
        fns = [str(fn) for fn in path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')] #bview.20250101.0000.gz        
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/routeviews/')
        fns += [str(fn) for fn in path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')]
    
    with Pool(processes=20) as pool:
        results = pool.map(GetFULLVPPrefRoutesFromOneRC, fns)
        for res in results:
            pass

def GetFullVPsAndPrefOrigins(given_time):
    #full VPs can be updated once a month; pref-origins should be updated in real-time
    if os.path.exists(f'{config_para.output_dir}/full_vps_{given_time[:6]}.json') and \
        os.path.exists(f'{config_para.output_dir}/pref_origins_{given_time}.json'): return
    
    fns = []
    if USE_NETDISK:
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/ripe/')
        fns = [str(fn) for fn in path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')] #bview.20250101.0000.gz        
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/routeviews/')
        fns += [str(fn) for fn in path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')]
    res = GetRIBs(fns, 'GET-FULL-VPS+GET-PREF-ORIGINS')
    
    if not os.path.exists(f'{config_para.output_dir}/full_vps_{given_time[:6]}.json'):
        with open(f'{config_para.output_dir}/full_vps_{given_time[:6]}.json', 'w') as wf:
            rec = {}
            for key, val in res['GET-FULL-VPS'].items():
                rec[key] = [[subval[0], subval[1]] for subval in val]
            json.dump(rec, wf, indent=1)
    if not os.path.exists(f'{config_para.output_dir}/pref_origins_{given_time}.json'):
        with open(f'{config_para.output_dir}/pref_origins_{given_time}.json', 'w') as wf:
            rec = {key:list(val) for key, val in res['GET-PREF-ORIGINS'].items()}
            json.dump(rec, wf, indent=1)

def PreWorkGetFullVPsAndPrefOrigins(given_time):
    # if os.path.exists(f'{config_para.output_dir}/full_vps_{given_time}.json') and \
    #     os.path.exists(f'{config_para.output_dir}/pref_origins_{given_time}.json'): return
    
    fns = []
    if USE_NETDISK:
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/ripe/')
        fns = [str(fn) for fn in path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')] #bview.20250101.0000.gz        
        path = Path(f'{config_para.input_dir}/rib/{given_time[:4]}-{given_time[4:6]}/routeviews/')
        fns += [str(fn) for fn in path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')]
    res = GetRIBs(fns, 'GET-FULL-VPS+GET-PREF-ORIGINS')
    
    with open(f'{config_para.output_dir}/full_vps_{given_time}.json', 'w') as wf:
        rec = {}
        for key, val in res['GET-FULL-VPS'].items():
            rec[key] = [[subval[0], subval[1]] for subval in val]
        json.dump(rec, wf, indent=1)
    with open(f'{config_para.output_dir}/pref_origins_{given_time}.json', 'w') as wf:
        rec = {key:list(val) for key, val in res['GET-PREF-ORIGINS'].items()}
        json.dump(rec, wf, indent=1)
    print('Step 1 PreWorkGetFullVPsAndPrefOrigins done.')

def GetPSRFromOneRC(fn, date, as_rels):
    #print(f'begin to get full VPs from {fn}')
    vp_origin_route = {} #defaultdict(set) #(lambda:defaultdict(set))
    rc = '.'.join(fn.split('/')[-1].split('.')[:-4]) if 'tmp_rib' in fn else fn.split('/')[-2]
    rtree = ROATree(date)
    full_vps = set()
    with open('{config_para.output_dir}/full_vps_202505.json', 'r') as rf:
        data = json.load(rf)
        for val in data.values():
            for vp, tmp_rc in val:
                if tmp_rc == rc: full_vps.add(vp)
                
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                vp, vp_asn, pref, path = elems[3:7]
                if vp not in full_vps: continue
                if (':' in pref) or (pref == '0.0.0.0/0'): continue
                if int(pref.split('/')[-1]) > 24: continue
                
                path_list = CompressBGPRoute(path)
                if not path_list: continue
                if rtree.Validate(pref, path_list[-1]) =='invalid': continue
                if vp not in vp_origin_route: vp_origin_route[vp] = defaultdict(lambda:defaultdict(list))
                #vp_origin_route[(vp, path_list[-1])].add(' '.join(path_list)) #[' '.join(path_list)].add(pref)
                vp_origin_route[vp][path_list[-1]][' '.join(path_list)].append(pref)
                #if config_para.g_is_demo and len(vp_origin_route[vp]) >= 1000: break
    except Exception as e:
        print(e)
    
    psr_c = Counter()
    psr_all, psr_concerned = 0, 0
    concerned = []
    for vp, val in vp_origin_route.items():
        for origin, subval in val.items():
            psr_c[len(subval)] += 1
            if len(subval) == 1: continue
            paths = list(subval.keys())
            for i, path1 in enumerate(paths):
                for path2 in paths[i+1:]:
                    psr_all += 1
                    path1_list = path1.split(' ')
                    path2_list = path2.split(' ')
                    for i1, mid in enumerate(path1_list[1:-1]): 
                        if mid not in path2_list: continue
                        i2 = path2_list.index(mid)
                        if i2 > 0: 
                            pred1, succ1 = path1_list[i1], path1_list[i1+2]
                            pred2, succ2 = path2_list[i2-1], path2_list[i2+1]
                            if succ1 == succ2: continue
                            #succ1 != succ2, mid 是分叉点
                            pred1_rel = as_rels.GetASRelation(pred1, mid)
                            pred2_rel = as_rels.GetASRelation(pred2, mid)
                            succ1_rel = as_rels.GetASRelation(succ1, mid)
                            succ2_rel = as_rels.GetASRelation(succ2, mid)
                            if (pred1_rel == pred2_rel) and (succ1_rel == succ2_rel):
                                #目标！
                                psr_concerned += 1
                                concerned.append([mid, succ1, subval[path1], succ2, subval[path2]])
                            break
    #print(f'psr_c: {psr_c}, psr_all: {psr_all}, psr_concerned: {psr_concerned}')
    
    return psr_c, psr_all, psr_concerned, concerned

def GetPSR(fns, date):
    as_rels = AS_Relations(date)
    paras = [(fn, date, as_rels) for fn in fns]
    with Pool(processes=30) as pool:
        results = pool.starmap(GetPSRFromOneRC, paras)
        
        psr_c = Counter()
        psr_all, psr_concerned = 0, 0
        concerned = []
        for res in results:
            tmp_psr_c, tmp_psr_all, tmp_psr_concerned, tmp_concerned = res
            for key, val in tmp_psr_c.items(): psr_c[key] += val
            psr_all += tmp_psr_all
            psr_concerned += tmp_psr_concerned
            concerned = concerned + tmp_concerned
        print(f'final: psr_c: {psr_c}, psr_all: {psr_all}, psr_concerned: {psr_concerned}')
        with open(f'{config_para.output_dir}/concerned_psr.json', 'w') as wf:
            json.dump(concerned, wf, indent=1)


def ChechPSRConcernedInOneRC(fn, check):
    #print(f'begin to get full VPs from {fn}')
    check_prefs = set(check.keys())
    resolved = defaultdict(list)
                
    try:
        with subprocess.Popen(['bgpdump', '-m', fn], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            for line in proc.stdout:
                elems = line.decode('latin-1').rstrip('\n').split('|')
                if len(elems) < 6: continue
                pref, path = elems[5:7]
                if pref not in check_prefs: continue
                for link, i in check[pref]:
                    if link in path: #找到了
                        resolved[i].append((link, pref))
    except Exception as e:
        print(e)
    
    return resolved 

def ChechPSRConcerned(fns, check):
    paras = [(fn, check) for fn in fns]
    with Pool(processes=1) as pool:
        results = pool.starmap(ChechPSRConcernedInOneRC, paras)
        
        resolved = defaultdict(list)
        for res in results:
            for i, val in res.items():
                resolved[i] = resolved + val
        print(f'i: {i}')
        with open(f'{config_para.output_dir}/psr_resolved.json', 'w') as wf:
            json.dump(resolved, wf, indent=1)
        