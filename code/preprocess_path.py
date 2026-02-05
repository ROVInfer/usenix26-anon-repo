
import argparse
import json
import numpy as np
import sys
from glob import glob
from as_relations import AS_Relations
import os
from scipy import sparse

from fire_cp import calculate_time
from config_para import config_para

FOCUS_INTERFACE = True #False #

def DealMOASInPath(path_list, as_rels):
    res = []
    rel_priority = {'SAME': 3, 'SIBLING': 2, 'PROVIDER': 1, 'PEER': 1, 'CUSTOMER': 1, 'UNKNOWN': 0}
    for i, elem in enumerate(path_list):
        if '_' not in elem:
            res.append(elem)
            continue
        cur = elem.split('_')
        prev, succ = [], []
        if i > 0:
            prev = [path_list[i-1].strip('-+')] if '_' not in path_list[i-1] else path_list[i-1].split('_')
        if i < len(path_list) - 1:
            succ = [path_list[i+1].strip('-+')] if '_' not in path_list[i+1] else path_list[i+1].split('_')
        flag = {}
        for subcur in cur:
            prev_rels = [as_rels.GetASRelationIncludeSibling(subprev, subcur) for subprev in prev] if prev else []
            succ_rels = [as_rels.GetASRelationIncludeSibling(subcur, subsucc) for subsucc in succ] if succ else []
            prev_rel_flag = max([rel_priority[rel] for rel in prev_rels]) if prev_rels else 0
            succ_rel_flag = max([rel_priority[rel] for rel in succ_rels]) if succ_rels else 0
            flag[subcur] = str(prev_rel_flag)+str(succ_rel_flag)
        sel = max(flag.items(), key=lambda x:(x[1], as_rels.GetCCSize(x[0])))
        res.append(sel[0])
    return res

def DealDuplicateHopsInPath(path_list):
    res = []
    for elem in path_list:
        if res:
            k = -1
            for k in range(len(res)-1, -1, -1):
                if res[k][0] != '-': break
            if elem.strip('+') == res[k].strip('+'): continue #去除连续重复跳
        if elem in res: #loop
            if elem == '-1': res.append(elem) #IXP hop，保留
            else:
                if elem[0] == '-': 
                    res.append(elem)
                    continue #IXP route server，保留
                prev_i = res.index(elem)
                if len(res) - prev_i - 1 <= 1: #两个相同的AS跳中间只有一个不同的AS，这里认为了mapping error? 去掉
                    res = res[:prev_i+1]
                else:
                    return []
        else: res.append(elem)
    return res

def DealIXPHopInPath(path_list):
    res = []
    for i, elem in enumerate(path_list):
        if elem != '-1': #'-1' 跳略过，只对后面的接口有参考
            if i > 0 and path_list[i-1] == '-1':
                if elem[0] != '-': res.append('+'+elem) #表示和上一跳的接口经过IXP（rs未知）
                else: res.append(elem) #后面有明确的经过rs，这里还是按rs算
            else: res.append(elem)
    return res

def RefinePath(path, as_rels):
    path_list = []
    prev_ixp = False
    for elem in path.split(' '):
        if elem == '*': continue
        if elem == '-1':
            prev_ixp = True
            continue
        if elem[0] == '-':            
            t1, t2 = elem.split('+')
            path_list.append(t1)
            path_list.append('+'+t2)
            continue
        if prev_ixp and elem[0] != '+': elem = '+'+elem
        path_list.append(elem)
        prev_ixp = False
    path_list = DealDuplicateHopsInPath(path_list)
    path_list = DealMOASInPath(path_list, as_rels)
    path_list = DealDuplicateHopsInPath(path_list) #再次处理可能的重复跳
    path_list = DealIXPHopInPath(path_list)
    return path_list

def ResolveASNPathToIntfPath(path_list, as_rels):
    tmp = []
    prev_rel = 'PROVIDER' #先暂定PEER
    last_hop = -1 if path_list[-1].strip('-+').isdigit() else -2
    for i, cur_asn in enumerate(path_list[:last_hop]): #计算到倒数第三个和倒数第二个的关系
        if cur_asn[0] == '-':
            tmp.append('I'+cur_asn[1:]+'-RS') #rs
            prev_rel = 'PEER'
            continue
        next_asn = path_list[i+1]
        rel = 'UNKNOWN'
        if next_asn[0] == '-' or next_asn[0] == '+': rel = 'PEER'
        else: rel = as_rels.GetASRelation(cur_asn.strip('+'), next_asn)
        if rel == 'UNKNOWN':
            break
        else:
            tmp.append(cur_asn.strip('-+')+'-'+rel)
            prev_rel = rel
    if last_hop == -2: 
        if path_list[-1] != 'UNKNOWN': 
            #tmp.append(path_list[-2].strip('-+')+'-'+path_list[-1].strip('-+')) #注意，接口类型的path就没有最后一跳了，截止到倒数第二跳和它和最后一跳的关系为止
            tmp.append(path_list[-2]+'-'+path_list[-1]) #注意，接口类型的path就没有最后一跳了，截止到倒数第二跳和它和最后一跳的关系为止
        else: 
            #tmp.append(path_list[-2].strip('-+')+'-'+'PEER')
            tmp.append(path_list[-2]+'-'+'PEER')
    #检查valley-free，主要过滤mapping错误
    downward_part = False
    semi_downward_part = False
    for i, elem in enumerate(tmp):
        rel = elem.split('-')[-1]
        if downward_part and rel != 'CUSTOMER': return []
        if semi_downward_part and rel == 'PROVIDER': return []
        if rel == 'PEER': semi_downward_part = True
        if rel == 'CUSTOMER': downward_part = True
    return tmp
    
def PreprocessFilePaths(rfns, as_rels, wfn=None): #1.把字符串路径变为list类型路径；2. 如果要接口，加上接口类型
    res = set()
    for rfn in rfns:
        with open(rfn, 'r') as rf:
            data = json.load(rf)
            paths = None
            if isinstance(data, list): paths = data #如果直接是route list，复制
            elif isinstance(data, dict):
                paths = {route for routes in data.values() for route in routes} #如果是{pref:paths} (一般是nonrovseg-fn)
            else:
                print(f'{rfn} format not correct!')
                sys.exit()
            for path in paths:
                path_list = RefinePath(path, as_rels) #返回的是无重复、无loop、无MOAS的序列
                if path.count('-') > 0:
                    a = 1
                if len(path_list) <= 1: continue #只有源AS的忽略
                if not FOCUS_INTERFACE:
                    path_list = [elem.strip('-+') for elem in path_list if elem != '-1']
                    if not path_list[-1].isdigit(): res.add(' '.join(path_list[:-1])) #ROV路径段最后一个元素是接口类型，去掉
                    else: res.add(' '.join(path_list))
                else:
                    tmp = ResolveASNPathToIntfPath(path_list, as_rels)
                    if tmp: res.add(' '.join(tmp))
                    a = 1
    
    rec = [path.split(' ') for path in res]
    if wfn:
        with open(wfn, 'w') as wf:
            json.dump(rec, wf, indent=1)
    return rec

def GetASNsOnlyInOneKindSegsAndFilterSegs(rov_segs, nonrov_segs):
    rov_covered_asns = {elem for seg in rov_segs for elem in seg}
    nonrov_covered_asns = {elem for seg in nonrov_segs for elem in seg}
    asns_only_in_rov_segs = rov_covered_asns.difference(nonrov_covered_asns)
    asns_only_in_nonrov_segs = nonrov_covered_asns.difference(rov_covered_asns)
    filtered_rov_segs = [seg for seg in rov_segs if not any(asn in asns_only_in_rov_segs for asn in seg)]
    filtered_nonrov_segs = [seg for seg in nonrov_segs if not all(asn in asns_only_in_nonrov_segs for asn in seg)]
    return asns_only_in_rov_segs, asns_only_in_nonrov_segs, filtered_rov_segs, filtered_nonrov_segs
    
def IsSublist(big, small):
    return any(big[i:i+len(small)] == small for i in range(len(big) - len(small) + 1))
    
def GenerateYsObserved(rov_segs, nonrov_segs):
    ys_observed = [1 for _ in range(len(rov_segs))] + [0 for _ in range(len(nonrov_segs))]
    return np.array(ys_observed)

def GenerateYXRelation(segs, asns):
    as_index = {as_num: idx for idx, as_num in enumerate(asns)}
    yx_relation = np.zeros((len(segs), len(asns)), dtype=int)
    
    for i, seg in enumerate(segs):
        for asn in seg:
            yx_relation[i, as_index[asn]] = 1
    return yx_relation

def ProcessPathsAndGenModelInputs(todo, given_time):
    label = '_'.join(todo.keys())
    last_dir = 'intfs' if FOCUS_INTERFACE else 'asns'
    if os.path.exists(f'{config_para.output_dir}/yx_relation_{given_time}.npy'): return
    
    as_rels = AS_Relations(given_time)
    rov_segs, nonrov_segs = [], []
    for _type, val in todo.items():
        rov_fns, nonrov_fns = val
        rov_fns = [rov_fn for rov_fn in rov_fns if os.path.exists(rov_fn)]
        if rov_fns:
            wfn = f'{config_para.output_dir}/v2_resolved_rov_segs_{_type}_{given_time}.json'
            rov_segs += PreprocessFilePaths(rov_fns, as_rels, wfn)
        nonrov_fns = [nonrov_fn for nonrov_fn in nonrov_fns if os.path.exists(nonrov_fn)]
        if nonrov_fns:
            wfn = f'{config_para.output_dir}/v2_resolved_nonrov_segs_{_type}_{given_time}.json'
            nonrov_segs += PreprocessFilePaths(nonrov_fns, as_rels, wfn)
    rov_covered_asns = {elem for seg in rov_segs for elem in seg}
    nonrov_covered_asns = {elem for seg in nonrov_segs for elem in seg}
    print(f'rov_segs: {len(rov_segs)}, nonrov_segs: {len(nonrov_segs)}')
    print(f'rov_covered_asns: {len(rov_covered_asns)}, nonrov_covered_asns: {len(nonrov_covered_asns)}')
    
    final_rov_segs = rov_segs
    final_nonrov_segs = nonrov_segs
        
    ys_observed = GenerateYsObserved(final_rov_segs, final_nonrov_segs)
    if not os.path.exists(f'{config_para.output_dir}/'): os.mkdir(f'{config_para.output_dir}/')
    np.save(f'{config_para.output_dir}/ys_observed_{given_time}.npy', ys_observed)
    all_asns = {elem for seg in final_rov_segs for elem in seg}
    all_asns.update({elem for seg in final_nonrov_segs for elem in seg})
    all_asns = list(all_asns)
    with open(f'{config_para.output_dir}/serialed_asns_{given_time}.json', 'w') as wf:
        json.dump(all_asns, wf, indent=1)
    yx_relation = GenerateYXRelation(final_rov_segs + final_nonrov_segs, all_asns)
    np.save(f'{config_para.output_dir}/yx_relation_{given_time}.npy', yx_relation)

def dense_to_sparse_components(dense_matrix):
    rows, cols = np.nonzero(dense_matrix) 
    data = dense_matrix[rows, cols]
    shape = dense_matrix.shape 
    sparse_matrix = sparse.csr_matrix((data, (rows, cols)), shape=shape)
    return rows, cols, data, shape, sparse_matrix

def ProcessPathsAndGenModelInputs_v2(rov_fns, nonrov_fns, given_time):
    as_rels = AS_Relations(given_time)
    rov_segs, nonrov_segs = [], []
    
    if rov_fns:
        wfn = f'{config_para.output_dir}/v2_resolved_rov_segs_{given_time}.json'
        rov_segs = PreprocessFilePaths(rov_fns, as_rels, wfn)
    nonrov_fns = [nonrov_fn for nonrov_fn in nonrov_fns if os.path.exists(nonrov_fn)]
    if nonrov_fns:
        wfn = f'{config_para.output_dir}/v2_resolved_nonrov_segs_{given_time}.json'
        nonrov_segs = PreprocessFilePaths(nonrov_fns, as_rels, wfn)
    
    rov_covered_intfs = {elem for seg in rov_segs for elem in seg}
    nonrov_covered_intfs = {elem for seg in nonrov_segs for elem in seg}
    rov_covered_asns = {elem.split('-')[0] for elem in rov_covered_intfs}
    nonrov_covered_asns = {elem.split('-')[0] for elem in nonrov_covered_intfs}
    print(f'rov_segs: {len(rov_segs)}, nonrov_segs: {len(nonrov_segs)}')
    print(f'rov_covered_intfs: {len(rov_covered_intfs)}, nonrov_covered_intfs: {len(nonrov_covered_intfs)}, \
        all_intfs: {len(rov_covered_intfs | nonrov_covered_intfs)}')
    print(f'rov_covered_asns: {len(rov_covered_asns)}, nonrov_covered_asns: {len(nonrov_covered_asns)}, \
        all_asns: {len(rov_covered_asns | nonrov_covered_asns)}')
    
    ys_observed = GenerateYsObserved(rov_segs, nonrov_segs)
    np.save(f'{config_para.output_dir}/ys_observed_{given_time}.npy', ys_observed)
    all_asns = {elem for seg in rov_segs for elem in seg}
    all_asns.update({elem for seg in nonrov_segs for elem in seg})
    all_asns = list(all_asns)
    with open(f'{config_para.output_dir}/serialed_asns_{given_time}.json', 'w') as wf:
        json.dump(all_asns, wf, indent=1)
    yx_relation = GenerateYXRelation(rov_segs + nonrov_segs, all_asns)
    # rows, cols, data, shape, sparse_matrix = dense_to_sparse_components(yx_relation)
    # sparse.save_npz(f"{config_para.output_dir}/matrix.npz", sparse_matrix)
    yx_relation = GenerateYXRelation(rov_segs + nonrov_segs, all_asns)
    np.save(f'{config_para.output_dir}/yx_relation_{given_time}.npy', yx_relation)
    
def MainFunc():
    global calculate_time
        
    rov_fns = [str(fn) for fn in glob(f'{config_para.output_dir}/rov_segs_from_ihrd_cp_*.json')]
    rov_fns += [str(fn) for fn in glob(f'{config_para.output_dir}/rov_segs_from_ihrd_dp_*.json')]
    nonrov_fns = [str(fn) for fn in glob(f'{config_para.output_dir}/all_invalid_routes_*.json')]
    nonrov_fns += [str(fn) for fn in glob(f'{config_para.output_dir}/nonrov_segs_from_ihrd_dp_*.json')]
    
    ProcessPathsAndGenModelInputs_v2(rov_fns, nonrov_fns, calculate_time)
        
if __name__ == '__main__':    
    parser = argparse.ArgumentParser(description="FIRE Control Plane Inference")
    
    parser.add_argument('--input_dir', type=str, default='../sample_input', 
                        help='Directory containing inputs')
    parser.add_argument('--output_dir', type=str, default='../sample_output',
                        help='Directory to save outputs')
    args = parser.parse_args()

    config_para.input_dir = args.input_dir
    config_para.output_dir = args.output_dir
    
    MainFunc()
