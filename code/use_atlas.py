
from ripe.atlas.cousteau import (
  Ping,
  Traceroute,
  Dns,
  AtlasSource,
  AtlasRequest,
  AtlasCreateRequest,
  AtlasResultsRequest,
  AtlasLatestRequest,
  ProbeRequest
)
import requests
import os
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from multiprocessing import Pool
import time
from ip2as import IP2AS
from glob import glob
from as_relations import AS_Relations
from config_para import config_para

ATLAS_MSM_ID = '' #need to load msm_id

class ATLAS_PARAS:
    def __init__(self):
        self.my_keys = [ATLAS_MSM_ID]
        self.MAX_PROBES_PER_DST_ONCE = 25
        self.MAX_MSMS_ONCE = 100
        self.MAX_TASKS_PER_KEY = 16500

atlas_para = ATLAS_PARAS()        

def FetchOriAtlasProbeInfo(given_time):
    ori_atlas_probe_fn = f'{config_para.output_dir}/atlas_probes_original_data_{given_time[:6]}01.json'
    probes = []
    if not os.path.exists(ori_atlas_probe_fn):
        url = "https://atlas.ripe.net/api/v2/probes/"
        params = {
            "format": "json",
            "page_size": 500  # Maximum page size supported by the API
        }
        while url:
            print(f"Fetching: {url}")
            response = requests.get(url, params=params)
            if response.status_code != 200:
                print(f"Failed to fetch data: {response.status_code}, {response.text}")
                break
            data = response.json()
            probes.extend(data['results'])
            url = data['next']  # API provides the URL for the next page
        with open(ori_atlas_probe_fn, 'w') as wf:
            json.dump(probes, wf, indent=1) #2025.5.6改，原来写的是data，但明显不对？
    else:
        with open(ori_atlas_probe_fn, 'r') as rf: probes = json.load(rf)
    
    return probes

def FetchFinalProbes(given_time, fetch_probe_ids=False):
    atlas_probeid_fn = f'{config_para.output_dir}/atlas_probeids_{given_time[:6]}01.json'
    if os.path.exists(atlas_probeid_fn):
        with open(atlas_probeid_fn, 'r') as rf:
            data = json.load(rf) #probeid_probe_asn[elem["id"]] = [elem["address_v4"], elem["asn_v4"]]
            if fetch_probe_ids: return data
            asn_probes = defaultdict(list)
            for addr, asn in data.values():
                asn_probes[asn].append(addr)
            return asn_probes
    else:
        data = FetchOriAtlasProbeInfo(given_time)
        asn_probes = defaultdict(list)
        probeid_probe_asn = {}
        for elem in data:
            if True: #不在这里选择connected状态，因为probe状态变化频率很高，需要在使用时实时选择connected的probe
                if isinstance(elem["asn_v4"], int) and isinstance(elem["address_v4"], str):
                    asn_probes[elem["asn_v4"]].append(elem["address_v4"])
                    if isinstance(elem["id"], int):
                        probeid_probe_asn[elem["id"]] = [elem["address_v4"], elem["asn_v4"]]
        with open(atlas_probeid_fn, 'w') as wf:
            json.dump(probeid_probe_asn, wf, indent=1)
        if fetch_probe_ids: return probeid_probe_asn
        else: return asn_probes
        
def FetecAllCurrentConnectedASNProbes(use_last_results=False):
    fn = f'{config_para.sample_mid_dir}/atlas_current_connected_probes.json' if config_para.sample_mid_dir else f'{config_para.output_dir}/atlas_current_connected_probes.json'
    if use_last_results and os.path.exists(fn):
        with open(fn, 'r') as rf:
            data = json.load(rf)
            return data
        
    url = "https://atlas.ripe.net/api/v2/probes/"
    params = {
        "format": "json",
        "status_name": "Connected",
        "page_size": 500  # Maximum page size supported by the API
    }
    asn_probes = defaultdict(list)
    while url:
        print(f"Fetching: {url}")
        response = requests.get(url, params=params)
        if response.status_code != 200:
            print(f"Failed to fetch data: {response.status_code}, {response.text}")
            break
        data = response.json()
        for elem in data['results']:
            if isinstance(elem["asn_v4"], int) and isinstance(elem["address_v4"], str):
                asn_probes[str(elem['asn_v4'])].append(elem['address_v4'])
        url = data['next']  # API provides the URL for the next page    
    with open(fn, 'w') as wf:
        json.dump(asn_probes, wf, indent=1)
        
    return asn_probes
    
def Create1TracerouteTask(dst_ip, probe_asns, atlas_key):    
    sources = [AtlasSource(type="asn", value=int(asn), requested=1, tags={"include": ["system-ipv4-works"]}) for asn in probe_asns]
    traceroute = Traceroute(af=4, target=dst_ip, description=f'traceroute ip {dst_ip}', protocol='ICMP')
    for _ in range(2): #尝试两次
        atlas_request = AtlasCreateRequest(
            #start_time=datetime.utcnow() + timedelta(seconds=20 + random.randint(0, 10)),
            start_time=datetime.utcnow(),
            key=atlas_key,
            measurements=[traceroute],
            sources=sources,
            is_oneoff=True
        )
        (is_success, response) = atlas_request.create()
        print('create_task', dst_ip, is_success, response)
        if is_success:
            return response['measurements'][0] #返回msm_id
        time.sleep(20)
    
    return -1 #两次都失败

def FetchMsmResult(msm_id, given_time, rec_dir, fn=None):
    if not fn:
        fn = rec_dir + f'{given_time}/{msm_id}.json'
    if os.path.exists(fn):
        with open(fn, 'r') as rf:
            data = json.load(rf)
            return data
    url_path = f'/api/v2/measurements/{msm_id}/'
    for i in range(20):
        msm_info_request = AtlasRequest(**{'url_path': url_path})
        (is_success, msm_info) = msm_info_request.get()
        if not is_success:
            print(f'fetch measurement {msm_id} failed!')
            break
        if 'description' not in msm_info:
            print(f'[ERROR] measurement {msm_id} msm_info: {msm_info}')
            break
        status = msm_info['status']['name']
        if (status == 'Stopped') or (status == 'Failed'):
            kwargs = {"msm_id": msm_id}
            (is_success, res) = AtlasResultsRequest(**kwargs).create()
            if is_success:
                print(f'fetch measurement {msm_id} succeed!')
                with open(fn, 'w') as wf:
                    json.dump(res, wf, indent=1)
                return res
            return None
        
        print(f'measurement {msm_id} status: {status}, already waited for {i} minutes.')
        if 'No suitable probes' in status: return None
        time.sleep(60)
        
    print(f'fetch measurement {msm_id} timeout.')
    return None
    
def Launch1TracerouteTask(dst_ip, probe_asns, given_time, rec_dir, atlas_key):
    msm_id = Create1TracerouteTask(dst_ip, probe_asns, atlas_key)
    if isinstance(msm_id, int) and msm_id > 0:
        os.system(f'touch {rec_dir}{given_time}/msm_id_{msm_id}')
        FetchMsmResult(msm_id, given_time, rec_dir)

def GetMyTraceMsmIdsInSpecTime(atlas_key, start_time, end_time):    
    headers = {'Authorization': f'Key {atlas_key}'}
    params = {
        'start_time__gt': start_time.timestamp(),
        'stop_time__lt': end_time.timestamp(),
        'type': 'traceroute',
        #'status': 'Success'#,  # 可根据需要过滤不同的状态
        'is_oneoff': True,
        'af': 4,
        'mine': True,
        'page_size': 500,  # 获取的结果数量，可以调整
        'page': 1
    }    
    all_results = []
    while True:
        response = requests.get('https://atlas.ripe.net/api/v2/measurements/my', params=params, headers=headers)
        data = response.json()
        results = data.get('results', [])
        if not results:
            break
        all_results.extend(elem['id'] for elem in results if 'id' in elem)
        print(f"Fetched {len(results)} results (total so far: {len(all_results)})")
        if len(results) < params['page_size']:
            break  # 最后一页
        params['page'] += 1
        time.sleep(1)  # 避免触发速率限制
    return all_results

def QueryProbeASNOnline(probe_id):
    # API 端点
    url = f"https://atlas.ripe.net/api/v2/probes/{probe_id}/"
    
    # 发送请求
    response = requests.get(url)
    
    # 检查请求是否成功
    if response.status_code != 200:
        print(f"Error: Unable to fetch data for Probe ID {probe_id}")
        return None
    
    # 解析 JSON 数据
    probe_data = response.json()
    
    # 提取 AS 信息
    asn_v4 = probe_data.get("asn_v4")
    
    return str(asn_v4)

def LauchTracerouteTasks(dst_ip_probes, given_time, rec_dir, atlas_key, only_check=True): 
    print(f'total liveips #: {len(dst_ip_probes)}')   
    
    paras = [(dst_ip, list(val[0]), given_time, rec_dir, atlas_key) for dst_ip, val in dst_ip_probes.items() if len(val[0]) > 0]
    tasks_num = sum([len(val[0]) for val in dst_ip_probes.values()])
    print(f'to launch dst_ips #: {len(paras)}, tasks_num: {tasks_num}')
    #print(not_found_probe_ids)
    
    if not os.path.exists(f'{rec_dir}'): os.mkdir(f'{rec_dir}')
    if not os.path.exists(f'{rec_dir}{given_time}/'): os.mkdir(f'{rec_dir}{given_time}/')
    if only_check: return 
        
    pool = Pool(processes=20)
    pool.starmap(Launch1TracerouteTask, paras)
    pool.close()
    pool.join()

def ResolveTracerouteResult(fn, probeid_probe_asn):    
    res = []
    with open(fn, 'r') as rf:
        data = json.load(rf)
        for elem in data:
            if any(keyword not in elem for keyword in ['src_addr', 'dst_addr', 'result']): continue
        
            tmp = probeid_probe_asn.get(str(elem["prb_id"]), None)
            probe = str(tmp[1]) if tmp else None
            dst_ip = elem['dst_addr']
            ip_list = []
            multi_resp_in1hop = 'no-multi-resp'
            reach_dst = 'not-reach-dst'
            for hop in elem['result']:
                if 'result' not in hop: continue
                tmp_hop_set = {subelem['from'] for subelem in hop['result'] if 'from' in subelem}
                if len(tmp_hop_set) == 1: ip_list.append(list(tmp_hop_set)[0])
                else:
                    #print(f'tmp_hop_set: {tmp_hop_set}')
                    ip_list.append('*')
                    if tmp_hop_set: multi_resp_in1hop = 'multi-resp'
            if ip_list[-1] == dst_ip: reach_dst = 'reach-dst'
            res.append([dst_ip, probe, ip_list, multi_resp_in1hop, reach_dst])
    return res

def ResolveTracerouteResultToASPaths(fn, probeid_probe_asn, ip2as, debug=False):
    res = ResolveTracerouteResult(fn, probeid_probe_asn)
    rec = defaultdict(defaultdict)
    probe_fst_asn_differ_num, total = 0, 0
    for dst_ip, probe, ip_list, multi_resp_in1hop, reach_dst in res:
        if probe == '203969':
            a = 1
        asn_list = []
        prev_ixp = False
        for ip in ip_list:
            asn = '*' if ip == '*' else '_'.join(ip2as.MapIP2AS(ip))
            if not asn: asn = '*'
            if asn == 'IXP': prev_ixp = True
            else:
                if asn.isdigit() and prev_ixp: asn = '+'+asn
                prev_ixp = False
                asn_list.append(asn)
        if asn_list:
            if asn_list[0] == '*' and not probe: continue
            elif asn_list[0] == '*': asn_list[0] = probe
            elif not probe: probe = asn_list[0]
            if probe != asn_list[0]:
                # print(f'[1] fn: {fn}, probe: {probe}')
                # print(asn_list)
                # print(ip_list)
                # print('')
                probe_fst_asn_differ_num += 1
            total += 1
            rec[dst_ip][probe] = [' '.join(asn_list), multi_resp_in1hop, reach_dst]
    #print(f'total: {total}, probe_fst_asn_differ_num: {probe_fst_asn_differ_num}')
    return rec

def CompressTraceroutePath(path, as_rels):
    path_list = [elem for elem in path.split(' ') if elem != '*']
    r1 = []
    for elem in path_list:
        if elem not in r1: r1.append(elem)
    r2 = []
    for i, elem in enumerate(r1):
        if '_' not in elem:
            r2.append(elem)
            continue
        prev_hop = r1[i-1] if i > 0 else None
        succ_hop = r1[i+1] if i < len(r1)-1 else None
        score = {}
        for subelem in elem.split('_'):
            prev_rel = as_rels.GetASRelationIncludeSibling(prev_hop, elem)
            succ_rel = as_rels.GetASRelationIncludeSibling(elem, succ_hop)
            if prev_rel == 'SAME' or succ_rel == 'SAME':
                score[subelem] = 100
            elif (prev_rel == 'PROVIDER' and succ_rel != 'UNKNOWN') or \
                (prev_rel != 'UNKNOWN' and succ_rel == 'CUSTOMER'):
                    score[subelem] = 50
            else: score[subelem] = 0
        r2.append(max(score.items(), key=lambda x:(x[1], as_rels.GetCCSize(x[0])))[0])
    return ' '.join(r2)

def ResolveTracerouteRes(work_dir, given_time, debug=False, discard_last_hop=False, use_backupdirs=False):
    wfn = work_dir + f'{given_time}_resolved.json' if not debug else work_dir + f'{given_time}_resolved_debug.json'
    #if os.path.exists(wfn): return wfn
    
    ip2as = IP2AS(given_time)
    probeid_probe_asn = FetchFinalProbes(given_time, True)
    as_rels = AS_Relations(given_time)
    
    res = defaultdict(defaultdict)
    #debug_tasks = Counter()
    fns = glob(work_dir + f'backup*/{given_time}/*.json') if use_backupdirs else glob(work_dir + f'{given_time}/*.json')
    for fn in fns:
        msm_id = fn.split('/')[-1].split('.')[0]
        tmp = ResolveTracerouteResultToASPaths(fn, probeid_probe_asn, ip2as, debug) #tmp[dst_ip][probe] = [asn_path, multi_resp_in1hop, reach_dst]
        for dst_ip, val in tmp.items():
            for probe, subval in val.items():
                asn_path, multi_resp_in1hop, reach_dst = subval
                if discard_last_hop and reach_dst: asn_path = ' '.join(asn_path.split(' ')[:-1])
                path1 = CompressTraceroutePath(asn_path, as_rels)
                if not debug: res[dst_ip][probe] = [path1, multi_resp_in1hop, reach_dst]
                else:
                    dst_pref, dst_asn = ip2as.MapIP2AS(dst_ip, True)
                    res[dst_ip][probe] = [path1, multi_resp_in1hop, reach_dst, msm_id, dst_pref, dst_asn]
    # show = {key:val for key, val in debug_tasks.items() if val > 1}
    # print(show)
    with open(wfn, 'w') as wf:
        json.dump(res, wf, indent=1)
    return wfn
                
def CheckIfASHasConnectedProbes(asn):
    url = "https://atlas.ripe.net/api/v2/probes/"
    params = {
        "format": "json",
        "asn_v4": int(asn),
        "status_name": "Connected"
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:            
        data = response.json()
        return data['count'] > 0
