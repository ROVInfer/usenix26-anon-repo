
import argparse
import pandas as pd
import numpy as np
import json
import os
import sys
from tqdm import tqdm
from config_para import config_para
from fire_cp import calculate_time

def calculate_hdi_width(samples, hdi_prob=0.94):
    n = len(samples)
    if n == 0:
        return 1.0 # 没数据，宽度最大，Conf为0
    
    sorted_data = np.sort(samples)
    interval_idx_inc = int(np.floor(hdi_prob * n))
    n_intervals = n - interval_idx_inc
    
    # 向量化计算所有可能的 94% 区间宽度
    # interval_width[i] = sorted_data[i + interval_idx_inc] - sorted_data[i]
    if n_intervals <= 0:
        # 样本太少，直接取最大减最小
        return sorted_data[-1] - sorted_data[0]
        
    widths = sorted_data[interval_idx_inc:] - sorted_data[:n_intervals]
    return widths.min()

def generate_classification():
    CONFIDENCE_THRESHOLD = 0.5
    EEP_ROV_THRESHOLD = 0.7      # EEP > 0.7 => ROV
    EEP_NONROV_THRESHOLD = 0.3   # EEP < 0.3 => Non-ROV

    input_csv = f"{config_para.output_dir}/mcmc_samples_{calculate_time}.csv"
    input_map = f"{config_para.output_dir}/serialed_asns_{calculate_time}.json"
    
    out_rov_std = f"{config_para.output_dir}/rov_intfs_{calculate_time}.json"
    out_nonrov_std = f"{config_para.output_dir}/nonrov_intfs_{calculate_time}.json"
    out_rov_rs = f"{config_para.output_dir}/rov-route-server_{calculate_time}.json"
    out_nonrov_rs = f"{config_para.output_dir}/nonrov-route-server_{calculate_time}.json"

    with open(input_map, 'r') as f:
        var_names = json.load(f)
    print(f"Loaded {len(var_names)} variable names.")
        
    df = pd.read_csv(input_csv)
    print(f"Loaded MCMC samples: {df.shape}")

    # 验证维度
    if df.shape[1] != len(var_names):
        print(f"[Warning] Column mismatch! CSV: {df.shape[1]}, Names: {len(var_names)}")

    list_rov_std, list_nonrov_std = [], []
    list_rov_rs, list_nonrov_rs = [], []
    
    stats = {
        "total": 0,
        "discarded_low_conf": 0,
        "discarded_mixed": 0,
        "rov_std": 0, "nonrov_std": 0,
        "rov_rs": 0, "nonrov_rs": 0
    }

    for i in tqdm(range(len(var_names)), desc="Processing"):
        if i >= df.shape[1]: 
            break
            
        name = str(var_names[i]).strip()
        samples = df.iloc[:, i].values
        
        mean_z = np.mean(samples)
        eep = 1.0 - mean_z
        
        hdi_w = calculate_hdi_width(samples, hdi_prob=0.94)
        confidence = 1.0 - hdi_w
        
        stats["total"] += 1
        
        if confidence < CONFIDENCE_THRESHOLD:
            stats["discarded_low_conf"] += 1
            continue 
            
        is_rov = False
        is_nonrov = False
        
        if eep > EEP_ROV_THRESHOLD:
            is_rov = True
        elif eep < EEP_NONROV_THRESHOLD:
            is_nonrov = True
        else:
            stats["discarded_mixed"] += 1
            continue

        is_rs_node = name.startswith('-') and ('+RS' in name)
        if is_rs_node:
            if is_rov:
                list_rov_rs.append(name)
                stats["rov_rs"] += 1
            elif is_nonrov:
                list_nonrov_rs.append(name)
                stats["nonrov_rs"] += 1
        else:
            if is_rov:
                list_rov_std.append(name)
                stats["rov_std"] += 1
            elif is_nonrov:
                list_nonrov_std.append(name)
                stats["nonrov_std"] += 1

    print(f"Total Groups Processed: {stats['total']}")
    print(f"Discarded (Low Confidence < 0.5): {stats['discarded_low_conf']}")
    print(f"Discarded (Ambiguous 0.3-0.7): {stats['discarded_mixed']}")
    print(f"[Standard] ROV (Enforcing): {stats['rov_std']}")
    print(f"[Standard] Non-ROV: {stats['nonrov_std']}")
    print(f"[RouteServer] ROV: {stats['rov_rs']}")
    print(f"[RouteServer] Non-ROV: {stats['nonrov_rs']}")

    def save_json(data, filename):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=1)

    save_json(list_rov_std, out_rov_std)
    save_json(list_nonrov_std, out_nonrov_std)
    save_json(list_rov_rs, out_rov_rs)
    save_json(list_nonrov_rs, out_nonrov_rs)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FIRE Control Plane Inference")
    
    parser.add_argument('--input_dir', type=str, default='../sample_input', 
                        help='Directory containing inputs')
    parser.add_argument('--output_dir', type=str, default='../sample_output',
                        help='Directory to save outputs')
    args = parser.parse_args()

    config_para.input_dir = args.input_dir
    config_para.output_dir = args.output_dir
    generate_classification()
    