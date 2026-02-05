
import argparse
import torch
import numpy as np
import altair as alt
from tqdm import tqdm
import pandas as pd
import random as rand
import os
import sys
from config_para import config_para
from fire_cp import calculate_time

# 设置设备：自动检测 CUDA
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"[INFO] Running on device: {device}")


alt.data_transformers.enable('default', max_rows=None)

def log_likelihood(D0, D1, N):
    """
    计算全量数据的对数似然。
    D0: 观测到非法路由的路径矩阵 (Path x Node)
    D1: 未观测到非法路由(被过滤)的路径矩阵 (Path x Node)
    N:  节点不过滤(Permit)的概率向量
    """
    # 加上极小值 1e-10 防止 log(0)
    log_N = torch.log(N + 1e-10).float()
    
    # LL0: 路径通了 = 所有节点都通过
    LL0 = torch.matmul(D0, log_N)
    LL0_s = LL0.sum()
    
    # LL1: 路径断了 = 1 - (所有节点都通过)
    # log(1 - exp(sum(log_N)))
    inner = torch.matmul(D1, log_N)
    # clamp max=0 防止 exp(>0) 导致 1-exp 变负数
    LL1 = torch.log(1 - torch.exp(inner).clamp(max=0.99999999) + 1e-10)
    
    return LL0_s, LL1

def log_likelihood_update(LL0_s, LL1, N, N_, node, D0, D1):
    """
    增量更新似然函数，避免全量重算。
    """
    # 1. 更新 LL0_s (标量)
    # 只有经过 node 的路径才会改变
    # D0[:, node] 是一个 mask，表示哪些路径经过该节点
    # 增量 = D0_paths * (log(New) - log(Old))
    diff = torch.log(N_[node] + 1e-10) - torch.log(N[node] + 1e-10)
    LL0_s_new = LL0_s + D0[:, node].sum() * diff

    # 2. 更新 LL1 (向量)
    # 只有经过 node 的 D1 路径需要更新
    LL1_new = LL1.clone()
    
    # 找出经过该 node 的 D1 路径索引
    affected_indices = (D1[:, node] == 1).nonzero(as_tuple=True)[0]
    
    if len(affected_indices) > 0:
        # 只提取受影响的子矩阵进行重算，比全量快
        subset_D1 = D1[affected_indices, :]
        
        # 重新计算这些路径的概率
        # 注意：这里我们用 N_ (新状态)
        inner = torch.matmul(subset_D1.float(), torch.log(N_).float())
        LL1_new[affected_indices] = torch.log(1 - torch.exp(inner).clamp(max=0.99999999) + 1e-10)

    return LL0_s_new, LL1_new

def mcmc(D0, D1, n, iterations, beacons, burn_in=1, record_step=None, sd=1):
    """
    执行 Metropolis-Hastings 采样
    """
    # 初始化 N (所有节点不过滤的概率初始为 0.5)
    N = torch.ones((n, 1), device=device) * 0.5
    N_ = N.clone() # N_ 是 Proposal State (提议状态)

    # 初始似然
    LL0_s, LL1 = log_likelihood(D0, D1, N)
    old_likelihood = LL0_s + LL1.sum()
    
    acceptance = 0
    save = {i: [] for i in range(n)}
    
    print(f"[INFO] Starting MCMC for {iterations} iterations...")
    
    for it in tqdm(range(iterations)):

        # 1. 随机选择一个非 Beacon 节点
        node = rand.choice(range(n))
        while node in beacons:
            node = rand.choice(range(n))

        # 2. 生成提议值 (Proposal)
        # 采用截断正态分布 Truncated Normal (0, 1)
        current_val = N[node].item()
        
        # 简单的拒绝采样生成合法的下一步
        while True:
            step = np.random.normal(0, sd)
            candidate = current_val + step
            if 0 < candidate < 1: # 严格 (0,1) 避免 log(0) 或 log(1)
                new_diff = step
                break
        
        old_val = N[node].clone() # 备份旧值
        N_[node] += new_diff      # 更新 N_ 为新值

        # 3. 计算似然比 (Likelihood Ratio)
        LL0_s_new, LL1_new = log_likelihood_update(LL0_s, LL1, N, N_, node, D0, D1)
        new_likelihood = LL0_s_new + LL1_new.sum()
        
        # 4. 计算 Hastings Correction (校正因子)
        # 公式：alpha = log(L_new) - log(L_old) + log(Z_old) - log(Z_new)
        # Z 是截断正态分布的归一化常数：Z = Phi((1-mu)/sigma) - Phi((0-mu)/sigma)
        
        # 使用 torch.special.ndtr 计算标准正态分布 CDF
        # Z_new (Proposal 是以 current_val 为均值生成的) -> 等等，MH 算法中 q(x'|x) 是以 x 为均值
        # Proposal q(new|old): Normal(old, sd) truncated to [0,1]
        # Proposal q(old|new): Normal(new, sd) truncated to [0,1]
        # Ratio = q(old|new) / q(new|old) = Z(old) / Z(new)
        # Log Ratio = log(Z_old) - log(Z_new)
        
        # 计算 Z_old (以当前值为均值时的归一化常数)
        z_old_upper = torch.special.ndtr((1.0 - old_val) / sd)
        z_old_lower = torch.special.ndtr((0.0 - old_val) / sd)
        Z_old = z_old_upper - z_old_lower
        
        # 计算 Z_new (以新值为均值时的归一化常数)
        # 注意：这里 mean 是 N_[node] (即 candidate)
        z_new_upper = torch.special.ndtr((1.0 - N_[node]) / sd)
        z_new_lower = torch.special.ndtr((0.0 - N_[node]) / sd)
        Z_new = z_new_upper - z_new_lower
        
        # 加上 Hastings Correction
        correction = torch.log(Z_old + 1e-10) - torch.log(Z_new + 1e-10)
        
        alpha = new_likelihood - old_likelihood + correction
        
        # 5. 接受/拒绝 (Accept/Reject)
        # 随机生成 log(u), u ~ Uniform(0,1)
        if torch.log(torch.rand((1,), device=device)) < alpha:
            # Accept
            acceptance += 1
            old_likelihood = new_likelihood
            LL0_s = LL0_s_new
            LL1 = LL1_new
            N[node] = N_[node] # 确认更新 N
            
            # 记录样本
            if record_step and it > burn_in and it % record_step == 0:
                for l in range(n):
                    save[l].append(N[l].item())
        else:
            # Reject
            N_[node] = N[node] # 还原 N_ 为旧值 (回滚)

    print(f"[INFO] MCMC Finished. Acceptance Rate: {acceptance/iterations:.4f}")

    if record_step:
        return save, acceptance
    else:
        return N

# ================= 主程序入口 =================
if __name__ == "__main__":    
    parser = argparse.ArgumentParser(description="FIRE Control Plane Inference")
    
    parser.add_argument('--input_dir', type=str, default='../sample_input', 
                        help='Directory containing inputs')
    parser.add_argument('--output_dir', type=str, default='../sample_output',
                        help='Directory to save outputs')
    args = parser.parse_args()

    config_para.input_dir = args.input_dir
    config_para.output_dir = args.output_dir
    
    # 1. 加载数据
    print("Loading data...")
    try:
        ys_observed = np.load(f"{config_para.output_dir}/ys_observed_{calculate_time}.npy")
        yx_relation = np.load(f"{config_para.output_dir}/yx_relation_{calculate_time}.npy")
    except FileNotFoundError:
        print(f"[Error] Data files not found in {config_para.output_dir}. Please check path.")
        sys.exit(1)

    ny, nx = yx_relation.shape
    print(f'Paths (ny): {ny}, AS/Groups (nx): {nx}')

    # 2. 构建 D0 和 D1 矩阵
    # ys_observed: 1 (True) 表示路径断了(ROV生效), 0 (False) 表示路径通了(未过滤)
    # 注意：这里需要确认原始定义。根据代码逻辑：
    # ys_observed.sum() 是 num_true (D1)。通常 D1 代表 ROV 导致的不连通。
    
    num_true = ys_observed.sum() 
    num_false = (ys_observed.shape[0] - num_true)
    
    print(f"Observed Filtered Paths (D1): {num_true}")
    print(f"Observed Permitted Paths (D0): {num_false}")

    # 初始化矩阵并移动到 device (GPU/CPU)
    D0 = torch.zeros((num_false, nx), device=device)
    D1 = torch.zeros((num_true, nx), device=device)

    # 填充矩阵 (这部分稍微耗时，但在 CPU 上做一次即可)
    # 如果 yx_relation 很大，建议优化这里的加载方式，但在 Demo 规模下没问题
    r0, r1 = 0, 0
    for row_idx in tqdm(range(ny), desc="Building Matrices"):
        if ys_observed[row_idx] == 1:
            # 这是一个被过滤的路径 -> D1
            indices = np.where(yx_relation[row_idx] == 1)[0]
            # 将 numpy 索引转为 tensor 索引赋值
            D1[r1, indices] = 1.0
            r1 += 1
        else:
            # 这是一个通的路径 -> D0
            indices = np.where(yx_relation[row_idx] == 1)[0]
            D0[r0, indices] = 1.0
            r0 += 1
            
    # 3. 配置 MCMC 参数
    # 建议先跑一个小规模测试
    iterations = nx * 1000  # 如果 nx 很大，这里会很久，Demo 可以改小
    save_its = 1000         # 最终保存多少个样本点
    
    # 如果是 Demo 模式或调试，减少迭代次数
    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        print("[INFO] Running in DEMO mode")
        iterations = 5000
        save_its = 100

    # 4. 运行 MCMC
    # 这里我们想要保存样本分布，所以调用带 record_step 的模式
    # step 计算：每隔多少步采一个样
    step = max(1, iterations // save_its)
    
    save_dict, acc = mcmc(
        D0, D1, 
        n=nx, 
        iterations=iterations, 
        beacons=set(), 
        burn_in=iterations // 2, # 丢弃前一半作为 Burn-in
        record_step=step, 
        sd=0.5 # 建议 sd 稍微小一点，接受率会高一些
    )
    
    # 5. 保存结果
    print("Saving results...")
    # 将字典转换为 DataFrame (行: 样本, 列: 节点)
    mcmc_samples = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in save_dict.items()]))
    
    output_path = f"{config_para.output_dir}/mcmc_samples_{calculate_time}.csv"
    mcmc_samples.to_csv(output_path, index=False)
    print(f"Done! Results saved to {output_path}")