import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from mpl_toolkits.axes_grid1.inset_locator import mark_inset
import matplotlib.ticker as ticker

# --- USENIX 风格配置 ---
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'Times', 'DejaVu Serif'],
    'font.size': 10,
    'axes.labelsize': 10,
    'axes.titlesize': 10,
    'xtick.labelsize': 9,        # 刻度字体微调
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'lines.linewidth': 1.2,
    'axes.linewidth': 1.0,
    'mathtext.fontset': 'stix',
})

def plot_bgp_cdf_usenix_final():
    files = {
        'Inferred': '../sample_output/infection_stats_inferred.csv',
        'Uniform': '../sample_output/infection_stats_uniform.csv',
        'Supplemented': '../sample_output/infection_stats_supplemented.csv'
    }
    
    # 1. 画布尺寸：保持紧凑 (宽 3.4 inch, 高 2.3 inch)
    fig, ax = plt.subplots(figsize=(3.4, 2.3))
    
    colors = {'Inferred': '#1f77b4', 'Uniform': '#ff7f0e', 'Supplemented': '#2ca02c'}
    data_store = {}

    print("Loading data...")
    for label, path in files.items():
        try:
            df = pd.read_csv(path)
            data = df[df['impact_count'] > 0]['impact_count'].values
            sorted_data = np.sort(data)
            yvals = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
            data_store[label] = (sorted_data, yvals)
            ax.step(sorted_data, yvals, label=label, where='post', color=colors[label])
        except Exception:
            pass

    # --- 2. 坐标轴紧凑化处理 ---
    
    # X轴设置
    ax.set_xlabel('Infection Scale (# ASes)', labelpad=2) # labelpad=2 让标签靠近轴
    ax.xaxis.set_tick_params(pad=2) # pad=2 让刻度数字靠近轴
    
    # Y轴设置：百分比显示
    ax.set_ylabel('CDF (%)', labelpad=0) # labelpad=0 极致紧凑
    ax.yaxis.set_tick_params(pad=2)
    
    # 手动设置 Y 轴刻度为 0, 25, 50, 75, 100
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(['0', '25', '50', '75', '100'])
    
    # 网格线
    ax.grid(True, linestyle='--', alpha=0.5)
    
    # --- 3. 图例位置优化 ---
    # 利用 Green(高) 和 Blue(低) 之间的空隙
    # bbox_to_anchor=(x, y) 坐标系是 (0~1, 0~1)
    # (0.98, 0.5) 大概在右侧中间位置，刚好避开上下曲线
    ax.legend(loc='lower right', 
          bbox_to_anchor=(1.0, 0.01),  # 【关键】调整这里的第二个数字，越小越往下
          frameon=False, 
          handlelength=1.2, 
          borderpad=0.2,
          labelspacing=0.1)            # 保持紧凑的行间距
    
    # --- 4. 嵌入小图 (Inset) ---
    # 保持在左上角
    ax_ins = ax.inset_axes([0.12, 0.65, 0.30, 0.3])
    
    for label, (x, y) in data_store.items():
        ax_ins.step(x, y, where='post', color=colors[label], linewidth=1.0)

    # 小图设置
    ax_ins.set_xscale('log')
    ax_ins.set_xlim(1, 1000)
    ax_ins.set_ylim(0, 0.45)
    
    # 小图文字：使用 LaTeX 渲染数学符号
    #ax_ins.text(0.05, 0.8, r'Zoom ($x<10^3$)', transform=ax_ins.transAxes, fontsize=8)
    
    # 小图刻度
    ax_ins.tick_params(axis='both', which='major', labelsize=7, pad=1)
    ax_ins.grid(True, linestyle=':', alpha=0.5)
    
    # 小图 Y 轴也只显示简单的 0, 0.2, 0.4 (可选)
    # ax_ins.set_yticks([0, 0.2, 0.4])

    # 连接线
    mark_inset(ax, ax_ins, loc1=2, loc2=4, fc="none", ec="0.5", linestyle="--", linewidth=0.8)

    plt.show()

if __name__ == "__main__":
    plot_bgp_cdf_usenix_final()