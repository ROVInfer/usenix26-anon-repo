import requests
import time
import json
import numpy as np
from collections import defaultdict, Counter
from fire_cp import calculate_time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.dates as mdates
from datetime import datetime
import math

TARGET_DATE = "2025-08-04" 

fire_rov, fire_nonrov = set(), set()

with open(f'../data/rov_intfs_{calculate_time}.json', 'r') as rf:
    data = json.load(rf)
    fire_rov.update({elem.split('-')[0] for elem in data})
with open(f'../data/nonrov_intfs_{calculate_time}.json', 'r') as rf:
    data = json.load(rf)
    fire_nonrov.update({elem.split('-')[0] for elem in data})
partial_asns = fire_rov & fire_nonrov

cloudflare_rov_asns = {'3356', '1299', '174', '2914', '6939', '3257', '6453', '6461', '3491', '1273', '9002', '5511', '4637', '12956', '7922', '7018', '701', '6830', '3320', '286', '4826', '33891', '3303', '22773', '28329', '1221', '5405', '5617', '1239', '8708', '20965', '52873', '1764', '852', '10796', '263444', '13030', '9443', '30781', '3462', '28186', '29535', '35280', '5089', '3292', '28263', '2119', '47147', '17451', '52863', '6079', '45177', '15576', '8767', '11351', '15895', '207841', '16086', '28126', '25369', '719', '1136', '12271', '44530', '14282', '18106', '8100', '6866', '55850', '52999', '3399', '2860', '8560', '29695', '29518', '33915', '262659', '12337', '42831', '50058', '35432', '8426', '55805', '56655', '12611', '553', '5539', '25291', '2852', '2611', '51088', '13335', '9136', '2027', '33182', '3265', '51559', '8283', '13101', '150369', '4764', '7642', '21738', '8075', '58820', '7195', '24309', '35612', '16509', '264130', '1213', '52210', '61785', '18209', '41164', '51519', '2906', '212271', '37611', '1403', '204274', '29413', '31472', '397143', '60876', '49409', '27400', '394256', '39839', '14907', '199811', '14525', '44034', '12876', '47524', '197540', '35008', '6167', '21040', '31423', '30736', '46805', '33986', '41000', '205668', '197301', '204151', '20259', '39384', '263812', '54681', '393891', '60422', '265656', '399866', '201199', '215467', '51999', '56958', '211562', '213268', '19468', '17147', '207149', '397388', '142582', '202427', '200242'}
cloudflare_nonrov_asns = {'6762', '12389', '20485', '7473', '16735', '52320', '10429', '262589', '37468', '4809', '7738', '4766', '18881', '4230', '5483', '267613', '7029', '26615', '28598', '7474', '13786', '9318', '7545', '22356', '577', '6128', '17676', '4788', '14840', '38195', '9121', '6327', '9009', '8447', '11404', '53013', '7303', '12874', '23106', '25933', '3269', '2764', '53087', '812', '2856', '12430', '6730', '12578', '8881', '9299', '5650', '45899', '263009', '28260', '3209', '31027', '4775', '9269', '11664', '14868', '9790', '1853', '28368', '15557', '52871', '12083', '25255', '53181', '43350', '40676', '19108', '29049', '7992', '35805', '9829', '55836', '25229', '9924', '6697', '24940', '21013', '5769', '264144', '199524', '50304', '6848', '23655', '8422', '30722', '4922', '5432', '28580', '15704', '12735', '4739', '6677', '36351', '3737', '49505', '46562', '55410', '23930', '37153', '29691', '12849', '45595', '42926', '803', '9824', '42772', '262287', '50340', '41998', '14537', '8280', '45011', '60294', '12353', '5645', '23944', '9541', '46375', '9891', '6147', '25106', '55720', '23969', '46844', '3243', '13213', '11338', '27796', '27715', '197155', '24904', '12322', '5410', '51765', '137409', '4670', '20845', '35228', '21334', '34569', '43317', '58477', '16276', '29854', '8412', '24768', '4804', '47536', '43289', '58065', '3238', '32489', '54133', '21928', '5378', '21502', '397373', '42863', '133480', '45669', '200899', '32329', '34803', '51430', '12390', '198570', '138384', '38266', '11878', '197328', '10507', '13170', '15435', '51852', '11831', '33083', '14593', '25560', '15456', '56309', '263945', '196819', '57814', '28573', '16135', '51207', '31615', '24158', '395954', '37705', '55286', '19165', '50266', '132199', '206067', '36850', '7203', '10139', '396190', '30633', '34296', '17552', '17858', '9644', '9605', '15457', '4685', '17853', '212238', '396362', '19148', '29485', '54858', '394380', '135478', '47800', '45382', '15491', '36445', '42580', '34702', '50613', '393886', '197706', '61272', '30900', '17090', '134094', '52270', '15003', '201924', '42082', '36077', '394752', '200698', '200651', '396986', '42994', '265708', '205053', '57127', '264649', '200709', '208673', '43945', '139879', '133481', '39651'}

strict_dp_rov = set()
strict_dp_nonrov = set()
with open('../sample_input/usenix23_res_with_indent.json', 'r') as rf:
    data = json.load(rf)
    for grade, val in data.items():
        tmp = {str(asn) for asn in val['data']}
        if int(grade) >= 7: strict_dp_rov.update(tmp)
        if int(grade) <= 1: strict_dp_nonrov.update(tmp)
        
cloudflare_partial_rov_asns = {'2497', '4713', '8866', '212477', '54825', '786', '60068', '680', '61317', '36352', '13188', '132335', '14061', '63023', '8218', '12576', '6871', '46664', '54455', '55536'}

fire_rov_asns = fire_rov - partial_asns
fire_nonrov_asns = fire_nonrov - partial_asns
print(f'fire_rov_asns#: {len(fire_rov_asns)}')
print(f'partial_asns#: {len(partial_asns)}')
print(f'fire_nonrov_asns#: {len(fire_nonrov_asns)}\n')

print(f'cloudflare_rov_asns: {len(cloudflare_rov_asns)}, cloudflare_nonrov_asns: {len(cloudflare_nonrov_asns)}\n')

print(f'strict_dp_rov: {len(strict_dp_rov)}, strict_dp_nonrov: {len(strict_dp_nonrov)}\n')

print(f'cloudflare_rov_asns&fire_rov_asns(match)#: {len(fire_rov_asns&cloudflare_rov_asns)}')
print(f'cloudflare_rov_asns&partial_asns(partial match)#: {len(partial_asns&cloudflare_rov_asns)}')
print(f'cloudflare_rov_asns&fire_nonrov_asns(conflict)#: {len(fire_nonrov_asns&cloudflare_rov_asns)}\n')

print(f'cloudflare_nonrov_asns&fire_nonrov_asns(match)#: {len(fire_nonrov_asns&cloudflare_nonrov_asns)}')
print(f'cloudflare_nonrov_asns&partial_asns(partial match)#: {len(partial_asns&cloudflare_nonrov_asns)}')
print(f'cloudflare_nonrov_asns&fire_rov_asns(conflict)#: {len(fire_rov_asns&cloudflare_nonrov_asns)}\n')
concerned_asns = fire_rov_asns&cloudflare_nonrov_asns
pdf_fn = ''#../sample_output/concerned_asn_apnic_fire_rov_cf_nonrov_fin.pdf'

print(f'strict_dp_rov&fire_rov_asns(match)#: {len(fire_rov_asns&strict_dp_rov)}')
print(f'strict_dp_rov&partial_asns(partial match)#: {len(partial_asns&strict_dp_rov)}')
print(f'strict_dp_rov&fire_nonrov_asns(conflict)#: {len(fire_nonrov_asns&strict_dp_rov)}\n')

rovmi_rov = None  
rovmi_nonrov = None
with open(f'../sample_input/rovmi_res.json', 'r') as rf:
    data = json.load(rf)
    rovmi_rov = set(data['rov'])
    rovmi_nonrov = set(data['nonrov'])
print(f'cloudflare_rov_asns&rovmi_rov(match)#: {len(rovmi_rov&cloudflare_rov_asns)}')
print(f'cloudflare_rov_asns&rovmi_nonrov(conflict)#: {len(rovmi_nonrov&cloudflare_rov_asns)}\n')

def parse_apnic_as_history(json_obj, window="7"):
    target_records = []
    for item in json_obj['data']:
        target_records.append((item['date'], item.get(window)['filter_rate']))
    
    return target_records

def get_concerned_apnic(asn_list):
    print(f"Checking {len(asn_list)} ASes against APNIC data...\n")
    
    results = {}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Accept-Language": "en-US,en;q=0.9",
    }
    
    session = requests.Session()

    for i, asn in enumerate(asn_list):
        asn = str(asn).strip().upper()
            
        url = f"https://stats.labs.apnic.net/cgi-bin/rpki-json-table.pl?x={asn}"
        headers["Referer"] = f"https://stats.labs.apnic.net/rpki/{asn}"        
        session.headers.update(headers)
        
        try:
            if i > 0 and i % 10 == 0: time.sleep(1)
                
            resp = session.get(url, timeout=15)
            if resp.status_code != 200:
                no_data_count += 1
                continue
                
            data = resp.json()
            res = parse_apnic_as_history(data, None)
            if res: results[asn] = res
                
        except Exception as e:
            print(f"Error {asn}: {e}")
    with open('../sample_output/concerned_asn_apnic.json', 'w') as wf:
        json.dump(results, wf, indent=1)
    
def check_apnic_consistency(asn_list, date_str):
    consistent_count = 0
    inconsistent_count = 0
    partial_count = 0
    no_data_count = 0
    res = None
    rec = defaultdict(list)
    
    print(f"Checking {len(asn_list)} ASes against APNIC data for {date_str}...\n")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Accept-Language": "en-US,en;q=0.9",
    }
    
    session = requests.Session()

    for i, asn in enumerate(asn_list):
        asn = str(asn).strip().upper()
            
        url = f"https://stats.labs.apnic.net/cgi-bin/rpki-json-table.pl?x={asn}"
        headers["Referer"] = f"https://stats.labs.apnic.net/rpki/{asn}"        
        session.headers.update(headers)
        
        try:
            if i > 0 and i % 10 == 0: time.sleep(1)
                
            resp = session.get(url, timeout=15)
            if resp.status_code != 200:
                no_data_count += 1
                continue
                
            data = resp.json()
            res = parse_apnic_as_history(data, date_str)
            if not res: continue
            
            max_f = -1
            for date, filter_rate in res:
                if '2025-04-01' < date[:8] < '2025-09-01':
                    rec[asn].append((date, filter_rate))
                    if max_f < filter_rate: max_f = filter_rate
            if max_f == -1: continue
            if max_f >= 90: consistent_count += 1
            elif  max_f <= 10: inconsistent_count += 1
            else: partial_count += 1
            print(f"i: {i}, [{asn}] filter rate: {max_f:.1f}%")
                
        except Exception as e:
            print(f"Error {asn}: {e}")
            no_data_count += 1

    with open(f'../sample_output/irov_concerned.json', 'w') as wf:
        json.dump(rec, wf, indent=1)
    
    total_checked = consistent_count + inconsistent_count + partial_count
    if total_checked == 0: return
    
    print(f'consistent_count: {consistent_count}')
    print(f'partial_count: {partial_count}')
    print(f'inconsistent_count: {inconsistent_count}')
    

def parse_data(dataset):
    dates = [datetime.strptime(item[0], "%Y-%m-%d") for item in dataset]
    vals = [item[1] for item in dataset]
    return dates, vals

def create_pdf(pdf_fn, plots_per_page=3):
    data_source = None
    with open('../sample_output/concerned_asn_apnic.json', 'r') as rf:
        data_source = json.load(rf)

    with PdfPages(pdf_fn) as pdf:
        total_plots = len(data_source)
        # 计算总页数
        total_pages = math.ceil(total_plots / plots_per_page)
        
        print(f"total_plots: {total_plots}, total_pages: {total_pages}")
        
        i = 0
        fig, axes = None, None
        for asn, val in data_source.items():
            if i % plots_per_page == 0:
                if fig:
                    fig.autofmt_xdate() 
                    plt.tight_layout()
                    pdf.savefig(fig)
                    plt.close(fig)                        
                fig, axes = plt.subplots(plots_per_page, 1, figsize=(8.27, 11.69), dpi=100)
            
            ax = axes[i%plots_per_page]
            dates, vals = parse_data(val)
            ax.plot(dates, vals, marker='o', markersize=4, linestyle='-')
            
            ax.set_title(f"AS: {asn}")
            ax.set_ylabel("Value")
            ax.grid(True, linestyle='--', alpha=0.6)
            
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            ax.xaxis.set_major_locator(mdates.AutoDateLocator())
            i += 1
            
        if i % plots_per_page != 0:
            for j in range(i%3, plots_per_page):
                axes[j].axis('off')
        if fig:
            fig.autofmt_xdate() 
            plt.tight_layout()
            pdf.savefig(fig)
            plt.close(fig)


if __name__ == "__main__":
    if pdf_fn:
        get_concerned_apnic(concerned_asns)
        create_pdf(pdf_fn)
    #check_apnic_consistency(fire_rov_asns, TARGET_DATE)
    # check_apnic_consistency(strict_dp_rov, "2022-01-01" )
    # check_apnic_consistency(rovmi_rov, TARGET_DATE)
    