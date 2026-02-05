
from get_BGP_info_from_local import g_rib_dir, GetPSR, ChechPSRConcerned
from pathlib import Path
import json
import ijson
from collections import defaultdict, Counter

def DealConcerned(fns):
    check = defaultdict(list)
    with open('../sample_output/concerned_psr.json', 'r') as rf:
        
        for line in ijson.items(rf, 'item'):
            mid, nh1, prefs1, nh2, prefs2 = line
            for pref in prefs1: check[pref].add((mid + ' ' + nh2))
            for pref in prefs2: check[pref].add((mid + ' ' + nh1))
            
    ChechPSRConcerned(fns, check)

def MainFunc():
    given_time = '20250804000000'
    fns = []
    path = Path(f'/networkDisk1/RIB/{given_time[:4]}-{given_time[4:6]}/ripe/')
    fns = [str(fn) for fn in path.glob(f'*/bview.{given_time[:8]}.{given_time[8:12]}.gz')] #bview.20250101.0000.gz        
    path = Path(f'/networkDisk1/RIB/{given_time[:4]}-{given_time[4:6]}/routeviews/')
    fns += [str(fn) for fn in path.glob(f'*/rib.{given_time[:8]}.{given_time[8:12]}.bz2')]
    GetPSR(fns, given_time)
    DealConcerned(fns)

if __name__ == '__main__':
    MainFunc()
    