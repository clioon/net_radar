from scapy.all import sr1, IP, ICMP, TCP
from .osfingerprint_db import OS_FINGERPRINT_DB
from collections import Counter

def get_icmp_ttl(ip, timeout=2):
  pkt = IP(dst=ip)/ICMP()
  response = sr1(pkt, timeout=timeout, verbose=0)
  if response:
    print("icmp ttl: ", response.ttl)
    return response.ttl
  print("icmp ttl: {}")
  return None

def get_tcp_info(ip, ports=None, timeout=2):
  results = {}
  if ports is None:
    ports = [80, 443, 22]

  for port in ports:
    try:
      pkt = IP(dst=ip)/TCP(dport=port, flags="S")
      response = sr1(pkt, timeout=timeout, verbose=0)
      if response and response.haslayer(TCP):
        tcp_data = {
          "ttl": response.ttl,
          "window": response[TCP].window,
          "options": response[TCP].options,
          "flags": response[TCP].flags,
        }

        if response.haslayer(IP):
          tcp_data["df_flag"] = bool(response[IP].flags & 0x02)
        
        results[port] = tcp_data

    except Exception as e:
      continue
  
  print("tcp info: ", results)
  return results

def normalize_ttl(ttl):
  if ttl is None:
    return None     
  if ttl <= 64:
    return 64
  elif ttl <= 128:
    return 128
  else:
    return 255
  
def get_mode(values):
  if not values: 
    return
  
  counts = Counter(values)
  max_count = max(counts.values())

  for v in values:
    if counts[v] == max_count:
      return v

def get_fingerprint_os(ip, ports=None, timeout=2):
  data = {
    "icmp_ttl": normalize_ttl(get_icmp_ttl(ip)),
    "tcp_data": {}
  }

  tcp_info = get_tcp_info(ip, ports, timeout)
  if tcp_info: 
    data["tcp_data"] = tcp_info

    common_ttl = []
    common_window = []
    common_options = []
      
    for port, info in tcp_info.items():
      common_ttl.append(info["ttl"])
      common_window.append(info["window"])
      common_options.append(tuple(opt[0] for opt in info["options"]))

    data["tcp_ttl"] = get_mode(common_ttl)
    data["window"] = get_mode(common_window)
    data["tcp_options"] = get_mode(common_options)
  
  return data

def check_options_match(actual_options, expected_options, check_order=True):
  if expected_options is None:
    return False
  
  if check_order:
    return actual_options == expected_options
  else:
    return set(actual_options) == set(expected_options)

def fuzzy_window_match(actual, expected, tolerance=0.1):
  if expected is None:
    return False
      
  return any(abs(actual - exp) / exp <= tolerance for exp in expected)

def os_guess(fingerprint):
  best_match = "Unknown"
  best_score = 0
  
  for os_data in OS_FINGERPRINT_DB:
    score = 0
  
    icmp_ttl = fingerprint.get("icmp_ttl")
    if icmp_ttl is not None and "icmp_ttl" in os_data:
      if icmp_ttl in os_data["icmp_ttl"]:
        score += 2 
    
    tcp_ttl = fingerprint.get("tcp_ttl")
    if tcp_ttl is not None and "tcp_ttl" in os_data:
      if tcp_ttl in os_data["tcp_ttl"]:
        score += 2
    
    window = fingerprint.get("window")
    if window is not None and "window" in os_data:
      if fuzzy_window_match(window, os_data["window"]):
        score += 1
    
    options = fingerprint.get("tcp_options")
    if options is not None and "options" in os_data:
      check_order = os_data.get("options_order", False)
      if check_options_match(options, os_data["options"], check_order):
        score += 3 

        if check_order and [opt[0] for opt in options] == os_data["options"]:
          score += 1
    
    df_flag = None
    for port_data in fingerprint.get("tcp_data", {}).values():
      if "df_flag" in port_data:
        df_flag = port_data["df_flag"]
        break
            
    if df_flag is not None and "df_flag" in os_data:
      if df_flag == os_data["df_flag"]:
        score += 1
    
    if score > best_score:
      best_score = score
      best_match = os_data["name"]

  return best_match, best_score