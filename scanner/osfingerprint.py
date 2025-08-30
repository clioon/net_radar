from scapy.all import sr1, IP, ICMP, TCP
from .osfingerprint_db import OS_FINGERPRINT_DB
import requests

def get_icmp_ttl(ip):
  pkt = IP(dst=ip)/ICMP()
  response = sr1(pkt, timeout=2, verbose=0)
  if response:
    return response.ttl
  return None

def get_tcp_info(ip, port=80):
  pkt = IP(dst=ip)/TCP(dport=port, flags="S")
  response = sr1(pkt, timeout=2, verbose=0)
  if response and response.haslayer(TCP):
    tcp_ttl = response.ttl
    window = response[TCP].window
    opts = {k: v for k, v in response[TCP].options}
    return {"tcp_ttl": tcp_ttl, "window":window, "tcp_options":opts}
  return None

def fingerprint_os(ip):
  data = {}

  icmp_ttl = get_icmp_ttl(ip)
  data["icmp_ttl"] = icmp_ttl

  tcp_info = get_tcp_info(ip)
  if tcp_info: 
    data.update(tcp_info)

  return data

def simple_guess_os(fingerprint):
  best_match = None
  best_score = 0
  ttl_tolerance = 5

  for os_data in OS_FINGERPRINT_DB:
    score = 0
    
    target_icmp_ttl = int(fingerprint.get("icmp_ttl") or 0)
    target_tcp_ttl = int(fingerprint.get("tcp_ttl") or 0)

    if "icmp_ttl" in os_data and any(abs(target_icmp_ttl - db_ttl) <= ttl_tolerance for db_ttl in os_data["icmp_ttl"]): score += 1
    if "tcp_ttl" in os_data and any(abs(target_tcp_ttl - db_ttl) <= ttl_tolerance for db_ttl in os_data["tcp_ttl"]): score += 1
    if fingerprint.get("window") in os_data["window"]: score += 1

    if score > best_score: 
      best_score = score
      best_match = os_data["name"]
    
  return best_match if best_match else "Unknown"