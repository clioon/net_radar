from scapy.all import ARP, Ether, srp, DNS, DNSQR, IP, UDP, sr1, TCP, RandShort, ICMP
import requests
import socket
import time
import nmap
import logging

COMMON_TCP_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 9009, 135, 139, 389, 636, 3306, 5432, 5900, 8080, 8443, 10000]

def arp_scanner(ip_range, timeout=2):
  """
  Scans the local network for active devices using ARP requests and ICMP for ping latency.

  Args:
    ip_range (str): The IP range to scan, e.g., "192.168.0.0/24".

  Returns:
    list: A list of dictionaries, each containing 'IP', 'MAC' and 'Latency' of a found device.
  """

  # remove warnings
  logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

  ether = Ether(dst="ff:ff:ff:ff:ff:ff")
  arp = ARP(pdst=ip_range)
  packet = ether/arp
  result = srp(packet, verbose=0, timeout=timeout)[0]

  clients = []

  for sent, received in result:
    ip = received.psrc
    mac = received.hwsrc

    latency = None
    try:
      icmp_pkt = IP(dst=ip)/ICMP()
      start = time.time()
      resp = sr1(icmp_pkt, timeout=1, verbose=0)
      end = time.time()
      if resp:
        latency = resp.time - icmp_pkt.sent_time
        latency = round(latency * 1000, 2)
    except Exception:
      pass

    clients.append({ 
      'Latency': latency,
      'MAC': mac,
      'IP': ip
    })
  return clients

def mac_lookup(mac_addr):
  """
  Looks up the vendor/manufacturer of a device based on its MAC address 
  using the MAC Vendor Lookup API.

  Args:
    mac_addr (str): The MAC address to query, in any common format (e.g., "00:23:AB:7B:58:99").
  """

  try:
    mac_addr = mac_addr.strip().replace("-", ":").upper()
    url = f"https://www.macvendorlookup.com/api/v2/{mac_addr}"
    response = requests.get(url)

    if response.status_code == 200:
      data = response.json()
      if data:
        return data[0]['company']
      else:
        return "Vendor not found"
      
    elif response.status_code == 204:
      return "Unknown"
    
    else:
      return f"Error: {response.status_code}"
  except Exception as e:
    return e

def get_hostname(ip, timeout=2):
  """
  Tries to resolve the hostname with two methods:
  1. Standard reverse DNS lookup using socket.gethostbyaddr().
  2. Direct reverse DNS query by sending a custom DNS PTR packet to a DNS server.
  """

  hostname = None

  try:
    result = socket.gethostbyaddr(ip)
    if result and result[0]: return result[0]
  except (socket.herror, socket.gaierror, socket.timeout):
    pass

  try:
    dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"{'.'.join(reversed(ip.split('.')))}.in-addr.arpa", qtype="PTR"))
    response = sr1(dns_query, timeout=timeout, verbose=0)

    if response and response.haslayer(DNS) and response[DNS].an:
      for i in range(response[DNS].ancount):
        if response[DNS].an[i].type == 12:
          hostname = response[DNS].an[i].rdata.decode('utf-8')
          if hostname:
            return hostname[:-1] if hostname.endswith('.') else hostname
          
  except:
    pass

  return "Unknown"

def open_ports_scanner(ip, ports=None, timeout=1):
  """
  - Simple port scanner with SYN scan
  - Simple port scanner with socket connect()
  """

  if ports is None:
    ports = COMMON_TCP_PORTS

  source_port = RandShort()
  open_ports = set()

  for port in ports:
    pkt = sr1(IP(dst=ip)/TCP(sport=source_port, dport=port, flags='S'), timeout=timeout, verbose=0)

    if pkt is not None:
      if pkt.haslayer(TCP):
        if pkt[TCP].flags == 18:
          open_ports.add(port)

  for port in ports:
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(timeout)
      if sock.connect_ex((ip, port)) == 0:
        open_ports.add(port)
      sock.close()
    except:
      continue

  return open_ports

def nmap_scanner(ip_range, ports=None, timeout=10000, full_scan=False):
  """
  Scanner using Nmap.
  """

  nm = nmap.PortScanner()

  if full_scan:
    ports_str = "-p-"
  elif ports:
    ports_str = "-p " + ",".join(map(str, ports))
  else:
    ports_str = ""

  nm.scan(
    hosts=ip_range,
    arguments=f"-T4 -n -Pn --host-timeout {timeout}ms {ports_str}"
  )

  results = {}
  for host in nm.all_hosts():
    host_info = {
      "IP": host,
      "MAC": nm[host]["addresses"].get("mac", "Unknown"),
      "Vendor": nm[host]["vendor"].get(nm[host]["addresses"].get("mac", ""), "Unknown"),
      "Hostname": nm[host].hostname() if nm[host].hostname() else "Unknown",
      "Latency_micros": nm[host].get("times", {}).get("srtt", None),
      "Open_Ports": []
    }

    for proto in nm[host].all_protocols():
      for port, portdata in nm[host][proto].items():
        if portdata["state"] == "open":
          host_info["Open_Ports"].append(port)

    results[host] = host_info

  return results
