from scapy.all import ARP, Ether, srp, DNS, DNSQR, IP, UDP, sr1
import requests
import socket

def arp_scanner(ip_range, timeout=2):
  """
  Scans the local network for active devices using ARP requests.

  Args:
    ip_range (str): The IP range to scan, e.g., "192.168.0.0/24".

  Returns:
    list: A list of dictionaries, each containing 'IP' and 'MAC' of a found device.
  """
  
  ether = Ether(dst="ff:ff:ff:ff:ff:ff")
  arp = ARP(pdst=ip_range)
  packet = ether/arp
  result = srp(packet, verbose=0, timeout=timeout)[0]

  clients = []

  for sent, received in result:
    clients.append({ 'IP': received.psrc, 'MAC': received.hwsrc })

  return clients

def mac_lookup(mac_addr):
  """
  Looks up the vendor/manufacturer of a device based on its MAC address 
  using the MAC Vendor Lookup API.

  Args:
    mac_addr (str): The MAC address to query, in any common format (e.g., "00:23:AB:7B:58:99").
  """

  url = f"https://www.macvendorlookup.com/api/v2/{mac_addr}"
  response = requests.get(url)

  if response.status_code == 200:
    data = response.json()
    if data:
      return data[0]['company']
    else:
      return "Vendor not found"
    
  elif response.status_code == 204:
    return "No match found"
  
  else:
    return f"Error: {response.status_code}"

def get_hostname(ip, timeout=2):
  """
  Tries to resolve the hostname with two methods:
  1. Standard reverse DNS lookup using socket.gethostbyaddr().
  2. Direct reverse DNS query by sending a custom DNS PTR packet to a DNS server.
  """

  hostname = None

  try:
    return socket.gethostbyaddr(ip)[0]
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