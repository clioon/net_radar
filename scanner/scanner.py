from scapy.all import ARP, Ether, srp
import requests
import socket

def arp_scanner(ip_range):
  ether = Ether(dst="ff:ff:ff:ff:ff:ff")
  arp = ARP(pdst=ip_range)
  packet = ether/arp
  result = srp(packet, verbose=0, timeout=5)[0]

  clients = []

  for sent, received in result:
    clients.append({ 'IP': received.psrc, 'MAC': received.hwsrc })

  return clients

def mac_lookup(mac_addr):
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

def get_hostname(ip):
  try:
    return socket.gethostbyaddr(ip)[0]
  except socket.herror:
    return "Unknown"
