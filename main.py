from scanner import *
import socket

ip_range = "192.168.0.0/24"
# ip_range = "192.168.0.7"

clients = arp_scanner(ip_range)

for client in clients:
  print("\n======== Calculating", client, "======== \n")
  #hostname
  client['Hostname'] = get_hostname(client['IP'])

  #mac
  vendor = mac_lookup(client['MAC'])
  #vendor = "none"
  client['Vendor'] = vendor

  #os
  fp = get_fingerprint_os(client['IP'], None, 2)
  client['OS'] = os_guess(fp)

print(f"{'IP':<16} {'MAC':<18} {'Hostname':<10} {'Vendor':<30} {'OS'}")
print("-" * 110)
for client in clients:
    print(f"{client['IP']:<16} {client['MAC']:<18} {client['Hostname']:<10} {client['Vendor']:<30} {client['OS']}")
