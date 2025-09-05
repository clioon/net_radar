from scanner import *
import socket
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem
from PyQt5 import uic
from PyQt5.QtCore import Qt, QTimer
# ip_range = "192.168.0.0/24"
# #ip_range = "192.168.0.1"

# timeout = 2

# clients = arp_scanner(ip_range, timeout)

# for client in clients:
#   print("\n======== Calculating", client, "======== \n")
#   #open ports
#   open_ports = open_ports_scanner(client['IP'], timeout=timeout)
#   print("open ports: ", open_ports)

#   #hostname
#   client['Hostname'] = get_hostname(client['IP'])

#   #mac
#   vendor = mac_lookup(client['MAC'])
#   #vendor = "none"
#   client['Vendor'] = vendor

#   #os
#   fp = get_fingerprint_os(client['IP'], open_ports, timeout)
#   client['OS'] = os_guess(fp)

# print("\n")
# print(f"{'IP':<16} {'MAC':<18} {'Hostname':<10} {'Vendor':<30} {'OS'}")
# print("-" * 110)
# for client in clients:
#     print(f"{client['IP']:<16} {client['MAC']:<18} {client['Hostname']:<10} {client['Vendor']:<30} {client['OS']}")

class ScannerGUI(QMainWindow):
  def __init__(self):
    super().__init__()
    uic.loadUi("main.ui", self)

    # scan ip button
    self.scan_button.clicked.connect(self.scan_ip)

    # network table timer
    self.timer = QTimer()
    self.timer.timeout.connect(self.update_network_scan)
    self.timer.start(15000)  # atualiza a cada 15s
    self.update_network_scan()

  def update_network_scan(self):
    self.scan_led.setStyleSheet(
      "background-color: green; border-radius: 7px; min-width: 15px; min-height: 15px;"
    )

    ip_range = self.ip_range.text()
    clients = arp_scanner(ip_range, timeout=2)

    self.network_table.setRowCount(len(clients))
    for row, client in enumerate(clients):
      ip_item = QTableWidgetItem(client["IP"])
      ip_item.setTextAlignment(Qt.AlignCenter)
      mac_item = QTableWidgetItem(client["MAC"])
      mac_item.setTextAlignment(Qt.AlignCenter)
      self.network_table.setItem(row, 0, ip_item)
      self.network_table.setItem(row, 1, mac_item)

    QTimer.singleShot(500, lambda: self.scan_led.setStyleSheet(
      "background-color: rgb(222, 221, 218); border-radius: 7px; min-width: 15px; min-height: 15px;"
    ))

  def scan_ip(self):
    ip = self.ip_input.text()
    if not ip:
      return
    self.result_text.clear()
    open_ports = open_ports_scanner(ip, timeout=1)
    hostname = get_hostname(ip)
    vendor = mac_lookup(ip)
    self.result_text.append(f"IP: {ip}")
    self.result_text.append(f"Hostname: {hostname}")
    self.result_text.append(f"Open ports: {open_ports}")
    self.result_text.append(f"Vendor: {vendor}")


if __name__ == "__main__":
  app = QApplication(sys.argv)
  gui = ScannerGUI()
  gui.show()
  sys.exit(app.exec_())