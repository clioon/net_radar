from scanner import *
import socket
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QAbstractItemView, QMenu, QAction
from PyQt5 import uic
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QObject, pyqtSlot

class ScannerGUI(QMainWindow):
  def __init__(self):
    super().__init__()
    uic.loadUi("main.ui", self)

    # threads variables
    self.arp_worker = None
    self.arp_worker_lock = False
    self.ip_scanner_worker = None
    self.ip_scanner_worker_lock = False

    # scan ip button
    self.scan_button.clicked.connect(self.scan_ip)

    # nmap check box
    self.nmap_option = False
    self.nmap_checkBox.stateChanged.connect(self.toggle_nmap)

    # network table
    self.timer = QTimer()
    self.timer.timeout.connect(self.update_network_scan)
    self.timer.start(15000)
    self.update_network_scan()
    self.network_table.setSelectionBehavior(QAbstractItemView.SelectRows)
    self.network_table.setSelectionMode(QAbstractItemView.SingleSelection)
    self.network_table.setContextMenuPolicy(Qt.CustomContextMenu)
    self.network_table.customContextMenuRequested.connect(self.show_context_menu)

  def toggle_nmap(self, state):
    self.nmap_option = self.nmap_checkBox.isChecked()

  def show_context_menu(self, pos):
    index = self.network_table.indexAt(pos)
    if not index.isValid(): return

    row = index.row()
    ip_item = self.network_table.item(row, 0)
    mac_item = self.network_table.item(row, 1)

    ip = ip_item.text() if ip_item else ""
    mac = mac_item.text() if mac_item else ""

    menu = QMenu(self)

    copy_ip_action = QAction("Copy IP", self)
    copy_mac_action = QAction("Copy MAC", self)

    copy_ip_action.triggered.connect(lambda: QApplication.clipboard().setText(ip))
    copy_mac_action.triggered.connect(lambda: QApplication.clipboard().setText(mac))

    menu.addAction(copy_ip_action)
    menu.addAction(copy_mac_action)

    menu.exec_(self.network_table.viewport().mapToGlobal(pos))

  def update_network_scan(self):
    if self.arp_worker_lock: return
    self.arp_worker_lock = True

    self.scan_led.setStyleSheet(
      "background-color: rgb(111, 114, 250); border-radius: 7px; min-width: 15px; min-height: 15px;"
    )

    ip_range = self.ip_range.text()
    self.arp_worker = ArpScannerThread(ip_range, timeout=1)
    self.arp_worker.result_ready.connect(self.update_table)
    self.arp_worker.error.connect(lambda e: print("Scan error:", e))
    self.arp_worker.finished.connect(self.arp_worker.deleteLater)
    self.arp_worker.finished.connect(lambda: setattr(self, 'arp_worker_lock', False))
    self.arp_worker.start()

  def update_table(self, clients):
    self.network_table.setRowCount(len(clients))
    for row, client in enumerate(clients):
      ip_item = QTableWidgetItem(client["IP"])
      ip_item.setTextAlignment(Qt.AlignCenter)

      mac_item = QTableWidgetItem(client["MAC"])
      mac_item.setTextAlignment(Qt.AlignCenter)

      latency = client["Latency"]
      latency_text = f"{latency}" if latency is not None else "--"
      latency_item = QTableWidgetItem(latency_text)
      latency_item.setTextAlignment(Qt.AlignCenter)

      self.network_table.setItem(row, 0, ip_item)
      self.network_table.setItem(row, 1, mac_item)
      self.network_table.setItem(row, 2, latency_item)

    QTimer.singleShot(0, lambda: self.scan_led.setStyleSheet(
      "background-color: rgb(222, 221, 218); border-radius: 7px; min-width: 15px; min-height: 15px;"
    ))

  def scan_ip(self):
    if self.ip_scanner_worker_lock: return
    self.ip_scanner_worker_lock = True

    self.progressBar.setValue(0)

    ip = self.ip_input.text()
    if not ip:
      self.ip_scanner_worker_lock = False
      return
    self.result_text.clear()
    self.result_text.append(f"Scanning IP: {ip}...")
    
    self.ip_scanner_worker = IpScannerThread(ip, timeout=1, nmap_option=self.nmap_option)
    self.ip_scanner_worker.progress.connect(self.progressBar.setValue)  
    self.ip_scanner_worker.result_ready.connect(self.update_scanner_result)
    self.ip_scanner_worker.error.connect(self.error_display)
    self.ip_scanner_worker.finished.connect(self.ip_scanner_worker.deleteLater)
    self.ip_scanner_worker.finished.connect(lambda: setattr(self, 'ip_scanner_worker_lock', False))
    self.ip_scanner_worker.start()

  def error_display(self, e):
    self.result_text.clear()
    self.result_text.append(f"Scan Error: {e}")
    self.progressBar.setValue(0)

  def update_scanner_result(self, results):
    self.result_text.clear()
    self.result_text.append(f"IP: {results['ip']}")
    self.result_text.append(f"Hostname: {results['hostname']}")
    
    ports = results['open_ports']
    if not ports:
      ports_str = "--"
    else:
      ports_str = ", ".join(str(p) for p in sorted(ports))

    self.result_text.append(f"Open ports: {ports_str}")
    self.result_text.append(f"Vendor: {results['vendor']}")
    self.result_text.append(f"OS: {results['os'][0]}, score: {results['os'][1]}/100")


class IpScannerThread(QThread):
  result_ready = pyqtSignal(dict)
  error = pyqtSignal(str)
  progress = pyqtSignal(int)

  def __init__(self, target_ip, nmap_option, timeout=1):
    super().__init__()
    self.target_ip = target_ip
    self.timeout = timeout
    self.nmap_option = nmap_option
  
  def run(self):
    try:
      results = {}
      results["ip"] = self.target_ip

      steps = 9
      current = 0
      current += 1
      self.progress.emit(int(current / steps * 100))

      if not self.nmap_option:
        results["open_ports"] = open_ports_scanner(self.target_ip, timeout=self.timeout)
        current += 3
        self.progress.emit(int(current / steps * 100))

        results["hostname"] = get_hostname(self.target_ip)
        current += 1
        self.progress.emit(int(current / steps * 100))

        results["vendor"] = mac_lookup(self.target_ip)
        current += 1
        self.progress.emit(int(current / steps * 100))

        results["fp"] = get_fingerprint_os(self.target_ip, results["open_ports"], timeout=self.timeout)
        current += 2
        self.progress.emit(int(current / steps * 100))

        results["os"] = os_guess(results["fp"])
        current += 1
        self.progress.emit(int(current / steps * 100))

      else:
        ipscan = nmap_scanner(self.target_ip, full_scan=True)
        current += 5
        self.progress.emit(int(current / steps * 100))

        if self.target_ip in ipscan:
          host_info = ipscan[self.target_ip]
          results["open_ports"] = host_info["Open_Ports"]
          results["hostname"] = host_info["Hostname"]
          results["vendor"] = host_info["Vendor"]
          results["fp"] = None
          results["os"] = nmap_os_fingerprint(self.target_ip)
        else:
          results["open_ports"] = []
          results["hostname"] = "Unknown"
          results["vendor"] = "Unknown"
          results["fp"] = None
          results["os"] = ("Unknown", 0)

        current += 3
        self.progress.emit(int(current / steps * 100))

      self.result_ready.emit(results)

    except Exception as e:
      self.error.emit(str(e))

class ArpScannerThread(QThread):
  result_ready = pyqtSignal(list)
  error = pyqtSignal(str)

  def __init__(self, ip_range, timeout=1):
    super().__init__()
    self.ip_range = ip_range
    self.timeout = timeout

  def run(self):
    try:
      clients = arp_scanner(self.ip_range, timeout=self.timeout)
      self.result_ready.emit(clients)
    except Exception as e:
      self.error.emit(str(e))

if __name__ == "__main__":
  app = QApplication(sys.argv)
  gui = ScannerGUI()
  gui.show()
  sys.exit(app.exec_())