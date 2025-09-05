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

    # scan ip button
    self.scan_button.clicked.connect(self.scan_ip)

    # network table
    self.timer = QTimer()
    self.timer.timeout.connect(self.update_network_scan)
    self.timer.start(15000)
    self.update_network_scan()
    self.network_table.setSelectionBehavior(QAbstractItemView.SelectRows)
    self.network_table.setSelectionMode(QAbstractItemView.SingleSelection)
    self.network_table.setContextMenuPolicy(Qt.CustomContextMenu)
    self.network_table.customContextMenuRequested.connect(self.show_context_menu)

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