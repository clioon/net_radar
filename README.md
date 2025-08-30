Net Radar 📡
============

NetRadar is a Python project that implements **network device discovery** and basic **OS fingerprinting**, built from scratch using Scapy.
It allows you to:
- Discover active devices on a local network via **ARP** packets.
- Retrieve basic information for each device, such as **IP**, **MAC** address, **Hostname** (if available), and **vendor**.
- Perform a simple **OS fingerprint**, analyzing ICMP and TCP responses.

## Features

- ARP Scanner
- Hostname Resolution
- MAC Vendor Lookup
  > Uses the [MAC Vendor Lookup API](https://www.macvendorlookup.com/) to identify device manufacturers.
- OS Fingerprinting
  > Uses a simple custom-made OS fingerprint database, comparing TTL, TCP window size, and TCP options.

## How to Use

1. **Create and activate a virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate
```
2. **Install dependencies**
```bash
pip install -r requirements.txt
```
3. **Run the scanner**

## Notes

- This project is **purely for educational purposes**. It demonstrates how network scanning and basic OS fingerprinting can be implemented from scratch using Python and Scapy.
  > \- All packets are crafted manually using Scapy, providing hands-on learning about networking protocols.  
  > \- OS fingerprinting is basic and intended for learning; it does not replace professional tools like Nmap.  
  > \- Hostnames and full device information may not always be available depending on network configuration and device settings.
- ⚠️ Use this tool **responsibly and legally**. Scanning networks without permission may violate privacy laws and local regulations. Only run the scanner on networks you **own or have explicit authorization to test**.
