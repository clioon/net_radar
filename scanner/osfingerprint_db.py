OS_FINGERPRINT_DB = [
  {
    "name": "Windows 10/11",
    "icmp_ttl": [128],
    "tcp_ttl": [128],
    "window": [64240, 65535, 256],
    "options": ["MSS", "NOP", "NOP", "SACK", "NOP", "WScale"],
    "options_order": True,
    "df_flag": True
  },
  {
    "name": "Windows 7/8",
    "icmp_ttl": [128],
    "tcp_ttl": [128],
    "window": [8192, 64240],
    "options": ["MSS", "NOP", "NOP", "SACK", "NOP", "WScale"],
    "options_order": True,
    "df_flag": True
  },
  {
    "name": "Linux (Kernel moderno)",
    "icmp_ttl": [64],
    "tcp_ttl": [64],
    "window": [65535, 29200],
    "options": ["MSS", "SACK", "TS", "NOP", "WScale"],
    "options_order": True,
    "df_flag": True
  },
  {
    "name": "Linux (Kernel antigo)",
    "icmp_ttl": [64],
    "tcp_ttl": [64],
    "window": [5840, 5720],
    "options": ["MSS", "SACK", "TS", "NOP", "WScale"],
    "options_order": True,
    "df_flag": True
  },
  {
    "name": "macOS",
    "icmp_ttl": [64],
    "tcp_ttl": [64],
    "window": [65535, 65536],
    "options": ["MSS", "SACK", "TS", "NOP", "WScale"],
    "options_order": True,
    "df_flag": True
  },
  {
    "name": "Cisco IOS",
    "icmp_ttl": [255],
    "tcp_ttl": [255],
    "window": [4128, 8192],
    "options": ["MSS"],
    "options_order": True,
    "df_flag": True
  },
  {
    "name": "FreeBSD",
    "icmp_ttl": [64],
    "tcp_ttl": [64],
    "window": [65535],
    "options": ["MSS", "SACK", "TS", "NOP", "WScale"],
    "options_order": True,
    "df_flag": True
  },
  {
    "name": "Android/Linux Mobile",
    "icmp_ttl": [64],
    "tcp_ttl": [64],
    "window": [65535, 29200, 64240],
    "options": ["MSS", "SACK", "TS", "NOP", "WScale"],
    "options_order": True,
    "df_flag": True
  }
]