# Network Packet Analyzer

> **One‑stop tool to capture, inspect and analyze network packets (PCAP), visualize traffic, and detect basic anomalies.**

---

## 🔥 Quick start

1. Clone the repo:

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

2. Install dependencies (example uses Python and pip):

```bash
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Start the capture & web UI:

```bash
python app.py           # or ./run.sh if provided
```

4. Open the UI at `http://netsecure-aryan.vercel.app` (or the port shown in the console).

---

## 📸 Screenshots

> Add screenshots to the `screenshots/` folder before uploading. Name them exactly as below or update the paths in this README.

* `C:\Users\MY LENOVO\Pictures\Screenshots\Screenshot (1).png` — Homepage / Dashboard (traffic summary)
* `C:\Users\MY LENOVO\Pictures\Screenshots\Screenshot (2).png` — Live capture view
* `C:\Users\MY LENOVO\Pictures\Screenshots\Screenshot 2025-10-27 214754.png` — Packet details / hex view
* `C:\Users\MY LENOVO\Pictures\Screenshots\Screenshot 2025-10-27 214733.png` — Traffic/Threat graphs

Placeholders in markdown:

```markdown
![Overview](./C:\Users\MY LENOVO\Pictures\Screenshots\Screenshot (1).png)
![Live capture](./C:\Users\MY LENOVO\Pictures\Screenshots\Screenshot (2).png)
![Packet details](./C:\Users\MY LENOVO\Pictures\Screenshots\Screenshot 2025-10-27 214754.png)
![Graphs](./C:\Users\MY LENOVO\Pictures\Screenshots\Screenshot 2025-10-27 214733.png)
```

---

## 🧭 Project structure

```
├─ app.py                 # main entrypoint (or server/index.js)
├─ requirements.txt       # python dependencies
├─ package.json           # node dependencies (if used)
├─ README.md
├─ screenshots/
│  ├─ 01-overview.png
│  ├─ 02-live-capture.png
│  └─ ...
├─ src/                   # frontend code
├─ backend/               # capture & analysis engine
├─ docs/
└─ tests/
```

---

## ✅ Features

* Live packet capture (PCAP) from network interfaces
* Save/Load PCAP files
* Packet dissection (Ethernet/IP/TCP/UDP/HTTP/SSL etc.)
* Hex + ASCII packet viewer
* Search & filter by address, port, protocol, payload
* Basic anomaly detection and threat stats
* Visual graphs for traffic volume and protocol distribution

---

## ⚙️ How to use

### 1) Capture live traffic

1. Select an interface from the dropdown.
2. Choose capture filters (BPF syntax supported, e.g., `tcp and port 80`).
3. Click **Start Capture**.
4. Click **Stop Monitoring** to end capture and save to disk.

**CLI example** (if included):

```bash
python capture.py --iface eth0 --filter "tcp and not port 22" --out captures/session1.pcap
```

---

### 2) Open a PCAP file

1. Click **Open PCAP** in the UI.
2. Browse and select `*.pcap` or `*.pcapng`.
3. The packets load into the table and summary panels.

**CLI example:**

```bash
python analyze.py --input captures/session1.pcap
```

---

### 3) Inspect packets

* Click a row in the packet list to expand details.
* View protocol tree, decoded fields, and raw hex/ASCII.
* Use the search box to find IP addresses, ports or strings.

---

### 4) Graphs & statistics

* Open the **Statistics** tab for protocol distribution and traffic over time.
* Use time-range controls to zoom in on spikes.

---

## 🧪 Tests

Run unit tests:

```bash
pytest -q
```

Add integration tests that record a short capture and assert parsing results.

---

## 🛡 Security & permissions

* Running live capture requires elevated privileges on most OSes. Use `sudo` or give the binary `CAP_NET_RAW` where applicable.
* Never upload captures that contain sensitive personal data. Sanitize PCAPs before sharing.

---

## 💡 Development notes

* Parser located at `backend/parser.py` — extend protocol decoders by adding new classes that implement `decode()` and `to_dict()`.
* Frontend uses `src/` — modify components and add new controls for filtering.
* To add a new detection rule, add JSON rule file to `backend/rules/` and restart the service.

---

## 🧾 Example configuration

`config.yaml` (example):

```yaml
capture:
  interface: eth0
  bpf: "tcp and not port 22"
storage:
  pcap_dir: ./captures
server:
  host: 0.0.0.0
  port: 8000
```

---

## 🐞 Troubleshooting

* **No interfaces found** — ensure your user has permission to list interfaces (install libpcap/winpcap and run as admin).
* **Packets not appearing** — check BPF filter syntax and that the chosen interface is active.
* **Port already in use** — change `server.port` in `config.yaml` or kill the process using that port.

---

## 📦 Releases & packaging

* Create Git tags for releases: `git tag -a v1.0 -m "v1.0"` and push tags.
* Attach compiled binaries or Docker images to releases for easy installs.

**Docker example**:

```Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
CMD ["python","app.py"]
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat-awesome-decoder`
3. Commit changes with tests
4. Open a PR with description and screenshots

Please follow the code style configured in `.editorconfig` and run linters before opening a PR.

---

## 📄 License

This project is released under the MIT License. See `LICENSE` for details.

---

## 📬 Contact

Maintainer: **ARYAN TOMAR** — `jobaryantomar898@gmail.com`

For bug reports use GitHub Issues and for feature requests open a discussion.

Description
This Network Protocol Analyzer captures and logs network traffic in real-time using Python and the Scapy library. It provides detailed information about network packets, including timestamps, source/destination IP addresses, protocol details (TCP/UDP), and port numbers. The analyzer automatically selects the best available network interface and logs a configurable number of packets to prevent excessive log file sizes. This tool is invaluable for network monitoring, analysis, and troubleshooting.

Features

1.Real-time Packet Sniffing: Captures network traffic in real-time using Scapy. 📡

2.Automatic Interface Selection: Automatically selects the optimal network interface for capturing packets. 💻

3.Detailed Logging: Logs essential packet details (timestamp, summary, source/destination IPs, protocol, ports) to network_traffic.log. 📝

4.Packet Type Identification: Identifies IP, TCP, and UDP packets and extracts relevant information. 🔎

5.Configurable Logging Limit: Limits the number of logged packets (default 20) to manage log file size. 🔢

6.Informative Packet Summaries: Provides brief summaries of each captured packet. ℹ️

Technologies Used

1.Python: The core programming language for the analyzer. 🐍

2.Scapy: A powerful Python library for network packet manipulation and analysis. 📡

Ideal For
1.Network Administrators: Monitoring and analyzing network traffic for troubleshooting and security. 🧑‍💻

2.Security Researchers: Investigating network communications and potential threats. 🕵️‍♀️

3.Network Engineers: Analyzing network protocols and performance. 👨‍💼

4.Python Developers: Learning about network programming and packet analysis with Scapy. 🧑‍🎓

How to Run
Clone the repository: git clone <repo url>

Install Scapy: pip install scapy

Run the program (with appropriate permissions): python network_analyzer.py (or python3 network_analyzer.py) You may need administrator or root privileges to capture network traffic.I've created NetSecure Analyzer - a professional packet analysis tool with comprehensive network security monitoring capabilities!

Key Features Built:

1.Real-time Traffic Monitoring - Live packet capture simulation with threat detection
2.Multi-level Threat Classification - Color-coded security alerts (safe → critical)
3.Interactive Packet Inspector - Deep packet analysis with headers and payload inspection
4.Security Dashboard - Real-time statistics and network throughput monitoring
5.Threat Alerts System - Immediate notifications for suspicious activities
6.Professional Security Reports - Detailed findings and recommendations

Design Highlights:

1.Security-focused dark theme with professional blue/cyan accents
2.Color-coded threat levels using semantic design tokens
3.Monospace fonts for technical packet data
4.Real-time animations and status indicators
5.Responsive enterprise-grade interface

Note: This is a sophisticated simulation since actual packet capture requires system-level access not available in web browsers. The tool demonstrates professional network security monitoring interfaces used by SOC.This is for educational purpose only .
## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS
- concepts of wireshark,tcpdump,scapy
