# 📡 Java Packet Sniffer

![Java](https://img.shields.io/badge/Java-11%2B-orange?logo=java)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-Maven-red)

> A powerful network packet sniffer written in Java with a beautiful ASCII banner, colored output, and real-time statistics.

---

## 🖥️ Preview

```
  ██████╗ ██╗  ██╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗
  ██╔══██╗██║ ██╔╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝
  ██████╔╝█████╔╝    ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  
  ██╔═══╝ ██╔═██╗    ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  
  ██║     ██║  ██╗   ██║       ███████║██║ ╚████║██║██║     ██║     
  ╚═╝     ╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝

  #1     14:32:05.123   TCP    192.168.1.5      → 142.250.1.1      84 B   443→80 [HTTP][SYN ACK]
  #2     14:32:05.201   UDP    192.168.1.5      → 8.8.8.8          72 B   12345→53 [DNS]
  #3     14:32:05.310   ICMP   192.168.1.1      → 192.168.1.5      64 B   ECHO_REQUEST
```

---

## ✨ Features

- 🎨 **ASCII Banner** with colored terminal output
- 🌐 **Auto-detects** all network interfaces with IPs
- 🔍 **BPF Filter** support (`tcp`, `udp port 53`, `host 192.168.1.1`, etc.)
- 📦 **Protocol detection**: TCP, UDP, ICMP, ARP, HTTP, HTTPS, DNS, SSH, FTP and more
- 🏴 **TCP Flag display**: SYN, ACK, FIN, RST, PSH, URG
- 👁️ **Payload preview** mode (ASCII)
- 🔢 **Hex dump** mode
- 📊 **Live statistics** on exit
- 💾 **Save to log file** option
- 🔢 **Packet limit** support

---

## 📋 Requirements

| Requirement | Version |
|---|---|
| Java JDK | 11+ |
| Maven | 3.6+ |
| libpcap | Latest |

---

## 🚀 Installation & Run

### Kali Linux / Ubuntu / Debian

```bash
# 1. Install dependencies
sudo apt update
sudo apt install default-jdk maven libpcap-dev -y

# 2. Clone the repo
git clone https://github.com/YOUR_USERNAME/java-packet-sniffer.git
cd java-packet-sniffer

# 3. Build & Run (one command)
chmod +x run.sh
./run.sh
```

### Manual Build

```bash
# Build
mvn package

# Run (needs root for raw packet capture)
sudo java -jar target/packet-sniffer.jar
```

---

## 💬 Usage

When you run the tool, it will ask:

```
[+] Choose interface number:   → pick eth0, wlan0, etc.
[+] BPF Filter:                → optional, e.g. "tcp port 80"
[+] Show payload preview?      → y/N
[+] Show hex dump?             → y/N
[+] Save log to file?          → y/N
[+] Max packets (0=unlimited): → 0 for endless capture
```

### BPF Filter Examples

| Filter | Description |
|---|---|
| `tcp` | Only TCP packets |
| `udp` | Only UDP packets |
| `port 80` | Only HTTP traffic |
| `port 53` | Only DNS traffic |
| `host 192.168.1.1` | Only packets to/from one IP |
| `tcp port 443` | Only HTTPS |
| `not port 22` | Everything except SSH |
| `icmp` | Only ping packets |

---

## 📁 Project Structure

```
java-packet-sniffer/
├── src/
│   └── main/java/
│       └── PacketSniffer.java   ← Main source code
├── pom.xml                      ← Maven build file
├── run.sh                       ← Build & run script
├── .gitignore
└── README.md
```

---

## ⚠️ Legal Notice

> This tool is for **educational purposes and authorized network monitoring only**.  
> Never use it on networks you do not own or have explicit permission to monitor.  
> Unauthorized packet sniffing is **illegal** in most countries.

---

## 📄 License

MIT License — free to use, modify, and share.
