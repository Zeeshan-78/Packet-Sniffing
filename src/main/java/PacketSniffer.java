import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;

import java.io.*;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.*;

/**
 * ╔═══════════════════════════════════════════════════╗
 *   Java Packet Sniffer — Educational Network Tool
 *   Use only on networks you own or have permission
 * ╚═══════════════════════════════════════════════════╝
 */
public class PacketSniffer {

    // ── ANSI Colors ────────────────────────────────────────────────────────────
    static final String RESET   = "\u001B[0m";
    static final String RED     = "\u001B[31m";
    static final String GREEN   = "\u001B[32m";
    static final String YELLOW  = "\u001B[33m";
    static final String BLUE    = "\u001B[34m";
    static final String MAGENTA = "\u001B[35m";
    static final String CYAN    = "\u001B[36m";
    static final String WHITE   = "\u001B[97m";
    static final String BOLD    = "\u001B[1m";
    static final String DIM     = "\u001B[2m";

    // ── Stats ──────────────────────────────────────────────────────────────────
    static final AtomicLong totalPackets = new AtomicLong(0);
    static final AtomicLong totalBytes   = new AtomicLong(0);
    static final AtomicLong tcpCount    = new AtomicLong(0);
    static final AtomicLong udpCount    = new AtomicLong(0);
    static final AtomicLong icmpCount   = new AtomicLong(0);
    static final AtomicLong arpCount    = new AtomicLong(0);
    static final AtomicLong otherCount  = new AtomicLong(0);
    static final AtomicBoolean running  = new AtomicBoolean(true);

    static final DateTimeFormatter TIME_FMT =
        DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    static PcapHandle handle = null;
    static PrintWriter logWriter = null;
    static boolean logToFile = false;
    static String logFileName = "";

    // ── Banner ─────────────────────────────────────────────────────────────────
    static void printBanner() {
        System.out.println(BOLD + RED);
        System.out.println("  ██████╗ ██╗  ██╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗");
        System.out.println("  ██╔══██╗██║ ██╔╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝");
        System.out.println("  ██████╔╝█████╔╝    ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  ");
        System.out.println("  ██╔═══╝ ██╔═██╗    ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ");
        System.out.println("  ██║     ██║  ██╗   ██║       ███████║██║ ╚████║██║██║     ██║     ");
        System.out.println("  ╚═╝     ╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ");
        System.out.println(RESET);
        System.out.println(BOLD + WHITE +
            "  ┌──────────────────────────────────────────────────────────────────┐");
        System.out.println(
            "  │          Java Network Packet Sniffer  v1.0                      │");
        System.out.println(
            "  │     For authorized network monitoring and security research      │");
        System.out.println(
            "  └──────────────────────────────────────────────────────────────────┘"
            + RESET);
        System.out.println();
    }

    // ── List interfaces ────────────────────────────────────────────────────────
    static List<PcapNetworkInterface> listInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
        if (nifs == null || nifs.isEmpty()) {
            System.out.println(RED + "[!] No network interfaces found. Try running as root/sudo." + RESET);
            System.exit(1);
        }
        System.out.println(BOLD + CYAN + "\n  Available Network Interfaces:" + RESET);
        System.out.println(DIM + "  ──────────────────────────────────────────────────" + RESET);
        for (int i = 0; i < nifs.size(); i++) {
            PcapNetworkInterface nif = nifs.get(i);
            String desc = nif.getDescription() != null ? nif.getDescription() : "No description";
            System.out.printf("  " + GREEN + "[%02d]" + RESET + " " + BOLD + "%-20s" + RESET +
                              DIM + " %s" + RESET + "%n", i + 1, nif.getName(), desc);

            // Show IP addresses
            for (PcapAddress addr : nif.getAddresses()) {
                if (addr.getAddress() != null) {
                    System.out.printf("       " + YELLOW + "↳ IP: %s" + RESET + "%n",
                                      addr.getAddress().getHostAddress());
                }
            }
        }
        System.out.println();
        return nifs;
    }

    // ── Format bytes ───────────────────────────────────────────────────────────
    static String fmtBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024));
    }

    // ── Protocol color ─────────────────────────────────────────────────────────
    static String protoColor(String proto) {
        return switch (proto) {
            case "TCP"  -> CYAN;
            case "UDP"  -> GREEN;
            case "ICMP" -> YELLOW;
            case "ARP"  -> MAGENTA;
            case "DNS"  -> BLUE;
            case "HTTP" -> RED;
            default     -> WHITE;
        };
    }

    // ── Detect app-layer protocol ──────────────────────────────────────────────
    static String detectAppProto(int srcPort, int dstPort) {
        int lo = Math.min(srcPort, dstPort);
        int hi = Math.max(srcPort, dstPort);
        if (lo == 80  || hi == 80)  return "HTTP";
        if (lo == 443 || hi == 443) return "HTTPS";
        if (lo == 53  || hi == 53)  return "DNS";
        if (lo == 22  || hi == 22)  return "SSH";
        if (lo == 21  || hi == 21)  return "FTP";
        if (lo == 25  || hi == 25)  return "SMTP";
        if (lo == 110 || hi == 110) return "POP3";
        if (lo == 143 || hi == 143) return "IMAP";
        if (lo == 3306|| hi == 3306)return "MySQL";
        if (lo == 5432|| hi == 5432)return "Postgres";
        if (lo == 6379|| hi == 6379)return "Redis";
        if (lo == 8080|| hi == 8080)return "HTTP-ALT";
        return null;
    }

    // ── Hex dump (first N bytes) ───────────────────────────────────────────────
    static String hexDump(byte[] data, int maxBytes) {
        if (data == null || data.length == 0) return "";
        int len = Math.min(data.length, maxBytes);
        StringBuilder hex = new StringBuilder();
        StringBuilder ascii = new StringBuilder();
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < len; i++) {
            if (i > 0 && i % 16 == 0) {
                result.append(String.format("    %s%-48s%s  %s%s%s%n",
                    DIM, hex, RESET, CYAN, ascii, RESET));
                hex.setLength(0); ascii.setLength(0);
            }
            hex.append(String.format("%02X ", data[i]));
            char c = (char)(data[i] & 0xFF);
            ascii.append((c >= 32 && c < 127) ? c : '.');
        }
        if (hex.length() > 0) {
            result.append(String.format("    %s%-48s%s  %s%s%s%n",
                DIM, hex, RESET, CYAN, ascii, RESET));
        }
        return result.toString();
    }

    // ── Print statistics ───────────────────────────────────────────────────────
    static void printStats() {
        System.out.println("\n" + BOLD + WHITE +
            "  ╔══════════════════════════════════════════╗");
        System.out.println(
            "  ║           CAPTURE STATISTICS             ║");
        System.out.println(
            "  ╚══════════════════════════════════════════╝" + RESET);
        System.out.printf("  " + GREEN  + "  Total Packets : " + BOLD + "%d%n" + RESET, totalPackets.get());
        System.out.printf("  " + CYAN   + "  Total Data    : " + BOLD + "%s%n" + RESET, fmtBytes(totalBytes.get()));
        System.out.println(DIM + "  ──────────────────────────────────────" + RESET);
        System.out.printf("  " + CYAN   + "  TCP           : %d%n" + RESET, tcpCount.get());
        System.out.printf("  " + GREEN  + "  UDP           : %d%n" + RESET, udpCount.get());
        System.out.printf("  " + YELLOW + "  ICMP          : %d%n" + RESET, icmpCount.get());
        System.out.printf("  " + MAGENTA+ "  ARP           : %d%n" + RESET, arpCount.get());
        System.out.printf("  " + WHITE  + "  Other         : %d%n" + RESET, otherCount.get());
        if (logToFile) {
            System.out.println(DIM + "  ──────────────────────────────────────" + RESET);
            System.out.printf("  " + YELLOW + "  Log saved to  : %s%n" + RESET, logFileName);
        }
        System.out.println();
    }

    // ── Handle one packet ──────────────────────────────────────────────────────
    static void handlePacket(Packet packet, boolean verbose, boolean showHex) {
        if (packet == null) return;

        long pktNum  = totalPackets.incrementAndGet();
        int  rawLen  = packet.length();
        totalBytes.addAndGet(rawLen);
        String timestamp = LocalDateTime.now().format(TIME_FMT);

        String srcIP = "?", dstIP = "?";
        String proto = "???";
        String extra = "";

        // ── ARP ───────────────────────────────────────────────────────────────
        if (packet.contains(ArpPacket.class)) {
            ArpPacket arp = packet.get(ArpPacket.class);
            proto  = "ARP";
            srcIP  = arp.getHeader().getSrcProtocolAddr().getHostAddress();
            dstIP  = arp.getHeader().getDstProtocolAddr().getHostAddress();
            extra  = arp.getHeader().getOperation().name();
            arpCount.incrementAndGet();

        // ── IP-based ──────────────────────────────────────────────────────────
        } else if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ip = packet.get(IpV4Packet.class);
            srcIP = ip.getHeader().getSrcAddr().getHostAddress();
            dstIP = ip.getHeader().getDstAddr().getHostAddress();

            // TCP
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcp = packet.get(TcpPacket.class);
                int sp = tcp.getHeader().getSrcPort().valueAsInt();
                int dp = tcp.getHeader().getDstPort().valueAsInt();
                proto  = "TCP";
                String app = detectAppProto(sp, dp);
                extra  = String.format("%d → %d%s", sp, dp,
                         app != null ? " [" + app + "]" : "");
                extra += flagStr(tcp);
                tcpCount.incrementAndGet();

            // UDP
            } else if (packet.contains(UdpPacket.class)) {
                UdpPacket udp = packet.get(UdpPacket.class);
                int sp = udp.getHeader().getSrcPort().valueAsInt();
                int dp = udp.getHeader().getDstPort().valueAsInt();
                proto  = "UDP";
                String app = detectAppProto(sp, dp);
                extra  = String.format("%d → %d%s", sp, dp,
                         app != null ? " [" + app + "]" : "");
                udpCount.incrementAndGet();

            // ICMP
            } else if (packet.contains(IcmpV4CommonPacket.class)) {
                proto = "ICMP";
                IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
                extra = icmp.getHeader().getType().name();
                icmpCount.incrementAndGet();

            } else {
                proto = ip.getHeader().getProtocol().name();
                otherCount.incrementAndGet();
            }

        } else {
            proto = "???";
            otherCount.incrementAndGet();
        }

        // ── Print packet line ──────────────────────────────────────────────────
        String color = protoColor(proto);
        String line  = String.format(
            "  %s#%-5d%s %s%s%s  %s%-6s%s  %s%-16s%s → %s%-16s%s  %s%d B%s  %s%s%s",
            DIM,    pktNum,    RESET,
            DIM,    timestamp, RESET,
            color,  proto,     RESET,
            YELLOW, srcIP,     RESET,
            CYAN,   dstIP,     RESET,
            DIM,    rawLen,    RESET,
            DIM,    extra,     RESET
        );
        System.out.println(line);
        if (logToFile && logWriter != null) {
            logWriter.println(String.format("#%d %s  %-6s  %-16s -> %-16s  %d B  %s",
                pktNum, timestamp, proto, srcIP, dstIP, rawLen, extra));
        }

        // ── Verbose / Hex ──────────────────────────────────────────────────────
        if (verbose && packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            if (tcp.getPayload() != null) {
                byte[] payload = tcp.getPayload().getRawData();
                if (payload.length > 0) {
                    String text = new String(payload).replaceAll("[\\x00-\\x1F\\x7F-\\xFF]", ".");
                    String preview = text.length() > 80 ? text.substring(0, 80) + "…" : text;
                    System.out.println("  " + DIM + "  Payload: " + RESET + GREEN + preview + RESET);
                }
            }
        }
        if (showHex && packet.getRawData() != null) {
            System.out.print(hexDump(packet.getRawData(), 64));
        }
    }

    // ── TCP flag string ────────────────────────────────────────────────────────
    static String flagStr(TcpPacket tcp) {
        TcpPacket.TcpHeader h = tcp.getHeader();
        StringBuilder sb = new StringBuilder(" [");
        if (h.getSyn()) sb.append("SYN ");
        if (h.getAck()) sb.append("ACK ");
        if (h.getFin()) sb.append("FIN ");
        if (h.getRst()) sb.append("RST ");
        if (h.getPsh()) sb.append("PSH ");
        if (h.getUrg()) sb.append("URG ");
        String s = sb.toString().trim();
        return s.equals("[") ? "" : s + "]";
    }

    // ── Print header ───────────────────────────────────────────────────────────
    static void printHeader() {
        System.out.println();
        System.out.println(BOLD + WHITE +
            "  #       Time           Proto   Src              Dst              Size   Info" + RESET);
        System.out.println(DIM +
            "  ─────────────────────────────────────────────────────────────────────────────" + RESET);
    }

    // ── Main ───────────────────────────────────────────────────────────────────
    public static void main(String[] args) throws Exception {
        printBanner();

        Scanner sc = new Scanner(System.in);

        // List interfaces
        List<PcapNetworkInterface> nifs = listInterfaces();

        // Choose interface
        System.out.print(BOLD + GREEN + "  [+] Choose interface number: " + RESET);
        int idx = 1;
        try { idx = Integer.parseInt(sc.nextLine().trim()); } catch (Exception ignored) {}
        if (idx < 1 || idx > nifs.size()) idx = 1;
        PcapNetworkInterface nif = nifs.get(idx - 1);
        System.out.println(GREEN + "  [✓] Selected: " + BOLD + nif.getName() + RESET);

        // BPF Filter
        System.out.print(BOLD + GREEN +
            "  [+] BPF Filter (Enter to skip, e.g. 'tcp port 80'): " + RESET);
        String filter = sc.nextLine().trim();

        // Verbose mode
        System.out.print(BOLD + GREEN + "  [+] Show payload preview? [y/N]: " + RESET);
        boolean verbose = sc.nextLine().trim().equalsIgnoreCase("y");

        // Hex dump
        System.out.print(BOLD + GREEN + "  [+] Show hex dump? [y/N]: " + RESET);
        boolean showHex = sc.nextLine().trim().equalsIgnoreCase("y");

        // Log to file
        System.out.print(BOLD + GREEN + "  [+] Save log to file? [y/N]: " + RESET);
        logToFile = sc.nextLine().trim().equalsIgnoreCase("y");
        if (logToFile) {
            logFileName = "capture_" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".log";
            logWriter = new PrintWriter(new FileWriter(logFileName));
            System.out.println(GREEN + "  [✓] Logging to: " + BOLD + logFileName + RESET);
        }

        // Packet count limit
        System.out.print(BOLD + GREEN + "  [+] Max packets to capture (0 = unlimited): " + RESET);
        int maxPkts = 0;
        try { maxPkts = Integer.parseInt(sc.nextLine().trim()); } catch (Exception ignored) {}

        // Open handle
        int snapLen  = 65536;
        int timeout  = 10;
        handle = nif.openLive(snapLen, PromiscuousMode.PROMISCUOUS, timeout);

        if (!filter.isEmpty()) {
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            System.out.println(GREEN + "  [✓] Filter applied: " + BOLD + filter + RESET);
        }

        // Shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            running.set(false);
            if (handle != null && handle.isOpen()) handle.close();
            if (logWriter != null) logWriter.close();
            System.out.println();
            printStats();
        }));

        System.out.println();
        System.out.println(GREEN + "  [✓] Capturing on " + BOLD + nif.getName() + RESET +
                           GREEN + " — " + BOLD + "Ctrl+C to stop" + RESET);
        printHeader();

        int captured = 0;
        while (running.get()) {
            try {
                Packet pkt = handle.getNextPacketEx();
                if (pkt != null) {
                    handlePacket(pkt, verbose, showHex);
                    captured++;
                    if (maxPkts > 0 && captured >= maxPkts) {
                        System.out.println("\n" + YELLOW + "  [!] Packet limit reached." + RESET);
                        break;
                    }
                }
            } catch (TimeoutException ignored) {
            } catch (EOFException | NotOpenException e) {
                break;
            }
        }

        if (handle != null && handle.isOpen()) handle.close();
        if (logWriter != null) logWriter.close();
        printStats();
    }
}
