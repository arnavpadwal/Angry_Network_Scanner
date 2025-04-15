import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.TcpPort;

import java.io.FileWriter;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

// Main class
public class AngryNetScan {

    // ANSI escape codes for colored CLI output
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";

    // Result holders
    private static List<Map<String, Object>> localScanResults = Collections.synchronizedList(new ArrayList<>());
    private static List<Map<String, Object>> networkScanResults = Collections.synchronizedList(new ArrayList<>());
    private static List<Map<String, Object>> packetAnalysisResults = Collections.synchronizedList(new ArrayList<>());

    public static void main(String[] args) {

        System.out.println(ANSI_BLUE + "\n=== Starting Local Device Scan ===\n" + ANSI_RESET);
        localDeviceScan();
        saveResultsAsJson(localScanResults, "LocalScanResults.json");

        System.out.println(ANSI_BLUE + "\n=== Starting Entire Network Scan ===\n" + ANSI_RESET);
        networkScan();
        saveResultsAsJson(networkScanResults, "NetworkScanResults.json");

        System.out.println(ANSI_BLUE + "\n=== Starting Packet Capture and Analysis (Press Ctrl+C to stop) ===\n" + ANSI_RESET);
        // Run packet capture in main thread (or separate thread as desired)
        packetCaptureAndAnalysis();
    }

    // ******************* Local Device Scan **********************
    public static void localDeviceScan() {
        final String host = "127.0.0.1";
        // For dynamic thread pool, number of threads = available processors * 2 (as an example)
        int threads = Runtime.getRuntime().availableProcessors() * 2;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        AtomicInteger openCount = new AtomicInteger(0);

        // We'll scan ports from 1 to 65535
        for (int port = 1; port <= 65535; port++) {
            final int currentPort = port;
            executor.submit(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, currentPort), 50); // 50ms timeout
                    // if connection is established then port is open
                    String message = ANSI_GREEN + "Open port detected: " + currentPort + ANSI_RESET;
                    System.out.println(message);
                    Map<String, Object> result = new HashMap<>();
                    result.put("port", currentPort);
                    result.put("status", "open");
                    result.put("remarks", "Port accepted connection");
                    localScanResults.add(result);
                    openCount.incrementAndGet();
                } catch (IOException e) {
                    // port is closed or filtered; do nothing or log if needed
                }
            });
        }
        executor.shutdown();
        try {
            // wait for all tasks to finish or timeout after a while
            if (!executor.awaitTermination(20, TimeUnit.MINUTES)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println(ANSI_YELLOW + "Local scan finished. Open ports count: " + openCount.get() + ANSI_RESET);
    }

    // ******************* Network Scan **********************
    public static void networkScan() {
        // Determine local network interface and IPv4 address/subnet
        List<InetAddress> localAddresses = getLocalIPv4Addresses();
        if (localAddresses.isEmpty()) {
            System.out.println(ANSI_RED + "No non-loopback IPv4 address found. Exiting network scan." + ANSI_RESET);
            return;
        }
        // For simplicity, we take the first one and assume a /24 subnet.
        InetAddress localAddress = localAddresses.get(0);
        System.out.println(ANSI_YELLOW + "Using local address: " + localAddress.getHostAddress() + " (Assuming /24 subnet)" + ANSI_RESET);
        String subnet = getSubnet(localAddress);
        // For a /24 network, iterate from .1 to .254 (skipping network and broadcast addresses).
        ExecutorService executor = Executors.newCachedThreadPool();
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 1; i <= 254; i++) {
            final String targetIp = subnet + i;
            futures.add(executor.submit(() -> {
                try {
                    InetAddress addr = InetAddress.getByName(targetIp);
                    // Ping host with 100ms timeout. If reachable, scan ports
                    if (addr.isReachable(100)) {
                        System.out.println(ANSI_GREEN + "Host up: " + targetIp + ANSI_RESET);
                        Map<String, Object> hostResult = new HashMap<>();
                        hostResult.put("ip", targetIp);
                        List<Map<String, Object>> openPorts = scanPorts(targetIp);
                        hostResult.put("openPorts", openPorts);
                        // You can add further analysis here (e.g. service banners)
                        networkScanResults.add(hostResult);
                    }
                } catch (IOException e) {
                    // Host unreachable, do nothing.
                }
            }));
        }
        // wait for completion
        for (Future<?> f : futures) {
            try {
                f.get();
            } catch (Exception e) {
                // ignore or log
            }
        }
        executor.shutdown();
        System.out.println(ANSI_YELLOW + "Network scan completed." + ANSI_RESET);
    }

    // Scan ports on a given host (try all ports from 1 to 65535). For network scan, use dynamic threads.
    public static List<Map<String, Object>> scanPorts(String host) {
        List<Map<String, Object>> openPorts = Collections.synchronizedList(new ArrayList<>());
        int threads = Runtime.getRuntime().availableProcessors() * 2;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<?>> futures = new ArrayList<>();

        for (int port = 1; port <= 65535; port++) {
            final int currentPort = port;
            futures.add(executor.submit(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, currentPort), 50);
                    // if connection established, port is open
                    String msg = ANSI_GREEN + "Host: " + host + " open port: " + currentPort + ANSI_RESET;
                    System.out.println(msg);
                    Map<String, Object> result = new HashMap<>();
                    result.put("port", currentPort);
                    result.put("status", "open");
                    result.put("remarks", "Port accepted connection");
                    openPorts.add(result);
                } catch (IOException e) {
                    // port closed; do nothing.
                }
            }));
        }
        executor.shutdown();
        try {
            if (!executor.awaitTermination(30, TimeUnit.MINUTES)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return openPorts;
    }

    // ******************* Packet Capture and Analysis **********************
    public static void packetCaptureAndAnalysis() {
        // Find a non-loopback interface for capture
        PcapNetworkInterface nif = null;
        try {
            // pick the first network interface that supports capture
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            for (PcapNetworkInterface dev : allDevs) {
                if (!dev.getName().contains("lo") && dev.getAddresses().size() > 0) {
                    nif = dev;
                    break;
                }
            }
            if (nif == null) {
                System.out.println(ANSI_RED + "No suitable network interface found for packet capture." + ANSI_RESET);
                return;
            }
            System.out.println(ANSI_YELLOW + "Capturing on interface: " + nif.getName() + ANSI_RESET);
        } catch (PcapNativeException e) {
            System.out.println(ANSI_RED + "Error finding network interfaces: " + e.getMessage() + ANSI_RESET);
            return;
        }

        int snapshotLength = 65536; // in bytes
        int timeout = 10; // in milliseconds

        try (PcapHandle handle = nif.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout)) {

            PacketListener listener = packet -> {
                // For each captured packet, print info and run some basic rules
                String packetInfo = ANSI_BLUE + "Packet captured: " + packet + ANSI_RESET;
                System.out.println(packetInfo);
                Map<String, Object> analysis = new HashMap<>();
                analysis.put("timestamp", System.currentTimeMillis());
                analysis.put("packet", packet.toString());
                // Basic anomaly detection rules:
                String remark = "";
                boolean anomaly = false;
                // Rule 1: TCP packet with SYN and no ACK flag
                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcp = packet.get(TcpPacket.class);
                    TcpPacket.TcpHeader header = tcp.getHeader();
                    if (header.getSyn() && !header.getAck()) {
                        anomaly = true;
                        remark += "TCP SYN without ACK; ";
                    }
                }
                // Rule 2: packet with unusually large size
                if (packet.length() > 1500) {
                    anomaly = true;
                    remark += "Large packet size: " + packet.length() + "; ";
                }
                // Rule 3: UDP packet from a privileged port (other than DNS 53)
                if (packet.contains(UdpPacket.class)) {
                    UdpPacket udp = packet.get(UdpPacket.class);
                    int srcPort = udp.getHeader().getSrcPort().valueAsInt();
                    if (srcPort < 1024 && srcPort != 53) {
                        anomaly = true;
                        remark += "UDP packet from privileged port: " + srcPort + "; ";
                    }
                }
                analysis.put("anomaly", anomaly);
                analysis.put("remarks", remark.isEmpty() ? "Normal" : remark);
                packetAnalysisResults.add(analysis);
            };

            // Start packet capture in blocking loop
            // Note: capture 0 means infinite capture until error or interruption.
            handle.loop(-1, listener);
        } catch (PcapNativeException | InterruptedException | NotOpenException e) {
            System.out.println(ANSI_RED + "Error in packet capture: " + e.getMessage() + ANSI_RESET);
        }
    }

    // ******************* Utility Functions **********************
    // Get non-loopback IPv4 addresses
    private static List<InetAddress> getLocalIPv4Addresses() {
        List<InetAddress> addresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                if (iface.isLoopback() || !iface.isUp())
                    continue;
                Enumeration<InetAddress> inetAddrs = iface.getInetAddresses();
                while (inetAddrs.hasMoreElements()) {
                    InetAddress addr = inetAddrs.nextElement();
                    if (addr instanceof Inet4Address) {
                        addresses.add(addr);
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return addresses;
    }

    // Given an IPv4 address (e.g., 192.168.1.5), return the subnet string like "192.168.1."
    private static String getSubnet(InetAddress address) {
        String ip = address.getHostAddress();
        int lastDot = ip.lastIndexOf(".");
        return ip.substring(0, lastDot + 1);
    }

    // Save results as pretty JSON file (basic implementation)
    private static void saveResultsAsJson(List<Map<String, Object>> results, String filename) {
        String json = toJson(results);
        try (FileWriter file = new FileWriter(filename)) {
            file.write(json);
            System.out.println(ANSI_BLUE + "Results saved to: " + filename + ANSI_RESET);
        } catch (IOException e) {
            System.out.println(ANSI_RED + "Error saving JSON file: " + e.getMessage() + ANSI_RESET);
        }
    }

    // Simple JSON conversion (for demonstration; in production use a JSON library)
    private static String toJson(Object obj) {
        if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            
            int count = 0;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                sb.append("\"").append(entry.getKey().toString()).append("\":");
                sb.append(toJson(entry.getValue()));
                if (++count < map.size())
                    sb.append(",");
            }
            
            sb.append("}");
            return sb.toString();
            
        } else if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            
            int count = 0;
            for (Object item : list) {
                sb.append(toJson(item));
                if (++count < list.size())
                    sb.append(",");
            }
            
            sb.append("]");
            return sb.toString();
            
        } else if (obj instanceof String) {
            return "\"" + obj.toString().replace("\"", "\\\"") + "\"";
            
        } else {
            return obj.toString();
        }
    }

}
