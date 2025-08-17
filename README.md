

# Network Lab Setup with pfSense, Splunk, Kali, and WebServer

This lab demonstrates how to build a small enterprise-like environment using **pfSense** as the router/firewall, with **Splunk** for monitoring, a **Web Server** as the target system, and **Kali Linux** as the attacker machine. The goal is to practice configuring networking, routing, and security rules while enabling controlled communication between networks.

---

## Machine Information

| Machine       | Interface        | Network            | IP Address      |
| ------------- | ---------------- | ------------------ | --------------- |
| **Kali**      | eth0             | VMnet2 (Host-Only) | 10.81.1.128     |
| **pfSense**   | eth0 (WAN)       | NAT                | 192.168.100.10  |
|               | eth1 (OPT1/Kali) | VMnet2 (Host-Only) | 10.81.1.1       |
|               | eth2 (LAN)       | VMnet4 (Host-Only) | 172.16.5.1      |
| **Splunk**    | eth0             | NAT (optional)     | 192.168.100.130 |
|               | eth1             | VMnet4 (Host-Only) | 172.16.5.50     |
| **WebServer** | eth0             | VMnet4 (Host-Only) | 172.16.5.200    |

Here we separate traffic into three zones:

* **WAN (Internet access)** through NAT.
* **LAN (Internal business network)** where Splunk and the WebServer reside.
* **Kali (Attacker network)** isolated on its own subnet, but connected through pfSense so we can control and monitor attacks.

---

## 1. pfSense (Router/Firewall)

### Console Setup

When pfSense boots, accept the defaults. After initial configuration, we assign interfaces:

* **WAN → em0** (connected to Internet/NAT).
* **LAN → em2** (our internal protected network).
* **OPT1 → em1** (this will be renamed later as "Kali").

This segmentation mimics real enterprise setups: WAN for outside traffic, LAN for production, and a separate monitored network for attackers.

### Assigning IPs

Using **Option 2** in the console:

* **LAN (em2):**

  * IP: `172.16.5.20`
  * Subnet: `/24`
  * No gateway (since this is an internal segment).
  * DHCP: disabled for now.
  * HTTPS enabled for secure pfSense web UI access.

* **WAN (em0):**

  * IP: `192.168.100.10`
  * Gateway: `192.168.100.2` (default NAT gateway to Internet).

* **OPT1 (em1 – Kali):**

  * IP: `10.81.1.1`

At this stage, pfSense acts as the central router, separating and routing between networks.

---

## 2. Splunk Configuration

Splunk will live in the **LAN zone**, so we must point it to pfSense as its gateway.
We edit `/etc/netplan/50-vagrant.yaml`:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: false
      addresses:
        - 172.16.5.50/24
      nameservers:
        addresses: [8.8.8.8, 172.16.5.1]
      routes:
        - to: 0.0.0.0/0
          via: 172.16.5.1
          metric: 100
```

* **IP:** `172.16.5.50` (static LAN address).
* **Gateway:** `172.16.5.1` (pfSense LAN).
* **DNS:** Google DNS (`8.8.8.8`) + pfSense (`172.16.5.1`).

Apply with:

```bash
sudo netplan apply
```

This ensures Splunk can reach pfSense, resolve hostnames, and access the Internet.

---

## 3. pfSense Web Interface

Access pfSense webConfigurator via **[https://172.16.5.1](https://172.16.5.1)**.
Login credentials: `admin / pfsense`.

### Wizard Setup

* **DNS servers:** `8.8.8.8` (primary), `4.4.4.4` (secondary).
* **Timezone:** set correctly.
* **Admin password:** change to something secure.
* Reload → apply changes.

This wizard initializes pfSense for first-time use.

---

## 4. Interface Settings in Web UI

Inside pfSense web UI:

* Rename **OPT1 → Kali** for clarity.
* Enable all three interfaces: **WAN, LAN, Kali**.
* On **WAN**, add a gateway (`192.168.100.2`) to enable Internet connectivity through NAT.

This makes pfSense aware of where to forward outbound traffic.

---

## 5. Firewall Rules

By default, pfSense applies:

* **LAN → Allow all outbound**.
* **OPT interfaces → Deny all traffic**.

To allow communication, we must explicitly permit rules.

### Rules to Add

* **Kali Interface (OPT1):**

  * Action: Pass
  * Protocol: Any
  * Source: Kali net (10.81.1.0/24)
  * Destination: Any

* **LAN Interface:**

  * Action: Pass
  * Protocol: Any
  * Source: LAN net (172.16.5.0/24)
  * Destination: Any

With these, both LAN and Kali networks can talk to pfSense and beyond.

---

## Final Result

After completing these steps:

* **Kali (10.81.1.128)** can attack LAN systems via pfSense.
* **Splunk (172.16.5.50)** communicates with the WebServer and also monitors logs.
* **WebServer (172.16.5.200)** can be accessed internally for testing.
* **pfSense** enforces control and acts as the chokepoint for routing and filtering.

This mirrors a real-world **enterprise network** where security teams monitor attacks in a safe, segmented lab.


