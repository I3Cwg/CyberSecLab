# Summarize the issues I’ve encountered and how to resolve them.


## 1. **Không truy cập được WebUI pfSense**

* **Nguyên nhân:** Bạn đang thử từ WAN hoặc OPT interface (pfSense mặc định chặn).
* **Giải pháp:**

  * Truy cập từ **LAN IP** (`https://172.16.5.1`).
  * Đảm bảo client (Splunk, Windows) nằm cùng mạng **LAN (VMnet2)**.
  * Nếu muốn truy cập từ OPT1 (Kali), phải thêm **Firewall Rule** cho OPT1 → cho phép TCP/443 đến “This Firewall”.

---

## 2. **Kali ping được pfSense, nhưng pfSense không ping lại được Kali (hoặc ngược lại)**

* **Nguyên nhân:**

  * OPT interfaces mặc định **deny all inbound traffic**.
* **Giải pháp:**

  * Vào **Firewall → Rules → OPT1** → thêm rule:

    * Action: Pass
    * Source: OPT1 net
    * Destination: any
    * Protocol: any
  * Apply → giờ Kali có thể ping pfSense và đi ra ngoài.

---


## 4. **Linux (Splunk server) chỉ ping được trong LAN, không đi Internet**

* **Nguyên nhân:**
  * File netplan thiếu **default gateway**.
* **Giải pháp:**


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
  * Fix quyền file netplan:

    ```bash
    sudo chown root:root /etc/netplan/50-vagrant.yaml
    sudo chmod 600 /etc/netplan/50-vagrant.yaml
    ```
  * Apply:

    ```bash
    sudo netplan generate
    sudo netplan try
    sudo netplan apply
    ```

---

## 5. **DNS và Routing hay bị nhầm**

* **Nguyên nhân:** nhiều bạn nhầm DNS server với Gateway.
* **Ghi nhớ:**

  * **Gateway** = “cửa ra khỏi mạng LAN” → luôn trỏ về pfSense LAN IP (`172.16.5.1`).
  * **Nameserver** = dịch tên miền → có thể dùng `8.8.8.8`, `1.1.1.1` hoặc chính pfSense (`172.16.5.1` nếu bạn bật DNS Resolver).

---
Ping block didn’t work inside the same LAN

Symptom: Host 172.16.5.50 can ping 172.16.5.100 even with a Reject ICMP rule.

Root cause: Both hosts are in the same L2 subnet, so traffic never traverses pfSense (it stays on the switch).

Fix options:

Split into VLANs/subnets so inter-host traffic must route via pfSense, then apply ICMP reject rules; or

Use L2 switch ACL to block host-to-host ping within the same VLAN.

---
Apache logs ingestion without parsing

Symptom: Apache logs arrive but fields like clientip, method, status aren’t extracted.

Root cause: Missing Apache TA or wrong sourcetypes.

Fix: Install Splunk Add-on for Apache on indexers + search heads. On UF:

[monitor:///var/log/apache2/access.log]
sourcetype = apache:access
index = web_access

[monitor:///var/log/apache2/error.log]
sourcetype = apache:error
index = web_error


Ensure web_access and web_error indexes exist.

Verify (SPL):

index=web_access sourcetype=apache:access
| stats count by clientip, method, status, uri_path

---

