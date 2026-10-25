# Data exploration

Notes from inspecting the raw datasets by hand (README files and Wireshark),
before writing any code. Goal: check the design decisions in `baseline_spec.md`
against real packets, and collect what is needed for device attribution
(decision 8) and labeling (decision 9).

---

## 1. What the dataset READMEs say

### CICIoT2022 (used for profiling)
- 40 IoT devices, grouped as Audio, Camera, Home Automation and Other
  (smart TV, water sensor, weather station).
- **Power:** each device powered on alone after a network reboot; 3 captures per device.
  Clean single-device traffic.
- **Idle:** whole network at night, no human interaction; 30 daily pcaps.
- **Interactions:** each device function triggered 3 times, via physical buttons,
  companion app on LAN, companion app over WAN, or voice assistant.
- **Active:** whole network during the day, people interacting; 30 daily pcaps.
- Not used: Scenarios, Attacks.

### CICIoT2023 (used for evaluation)
- Each pcap was split with tcpdump into chunks of at most 2 GB.
- `README_Victims_List.pdf` lists target devices **by name** for every attack.
  MAC addresses are given only for 3 Raspberry Pis:
  `dc:a6:32:c9:e6:f4`, `dc:a6:32:c9:e4:c6`, `dc:a6:32:c9:e5:02`.
- **Attackers are not listed.** They must be identified from the traffic.
- Device names in the PDF are inconsistent (e.g. "Gosund" / "GoSund",
  "HomeEye" / "Home Eye Camera"); a canonical device list is needed.

### Victims of the two starter attacks
| Attack | Victims |
|---|---|
| Dictionary brute force | HeimVision Smart WiFi Camera, Luohe Cam Dog, 3 Raspberry Pis (`e6:f4`, `e4:c6`, `e5:02`) |
| Port scan | ~60 devices, almost the whole network |

This matches the paper (Section 5.4.3): the dictionary file contains 3 SSH and
2 RTSP brute-force attacks — consistent with 3 Raspberry Pis (SSH) and
2 cameras (RTSP).

### Device overlap
CICIoT2022 has 40 devices; CICIoT2023 has 105. Some 2023 devices will have no
2022 profile, which the paper also reports as a source of false positives.

---

## 2. File statistics (`capinfos`)

| File | Packets | Size | Duration |
|---|---|---|---|
| `ciciot2023/PCAP/DictionaryBruteForce/DictionaryBruteForce.pcap` | 133 k | 39 MB | 254,640 s (≈ 70.7 h) |
| `ciciot2023/PCAP/Recon-PortScan/Recon-PortScan.pcap` | 831 k | 200 MB | 89,100 s (≈ 24.75 h) |
| `ciciot2023/PCAP/Benign_Final/BenignTraffic.pcap` | 3,664 k | 2,048 MB | 33,328 s (≈ 9.3 h) |

**Observation:** the paper reports each brute-force attack lasting 60–195 s
and the port scan about 60 s (Table 8), yet these files span days or a full day.
The attacks are short bursts inside long captures, so a whole attack file
cannot be labeled "attack". Only attacker → victim packets are attacks.

### Sample used for exploration
`data/samples/benign_sample.pcap`: first 200,000 packets of `BenignTraffic.pcap`,
47 MB, about the first 30 minutes. Created with:

```
editcap -r data/raw/ciciot2023/PCAP/Benign_Final/BenignTraffic.pcap data/samples/benign_sample.pcap 1-200000
```

---

## 3. Step A — devices in the benign sample

Wireshark: Statistics → Endpoints, with name resolution on.
Full list saved in `docs/device_macs.csv`.

**Counts:** 88 Ethernet addresses, 356 IPv4 addresses.

### 3.1 Gateway
`3c:18:a0:41:c3:a0` appears in 156,323 of 200,000 packets (78%), sending and
receiving. Almost certainly the gateway (the Windows machine routing traffic to
the internet).
- It gets **no profile** (decision 8).
- A packet whose destination MAC is the gateway is leaving the local network,
  which complements the **scope** field.

### 3.2 Group (non-device) addresses — 17
Broadcast `ff:ff:ff:ff:ff:ff` and multicast addresses (prefixes `01:` and `33:`),
including mDNS, SSDP, Spanning Tree (`01:80:c2:00:00:00`) and Cisco
(`01:00:0c:...`). They only receive, never send.

**Rule for code:** a MAC is a group address if the lowest bit of its first byte is 1
(first byte is odd).

```python
is_group = int(mac[0:2], 16) & 1 == 1
```

### 3.3 Real devices — 71
- **~59 IoT devices**, close to the ~60 targets in the victims list.
- **1 gateway** (3.1).
- **10 Raspberry Pis** (prefixes `dc:a6:32` and `e4:5f:01`):
  - 3 are **victims**: `dc:a6:32:c9:e4:c6`, `dc:a6:32:c9:e6:f4`, `dc:a6:32:c9:e5:02`.
  - 6 are **almost silent** in benign traffic (2–5 packets in 30 min):
    `dc:a6:32:c9:e4:d5`, `dc:a6:32:c9:e4:90`, `dc:a6:32:c9:e5:a4`,
    `dc:a6:32:c9:e4:ab`, `dc:a6:32:c9:e5:ef`, `e4:5f:01:55:90:c4`.
    *Hypothesis:* these are the attacker machines (to verify in Steps B and C).
  - 1 is **busy** in benign traffic: `dc:a6:32:dc:27:d5` (3,353 packets).
    *Hypothesis:* the "attacker Raspberry Pi" the paper mentions as having normal
    casting traffic to the Google Nest Mini on port 8009 (to verify).
- **1 randomized MAC:** `56:4f:8a:e1:f3:2d`. The second hex digit marks a locally
  administered address, typical of phones and laptops, not IoT devices.

### 3.4 Families of identical devices
- 10 MACs (prefixes `24:a1:60`, `50:02:91`, `b8:f0:09`, `c4:dd:57`, `f4:cf:a2`)
  each sent ~1,120 packets and received 56–57.
- 5 MACs with prefix `d4:a6:51` behave almost identically to each other.

*Hypothesis:* batches of cheap smart plugs and bulbs with the same firmware.
Consequence: the MAC fields are the only thing telling these devices apart,
which supports keeping them in the representation (decision 1).

### 3.5 IPv4
- **Local network: `192.168.137.0/24`** (private, RFC 1918). This confirms
  **decision 5**: our private-IP rule correctly marks it as LAN.
  It is also the default subnet of Windows Internet Connection Sharing, consistent
  with the CIC lab description. The gateway is likely `192.168.137.1` (to confirm).
- `0.0.0.0` (475 packets): devices requesting an address via DHCP.
- Many public IPs exchange exactly one 90-byte packet each way, which matches
  the size of an NTP time-sync packet. Repetitive traffic like this is what
  packet representations compress well.

---

## 4. Step B — dictionary brute-force attacker

File: `ciciot2023/PCAP/DictionaryBruteForce/DictionaryBruteForce.pcap`
(whole file, 133,138 packets). Filter `tcp.port == 22 || tcp.port == 554`
keeps 27,949 packets (21.0%).

### Attacker
**`dc:a6:32:dc:27:d5` (Raspberry Pi)** is the source of all 5 attacks.
This is the Pi that is *busy* in benign traffic (Step A, 3,353 packets), so the
attacker also produces normal traffic. Labels must use attacker → victim pairs,
not "everything from the attacker".

Evidence: its SSH client identifies as `SSH-2.0-libssh_0.9.5` (library used by
brute-force tools such as Hydra); the victims answer `SSH-2.0-OpenSSH_8.4p1 Raspbian`.
First attack packet: 2022-10-14 16:18:30 UTC.

### The 5 attacks
| # | Victim MAC | Victim IP | Attacker IP | Protocol | Packets | Duration |
|---|---|---|---|---|---|---|
| 1 | `dc:a6:32:c9:e5:02` (Pi) | 192.168.137.238 | 192.168.137.225 | SSH (22) | 314 | 10.2 s |
| 2 | `dc:a6:32:c9:e6:f4` (Pi) | 192.168.137.161 | 192.168.137.225 | SSH (22) | 323 | 21.3 s |
| 3 | `BilianElectr_cd:18:32` (camera) | 192.168.137.140 | 192.168.137.65 | RTSP (554) | 1,990 | 50.7 s |
| 4 | `BilianElectr_ec:10:4a` (camera) | 192.168.137.11 | 192.168.137.65 | RTSP (554) | 3,674 | 16.8 s |
| 5 | `dc:a6:32:c9:e4:c6` (Pi) | 192.168.137.67 | 192.168.137.65 | SSH (22) | 21,648 | 1,420.8 s |

This matches the victims list (3 Pis + HeimVision and Luohe cameras) and the paper
(3 SSH + 2 RTSP attacks). Bilian Electronic makes Wi-Fi modules used in cameras;
which camera is HeimVision and which is Luohe is still unknown.

### Timing
The I/O graph shows two clusters about 250,000 s (≈ 2.9 days) apart:
attacks 1–2 in the first, attacks 3–5 in the second.

### Same MAC, different IPs
The attacker is `.225` in the first cluster and `.65` in the second: DHCP gave it a
new address between the two. Real evidence for the paper's choice to drop IPs from
representations (Section 4.3.4), and the reason labels use MACs, not IPs.

### Difference from the paper
Our durations (10–1,421 s) differ from the paper's Table 8 (61, 61, 195, 60, 60 s).
Likely reasons: we measure only attacker ↔ victim SSH/RTSP packets, while the
paper's traffic duration seems to include surrounding traffic (≈ 60 s windows),
and the paper caps tests at 10,000 packets.

### Labeling rule (decision 9)
A packet is **attack** if source MAC = attacker and destination MAC = one of the
attack's victims, within that attack's time window (first to last attacker → victim
packet). Everything else is **benign**. Windows are computed in code, not copied
from Wireshark.

## 5. Step C — port-scan attacker

File: `ciciot2023/PCAP/Recon-PortScan/Recon-PortScan.pcap` (831 k packets, 24.75 h).
Wireshark's sorting hid the scanner (French thousands separators break numeric sort),
so counts were made with `tshark`.

### Attacker
**`dc:a6:32:dc:27:d5`, IP `192.168.137.178`**: the same Raspberry Pi as the
brute-force attacks (third IP for the same MAC: `.225`, `.65`, `.178`).
It sent **143,141 SYN packets**; the next sender sent 9,804.

Other top SYN senders are normal devices. Example: `ac:17:02:05:34:27` sends almost all
its SYNs to one internet server (`157.249.81.141`) on ports 80 and 443.

### Scan pattern
- ~150–164 SYNs per destination port, spread evenly over ~930 ports, consistent with
  Nmap's default top-1,000 ports.
- Bursts of ~2,000 SYNs about every 3 minutes, one device at a time
  (~1,000 ports × 2 attempts). Each device received ~2,000–3,000 SYNs.
- Port 8009 (attacker's normal casting traffic) is not significant.

### Two scan sessions
| Session | Date | Local time (+02:00) | UTC |
|---|---|---|---|
| 1 | 26 Sep 2022 | 18:31 → 21:07 | 16:31 → 19:07 |
| 2 | 27 Sep 2022 | 15:44 → 19:14 | 13:44 → 17:14 |

No busy minute (> 100 attacker SYNs) outside these sessions.

### Difference from the paper
The paper reports ~60 s of port-scan traffic (Table 8) because it tests at most
10,000 packets per attack. The full scan is ~5.5 hours over two sessions.

### Consequence for labeling
"First to last attacker packet" is not a valid window: it spans ~25 h including the
attacker's normal traffic. Sessions must be detected from busy minutes (see
`baseline_spec.md`, decision 9).

---

## 6. Open questions
- Confirm the gateway IP (`192.168.137.1`?).
- Which MAC is the brute-force attacker? Which is the port scanner?
- Is `dc:a6:32:dc:27:d5` the attacker Pi with normal casting traffic?
- Build a canonical MAC → device-name table (needs the CIC topology images and
  manufacturer prefixes).