# Baseline specification — IoT-PRIDS reimplementation

> DRAFT.

This file contains the design decisions needed to reimplement IoT-PRIDS
(Zohourian et al., *Computers & Security* 146, 2024, 104034) from the paper alone.
The authors' code is not public, so wherever the paper is vague or inconsistent,
the decision below is mine with justification.

Each item has three parts: **Paper says**, **I decided**, **Why**.

---

## 1. Fields in a representation

- **Paper says:** Fig. 3 (a UDP example) keeps eth.src, eth.dst, ip.dsfield, ip.flags,
  TTL (converted), scope (synthesized), source port, destination port and length (converted).
  Section 4.3 lists the headers removed. Fields for TCP packets are not listed.
- **I decided:** a representation contains
  1. eth.src (source MAC)
  2. eth.dst (destination MAC)
  3. ip.flags
  4. TTL bucket (see item 2)
  5. scope (see item 5)
  6. transport protocol (TCP or UDP)
  7. service port (see item 3)
  8. ephemeral-port bucket (see item 3)
  9. payload-length bucket (see item 4)
  10. TCP flags (TCP packets only; empty for UDP)
- **Why:** TCP flags are the most telling TCP header ,we can see scans and floods. The transport protocol is kept even though the paper drops it , otherwise , a UDP packet and a TCP packet on the same ports would get identical representations.

## 1b. DS field (dsfield / diff-ser-field)

- **Paper says:** Section 4.3.2 removes `diff-ser-field`, but Fig. 3 still shows `dsfield`
  in the final representation.
- **I decided:** remove it. Keeping it is tested later as an ablation.
- **Why:** the text describes the procedure explicitly, so it takes priority over the figure.
  The ablation turns the inconsistency into a small, reportable result.

## 2. TTL conversion

- **Paper says:** TTL is marked as "converted" in Fig. 3; the conversion is not described.
- **I decided:** snap TTL to its likely initial value: ≤ 32 → 32, ≤ 64 → 64,
  ≤ 128 → 128, otherwise 255.
- **Why:** the initial TTL is set by the operating system, so it is a stable fingerprint
  of the device. The exact value also depends on how many routers the packet crossed,
  which is noise for our purpose.

## 3. Service port vs. ephemeral port

- **Paper says:** after "identifying the service port", the ephemeral port is bucketed
  into ranges of 10,000: [0–10,000], [10,001–20,000], …, [60,001–65,535].
  How the service port is identified is not stated.
- **I decided:** the lower of the two ports is the service port and is kept exactly;
  the higher one is the ephemeral port and is replaced by its 10,000-wide bucket.
- **Why:** simple, deterministic, and correct for almost all client–server traffic,
  because services listen on low, well-known ports while clients pick high ephemeral ports.

## 4. Payload length

- **Paper says:** UDP and TCP payload lengths are mapped to the nearest higher power of 2.
- **I decided:** same as the paper. A payload length of 0 stays 0.
- **Why:** clearly specified; no decision needed beyond the zero case.

## 5. Scope (LAN / WAN)

- **Paper says:** a synthesized feature "scope" says whether communication is internal
  (local network) or external (internet). The rule is not given.
- **I decided:** LAN if the other endpoint's IP is private (RFC 1918: 10.0.0.0/8,
  172.16.0.0/12, 192.168.0.0/16), link-local (169.254.0.0/16) or multicast
  (224.0.0.0/4), or broadcast; otherwise WAN.
- **Why:** needs no knowledge of the lab's specific subnet, so it works unchanged on
  other networks.

## 6. Detection threshold

- **Paper says:** a packet is abnormal if its distance exceeds "a predefined threshold".
  The value is never stated.
- **I decided:** the threshold is a configurable parameter. It is tuned on held-out
  benign traffic only, e.g. the smallest threshold that keeps the false-positive rate
  at or below 1%. The weighted versions use exactly the same tuning rule.
- **Why:** IoT-PRIDS is anomaly-based and must not see attack labels during training.
  Tuning on attack data would make it secretly supervised, and the baseline vs. weighted
  comparison would not be fair.

## 7. Flow definition

- **Paper says:** flow-level detection takes the mode (majority vote) of the packet
  verdicts in each flow. What makes a flow is not defined.
- **I decided:** bidirectional 5-tuple (source IP, destination IP, source port,
  destination port, protocol) with a 120-second idle timeout.
- **Why:** matches CICFlowMeter, the CIC lab's own flow tool, so it is easy to defend.

## 8. Device attribution

- **Paper says:** profiles are per device (host-based). How a packet is assigned to
  a device is not stated.
- **I decided:** the profile key is the IoT device's MAC address. An outbound packet
  is checked against the source MAC's profile; an inbound packet against the destination
  MAC's profile. Packets involving no known device are skipped.
- **Why:** matches the paper's host-based framing, where each device judges its own traffic.

## 9. Labeling of attack traffic

- **Paper says:** all packets from attacker to victim are labeled as attack, with manual
  exceptions (e.g. the attacker Raspberry Pi's normal casting traffic to the Google Nest
  Mini on port 8009). Tests use at most 10,000 attack packets.
- **I decided:** to be decided after reading the CICIoT2023 documentation and topology,
  and inspecting the attack pcaps in Wireshark.
- **Why:** depends on the data; cannot be fixed from the paper alone.

---

## Open questions

- Which MAC addresses are IoT devices, attackers, and infrastructure (router, switch)?
- Does the 10,000-packet cap apply per pcap, per attack, or per victim?