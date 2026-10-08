# IoT-PRIDS Research — Weighted Distances for Lightweight IoT Intrusion Detection

> **Status: work in progress** (Master's research, started October 2026).
> This README describes the goal and plan. Results will be added as experiments are completed.

## In one sentence

I am reimplementing **IoT-PRIDS**, a lightweight, non-machine-learning intrusion detection system for IoT networks, and researching whether **weighted distance metrics** can make it detect more attacks with fewer false alarms.

## The problem

IoT devices (cameras, smart speakers, sensors) are often the weakest link in a network: limited resources, little built-in security, and easy to exploit as entry points for scans, brute-force attacks and DDoS botnets.

Most intrusion detection systems rely on machine learning trained on **labelled attack data**, and are often too heavy to run near the devices themselves. IoT-PRIDS takes a different route: it learns only from **normal traffic**, needs no ML training, and is light enough to run on gateways or the devices themselves.

## How IoT-PRIDS works

1. **Profiling:** every benign packet from a device is reduced to a short *packet representation* — a handful of behavioural header values (who it talks to, which service, TTL, flags, size bucket). Millions of packets collapse into a few thousand representations per network: the device's normal profile.
2. **Monitoring:** each new packet is mapped the same way and compared with its device's profile. If it is too far from every normal representation, it is flagged as anomalous. Flows are then judged by majority vote of their packets.

Because it only learns what "normal" looks like, it can flag attacks it has never seen before.

## My research question

The original method measures "too far" with the **Hamming distance**: every differing field counts as 1. A packet sent to a never-seen device counts the same as a packet that is slightly longer than usual.

**Does weighting the representation fields by importance improve detection (recall, precision, F1, false-positive rate) while keeping the method lightweight?**

Planned directions:

- hand-set weights reflecting security intuition (e.g. new endpoint or new service > new length bucket);
- data-driven weights learned from benign traffic only, keeping the method anomaly-based;
- per-device weights;
- a fair comparison against the baseline with the same data, splits and threshold-tuning rule.

## Approach

| Phase | What | Status |
|---|---|---|
| 0–1 | Environment, design specification, dataset documentation | In progress |
| 2 | Exploratory analysis of the raw packet captures | Planned |
| 3–4 | pcap parsing and packet-representation mapping, with unit tests | Planned |
| 5–7 | Profiles, distance and detection; reproduction of the paper's results | Planned |
| 8 | Config-driven experiment harness (one command per experiment) | Planned |
| 9 | Weighted-distance variants and ablations | Planned |
| 10 | Final results, plots and write-up | Planned |

The baseline is reimplemented from scratch from the paper; ambiguities in the paper are resolved and justified in [`docs/baseline_spec.md`](docs/baseline_spec.md).

## Data

- **CICIoT2022** (Canadian Institute for Cybersecurity) — benign traffic from real IoT devices, used for profiling.
- **CICIoT2023** — benign and attack traffic (reconnaissance, brute force, web attacks, DoS, DDoS) from a 105-device IoT lab, used for evaluation.

Datasets are not stored in this repository. See [`data/README.md`](data/README.md) for sources, exact files and checksums.

## Tech stack

Python · dpkt (packet parsing) · pandas / PyArrow (Parquet) · NumPy · PyYAML (experiment configs) · Matplotlib · pytest · Wireshark

## Skills this project demonstrates

- Network traffic analysis at the packet-header level (Ethernet, IP, TCP/UDP)
- Anomaly-based threat detection and IoT security
- Reproducing published research and documenting design decisions
- Rigorous evaluation: precision, recall, F1, false-positive rate, ablations, fair baselines
- Reproducible engineering: tests, configs, versioned results

## Reference

This is an independent reimplementation and extension of:

A. Zohourian, S. Dadkhah, H. Molyneaux, E. C. P. Neto, A. A. Ghorbani,
"IoT-PRIDS: Leveraging packet representations for intrusion detection in IoT networks,"
*Computers & Security*, vol. 146, 104034, 2024. https://doi.org/10.1016/j.cose.2024.104034

It is not affiliated with the original authors.

## Author

Yasmine Boudour - Master's student, University of Lille
