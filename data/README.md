# Data

Datasets are NOT stored in Git. This file explains how to rebuild `data/raw/` exactly.

## Sources
| Dataset | Page | Download link | Downloaded on |
|---|---|---|---|
| CICIoT2022 | https://www.unb.ca/cic/datasets/iotdataset-2022.html | http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2022/ | [date] |
| CICIoT2023 | https://www.unb.ca/cic/datasets/iotdataset-2023.html | http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/ | [date] |

Both links require a free CIC registration form.

## What I downloaded
- CICIoT2022: 1-Power.tar.gz, 2-Idle.tar.gz, 3-Interactions.tar.gz, Active/2021_11_02_Active.pcap, Readme.txt
- CICIoT2023: PCAP/Benign_Final, PCAP/DictionaryBruteForce, PCAP/Recon-PortScan, README files, Supplementary Materials/tools

## Layout
[paste the output of `tree data\raw`]

## Preparation steps
1. Extracted the 2022 archives in place with `tar -xzf <archive>`.
2. Flattened the nested `Supplementary Materials/tools/tools` folder (documentation only).

## Integrity
SHA-256 checksums of every file are in `data/checksums.sha256`.

## Citations
- Dadkhah et al., "Towards the development of a realistic multidimensional IoT profiling dataset", PST 2022.
- Neto et al., "CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT environment", Sensors 23(13), 5941, 2023.