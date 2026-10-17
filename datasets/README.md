# CICIDS2017 Dataset

## About

The **CICIDS2017** dataset (Canadian Institute for Cybersecurity Intrusion Detection
Systems 2017) is used as the primary evaluation dataset for SentinelMesh.

## Download Instructions

1. Visit the official dataset page:
   https://www.unb.ca/cic/datasets/ids-2017.html

2. Download the **raw PCAP files** (required for Sniffer Agent replay) and the
   **labeled CSV files** (required for precision/recall/F1 evaluation).

3. Place the PCAP files in this directory, preserving the original filenames.

## Required Subsets (Section 10.8)

For headline metrics, only the following subsets are used:

| Day       | File                                    | Labels Used                              |
|-----------|-----------------------------------------|------------------------------------------|
| Thursday  | Thursday-WorkingHours.pcap_ISCX.csv     | BENIGN, Web Attack – Sql Injection       |
| Friday    | Friday-WorkingHours-Morning.pcap_ISCX.csv + Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | BENIGN, PortScan |

All other attack classes (DoS, Bot, Brute Force, XSS, Infiltration, Heartbleed)
are **out of detection scope** — see Section 10.8 for rationale.

## SYN Flood Validation

SYN flood detection is validated separately using synthetic traffic generated
with `hping3 -S --flood` in the isolated lab network, not CICIDS2017.
