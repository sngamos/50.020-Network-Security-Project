# 50.020 Network Security Project

## Instructions for Project
Find cybersecurity research paper that discusses a “network” security solution using AI, implement, and demonstrate.

## Paper Selected
- [A comparative analysis of Network Intrusion Detection (NID) using ArtificialIntelligence techniques for increase network security](https://ijsra.net/sites/default/files/IJSRA-2024-2664.pdf)
    - offline pdf [here](IJSRA-2024-2664.pdf)


## Demonstration Diagram

```
┌─────────────────────────────────────────────────────────┐
│              Attack Traffic                       │
└────────────────────┬─────────────────────┘
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
┌─────────────────┐    ┌──────────────────┐
│  Traditional    │    │   ML-Based IDS   │
│  Signature IDS  │    │  (Your Model)    │
│  (Snort)        │    │  Random Forest   │
└────────┬────────┘    └────────┬─────────┘
         │                      │
         ▼                      ▼
┌─────────────────┐    ┌──────────────────┐
│  Detection Log  │    │  Detection Log   │
│  - Rules hit    │    │  - Predictions   │
│  - Alerts       │    │  - Confidence    │
└────────┬────────┘    └────────┬─────────┘
         │                      │
         └──────────┬───────────┘
                    ▼
         ┌──────────────────────┐
         │  Comparison Dashboard│
         │  - Detection rates   │
         │  - False positives   │
         │  - Response time     │
         └──────────────────────┘
```
