# 50.020 Network Security Project

## Instructions for Project
Find cybersecurity research paper that discusses a “network” security solution using AI, implement, and demonstrate.

## Paper Selected
- [A comparative analysis of Network Intrusion Detection (NID) using ArtificialIntelligence techniques for increase network security](https://ijsra.net/sites/default/files/IJSRA-2024-2664.pdf)
    - [Offline pdf paper here](docs/IJSRA-2024-2664.pdf)


## Demonstration Diagram

```
┌──────────────────────────────────────────┐
│              Attack Traffic              │
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

### Demonstration methodology
1. Rules to detect simple SQL injection attacks using Snort IDS.
2. Hopefully, snort IDS will be able to detect basic SQL injection attacks based on the rules defined since the signatures are well known and can be matched easily.
3. Then we run an obfuscated SQL injection attack that uses techniques such as encoding, comments, and whitespace variations to evade detection.
4. Snort IDS is expected to miss the obfuscated SQL injection attacks since the signatures are altered and do not match the predefined rules.
5. The ML-based IDS (Random Forest model) is expected to detect both basic and obfuscated SQL injection attacks since it learns patterns and behaviors associated with SQL injection attacks, rather than relying solely on predefined signatures.
6. Finally, we compare the detection rates and false positives between Snort IDS and the ML-based IDS to evaluate their effectiveness in detecting SQL injection attacks.
