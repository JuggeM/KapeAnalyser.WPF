# CSIRT KAPE Analyser

A Windows desktop application for triaging Windows collections: **DFIR ORC** collects, **KAPE** (EZ Tools modules) parses, and this tool turns the module CSVs into per-host findings and a case summary. It is the Windows counterpart to the CSIRT UAC Parser and uses the same layout and output style.

## What it does

1. **Finds hosts**: any folder under the case folder that holds EZ Tools CSVs, directly or in KAPE's category folders (`EventLogs`, `ProgramExecution`, `FileSystem`, `Registry`, …). Folders named after an ORC archive (`ORC_WorkStation_WS01_…`) or a KAPE timestamp folder work too.
2. **Analyses** each host's module output (below) and writes a QuickWins report plus CSVs for Timeline Explorer.
3. **Connects hosts**: lateral movement between case hosts, sources that logged on to several hosts, a case timeline, and a case IOC list searched in every CSV of every host.
4. **Reports**: a case report for stakeholders (below) and per-host QuickWins in the same layout as the CSIRT UAC Parser.

| Source | KAPE module output | What it detects |
|---|---|---|
| EVTX | `*_EvtxECmd_Output.csv` | Brute force (4625/4771/4776) and *succeeded* after failures, RDP logons (4624 type 10, 1149, 21/25), network logons from external IPs, type 9 logons, accounts created and added to privileged groups, services (7045/4697), scheduled tasks (4698), process command lines (4688, Sysmon 1), PowerShell (4104, 400/600/800), Defender detections, exclusions and tampering, log clearing (1102/104), Kerberoasting (RC4 4769), admin shares (5140/5145), LSASS access (Sysmon 10), autorun registry writes (Sysmon 13), WMI subscriptions, BITS jobs |
| PREFETCH | `*_PECmd_Output.csv` | Known attacker and dual-use tools, executables run from staging folders |
| AMCACHE | `*_Amcache_*FileEntries.csv` | Same, with SHA1 |
| SHIMCACHE | `*AppCompatCache*.csv` | Same (times are file modification times) |
| REGISTRY | `*_RECmd_Batch_*_Output.csv` | Every value checked for tools, staging paths and attack command lines (UserAssist, BAM, RunMRU, services, …); autoruns; Defender exclusions; host name and IPs |
| LNK / JUMPLIST | `*_LECmd_Output.csv`, `*_AutomaticDestinations.csv` | Opened tools, malicious shortcut arguments, admin shares, removable media |
| MFT | `*_MFTECmd_$MFT_Output.csv` | Tools on disk, executables in staging folders, internet downloads (Zone.Identifier), timestomping (SI < FN), large archives, mass ransom notes |
| USNJRNL | `*_MFTECmd_$J_Output.csv` | Tools created, renamed or deleted; prefetch files created for tools; mass ransom notes |
| RECYCLEBIN | `*_RBCmd_Output.csv` | Deleted tools and large archives |
| SHELLBAGS | SBECmd output | Tool and loot folder names, admin shares |

Run KAPE with the `!EZParser` compound module (or the individual modules) against the ORC collection.

## Case folder

```
CaseFolder\
├── Kape\
│   ├── WS01\EventLogs\…, ProgramExecution\…, FileSystem\…, Registry\…
│   └── ORC_Server_FS01_20261101_120000\…
├── iocs.txt                ← case IOC list (IOCs panel)
└── Processed\
    ├── CaseSummary.txt     ← hosts ranked, lateral movement, case timeline, IOCs across hosts, top findings per host
    ├── CaseReport.html     ← case report (Case report panel → Open in browser)
    ├── CaseReport.json     ← your edits to the case report
    ├── CaseFindings.csv    ← all hosts' findings (Timeline Explorer)
    └── WS01\
        ├── QuickWins.txt / .rtf  ← host, key findings, IOCs seen in findings, coverage, logons, one table per source
        ├── Findings.csv    ← one row per finding, with detail and artifact
        ├── Logons.csv      ← inbound network/RDP/admin-share logons by source
        └── IocHits.csv
```

A host is processed once. To process it again, delete its folder in `Processed\`.

## Case report

The **Case report** panel turns every host's `Findings.csv` into a readable English summary, like the CSIRT UAC Parser's. Each key finding gets a likelihood from the PHIA yardstick (almost certain, highly likely, likely…), based on its severity, whether another KAPE module on the same host saw the same indicator or tool (for example mimikatz in Prefetch, the USN journal and a 4688 event), and matches against the case IOC list. Every CRITICAL finding, the strongest 4 HIGH findings per host and anything linking case hosts are ticked by default. Change the selection with **Select all ≥ HIGH**, **Select all** and **Reset to default**. Edit the title, bottom line, gaps and next steps, then use **Open in browser** or **Export ▾** (HTML, Word .docx or RTF). Edits are saved to `Processed\CaseReport.json` and kept when you run the analysis again.

## Running

- UI: build and start `KapeAnalyser.WPF.exe`, choose the case folder, **Run analysis**.
- Headless: `KapeAnalyser.WPF.exe --case C:\Cases\X [--out <folder>] [--name <case>] [--analyst <name>]`

Test case: `tools\New-TestCase.ps1 -CaseFolder C:\Cases\KapeTest` writes synthetic module output for three hosts (documentation-range IPs, fictional names).

## Antivirus

The detection rules contain attacker strings (tool names, mimikatz command syntax, AMSI-bypass markers), so Windows Defender may flag the built `KapeAnalyser.WPF.dll` as malicious and refuse to load it. As with other DFIR tools (KAPE and EZ Tools are often flagged too), add an antivirus exclusion for the folder you build or run it from, following your organisation's policy.

## Requirements

Windows 10/11, .NET 8 SDK to build.
