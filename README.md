# SOC Home Lab: Wazuh SIEM Detection and Incident Reporting

A hands-on Security Operations Center (SOC) lab built with VirtualBox. I simulated three real attack techniques against a Linux host, detected them with the Wazuh SIEM, wrote a custom detection rule for a gap in the default ruleset, mapped each detection to MITRE ATT&CK, and documented every incident in a professional report.

**Author:** Mansoob Iqbal
**LinkedIn:** https://www.linkedin.com/in/mansoob-iqbal-509490344

---

## What This Project Demonstrates

- Building and troubleshooting a working SIEM from scratch (Wazuh manager, indexer, dashboard, agent)
- Simulating attacks and validating whether detections actually fire
- Finding a detection gap and closing it with a **custom Wazuh rule**
- Mapping detections to **MITRE ATT&CK** techniques
- Writing structured incident reports with evidence, analysis and recommendations

## Lab Architecture

| Machine | Role | IP |
|---|---|---|
| Wazuh-Manager | Wazuh 4.9.2 (manager, indexer, dashboard) on Ubuntu 22.04 | 192.168.50.10 |
| Victim-Linux | Monitored host with Wazuh agent, Ubuntu 22.04 | 192.168.50.20 |
| Kali Linux | Attacker | 192.168.50.30 |

All machines share an isolated VirtualBox Internal Network (`labnet`), so no attack traffic leaves the lab. A second NAT adapter is used only for package downloads.

## Attacks and Detections

| # | Attack | Tool | Detection | MITRE ATT&CK | Report |
|---|---|---|---|---|---|
| 1 | SSH brute force | Hydra | Built-in rules 5760 and 5763 (level 10) | T1110 Brute Force (Credential Access) | [IR-2026-001](reports/IR-2026-001-ssh-brute-force.md) |
| 2 | Network port scan | Nmap | **Custom rule 100100** (level 7) | T1046 Network Service Discovery (Discovery) | [IR-2026-002](reports/IR-2026-002-nmap-port-scan.md) |
| 3 | File tampering | Local shell commands | Built-in syscheck rules 554, 550, 553 | T1565.001 Stored Data Manipulation (Impact) | [IR-2026-003](reports/IR-2026-003-file-integrity-monitoring.md) |

## Highlight: Custom Detection Rule

Wazuh did not alert on the Nmap scan by default. After enabling firewall (UFW) logging on the victim and forwarding `/var/log/ufw.log` to the manager, the blocked scan packets only matched a generic level 0 rule that produces no alert. I wrote a custom rule to turn them into real alerts:

```xml
<group name="firewall,ufw,">

  <rule id="100100" level="7">
    <if_sid>4100</if_sid>
    <action>UFW BLOCK</action>
    <description>UFW: Blocked connection attempt detected (possible port scan).</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>firewall_blocked,pci_dss_10.6.1,gdpr_IV_35.7.d,</group>
  </rule>

</group>
```

The rule was validated with `wazuh-logtest` and then confirmed in the dashboard with a live scan.

![Port scan alert with MITRE mapping](screenshots/02-nmap-scan/04-alert-with-mitre-T1046.png)

## More Evidence

![SSH brute force dashboard summary](screenshots/01-brute-force-ssh/01-dashboard-summary.png)

![File integrity monitoring alerts](screenshots/03-file-integrity-monitoring/01-dashboard-syscheck-alerts.png)

## Troubleshooting Highlights

Real problems I solved while building the lab, which are documented because fixing them was a big part of the learning:

- **Wazuh indexer timing out on an 8 GB host:** extended the systemd start timeout and gave the service time to start.
- **Dashboard showing no data even though the manager had alerts:** the Wazuh Filebeat module and index template had not been installed during setup. Installing the module and running the index setup fixed it.
- **Agent registration failing:** the agent version must match the manager version exactly. Installing the matching version from the Wazuh apt repository fixed it.
- **Custom rule not matching:** the `decoded_as` approach failed because the built-in `kernel` decoder already handled the log, and `<field name="action">` failed because `action` is a reserved field. The working approach used the dedicated `<action>` tag with `<if_sid>`.
- **Dashboard unreachable from Windows:** a VirtualBox port forwarding rule with a fixed guest IP caused connection resets. Removing the guest IP fixed it.

## Known Limitations and Next Steps

- Rule 100100 fires on every blocked packet, so it can also trigger on normal internet noise. The next improvement is to tune it with `frequency` and `timeframe` so one scan produces one alert.
- Detection is per host. Network-level detection (for example an IDS such as Suricata) would add coverage across the whole subnet.
- Add correlation between a brute force alert and a later successful SSH login from the same source.

## Repository Structure

```
.
├── README.md
├── reports/
│   ├── IR-2026-001-ssh-brute-force.md
│   ├── IR-2026-002-nmap-port-scan.md
│   └── IR-2026-003-file-integrity-monitoring.md
└── screenshots/
    ├── 01-brute-force-ssh/
    ├── 02-nmap-scan/
    └── 03-file-integrity-monitoring/
```

## Tools Used

Wazuh, VirtualBox, Ubuntu, Kali Linux, Hydra, Nmap, UFW, MITRE ATT&CK
