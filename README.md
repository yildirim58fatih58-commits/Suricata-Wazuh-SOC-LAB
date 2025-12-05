# Suricata + Wazuh SOC Lab

Dieses Repository dokumentiert mein privates SOC-Homelab.

Ziel:
- Netzwerkangriffe und verdächtige Downloads mit Suricata erkennen
- Alerts über den Wazuh-Agent an einen Wazuh-Manager senden
- Events im Wazuh-Dashboard (Threat Hunting) auswerten

## Architektur

- Suricata/Kali-VM als IDS/IPS-Sensor (192.168.178.94)
- Wazuh Single-Node (Docker) als SIEM (192.168.178.100)
- Windows-Client als Angreifer/Opfer (SSH, PowerShell, Downloads)

## Use Cases

1. **SSH Brute Force**
   - Tool: Hydra
   - Ziel: SSH-Dienst mit schwachem Passwort
   - Detection: Suricata-Regel in `local.rules`, Wazuh-Alert „SSH Brute Force Attempt“

2. **Suspicious PowerShell Download**
   - Windows lädt per PowerShell eine Datei von der Kali-VM
   - Detection: Suricata-Regel, die auf die URL /payload.fatih reagiert
   - Sichtbar in Wazuh als „Suricata: Alert – Suspicious PowerShell Download“

3. **Malware/Trojan Test Download**
   - Download einer Fake-Malware-Datei `malware-test.bin`
   - Detection: Suricata-Regel „Malware/Trojan Test Download“

4. **ICMP Ping / Reconnaissance**
   - Mehrere Ping-Pakete zur Netz-Erkundung
   - Detection: Suricata-Regel „ICMP Ping Detected“

## Wazuh-Integration

- Wazuh-Agent auf Kali überwacht `/var/log/suricata/eve.json`
- Events werden an den Wazuh-Manager gesendet und im Dashboard angezeigt
- Threat Hunting Filterbeispiel:
  - `agent.name:"kali"`  
  - `agent.name:"kali" AND rule.groups:"suricata"`

Fehler und Troubleshooting (JSON-Decoder, Docker-Stack, ossec.conf) sind in der PDF  
`docs/SURICATA_WAZUH_SOC_LAB.pdf` dokumentiert.


Die wichtigsten Nachweise liegen im Ordner `screenshots/`, u. a.:

- `SSH Bruteforce Shot.png` – SSH-Bruteforce mit Suricata-Alert
- `Malware Powershell shot.png` / `PowerShell.png` – verdächtiger PowerShell-Download
- `Malware Shot.png` – Malware-Test-Download in Suricata
- `Wazuh Alert.png` – Wazuh Threat Hunting mit Suricata-Alerts
- `Regeln Shot.png` – Suricata `local.rules` mit eigenen Regeln
- `wazuh ossec conf.png` – Wazuh-Agent-Konfiguration für `eve.json`
