# 🛡️ Wdrożenie Środowiska Wazuh SIEM & EDR: Detection Engineering & SOAR Home Lab

## 📋 Streszczenie Managerskie (Executive Summary)
Projekt prezentuje kompleksowe zaprojektowanie, wdrożenie oraz utrzymanie centralnego środowiska monitorowania bezpieczeństwa (**SIEM/EDR**) w architekturze *On-Premise*. Głównym celem laboratorium jest praktyczna demonstracja umiejętności z zakresu:
* **Inżynierii Detekcji (Detection Engineering):** Tworzenie autorskich reguł korelacyjnych w oparciu o logi systemowe (`journald`) oraz zaawansowaną telemetrię endpointową (`Sysmon`), z pełnym mapowaniem do matrycy **MITRE ATT&CK** (`T1110`, `T1003`).
* **Automatyzacji Reakcji na Incydenty (SOAR / Active Response):** Konfiguracja mechanizmów aktywnej obrony, które w czasie rzeczywistym mitygują zagrożenia (automatyczna blokada agresora w `iptables` na systemie Linux oraz autonomiczna neutralizacja procesu i plików narzędzia Mimikatz na stacji Windows) bez udziału analityka.
* **Administracji i Troubleshootingu Infrastruktury SIEM:** Rozwiązywanie rzeczywistych problemów produkcyjnych obejmujących zarządzanie wolumenami logicznymi (LVM), uwierzytelnianie usług (Filebeat Keystore, OpenSearch Security, RBAC API), analizę dzienników `systemd` oraz dopasowywanie logiki skryptów wykonawczych do formatu danych przekazywanych przez agenta.

---

## 🏗️ Architektura Środowiska (Lab Topology)

Środowisko zostało zbudowane w oparciu o wirtualizację w sieci mostkowanej (*Bridged Network*), co pozwala na symulację rzeczywistego ruchu sieciowego w segmencie LAN (`192.168.0.0/24`).

```mermaid
graph TD
    subgraph "Strefa Ataku (Red Team)"
        Attacker["💻 Maszyna Atakująca<br/>IP: 192.168.0.52<br/>Narzędzia: Hydra, Mimikatz"]
    end

    subgraph "Monitorowane Endpointy (Blue Team Targets)"
        LinuxTarget["🐧 Endpoint 1: Linux Target<br/>Ubuntu/Debian (IP: 192.168.0.17)<br/>Wazuh Agent + journald + iptables"]
        WinTarget["🪟 Endpoint 2: Windows Target<br/>Windows 10 (IP: 192.168.0.224)<br/>Wazuh Agent + Sysmon (SwiftOnSecurity)"]
    end

    subgraph "Centralny SIEM / SOAR"
        WazuhSIEM["🛡️ Wazuh Server All-in-One<br/>Ubuntu Server 24.04 LTS (IP: 192.168.0.136)<br/>Manager + Indexer + Dashboard + Filebeat"]
    end

    Attacker -->|"1. SSH Brute-Force (Port 22)"| LinuxTarget
    Attacker -->|"2. Credential Dumping (Mimikatz)"| WinTarget
    LinuxTarget -->|"Telemetria (Port 1514/1515)"| WazuhSIEM
    WinTarget -->|"Telemetria Sysmon (Port 1514/1515)"| WazuhSIEM
    WazuhSIEM -.->|"Active Response: firewall-drop (iptables)"| LinuxTarget
    WazuhSIEM -.->|"Active Response: quarantine-mimi.cmd (Taskkill + Quarantine)"| WinTarget
```

### Specyfikacja komponentów:
| Rola w architekturze | System operacyjny | Adres IP | Kluczowe moduły i konfiguracja |
|---|---|---|---|
| **Wazuh Server (SIEM)** | Ubuntu Server 24.04 LTS | `192.168.0.136` | Wazuh Manager, Wazuh Indexer, Wazuh Dashboard, Filebeat (`4.14.9`) |
| **Endpoint 1 (Linux Target)** | Ubuntu / Debian | `192.168.0.17` | Wazuh Agent, kolektywizacja logów z `systemd-journald`, zapora `iptables` |
| **Endpoint 2 (Windows Target)** | Windows 10 Pro | `192.168.0.224` | Wazuh Agent, **Sysmon** (konfiguracja *SwiftOnSecurity*), kanał `Operational` |
| **Attacker Host (Red Team)** | Linux Host | `192.168.0.52` | THC-Hydra (Brute-Force SSH), narzędzia testowe (ICMP/ping) |

---

## 📁 Struktura Repozytorium (Artefakty Konfiguracyjne)

W repozytorium znajdują się kluczowe pliki konfiguracyjne oraz skrypty wykorzystane podczas wdrożenia:
```text
├── README.md                                  # Dokumentacja techniczna i raport z wdrożenia
├── local_rules.xml                            # Autorskie reguły detekcyjne (ID 100002, ID 100005)
├── manager-active-response.conf               # Konfiguracja bloków <command> i <active-response> Managera
├── windows_agent_sysmon.conf                  # Konfiguracja integracji z kanałem Sysmon Operational
├── quarantine-mimi.py                         # Skrypt kwarantanny artefaktów Mimikatz
└── quarantine-mimi.cmd                        # Launcher Active Response dla Windows
```

---

## 🚀 Faza 1: Wdrożenie i Ingestia Logów (Log Ingestion)

### 1. Centralny Serwer Wazuh (`192.168.0.136`)
Wdrożono architekturę *All-in-One* obejmującą silnik analityczny (Manager), bazę opartą na OpenSearch (Indexer) oraz interfejs wizualizacyjny (Dashboard). Przeprowadzono twardą konfigurację uprawnień RBAC oraz synchronizację certyfikatów i magazynów kluczy (szczegóły w sekcji *Troubleshooting*).

<img width="1854" height="964" alt="Widok główny Wazuh Dashboard z aktywnymi agentami" src="https://github.com/user-attachments/assets/52e2d62a-d094-4cbc-80d5-6dd9b6d95503" />

### 2. Konfiguracja Agenta Linux (`192.168.0.17`)
* Zainstalowano i zarejestrowano Agenta Wazuh (`v4.14.9`) z wymuszeniem komunikacji po protokole IPv4.
* Skonfigurowano zbieranie zdarzeń uwierzytelniania bezpośrednio z podsystemu `journald`, nadając procesowi agenta odpowiednie uprawnienia grupowe (`systemd-journal`).

### 3. Konfiguracja Agenta Windows i Integracja z Sysmon (`192.168.0.224`)
Standardowe logi systemu Windows (Security Event Log) często nie zapewniają wystarczającej widoczności na poziomie tworzenia procesów czy modyfikacji plików. Aby podnieść możliwości detekcyjne do standardu **EDR**:
* Wdrożono usługę **Sysmon (System Monitor)** z wykorzystaniem ustandaryzowanego profilu konfiguracyjnego *SwiftOnSecurity*.
* Skonfigurowano plik `ossec.conf` na stacji Windows w celu nasłuchiwania na dedykowanym kanale zdarzeń `Microsoft-Windows-Sysmon/Operational`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
Dzięki temu SIEM w czasie rzeczywistym przetwarza m.in. zdarzenia **Event ID 1** (Process Creation), **Event ID 3** (Network Connection) oraz **Event ID 11** (FileCreate).

---

## ⚔️ Scenariusz 1: Atak SSH Brute-Force i Automatyczna Blokada (Linux SOAR)

### 1. Symulacja Ataku (Red Teaming — MITRE ATT&CK: `T1110`)
Z maszyny atakującej (`192.168.0.52`) przeprowadzono słownikowy atak siłowy (*Brute-Force*) na usługę SSH serwera docelowego (`192.168.0.17`) przy użyciu narzędzia **Hydra**:
* **Cel:** `ssh://192.168.0.17:22`
* **Atakowane konto:** `polafasola2`
* **Artefakty w logach:** Zmasowane generowanie wpisów o nieudanym uwierzytelnianiu w dzienniku `journald` dla demona `sshd`.

### 2. Inżynieria Detekcji (Custom Rule `100002`)
W pliku `/var/ossec/etc/rules/local_rules.xml` na serwerze Managera zaprojektowano regułę korelacyjną agregującą pojedyncze nieudane logowania (wbudowana reguła `5760` – *sshd: authentication failed*).

<img width="1858" height="352" alt="Konfiguracja reguły 100002 w local_rules.xml" src="https://github.com/user-attachments/assets/96efd797-b73b-4746-be3b-0ac04a982b67" />

```xml
<group name="local,syslog,sshd,">
  <rule id="100002" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>SSH Brute Force wykryty: 5 nieudanych logowan w ciagu minuty z IP $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```
* **Logika detekcji:** Jeżeli z tego samego adresu źródłowego (`<same_source_ip />`) wystąpi 5 zdarzeń o ID `5760` w oknie czasowym 60 sekund, SIEM eskaluje wagę zdarzenia z poziomu `5` na poziom `10` (reguła `100002`) i przypisuje technikę **MITRE T1110 (Brute Force)**.

### 3. Konfiguracja Active Response (SOAR)
W celu automatycznej mitygacji ataku powiązano regułę `100002` ze skryptem wykonawczym `firewall-drop` w głównym pliku konfiguracyjnym Managera (`/var/ossec/etc/ossec.conf`):

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>600</timeout>
</active-response>
```
W momencie wyzwolenia reguły `100002` Manager wysyła rozkaz bezpośrednio do agenta, na którym wykryto atak (`<location>local</location>`), dodając adres IP agresora do łańcucha blokującego w lokalnym firewallu na czas 600 sekund.

### 4. Weryfikacja i Dowody Działania (PoC)

**Krok A: Wykrycie ataku i korelacja zdarzeń w Wazuh Dashboard**  
System poprawnie zarejestrował pojedyncze próby logowania (reguła `5760`, poziom 5) oraz wygenerował skorelowany alert wysokiego ryzyka (reguła `100002`, poziom 10, zastępująca standardową regułę `5763`) wskazujący na atak Brute-Force na konto `polafasola2`.

<img width="1854" height="962" alt="Wykrycie ataku Brute Force w Wazuh Dashboard - widok ogólny" src="https://github.com/user-attachments/assets/4536d79e-aa86-4f7f-8a6d-45883c69c8fd" />
<img width="1858" height="965" alt="Szczegóły alertu 100002 i zdarzeń 5760 w Wazuh Dashboard" src="https://github.com/user-attachments/assets/408753ce-c30e-4511-9843-df40058fc303" />

**Krok B: Automatyczna modyfikacja tablicy filtracji (`iptables`) na hoście ofiary**  
Weryfikacja reguł zapory sieciowej na maszynie `192.168.0.17` potwierdziła automatyczne utworzenie wpisu `DROP` dla adresu IP atakującego (`192.168.0.52`) w łańcuchu `INPUT` oraz `FORWARD`.

<img width="529" height="97" alt="Zrzut z iptables potwierdzający zablokowanie IP 192.168.0.52" src="https://github.com/user-attachments/assets/a3f60aa2-9224-4e59-a699-6b938f717410" />

**Krok C: Potwierdzenie izolacji atakującego (Test łączności)**  
Z perspektywy maszyny atakującej (`192.168.0.52`) odnotowano **100% utratę pakietów (`100% packet loss`)** w komunikacji z celem, podczas gdy maszyna chroniona (`192.168.0.17`) zachowała pełną łączność z serwerem zarządzającym SIEM (`192.168.0.136`).

<img width="536" height="245" alt="Test ping potwierdzający 100% utratę pakietów dla atakującego" src="https://github.com/user-attachments/assets/5d420193-b102-4327-ae3b-5c22c6e6cdea" />

---

## 🪟 Scenariusz 2: Detekcja i Neutralizacja Narzędzia Mimikatz na Stacji Windows (EDR & Sysmon)

### 1. Symulacja Ataku (MITRE ATT&CK: `T1003` — OS Credential Dumping)
Na maszynie Windows 10 (`192.168.0.224`), po celowym wyłączeniu ochrony antywirusowej Windows Defender (symulacja przełamania pierwszej linii obrony / *Defense Evasion*), przeprowadzono próbę dostarczenia i uruchomienia narzędzia **Mimikatz**, służącego do ekstrakcji poświadczeń z pamięci procesu LSASS.

### 2. Przechwycenie Telemetrii przez Sysmon
Dzięki integracji z kanałem `Microsoft-Windows-Sysmon/Operational`, aktywność została natychmiast wyłapana już na etapie dostarczenia archiwum/pliku wykonywalnego (*Delivery* — **Sysmon Event ID 11: FileCreate**) oraz inicjalizacji procesu (**Sysmon Event ID 1: Process Creation**), zanim atakujący zdołał przeprowadzić pełny zrzut pamięci.

<img width="1854" height="964" alt="Wykrycie artefaktów Mimikatz przez Sysmon w Wazuh Dashboard" src="https://github.com/user-attachments/assets/e8127bc6-eb61-48fb-b65b-8b8628ae3ebc" />

### 3. Inżynieria Detekcji (Custom Rule `100005`)
W celu precyzyjnego wyodrębnienia incydentu z ogólnego strumienia zdarzeń Sysmon opracowano autorską regułę detekcyjną o **ID 100005** (poziom ważności `12` — *High/Critical*), nasłuchującą na zdarzenia z grupy `sysmon` wskazujące na obecność lub uruchomienie narzędzia `mimikatz`:

```xml
<group name="windows,sysmon,mimikatz_detection,">
  <rule id="100005" level="12">
    <if_group>sysmon</if_group>
    <match type="pcre2">(?i)mimikatz</match>
    <description>CRITICAL EDR ALERT: Wykryto aktywnosc narzedzia Mimikatz na stacji Windows (Host: $(win.system.computer))</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</group>
```

### 4. Automatyczna Mitygacja na Stacji Roboczej (Windows Active Response)
Ponieważ zdarzenia Sysmon (Event ID 1 / Event ID 11) mają charakter lokalny (host-based) i nie zawierają w strukturze JSON pola `srcip`, standardowe skrypty sieciowe (np. `netsh` blokujący IP agresora) nie mogą zostać zastosowane (szczegóły w sekcji *Troubleshooting – Problem 5*). 

Zamiast blokady sieciowej zaprojektowano mechanizm bezpośredniej neutralizacji zagrożenia na poziomie systemu operacyjnego (EDR Remediation):

**A. Skrypt wykonawczy na stacji Windows (`C:\Program Files (x86)\ossec-agent\active-response\bin\quarantine-mimi.py`):**
Skrypt czyta alert Active Response ze standardowego wejścia, wymusza zakończenie procesu Mimikatz za pomocą `taskkill`, przenosi wskazany plik do `C:\Quarantine` zamiast go usuwać, nadaje mu rozszerzenie `.locked`, oblicza SHA-256 i zapisuje ślad audytowy w `active-responses.log`. Plik `quarantine-mimi.cmd` uruchamia skrypt Python, ponieważ agent Windows wykonuje skrypty Active Response przez pliki wykonywalne lub launchery batch:

```cmd
@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
if defined WAZUH_PYTHON set "PYTHON=%WAZUH_PYTHON%"
if not defined PYTHON set "PYTHON=py.exe"
"%PYTHON%" "%SCRIPT_DIR%quarantine-mimi.py"
exit /b %ERRORLEVEL%
```

**B. Konfiguracja wyzwalacza na serwerze Wazuh Manager (`/var/ossec/etc/ossec.conf`):**
```xml
<command>
  <name>quarantine_mimi</name>
  <executable>quarantine-mimi.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>quarantine_mimi</command>
  <location>local</location>
  <rules_id>100005</rules_id>
</active-response>
```
Po wykryciu reguły `100005` Wazuh Manager natychmiast wysyła komendę `quarantine_mimi` do agenta Windows (`<location>local</location>`), który zatrzymuje proces i zabezpiecza plik w kwarantannie bez usuwania dowodu.

---

## 🔧 Wyzwania Inżynierskie i Rozwiązywanie Problemów (Troubleshooting Log)

Podczas budowy infrastruktury od zera rozwiązano szereg problemów administracyjnych i architektonicznych, typowych dla produkcyjnych wdrożeń systemów klasy SIEM/EDR:

### 1. Błąd alokacji przestrzeni dyskowej LVM podczas instalacji (`disk full error`)
* **Diagnoza:** Instalacja pakietu `wazuh-dashboard` (ponad 1 GB po rozpakowaniu bibliotek Node.js) kończyła się błędem potoku `dpkg-deb`. Analiza pliku `/var/log/wazuh-install.log` wykazała brak miejsca na partycji głównej `/`. Instalator Ubuntu Server 24.04 domyślnie przydzielił dla wolumenu logicznego `ubuntu-lv` jedynie 50% dostępnej przestrzeni dyskowej (24 GB z 50 GB).
* **Rozwiązanie:** Rozszerzono wolumen logiczny LVM w locie (bez utraty danych i bez restartu maszyny) na całą dostępną przestrzeń grupy wolumenów:
  ```bash
  sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
  sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
  ```

### 2. Błąd `Error 900` w Wazuh API oraz niedostępność Dashboardu (`BrokenProcessPool`)
* **Diagnoza:** Interfejs Wazuh Dashboard zgłaszał brak łączności z API Managera na porcie `55000`, a bezpośrednie zapytania `curl` zwracały `Unauthorized` lub błąd wewnętrzny `Error 900 (One of the API child processes terminated abruptly)`. W logach `/var/ossec/logs/api.log` zidentyfikowano wyjątek `BrokenProcessPool` wynikający z osieroconych procesów potomnych (`wazuh_apid.py`, `wazuh-db`) oraz desynchronizacji bazy RBAC po wcześniejszych awariach pamięci.
* **Rozwiązanie:** Przeprowadzono twarde zatrzymanie osieroconych demonów, wykonano reset bazy kontroli dostępu (`rbac.db`), a następnie za pomocą tokenów JWT i zapytań `PUT /security/users/{id}` nadano nowe poświadczenia dla kont `wazuh` oraz `wazuh-wui`, synchronizując je z plikiem `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`.

### 3. Brak przesyłania alertów do Dashboardu (`Filebeat Error 401 Unauthorized`)
* **Diagnoza:** Mimo że Wazuh Manager poprawnie rejestrował atak SSH w lokalnym pliku `/var/ossec/logs/alerts/alerts.log`, zdarzenia nie pojawiały się w interfejsie graficznym. Diagnostyka usługi `filebeat` ujawniła błąd `401 Unauthorized` podczas próby zapisu indeksów do bazy Wazuh Indexer (po ręcznej zmianie hasła konta `admin` w module OpenSearch Security).
* **Rozwiązanie:** Zaktualizowano zaszyfrowany magazyn kluczy usługi Filebeat (Keystore), wprowadzając zaktualizowane hasło dostępowe do Indexera:
  ```bash
  sudo filebeat keystore add password
  sudo systemctl restart filebeat
  ```

### 4. Błąd startu usługi Wazuh Indexer (`java.nio.file.AccessDeniedException`) oraz uprawnienia `journald`
* **Diagnoza:** Po rekonfiguracji klaster Indexera odmawiał startu (`status=1/FAILURE`), rzucając wyjątek braku dostępu do plików konfiguracyjnych i kopii zapasowych. Równolegle na agencie Linux stwierdzono brak uprawnień użytkownika `wazuh` do odczytu systemowego dziennika zdarzeń.
* **Rozwiązanie:** 
  * Na serwerze SIEM przywrócono rekurencyjnie właściciela oraz uprawnienia `750` dla katalogów `/etc/wazuh-indexer`, `/var/lib/wazuh-indexer` i `/var/log/wazuh-indexer`, a następnie ponownie zainicjowano indeks bezpieczeństwa skryptem `indexer-security-init.sh`.
  * Na agencie Linux dodano konto serwisowe do odpowiedniej grupy systemowej (`usermod -aG systemd-journal wazuh`), co odblokowało pełną widoczność zdarzeń SSH.

### 5. Brak działania wbudowanych skryptów sieciowych Active Response na Windowsie (`Cannot read 'srcip' from data`)
* **Diagnoza:** Pierwsza iteracja Active Response dla stacji Windows zakładała użycie domyślnego skryptu `netsh.exe` w celu odcięcia ruchu sieciowego po wykryciu Mimikatza. Analiza pliku `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` ujawniła błąd: `Cannot read 'srcip' from data`.
* **Przyczyna:** Alerty pochodzące z Sysmona (Event ID 1 / Event ID 11) reprezentują lokalne operacje na procesach i plikach, przez co w wygenerowanym obiekcie JSON nie posiadają pola `data.srcip`. Wbudowane binaria firewalli wymagają tego parametru do nałożenia reguły blokującej.
* **Rozwiązanie:** Zmieniono wektor mitygacji z sieciowego na procesowo-plikowy (EDR). Opracowano skrypt `quarantine-mimi.py` niewymagający parametru `srcip`, który zatrzymuje złośliwy proces (`taskkill`) i przenosi plik do kwarantanny, zachowując dowód do dalszej analizy.

### 6. Błąd walidacji konfiguracji `ossec.conf` i awaria startu `wazuh-manager.service`
* **Diagnoza:** Po dodaniu definicji Active Response dla systemu Windows próba restartu Managera zakończyła się błędem `Job for wazuh-manager.service failed because the control process exited with error code`.
* **Przyczyna:** Inspekcja dziennika systemowego (`sudo journalctl -xeu wazuh-manager.service`) wykazała dwa błędy konfiguracyjne w pliku `/var/ossec/etc/ossec.conf`: użycie dyrektywy `<location>defined-agent</location>` bez wymaganego tagu `<agent_id>` oraz zduplikowanie bloku `<active-response>` dla reguły `100005` (pozostałość po wcześniejszym wywołaniu `netsh`).
* **Rozwiązanie:** Usunięto zduplikowany blok XML, ujednolicono wywołanie do komendy `quarantine_mimi` oraz zmieniono lokalizację wykonania na `<location>local</location>` (co instruuje SIEM, aby wykonał skrypt na tym agencie, który wygenerował alert).
