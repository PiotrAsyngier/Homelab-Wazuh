# 🛡️ Raport z wdrożenia środowiska Wazuh SIEM & EDR

## 🎯 Wstęp i Architektura
Projekt obejmuje zaprojektowanie, wdrożenie i utrzymanie centralnego środowiska monitorowania bezpieczeństwa w architekturze On-Premise. Głównym celem jest zademonstrowanie praktycznych umiejętności z zakresu **Detection Engineering** oraz **Incident Response (SOAR)**.

### Architektura (stan na pierwszą fazę)
* **Wazuh Manager (SIEM):** Maszyna Ubuntu Server 24.04 LTS (All-in-One: Manager + Indexer + Dashboard) w sieci mostkowanej (IP: `192.168.0.136`).
* **Endpoint 1 (Linux Target):** Maszyna wirtualna Ubuntu/Debian (IP: `192.168.0.17`) z agentem Wazuh monitorującym logi systemowe (`journald`).

---

## 🚀 Faza 1: Wdrożenie i Zbieranie Logów (Log Ingestion)

1. **Manager:** 
   * Rozwiązano problemy z bazą RBAC oraz poświadczeniami API (Error 900).
   * Nadano nowe hasła oraz przywrócono poprawne połączenie Dashboard <-> API.
2. **Agent Linux:**
   * Zainstalowano Agenta Wazuh (wersja 4.14.9) z wymuszeniem pobrania pakietów po protokole IPv4.
   * Rozwiązano problem uprawnień do odczytu dziennika — dodano użytkownika `wazuh` do grupy `systemd-journal`.
   * Naprawiono błąd połączenia z bazą Indexera (*Error 401 Unauthorized*), aktualizując hasło w Keystore usługi Filebeat na serwerze Managera.

---

## ⚔️ Faza 2: Symulacja Ataków (Red Teaming)

Przeprowadzono symulację ataku typu **Brute-Force** na usługę SSH maszyny `linux-target` (`192.168.0.17`).

* **Narzędzie:** Hydra
* **Źródło ataku:** Zewnętrzna maszyna o adresie IP `192.168.0.52`.
* **Cel:** Port 22 (SSH), użytkownik docelowy: `polafasola2`.
* **Skutek ataku:** Wygenerowanie licznych błędów uwierzytelniania w logach agenta przechwyconych przez systemowy demona `journald`.

---

## 🛡️ Faza 3: Detekcja i Automatyczna Reakcja (Active Response)

### Reguła Detekcyjna (Detection Engineering)
Opracowano autorską regułę w pliku `local_rules.xml` identyfikującą atak Brute-Force (mapowanie do **MITRE ATT&CK: T1110**). 

<img width="1858" height="352" alt="obraz" src="https://github.com/user-attachments/assets/96efd797-b73b-4746-be3b-0ac04a982b67" />

Reguła nasłuchuje na standardowe zdarzenia błędnego logowania (ID `5760` z demona `sshd`) i podnosi alarm o **ID 100002**, jeśli wystąpią one 5 razy w ciągu 60 sekund z tego samego adresu IP.

### Active Response (SOAR)
Skonfigurowano moduł **Active Response** na Managerze powiązany ze stworzoną regułą. W momencie detekcji ataku do Agenta wysyłane jest żądanie uruchomienia skryptu `firewall-drop`.

### Potwierdzenie wdrożenia (Dowody)

1. Atak został poprawnie wykryty w Wazuh Dashboard (alerty poziomu 5 dla ID 5760 oraz poziomu 10 dla autorskiej detekcji Brute Force).
<img width="1854" height="962" alt="obraz" src="https://github.com/user-attachments/assets/4536d79e-aa86-4f7f-8a6d-45883c69c8fd" />
<img width="1858" height="965" alt="obraz" src="https://github.com/user-attachments/assets/408753ce-c30e-4511-9843-df40058fc303" />


2. Adres IP atakującego (`192.168.0.52`) został automatycznie zablokowany za pomocą mechanizmu `iptables` (reguła `DROP` w łańcuchu `INPUT`) na maszynie docelowej `192.168.0.17`.
<img width="529" height="97" alt="obraz" src="https://github.com/user-attachments/assets/a3f60aa2-9224-4e59-a699-6b938f717410" />



3. Skuteczność blokady potwierdzono 100% utratą pakietów ping z perspektywy atakującego, przy jednoczesnym zachowaniu łączności ofiary z maszyną Managera (`192.168.0.136`).
<img width="536" height="245" alt="obraz" src="https://github.com/user-attachments/assets/5d420193-b102-4327-ae3b-5c22c6e6cdea" />

