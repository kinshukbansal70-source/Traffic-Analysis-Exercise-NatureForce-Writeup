# Traffic Analysis Write-Up: NATUREFORCE Exercise (2026-10-01)

**Source:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) training exercise dated 2026-10-01
**Tools:** Wireshark 4.6.4 (Ubuntu ARM64 VM in VMware Fusion), `sha256sum`, VirusTotal
**Capture:** `2026-10-01-traffic-analysis-exercise.pcap` (42,497 packets)

> All analysis was done inside an isolated VM with the network adapter disconnected. The downloaded executable was never run.

---

## Summary

A Windows workstation (`DESKTOP-4VGYQX7`, user `bdiaz`, IP `10.10.1.128`) in the NATUREFORCE Active Directory domain downloaded a Windows executable, `runner_ilove.exe`, over HTTP on an unusual port (TCP 9000) from `107[.]175[.]82[.]242`. The request used a `curl` user-agent and the server was a MinIO object-storage instance. VirusTotal flags the file as malicious (47 of 71 vendors), with several vendors labeling it as an AsyncRAT-type trojan/backdoor.

## Scenario

The SOC alerts for this exercise were:

- `107[.]175[.]82[.]242:9000`: Windows EXE sent from an IP address over an unusual TCP port
- `195[.]64[.]128[.]106:443`: CNCmachineRMS RAT C2 traffic

The goal was to review the pcap, verify the alerts, and identify the infected host.

## Victim Host

| Item | Value |
|---|---|
| IP address | `10.10.1.128` |
| MAC address | `00:22:fb:ec:7e:e7` (Intel OUI) |
| Host name | `DESKTOP-4VGYQX7` |
| User account | `bdiaz` (realm `NATUREFORCE`) |
| Domain controller | `10.10.1.10` (WIN-LEKBU2OY51N) |

**How each was found**

- **IP / MAC:** `ip.addr == 10.10.1.128`, then the Ethernet II source in frame 5.
- **Host name:** the LLMNR query in frame 5 (`Standard query ... ANY DESKTOP-4VGYQX7`). Kerberos packets also list `DESKTOP-4VGYQX7<20>` as the client address.
- **User account:** filter `kerberos.CNameString && ip.addr == 10.10.1.128`; the AS-REQ in frame 1214 shows `CNameString: bdiaz`, realm `NATUREFORCE`. (A name ending in `$` would be a computer account; this one is not.)

## Timeline (UTC)

| Time | Event |
|---|---|
| 2026-10-01 19:27:27 | Capture starts; host performs normal domain activity (DNS SRV, LDAP/CLDAP, Kerberos) with the domain controller |
| 19:30:36.806810 | Victim sends `GET /wilow/runner_ilove.exe` to `107[.]175[.]82[.]242:9000` (frame 23091) |
| 19:30:38.580040 | Server completes `HTTP/1.1 200 OK` response (frame 24916), 1,216 reassembled TCP segments |

The download took roughly 1.8 seconds.

## Analysis

### The download (frames 23091 and 24916)

Request:

```
GET /wilow/runner_ilove.exe HTTP/1.1
Host: 107[.]175[.]82[.]242:9000
User-Agent: curl/8.21.0
Accept: */*
```

Response headers of note:

- `Content-Type: binary/octet-stream`
- `Content-Length`: 1,647,168 bytes (matches the reassembled TCP length)
- `Server: MinIO`
- `Last-Modified: Thu, 01 Oct 2026 18:46:36 GMT` (about 44 minutes before the download)
- `ETag: "cb50fe432a302b85845bc7ea98742c11"`

**Observations**

- The `curl` user-agent on a Windows workstation suggests a script or command-line tool fetched the file rather than a user browsing.
- The payload was served from a MinIO server on a non-standard port, which is unusual for legitimate software distribution.
- The file was staged shortly before it was fetched.

### The file

The HTTP object was exported with **File > Export Objects > HTTP** and hashed with `sha256sum`.

```
SHA-256: b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061
```

VirusTotal results:

- **Detections:** 47 / 71 vendors flag the file as malicious
- **Popular threat label:** `trojan.capdoor/zusy`; family labels: capdoor, zusy, misc
- **Vendor names include:** Trojan/Win.AsyncRAT (AhnLab), Backdoor:Win/CapDoor (AliCloud), Trojan/Win64.Zusy (Antiy)
- **Type / size:** 64-bit Windows EXE, 1.57 MB
- **Name seen by VirusTotal:** `service.exe` (served here as `runner_ilove.exe`)
- **Behavior tags:** checks-cpu-name, detect-debug-environment, calls-wmi, spreader

The family naming varies by vendor, so it is described here as a trojan/backdoor with multiple AsyncRAT-related detections rather than a single confirmed family. The exercise alert refers to "CNCmachineRMS," which does not match the labels most vendors gave this sample.

### Alert verification

- **EXE over port 9000:** confirmed. The download is visible in the capture.
- **C2 to `195[.]64[.]128[.]106:443`:** not observed. The filter `ip.addr == 195.64.128.106` returned 0 packets. The C2 traffic was not located in this analysis; further work would check the victim's external conversations, TLS server names, and DNS queries after 19:30:38 UTC.

## Indicators of Compromise (defanged)

| Type | Value |
|---|---|
| IP:port | `107[.]175[.]82[.]242:9000` |
| URL | `hxxp://107[.]175[.]82[.]242:9000/wilow/runner_ilove[.]exe` |
| File name | `runner_ilove.exe` |
| SHA-256 | `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061` |
| User-Agent | `curl/8.21.0` |
| Alert IP (not seen in pcap) | `195[.]64[.]128[.]106:443` |

## Takeaways

- **Detection:** alert on executable downloads (`binary/octet-stream`, `MZ` header) over HTTP on non-standard ports, and on `curl` user-agents from Windows workstations.
- **Prevention:** block or inspect outbound traffic to uncommon ports and unknown IPs; restrict command-line download tools for standard users.
- **Response:** isolate `DESKTOP-4VGYQX7`, reset credentials for `bdiaz`, and scope for lateral movement (VirusTotal tags the sample as a spreader).

## Limitations

- C2 traffic was not identified in this pass.
- The file was not executed or reverse engineered; conclusions come from network evidence and VirusTotal reputation only.

## What I Learned

- Using Wireshark filters (`ip.addr`, `http.request`, `kerberos.CNameString`) to isolate a host's activity
- Extracting files with Export Objects and hashing them for threat-intel lookups
- Identifying host name, MAC, and user account from LLMNR, Ethernet, and Kerberos traffic
- Documenting findings with a timeline and defanged IOCs
