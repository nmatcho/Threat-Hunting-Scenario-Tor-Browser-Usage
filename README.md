# Threat Hunt Report: Unauthorized TOR Usage
[Scenario Creation](https://github.com/nmatcho/Threat-Hunting-Scenario-Tor-Browser-Usage-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## In-Depth Analysis

### 1. Searched the `DeviceFileEvents` Table

I searched the DeviceFileEvents table for ANY File containing “Tor” on the employee in question’s workstation and account name. I confirmed the employee downloaded a Tor browser, which generated many “tor” related files including one named “tor shopping list.txt” being copied to the Desktop. I noted that these events started at “2025-10-23T19:58:24.2461505Z” (3:58PM 10/23/25).

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName  == "OBFUSCATED"
| where InitiatingProcessAccountName == "OBFUSCATED"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-10-23T19:58:24.2461505Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="730" height="388" alt="image" src="https://github.com/user-attachments/assets/8c59cde8-8e0d-4d11-ae3c-73ad13422ab7" />

---

### 2. Searched the `DeviceProcessEvents` Table

I shifted to the DeviceProcessEvents table to find any commands being run at the same time and establish more evidence. I immediately discovered a silent install of “tor-browser-windows-x86_64-portable-14.5.8.exe” around 2025-10-23T20:00:47.0997688Z

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "OBFUSCATED"
| where Timestamp >= datetime(2025-10-23T19:58:24.2461505Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp asc
```

<img width="584" height="457" alt="image" src="https://github.com/user-attachments/assets/770fd6ce-a9e0-4f58-b423-1cc80170f2ba" />

As of right now I know the “Tor Browser” was installed and a suspicious text file “tor shopping list” was created, but I have no evidence of the employee launching the browser and using the company network to access the dark web. I dove deeper into the DeviceProcessEvents table to view what the commands following the silent install did. Immediately after the install I saw many firefox.exe instances. I wasn’t sure what to make of them. At first I assumed they were legitimate uses, but then I noticed the FolderPath for firefox is embedded in the Tor Browser directory.

<img width="578" height="444" alt="image" src="https://github.com/user-attachments/assets/62adc2a6-283f-428f-9f8a-43603f04d81d" />

The "ProcessCommandLine" section gives further evidence of the Tor Browser being launched on the company network with the commands highlighted in the following image:

<img width="1114" height="459" alt="image" src="https://github.com/user-attachments/assets/f7e54105-5eba-49c0-9ac7-d4723f4866d8" />

According to ChatGPT, the second command launches the Tor process using the specified configuration files and data directories. It sets up Tor's SOCKS proxy on port 9150 and control interface on port 9151, using local configuration files for routing, geoIP data, and authentication, but starts with the network initally disabled.

```cmd
"tor.exe" -f "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc" DataDirectory "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor" ClientOnionAuthDir "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\onion-auth" --defaults-torrc "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc-defaults" GeoIPFile "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\geoip" GeoIPv6File "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\geoip6" +__ControlPort 127.0.0.1:9151 HashedControlPassword ********** +__SocksPort "127.0.0.1:9150 ExtendedErrors IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth" __OwningControllerProcess 1020 DisableNetwork 1
```

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

With this information I now know that evidence for network use will be on ports 9150 and 9151. I then shifted to the DeviceNetworkEvents table to find further confirmation of this.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

## Executive Summary of Events

Management suspected an employee of using the Tor Browser to bypass network controls after unusual encrypted traffic was detected. Investigation confirmed that the Tor Browser was silently installed on the workstation, evidenced by installation artifacts and a suspicious file on the Desktop. Process logs showed the browser and Tor processes were launched, and network logs confirmed both local communication on Tor’s SOCKS/control ports and subsequent outbound connections to external IPs, demonstrating active use of the Tor network. While the specific websites visited could not be determined, the findings clearly indicate unauthorized Tor usage on the company network. The device was isolated and the user’s direct manager was notified.

---
