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

### 1. Searched the `DeviceFileEvents` Table to Confirm Installation

- I searched the DeviceFileEvents table for ANY File containing “Tor” on the employee in question’s workstation and account name. I confirmed the employee downloaded and installed a Tor Browser, which generated many “tor” related files. Another suspicious file named “tor shopping list.txt” was found on the Desktop located at C:\Users\OBFUSCATED\Desktop\Tor-shopping-list\Tor shopping list.txt. The launcher itself was located on the Desktop too at C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt. I made a note that these events started at “2025-10-23T19:56:47.7628049Z” (3:56PM EST 10/23/25).

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

### 2. Searched the `DeviceProcessEvents` Table to Confirm Launch

- I shifted to the DeviceProcessEvents table to find any commands being run at the same time and establish more evidence. I immediately discovered a silent install of “tor-browser-windows-x86_64-portable-14.5.8.exe” at 2025-10-23T19:59:46.8619451Z.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "OBFUSCATED"
| where Timestamp >= datetime(2025-10-23T19:58:24.2461505Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp asc
```

<img width="584" height="457" alt="image" src="https://github.com/user-attachments/assets/770fd6ce-a9e0-4f58-b423-1cc80170f2ba" />

- As of right now I know the “Tor Browser” was installed and a suspicious text file “tor shopping list” was created, but I have no evidence of the employee launching the browser and using the company network to access the dark web. I dove deeper into the DeviceProcessEvents table to view what the commands following the silent install did. Immediately after the install I saw many "firefox.exe" instances beginning at 2025-10-23T20:00:47.0997688Z. I wasn’t sure what to make of them. At first I assumed they were legitimate uses, but then I noticed the FolderPath for "firefox.exe" is embedded in the Tor Browser directory.

<img width="578" height="444" alt="image" src="https://github.com/user-attachments/assets/62adc2a6-283f-428f-9f8a-43603f04d81d" />

- The "ProcessCommandLine" section gives further evidence of the Tor Browser being launched on the company network with the commands highlighted in the following image:

<img width="1114" height="459" alt="image" src="https://github.com/user-attachments/assets/f7e54105-5eba-49c0-9ac7-d4723f4866d8" />

- According to ChatGPT, the second command highlighted launches the Tor process using specified configuration files and data directories. It sets up Tor's SOCKS proxy on port 9150 and control interface on port 9151, using local configuration files for routing, geoIP data, and authentication, but starts with the network initally disabled.

```cmd
"tor.exe" -f "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc" DataDirectory "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor" ClientOnionAuthDir "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\onion-auth" --defaults-torrc "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc-defaults" GeoIPFile "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\geoip" GeoIPv6File "C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\geoip6" +__ControlPort 127.0.0.1:9151 HashedControlPassword ********** +__SocksPort "127.0.0.1:9150 ExtendedErrors IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth" __OwningControllerProcess 1020 DisableNetwork 1
```

---

### 3. Searched the `DeviceNetworkEvents` Table for External TOR Network Connections

- With this information I now know that evidence for network use will be on ports 9150 and 9151. I then shifted to the DeviceNetworkEvents table to find further confirmation of this.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "OBFUSCATED"
| where Timestamp >= datetime(2025-10-23T19:58:24.2461505Z)
| where RemotePort == 9150 or RemotePort == 9151
| project Timestamp, ActionType, RemoteIP, RemotePort, InitiatingProcessSHA256, InitiatingProcessCommandLine
```

<img width="1149" height="103" alt="image" src="https://github.com/user-attachments/assets/6bb8cc98-1da6-41d0-a85a-7a4a410f27b0" />

- The resulting query was a "ConnectionSuccess" ActionType to each port, confirming the Tor Browser was launched. However, this evidence doesn't yet confirm EXTERNAL connection on the company network because it was using the LOCAL loopback address confirmed inthe RemoteIP section (127.0.0.1). I then began to hunt for possible outbound connections to RemoteIPs following the successful loopback connections. I also made sure to include the same InitiatingProcessCommandLine to confirm they were outbound connections using the Tor Browser.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "OBFUSCATED"
| where Timestamp >= datetime(2025-10-23T19:58:24.2461505Z)
| where InitiatingProcessCommandLine contains "tor"
| where ActionType == "ConnectionSuccess"
| where RemoteIP != "127.0.0.1"
| project Timestamp, ActionType, RemoteIP, RemotePort, InitiatingProcessSHA256, InitiatingProcessCommandLine
```

<img width="1158" height="230" alt="image" src="https://github.com/user-attachments/assets/2e886f3c-1a24-48cc-92db-ab5efe07c7eb" />

- The output generated three "ConnectionSuccess" ActionTypes to unique RemoteIPs, confirming EXTERNAL network connections via the Tor Browser.

---

## Chronological Event Timeline 

### 1. File Download - TOR Download

- **Timestamp:** '2025-10-23T19:56:47.7628049Z`
- **Event:** The user "OBFUSCATED" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\OBFUSCATED\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe`

### 2. Process Execution - TOR Installation

- **Timestamp:** '2025-10-23T19:59:46.8619451Z`
- **Event:** The user "OBFUSCATED" silently installed the executable 'tor-browser-windows-x86_64-portable-14.0.1.exe' using the '/s' command.
- **Action:** File installation command detected.
- **Command Executed:** `tor-browser-windows-x86_64-portable-14.5.8.exe /S`

### 2. File Installation - TOR Installation

- **Timestamp:** '2025-10-23T20:00:03.3275435Z`
- **Event:** The previously mentioned file installed by the user "OBFUSCATED" was saved to the Desktop as "Tor-Launcher.txt".
- **Action:** File installation detected.
- **File Path:** `C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt`



### 2. Suspicious File Created - TOR Shopping List

- **Timestamp:** `2025-10-23T20:20:05.1919289Z`
- **Event:** The user "OBFUSCATED" create a .txt file named "Tor shopping list.txt" and saved it to the Desktop.
- **Action:** Suspicious File Detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt`  

### 2. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 3. Network Connection - TOR Network

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

- TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

## Executive Summary of Events

Management suspected an employee of using the Tor Browser to bypass network controls after unusual encrypted traffic was detected. Investigation confirmed that the Tor Browser was silently installed on the workstation, evidenced by installation artifacts and a suspicious file on the Desktop. Process logs showed the browser and Tor processes were launched, and network logs confirmed both local communication on Tor’s SOCKS/control ports and subsequent outbound connections to external IPs, demonstrating active use of the Tor network. While the specific websites visited could not be determined, the findings clearly indicate unauthorized Tor usage on the company network. The device was isolated and the user’s direct manager was notified.

---
