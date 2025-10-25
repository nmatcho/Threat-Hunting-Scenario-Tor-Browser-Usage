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

- With this information I now know that evidence for network traffic will be on ports 9150 and 9151. I then shifted to the DeviceNetworkEvents table to find confirmation of this.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "OBFUSCATED"
| where Timestamp >= datetime(2025-10-23T19:58:24.2461505Z)
| where RemotePort == 9150 or RemotePort == 9151
| project Timestamp, ActionType, RemoteIP, RemotePort, InitiatingProcessSHA256, InitiatingProcessCommandLine
```

<img width="1149" height="103" alt="image" src="https://github.com/user-attachments/assets/6bb8cc98-1da6-41d0-a85a-7a4a410f27b0" />

- The resulting query was a "ConnectionSuccess" ActionType to each port, confirming the Tor Browser was launched. However, this evidence doesn't yet confirm EXTERNAL connection on the company network because it was using the LOCAL loopback address confirmed in the RemoteIP section (127.0.0.1). I then began to hunt for possible outbound connections to RemoteIPs following the successful loopback connections. I also made sure to include the same InitiatingProcessCommandLine to confirm they were outbound connections using the Tor Browser.

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

## Response Taken

- TOR usage was confirmed on the endpoint "OBFUSCATED" by the user "OBFUSCATED". The device was isolated, and the user's direct manager was notified.

---

## Chronological Event Timeline 

### 1. File Download - TOR Browser Download

- **Timestamp:** '2025-10-23T19:56:47.7628049Z` 3:56PM EST 10/23/25
- **Event:** The user "OBFUSCATED" downloaded a file named "tor-browser-windows-x86_64-portable-14.0.1.exe" to the Downloads folder.
- **Action:** File download detected.
- **File Path:** C:\Users\OBFUSCATED\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** '2025-10-23T19:59:46.8619451Z` 3:59PM EST 10/23/25
- **Event:** The user "OBFUSCATED" silently installed the executable "tor-browser-windows-x86_64-portable-14.0.1.exe' using the /s" command.
- **Action:** File installation command detected.
- **Command Executed:** tor-browser-windows-x86_64-portable-14.5.8.exe /S

### 3. File Installation - TOR Browser Installation

- **Timestamp:** '2025-10-23T20:00:03.3275435Z` 4:00PM EST 10/23/25
- **Event:** The previously mentioned file installed by the user "OBFUSCATED" was saved to the Desktop as "Tor-Launcher.txt".
- **Action:** File installation detected.
- **File Path:** C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt

### 4. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-10-23T20:00:47.0997688Z` 4:00PM EST 10/23/25
- **Event:** The user "OBFUSCATED" launched the TOR browser. Discovered by review of "firefox.exe" and "ProcessCommandLine" instances.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** C:\Users\OBFUSCATED\Desktop\Tor Browser\Browser\firefox.exe

### 5. Network Connection - Internal TOR Network Connections

- **Timestamp:** `2025-10-23T20:00:54.0914535Z` 4:00PM EST 10/23/25
- **Event:** Further confirmation the user "OBFUSCATED" launching the Tor Browser evidenced by connections over common TOR ports 9150 and 9151 to the loopback address.
- **Action:** Connection success.
- **RemoteIPs:** 127.0.0.1
- **RemotePorts:** 9150 and 9151

### 6. Network Connection - External TOR Network Connections

- **Timestamp:** `2025-10-23T20:00:59.0185706Z` 4:01PM EST 10/23/25
- **Event:** Confirmed the Tor Browser accessed websites using the Tor Browser over port 443 and 8080.
- **Action:** Connection success.
- **RemoteIPs:** 162.55.48.243, 94.23.247.42, 188.165.4.146
- **RemotePorts:** 443 and 8080

### 7. Suspicious File Created - TOR Shopping List

- **Timestamp:** `2025-10-23T20:20:05.1919289Z` 4:20PM EST 10/23/25
- **Event:** The user "OBFUSCATED" create a .txt file named "Tor shopping list.txt" and saved it to the Desktop.
- **Action:** Suspicious File Detected.
- **File Path:** C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt 

### 8. File Deleted - Tor Browser

- **Timestamp:** `2025-10-23T20:20:58.9451151Z` 4:21PM EST 10/23/25
- **Event:** The user "OBFUSCATED" deleted the file named "tor.exe" from the Desktop.
- **Action:** Suspicious File Deleted.
- **File Path:** C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt

---

## Executive Summary of Events

Management suspected an employee of using the Tor Browser to bypass network controls after unusual encrypted traffic was detected. Investigation confirmed that the Tor Browser was silently installed on the workstation, evidenced by installation artifacts and a suspicious file on the Desktop. Process logs showed the browser and Tor processes were launched, and network logs confirmed both local communication on Tor’s SOCKS/control ports and subsequent outbound connections to external IPs, demonstrating active use of the Tor network. While the specific websites visited could not be determined, the findings clearly indicate unauthorized Tor usage on the company network. The device was isolated and the user’s direct manager was notified.

---
