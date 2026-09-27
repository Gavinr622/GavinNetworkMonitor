# Gavin Network Monitor

A Windows desktop network diagnostics GUI built with Python, Tkinter, Scapy, and Npcap. It displays packet metadata and selected protocol/header information for troubleshooting and learning. It is designed not to display packet payload contents.

## Version and downloads

- **Current project version:** `v7.3`
- **Release status:** GitHub source release; not a compiled installer.
- **Download:** Open the repository's **Releases** page and download the ZIP asset attached to the latest release.
- **Automatic download:** After setting your GitHub username in `Download_GavinNetworkMonitor.bat`, run it to fetch and extract the latest published ZIP release. See `DOWNLOAD_INSTRUCTIONS.txt`.

### Publishing a GitHub release

1. Push the project files to the `GavinNetworkMonitor` repository.
2. On GitHub, open **Releases** → **Draft a new release**.
3. Create a tag named `v7.3` and set the release title to `Gavin Network Monitor v7.3`.
4. Paste the following release notes, attach the project ZIP, and publish.

**Copy/paste release notes:**

```text
Gavin Network Monitor v7.3 — Source Release

Includes live packet metadata monitoring, interface selection, traffic filters,
domain/IP watch list, packet header inspection, CSV exports, in-app documentation,
configurable loading screen, and guarded command console.

Requirements: Windows 10/11 64-bit, Python 3.10+, Scapy, and Npcap.
This is a source-code release, not a compiled installer. See README.md for setup.
Use only on your own computer or networks you are authorized to troubleshoot.
```

After publishing, the downloader can retrieve the ZIP from the latest release.

## Features

- Live packet metadata table (time, protocol, endpoints, ports, and packet size)
- Interface selection and traffic filtering
- Domain/IP watch list with DNS resolution and match logging
- Packet header inspection
- CSV export for traffic and domain matches
- In-app documentation, settings, and configurable loading screen
- Admin-gated in-app command console with guarded commands

## Requirements

- Windows 10/11, 64-bit
- Python 3.10 or newer (tested in the project environment with Python 3.13)
- Npcap installed on Windows, with packet-capture support enabled
- Python dependency: Scapy (`scapy>=2.5`)

## Setup

1. Install Python from <https://www.python.org/downloads/> and enable the Python launcher (`py`).
2. Install Npcap from <https://npcap.com/>. Use its default installation options unless you know you need something different.
3. Open Command Prompt in this repository folder and install the Python dependency:

   ```bat
   py -m pip install -r requirements.txt
   ```

4. Double-click `Install_Dependencies.bat` to install the Python packages, or run the pip command below.
5. Run `Run_GavinNetworkMonitor.bat`, or start it manually:

   ```bat
   py app.py
   ```

5. If packet capture does not start, close the app and relaunch it with the Windows permissions required by your Npcap setup. Do not disable Windows security features to make it run.

## Project layout

```text
app.py                         Main Tkinter application
cmd/                           Command-console implementation
config/                        Default settings and command/app configuration
docs/                          In-app HTML documentation and icon
loading_screen.py              Built-in loading-screen defaults
LOADING_SCREEN.md              Loading-screen customization notes
requirements.txt               Python dependencies
Install_Dependencies.bat       Installs Python dependencies
admin.txt                      Built-in demo admin login and security note
Run_GavinNetworkMonitor.bat    Windows launcher
Download_GavinNetworkMonitor.bat  Latest-release downloader
DOWNLOAD_INSTRUCTIONS.txt      Downloader setup and release template
```

## Safety and privacy

Use this tool only on your own computer or on networks you are authorized to troubleshoot. Packet metadata can still reveal sensitive information such as device addresses and connection patterns. The app is intended for metadata/header diagnostics, not collecting message contents, credentials, or other people's private communications. Obtain permission before monitoring a shared network, and avoid publishing captures or logs that contain personal or network-identifying data.

The built-in admin prompt is an application-level gate, not secure operating-system authentication. The demo credentials are listed in `admin.txt`; they are hard-coded in the source and must not be treated as a security boundary.

## Configuration

The `config/` directory contains the application's default JSON configuration files. The loading-screen customization options are described in `LOADING_SCREEN.md`. Keep a backup before editing configuration files.

## GitHub notes

This archive is a source-code project, not a compiled installer. Do not commit packet captures, exported CSV logs, credentials, private configuration, or personal network details. Review changes before publishing.

## License

No license has been selected yet. Unless a license is added, normal copyright applies and reuse/redistribution permissions are not granted by default.
