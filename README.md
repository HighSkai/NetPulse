<div align="center">

<img src="src/netpulse/web/static/wordmark.svg" alt="NetPulse" width="300">

**A self-hosted network monitor for your home or lab network.**

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/HighSkai/NetPulse)](https://github.com/HighSkai/NetPulse/releases)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Platform: Windows](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white)

</div>

NetPulse runs on one Windows PC and checks the devices on your network every 30 seconds: routers, access points, cameras, a NAS, printers, smart-home gear and the public services you rely on. It keeps the history in SQLite, alerts you when something goes down, and serves a dashboard to every phone, tablet and laptop you sign in from.

It needs no cloud account and sends no telemetry. Every script, style and font ships with it.

## Features

**Monitoring**
- Checks by ping or by TCP port, 32 devices at a time, every 30 s, 1, 5 or 15 minutes per device. Pause a device without losing it.
- Up, degraded, down and paused states. *Degraded* means the last 10 checks averaged over 150 ms or 2 of them failed. An outage starts after 2 failures in a row.
- Uses Windows' `IcmpSendEcho` directly, so it works in any display language.

**Dashboard**
- An overview that puts problems first, with a 24-hour status grid and a likely cause when several devices fail together.
- Device pages with latency and availability from 1 hour to 1 year, plus the outage log.
- A network map of this PC, its subnets, the gateway and every device.
- Availability reports for 7, 30 or 90 days, on screen or as CSV.

**Inventory**
- Type, group, vendor, model, location, MAC address, tags and notes, all searchable and filterable.
- CSV import and export.
- Discovery sweeps of your subnets, on demand or on a schedule. Nothing is monitored until you accept it.
- Deleted devices keep their history and can be restored.

**Alerts**
- Opens when a device goes down, stays degraded, appears for the first time, or when monitoring itself stops. Closes when the cause ends.
- Sends to a webhook, Discord or email, by severity, with a delay and grouping to keep it quiet.

**Diagnostics**
- Path traces with loss and times per hop.
- Packet capture through Npcap (optional), saved as PCAP files that open in Wireshark.
- Checks from outside through Globalping (off until an administrator agrees).
- This PC's adapters, gateways, DNS servers and DHCP lease.

**Multi-user**
- Administrator and viewer accounts, with permissions you can grant, a list of active sessions and an audit log.
- Access from any device on your network over HTTPS.
- Works on phones and without JavaScript. Light and dark themes, and reduced motion is respected.

## Requirements

- Windows 10 or 11
- [Python](https://www.python.org/downloads/) 3.11 or newer
- [Npcap](https://npcap.com), only for packet capture

No Administrator rights are needed, except once to open the firewall for other devices.

## Quick start

1. Install Python and tick **Add python.exe to PATH** in the installer.
2. Download NetPulse (**Code, Download ZIP**, or `git clone`) into a folder of its own, such as `C:\NetPulse`.
3. Double-click **`NetPulse.bat`**.

The first run sets NetPulse up in a `.venv` folder, which takes about a minute and needs the internet. After that it starts NetPulse and opens it in your browser. Keep the window open while you use it; close it to stop.

On the first visit, create the administrator account. There is no default account or password. Then add devices one at a time, import a CSV, or sweep your network from the **discover** page.

To make a desktop shortcut, right-click `NetPulse.bat` and choose **Send to, Desktop (create shortcut)**. Keep the file itself in the NetPulse folder.

**Updating:** replace the files (or `git pull`), keeping `netpulse.db` and the `netpulse-tls` folder. The next start installs the new version and upgrades the database, backing it up first. A 1.x database keeps all its history; you are asked to create the administrator once.

## Opening NetPulse from other devices

NetPulse answers only on its own PC until you turn on network access.

1. In **settings, Access**, tick *Let other devices on my network open NetPulse* and save. It applies immediately.
2. Open the port once, in PowerShell run as Administrator (the access page shows this with your port):

   ```powershell
   New-NetFirewallRule -DisplayName "NetPulse" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow -Profile Private
   ```

   The rule applies only on networks Windows marks as Private. If your home network is marked Public, the access page tells you how to change it.
3. On another device, open the address the access page shows, such as `https://192.168.1.20:5000`, and sign in.

**HTTPS.** NetPulse creates its own certificate authority to encrypt these connections. Browsers warn about it until you install that authority on the device: download it from the access page, which explains how for Windows, macOS, iOS and Android, then restart the browser. The authority can only sign for private addresses and local names, so it can't be used to impersonate a public website. You can use your own certificate instead, or turn HTTPS off.

**Names.** To use a name such as *netpulse.lan*, point it at this PC in your router or Pi-hole, then add it on the access page. NetPulse refuses any name it doesn't know, which blocks DNS-rebinding attacks.

**Not for the internet.** To reach NetPulse from outside, use a VPN to your home network instead of forwarding the port.

**Locked out?** Start it with `NetPulse.bat --local-only` (or `netpulse --local-only`). It ignores the network settings and serves this PC only, so you can fix them.

## Accounts and permissions

Add accounts under **settings, Users**. Each new account gets a temporary password and chooses its own at the first sign-in.

| | Administrator | Viewer |
| --- | --- | --- |
| Overview, devices, map, network, discover, probe, alerts, reports | yes | yes, to look |
| Add, edit, pause and delete devices and groups | yes | if granted |
| Check now, traces, sweeps, acknowledge alerts | yes | if granted |
| Alert rules and channels | yes | if granted |
| Packet captures | yes | if granted |
| Checks from outside | yes | if granted |
| Change settings, network access and accounts; the audit log | yes | never |

- Permissions are checked on the server for every request.
- Disabling an account, removing a permission or resetting a password signs that account out everywhere.
- The last administrator can't be disabled, demoted or deleted.
- Sessions end after 7 days unused, or 30 days after signing in. After 10 failed sign-ins from one address, or 20 for one username, sign-in pauses for 15 minutes.

**Forgot the administrator password?** Run this in the NetPulse folder:

```powershell
.venv\Scripts\netpulse.exe --db netpulse.db reset-password NAME
```

It prints a temporary password. `users` instead of `reset-password NAME` lists the accounts.

## Alerts and notifications

Open alerts are on the **alerts** tab. Under **settings, Alerts**, choose what raises an alert and where messages go:

- **Webhook:** a JSON `POST` for Home Assistant, ntfy, Gotify, n8n and similar tools.
- **Discord:** a channel webhook address.
- **Email:** any SMTP server, over STARTTLS or TLS.

Each channel takes alerts from a chosen severity up: *info* (new devices), *warning* (degraded) or *critical* (down, monitoring stopped). Use **Send a test** to check a channel. Webhook addresses are stored as secrets and never shown again.

## Command line

```powershell
netpulse [--db PATH] [--port N] [--local-only] [--open] [--debug]
netpulse [--db PATH] reset-password NAME
netpulse [--db PATH] users
```

| Option | Description |
| --- | --- |
| `--db PATH` | The database file, created if missing. Defaults to `netpulse.db` in the current folder. |
| `--port N` | The port for this run, instead of the one on the access page (5000). |
| `--local-only` | Serve this PC only, over plain HTTP, whatever the access settings say. |
| `--open` | Open NetPulse in the browser once it is listening. `NetPulse.bat` passes it. |
| `--debug` | Flask's development server, on this PC only. For development. |

`NetPulse.bat` passes anything after it to NetPulse. To install without it:

```powershell
python -m venv .venv
.venv\Scripts\pip install .
.venv\Scripts\netpulse.exe --db C:\NetPulse\netpulse.db --open
```

To start NetPulse with Windows, add a Task Scheduler task that runs `C:\NetPulse\.venv\Scripts\netpulse.exe` with `--db C:\NetPulse\netpulse.db`, **At startup**.

## Your data

- **`netpulse.db`** holds your devices, their history, accounts, sessions and alert settings. Passwords are stored only as Argon2id hashes and session tokens only as hashes. Keep the file private.
- **`netpulse-tls`** holds NetPulse's certificate authority and its private key. Keep it as private as the database.
- **`netpulse-captures`** holds packet captures. The last 50, or the last 30 days, are kept.
- Single checks are kept 90 days by default (configurable in **settings**). Hourly totals and outages are kept for good, so long-range charts stay complete.

NetPulse contacts only the devices you add, the notification channels you set up, and Globalping if an administrator turns it on. Globalping results are public, and private addresses are never sent there. Packet captures can contain sensitive data: one only starts when someone presses **Start**, and the files never leave the PC.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Another device can't open NetPulse | Check that network access is on, you're using the address the access page shows, and the firewall rule exists. On a network Windows marks Public, the rule doesn't apply; the access page shows how to change that. |
| *netpulse.lan* "can't be reached" | Nothing points that name at this PC yet. Set it in your router or Pi-hole (the access page checks it), or use the address. |
| Chrome still says "Not secure" after installing the authority | Restart Chrome (`chrome://restart`). Install the authority on every device you use. |
| "This NetPulse does not answer to the name …" | Add the name on the access page, or use the address. |
| Can't reach NetPulse after changing access | Start it with `--local-only` and fix the settings on this PC. |
| "Too many failed sign-ins" | Wait 15 minutes, or sign in on the PC NetPulse runs on. |
| "port 5000 is in use" | NetPulse is probably already running. Otherwise start with `--port 5001`. |
| `NetPulse.bat` says it needs Python | Install Python 3.11+ with **Add python.exe to PATH** ticked. |
| A device that is on shows Down | It ignores ping. Edit it and check a TCP port instead. |
| My devices are gone | NetPulse opened a different database. Use the same `--db` path as before; it is logged at startup. |
| The traffic page says capture is unavailable | Install Npcap with **Restrict Npcap driver's access to Administrators only** unticked. |

## Limitations

- Windows only, IPv4 only.
- Checks are ping or TCP; no HTTP, DNS, SNMP or certificate-expiry checks yet.
- Local accounts only; no single sign-on.
- Not a Windows service; use Task Scheduler to start it with Windows.

## Reference

### Check results

A check either succeeds with a round-trip time in whole milliseconds, or fails with one of these codes:

| Code | Meaning |
| --- | --- |
| `timeout` | No reply in time |
| `unreachable` | The destination was unreachable, or the TCP port refused the connection |
| `name_resolution` | The host name could not be resolved |
| `transmit_failed` | This PC could not send the request |
| `ttl_expired` | The packet expired in transit |
| `unreadable_output` | Only with the `ping.exe` fallback: its output could not be read |

<details>
<summary><strong>HTTP routes</strong></summary>

Every `POST` needs the page's CSRF token (`csrf_token` field or `X-CSRF-Token` header). Every route except sign-in and setup needs a session; *Needs* is the permission required beyond that.

| Route | What it does | Needs |
| --- | --- | --- |
| `GET /setup` | First-run setup, on this PC only, before any account exists | |
| `POST /setup` | Create the administrator and sign in | |
| `GET /login` | Sign-in form | |
| `POST /login` | Sign in | |
| `POST /logout` | Sign out | |
| `GET /account` | Your account, permissions and sessions | |
| `POST /account/password` | Change your password | |
| `POST /account/sessions/<int:session_id>/revoke` | Sign out one of your sessions | |
| `POST /account/sessions/revoke-others` | Sign out all your other sessions | |
| `GET /` | Overview | |
| `GET /devices` | Device table and add form | |
| `GET /devices/rows` | Device table body (polled) | |
| `POST /devices` | Add a device | `devices.manage` |
| `GET /devices/<int:device_id>` | Device page | |
| `GET /devices/<int:device_id>/edit` | Edit form | `devices.manage` |
| `POST /devices/<int:device_id>/edit` | Save a device | `devices.manage` |
| `POST /devices/<int:device_id>/check` | Check now | `checks.run` |
| `POST /devices/<int:device_id>/pause` | Pause or resume | `devices.manage` |
| `POST /devices/<int:device_id>/delete` | Delete, keeping history | `devices.manage` |
| `GET /devices/deleted` | Deleted devices | |
| `POST /devices/<int:device_id>/restore` | Restore a deleted device | `devices.manage` |
| `POST /devices/<int:device_id>/purge` | Erase a deleted device and its history | `devices.manage` |
| `GET /devices/groups` | Groups | |
| `POST /devices/groups` | Add a group | `devices.manage` |
| `POST /devices/groups/<int:group_id>` | Rename a group | `devices.manage` |
| `POST /devices/groups/<int:group_id>/delete` | Delete a group | `devices.manage` |
| `GET /devices/import` | Import form | `devices.manage` |
| `POST /devices/import` | Import devices from CSV | `devices.manage` |
| `GET /devices/export.csv` | Export devices as CSV | |
| `GET /status` | Status bar (polled) | |
| `GET /alerts` | Open and past alerts | |
| `POST /alerts/<int:alert_id>/ack` | Acknowledge an alert | `alerts.ack` |
| `POST /alerts/ack-all` | Acknowledge every open alert | `alerts.ack` |
| `GET /reports` | Availability report | |
| `GET /reports.csv` | Availability report as CSV | |
| `GET /settings` | Settings | |
| `POST /settings` | Save degraded thresholds | `settings.manage` |
| `POST /settings/retention` | Save retention | `settings.manage` |
| `POST /settings/discovery` | Save the sweep schedule | `settings.manage` |
| `GET /settings/access` | Network access | `settings.manage` |
| `POST /settings/access` | Save and apply network access | `settings.manage` |
| `POST /settings/access/certificate` | Make a new server certificate | `settings.manage` |
| `GET /settings/access/authority.crt` | Download the certificate authority (never its key) | |
| `GET /settings/users` | Accounts | `users.manage` |
| `POST /settings/users` | Add an account | `users.manage` |
| `GET /settings/users/<int:user_id>` | One account | `users.manage` |
| `POST /settings/users/<int:user_id>` | Save an account | `users.manage` |
| `POST /settings/users/<int:user_id>/password` | Set a temporary password | `users.manage` |
| `POST /settings/users/<int:user_id>/sessions/revoke` | Sign an account out everywhere | `users.manage` |
| `POST /settings/users/<int:user_id>/delete` | Delete an account | `users.manage` |
| `GET /settings/audit` | Audit log | `users.manage` |
| `GET /settings/alerts` | Alert rules and channels | `alerts.manage` |
| `POST /settings/alerts` | Save alert rules | `alerts.manage` |
| `POST /settings/alerts/channels` | Add a channel | `alerts.manage` |
| `GET /settings/alerts/channels/<int:channel_id>` | Edit a channel | `alerts.manage` |
| `POST /settings/alerts/channels/<int:channel_id>` | Save a channel | `alerts.manage` |
| `POST /settings/alerts/channels/<int:channel_id>/test` | Send a test message | `alerts.manage` |
| `POST /settings/alerts/channels/<int:channel_id>/delete` | Delete a channel | `alerts.manage` |
| `GET /network` | This PC's network settings | |
| `POST /network/refresh` | Read the network settings again | `diagnostics.run` |
| `GET /map` | Network map | |
| `GET /map/view` | Map data (polled) | |
| `GET /discover` | Discovery | |
| `GET /discover/view` | Sweep progress (polled) | |
| `POST /discover` | Start a sweep | `discovery.run` |
| `POST /discover/<int:host_id>/accept` | Monitor a discovered host | `devices.manage` |
| `POST /discover/<int:host_id>/ignore` | Ignore a discovered host | `devices.manage` |
| `POST /discover/<int:host_id>/restore` | Un-ignore a host | `devices.manage` |
| `GET /probe` | Path traces | |
| `GET /probe/view` | Trace progress (polled) | |
| `POST /probe/trace` | Start a trace | `diagnostics.run` |
| `GET /probe/traces/<int:trace_id>` | A past trace | |
| `GET /probe/outside` | Checks from outside | |
| `GET /probe/outside/view` | Check progress (polled) | |
| `POST /probe/outside/consent` | Turn Globalping on or off | `settings.manage` |
| `POST /probe/outside/check` | Check a public host from outside | `outside.run` |
| `GET /probe/outside/checks/<int:check_id>` | A past check from outside | |
| `GET /traffic` | Packet capture | `capture.view` |
| `GET /traffic/view` | Live capture (polled) | `capture.view` |
| `POST /traffic/start` | Start a capture | `capture.run` |
| `POST /traffic/stop` | Stop the capture | `capture.run` |
| `GET /traffic/<int:capture_id>` | A capture's packets | `capture.view` |
| `GET /traffic/<int:capture_id>/pcap` | Download a capture | `capture.view` |
| `POST /traffic/<int:capture_id>/delete` | Delete a capture | `capture.run` |

</details>

## License

[GPL-3.0-only](LICENSE). Copyright (C) 2026 the NetPulse authors.

Built with [Flask](https://flask.palletsprojects.com/), [cheroot](https://cheroot.cherrypy.dev/), [argon2-cffi](https://argon2-cffi.readthedocs.io/), [cryptography](https://cryptography.io/), [HTMX](https://htmx.org/), [uPlot](https://github.com/leeoniya/uPlot), [Cytoscape.js](https://js.cytoscape.org/) and [IBM Plex Mono](https://github.com/IBM/plex); their licences are in `src/netpulse/web/static/`. Packet capture uses [Npcap](https://npcap.com/), and checks from outside use [Globalping](https://globalping.io/).
