# Bundled profile catalogue

Three profiles ship with PortProof v1. Every row in every profile traces to a public,
non-authenticated Microsoft Learn page, cited by URL and retrieval date in the profile's own
`*.provenance.json` sidecar (PortProof itself never reads the sidecar; it exists for humans and for
`docs/content-provenance.md`, gate 6's evidence). No vendor security-platform profile (Genetec,
C-CURE, or similar) ships in v1 - see `docs/content-provenance.md` for why.

Each entry below names the profile's files, the vendor and product version the sources describe,
the group names an operator must bind with `-Set` before running it, and an example invocation.

## Active Directory / domain controller reachability

- Files: `profiles/ad-dc.csv`, `profiles/ad-dc.json`, `profiles/ad-dc.provenance.json`
- Vendor: Microsoft. Product: Windows Server Active Directory Domain Services (AD DS).
- Product version: current supported Windows Server versions; the client/DC port set has been
  stable since Windows Server 2008 R2.
- Groups to bind: `%CLIENT%` (the machine or subnet acting as a domain member/client),
  `%DC%` (the domain controller or controllers).
- Sources and retrieval dates:
  - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements - retrieved 2026-09-25
  - https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts - retrieved 2026-09-25
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd772723(v=ws.10) - archived, retrieved 2026-09-25 (the most explicit per-role matrix; the two live pages above are authoritative where they disagree)
- Covers: DNS (53/TCP, 53/UDP), Kerberos (88/TCP, 88/UDP), the RPC endpoint mapper (135/TCP -
  dynamic RPC's ephemeral high ports are *not* proven by this profile), LDAP (389/TCP, 389/UDP),
  SMB for SYSVOL/NETLOGON (445/TCP), Kerberos password change (464/TCP, 464/UDP), LDAPS (636/TCP,
  `Required: no` - not enabled without a certificate), the Global Catalog (3268/TCP, 3269/TCP,
  both `Required: no` - only present on a GC-holding DC), and W32Time/NTP client-to-DC time sync
  (123/UDP, `Required: no` - UDP).
- Example:
  ```
  PortProof.ps1 -Profile profiles\ad-dc.csv -Set "CLIENT=10.10.1.50;DC=dc01.corp.example,dc02.corp.example" -Out .\out
  ```

## SQL Server reachability

- Files: `profiles/sql-server.csv`, `profiles/sql-server.json`, `profiles/sql-server.provenance.json`
- Vendor: Microsoft. Product: SQL Server Database Engine (on Windows).
- Product version: SQL Server 2017 and later (the cited pages' moniker range).
- Groups to bind: `%CLIENT%` (the application or admin workstation), `%SQL%` (the SQL Server host).
- Sources and retrieval dates:
  - https://learn.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access - retrieved 2026-09-25
  - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-windows-firewall-for-database-engine-access - retrieved 2026-09-25
- Covers: the default-instance Database Engine (1433/TCP, `Required: yes`), the SQL Server Browser
  service used for named-instance discovery (1434/UDP, `Required: no` - UDP), the default
  instance's Dedicated Admin Connection (1434/TCP, `Required: no` - disabled remotely by default),
  Service Broker (4022/TCP, `Required: no` - no fixed default, conventional port only), and the RPC
  endpoint mapper used by Configuration Manager/WMI/MSDTC/the Transact-SQL debugger (135/TCP,
  `Required: no` - dynamic RPC not proven). Named-instance dynamic ports and Analysis
  Services/Reporting Services/Integration Services ports are out of scope for v1.
- Example:
  ```
  PortProof.ps1 -Profile profiles\sql-server.csv -Set "CLIENT=10.10.2.10;SQL=sql01.corp.example" -Out .\out
  ```

## RDP + WinRM management baseline

- Files: `profiles/rdp-winrm.csv`, `profiles/rdp-winrm.json`, `profiles/rdp-winrm.provenance.json`
- Vendor: Microsoft. Product: Remote Desktop Services (RDP) and Windows Remote Management (WinRM).
- Product version: current Windows/Windows Server; WinRM 2.0 default ports.
- Groups to bind: `%ADMIN%` (the administrator's workstation or jump host), `%SERVER%` (the
  managed server).
- Sources and retrieval dates:
  - https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/change-listening-port - retrieved 2026-09-25
  - https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management - retrieved 2026-09-25
  - https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/configure-winrm-for-https - retrieved 2026-09-25
- Covers: RDP (3389/TCP, `Required: yes`), WinRM over HTTP (5985/TCP, `Required: yes`), WinRM over
  HTTPS (5986/TCP, `Required: no` - not created by `winrm quickconfig` without an explicit
  `-transport:https` and a certificate), and the pre-2.0 compatibility listeners (80/TCP and
  443/TCP, both `Required: no` - disabled by default).
- Example:
  ```
  PortProof.ps1 -Profile profiles\rdp-winrm.csv -Set "ADMIN=10.10.3.5;SERVER=web01.corp.example" -Out .\out
  ```
