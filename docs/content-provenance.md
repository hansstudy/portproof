# Content provenance

This page is the fixed evidence path for the house release checklist's gate 6 (content
provenance). It records every class of third-party content PortProof ships, the terms it was used
under, and how it is used. PortProof ships exactly one class of third-party content: the port and
protocol facts in its three bundled profiles.

## The provenance rule

Binding on every profile in this repository, present or future:

> A profile row may be authored **only** from public, non-authenticated vendor documentation. The
> source URL and the retrieval date are recorded in the profile's sidecar
> (`profiles/<name>.provenance.json`) and in `docs/profiles/catalogue.md`, at authoring time.
> Partner-portal copies, licensed documentation, NDA material, and internal customer deployment
> documents are prohibited sources - including where the same fact is also published publicly -
> because provenance cannot be reconstructed after the fact from a copy alone.

A profile row is a set of **facts** (a port number, a protocol, whether a service is enabled by
default): the port tables and matrices on the cited pages are not reproduced. Where a page's own
table happens to be the clearest way to hold those facts, PortProof's profile still only stores
the port/protocol/required/notes tuple in its own schema (`docs/profiles/schema.md`), transcribed
and re-verified against the live page at authoring time - it does not copy the source page's table
markup, prose, or formatting.

## Third-party source class: Microsoft Learn documentation

**What it is.** Public pages under `learn.microsoft.com` (including its `previous-versions` and
`troubleshoot` archives), reachable without any sign-in, subscription, or partner-portal
credential.

**Terms of use.** Microsoft Learn content is published under Microsoft's standard documentation
terms (see the site's own "Trademarks" and content-licensing footer, linked from every page under
`learn.microsoft.com`). PortProof does not redistribute Microsoft's page text, markup, or
diagrams: it transcribes discrete port/protocol facts (a number, a transport, a default-enabled
state) into its own data schema, each fact traceable to the page and date it was read from. This
is fact extraction, not content redistribution, and is the basis on which the rule above permits
it.

**How it is used.** Every row of `profiles/ad-dc.{csv,json}`, `profiles/sql-server.{csv,json}`,
and `profiles/rdp-winrm.{csv,json}` maps to at least one Microsoft Learn source URL, recorded with
its retrieval date in that profile's `*.provenance.json` sidecar and summarised in
`docs/profiles/catalogue.md`. The tool itself never reads a sidecar; the sidecar and this page
exist for the operator, for the release checklist, and for anyone auditing where a bundled fact
came from. The sources, by profile:

| Profile | Sources |
|---|---|
| `ad-dc` | `troubleshoot/windows-server/networking/service-overview-and-network-port-requirements`; `troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts`; `previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd772723(v=ws.10)` (archived, corroborating) |
| `sql-server` | `sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access`; `sql/database-engine/configure-windows/configure-a-windows-firewall-for-database-engine-access` |
| `rdp-winrm` | `windows-server/remote/remote-desktop-services/remotepc/change-listening-port`; `windows/win32/winrm/installation-and-configuration-for-windows-remote-management`; `troubleshoot/windows-client/system-management-components/configure-winrm-for-https` |

Full URLs and per-row citations are in each profile's `*.provenance.json` sidecar and in
`docs/profiles/catalogue.md`; they are not repeated in full here to keep this page as the single
narrative record rather than a second copy of the sidecar data.

## No security-platform profile ships

The breakdown that motivated this tool also named a fourth profile family - security-platform port
tables from vendors such as Genetec (Security Center) and C-CURE. Those vendors do publish port
tables as public documentation pages, so public reachability is **not** the blocker. Two separate
questions must both be answered "yes" before such a profile could ship, and neither has been:

1. Does redistributing a machine-readable derivative of that table breach the vendor's partner
   agreement or the documentation site's terms of use?
2. Was the content taken from the public page itself, or from a partner-portal copy of the same
   table? The second is prohibited regardless of the answer to the first, and is unverifiable
   after the fact - which is exactly why the provenance rule above requires the URL and retrieval
   date to be recorded at authoring time rather than reconstructed later.

This is conditional on a separate, unresolved question about the redistribution terms for that
vendor content. **PortProof v1 therefore ships no Genetec, C-CURE, or other security-platform profile**
- only the three Microsoft-documented profiles above. `profiles/` is a versioned data directory
precisely so a vendor profile can be added later, under the same provenance rule, as a data-only
change requiring no code release.

## Why the tool itself carries no other third-party content

PortProof's source (`src/`), tests, and build tooling contain no vendored third-party code,
fonts, images, or generated text. The only external facts embedded anywhere in the repository are
the profile rows described above.
