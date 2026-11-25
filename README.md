# SsddMailAnalyser

**S**uspicious **S**PF, **D**KIM, **D**MARC: guided diagnosis of mail that stopped arriving.

A WPF tool for technicians. It walks through four steps:

1. **What broke**: incoming (an external sender's mail no longer reaches the recipient here) or
   outgoing (mail from here no longer reaches an external recipient); and where the analysis
   runs: on an isolated system (public view only) or inside the supported site's network.
   Optional statement: the supported side handles other mail normally; gaps on the external
   party's side are then ranked as the likely cause.
2. **Evidence**: headers of a mail that worked, headers of a failing mail, the bounce.
   Pasted text, .eml, .txt or Outlook .msg files. Each kind of evidence has its own tab; a
   filled tab shows a check mark.
   Optional **record history** tab: one row per archive page that matters (all records of the
   sender domain, SPF, DMARC, DMARC of the parent domain, each DKIM selector of the evidence).
   Each row opens its page on dnshistory.org in the browser, takes the copied page by Paste,
   checks that the page is for the row's name, and shows the record's state on the date of the
   working mail. A history page lists only values that are no longer published ("No historical
   ... records" means unchanged or never published); the current value and the archive's dates
   are on the name's overview page, so record rows also offer Open overview and hold both
   pages. A record the archive saw gone and that live DNS still does not find counts as most
   likely absent at the working mail's date, which weighs less than proof from the archive
   alone. The app never fetches from the archive itself.
3. **Checks**: domains, sending IP and DKIM selectors suggested from the evidence, editable.
   The DMARC record and the DKIM key at the time of the working mail can be stated
   (existed / did not exist) when known; otherwise they come from the headers or the pasted history.
4. **Diagnosis**: the likely cause, who fixes it, the next step, a working / failing / now
   table (cells that differ from the working mail are marked amber, with the difference in
   words) and every finding. A **Technical trace** tab lists every action with its timing and
   the full response: each DNS exchange dig-style (server, transport, flags, all sections, the
   referral walk from the root), each SMTP command and reply, the TLS handshake and certificate
   chain, HTTP fetches, the SPF evaluation path and how the evidence was parsed. Each finding
   links to its trace entries.
   **Export**:
   - HTML report for the sender: sending-side findings only, each with what to change and the
     record to publish. No internal details of the recipient: the site's DNS servers and any
     non-public address in its DNS trace are replaced by placeholders; in the internal mode the
     DNS section says it shows the site's view.
   - Full HTML report: self-contained, opens in any browser, prints black on white.
   - JSON: findings, comparison, records, full trace, optional raw evidence.
   - HTML and JSON ask whether to include the evidence. Left out, the raw text, the subject
     lines and the recipient lists are dropped; the addresses, server names and IPs that the
     findings and the trace are about stay.
   - CSV of findings or of the trace (semicolon, UTF-8 BOM, for Excel).
   - Text report.

Live checks: SPF (full RFC 7208 evaluation, 10-lookup count), DKIM keys, DMARC policy and
alignment, reverse DNS, blocklists (curated and tiered: major, minor, neighbourhood such as
UCEPROTECT Level 2/3, and domain lists; every list self-tested per RFC 5782 before its
answers are used; sending IPs, the sender's MX hosts, From, Return-Path and DKIM domains),
MX, MTA-STS, DANE presence, and an SMTP/STARTTLS probe (EHLO and STARTTLS only, never a
message). Before attributing a failed probe to the recipient, a
reachability test connects to Google's and Microsoft's MX on 25 and their submission port 587,
takes a 443 timing baseline to the target, and finds this machine's public IP via DNS
(with its blocklist status): open, blocked here, rejected here, or 25-only block.

DNS, built in (no packages): authoritative mode resolves from the root and asks every
name server of a zone (catches servers that disagree); a chosen recursive server; or DNS over
HTTPS. If port 53 is blocked, it falls back to DNS over HTTPS through the system proxy.
Before any check, the resolver in use is probed: it must find a name that always exists and
must not find one that cannot. A network that answers port 53 itself (a root server
"answering" like a recursive resolver), a resolver that finds nothing, or one that rewrites
"no such name" into an address is left for the next resolver in the chain and reported under
"DNS path". If no resolver gives usable answers, failed lookups are reported as inconclusive
for this machine, never as a fault of the domain.
Inside the supported site's network, its internal DNS is compared with the public view. Zone
SOA serials are read as change dates where they follow the YYYYMMDDnn or Unix-time convention.
TTLs of the key records are reported as "changes visible everywhere within X" (negative TTL
for records that do not exist yet).

Ranking: a change after the working mail (a record removed, a new or expiring listing) ranks
above a gap that already existed while mail still arrived. A missing DMARC record alone rarely
stops mail; it weighs in when other signals are bad.

No third-party packages. Theme: HueTheme (Teal family) in `Theme/`, busy overlay in `BusyOverlay/`.

## Before you build or run it

- **Talks to other computers:** connects to gmail.com, gmail-smtp-in.l.google.com, outlook.com, outlook-com.olc.protection.outlook.com, smtp.gmail.com and smtp.office365.com and others.
- **Reads or sends personal data:** reads the clipboard.

## Who learns which names you check

Every DNS question carries the domain, selector or
IP being checked. Depending on the resolver chosen it goes to the root, top-level and the
domains' own name servers, to this computer's DNS server, or over HTTPS to Cloudflare
(cloudflare-dns.com), Google (dns.google) or Quad9 (dns.quad9.net). With blocklists on,
the sending IPs and domains are asked of the list operators (Spamhaus, Barracuda, SpamCop,
Mailspike, PSBL, UCEPROTECT, DroneBL, blocklist.de, GBUdb, SURBL, URIBL). The
reachability test learns this machine's public IP by asking Google's and Akamai's name
servers. The SMTP probe connects to the recipient domain's mail servers and announces
itself with this machine's public IP (`EHLO [203.0.113.7]`), never with the computer's
name; a session ends after 45 seconds at most. From outside the site's network, a mail
server that resolves only to private addresses is not connected to. The computer's name
is not written to the trace or to any export. Target names that are not made of
domain-name characters are not looked up at all. The MTA-STS
check fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt` (no redirects followed,
64 KB at most). The DNS over HTTPS fallback, the blocklists, the SMTP probe and the
MTA-STS fetch each have a switch on the Checks page. Nothing is sent anywhere else, and
no message is ever sent.

## Reverse direction

After a run, "Check reverse direction" on the Diagnosis page swaps the two domains and
checks mail going the other way, with the same settings and from the same network position.
It is a health check without evidence: the sender domain's SPF and DMARC records, name
servers and domain blocklists, and the receiver's MX, MTA-STS and mail servers. It cannot
say whether a particular sending server passes SPF, and it checks no reverse DNS, IP
blocklist or DKIM key, because no mail of that direction was given. The diagnosis of the
case is kept; "Showing" switches between the two, and the header pills, Copy report and
Export follow the one on screen.

## Settings

The app keeps one file, `SsddMailAnalyser.json`, in the folder the exe is in, and writes it
only when you save settings or press "Add ... to my domains":

```json
{
  "domains": [ "example.com", "example.org" ],
  "busyAlwaysTurn": true
}
```

- `domains`: the mail domains you look after. On the first step, "My domain" lists them;
  picking one fills in the side that is yours (the recipient for incoming mail, the sender
  for outgoing), so only the other party's address has to be typed. Edit the list under
  Settings (the gear in the header) or in the file.
- `busyAlwaysTurn`: the busy rings turn even where Windows has animation off (remote
  sessions, virtual machines).

A missing or damaged file is ignored, and entries that are not domain names are skipped. If
the folder cannot be written, the settings last until the app is closed. Deleting the file
resets everything; nothing is stored anywhere else.

## Security

How to report a problem, the precautions the code takes with untrusted input and on the
network, and where they end: see [SECURITY.md](SECURITY.md).

## Build

```
dotnet publish SsddMailAnalyser.csproj -c Release
```

Produces one self-contained `SsddMailAnalyser.exe` (win-x64) in `bin/Release/net10.0-windows/win-x64/publish/`.
The same command works on a Linux or macOS build machine (`EnableWindowsTargeting` is set in the project).

## Layout

```
App.xaml(.cs), MainWindow.xaml(.cs)   the wizard
MainWindow.History.cs               the record-history tab
SettingsWindow.xaml(.cs)            the settings dialog
Core/Trace.cs     technical trace entries
Core/Dns/         wire format, resolvers (recursive, DoH, iterative), DNS client with fallback, record-history parser
Core/Mail/        header parser, Authentication-Results, MIME, .msg reader, bounce parser, status codes
Core/Checks/      SPF evaluator, DKIM/DMARC/PTR/blocklists, MX/MTA-STS/SMTP probe, reachability
Core/AppSettings  the settings file next to the exe: my domains, busy animation
Core/Diagnosis/   case model, target suggestion, rules and ranking, text/HTML reports, JSON/CSV export
Theme/            HueTheme kit 1.1.5, as supplied
BusyOverlay/      BusyOverlayKit (HueTheme kit 1.1.5), as supplied
```
