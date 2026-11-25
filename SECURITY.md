# Security

SsddMailAnalyser reads text that somebody else wrote (mail headers, bounces, mail files)
and talks to servers its user does not control. This page says how to report a problem,
which precautions the code takes, and where they end.

## Reporting a problem

Use GitHub's private vulnerability reporting: on the repository page, open the **Security**
tab and choose **Report a vulnerability**. Please do not open a public issue for a security
problem.

Fixes are made for the latest release only. Say which version you used (it is written into
the HTML and JSON exports) and, if you can, attach the input that triggers the problem with
private details removed.

## What the app touches on the machine

The README section "Before you build or run it" is the declaration of what the code does
on the machine it runs on. It is not repeated here. In short: no installation, no
administrator rights, no registry access, and no program started except your browser when
you press "Open page". Two kinds of file are written: the export you save, and
`SsddMailAnalyser.json` next to the exe when you save settings.

## Untrusted input

Everything pasted or loaded is treated as data from a stranger.

- **Size.** A file larger than 60 MB is not loaded. A bounce line longer than 1,000
  characters is cut at that length before it is scanned.
- **Mail files.** `.eml` and Outlook `.msg` files are read by the app's own parsers; no
  attachment is opened, extracted or run. The `.msg` reader refuses a file whose sector
  table loops or is larger than the file.
- **Names.** A sender, envelope, receiver or DKIM name that contains anything but
  domain-name characters (letters, digits, hyphen, underscore, dots) is not looked up and
  not connected to. It is listed in a finding instead. Names put into a link are escaped.
- **Output.** Everything written to an HTML report is escaped, and the report loads
  nothing from the network. CSV fields that a spreadsheet would run as a formula (leading
  `=`, `+`, `-`, `@`, tab or carriage return) are neutralised.
- **Instructions in evidence.** Nothing in the evidence can start an action. The checks
  that run are the ones ticked on the Checks page.

## Network behaviour

- **No mail is ever sent.** The SMTP probe reads the greeting, says EHLO, upgrades with
  STARTTLS, says EHLO again and quits. It never sends MAIL FROM.
- **What the probe reveals.** EHLO announces this machine's public IP as an address
  literal, which the server sees anyway, and never the computer's name.
- **Limits on a session.** A reply line is read up to 4,096 bytes and a reply up to 100
  lines. Each read waits 10 seconds at most and a whole session 45 seconds at most. Cancel
  ends a session at once.
- **Private addresses.** When the analysis runs from outside the site's network, a mail
  server that resolves only to private addresses is not connected to.
- **Certificates.** DNS over HTTPS and the MTA-STS fetch validate certificates the normal
  way. The STARTTLS probe accepts any certificate on purpose: its job is to report an
  expired, mismatched or untrusted certificate, and nothing is sent over that connection
  afterwards.
- **MTA-STS.** The policy is fetched only from `https://mta-sts.<domain>/.well-known/mta-sts.txt`,
  redirects are not followed (RFC 8461), and at most 64 KB are read.
- **DNS answers are checked before they are believed.** Before any check, the resolver in
  use must find a name that always exists and must not find one that cannot. A network
  that answers port 53 itself, a resolver that finds nothing, or one that turns "no such
  name" into an address is left for the next resolver and reported. If no resolver gives
  usable answers, failed lookups are reported as inconclusive for this machine, never as a
  fault of the domain.
- **Blocklists.** A list's answers are used only alongside its own test entries
  (RFC 5782). If no list passes, the result is inconclusive, not "not listed".

## The settings file

`SsddMailAnalyser.json` holds the domains you entered as your own, in plain text, and one
display option. It is read at start and written only on "Save" in Settings or "Add ... to
my domains". Every entry is checked with the same name rule as pasted evidence when the
file is read; a damaged file is ignored. The list never enters an export, but it travels
with the folder: copying the app's folder to someone else hands them the list.

## What leaves the machine in an export

- The computer's name is not written to the trace or to any export.
- HTML and JSON exports ask whether to include the evidence. Left out, the raw text, the
  subject lines and the recipient lists are dropped. The addresses, server names and IPs
  that the findings and the trace are about stay.
- The report for the sender contains no pasted evidence and no trace. The site's DNS
  servers and every non-public address are replaced by a placeholder.

The README section "Who learns which names you check" lists the outside parties that see
a queried name.

## Known limits

- **DNS is not authenticated.** DNSSEC is not validated. Someone on the network path
  between this machine and a name server can supply false records, and the findings would
  be built on them. DNS over HTTPS protects the path to the resolver, not the resolver's
  own answers.
- **The MTA-STS fetch is not restricted to public addresses**, because behind a proxy the
  connection goes to the proxy. The certificate check limits what an internal host could
  return.
- **Inside-the-network mode connects to whatever the site's DNS names**, private addresses
  included. That is its purpose.
- **Organisational domains are approximated** from a built-in list of two-label suffixes,
  not the full Public Suffix List. The report says so where it matters.
- **The exe is not code-signed** unless the publisher signs it, and as a single-file app it
  unpacks itself into the user's temporary folder at start. Get it from the project's
  release page only.
- **Testing, not proof.** The parsers were tested with malformed and oversized input and
  the SPF evaluator against RFC 7208 cases. The code has not had an independent security
  audit.
