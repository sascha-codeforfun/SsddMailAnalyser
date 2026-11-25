using System;
using System.Collections.Generic;
using System.Linq;

namespace SsddMailAnalyser.Core.Mail;

public enum NdrCategory
{
    Authentication,   // SPF / DKIM / DMARC / compauth
    Reputation,       // blocklists, IP/tenant reputation, spam verdicts
    ReverseDns,
    Recipient,        // unknown user, mailbox full, disabled
    Routing,          // no MX, no route, loops, connector problems
    Transport,        // TLS, timeouts, refused connections
    Policy,           // relay denied, size limits, group restrictions, rate limits
    Unknown,
}

public sealed record NdrMeaning(
    string Code,
    NdrCategory Category,
    string Title,
    string Meaning,
    string WhoFixes,
    string NextStep);

/// <summary>
/// The enhanced status codes (RFC 3463) and vendor-specific ones that appear in bounces
/// from Exchange Online, Gmail, Postfix and the usual gateways, mapped to what to do next.
/// </summary>
public static class NdrKnowledge
{
    private static readonly Dictionary<string, NdrMeaning> Codes = new(StringComparer.OrdinalIgnoreCase);

    private static void Add(string code, NdrCategory cat, string title, string meaning, string who, string next) =>
        Codes[code] = new NdrMeaning(code, cat, title, meaning, who, next);

    static NdrKnowledge()
    {
        // ---- authentication
        Add("5.7.26", NdrCategory.Authentication, "Rejected for failing DMARC",
            "The receiver checked SPF and DKIM against the From domain; neither passed in alignment, and the From domain's DMARC policy says reject. Gmail also uses 5.7.26 for mail that is not authenticated at all.",
            "Sender's domain admin",
            "Find out which leg should carry DMARC (see 'Then vs now') and fix that: SPF include for the sending service, or DKIM signing with the From domain.");
        Add("5.7.509", NdrCategory.Authentication, "Exchange Online: rejected by the sender domain's DMARC policy",
            "Microsoft 365 evaluated DMARC for the From domain, it failed, and the policy is p=reject.",
            "Sender's domain admin",
            "Check SPF for the sending IP and the DKIM selector; one of them must pass and align with the From domain.");
        Add("5.7.23", NdrCategory.Authentication, "Rejected for failing SPF",
            "The sending IP is not authorised by the envelope sender's SPF record and the receiver rejects on SPF fail (-all).",
            "Sender's domain admin",
            "Add the sending service to the SPF record, or make sure mail leaves through an authorised server.");
        Add("5.7.27", NdrCategory.Authentication, "Gmail: SPF failed",
            "Gmail rejected because SPF failed for the envelope sender.",
            "Sender's domain admin",
            "Authorise the sending IP in SPF; check the 10-lookup limit.");
        Add("5.7.30", NdrCategory.Authentication, "Gmail: DKIM required",
            "Gmail requires a valid DKIM signature from this sender (bulk sender rules).",
            "Sender's domain admin",
            "Sign outgoing mail with DKIM for the From domain and publish the selector key.");
        Add("5.7.515", NdrCategory.Authentication, "Outlook.com: sender authentication requirements not met",
            "Outlook.com / Hotmail rejects high-volume senders that do not pass SPF, DKIM and DMARC.",
            "Sender's domain admin",
            "Publish SPF, sign with DKIM, and publish a DMARC record (p=none at least) aligned with the From domain.");
        Add("5.7.135", NdrCategory.Authentication, "Exchange Online: composite authentication failed",
            "Microsoft's composite authentication (compauth) failed, so the message is treated as spoofed.",
            "Sender's domain admin",
            "Fix SPF/DKIM for the From domain; for forwarded mail ask the forwarder to use ARC or SRS.");

        // ---- reverse DNS
        Add("5.7.25", NdrCategory.ReverseDns, "Rejected: no valid reverse DNS (PTR)",
            "The sending IP has no PTR record, or the PTR name does not resolve back to the IP.",
            "Owner of the sending IP (sender's provider)",
            "Ask the provider of the sending IP to set a PTR that resolves forward to the same IP.");

        // ---- reputation
        Add("5.7.1", NdrCategory.Policy, "Delivery not authorised / message refused",
            "A generic refusal. The text around the code says why: blocklist, spam verdict, sender not allowed, relay denied or DMARC.",
            "Depends on the text",
            "Read the diagnostic text; the app's keyword matches below narrow it down.");
        Add("5.7.606", NdrCategory.Reputation, "Exchange Online: sending IP is banned",
            "Microsoft has banned the sending IP (5.7.606 to 5.7.649 are IP or tenant blocks).",
            "Owner of the sending IP",
            "Delist via sender.office.com (Microsoft's delisting portal) and find the cause of the poor reputation.");
        Add("5.7.705", NdrCategory.Reputation, "Exchange Online: tenant exceeded threshold",
            "The sending Microsoft 365 tenant was blocked for sending too much spam or bulk mail.",
            "Sender's Microsoft 365 admin",
            "Check the tenant for compromised accounts; Microsoft support has to lift the block.");
        Add("5.7.708", NdrCategory.Reputation, "Exchange Online: traffic not accepted from this IP",
            "The sending IP has a poor reputation at Microsoft, often a new or shared tenant IP.",
            "Sender's Microsoft 365 admin",
            "Send through a connector with a dedicated IP or ask Microsoft support.");
        Add("5.7.750", NdrCategory.Reputation, "Exchange Online: unregistered domain",
            "The sending tenant sends from a domain it has not verified.",
            "Sender's Microsoft 365 admin",
            "Add and verify the domain in the tenant.");
        Add("5.7.511", NdrCategory.Reputation, "Exchange Online: banned sender",
            "The sending address or IP was banned by Microsoft.",
            "Sender's admin",
            "Use the delisting portal; Microsoft support for persistent blocks.");
        Add("5.7.512", NdrCategory.Reputation, "Outlook.com: message content rejected",
            "Outlook.com rejected the message content as spam.",
            "Sender",
            "Check content, links and the sending IP's reputation.");
        Add("5.7.350", NdrCategory.Reputation, "Remote server rejected after a filter verdict",
            "A downstream server rejected a message that Microsoft relayed or forwarded.",
            "Recipient's admin",
            "Check the receiving system's logs for the reason.");
        Add("5.7.28", NdrCategory.Reputation, "Gmail: unusual rate of unsolicited mail",
            "Gmail sees unsolicited mail from this IP or domain at a high rate.",
            "Sender",
            "Check Postmaster Tools; reduce volume, remove purchased lists, authenticate fully.");
        Add("4.7.28", NdrCategory.Reputation, "Gmail: rate limited for unsolicited mail (temporary)",
            "Gmail is deferring mail from this IP or domain because of its spam rate.",
            "Sender",
            "Lower volume, authenticate fully, and let the queue retry.");
        Add("5.7.0", NdrCategory.Policy, "Security or policy failure",
            "Generic security status. Common reasons: TLS required but not offered, authentication required, or a policy block.",
            "Depends on the text",
            "Read the diagnostic text; check STARTTLS and connectors.");

        // ---- transport / TLS
        Add("5.7.10", NdrCategory.Transport, "Encryption required",
            "The receiving side requires TLS and the session was not encrypted.",
            "Sending server's admin",
            "Enable STARTTLS on the sending side, or fix the certificate the receiver rejects.");
        Add("4.4.7", NdrCategory.Transport, "Message expired in the queue",
            "The sending server tried repeatedly and gave up. The real reason is in the retry log: unreachable MX, temporary rejections, TLS failures.",
            "Sending server's admin",
            "Look at the last error in the queue log; check the recipient MX with the SMTP probe.");
        Add("5.4.7", NdrCategory.Transport, "Delivery time expired",
            "The message stayed in a queue too long.",
            "Sending server's admin",
            "Check the queue's last error, MX reachability and TLS.");
        Add("4.4.1", NdrCategory.Transport, "No answer from host",
            "The recipient's mail server did not respond (connection timeout).",
            "Recipient's admin, or the sender's network",
            "Probe the MX on port 25; check firewalls on both sides.");
        Add("4.4.2", NdrCategory.Transport, "Connection dropped",
            "The connection was lost during the session, often in the TLS handshake.",
            "Either side",
            "Probe the MX; compare TLS versions and ciphers.");
        Add("5.4.316", NdrCategory.Transport, "Exchange Online: connection refused",
            "Exchange could not connect to the destination server.",
            "Recipient's admin",
            "Check the recipient MX, firewall and port 25.");
        Add("4.4.316", NdrCategory.Transport, "Exchange Online: connection refused (retrying)",
            "Exchange could not connect to the destination server and keeps retrying.",
            "Recipient's admin",
            "Check the recipient MX, firewall and port 25.");
        Add("5.4.300", NdrCategory.Transport, "Exchange Online: message expired",
            "Exchange tried for the retry period and gave up.",
            "Sending server's admin",
            "Check the message trace for the last retry error.");

        // ---- routing
        Add("5.4.4", NdrCategory.Routing, "Unable to route: no MX or A record",
            "The recipient domain has no usable MX (or the lookup failed).",
            "Recipient's domain admin",
            "Check the recipient domain's MX records.");
        Add("5.4.1", NdrCategory.Routing, "Recipient address rejected (access denied)",
            "Exchange Online: the recipient domain is hosted in Microsoft 365 but the address does not exist there (directory-based edge blocking), or the domain's MX points to Microsoft without the domain being accepted.",
            "Recipient's admin",
            "Check that the address exists and the domain is an accepted domain in the recipient's tenant.");
        Add("5.4.6", NdrCategory.Routing, "Routing loop detected",
            "The message bounced between servers; usually a forwarding rule or connector misconfiguration.",
            "Recipient's admin",
            "Check forwarding rules and connectors.");
        Add("5.4.14", NdrCategory.Routing, "Hop count exceeded",
            "A mail loop, usually forwarding between two systems.",
            "Recipient's admin",
            "Check forwarding and connectors.");
        Add("5.1.8", NdrCategory.Routing, "Sender address rejected",
            "The receiver rejected the sender address, often because the sender's domain does not resolve, or the sender is blocked.",
            "Sender's domain admin",
            "Check that the sender domain has MX/A records; check the receiver's block lists.");
        Add("5.1.0", NdrCategory.Routing, "Sender denied",
            "The sender address is not allowed (blocked sender, or the domain fails a check).",
            "Recipient's admin",
            "Check the recipient's block lists and transport rules.");
        Add("5.7.57", NdrCategory.Policy, "Client not authenticated to send",
            "A device or app used SMTP AUTH submission without authenticating.",
            "Sender's admin",
            "Fix the device's SMTP AUTH settings.");
        Add("5.7.64", NdrCategory.Policy, "Exchange Online: tenant attribution failed",
            "The relay connector could not attribute the message to the tenant.",
            "Sender's Microsoft 365 admin",
            "Check the inbound connector certificate or IP.");
        Add("5.7.54", NdrCategory.Policy, "Unable to relay",
            "The server refused to relay to this recipient.",
            "The admin of the rejecting server",
            "Check that the recipient domain is accepted or the sender is allowed to relay.");
        Add("5.7.124", NdrCategory.Policy, "Sender not allowed to send to this group",
            "Delivery restrictions on the distribution group.",
            "Recipient's admin",
            "Allow the sender on the group or send to members directly.");
        Add("5.7.133", NdrCategory.Policy, "Sender not allowed to send to this group (external senders blocked)",
            "The group does not accept mail from outside the organisation.",
            "Recipient's admin",
            "Allow external senders on the group.");
        Add("5.7.13", NdrCategory.Recipient, "Recipient account disabled",
            "The recipient's mailbox or account is disabled.",
            "Recipient's admin",
            "Confirm the recipient is still active.");

        // ---- recipient
        Add("5.1.1", NdrCategory.Recipient, "Recipient address does not exist",
            "The receiving server does not know this mailbox.",
            "Recipient's admin, or the sender's address book",
            "Check the spelling; a cached autocomplete entry in Outlook is a common cause.");
        Add("5.1.10", NdrCategory.Recipient, "Exchange Online: recipient not found",
            "The recipient address was not found in the destination tenant.",
            "Recipient's admin",
            "Check the address; check SMTP proxy addresses in the tenant.");
        Add("5.2.2", NdrCategory.Recipient, "Mailbox full",
            "The recipient's mailbox is over its quota.",
            "Recipient",
            "The recipient has to free space.");
        Add("4.2.2", NdrCategory.Recipient, "Mailbox full (temporary)",
            "The recipient's mailbox is over its quota; the sender will retry.",
            "Recipient",
            "The recipient has to free space.");
        Add("5.2.1", NdrCategory.Recipient, "Mailbox disabled or not accepting mail",
            "The mailbox exists but is disabled.",
            "Recipient's admin",
            "Confirm the recipient is still active.");
        Add("5.2.3", NdrCategory.Policy, "Message too large for the recipient",
            "The message exceeds the recipient's size limit.",
            "Sender",
            "Send smaller attachments or a link.");
        Add("5.3.4", NdrCategory.Policy, "Message too big for the system",
            "The message exceeds a server's size limit.",
            "Sender",
            "Send smaller attachments or a link.");

        // ---- temporary
        Add("4.7.0", NdrCategory.Policy, "Temporary security or policy refusal",
            "Common causes: greylisting, rate limits, a temporary reputation hold, TLS negotiation failure.",
            "Usually nobody - wait",
            "If it persists past a few hours, check the diagnostic text and the sending IP's reputation.");
        Add("4.7.1", NdrCategory.Policy, "Temporary refusal",
            "Greylisting, rate limiting or a temporary policy hold.",
            "Usually nobody - wait",
            "If it persists, check the diagnostic text.");
        Add("4.7.26", NdrCategory.Authentication, "Gmail: temporarily rejected for missing authentication",
            "Gmail defers unauthenticated mail before rejecting it.",
            "Sender's domain admin",
            "Fix SPF or DKIM now; the next step is a permanent rejection.");
        Add("4.7.500", NdrCategory.Reputation, "Exchange Online: throttled (server busy)",
            "Microsoft is throttling the sending IP; often new IPs or volume spikes.",
            "Sender",
            "Let it retry; reduce volume.");
        Add("4.4.3", NdrCategory.Routing, "Temporary DNS failure",
            "The sending server could not resolve the destination.",
            "Sending server's admin, or the recipient's DNS",
            "Check the recipient domain's DNS for SERVFAIL (DNSSEC, broken delegation).");
        Add("4.3.2", NdrCategory.Transport, "System not accepting messages",
            "The receiving server is in maintenance or overloaded.",
            "Recipient's admin",
            "Let it retry.");
        Add("4.2.1", NdrCategory.Recipient, "Mailbox temporarily unavailable",
            "The mailbox is temporarily not accepting mail.",
            "Recipient's admin",
            "Let it retry.");
    }

    public static NdrMeaning? Lookup(string code)
    {
        if (Codes.TryGetValue(code, out var m)) return m;
        // Exchange Online 5.7.606-649: banned IPs and tenants.
        var parts = code.Split('.');
        if (parts.Length == 3 && parts[1] == "7" && int.TryParse(parts[2], out var n) && n >= 600 && n <= 649)
            return Codes["5.7.606"] with { Code = code };
        return null;
    }

    /// <summary>Keyword hints in the diagnostic text, independent of the code.</summary>
    public static readonly (string[] Keys, NdrCategory Category, string Hint)[] Keywords =
    {
        (new[] { "dmarc" }, NdrCategory.Authentication, "The rejection text mentions DMARC."),
        (new[] { "spf", "sender policy framework", "not designate", "designates" }, NdrCategory.Authentication, "The rejection text mentions SPF."),
        (new[] { "dkim", "domainkeys" }, NdrCategory.Authentication, "The rejection text mentions DKIM."),
        (new[] { "unauthenticated", "authentication required", "not authenticated" }, NdrCategory.Authentication, "The receiver says the mail was not authenticated."),
        (new[] { "spamhaus" }, NdrCategory.Reputation, "The sending IP or a domain is listed by Spamhaus."),
        (new[] { "spamcop" }, NdrCategory.Reputation, "The sending IP is listed by SpamCop."),
        (new[] { "barracuda" }, NdrCategory.Reputation, "The sending IP is listed by Barracuda."),
        (new[] { "nixspam", "manitu" }, NdrCategory.Reputation, "The sending IP is listed by NiX Spam."),
        (new[] { "blocklist", "blacklist", "block list", "black list", "rbl", "dnsbl", "listed at", "listed in", "listed by" }, NdrCategory.Reputation, "The rejection text mentions a blocklist."),
        (new[] { "reputation", "poor reputation", "banned", "block list" }, NdrCategory.Reputation, "The rejection text mentions reputation."),
        (new[] { "reverse dns", "ptr record", "reverse lookup", "rdns", "no ptr" }, NdrCategory.ReverseDns, "The rejection text mentions reverse DNS."),
        (new[] { "starttls", "tls required", "must issue a starttls", "encryption required", "certificate" }, NdrCategory.Transport, "The rejection text mentions TLS."),
        (new[] { "spam", "unsolicited", "junk", "content rejected", "message content" }, NdrCategory.Reputation, "The receiver classified the mail as spam."),
        (new[] { "user unknown", "does not exist", "no such user", "unknown recipient", "recipient not found", "address rejected", "mailbox unavailable", "invalid recipient", "unbekannt", "existiert nicht" }, NdrCategory.Recipient, "The recipient address is not known to the receiving server."),
        (new[] { "mailbox full", "quota", "over quota", "postfach voll", "postfach ist voll" }, NdrCategory.Recipient, "The recipient's mailbox is full."),
        (new[] { "relay", "relaying denied", "relay access denied" }, NdrCategory.Policy, "A server refused to relay."),
        (new[] { "too many", "rate limit", "rate-limit", "throttl" }, NdrCategory.Policy, "The receiver is rate limiting."),
        (new[] { "greylist", "graylist", "try again later" }, NdrCategory.Policy, "Greylisting: temporary, should resolve on retry."),
        (new[] { "message size", "too large", "exceeds the maximum", "size limit", "zu groß" }, NdrCategory.Policy, "Size limit."),
        (new[] { "timed out", "timeout", "connection refused", "could not connect", "unreachable", "no route" }, NdrCategory.Transport, "The sending server could not reach the recipient server."),
    };
}
