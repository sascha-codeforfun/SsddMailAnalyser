using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace SsddMailAnalyser.Core.Dns;

public enum DnsType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    TLSA = 52,
}

/// <summary>How a query ended, in the terms a mail admin thinks in.</summary>
public enum DnsStatus
{
    Ok,         // answers of the requested type
    NoData,     // the name exists, but not with this type
    NxDomain,   // the name does not exist
    ServFail,   // no answer could be obtained (broken delegation, DNSSEC failure, dead name servers)
    Refused,
    Timeout,
    Error,
}

public sealed class DnsRecord
{
    public string Name { get; init; } = "";
    public DnsType Type { get; init; }
    public uint Ttl { get; init; }

    /// <summary>A / AAAA.</summary>
    public IPAddress? Address { get; init; }

    /// <summary>CNAME, PTR, NS target, MX exchange or SOA primary name server, without the trailing dot.</summary>
    public string? Target { get; init; }

    /// <summary>MX preference.</summary>
    public ushort Preference { get; init; }

    /// <summary>TXT: the character-strings joined without separators (RFC 7208 / 6376 semantics).</summary>
    public string? Text { get; init; }

    /// <summary>TLSA: "usage selector matching data-hex".</summary>
    public string? Tlsa { get; init; }

    /// <summary>SOA serial.</summary>
    public uint Serial { get; init; }

    /// <summary>SOA minimum field: caps how long "no such record" may be cached.</summary>
    public uint SoaMinimum { get; init; }

    /// <summary>A stable text form of the record data, for comparing answers from different servers.</summary>
    public string Data => Type switch
    {
        DnsType.A or DnsType.AAAA => Address?.ToString() ?? "",
        DnsType.MX => $"{Preference} {Target}",
        DnsType.TXT => "\"" + Text + "\"",
        DnsType.TLSA => Tlsa ?? "",
        DnsType.SOA => $"{Target} serial {Serial.ToString(CultureInfo.InvariantCulture)}",
        _ => Target ?? "",
    };

    public override string ToString() => $"{Name} {Ttl} {Type} {Data}";
}

public sealed class DnsResponse
{
    public string Name { get; init; } = "";
    public DnsType Type { get; init; }
    public DnsStatus Status { get; init; }
    public string? Error { get; init; }
    public bool AuthenticData { get; init; }

    /// <summary>The query never reached a DNS service (port blocked, no route, proxy refused).
    /// Only this switches to the next resolver; SERVFAIL and NXDOMAIN are answers.</summary>
    public bool TransportFailure { get; init; }

    /// <summary>Which resolver produced the answer.</summary>
    public string Via { get; set; } = "";

    public IReadOnlyList<DnsRecord> Answers { get; init; } = Array.Empty<DnsRecord>();

    public bool IsOk => Status == DnsStatus.Ok;

    /// <summary>NXDOMAIN or NODATA: the "void lookup" of RFC 7208.</summary>
    public bool IsEmpty => Status is DnsStatus.NoData or DnsStatus.NxDomain;

    /// <summary>A failure that says nothing about the record itself.</summary>
    public bool IsTransient => Status is DnsStatus.ServFail or DnsStatus.Timeout or DnsStatus.Refused or DnsStatus.Error;

    public IEnumerable<DnsRecord> OfType(DnsType type) => Answers.Where(r => r.Type == type);

    public List<string> Texts() => OfType(DnsType.TXT).Select(r => r.Text ?? "").ToList();

    public List<IPAddress> Addresses() =>
        Answers.Where(r => r.Type is DnsType.A or DnsType.AAAA && r.Address is not null)
               .Select(r => r.Address!).ToList();

    public List<DnsRecord> Mx() => OfType(DnsType.MX).OrderBy(r => r.Preference).ThenBy(r => r.Target).ToList();

    public List<string> Targets(DnsType type) => OfType(type).Select(r => r.Target ?? "").ToList();

    /// <summary>The answer set as sorted text, for comparing two views of the same name.</summary>
    public string Fingerprint() => Status switch
    {
        DnsStatus.Ok => string.Join(" | ", OfType(Type).Select(a => a.Data).OrderBy(s => s, StringComparer.Ordinal)),
        DnsStatus.NoData => "(no record)",
        DnsStatus.NxDomain => "(name does not exist)",
        _ => "(" + Status + ")",
    };

    public string Describe() => Status switch
    {
        DnsStatus.Ok => string.Join(" | ", Answers.Where(a => a.Type == Type).Select(a => a.Data)),
        DnsStatus.NoData => "no record of this type (NODATA)",
        DnsStatus.NxDomain => "name does not exist (NXDOMAIN)",
        DnsStatus.ServFail => "SERVFAIL - no answer could be obtained" + (Error is null ? "" : ": " + Error),
        DnsStatus.Refused => "REFUSED" + (Error is null ? "" : ": " + Error),
        DnsStatus.Timeout => "no answer (timeout)" + (Error is null || Error == "timeout" ? "" : ": " + Error),
        _ => "error: " + Error,
    };
}

/// <summary>A parsed DNS message with all sections, as the iterative resolver needs them.</summary>
public sealed class DnsMessage
{
    public ushort Id { get; init; }
    public int Flags { get; init; }
    public int Size { get; init; }
    public int Rcode { get; init; }
    public bool Authoritative { get; init; }
    public bool Truncated { get; init; }
    public bool AuthenticData { get; init; }
    public List<DnsRecord> Answers { get; } = new();
    public List<DnsRecord> Authority { get; } = new();
    public List<DnsRecord> Additional { get; } = new();

    public static string RcodeName(int rcode) => rcode switch
    {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "RCODE" + rcode,
    };

    /// <summary>"NOERROR aa rd ra, 1 answer, 0 authority, 1 additional, 512 bytes"</summary>
    public string Summary()
    {
        var flags = new List<string>();
        if (Authoritative) flags.Add("aa");
        if (Truncated) flags.Add("tc");
        if ((Flags & 0x0100) != 0) flags.Add("rd");
        if ((Flags & 0x0080) != 0) flags.Add("ra");
        if (AuthenticData) flags.Add("ad");
        return $"{RcodeName(Rcode)} {string.Join(" ", flags)}, {Answers.Count} answer, {Authority.Count} authority, {Additional.Count} additional, {Size} bytes";
    }

    /// <summary>The message as dig would print it.</summary>
    public string Format(string name, DnsType type)
    {
        var sb = new StringBuilder();
        sb.Append(";; ").Append(Summary()).Append('\n');
        sb.Append(";; QUESTION: ").Append(name).Append(". IN ").Append(type).Append('\n');
        void Section(string title, List<DnsRecord> records)
        {
            if (records.Count == 0) return;
            sb.Append("\n;; ").Append(title).Append('\n');
            foreach (var r in records)
                sb.Append(r.Name.Length == 0 ? "." : r.Name + ".").Append('\t').Append(r.Ttl).Append("\tIN\t").Append(r.Type).Append('\t').Append(r.Data).Append('\n');
        }
        Section("ANSWER", Answers);
        Section("AUTHORITY", Authority);
        Section("ADDITIONAL", Additional);
        return sb.ToString();
    }

    public DnsResponse ToResponse(string name, DnsType type, string via)
    {
        var status = Rcode switch
        {
            0 => Answers.Any(a => a.Type == type) ? DnsStatus.Ok : DnsStatus.NoData,
            2 => DnsStatus.ServFail,
            3 => DnsStatus.NxDomain,
            5 => DnsStatus.Refused,
            _ => DnsStatus.Error,
        };
        return new DnsResponse
        {
            Name = name,
            Type = type,
            Status = status,
            Error = status == DnsStatus.Error ? $"RCODE {Rcode}" : null,
            AuthenticData = AuthenticData,
            Answers = Answers,
            Via = via,
        };
    }
}

/// <summary>DNS wire format (RFC 1035): building queries and parsing answers.</summary>
public static class DnsWire
{
    public static string Normalize(string name)
    {
        name = (name ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (name.Any(c => c > 127))
        {
            try { name = new IdnMapping().GetAscii(name); }
            catch (ArgumentException) { /* leave it; the query will fail visibly */ }
        }
        return name;
    }

    public static byte[] BuildQuery(ushort id, string name, DnsType type, bool recursionDesired)
    {
        var ms = new MemoryStream();
        void U16(int v) { ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)(v & 0xFF)); }

        U16(id);
        U16(recursionDesired ? 0x0100 : 0x0000);
        U16(1);         // QDCOUNT
        U16(0);         // ANCOUNT
        U16(0);         // NSCOUNT
        U16(1);         // ARCOUNT: the EDNS0 OPT record below

        if (name.Length > 0)
        {
            foreach (var label in name.Split('.'))
            {
                var bytes = Encoding.ASCII.GetBytes(label);
                if (bytes.Length == 0 || bytes.Length > 63) throw new ArgumentException($"invalid label in '{name}'");
                ms.WriteByte((byte)bytes.Length);
                ms.Write(bytes, 0, bytes.Length);
            }
        }
        ms.WriteByte(0);
        U16((ushort)type);
        U16(1);         // IN

        // EDNS0 OPT: root name, type 41, UDP payload 1232, no flags. Large TXT sets (SPF,
        // 2048-bit DKIM keys) then fit in one datagram more often.
        ms.WriteByte(0);
        U16(41);
        U16(1232);
        U16(0);
        U16(0);
        U16(0);

        return ms.ToArray();
    }

    public static DnsMessage Parse(byte[] msg)
    {
        if (msg.Length < 12) throw new FormatException("DNS message too short");
        int flags = (msg[2] << 8) | msg[3];
        var message = new DnsMessage
        {
            Id = (ushort)((msg[0] << 8) | msg[1]),
            Flags = flags,
            Size = msg.Length,
            Rcode = flags & 0x0F,
            Authoritative = (flags & 0x0400) != 0,
            Truncated = (flags & 0x0200) != 0,
            AuthenticData = (flags & 0x0020) != 0,
        };
        int qd = U16(msg, 4);
        int an = U16(msg, 6);
        int ns = U16(msg, 8);
        int ar = U16(msg, 10);

        int pos = 12;
        for (int i = 0; i < qd; i++)
        {
            ReadName(msg, ref pos);
            pos += 4;
        }
        ReadSection(msg, ref pos, an, message.Answers);
        ReadSection(msg, ref pos, ns, message.Authority);
        ReadSection(msg, ref pos, ar, message.Additional);
        return message;
    }

    private static void ReadSection(byte[] msg, ref int pos, int count, List<DnsRecord> into)
    {
        for (int i = 0; i < count; i++)
        {
            if (pos >= msg.Length) return;    // a truncated message: keep what was read
            string owner = ReadName(msg, ref pos);
            if (pos + 10 > msg.Length) return;
            var rrType = (DnsType)U16(msg, pos);
            uint ttl = (uint)((msg[pos + 4] << 24) | (msg[pos + 5] << 16) | (msg[pos + 6] << 8) | msg[pos + 7]);
            int rdLength = U16(msg, pos + 8);
            pos += 10;
            int rdStart = pos;
            if (rdStart + rdLength > msg.Length) return;

            DnsRecord? record = rrType switch
            {
                DnsType.A when rdLength == 4 =>
                    new DnsRecord { Name = owner, Type = rrType, Ttl = ttl, Address = new IPAddress(msg.AsSpan(rdStart, 4)) },
                DnsType.AAAA when rdLength == 16 =>
                    new DnsRecord { Name = owner, Type = rrType, Ttl = ttl, Address = new IPAddress(msg.AsSpan(rdStart, 16)) },
                DnsType.CNAME or DnsType.PTR or DnsType.NS =>
                    new DnsRecord { Name = owner, Type = rrType, Ttl = ttl, Target = ReadNameAt(msg, rdStart) },
                DnsType.MX =>
                    new DnsRecord { Name = owner, Type = rrType, Ttl = ttl, Preference = (ushort)U16(msg, rdStart), Target = ReadNameAt(msg, rdStart + 2) },
                DnsType.TXT =>
                    new DnsRecord { Name = owner, Type = rrType, Ttl = ttl, Text = ReadTxt(msg, rdStart, rdLength) },
                DnsType.TLSA when rdLength >= 3 =>
                    new DnsRecord
                    {
                        Name = owner, Type = rrType, Ttl = ttl,
                        Tlsa = $"{msg[rdStart]} {msg[rdStart + 1]} {msg[rdStart + 2]} " +
                               Convert.ToHexString(msg, rdStart + 3, rdLength - 3).ToLowerInvariant(),
                    },
                DnsType.SOA => ReadSoa(msg, owner, ttl, rdStart),
                _ => null,
            };
            if (record is not null) into.Add(record);
            pos = rdStart + rdLength;
        }
    }

    private static DnsRecord ReadSoa(byte[] msg, string owner, uint ttl, int rdStart)
    {
        int p = rdStart;
        var mname = ReadName(msg, ref p);
        ReadName(msg, ref p);   // rname
        uint U32(int at) => at + 4 <= msg.Length
            ? (uint)((msg[at] << 24) | (msg[at + 1] << 16) | (msg[at + 2] << 8) | msg[at + 3])
            : 0;
        uint serial = U32(p);
        uint minimum = U32(p + 16);   // serial, refresh, retry, expire, minimum
        return new DnsRecord { Name = owner, Type = DnsType.SOA, Ttl = ttl, Target = mname, Serial = serial, SoaMinimum = minimum };
    }

    private static int U16(byte[] msg, int pos) => (msg[pos] << 8) | msg[pos + 1];

    private static string ReadNameAt(byte[] msg, int pos) => ReadName(msg, ref pos);

    /// <summary>Reads a possibly compressed name; advances <paramref name="pos"/> past it.</summary>
    private static string ReadName(byte[] msg, ref int pos)
    {
        var labels = new List<string>();
        int cursor = pos;
        bool jumped = false;
        int jumps = 0;

        while (true)
        {
            if (cursor >= msg.Length) throw new FormatException("name runs past the message");
            int len = msg[cursor];
            if (len == 0)
            {
                cursor++;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= msg.Length) throw new FormatException("bad compression pointer");
                int target = ((len & 0x3F) << 8) | msg[cursor + 1];
                if (!jumped) pos = cursor + 2;
                jumped = true;
                if (++jumps > 64) throw new FormatException("compression loop");
                cursor = target;
                continue;
            }
            cursor++;
            if (cursor + len > msg.Length) throw new FormatException("label runs past the message");
            labels.Add(Encoding.ASCII.GetString(msg, cursor, len));
            cursor += len;
        }

        if (!jumped) pos = cursor;
        return string.Join(".", labels).ToLowerInvariant();
    }

    private static string ReadTxt(byte[] msg, int start, int length)
    {
        var sb = new StringBuilder();
        int pos = start;
        int end = start + length;
        while (pos < end)
        {
            int len = msg[pos++];
            if (pos + len > end) len = end - pos;
            sb.Append(Encoding.UTF8.GetString(msg, pos, len));
            pos += len;
        }
        return sb.ToString();
    }

    /// <summary>
    /// Reads a zone serial as a date when it follows one of the two common conventions:
    /// YYYYMMDDnn, or a Unix timestamp. Anything else is a plain counter and says nothing.
    /// </summary>
    public static DateTimeOffset? SerialAsDate(uint serial, out string convention)
    {
        convention = "counter";
        if (serial >= 1990010100u && serial <= 2099123199u)
        {
            var s = serial.ToString(CultureInfo.InvariantCulture);
            if (DateTime.TryParseExact(s[..8], "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d))
            {
                convention = "YYYYMMDDnn";
                return new DateTimeOffset(d, TimeSpan.Zero);
            }
        }
        if (serial >= 1_000_000_000u && serial <= 2_100_000_000u)
        {
            convention = "Unix time";
            return DateTimeOffset.FromUnixTimeSeconds(serial);
        }
        return null;
    }
}
