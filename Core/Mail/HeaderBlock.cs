using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SsddMailAnalyser.Core.Mail;

public sealed record HeaderField(string Name, string Value, int Index);

/// <summary>
/// An ordered list of header fields, newest (topmost) first, as pasted from Outlook's
/// "Internetkopfzeilen" / "Internet headers", from an .eml file or from an NDR.
/// </summary>
public sealed class HeaderBlock
{
    private static readonly Regex FieldStart = new(@"^([A-Za-z0-9][A-Za-z0-9\-_.]*)[ \t]*:(.*)$", RegexOptions.Compiled);

    public List<HeaderField> Fields { get; } = new();

    /// <summary>Text after the header block (an .eml body), if any.</summary>
    public string Body { get; private set; } = "";

    public bool IsEmpty => Fields.Count == 0;

    public static HeaderBlock Parse(string? text)
    {
        var block = new HeaderBlock();
        if (string.IsNullOrWhiteSpace(text)) return block;

        var lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        string? name = null;
        var value = new StringBuilder();
        int i = 0;

        // Skip leading blank lines and anything before the first field (a pasted "From x" mbox line).
        while (i < lines.Length && !FieldStart.IsMatch(lines[i])) i++;

        for (; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0 || line.Trim().Length == 0)
            {
                // End of the header block. Outlook adds the first MIME part's headers after a
                // blank line and a boundary; those are not message headers.
                block.Body = string.Join("\n", lines.Skip(i + 1));
                break;
            }

            if ((line[0] == ' ' || line[0] == '\t') && name is not null)
            {
                value.Append(' ').Append(line.Trim());
                continue;
            }

            var m = FieldStart.Match(line);
            if (m.Success)
            {
                if (name is not null) block.Add(name, value.ToString());
                name = m.Groups[1].Value;
                value.Clear().Append(m.Groups[2].Value.Trim());
            }
            else if (name is not null)
            {
                // A wrapped line without indentation (copy/paste damage): keep it with the field.
                value.Append(' ').Append(line.Trim());
            }
        }
        if (name is not null) block.Add(name, value.ToString());
        return block;
    }

    private void Add(string name, string value) => Fields.Add(new HeaderField(name, value, Fields.Count));

    public IEnumerable<HeaderField> All(string name) =>
        Fields.Where(f => f.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    public string? First(string name) => All(name).FirstOrDefault()?.Value;

    public bool Has(string name) => All(name).Any();

    // ------------------------------------------------------------- helpers shared by parsers

    private static readonly Regex EncodedWord = new(@"=\?([^?]+)\?([BbQq])\?([^?]*)\?=", RegexOptions.Compiled);

    /// <summary>Decodes RFC 2047 encoded words ("=?utf-8?Q?...?=").</summary>
    public static string DecodeWords(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        // Whitespace between two adjacent encoded words is not displayed.
        value = Regex.Replace(value, @"\?=\s+=\?", "?==?");
        return EncodedWord.Replace(value, m =>
        {
            try
            {
                var enc = GetEncoding(m.Groups[1].Value);
                byte[] bytes = m.Groups[2].Value.ToUpperInvariant() == "B"
                    ? Convert.FromBase64String(m.Groups[3].Value)
                    : MimeText.DecodeQuotedPrintable(m.Groups[3].Value.Replace('_', ' '));
                return enc.GetString(bytes);
            }
            catch (FormatException)
            {
                return m.Value;
            }
        });
    }

    public static Encoding GetEncoding(string? charset)
    {
        if (string.IsNullOrWhiteSpace(charset)) return Encoding.UTF8;
        var cs = charset.Trim().Trim('"');
        int star = cs.IndexOf('*');            // RFC 2231 language suffix
        if (star > 0) cs = cs[..star];
        try { return Encoding.GetEncoding(cs); }
        catch (ArgumentException) { return Encoding.Latin1; }
    }

    private static readonly Regex AngleAddress = new(@"<([^<>@\s]+@[^<>\s]+)>", RegexOptions.Compiled);
    private static readonly Regex BareAddress = new(@"([A-Za-z0-9._%+\-=/!#$&'*^`{|}~]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})", RegexOptions.Compiled);

    /// <summary>The first address in a From/To/Return-Path value.</summary>
    public static string? ExtractAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var m = AngleAddress.Match(value);
        if (m.Success) return m.Groups[1].Value.Trim();
        m = BareAddress.Match(value);
        return m.Success ? m.Groups[1].Value.Trim() : null;
    }

    public static List<string> ExtractAddresses(string? value)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(value)) return list;
        foreach (Match m in BareAddress.Matches(value))
        {
            var a = m.Groups[1].Value.Trim('.');
            if (!list.Contains(a, StringComparer.OrdinalIgnoreCase)) list.Add(a);
        }
        return list;
    }

    /// <summary>"k=v; k2=v2" tag lists (DKIM-Signature, DMARC, DKIM key records).</summary>
    public static Dictionary<string, string> ParseTags(string? value)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(value)) return tags;
        foreach (var part in value.Split(';'))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var k = part[..eq].Trim();
            var v = Regex.Replace(part[(eq + 1)..], @"\s+", " ").Trim();
            if (k.Length > 0 && !tags.ContainsKey(k)) tags[k] = v;
        }
        return tags;
    }

    /// <summary>Removes (comments), respecting nesting and quoted strings.</summary>
    public static string StripComments(string value, List<string>? comments = null)
    {
        var sb = new StringBuilder();
        var comment = new StringBuilder();
        int depth = 0;
        bool quoted = false;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (c == '\\' && i + 1 < value.Length)
            {
                (depth > 0 ? comment : sb).Append(value[i + 1]);
                i++;
                continue;
            }
            if (depth == 0 && c == '"') { quoted = !quoted; sb.Append(c); continue; }
            if (!quoted && c == '(')
            {
                if (depth > 0) comment.Append(c);
                depth++;
                continue;
            }
            if (!quoted && c == ')' && depth > 0)
            {
                depth--;
                if (depth == 0)
                {
                    comments?.Add(comment.ToString().Trim());
                    comment.Clear();
                    sb.Append(' ');
                }
                else comment.Append(c);
                continue;
            }
            (depth > 0 ? comment : sb).Append(c);
        }
        return sb.ToString();
    }
}
