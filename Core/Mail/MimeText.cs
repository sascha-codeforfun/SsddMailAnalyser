using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace SsddMailAnalyser.Core.Mail;

/// <summary>
/// Just enough MIME to read a bounce saved as .eml: walks multipart bodies, decodes base64 and
/// quoted-printable text, flattens HTML, and keeps the headers of the returned original
/// message (text/rfc822-headers or message/rfc822), which carry the original DKIM selector.
/// </summary>
public static class MimeText
{
    public sealed class Result
    {
        public string Text { get; set; } = "";
        public string? EmbeddedHeaders { get; set; }
        public string? DeliveryStatus { get; set; }
    }

    /// <summary>
    /// Turns pasted or loaded text into readable text. Text that is not a MIME message (a
    /// bounce copied out of Outlook's reading pane) comes back unchanged.
    /// </summary>
    public static Result Flatten(string? raw)
    {
        var result = new Result();
        if (string.IsNullOrWhiteSpace(raw)) return result;

        // Only a text that *starts* with header fields is a message. A bounce copied out of the
        // reading pane contains the original message's headers further down (Content-Type and
        // all); those must not turn the prose above them into "headers".
        var firstLine = raw.TrimStart().Split('\n')[0];
        bool startsWithField = Regex.IsMatch(firstLine, @"^[A-Za-z0-9][A-Za-z0-9\-_.]*[ \t]*:");
        var headers = HeaderBlock.Parse(raw);
        bool isMime = startsWithField && (headers.Has("Content-Type") || headers.Has("MIME-Version"));
        if (!isMime)
        {
            result.Text = raw;
            return result;
        }

        var sb = new StringBuilder();
        // Keep the top-level header text: Subject, From (postmaster), X-MS-Exchange codes.
        foreach (var f in headers.Fields)
            sb.Append(f.Name).Append(": ").Append(HeaderBlock.DecodeWords(f.Value)).Append('\n');
        sb.Append('\n');

        Walk(headers, headers.Body, sb, result, 0);
        result.Text = sb.ToString();
        return result;
    }

    private static void Walk(HeaderBlock headers, string body, StringBuilder sb, Result result, int depth)
    {
        if (depth > 8) return;

        var contentType = headers.First("Content-Type") ?? "text/plain";
        var mediaType = contentType.Split(';')[0].Trim().ToLowerInvariant();
        var parameters = HeaderBlock.ParseTags(contentType.Contains(';') ? contentType[(contentType.IndexOf(';') + 1)..] : "");
        var transfer = (headers.First("Content-Transfer-Encoding") ?? "").Trim().ToLowerInvariant();

        if (mediaType.StartsWith("multipart/"))
        {
            if (!parameters.TryGetValue("boundary", out var boundary)) { sb.Append(body); return; }
            boundary = boundary.Trim().Trim('"');
            foreach (var part in SplitParts(body, boundary))
            {
                // A part that starts with a blank line has no headers of its own.
                var partHeaders = part.StartsWith('\n') ? new HeaderBlock() : HeaderBlock.Parse(part);
                var partBody = partHeaders.IsEmpty ? part : partHeaders.Body;
                Walk(partHeaders, partBody, sb, result, depth + 1);
            }
            return;
        }

        if (mediaType == "message/rfc822" || mediaType == "text/rfc822-headers")
        {
            var decodedEmbedded = DecodeBody(body, transfer, parameters);
            var inner = HeaderBlock.Parse(decodedEmbedded);
            if (!inner.IsEmpty)
            {
                result.EmbeddedHeaders ??= string.Join("\n", inner.Fields.Select(f => f.Name + ": " + f.Value));
                sb.Append("\n--- returned message headers ---\n");
                foreach (var f in inner.Fields.Where(f => f.Name is "From" or "To" or "Subject" or "Date" or "Message-ID" or "Return-Path"))
                    sb.Append(f.Name).Append(": ").Append(HeaderBlock.DecodeWords(f.Value)).Append('\n');
            }
            return;
        }

        if (mediaType == "message/delivery-status" || mediaType == "message/global-delivery-status")
        {
            var ds = DecodeBody(body, transfer, parameters);
            result.DeliveryStatus = (result.DeliveryStatus ?? "") + ds;
            sb.Append("\n--- delivery status ---\n").Append(ds).Append('\n');
            return;
        }

        if (mediaType.StartsWith("text/"))
        {
            var text = DecodeBody(body, transfer, parameters);
            if (mediaType == "text/html") text = HtmlToText(text);
            sb.Append(text).Append('\n');
        }
        // images, attachments: ignored
    }

    private static IEnumerable<string> SplitParts(string body, string boundary)
    {
        var lines = body.Replace("\r\n", "\n").Split('\n');
        var delimiter = "--" + boundary;
        var close = delimiter + "--";
        StringBuilder? current = null;

        foreach (var line in lines)
        {
            var trimmed = line.TrimEnd();
            if (trimmed == close)
            {
                if (current is not null) yield return current.ToString();
                yield break;
            }
            if (trimmed == delimiter)
            {
                if (current is not null) yield return current.ToString();
                current = new StringBuilder();
                continue;
            }
            current?.Append(line).Append('\n');
        }
        if (current is not null) yield return current.ToString();
    }

    private static string DecodeBody(string body, string transfer, Dictionary<string, string> parameters)
    {
        parameters.TryGetValue("charset", out var charset);
        var encoding = HeaderBlock.GetEncoding(charset);
        try
        {
            if (transfer == "base64")
            {
                var clean = new string(body.Where(c => !char.IsWhiteSpace(c)).ToArray());
                return encoding.GetString(Convert.FromBase64String(clean));
            }
            if (transfer == "quoted-printable")
                return encoding.GetString(DecodeQuotedPrintable(body));
        }
        catch (FormatException)
        {
            // Malformed encoding: fall back to the undecoded body.
        }
        return body;
    }

    public static byte[] DecodeQuotedPrintable(string text)
    {
        var output = new MemoryStream();
        var input = text.Replace("\r\n", "\n");
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            if (c == '=')
            {
                if (i + 1 < input.Length && input[i + 1] == '\n') { i++; continue; }   // soft line break
                if (i + 2 < input.Length && IsHex(input[i + 1]) && IsHex(input[i + 2]))
                {
                    output.WriteByte(Convert.ToByte(input.Substring(i + 1, 2), 16));
                    i += 2;
                    continue;
                }
            }
            if (c < 256) output.WriteByte((byte)c);
            else
            {
                var b = Encoding.UTF8.GetBytes(c.ToString());
                output.Write(b, 0, b.Length);
            }
        }
        return output.ToArray();
    }

    private static bool IsHex(char c) => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

    public static string HtmlToText(string html)
    {
        var s = Regex.Replace(html, @"<(script|style)[^>]*>.*?</\1>", " ", RegexOptions.Singleline | RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"<\s*(br|/p|/div|/tr|/li|/h\d)\s*/?\s*>", "\n", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"<[^>]+>", " ");
        s = WebUtility.HtmlDecode(s);
        s = Regex.Replace(s, @"[ \t ]+", " ");
        s = Regex.Replace(s, @"\n\s*\n+", "\n\n");
        return s.Trim();
    }
}
