using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using SsddMailAnalyser.Core.Dns;

namespace SsddMailAnalyser.Core;

/// <summary>
/// What the app remembers between runs: the operator's own domains, so that only the other
/// party's has to be typed, and whether the busy rings always turn. Kept in
/// SsddMailAnalyser.json next to the exe and nowhere else, so deleting the app's folder
/// removes every trace.
///
/// The file is somebody's hand-edited text as much as it is ours. Whatever is wrong with it
/// (missing, unreadable, not JSON, wrong types, names that are no names) is skipped without
/// an error: the app starts with what could be read.
/// </summary>
public sealed class AppSettings
{
    public const string FileName = "SsddMailAnalyser.json";

    private const int MaxFileBytes = 1024 * 1024;
    private const int MaxDomains = 500;

    /// <summary>The operator's own domains, normalised, in the order they were added.</summary>
    public List<string> Domains { get; set; } = new();

    /// <summary>The busy rings turn whatever Windows says about animation (off in every remote session).</summary>
    public bool AlwaysTurn { get; set; } = true;

    /// <summary>
    /// Next to the exe. Not AppContext.BaseDirectory: this app is published as a single file
    /// that unpacks itself, and there that property names the temporary folder it unpacked
    /// to, not the folder the exe is in.
    /// </summary>
    public static string DefaultPath
    {
        get
        {
            var folder = Path.GetDirectoryName(Environment.ProcessPath);
            if (string.IsNullOrEmpty(folder)) folder = AppContext.BaseDirectory;
            return Path.Combine(folder, FileName);
        }
    }

    /// <summary>A domain as it is stored, or null if the text is not a name.</summary>
    public static string? Clean(string? text)
    {
        var domain = DomainUtil.DomainOf(text ?? "");
        return domain.Length > 0 && domain.Length <= 253 && DomainUtil.IsNameSafe(domain) ? domain : null;
    }

    public bool Has(string? domain)
    {
        var clean = Clean(domain);
        return clean is not null && Domains.Contains(clean, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>False if the text is not a name, is there already, or the list is full.</summary>
    public bool Add(string? text)
    {
        var clean = Clean(text);
        if (clean is null || Domains.Count >= MaxDomains || Domains.Contains(clean, StringComparer.OrdinalIgnoreCase)) return false;
        Domains.Add(clean);
        return true;
    }

    public static AppSettings Load(string path)
    {
        var settings = new AppSettings();
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length == 0 || info.Length > MaxFileBytes) return settings;

            using var doc = JsonDocument.Parse(File.ReadAllBytes(path),
                new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return settings;

            if (doc.RootElement.TryGetProperty("domains", out var domains) && domains.ValueKind == JsonValueKind.Array)
                foreach (var item in domains.EnumerateArray())
                    if (item.ValueKind == JsonValueKind.String) settings.Add(item.GetString());

            if (doc.RootElement.TryGetProperty("busyAlwaysTurn", out var turn) && turn.ValueKind is JsonValueKind.True or JsonValueKind.False)
                settings.AlwaysTurn = turn.GetBoolean();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException
                                       or NotSupportedException or ArgumentException or System.Security.SecurityException)
        {
            // Start with what was read so far.
        }
        return settings;
    }

    /// <summary>False when the folder cannot be written: the settings then last for the session.</summary>
    public bool Save(string path)
    {
        try
        {
            using var buffer = new MemoryStream();
            using (var json = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
            {
                json.WriteStartObject();
                json.WriteStartArray("domains");
                foreach (var domain in Domains) json.WriteStringValue(domain);
                json.WriteEndArray();
                json.WriteBoolean("busyAlwaysTurn", AlwaysTurn);
                json.WriteEndObject();
            }
            File.WriteAllText(path, Encoding.UTF8.GetString(buffer.ToArray()) + Environment.NewLine, new UTF8Encoding(false));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException
                                       or ArgumentException or System.Security.SecurityException)
        {
            return false;
        }
    }
}
