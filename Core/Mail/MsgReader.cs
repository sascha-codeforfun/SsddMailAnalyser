using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SsddMailAnalyser.Core.Mail;

/// <summary>
/// Reads what the analysis needs from an Outlook .msg file: the Internet headers, the body,
/// and the headers of an attached original message (which Exchange bounces carry).
///
/// A .msg is an OLE compound file (MS-CFB): a small FAT file system inside one file, with
/// each MAPI property as a stream named "__substg1.0_PPPPTTTT". Only reading is needed, so
/// this is the reading half of MS-CFB and nothing more.
/// </summary>
public static class MsgReader
{
    public sealed class Result
    {
        public string? Headers { get; set; }
        public string? Body { get; set; }
        public string? Subject { get; set; }
        public string? MessageClass { get; set; }
        public string? SenderAddress { get; set; }
        public List<string> AttachedHeaders { get; } = new();

        public bool IsBounce => MessageClass?.StartsWith("REPORT.", StringComparison.OrdinalIgnoreCase) == true;

        /// <summary>Text for the bounce box: subject, body, then the returned message's headers.</summary>
        public string AsBounceText()
        {
            var sb = new StringBuilder();
            if (!string.IsNullOrEmpty(Subject)) sb.Append("Subject: ").Append(Subject).Append("\n\n");
            if (!string.IsNullOrEmpty(Body)) sb.Append(Body.Replace("\r\n", "\n")).Append('\n');
            foreach (var h in AttachedHeaders)
                sb.Append("\nOriginal message headers:\n\n").Append(h.Replace("\r\n", "\n")).Append('\n');
            if (sb.Length == 0 && !string.IsNullOrEmpty(Headers)) sb.Append(Headers);
            return sb.ToString();
        }
    }

    private const uint EndOfChain = 0xFFFFFFFE;
    private const uint FreeSect = 0xFFFFFFFF;

    private sealed class Entry
    {
        public string Name = "";
        public byte Type;            // 1 storage, 2 stream, 5 root
        public uint Left, Right, Child;
        public uint Start;
        public long Size;
    }

    public static bool LooksLikeMsg(byte[] data) =>
        data.Length >= 512 && data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0 &&
        data[4] == 0xA1 && data[5] == 0xB1 && data[6] == 0x1A && data[7] == 0xE1;

    public static Result Read(byte[] data)
    {
        if (!LooksLikeMsg(data)) throw new InvalidDataException("not an Outlook .msg file (no compound-file signature)");

        int sectorShift = BitConverter.ToUInt16(data, 0x1E);
        int miniShift = BitConverter.ToUInt16(data, 0x20);
        if (sectorShift is not (9 or 12) || miniShift != 6) throw new InvalidDataException("unsupported compound-file sector size");
        int sectorSize = 1 << sectorShift;
        int miniSize = 1 << miniShift;
        uint firstDir = BitConverter.ToUInt32(data, 0x30);
        uint miniCutoff = BitConverter.ToUInt32(data, 0x38);
        uint firstMiniFat = BitConverter.ToUInt32(data, 0x3C);
        uint firstDifat = BitConverter.ToUInt32(data, 0x44);
        uint difatCount = BitConverter.ToUInt32(data, 0x48);

        // ---- the FAT: its sector numbers come from the DIFAT (109 in the header, then a chain)
        var fatSectors = new List<uint>();
        for (int i = 0; i < 109; i++)
        {
            uint s = BitConverter.ToUInt32(data, 0x4C + i * 4);
            if (s != FreeSect && s != EndOfChain) fatSectors.Add(s);
        }
        int sectorCount = data.Length / sectorSize + 1;
        uint difat = firstDifat;
        var difatSeen = new HashSet<uint>();
        for (int n = 0; n < difatCount && n < sectorCount && difat != EndOfChain && difat != FreeSect; n++)
        {
            // A chain that comes back to a sector it has been through would list the same FAT
            // sectors again and again, up to memory running out.
            if (!difatSeen.Add(difat)) throw new InvalidDataException("compound file is damaged (its sector table loops)");
            long off = Offset(difat, sectorSize);
            if (off + sectorSize > data.Length) break;
            int per = sectorSize / 4 - 1;
            for (int i = 0; i < per; i++)
            {
                uint s = BitConverter.ToUInt32(data, (int)off + i * 4);
                if (s != FreeSect && s != EndOfChain) fatSectors.Add(s);
            }
            difat = BitConverter.ToUInt32(data, (int)off + per * 4);
        }

        // A file cannot have more FAT sectors than sectors.
        if (fatSectors.Count > sectorCount) throw new InvalidDataException("compound file is damaged (sector table larger than the file)");

        var fat = new List<uint>();
        foreach (var fs in fatSectors)
        {
            long off = Offset(fs, sectorSize);
            for (int i = 0; i < sectorSize / 4; i++)
            {
                // A FAT sector past the end (truncated file) still occupies its index range.
                fat.Add(off + sectorSize <= data.Length ? BitConverter.ToUInt32(data, (int)off + i * 4) : FreeSect);
            }
        }

        byte[] ReadChain(uint start, long size)
        {
            var ms = new MemoryStream();
            uint s = start;
            int guard = 0;
            while (s != EndOfChain && s != FreeSect && s < fat.Count && guard++ < sectorCount)
            {
                long off = Offset(s, sectorSize);
                if (off >= data.Length) break;
                int len = (int)Math.Min(sectorSize, data.Length - off);
                ms.Write(data, (int)off, len);
                s = fat[(int)s];
            }
            var bytes = ms.ToArray();
            return size >= 0 && size < bytes.Length ? bytes[..(int)size] : bytes;
        }

        // ---- directory
        var dirBytes = ReadChain(firstDir, -1);
        var entries = new List<Entry>();
        for (int off = 0; off + 128 <= dirBytes.Length; off += 128)
        {
            int nameLen = BitConverter.ToUInt16(dirBytes, off + 0x40);
            var e = new Entry
            {
                Name = nameLen >= 2 ? Encoding.Unicode.GetString(dirBytes, off, Math.Min(64, nameLen) - 2) : "",
                Type = dirBytes[off + 0x42],
                Left = BitConverter.ToUInt32(dirBytes, off + 0x44),
                Right = BitConverter.ToUInt32(dirBytes, off + 0x48),
                Child = BitConverter.ToUInt32(dirBytes, off + 0x4C),
                Start = BitConverter.ToUInt32(dirBytes, off + 0x74),
                Size = sectorShift == 9 ? BitConverter.ToUInt32(dirBytes, off + 0x78) : BitConverter.ToInt64(dirBytes, off + 0x78),
            };
            entries.Add(e);
        }
        if (entries.Count == 0 || entries[0].Type != 5) throw new InvalidDataException("compound file has no root entry");

        // ---- mini stream (small streams live inside the root entry's stream, in 64-byte sectors)
        var root = entries[0];
        var miniStream = ReadChain(root.Start, root.Size);
        var miniFatBytes = ReadChain(firstMiniFat, -1);
        var miniFat = new List<uint>();
        for (int i = 0; i + 4 <= miniFatBytes.Length; i += 4) miniFat.Add(BitConverter.ToUInt32(miniFatBytes, i));

        byte[] ReadStream(Entry e)
        {
            if (e.Size <= 0) return Array.Empty<byte>();
            if (e.Size >= miniCutoff) return ReadChain(e.Start, e.Size);

            var ms = new MemoryStream();
            uint s = e.Start;
            int guard = 0;
            while (s != EndOfChain && s != FreeSect && s < miniFat.Count && guard++ < miniStream.Length / miniSize + 1)
            {
                long off = (long)s * miniSize;
                if (off >= miniStream.Length) break;
                int len = (int)Math.Min(miniSize, miniStream.Length - off);
                ms.Write(miniStream, (int)off, len);
                s = miniFat[(int)s];
            }
            var bytes = ms.ToArray();
            return e.Size < bytes.Length ? bytes[..(int)e.Size] : bytes;
        }

        // Children of a storage: a red-black tree hanging off its Child pointer.
        List<Entry> Children(Entry storage)
        {
            var list = new List<Entry>();
            var stack = new Stack<uint>();
            var seen = new HashSet<uint>();
            if (storage.Child < entries.Count) stack.Push(storage.Child);
            while (stack.Count > 0)
            {
                uint id = stack.Pop();
                if (id >= entries.Count || !seen.Add(id)) continue;
                var e = entries[(int)id];
                list.Add(e);
                if (e.Left < entries.Count) stack.Push(e.Left);
                if (e.Right < entries.Count) stack.Push(e.Right);
            }
            return list;
        }

        string? Prop(List<Entry> scope, string tag)
        {
            var uni = scope.FirstOrDefault(e => e.Type == 2 && e.Name.Equals($"__substg1.0_{tag}001F", StringComparison.OrdinalIgnoreCase));
            if (uni is not null) return Encoding.Unicode.GetString(ReadStream(uni)).TrimEnd('\0');
            var ansi = scope.FirstOrDefault(e => e.Type == 2 && e.Name.Equals($"__substg1.0_{tag}001E", StringComparison.OrdinalIgnoreCase));
            if (ansi is not null) return Ansi().GetString(ReadStream(ansi)).TrimEnd('\0');
            return null;
        }

        var top = Children(root);
        var result = new Result
        {
            Headers = Prop(top, "007D"),           // PR_TRANSPORT_MESSAGE_HEADERS
            Body = Prop(top, "1000"),              // PR_BODY
            Subject = Prop(top, "0037"),           // PR_SUBJECT
            MessageClass = Prop(top, "001A"),      // PR_MESSAGE_CLASS
            SenderAddress = Prop(top, "0C1F"),     // PR_SENDER_EMAIL_ADDRESS
        };

        // Attached messages (the returned original in a bounce): attachment storage -> embedded
        // message storage "__substg1.0_3701000D" -> its own transport headers.
        foreach (var attach in top.Where(e => e.Type == 1 && e.Name.StartsWith("__attach_version1.0_", StringComparison.OrdinalIgnoreCase)))
        {
            var embedded = Children(attach).FirstOrDefault(e => e.Type == 1 && e.Name.Equals("__substg1.0_3701000D", StringComparison.OrdinalIgnoreCase));
            if (embedded is null) continue;
            var headers = Prop(Children(embedded), "007D");
            if (!string.IsNullOrWhiteSpace(headers)) result.AttachedHeaders.Add(headers);
        }
        return result;
    }

    private static long Offset(uint sector, int sectorSize) => ((long)sector + 1) * sectorSize;

    private static Encoding Ansi()
    {
        try { return Encoding.GetEncoding(1252); }
        catch (ArgumentException) { return Encoding.Latin1; }
        catch (NotSupportedException) { return Encoding.Latin1; }
    }
}
