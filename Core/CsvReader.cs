using System.Globalization;
using System.Text;

namespace KapeAnalyser.WPF.Core;

/// <summary>
/// Streaming RFC 4180 reader for EZ Tools / KAPE module output. Handles
/// quoted fields with embedded commas, quotes and line breaks (EvtxECmd's
/// Payload column spans lines), a UTF-8 BOM, and files of several GB without
/// loading them into memory. Columns are looked up by header name, case-insensitive,
/// because column order differs between tool versions.
/// </summary>
public sealed class CsvReader : IDisposable
{
    private readonly StreamReader _reader;
    private readonly Dictionary<string, int> _columns = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _fields = new(64);
    private readonly StringBuilder _sb = new(256);

    public IReadOnlyList<string> Header { get; }
    public long RowNumber { get; private set; }

    public CsvReader(string path)
    {
        _reader = new StreamReader(
            new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 16),
            Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 16);

        Header = ReadRecord() ? _fields.ToArray() : Array.Empty<string>();
        for (int i = 0; i < Header.Count; i++)
            _columns.TryAdd(Header[i].Trim(), i);
    }

    public bool HasColumn(string name) => _columns.ContainsKey(name);

    /// <summary>Index of the first column that exists, or -1.</summary>
    public int Col(params string[] names)
    {
        foreach (var n in names)
            if (_columns.TryGetValue(n, out var i)) return i;
        return -1;
    }

    public bool Read()
    {
        while (ReadRecord())
        {
            // Skip blank lines
            if (_fields.Count == 1 && _fields[0].Length == 0) continue;
            RowNumber++;
            return true;
        }
        return false;
    }

    public string this[int index] => index >= 0 && index < _fields.Count ? _fields[index] : string.Empty;

    public string Get(string name) => _columns.TryGetValue(name, out var i) ? this[i] : string.Empty;

    private bool ReadRecord()
    {
        _fields.Clear();
        _sb.Clear();
        var line = _reader.ReadLine();
        if (line == null) return false;

        int i = 0;
        bool inQuotes = false;
        while (true)
        {
            if (i >= line.Length)
            {
                if (!inQuotes) break;
                // Quoted field continues on the next physical line
                var next = _reader.ReadLine();
                if (next == null) break;
                _sb.Append('\n');
                line = next;
                i = 0;
                continue;
            }

            char c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { _sb.Append('"'); i += 2; continue; }
                    inQuotes = false;
                    i++;
                    continue;
                }
                _sb.Append(c);
                i++;
            }
            else if (c == '"') { inQuotes = true; i++; }
            else if (c == ',') { _fields.Add(_sb.ToString()); _sb.Clear(); i++; }
            else { _sb.Append(c); i++; }
        }
        _fields.Add(_sb.ToString());
        return true;
    }

    public void Dispose() => _reader.Dispose();

    // ── Timestamps ───────────────────────────────────────────────────
    private static readonly string[] TimeFormats =
    {
        "yyyy-MM-dd HH:mm:ss.fffffff", "yyyy-MM-dd HH:mm:ss.ffffff", "yyyy-MM-dd HH:mm:ss.fff",
        "yyyy-MM-dd HH:mm:ss", "yyyy-MM-ddTHH:mm:ss.fffffffZ", "yyyy-MM-ddTHH:mm:ssZ",
        "yyyy-MM-ddTHH:mm:ss.fffffff", "yyyy-MM-ddTHH:mm:ss",
    };

    /// <summary>EZ Tools write UTC timestamps; null for empty or unparsable values.</summary>
    public static DateTime? ParseTime(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        const DateTimeStyles st = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
        if (DateTime.TryParseExact(s, TimeFormats, CultureInfo.InvariantCulture, st, out var t)
            || DateTime.TryParse(s, CultureInfo.InvariantCulture, st, out t))
        {
            // 1601-01-01 / 0001 values are "not set" FILETIMEs
            return t.Year < 1980 ? null : t;
        }
        return null;
    }
}
