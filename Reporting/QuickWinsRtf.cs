using System.Text;
using System.Text.RegularExpressions;

namespace KapeAnalyser.WPF.Reporting;

/// <summary>
/// Converts QuickWins.txt into a colour-coded QuickWins.rtf (same approach as
/// CsirtParser): section headers, severity per line, IPs highlighted, detail
/// lines dimmed.
/// </summary>
public static class QuickWinsRtf
{
    private const int Black = 1, Red = 2, Orange = 3, Blue = 4, Grey = 5, DarkRed = 6, Teal = 7;

    private const string ColourTable =
        @"{\colortbl ;\red0\green0\blue0;\red180\green0\blue0;\red180\green90\blue0;\red0\green70\blue160;" +
        @"\red120\green120\blue120;\red140\green0\blue0;\red0\green100\blue100;}";

    private static readonly Regex Ip = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);
    private static readonly Regex Crit = new(@"\[CRITICAL\]|^\s{2}CRITICAL\s|\sCRITICAL\s+\[", RegexOptions.Compiled);
    private static readonly Regex High = new(@"\[HIGH\]|^\s{2}HIGH\s|\sHIGH\s+\[|\[ERROR\]", RegexOptions.Compiled);
    private static readonly Regex Medium = new(@"\[MEDIUM\]|^\s{2}MEDIUM\s|\sMEDIUM\s+\[|EXTERNAL", RegexOptions.Compiled);
    private static readonly Regex Susp = new(@"\[SUSPICIOUS\]", RegexOptions.Compiled);

    public static void Convert(string outDir)
    {
        var txt = Path.Combine(outDir, HostReport.QuickWinsFile);
        if (!File.Exists(txt)) return;
        var sb = new StringBuilder();
        sb.Append(@"{\rtf1\ansi\deff0{\fonttbl{\f0\fmodern\fcharset0 Consolas;}{\f1\fswiss\fcharset0 Segoe UI;}}");
        sb.Append(ColourTable);
        sb.AppendLine(@"\margl720\margr720\margt720\margb720\f0\fs18");

        foreach (var line in File.ReadAllLines(txt, Encoding.UTF8))
        {
            var e = Escape(line);
            if (string.IsNullOrWhiteSpace(line)) sb.AppendLine(@"\pard\par");
            else if (line.StartsWith("#####")) sb.AppendLine($@"\pard\sb240\sa60\f1\fs24\b\cf{DarkRed} {e}\b0\f0\fs18\cf1\par");
            else if (line.StartsWith("=====") || line.StartsWith(" KAPE") || line.StartsWith(" Host:") || line.StartsWith(" Case:") || line.StartsWith(" Generated"))
                sb.AppendLine($@"\pard\f1\fs20\cf{Grey} {e}\f0\fs18\cf1\par");
            else if (line.StartsWith("      ")) sb.AppendLine($@"\pard\li720\fs16\cf{Grey} {e}\fs18\cf1\par");
            else if (Crit.IsMatch(line)) sb.AppendLine($@"\pard\b\cf{DarkRed} {Ips(e, DarkRed)}\b0\cf1\par");
            else if (High.IsMatch(line)) sb.AppendLine($@"\pard\b\cf{Red} {Ips(e, Red)}\b0\cf1\par");
            else if (Medium.IsMatch(line)) sb.AppendLine($@"\pard\cf{Orange} {Ips(e, Orange)}\cf1\par");
            else if (Susp.IsMatch(line)) sb.AppendLine($@"\pard\cf{Teal} {Ips(e, Teal)}\cf1\par");
            else sb.AppendLine($@"\pard\cf{Black} {Ips(e, Black)}\cf1\par");
        }
        sb.Append('}');
        File.WriteAllText(Path.Combine(outDir, "QuickWins.rtf"), sb.ToString(), Encoding.ASCII);
    }

    private static string Ips(string s, int restore) => Ip.Replace(s, m => $@"\cf{Blue}\b {m.Value}\b0\cf{restore} ");

    private static string Escape(string text)
    {
        var sb = new StringBuilder(text.Length + 16);
        foreach (var ch in text)
        {
            switch (ch)
            {
                case '\\': sb.Append(@"\\"); break;
                case '{': sb.Append(@"\{"); break;
                case '}': sb.Append(@"\}"); break;
                default:
                    if (ch > 127) sb.Append(@"\u").Append((short)ch).Append('?');
                    else sb.Append(ch);
                    break;
            }
        }
        return sb.ToString();
    }
}
