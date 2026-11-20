using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>
/// RECmd batch output (*_RECmd_Batch_*_Output.csv, e.g. Kroll_Batch). Every
/// row's value data is checked for known tools, staging paths and command-line
/// techniques — that covers UserAssist, BAM, RunMRU, TypedPaths, services and
/// autoruns in one pass. Autorun entries are also listed as context, and the
/// host name and IP addresses are read for the case summary.
/// </summary>
public sealed class RegistryAnalyser : IArtifactAnalyser
{
    public string Source => "REGISTRY";
    public string Module => "RECmd (batch)";
    public bool Enabled(AnalyserConfig c) => c.AnalyseRegistry;
    public bool Accepts(string f) => f.Contains("_RECmd_Batch_", StringComparison.OrdinalIgnoreCase)
                                    && f.EndsWith("_Output.csv", StringComparison.OrdinalIgnoreCase);

    private static readonly Regex AutorunKey = new(
        @"\\CurrentVersion\\(Run|RunOnce|RunOnceEx|RunServices|Policies\\Explorer\\Run)(\\|$)|\\Winlogon$|\\Image File Execution Options\\|\\AppInit_DLLs|\\Explorer\\Shell Folders\\Startup|\\Active Setup\\Installed Components\\|\\Environment$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex WinlogonValue = new(@"^(Userinit|Shell|Taskman|AppSetup)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex BenignWinlogon = new(@"^(C:\\Windows\\system32\\userinit\.exe,?|explorer\.exe|sihost\.exe|)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Ipv4 = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);

    private readonly FindingAggregator _agg = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cCat = csv.Col("Category"), cDesc = csv.Col("Description"), cKey = csv.Col("KeyPath"),
            cName = csv.Col("ValueName"), cData = csv.Col("ValueData"), cData2 = csv.Col("ValueData2"),
            cData3 = csv.Col("ValueData3"), cTime = csv.Col("LastWriteTimestamp"), cHive = csv.Col("HivePath"),
            cDeleted = csv.Col("Deleted");
        if (cKey < 0) return;
        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var t = CsvReader.ParseTime(csv[cTime]);
            cov.See(t);

            var key = csv[cKey];
            var name = csv[cName];
            var data = string.Join(" ", new[] { csv[cData], csv[cData2], csv[cData3] }.Where(s => s.Length > 0));
            var desc = csv[cDesc].Length > 0 ? csv[cDesc] : csv[cCat];
            var hive = DetectionRules.FileNameOf(csv[cHive]);
            var user = UserOfHive(csv[cHive]);
            var deleted = csv[cDeleted].Equals("True", StringComparison.OrdinalIgnoreCase) ? " [deleted key]" : "";

            // Host identity
            if (key.EndsWith(@"\ComputerName\ComputerName", StringComparison.OrdinalIgnoreCase) && name.Equals("ComputerName", StringComparison.OrdinalIgnoreCase))
                ctx.VoteHostname(csv[cData], 1_000_000);
            if (key.Contains(@"\Tcpip\Parameters\Interfaces", StringComparison.OrdinalIgnoreCase)
                && Regex.IsMatch(name, @"^(IPAddress|DhcpIPAddress)$", RegexOptions.IgnoreCase))
                foreach (Match m in Ipv4.Matches(data))
                    if (DetectionRules.IsUsableIp(m.Value)) ctx.HostIps.Add(m.Value);

            // Defender exclusions
            if (key.Contains(@"\Windows Defender\Exclusions\", StringComparison.OrdinalIgnoreCase) && name.Length > 0)
            {
                _agg.Add($"defex|{key}|{name}", Severity.High, t, Source, "Defender exclusion",
                    $"Defender exclusion ({key[(key.LastIndexOf('\\') + 1)..]}): {name}{deleted}", key, hive);
                continue;
            }

            // Outbound lateral movement and removable media (where this host connected to)
            if (OutboundOrUsb(key, name, csv[cData], t, user, hive, deleted, ctx)) continue;

            // Content checks on any row
            var hits = ctx.Rules.MatchCommandLine(data);
            var scored = DetectionRules.ExtractPaths(data).Append(name)
                .Select(p => (Path: p, Score: ctx.Rules.ScoreBinaryPath(p)))
                .Where(x => x.Score != null)
                .OrderBy(x => x.Score!.Value.Sev)
                .FirstOrDefault();

            bool autorun = AutorunKey.IsMatch(key) && (!key.EndsWith("Winlogon", StringComparison.OrdinalIgnoreCase) || WinlogonValue.IsMatch(name));

            if (hits.Count > 0 || scored.Score != null)
            {
                var sev = hits.Select(h => h.Severity).Append(scored.Score?.Sev ?? Severity.Suspicious).Min();
                if (autorun && sev > Severity.High) sev = Severity.High;     // tool/staging path in an autorun
                var reasons = hits.Select(h => h.Label).ToList();
                if (scored.Score != null) reasons.Add($"{scored.Score.Value.Reason} ({DetectionRules.FileNameOf(scored.Path)})");
                _agg.Add($"reg|{key}|{name}|{data}", sev, t, Source, autorun ? "Suspicious autorun" : (scored.Score?.Reason ?? hits[0].Label),
                    $"{desc}{(user.Length > 0 ? $" ({user})" : "")}: {string.Join(", ", reasons.Distinct())}{deleted}",
                    EventLogAnalyser.Trunc($"{key}\\{name} = {data}", 1000), hive);
                continue;
            }

            // Autoruns without a hit: listed as context (they are few)
            if (autorun && name.Length > 0 && data.Length > 0 && !(WinlogonValue.IsMatch(name) && BenignWinlogon.IsMatch(csv[cData].Trim())))
            {
                if (ctx.Rules.IsWhitelisted(data)) continue;
                _agg.Add($"autorun|{key}|{name}|{data}", Severity.Suspicious, t, Source, "Autorun entry",
                    $"Autorun{(user.Length > 0 ? $" ({user})" : "")}: {name} → {EventLogAnalyser.Trunc(data, 160)}{deleted}",
                    $"{key}\\{name}", hive);
            }
        }
    }

    // ── Outbound connections and removable media ─────────────────────
    private static readonly Regex RdpServerKey = new(@"\\Terminal Server Client\\Servers\\(?<t>[^\\]+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RdpDefaultKey = new(@"\\Terminal Server Client\\Default$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex MapDriveMruKey = new(@"\\Map Network Drive MRU$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex NetworkDriveKey = new(@"(^|\\)Network\\(?<d>[A-Za-z])$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex MountPoints2Key = new(@"\\MountPoints2\\(?<p>##[^\\]+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex TypedPathsKey = new(@"\\Explorer\\TypedPaths$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex UsbStorKey = new(@"\\Enum\\USBSTOR\\(?<dev>[^\\]+)\\(?<serial>[^\\]+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PortableKey = new(@"\\Windows Portable Devices\\Devices\\(?<id>[^\\]+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex AdminShare = new(@"^\\\\[^\\]+\\([A-Za-z]\$|ADMIN\$|IPC\$)(\\|$)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex UncRoot = new(@"^\\\\[^\\]+\\[^\\]+", RegexOptions.Compiled);

    /// <summary>
    /// Outbound RDP targets, mapped drives and network shares this host's users
    /// opened (lateral movement *from* this host), and USB storage that was
    /// connected (exfiltration). True when the row was handled.
    /// </summary>
    private bool OutboundOrUsb(string key, string name, string value, DateTime? t, string user, string hive, string deleted, AnalysisContext ctx)
    {
        var who = user.Length > 0 ? $" ({user})" : "";
        Match m;

        if ((m = RdpServerKey.Match(key)).Success || (RdpDefaultKey.IsMatch(key) && Regex.IsMatch(name, @"^MRU\d+$", RegexOptions.IgnoreCase)))
        {
            var target = m.Success ? m.Groups["t"].Value : value.Trim();
            if (target.Length == 0) return true;
            var hint = m.Success && name.Equals("UsernameHint", StringComparison.OrdinalIgnoreCase) && value.Length > 0 ? $" as {value}" : "";
            var sev = DetectionRules.IsExternalIp(target.Split(':')[0]) ? Severity.High : Severity.Medium;
            _agg.Add($"rdpout|{target.ToLowerInvariant()}|{user}", sev, t, Source, "Outbound RDP connection",
                $"Outbound RDP from this host to {target}{hint}{who}{deleted}", $"{key}\\{name}", hive, extra: hint.Length > 0 ? hint.Trim() : null);
            return true;
        }

        string? share = null;
        if (MapDriveMruKey.IsMatch(key) && Regex.IsMatch(name, @"^[a-z]$", RegexOptions.IgnoreCase)) share = value.Trim();
        else if (NetworkDriveKey.Match(key) is { Success: true } nd && name.Equals("RemotePath", StringComparison.OrdinalIgnoreCase))
            share = value.Trim() + $" (drive {nd.Groups["d"].Value.ToUpperInvariant()}:)";
        else if ((m = MountPoints2Key.Match(key)).Success) share = m.Groups["p"].Value.Replace('#', '\\');
        else if (TypedPathsKey.IsMatch(key) && value.StartsWith(@"\\", StringComparison.Ordinal)) share = value.Trim();
        if (share != null)
        {
            if (share.Length == 0) return true;
            var unc = UncRoot.Match(share) is { Success: true } u ? u.Value : share;
            var host = unc.TrimStart('\\').Split('\\')[0];
            bool admin = AdminShare.IsMatch(unc);
            var sev = admin ? Severity.High : DetectionRules.IsIp(host) ? Severity.Medium : Severity.Suspicious;
            _agg.Add($"share|{unc.ToLowerInvariant()}|{user}", sev, t, Source, admin ? "Admin share opened from this host" : "Network share opened from this host",
                $"{(admin ? "Admin share opened" : "Network share mapped")} from this host: {share}{who}{deleted}", $"{key}\\{name}", hive);
            return true;
        }

        if ((m = UsbStorKey.Match(key)).Success)
        {
            var serial = m.Groups["serial"].Value.Split('&')[0];
            var dev = Regex.Replace(m.Groups["dev"].Value, @"^Disk&Ven_|&Rev_.*$", "", RegexOptions.IgnoreCase).Replace("&Prod_", " ", StringComparison.OrdinalIgnoreCase).Replace('_', ' ');
            var label = name.Equals("FriendlyName", StringComparison.OrdinalIgnoreCase) && value.Length > 0 ? value : dev;
            _agg.Add($"usb|{serial}", Severity.Medium, t, Source, "USB storage device",
                $"USB storage device: {label} (serial {serial}){deleted}", $"{m.Groups["dev"].Value}\\{m.Groups["serial"].Value}", hive);
            return true;
        }
        if ((m = PortableKey.Match(key)).Success)
        {
            if (!name.Equals("FriendlyName", StringComparison.OrdinalIgnoreCase) || value.Length == 0) return true;
            _agg.Add($"wpd|{m.Groups["id"].Value}", Severity.Suspicious, t, Source, "Portable device",
                $"Portable / removable device: {value}{deleted}", m.Groups["id"].Value, hive);
            return true;
        }
        return false;
    }

    private static string UserOfHive(string hivePath)
    {
        var m = Regex.Match(hivePath ?? "", @"\\Users\\([^\\]+)\\", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : "";
    }

    public void Complete(AnalysisContext ctx) => ctx.AddRange(_agg.Flush());
}
