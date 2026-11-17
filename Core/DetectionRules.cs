using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Core;

/// <summary>
/// Shared Windows detection knowledge used by every analyser: attacker and
/// dual-use tools by file name, staging directories, and command-line
/// techniques. One place so prefetch, amcache, shimcache, event logs and the
/// file system all agree on what "suspicious" means.
/// </summary>
public sealed class DetectionRules
{
    public sealed record ToolHit(string Name, string Category, Severity Severity);
    public sealed record CmdHit(string Label, Severity Severity);

    // File name (no extension, lower case) → category, severity
    private static readonly (string Pattern, string Category, Severity Sev)[] Tools =
    {
        // Credential access
        ("mimikatz", "Credential theft tool", Severity.Critical),
        ("mimilib", "Credential theft tool", Severity.Critical),
        ("mimidrv", "Credential theft tool", Severity.Critical),
        ("lazagne", "Credential theft tool", Severity.Critical),
        ("nanodump", "Credential theft tool", Severity.Critical),
        ("pypykatz", "Credential theft tool", Severity.Critical),
        ("rubeus", "Credential theft tool", Severity.Critical),
        ("kekeo", "Credential theft tool", Severity.Critical),
        ("safetykatz", "Credential theft tool", Severity.Critical),
        ("secretsdump", "Credential theft tool", Severity.Critical),
        ("procdump", "Memory dump tool", Severity.High),
        ("procdump64", "Memory dump tool", Severity.High),
        ("dumpert", "Credential theft tool", Severity.Critical),
        ("kerbrute", "Credential attack tool", Severity.High),
        ("responder", "Credential attack tool", Severity.High),
        ("hashcat", "Password cracking tool", Severity.High),
        ("ntdsaudit", "Credential theft tool", Severity.High),
        // Lateral movement / execution
        ("psexec", "Remote execution tool", Severity.High),
        ("psexec64", "Remote execution tool", Severity.High),
        ("psexesvc", "Remote execution service (PsExec target)", Severity.High),
        ("paexec", "Remote execution tool", Severity.High),
        ("remcom", "Remote execution tool", Severity.High),
        ("crackmapexec", "Lateral movement tool", Severity.Critical),
        ("cme", "Lateral movement tool", Severity.High),
        ("netexec", "Lateral movement tool", Severity.Critical),
        ("nxc", "Lateral movement tool", Severity.High),
        ("wmiexec", "Lateral movement tool", Severity.Critical),
        ("smbexec", "Lateral movement tool", Severity.Critical),
        ("atexec", "Lateral movement tool", Severity.Critical),
        ("dcomexec", "Lateral movement tool", Severity.Critical),
        ("sharpexec", "Lateral movement tool", Severity.High),
        // Recon
        ("sharphound", "AD reconnaissance tool", Severity.Critical),
        ("bloodhound", "AD reconnaissance tool", Severity.Critical),
        ("azurehound", "AD reconnaissance tool", Severity.Critical),
        ("adfind", "AD reconnaissance tool", Severity.High),
        ("adrecon", "AD reconnaissance tool", Severity.High),
        ("pingcastle", "AD reconnaissance tool", Severity.Medium),
        ("seatbelt", "Host reconnaissance tool", Severity.High),
        ("winpeas", "Privilege escalation tool", Severity.Critical),
        ("sharpup", "Privilege escalation tool", Severity.High),
        ("powerup", "Privilege escalation tool", Severity.High),
        ("advanced_ip_scanner", "Network scanner", Severity.High),
        ("advanced ip scanner", "Network scanner", Severity.High),
        ("netscan", "Network scanner", Severity.High),
        ("angryip", "Network scanner", Severity.High),
        ("ipscan", "Network scanner", Severity.Medium),
        ("nmap", "Network scanner", Severity.High),
        ("masscan", "Network scanner", Severity.High),
        ("softperfect", "Network scanner", Severity.High),
        ("lansweeper", "Network scanner", Severity.Medium),
        ("nltest", "Domain trust discovery", Severity.Suspicious),
        // Tunnelling / C2
        ("plink", "Tunnelling tool", Severity.High),
        ("chisel", "Tunnelling tool", Severity.Critical),
        ("ligolo", "Tunnelling tool", Severity.Critical),
        ("ngrok", "Tunnelling tool", Severity.High),
        ("cloudflared", "Tunnelling tool", Severity.Medium),
        ("frpc", "Tunnelling tool", Severity.Critical),
        ("gost", "Tunnelling tool", Severity.High),
        ("socat", "Tunnelling tool", Severity.High),
        ("ncat", "Netcat", Severity.High),
        ("nc", "Netcat", Severity.High),
        ("nc64", "Netcat", Severity.High),
        ("beacon", "C2 implant (name)", Severity.High),
        ("sliver", "C2 implant (name)", Severity.High),
        ("havoc", "C2 implant (name)", Severity.High),
        // Remote access software
        ("anydesk", "Remote access software", Severity.Medium),
        ("teamviewer", "Remote access software", Severity.Suspicious),
        ("screenconnect", "Remote access software", Severity.Medium),
        ("connectwisecontrol", "Remote access software", Severity.Medium),
        ("atera", "Remote access software", Severity.Medium),
        ("splashtop", "Remote access software", Severity.Medium),
        ("rustdesk", "Remote access software", Severity.Medium),
        ("meshagent", "Remote access software", Severity.Medium),
        ("tacticalrmm", "Remote access software", Severity.Medium),
        ("netsupport", "Remote access software", Severity.Medium),
        ("client32", "Remote access software (NetSupport)", Severity.Medium),
        ("logmein", "Remote access software", Severity.Suspicious),
        ("ammyy", "Remote access software", Severity.High),
        // Exfiltration
        ("rclone", "Exfiltration tool", Severity.Critical),
        ("megasync", "Exfiltration tool", Severity.High),
        ("megacmd", "Exfiltration tool", Severity.High),
        ("restic", "Exfiltration tool", Severity.High),
        ("filezilla", "File transfer client", Severity.Suspicious),
        ("winscp", "File transfer client", Severity.Suspicious),
        ("pscp", "File transfer client", Severity.Medium),
        ("exmatter", "Exfiltration tool", Severity.Critical),
        ("stealbit", "Exfiltration tool", Severity.Critical),
        // Defence evasion / impact
        ("defendercontrol", "Defence evasion tool", Severity.Critical),
        ("dcontrol", "Defence evasion tool", Severity.Critical),
        ("gmer", "Rootkit / AV-killer tool", Severity.High),
        ("processhacker", "Process tool (AV-killer use)", Severity.Medium),
        ("systeminformer", "Process tool (AV-killer use)", Severity.Medium),
        ("pchunter", "Rootkit / AV-killer tool", Severity.High),
        ("powertool", "Rootkit / AV-killer tool", Severity.High),
        ("iobitunlocker", "Defence evasion tool", Severity.High),
        ("backstab", "Defence evasion tool", Severity.Critical),
        ("edrsilencer", "Defence evasion tool", Severity.Critical),
        ("terminator", "Defence evasion tool", Severity.High),
        ("everything", "File search tool (ransomware use)", Severity.Suspicious),
        ("ccleaner", "Anti-forensics tool", Severity.Medium),
        ("bleachbit", "Anti-forensics tool", Severity.High),
        ("sdelete", "Anti-forensics tool", Severity.High),
        ("sdelete64", "Anti-forensics tool", Severity.High),
        ("timestomp", "Anti-forensics tool", Severity.Critical),
    };

    private static readonly Dictionary<string, (string Category, Severity Sev)> ToolIndex =
        Tools.ToDictionary(t => t.Pattern, t => (t.Category, t.Sev), StringComparer.OrdinalIgnoreCase);

    // Directories attackers stage tools in. Matched against a normalised
    // path with backslashes ("\users\x\appdata\local\temp\a.exe").
    private static readonly (Regex Rx, string Label)[] StagingDirs =
    {
        (new(@"\\users\\public\\", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\Users\Public"),
        (new(@"\\appdata\\local\\temp\\", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"user Temp"),
        (new(@"\\windows\\temp\\", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\Windows\Temp"),
        (new(@"\\perflogs\\", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\PerfLogs"),
        (new(@"\\\$recycle\.bin\\", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"Recycle Bin"),
        (new(@"\\programdata\\[^\\]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr)$", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\ProgramData root"),
        (new(@"\\windows\\tasks\\", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\Windows\Tasks"),
        (new(@"\\windows\\debug\\", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\Windows\debug"),
        (new(@"\\windows\\tracing\\", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\Windows\Tracing"),
        (new(@"\\windows\\fonts\\[^\\]+\.(exe|dll|ps1|bat)$", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\Windows\Fonts"),
        (new(@"\\appdata\\roaming\\[^\\]+\.(exe|dll|ps1|bat|cmd|vbs)$", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"AppData\Roaming root"),
        (new(@"^(\\volume\{[^}]*\}|[a-z]:)?\\[^\\]+\.(exe|dll|ps1|bat|cmd|vbs|hta|scr)$", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"drive root"),
        (new(@"\\intel\\[^\\]+\.(exe|dll)$", RegexOptions.IgnoreCase | RegexOptions.Compiled), @"\Intel"),
    };

    private static readonly Regex DownloadsDir = new(@"\\users\\[^\\]+\\downloads\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Command-line techniques (PowerShell, LOLBins, ransomware prep, lateral movement)
    private static readonly (Regex Rx, string Label, Severity Sev)[] CmdPatterns =
    {
        (Rx(@"vssadmin(\.exe)?\s+.*delete\s+shadows"), "Shadow copies deleted (vssadmin)", Severity.Critical),
        (Rx(@"wmic(\.exe)?\s+.*shadowcopy\s+delete"), "Shadow copies deleted (wmic)", Severity.Critical),
        (Rx(@"Win32_ShadowCopy.*(Delete|Remove)"), "Shadow copies deleted (WMI)", Severity.Critical),
        (Rx(@"bcdedit(\.exe)?.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"), "Recovery disabled (bcdedit)", Severity.Critical),
        (Rx(@"wbadmin(\.exe)?\s+delete"), "Backups deleted (wbadmin)", Severity.Critical),
        (Rx(@"wevtutil(\.exe)?\s+(cl|clear-log)\b"), "Event log cleared (wevtutil)", Severity.Critical),
        (Rx(@"Clear-EventLog|Remove-EventLog"), "Event log cleared (PowerShell)", Severity.Critical),
        (Rx(@"comsvcs(\.dll)?[\s,#]+.*minidump"), "LSASS dump via comsvcs.dll", Severity.Critical),
        (Rx(@"procdump(64)?(\.exe)?\s.*lsass"), "LSASS dump via procdump", Severity.Critical),
        (Rx(@"sekurlsa::|lsadump::|kerberos::golden|privilege::debug"), "Mimikatz command", Severity.Critical),
        (Rx(@"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)"), "Registry hive dump (SAM/SYSTEM/SECURITY)", Severity.Critical),
        (Rx(@"ntdsutil.*(ifm|create\s+full)"), "NTDS.dit dump (ntdsutil)", Severity.Critical),
        (Rx(@"\\\\127\.0\.0\.1\\ADMIN\$\\__\d"), "Impacket wmiexec/smbexec output redirect", Severity.Critical),
        (Rx(@"cmd(\.exe)?\s+/Q\s+/c\s+.*1>\s*\\\\"), "Impacket-style remote command", Severity.Critical),
        (Rx(@"%COMSPEC%\s+/Q\s+/c\s+echo"), "Impacket smbexec service command", Severity.Critical),
        (Rx(@"powershell.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{20,}"), "Encoded PowerShell command", Severity.High),
        (Rx(@"FromBase64String"), "PowerShell base64 decode", Severity.Medium),
        (Rx(@"\b(IEX|Invoke-Expression)\b.*(DownloadString|DownloadData|Net\.WebClient|iwr|Invoke-WebRequest|irm)"), "PowerShell download-and-execute", Severity.Critical),
        (Rx(@"(DownloadString|DownloadFile|DownloadData)\s*\(\s*['""]?https?://"), "PowerShell download cradle", Severity.High),
        (Rx(@"Invoke-WebRequest|\biwr\s+https?://|Start-BitsTransfer"), "PowerShell download", Severity.Medium),
        (Rx(@"-(nop|noprofile)\b.*-(w|windowstyle)\s+(h|hidden)"), "Hidden PowerShell window", Severity.Medium),
        (Rx(@"(Set-MpPreference|Add-MpPreference).*(Disable|Exclusion)"), "Defender disabled / exclusion added", Severity.High),
        (Rx(@"certutil(\.exe)?.*(-urlcache|-verifyctl).*https?://"), "certutil download", Severity.High),
        (Rx(@"certutil(\.exe)?.*-decode"), "certutil decode", Severity.Medium),
        (Rx(@"bitsadmin(\.exe)?.*/(transfer|addfile).*https?://"), "bitsadmin download", Severity.High),
        (Rx(@"mshta(\.exe)?\s+(""|')?(https?|vbscript|javascript):"), "mshta remote/script execution", Severity.High),
        (Rx(@"regsvr32(\.exe)?.*/i:\s*https?://"), "regsvr32 remote scriptlet (Squiblydoo)", Severity.High),
        (Rx(@"rundll32(\.exe)?\s+.*javascript:"), "rundll32 script execution", Severity.High),
        (Rx(@"net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add"), "Local account created (net user /add)", Severity.High),
        (Rx(@"net1?(\.exe)?\s+localgroup\s+(administrators|""remote desktop users"")\s+\S+\s+/add"), "User added to admin/RDP group", Severity.High),
        (Rx(@"net1?(\.exe)?\s+group\s+""?domain admins""?\s+.*/add"), "User added to Domain Admins", Severity.Critical),
        (Rx(@"schtasks(\.exe)?\s+/create"), "Scheduled task created (schtasks)", Severity.Medium),
        (Rx(@"\bsc(\.exe)?\s+(\\\\\S+\s+)?create\s"), "Service created (sc)", Severity.Medium),
        (Rx(@"reg(\.exe)?\s+add\s+.*\\CurrentVersion\\Run"), "Run key added (reg add)", Severity.High),
        (Rx(@"reg(\.exe)?\s+add\s+.*(DisableAntiSpyware|DisableRealtimeMonitoring|fDenyTSConnections)"), "Security setting changed (reg add)", Severity.High),
        (Rx(@"netsh(\.exe)?\s+(advfirewall\s+set\s+\S+\s+state\s+off|firewall\s+set\s+opmode\s+disable)"), "Firewall disabled (netsh)", Severity.High),
        (Rx(@"netsh(\.exe)?\s+interface\s+portproxy\s+add"), "Port proxy added (netsh)", Severity.High),
        (Rx(@"\bnltest(\.exe)?\s+/(domain_trusts|dclist)"), "Domain discovery (nltest)", Severity.Medium),
        (Rx(@"\bwhoami(\.exe)?\s+/(all|priv|groups)"), "Privilege discovery (whoami)", Severity.Suspicious),
        (Rx(@"net1?(\.exe)?\s+(group\s+""?domain admins""?|user\s+/domain)"), "Domain account discovery (net)", Severity.Medium),
        (Rx(@"\b(7z|7za|rar|winrar)(\.exe)?\s+a\s.*(-p|-hp)"), "Password-protected archive created", Severity.High),
        (Rx(@"\brclone(\.exe)?\s+(copy|sync|move)"), "rclone transfer", Severity.Critical),
        (Rx(@"\\\\[^\\\s]+\\(ADMIN|C)\$\\"), "Admin share path in command", Severity.Medium),
        (Rx(@"Invoke-(Mimikatz|Kerberoast|ShareFinder|BloodHound|Portscan|SMBExec|WMIExec|TokenManipulation)"), "Offensive PowerShell function", Severity.Critical),
        (Rx(@"\bAmsiUtils\b|amsiInitFailed"), "AMSI bypass", Severity.Critical),
        (Rx(@"New-Object\s+(System\.)?Net\.Sockets\.TCPClient"), "PowerShell TCP client (reverse shell)", Severity.Critical),
    };

    private static Regex Rx(string p) => new(p, RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ExecutableExt = new(@"\.(exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|scr|sys|msi|cpl|lnk|jar|py)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ArchiveExt = new(@"\.(7z|zip|rar|tar|gz)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly string[] _extraKeywords;
    private readonly string[] _whitelist;

    public DetectionRules(AnalyserConfig config)
    {
        _extraKeywords = config.ExtraKeywords.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k.Trim()).ToArray();
        _whitelist = config.WhitelistPaths.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k.Trim()).ToArray();
    }

    public static string FileNameOf(string path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        var p = path.Trim().Trim('"');
        int i = p.LastIndexOfAny(new[] { '\\', '/' });
        return i >= 0 ? p[(i + 1)..] : p;
    }

    public bool IsWhitelisted(string path) =>
        !string.IsNullOrEmpty(path) && _whitelist.Any(w => path.Contains(w, StringComparison.OrdinalIgnoreCase));

    /// <summary>Known tool by file name (with or without extension, PsExec-style "-64" suffixes stripped).</summary>
    public ToolHit? MatchTool(string pathOrName)
    {
        var name = FileNameOf(pathOrName);
        if (name.Length == 0) return null;
        var stem = Path.GetFileNameWithoutExtension(name).ToLowerInvariant();
        var ext = Path.GetExtension(name).ToLowerInvariant();

        // Only executables, scripts and DLLs count — "nc.txt" or "everything.lnk" are not tools.
        if (ext.Length > 0 && !ExecutableExt.IsMatch(name)) return null;

        if (ToolIndex.TryGetValue(stem, out var hit)) return new ToolHit(stem, hit.Category, hit.Sev);
        // Prefixed names: "mimikatz_x64", "rclone-v1.65", "AnyDesk (1)"
        foreach (var t in Tools)
            if (t.Pattern.Length >= 5 && stem.StartsWith(t.Pattern, StringComparison.Ordinal))
                return new ToolHit(t.Pattern, t.Category, t.Sev);

        foreach (var k in _extraKeywords)
            if (name.Contains(k, StringComparison.OrdinalIgnoreCase))
                return new ToolHit(k, "Analyst keyword", Severity.High);
        return null;
    }

    /// <summary>Staging directory label when the path is in one, else null.</summary>
    public string? StagingDir(string path)
    {
        if (string.IsNullOrEmpty(path) || IsWhitelisted(path)) return null;
        foreach (var (rx, label) in StagingDirs)
            if (rx.IsMatch(path)) return label;
        return null;
    }

    private static readonly Regex PathInText = new(
        @"(?:[A-Za-z]:|%[A-Za-z]+%|\\\\[^\\\s""]+\\[^\\\s""]+)\\[^""|<>*?\r\n]*?\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|jar|py|msi)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Executable/script paths mentioned in free text (registry data, task actions).</summary>
    public static IEnumerable<string> ExtractPaths(string text)
    {
        if (string.IsNullOrEmpty(text)) yield break;
        foreach (Match m in PathInText.Matches(text)) yield return m.Value;
    }

    public static bool IsDownloads(string path) => DownloadsDir.IsMatch(path ?? "");
    public static bool IsExecutable(string path) => ExecutableExt.IsMatch(path ?? "");
    public static bool IsArchive(string path) => ArchiveExt.IsMatch(path ?? "");

    /// <summary>All command-line techniques seen in a command line / script block.</summary>
    public List<CmdHit> MatchCommandLine(string cmd)
    {
        var hits = new List<CmdHit>();
        if (string.IsNullOrWhiteSpace(cmd)) return hits;
        foreach (var (rx, label, sev) in CmdPatterns)
            if (rx.IsMatch(cmd)) hits.Add(new CmdHit(label, sev));
        foreach (var k in _extraKeywords)
            if (cmd.Contains(k, StringComparison.OrdinalIgnoreCase))
                hits.Add(new CmdHit($"Analyst keyword '{k}'", Severity.High));
        return hits;
    }

    /// <summary>
    /// Scores an executed or present binary by its path: known tool, staging
    /// directory, or both. Null when nothing is notable.
    /// </summary>
    public (Severity Sev, string Reason)? ScoreBinaryPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || IsWhitelisted(path)) return null;
        var tool = MatchTool(path);
        var dir = StagingDir(path);

        if (tool != null)
        {
            var sev = tool.Severity;
            // A known tool run from a staging directory is worse than one installed normally
            if (dir != null && sev > Severity.Critical) sev -= 1;
            return (sev, dir != null ? $"{tool.Category} in {dir}" : tool.Category);
        }
        if (dir != null && IsExecutable(path))
            return (Severity.Medium, $"Executable in {dir}");
        return null;
    }

    // ── Network helpers ──────────────────────────────────────────────
    /// <summary>Dotted-quad IPv4 or IPv6 (IPAddress.TryParse alone accepts "10" as 0.0.0.10).</summary>
    public static bool IsIp(string? s) =>
        !string.IsNullOrWhiteSpace(s)
        && (s.Count(c => c == '.') == 3 || s.Contains(':'))
        && System.Net.IPAddress.TryParse(s.Trim(), out _);

    /// <summary>
    /// True for addresses outside private, loopback, link-local, CGNAT and
    /// multicast ranges. Documentation ranges (203.0.113.0/24 etc.) count as
    /// external so test cases behave like real attacker IPs.
    /// </summary>
    public static bool IsExternalIp(string s)
    {
        if (!IsIp(s) || !System.Net.IPAddress.TryParse(s, out var ip)) return false;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            else return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || System.Net.IPAddress.IsLoopback(ip)
                          || s!.StartsWith("fc", StringComparison.OrdinalIgnoreCase) || s.StartsWith("fd", StringComparison.OrdinalIgnoreCase)
                          || s == "::");
        }
        var b = ip.GetAddressBytes();
        if (b[0] == 10 || b[0] == 127 || b[0] == 0) return false;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
        if (b[0] == 192 && b[1] == 168) return false;
        if (b[0] == 169 && b[1] == 254) return false;
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
        if (b[0] >= 224) return false;
        return true;
    }

    public static bool IsUsableIp(string s) =>
        IsIp(s) && s != "-" && s != "::1" && s != "127.0.0.1" && s != "0.0.0.0" && s != "::";
}
