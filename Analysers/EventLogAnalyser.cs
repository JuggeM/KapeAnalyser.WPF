using System.Text.Json;
using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>
/// EvtxECmd output (*_EvtxECmd_Output.csv). Event data is read from the
/// Payload column (the event XML as JSON) so field names are exact rather
/// than depending on EvtxECmd map wording; the JSON is only parsed for the
/// event IDs below, so multi-GB files stay fast.
/// </summary>
public sealed class EventLogAnalyser : IArtifactAnalyser
{
    public string Source => "EVTX";
    public string Module => "EvtxECmd";
    public bool Enabled(AnalyserConfig c) => c.AnalyseEventLogs;
    public bool Accepts(string f) => f.EndsWith("_EvtxECmd_Output.csv", StringComparison.OrdinalIgnoreCase);

    private static readonly HashSet<int> Interesting = new()
    {
        // Security
        1102, 4624, 4625, 4648, 4662, 4688, 4697, 4698, 4719, 4720, 4722, 4724, 4726, 4728, 4732, 4741, 4742, 4756, 4769, 4771, 4776, 4781, 5136, 5140, 5145,
        // System
        104, 7045,
        // RDP
        21, 25, 1149,
        // PowerShell
        400, 600, 800, 4104,
        // Defender
        1006, 1015, 1116, 1117, 5001, 5007, 5010, 5012,
        // Sysmon
        1, 3, 10, 11, 13,
        // Task scheduler, WMI, BITS
        106, 200, 201, 5861, 59,
    };

    private static readonly HashSet<string> AdminGroups = new(StringComparer.OrdinalIgnoreCase)
    {
        "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", "Remote Desktop Users",
        "Backup Operators", "Account Operators", "Server Operators", "DnsAdmins", "Group Policy Creator Owners",
        "Remote Management Users", "Administratoren", "Administrateurs", "Administratörer",
    };

    private readonly FindingAggregator _agg = new();
    private readonly Dictionary<string, (int Count, DateTime? First, DateTime? Last, HashSet<string> Users)> _failures = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Src, string User, DateTime? Time, string Type)> _successes = new();
    private readonly Dictionary<string, (HashSet<string> Services, DateTime? First, DateTime? Last)> _rc4Tickets = new(StringComparer.OrdinalIgnoreCase);

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cTime = csv.Col("TimeCreated"), cId = csv.Col("EventId"), cChan = csv.Col("Channel"),
            cProv = csv.Col("Provider"), cComp = csv.Col("Computer"), cPayload = csv.Col("Payload"),
            cSrc = csv.Col("SourceFile"), cMap = csv.Col("MapDescription");
        if (cId < 0 || cTime < 0) { ctx.Log($"[WARN] {Path.GetFileName(csvPath)}: not an EvtxECmd file (no EventId/TimeCreated)."); return; }

        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);
        var computerCounts = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

        while (csv.Read())
        {
            if ((csv.RowNumber & 0x3FFF) == 0) ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var time = CsvReader.ParseTime(csv[cTime]);
            cov.See(time);

            var comp = csv[cComp];
            if (comp.Length > 0) computerCounts[comp] = computerCounts.GetValueOrDefault(comp) + 1;

            if (!int.TryParse(csv[cId], out var id) || !Interesting.Contains(id)) continue;

            var ev = new Ev(time, id, csv[cChan], csv[cProv], csv[cPayload], ShortArtifact(csv[cSrc], csv[cChan]), csv[cMap]);
            try { Handle(ev, ctx); }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException) { /* malformed payload row */ }
        }

        foreach (var (name, n) in computerCounts) ctx.VoteHostname(name, n);
    }

    private sealed record Ev(DateTime? Time, int Id, string Channel, string Provider, string PayloadJson, string Artifact, string Map)
    {
        private Dictionary<string, string>? _data;
        public Dictionary<string, string> Data => _data ??= FlattenPayload(PayloadJson);
        public string D(string key) => Data.TryGetValue(key, out var v) ? v.Trim() : string.Empty;
        public bool Is(string channelFragment) => Channel.Contains(channelFragment, StringComparison.OrdinalIgnoreCase)
                                                  || Provider.Contains(channelFragment, StringComparison.OrdinalIgnoreCase);
    }

    private void Handle(Ev e, AnalysisContext ctx)
    {
        bool security = e.Channel.Equals("Security", StringComparison.OrdinalIgnoreCase);
        bool system = e.Channel.Equals("System", StringComparison.OrdinalIgnoreCase);

        if (security)
        {
            switch (e.Id)
            {
                case 4624: Logon(e, ctx); return;
                case 4625: Failure(e, e.D("IpAddress"), e.D("WorkstationName"), e.D("TargetUserName"), "4625"); return;
                case 4771: Failure(e, StripIpPrefix(e.D("IpAddress")), "", e.D("TargetUserName"), "4771"); return;
                case 4776:
                    if (e.D("Status") is "0x0" or "0" or "") return;
                    Failure(e, "", e.D("Workstation"), e.D("TargetUserName"), "4776"); return;
                case 4648: ExplicitCreds(e); return;
                case 4688: Process(e, ctx, e.D("NewProcessName"), e.D("CommandLine"), e.D("ParentProcessName"), e.D("SubjectUserName"), "4688"); return;
                case 4697: Service(e, ctx, e.D("ServiceName"), e.D("ServiceFileName"), e.D("ServiceAccount"), "4697"); return;
                case 4698: Task(e, ctx); return;
                case 4720:
                    if (e.D("TargetSid").StartsWith("S-1-", StringComparison.Ordinal))
                        _sidNames[e.D("TargetSid")] = Acct(e.D("TargetDomainName"), e.D("TargetUserName"));
                    Add(e, Severity.High, "Account created", $"Account created: {Acct(e.D("TargetDomainName"), e.D("TargetUserName"))} by {e.D("SubjectUserName")}");
                    return;
                case 4722: Add(e, Severity.Medium, "Account enabled", $"Account enabled: {e.D("TargetUserName")} by {e.D("SubjectUserName")}"); return;
                case 4724: Add(e, Severity.Medium, "Password reset", $"Password reset for {e.D("TargetUserName")} by {e.D("SubjectUserName")}"); return;
                case 4726: Add(e, Severity.Medium, "Account deleted", $"Account deleted: {e.D("TargetUserName")} by {e.D("SubjectUserName")}"); return;
                case 4781: Add(e, Severity.Medium, "Account renamed", $"Account renamed: {e.D("OldTargetUserName")} → {e.D("NewTargetUserName")} by {e.D("SubjectUserName")}"); return;
                case 4728 or 4732 or 4756: GroupAdd(e); return;
                case 4719: Add(e, Severity.Medium, "Audit policy changed", $"Audit policy changed by {e.D("SubjectUserName")}: {e.D("CategoryId")} {e.D("SubcategoryGuid")}".Trim()); return;
                case 1102:
                    Add(e, Severity.Critical, "Security log cleared",
                        $"Security event log cleared by {FirstNonEmpty(e.D("SubjectUserName"), "unknown user")}");
                    return;
                case 4769: Kerberos(e); return;
                case 5140 or 5145: Share(e, ctx); return;
                case 4662: DirectoryAccess(e); return;
                case 5136: DirectoryChange(e); return;
                case 4741 or 4742: ComputerAccount(e); return;
            }
            return;
        }

        if (system)
        {
            if (e.Id == 7045) Service(e, ctx, e.D("ServiceName"), e.D("ImagePath"), e.D("AccountName"), "7045");
            else if (e.Id == 104)
                Add(e, Severity.High, "Event log cleared",
                    $"Event log '{FirstNonEmpty(e.D("Channel"), "?")}' cleared by {FirstNonEmpty(e.D("SubjectUserName"), "unknown user")}");
            return;
        }

        if (e.Is("RemoteConnectionManager") && e.Id == 1149)
        {
            var user = Acct(e.D("Param2"), e.D("Param1"));
            Rdp(e, ctx, user, e.D("Param3"), "RDP 1149");
            return;
        }
        if (e.Is("LocalSessionManager") && e.Id is 21 or 25)
        {
            var addr = e.D("Address");
            if (!DetectionRules.IsUsableIp(addr)) return;
            Rdp(e, ctx, e.D("User"), addr, e.Id == 21 ? "RDP 21" : "RDP 25");
            return;
        }

        if (e.Is("PowerShell"))
        {
            if (e.Id == 4104) ScriptBlock(e, ctx);
            else if (e.Id is 400 or 600 or 800) HostApplication(e, ctx);
            return;
        }

        if (e.Is("Windows Defender"))
        {
            Defender(e);
            return;
        }

        if (e.Is("Sysmon"))
        {
            Sysmon(e, ctx);
            return;
        }

        if (e.Is("TaskScheduler"))
        {
            if (e.Id == 106)
                _agg.Add($"task106|{e.D("TaskName")}", Severity.Suspicious, e.Time, Source, "Scheduled task registered",
                    $"Scheduled task registered: {e.D("TaskName")} (by {e.D("UserContext")})", artifact: e.Artifact);
            else if (e.Id is 200 or 201)
            {
                var action = e.D("ActionName");
                var score = ctx.Rules.ScoreBinaryPath(action);
                if (score != null)
                    _agg.Add($"task200|{e.D("TaskName")}|{action}", score.Value.Sev, e.Time, Source, "Scheduled task ran suspicious binary",
                        $"Scheduled task {e.D("TaskName")} ran {action} — {score.Value.Reason}", artifact: e.Artifact);
            }
            return;
        }

        if (e.Is("WMI-Activity") && e.Id == 5861)
        {
            var consumer = FirstNonEmpty(e.D("CONSUMER"), e.D("Consumer"));
            _agg.Add($"wmi|{consumer}", Severity.High, e.Time, Source, "WMI permanent event subscription",
                $"WMI permanent event subscription: {Trunc(consumer, 160)}", Trunc(e.D("PossibleCause"), 500), e.Artifact);
            return;
        }

        if (e.Is("Bits-Client") && e.Id == 59)
        {
            var url = e.D("url");
            if (url.Length == 0 || BenignBitsHost.IsMatch(url)) return;
            _agg.Add($"bits|{url}", Severity.Suspicious, e.Time, Source, "BITS transfer",
                $"BITS transfer '{e.D("name")}' from {Trunc(url, 200)}", artifact: e.Artifact);
        }
    }

    private static readonly Regex BenignBitsHost = new(
        @"^https?://([^/]*\.)?(microsoft\.com|windowsupdate\.com|windows\.com|office\.com|office\.net|msedge\.net|live\.com|bing\.com|google\.com|googleapis\.com|gvt1\.com|adobe\.com|mozilla\.net|dropbox\.com|skype\.com|azureedge\.net|digicert\.com)(/|:|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ── Logons ───────────────────────────────────────────────────────
    private void Logon(Ev e, AnalysisContext ctx)
    {
        var user = e.D("TargetUserName");
        if (user.EndsWith("$") || user is "ANONYMOUS LOGON" or "SYSTEM" or "LOCAL SERVICE" or "NETWORK SERVICE" or "DWM-1" or "UMFD-0" or "UMFD-1") return;
        var type = e.D("LogonType");
        var ip = e.D("IpAddress");
        var ws = e.D("WorkstationName");
        var acct = Acct(e.D("TargetDomainName"), user);

        if (type is "3" or "10" or "8" or "9")
        {
            ctx.RecordLogon(acct, LogonTypeName(type), ws, ip, "4624", e.Time);
            var src = SourceKey(ip, ws);
            if (src.Length > 0) _successes.Add((src, acct, e.Time, type));
        }

        bool external = DetectionRules.IsExternalIp(ip);
        switch (type)
        {
            case "10":
                Rdp(e, ctx, acct, ip, null);
                break;
            case "3" when external:
                _agg.Add($"net-ext|{acct}|{ip}", Severity.High, e.Time, Source, "Network logon from external IP",
                    $"Network logon (type 3) for {acct} from external IP {ip}" + (ws.Length > 0 && ws != "-" ? $" ({ws})" : ""), artifact: e.Artifact);
                break;
            case "9" when e.D("LogonProcessName").StartsWith("seclogo", StringComparison.OrdinalIgnoreCase):
                _agg.Add($"type9|{acct}|{e.D("SubjectUserName")}", Severity.Medium, e.Time, Source, "Logon with new credentials (type 9)",
                    $"Logon type 9 (runas /netonly or pass-the-hash) as {acct} by {e.D("SubjectUserName")}, process {DetectionRules.FileNameOf(e.D("ProcessName"))}",
                    artifact: e.Artifact);
                break;
            case "8":
                _agg.Add($"type8|{acct}|{ip}", Severity.Suspicious, e.Time, Source, "Cleartext network logon (type 8)",
                    $"Cleartext network logon (type 8) for {acct} from {SourceKey(ip, ws)}", artifact: e.Artifact);
                break;
        }
    }

    private void Rdp(Ev e, AnalysisContext ctx, string user, string ip, string? via)
    {
        if (via != null) ctx.RecordLogon(user, "RemoteInteractive", "", ip, via, e.Time);
        if (!DetectionRules.IsUsableIp(ip)) return;
        bool external = DetectionRules.IsExternalIp(ip);
        _agg.Add($"rdp|{user.ToLowerInvariant()}|{ip}", external ? Severity.High : Severity.Medium, e.Time, Source,
            external ? "RDP logon from external IP" : "RDP logon",
            $"RDP logon for {user} from {(external ? "external IP " : "")}{ip}", artifact: e.Artifact);
    }

    private void Failure(Ev e, string ip, string ws, string user, string via)
    {
        var src = SourceKey(StripIpPrefix(ip), ws);
        if (src.Length == 0) return;
        _failures.TryGetValue(src, out var f);
        f.Users ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        f.Count++;
        if (e.Time.HasValue)
        {
            if (f.First == null || e.Time < f.First) f.First = e.Time;
            if (f.Last == null || e.Time > f.Last) f.Last = e.Time;
        }
        if (f.Users.Count < 50 && user.Length > 0) f.Users.Add(user);
        _failures[src] = f;
    }

    private void ExplicitCreds(Ev e)
    {
        var server = e.D("TargetServerName");
        if (server is "" or "localhost" or "-") return;
        var subj = e.D("SubjectUserName");
        if (subj.EndsWith("$")) return;
        var target = Acct(e.D("TargetDomainName"), e.D("TargetUserName"));
        _agg.Add($"4648|{subj}|{target}|{server}", Severity.Suspicious, e.Time, Source, "Explicit credentials used",
            $"Explicit credentials: {subj} used {target} for {server} via {DetectionRules.FileNameOf(e.D("ProcessName"))}",
            artifact: e.Artifact);
    }

    // Local group adds (4732) carry only the member SID; resolved in Complete()
    // from 4720 events, which may come later in the file or in another file.
    private readonly Dictionary<string, string> _sidNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(Ev E, string Group, string Name, string Sid)> _groupAdds = new();

    private void GroupAdd(Ev e) =>
        _groupAdds.Add((e, e.D("TargetUserName"), CnOf(e.D("MemberName")), e.D("MemberSid")));

    private void FlushGroupAdds()
    {
        foreach (var (e, group, name, sid) in _groupAdds)
        {
            var member = name.Length > 0 && name != "-" ? name
                : _sidNames.TryGetValue(sid, out var n) ? $"{n} ({sid})" : FirstNonEmpty(sid, "?");
            bool admin = AdminGroups.Contains(group);
            Add(e, admin ? Severity.High : Severity.Medium, admin ? "Added to privileged group" : "Added to group",
                $"{member} added to group '{group}' by {e.D("SubjectUserName")}");
        }
        _groupAdds.Clear();
    }

    // ── Domain controller ────────────────────────────────────────────
    // Replication rights: DS-Replication-Get-Changes(-All / -In-Filtered-Set)
    private static readonly Regex ReplicationGuids = new(
        @"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>4662 with replication rights from a user (not a DC computer account) = DCSync.</summary>
    private void DirectoryAccess(Ev e)
    {
        var props = e.D("Properties");
        if (!ReplicationGuids.IsMatch(props)) return;
        var who = e.D("SubjectUserName");
        if (who.EndsWith("$") || who.Length == 0) return;
        _agg.Add($"dcsync|{who}", Severity.Critical, e.Time, Source, "DCSync (directory replication by a user)",
            $"DCSync: {Acct(e.D("SubjectDomainName"), who)} requested directory replication (password hashes) from this DC",
            Trunc(props, 400), e.Artifact);
    }

    /// <summary>5136 directory changes that grant persistence or escalation.</summary>
    private void DirectoryChange(Ev e)
    {
        var dn = e.D("ObjectDN");
        var attr = e.D("AttributeLDAPDisplayName");
        var who = e.D("SubjectUserName");
        if (who.EndsWith("$")) return;
        var value = Trunc(e.D("AttributeValue"), 300);
        (Severity Sev, string Category, string Text)? hit =
            dn.Contains("CN=AdminSDHolder", StringComparison.OrdinalIgnoreCase)
                ? (Severity.Critical, "AdminSDHolder modified", $"AdminSDHolder changed ({attr}) by {who} — persists rights on every admin account")
            : attr.Equals("msDS-AllowedToActOnBehalfOfOtherIdentity", StringComparison.OrdinalIgnoreCase)
                ? (Severity.High, "Resource-based delegation set", $"Resource-based constrained delegation set on {CnOf(dn)} by {who}")
            : attr.Equals("msDS-KeyCredentialLink", StringComparison.OrdinalIgnoreCase)
                ? (Severity.High, "Shadow credentials", $"msDS-KeyCredentialLink written on {CnOf(dn)} by {who} (shadow credentials)")
            : attr.Equals("servicePrincipalName", StringComparison.OrdinalIgnoreCase) && e.D("ObjectClass").Equals("user", StringComparison.OrdinalIgnoreCase)
                ? (Severity.Medium, "SPN added to user", $"SPN set on user {CnOf(dn)} by {who} (targeted Kerberoasting?)")
            : dn.Contains("CN=Policies,CN=System", StringComparison.OrdinalIgnoreCase) && attr is "gPCFileSysPath" or "gPCMachineExtensionNames" or "gPCUserExtensionNames" or "versionNumber"
                ? (Severity.Medium, "Group Policy changed", $"Group Policy {CnOf(dn)} changed ({attr}) by {who}")
            : null;
        if (hit == null) return;
        _agg.Add($"5136|{hit.Value.Category}|{dn}|{who}", hit.Value.Sev, e.Time, Source, hit.Value.Category, hit.Value.Text,
            value.Length > 0 ? $"{attr} = {value}" : dn, e.Artifact);
    }

    /// <summary>4741/4742 by a user: machine account quota abuse, delegation set on a computer.</summary>
    private void ComputerAccount(Ev e)
    {
        var who = e.D("SubjectUserName");
        if (who.EndsWith("$") || who.Length == 0) return;
        var computer = e.D("TargetUserName");
        if (e.Id == 4741)
        {
            Add(e, Severity.Medium, "Computer account created by user",
                $"Computer account {computer} created by {who} (machine account quota — used for RBCD / noPac)");
            return;
        }
        var deleg = e.D("AllowedToDelegateTo");
        var uac = e.D("UserAccountControl");
        if (deleg.Length > 0 && deleg != "-")
            Add(e, Severity.High, "Delegation set on computer", $"Constrained delegation set on {computer} by {who}", deleg);
        else if (uac.Contains("%%2087") || uac.Contains("Trusted For Delegation", StringComparison.OrdinalIgnoreCase))
            Add(e, Severity.High, "Delegation set on computer", $"Unconstrained delegation enabled on {computer} by {who}", uac);
    }

    private void Kerberos(Ev e)
    {
        var enc = e.D("TicketEncryptionType");
        var svc = e.D("ServiceName");
        if (enc is "0x1" or "0x3" && !svc.EndsWith("$"))
        {
            _agg.Add($"des|{e.D("TargetUserName")}|{svc}", Severity.Medium, e.Time, Source, "DES Kerberos ticket",
                $"DES-encrypted service ticket for {svc} requested by {e.D("TargetUserName")} (weak encryption, crackable)", artifact: e.Artifact);
            return;
        }
        if (enc is not ("0x17" or "0x18") || svc.EndsWith("$") || svc.Equals("krbtgt", StringComparison.OrdinalIgnoreCase)) return;
        var who = e.D("TargetUserName");
        _rc4Tickets.TryGetValue(who, out var r);
        r.Services ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        r.Services.Add(svc);
        if (e.Time.HasValue) { if (r.First == null || e.Time < r.First) r.First = e.Time; if (r.Last == null || e.Time > r.Last) r.Last = e.Time; }
        _rc4Tickets[who] = r;
    }

    private void Share(Ev e, AnalysisContext ctx)
    {
        var share = e.D("ShareName");
        if (!(share.EndsWith("ADMIN$", StringComparison.OrdinalIgnoreCase) || share.EndsWith("C$", StringComparison.OrdinalIgnoreCase))) return;
        var ip = e.D("IpAddress");
        if (!DetectionRules.IsUsableIp(ip)) return;
        var user = Acct(e.D("SubjectDomainName"), e.D("SubjectUserName"));
        if (user.EndsWith("$")) return;
        ctx.RecordLogon(user, "AdminShare", "", ip, e.Id.ToString(), e.Time);
        _agg.Add($"share|{user}|{ip}|{share}", Severity.Medium, e.Time, Source, "Admin share accessed",
            $"Admin share {share} accessed by {user} from {ip}",
            artifact: e.Artifact, extra: e.D("RelativeTargetName"));
    }

    // ── Execution / persistence ──────────────────────────────────────
    private void Process(Ev e, AnalysisContext ctx, string image, string cmd, string parent, string user, string via)
    {
        var hits = ctx.Rules.MatchCommandLine(cmd);
        var tool = ctx.Rules.ScoreBinaryPath(image);
        var p = DetectionRules.FileNameOf(parent).ToLowerInvariant();
        var c = DetectionRules.FileNameOf(image).ToLowerInvariant();
        var lineage = ParentRule(p, c, cmd);

        if (hits.Count == 0 && tool == null)
        {
            // A web server, Office or WMI starting a shell is worth a look without any other pattern
            if (lineage != null)
                _agg.Add($"proc|{p}|{c}|{cmd}", lineage.Value.Sev, e.Time, Source, lineage.Value.Category,
                    $"{lineage.Value.Category}: {p} started {c} (user {user}, {via})", Trunc(FirstNonEmpty(cmd, image), 1000), e.Artifact);
            return;
        }

        var sev = hits.Select(h => h.Severity).Append(tool?.Sev ?? Severity.Suspicious).Min();
        var label = hits.Count > 0 ? string.Join(", ", hits.Select(h => h.Label).Distinct()) : tool!.Value.Reason;
        if (lineage != null)
        {
            // The parent makes a known pattern worse: whoami from w3wp is a webshell, not an admin
            if (lineage.Value.Sev < sev) sev = lineage.Value.Sev;
            label += $" ({lineage.Value.Category.ToLowerInvariant()}: {p})";
        }
        _agg.Add($"proc|{label}|{cmd}|{image}", sev, e.Time, Source, hits.Count > 0 ? hits[0].Label : tool!.Value.Reason,
            $"{label}: {DetectionRules.FileNameOf(image)} by {user} ({via})", Trunc(FirstNonEmpty(cmd, image), 1000), e.Artifact);
    }

    private static readonly Regex WebshellCommand = new(
        @"\b(whoami|net1?\s+(user|group|localgroup)|ipconfig|systeminfo|nltest|quser|query\s+user|tasklist|hostname|certutil|bitsadmin|powershell|curl|wget|Invoke-WebRequest|echo\s+.+>\s*\S+\.(jsp|aspx?|php))\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly HashSet<string> WebServers = new(StringComparer.OrdinalIgnoreCase)
        { "w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "php.exe", "tomcat.exe", "tomcat7.exe", "tomcat8.exe", "tomcat9.exe", "tomcat10.exe", "tomcat11.exe", "java.exe", "javaw.exe", "node.exe", "sqlservr.exe" };
    private static readonly HashSet<string> OfficeApps = new(StringComparer.OrdinalIgnoreCase)
        { "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe", "acrord32.exe", "acrobat.exe", "hwp.exe" };
    private static readonly HashSet<string> ShellChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "certutil.exe", "bitsadmin.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "curl.exe", "schtasks.exe",
        "wmic.exe", "msbuild.exe", "installutil.exe", "systeminfo.exe", "ipconfig.exe", "tasklist.exe", "quser.exe", "reg.exe",
    };

    /// <summary>
    /// Parent → child pairs that mean code execution through something that
    /// should never start a shell: a webshell (web server), a malicious
    /// document (Office), remote WMI execution (wmiprvse), or the print spooler.
    /// </summary>
    internal static (Severity Sev, string Category)? ParentRule(string parent, string child, string cmd = "")
    {
        if (parent.Length == 0 || !ShellChildren.Contains(child)) return null;
        // java.exe / node.exe start cmd for build tools too: there, only a recon or download command counts
        if (parent is "java.exe" or "javaw.exe" or "node.exe" && child is "cmd.exe" or "reg.exe" or "tasklist.exe"
            && !WebshellCommand.IsMatch(cmd)) return null;
        if (WebServers.Contains(parent)) return (Severity.Critical, "Web server started a shell");
        if (OfficeApps.Contains(parent)) return (Severity.High, "Office document started a shell");
        if (parent is "wmiprvse.exe" && child is "cmd.exe" or "powershell.exe" or "pwsh.exe" or "rundll32.exe" or "mshta.exe")
            return (Severity.High, "WMI started a shell (remote execution)");
        if (parent is "spoolsv.exe") return (Severity.Critical, "Print spooler started a shell");
        if (parent is "wscript.exe" or "cscript.exe" or "mshta.exe" && child is "powershell.exe" or "pwsh.exe" or "cmd.exe" or "rundll32.exe" or "regsvr32.exe")
            return (Severity.Medium, "Script host started a shell");
        return null;
    }

    private void Service(Ev e, AnalysisContext ctx, string name, string imagePath, string account, string via)
    {
        var hits = ctx.Rules.MatchCommandLine(imagePath);
        var score = ctx.Rules.ScoreBinaryPath(ExtractExe(imagePath));
        Severity sev = Severity.Suspicious;
        var reasons = new List<string>();

        if (hits.Count > 0) { sev = hits.Min(h => h.Severity); reasons.AddRange(hits.Select(h => h.Label)); }
        if (score != null) { if (score.Value.Sev < sev) sev = score.Value.Sev; reasons.Add(score.Value.Reason); }
        if (Regex.IsMatch(name, @"^(PSEXESVC|PAExec|RemCom|csexecsvc|BTOBTO)", RegexOptions.IgnoreCase)
            || imagePath.Contains("\\ADMIN$", StringComparison.OrdinalIgnoreCase))
        {
            if (Severity.High < sev) sev = Severity.High;
            if (!reasons.Any(r => r.Contains("Remote execution", StringComparison.OrdinalIgnoreCase))) reasons.Add("remote execution service");
        }
        if (Regex.IsMatch(imagePath, @"(powershell|pwsh|cmd(\.exe)?\s*/c|mshta|rundll32|regsvr32|wscript|cscript)", RegexOptions.IgnoreCase))
        { if (Severity.High < sev) sev = Severity.High; reasons.Add("service runs a shell/LOLBin"); }
        if (Regex.IsMatch(name, @"^[A-Za-z]{8}$|^[A-Za-z0-9]{16,}$") && !Regex.IsMatch(name, @"[aeiou]{1}.*[aeiou]", RegexOptions.IgnoreCase))
        { reasons.Add("random-looking service name"); if (Severity.Medium < sev) sev = Severity.Medium; }

        var why = reasons.Count > 0 ? " — " + string.Join(", ", reasons.Distinct()) : "";
        _agg.Add($"svc|{name}|{imagePath}", sev, e.Time, Source, sev <= Severity.High ? "Suspicious service installed" : "Service installed",
            $"Service installed ({via}): {name}{(account.Length > 0 ? $" as {account}" : "")}{why}", Trunc(imagePath, 1000), e.Artifact);
    }

    private void Task(Ev e, AnalysisContext ctx)
    {
        var name = e.D("TaskName");
        var xml = e.D("TaskContent");
        var cmd = string.Join(" ", Regex.Matches(xml, @"<(Command|Arguments)>(.*?)</\1>", RegexOptions.Singleline | RegexOptions.IgnoreCase)
                                      .Select(m => System.Net.WebUtility.HtmlDecode(m.Groups[2].Value)));
        var hits = ctx.Rules.MatchCommandLine(cmd);
        var score = ctx.Rules.ScoreBinaryPath(ExtractExe(cmd));
        var sev = Severity.Medium;
        var reasons = hits.Select(h => h.Label).ToList();
        if (hits.Count > 0) sev = (Severity)Math.Min((int)sev, (int)hits.Min(h => h.Severity));
        if (score != null) { sev = (Severity)Math.Min((int)sev, (int)score.Value.Sev); reasons.Add(score.Value.Reason); }
        if (Regex.IsMatch(cmd, @"(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|cmd(\.exe)?\s*/c)", RegexOptions.IgnoreCase))
        { sev = (Severity)Math.Min((int)sev, (int)Severity.High); reasons.Add("task runs a shell/LOLBin"); }

        _agg.Add($"4698|{name}|{cmd}", sev, e.Time, Source, sev <= Severity.High ? "Suspicious scheduled task created" : "Scheduled task created",
            $"Scheduled task created: {name} by {e.D("SubjectUserName")}" + (reasons.Count > 0 ? " — " + string.Join(", ", reasons.Distinct()) : ""),
            Trunc(cmd, 1000), e.Artifact);
    }

    private void ScriptBlock(Ev e, AnalysisContext ctx)
    {
        var text = e.D("ScriptBlockText");
        var hits = ctx.Rules.MatchCommandLine(text);
        if (hits.Count == 0) return;
        var label = string.Join(", ", hits.Select(h => h.Label).Distinct());
        var path = e.D("Path");
        _agg.Add($"4104|{label}|{Trunc(text, 300)}", hits.Min(h => h.Severity), e.Time, Source, hits[0].Label,
            $"PowerShell script block: {label}" + (path.Length > 0 ? $" ({DetectionRules.FileNameOf(path)})" : ""),
            Trunc(text, 1000), e.Artifact);
    }

    private static readonly Regex HostAppRx = new(@"HostApplication=(.+?)(?:\\r|\\n|\\t|\r|\n|\t|""|$)", RegexOptions.Compiled);

    private void HostApplication(Ev e, AnalysisContext ctx)
    {
        var m = HostAppRx.Match(e.PayloadJson);
        if (!m.Success) return;
        var cmd = m.Groups[1].Value.Replace("\\\\", "\\");
        var hits = ctx.Rules.MatchCommandLine(cmd);
        if (hits.Count == 0) return;
        var label = string.Join(", ", hits.Select(h => h.Label).Distinct());
        _agg.Add($"psh|{label}|{cmd}", hits.Min(h => h.Severity), e.Time, Source, hits[0].Label,
            $"PowerShell started: {label}", Trunc(cmd, 1000), e.Artifact);
    }

    private void Defender(Ev e)
    {
        switch (e.Id)
        {
            case 1006 or 1015 or 1116 or 1117:
            {
                var threat = FirstNonEmpty(e.D("Threat Name"), e.D("ThreatName"), e.D("Name"));
                var path = FirstNonEmpty(e.D("Path"), e.D("Path Name"));
                var action = FirstNonEmpty(e.D("Action Name"), e.D("Action"));
                _agg.Add($"def|{threat}|{path}", Severity.High, e.Time, Source, "Defender detection",
                    $"Defender detection: {threat}" + (action.Length > 0 && action != "%%887" ? $" (action: {action})" : "") +
                    (e.D("Detection User").Length > 0 ? $", user {e.D("Detection User")}" : ""),
                    Trunc(path, 1000), e.Artifact);
                break;
            }
            case 5001:
                Add(e, Severity.High, "Defender disabled", "Defender real-time protection disabled");
                break;
            case 5010 or 5012:
                Add(e, Severity.High, "Defender disabled", $"Defender {(e.Id == 5010 ? "antispyware" : "antivirus")} scanning disabled");
                break;
            case 5007:
            {
                var nv = e.D("New Value");
                if (nv.Contains("Exclusions", StringComparison.OrdinalIgnoreCase))
                    _agg.Add($"def5007|{nv}", Severity.High, e.Time, Source, "Defender exclusion added",
                        "Defender configuration changed: exclusion added", Trunc(nv, 1000), e.Artifact);
                else if (Regex.IsMatch(nv, @"(DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|DisableIOAVProtection|TamperProtection)\s*=\s*0x[1-9]", RegexOptions.IgnoreCase))
                    _agg.Add($"def5007|{nv}", Severity.High, e.Time, Source, "Defender disabled",
                        "Defender protection setting disabled", Trunc(nv, 1000), e.Artifact);
                break;
            }
        }
    }

    private void Sysmon(Ev e, AnalysisContext ctx)
    {
        switch (e.Id)
        {
            case 1:
                Process(e, ctx, e.D("Image"), e.D("CommandLine"), e.D("ParentImage"), e.D("User"), "Sysmon 1");
                break;
            case 3:
            {
                var ip = e.D("DestinationIp");
                var image = e.D("Image");
                if (!DetectionRules.IsExternalIp(ip)) break;
                var score = ctx.Rules.ScoreBinaryPath(image);
                if (score == null) break;
                _agg.Add($"sys3|{image}|{ip}", score.Value.Sev, e.Time, Source, "Outbound connection from suspicious binary",
                    $"{DetectionRules.FileNameOf(image)} connected to {ip}:{e.D("DestinationPort")} — {score.Value.Reason}", image, e.Artifact);
                break;
            }
            case 10:
            {
                if (!e.D("TargetImage").EndsWith("lsass.exe", StringComparison.OrdinalIgnoreCase)) break;
                var src = e.D("SourceImage");
                if (Regex.IsMatch(src, @"\\Windows\\System32\\(wininit|csrss|services|svchost|lsm|wbem\\wmiprvse|MsMpEng)\.exe$|\\Windows Defender\\|\\Microsoft\\Windows Defender\\|MsMpEng\.exe$|\\CrowdStrike\\", RegexOptions.IgnoreCase)
                    || ctx.Rules.IsWhitelisted(src)) break;
                _agg.Add($"sys10|{src}", Severity.High, e.Time, Source, "LSASS access",
                    $"LSASS opened by {DetectionRules.FileNameOf(src)} (access {e.D("GrantedAccess")})", src, e.Artifact);
                break;
            }
            case 11:
            {
                var f = e.D("TargetFilename");
                var tool = ctx.Rules.MatchTool(f);
                if (tool == null) break;
                _agg.Add($"sys11|{f}", tool.Severity, e.Time, Source, tool.Category,
                    $"File created: {DetectionRules.FileNameOf(f)} — {tool.Category}", f, e.Artifact);
                break;
            }
            case 13:
            {
                var key = e.D("TargetObject");
                if (!Regex.IsMatch(key, @"\\CurrentVersion\\(Run|RunOnce|RunServices)\\|\\Winlogon\\(Userinit|Shell)$|\\Image File Execution Options\\.+\\Debugger$", RegexOptions.IgnoreCase)) break;
                var data = e.D("Details");
                var hits = ctx.Rules.MatchCommandLine(data);
                var score = ctx.Rules.ScoreBinaryPath(ExtractExe(data));
                var sev = Severity.Medium;
                if (hits.Count > 0) sev = (Severity)Math.Min((int)sev, (int)hits.Min(h => h.Severity));
                if (score != null) sev = (Severity)Math.Min((int)sev, (int)score.Value.Sev);
                _agg.Add($"sys13|{key}|{data}", sev, e.Time, Source, "Autorun registry value set",
                    $"Autorun set by {DetectionRules.FileNameOf(e.D("Image"))}: {Trunc(key, 160)}", Trunc(data, 1000), e.Artifact);
                break;
            }
        }
    }

    // ── Completion: brute force, kerberoasting, flush aggregates ─────
    public void Complete(AnalysisContext ctx)
    {
        FlushGroupAdds();
        int threshold = Math.Max(1, ctx.Config.BruteForceThreshold);
        foreach (var (src, f) in _failures)
        {
            if (f.Count < threshold) continue;
            var users = string.Join(", ", f.Users.Take(8)) + (f.Users.Count > 8 ? $" (+{f.Users.Count - 8} more)" : "");
            var ip = src.Split(' ')[0];
            bool external = DetectionRules.IsExternalIp(ip);
            ctx.Add(new Finding
            {
                Severity = Severity.High, TimeUtc = f.First, LastUtc = f.Last, Count = f.Count, Source = Source,
                Category = "Brute force", Text = $"Brute force: {f.Count} failed logon(s) from {(external ? "external " : "")}{src} against {f.Users.Count} account(s)",
                Detail = users, Artifact = "Security.evtx",
            });

            // Success from the same source after the failures started
            foreach (var g in _successes.Where(s => s.Src.Equals(src, StringComparison.OrdinalIgnoreCase)
                                                  && (f.First == null || s.Time >= f.First))
                                        .GroupBy(s => s.User, StringComparer.OrdinalIgnoreCase))
            {
                var firstOk = g.Min(x => x.Time);
                ctx.Add(new Finding
                {
                    Severity = Severity.Critical, TimeUtc = firstOk, LastUtc = g.Max(x => x.Time), Count = g.Count(), Source = Source,
                    Category = "Brute force succeeded",
                    Text = $"Brute force succeeded: {g.Key} logged on (type {g.First().Type}) from {src} after {f.Count} failed attempt(s)",
                    Artifact = "Security.evtx",
                });
            }
        }

        foreach (var (who, r) in _rc4Tickets)
        {
            if (r.Services.Count < 3) continue;
            ctx.Add(new Finding
            {
                Severity = r.Services.Count >= 10 ? Severity.High : Severity.Medium, TimeUtc = r.First, LastUtc = r.Last, Count = r.Services.Count,
                Source = Source, Category = "Possible Kerberoasting",
                Text = $"Possible Kerberoasting: {who} requested RC4 service tickets for {r.Services.Count} service(s)",
                Detail = string.Join(", ", r.Services.Take(20)), Artifact = "Security.evtx",
            });
        }

        ctx.AddRange(_agg.Flush());
    }

    // ── Helpers ──────────────────────────────────────────────────────
    private void Add(Ev e, Severity sev, string category, string text, string detail = "") =>
        _agg.Add($"{category}|{text}", sev, e.Time, Source, category, text, detail, e.Artifact);

    private static string SourceKey(string ip, string ws)
    {
        bool okIp = DetectionRules.IsUsableIp(ip);
        bool okWs = !string.IsNullOrWhiteSpace(ws) && ws != "-";
        return okIp && okWs ? $"{ip} ({ws.ToUpperInvariant()})" : okIp ? ip : okWs ? ws.ToUpperInvariant() : "";
    }

    private static string StripIpPrefix(string ip) => ip.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) ? ip[7..] : ip;

    private static string Acct(string domain, string user)
    {
        if (string.IsNullOrWhiteSpace(user)) return "?";
        return string.IsNullOrWhiteSpace(domain) || domain == "-" ? user : $"{domain}\\{user}";
    }

    private static string LogonTypeName(string t) => t switch
    {
        "2" => "Interactive", "3" => "Network", "7" => "Unlock", "8" => "NetworkCleartext", "9" => "NewCredentials",
        "10" => "RemoteInteractive", "11" => "CachedInteractive", _ => "Type " + t,
    };

    private static string CnOf(string dn)
    {
        var m = Regex.Match(dn ?? "", @"^CN=([^,]+)");
        return m.Success ? m.Groups[1].Value : dn ?? "";
    }

    private static string FirstNonEmpty(params string[] v) => v.FirstOrDefault(s => !string.IsNullOrWhiteSpace(s) && s != "-") ?? "";

    internal static string Trunc(string s, int n) => string.IsNullOrEmpty(s) || s.Length <= n ? s ?? "" : s[..n] + "…";

    /// <summary>First executable path in a command line / ImagePath.</summary>
    internal static string ExtractExe(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return "";
        cmd = cmd.Trim();
        if (cmd.StartsWith('"')) { int end = cmd.IndexOf('"', 1); return end > 0 ? cmd[1..end] : cmd.Trim('"'); }
        var m = Regex.Match(cmd, @"^(.+?\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr|sys))\b", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : cmd.Split(' ')[0];
    }

    private static string ShortArtifact(string sourceFile, string channel)
    {
        var f = DetectionRules.FileNameOf(sourceFile);
        return f.Length > 0 ? f : channel;
    }

    /// <summary>
    /// Flattens EvtxECmd's Payload JSON: {"EventData":{"Data":[{"@Name":"X","#text":"v"},…]}}
    /// and UserData variants become a Name→value map; unnamed Data strings are joined under "Data".
    /// </summary>
    internal static Dictionary<string, string> FlattenPayload(string json)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(json) || json[0] != '{') return d;
        using var doc = JsonDocument.Parse(json);
        Walk(doc.RootElement, null, d);
        return d;
    }

    private static void Walk(JsonElement el, string? propName, Dictionary<string, string> d)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                if (el.TryGetProperty("@Name", out var nameEl))
                {
                    var value = el.TryGetProperty("#text", out var t) ? ValueOf(t) : "";
                    d[nameEl.GetString() ?? ""] = value;
                    return;
                }
                foreach (var p in el.EnumerateObject())
                {
                    if (p.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array) Walk(p.Value, p.Name, d);
                    else if (!p.Name.StartsWith("@xmlns", StringComparison.Ordinal)) d[p.Name.TrimStart('@', '#')] = ValueOf(p.Value);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                {
                    if (item.ValueKind is JsonValueKind.Object or JsonValueKind.Array) Walk(item, propName, d);
                    else
                    {
                        var key = propName ?? "Data";
                        d[key] = d.TryGetValue(key, out var prev) && prev.Length > 0 ? prev + " | " + ValueOf(item) : ValueOf(item);
                    }
                }
                break;
        }
    }

    private static string ValueOf(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString() ?? "",
        JsonValueKind.Null => "",
        JsonValueKind.Array => string.Join(" ", e.EnumerateArray().Select(ValueOf)),
        _ => e.ToString(),
    };
}
