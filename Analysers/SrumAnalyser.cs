using System.Globalization;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;

namespace KapeAnalyser.WPF.Analysers;

/// <summary>
/// SrumECmd output: *_SrumECmd_NetworkUsages_Output.csv (bytes sent and
/// received per app, per user, per hour) and *_SrumECmd_AppResourceUseInfo_Output.csv
/// (apps that ran, per hour). Answers "was data sent out, by what and how
/// much": known tools or binaries in staging folders that uploaded data, and
/// any other app with an unusually large upload. ExeInfo is a device path
/// ("\device\harddiskvolume3\perflogs\rclone.exe"); times are UTC.
/// </summary>
public sealed class SrumAnalyser : IArtifactAnalyser
{
    public string Source => "SRUM";
    public string Module => "SrumECmd";
    public bool Enabled(AnalyserConfig c) => c.AnalyseSrum;
    public bool Accepts(string f) =>
        f.EndsWith("_SrumECmd_NetworkUsages_Output.csv", StringComparison.OrdinalIgnoreCase)
        || f.EndsWith("_SrumECmd_AppResourceUseInfo_Output.csv", StringComparison.OrdinalIgnoreCase);

    private const long MB = 1024L * 1024;
    /// <summary>A tool or staging-folder binary that sent at least this much is reported.</summary>
    private const long ToolUploadBytes = 1 * MB;
    /// <summary>Any other app that sent at least this much (and more than it received) is reported.</summary>
    private const long LargeUploadBytes = 500 * MB;

    // Apps that legitimately upload a lot; they still count when they are tools or in staging folders
    private static readonly HashSet<string> BulkUploaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "system", "onedrive.exe", "msmpeng.exe", "backgroundtransferhost.exe", "teams.exe", "ms-teams.exe",
        "outlook.exe", "searchapp.exe", "wuauclt.exe", "msedgewebview2.exe", "officeclicktorun.exe", "sense.exe", "mssense.exe",
    };

    private sealed class Usage
    {
        public string Exe = "", User = "";
        public long Sent, Received;
        public DateTime? First, Last;
        public int Hours;
    }

    private readonly Dictionary<string, Usage> _net = new(StringComparer.OrdinalIgnoreCase);
    private readonly FindingAggregator _ran = new();

    public void Analyse(string csvPath, AnalysisContext ctx)
    {
        using var csv = new CsvReader(csvPath);
        int cTime = csv.Col("Timestamp"), cExe = csv.Col("ExeInfo"), cUser = csv.Col("UserName"), cSid = csv.Col("Sid");
        if (cTime < 0 || cExe < 0) { ctx.Log($"[WARN] {Path.GetFileName(csvPath)}: not SrumECmd output (no Timestamp/ExeInfo)."); return; }
        int cSent = csv.Col("BytesSent"), cRecv = csv.Col("BytesReceived");
        bool network = cSent >= 0;

        var cov = ctx.CoverageFor(Source);
        cov.Files.Add(csvPath);

        while (csv.Read())
        {
            if ((csv.RowNumber & 0x3FFF) == 0) ctx.Cancel.ThrowIfCancellationRequested();
            cov.Rows++;
            var time = CsvReader.ParseTime(csv[cTime]);
            cov.See(time);
            var exe = csv[cExe].Trim();
            if (exe.Length == 0) continue;
            var user = cUser >= 0 && csv[cUser].Length > 0 ? csv[cUser] : cSid >= 0 ? csv[cSid] : "";

            if (network)
            {
                var key = exe + "|" + user;
                if (!_net.TryGetValue(key, out var u)) _net[key] = u = new Usage { Exe = exe, User = user };
                u.Sent += Bytes(csv[cSent]);
                u.Received += cRecv >= 0 ? Bytes(csv[cRecv]) : 0;
                u.Hours++;
                if (time.HasValue)
                {
                    if (u.First == null || time < u.First) u.First = time;
                    if (u.Last == null || time > u.Last) u.Last = time;
                }
                continue;
            }

            // App resource use: evidence that a tool ran in that hour
            var score = ctx.Rules.ScoreBinaryPath(exe);
            if (score == null) continue;
            _ran.Add($"srum-ran|{exe}|{user}", score.Value.Sev, time, Source, score.Value.Reason,
                $"Ran: {DetectionRules.FileNameOf(exe)} — {score.Value.Reason}" + (user.Length > 0 ? $" (user {user})" : ""),
                exe, Path.GetFileName(csvPath));
        }
    }

    public void Complete(AnalysisContext ctx)
    {
        foreach (var u in _net.Values)
        {
            if (u.Sent <= 0) continue;
            var name = DetectionRules.FileNameOf(u.Exe);
            var score = ctx.Rules.ScoreBinaryPath(u.Exe);
            Severity sev;
            string why;
            if (score != null && u.Sent >= ToolUploadBytes)
            {
                sev = score.Value.Sev;
                // Hundreds of MB out through a tool or staged binary is exfiltration until shown otherwise
                if (u.Sent >= 100 * MB && sev > Severity.High) sev = Severity.High;
                why = score.Value.Reason;
            }
            else if (score == null && u.Sent >= LargeUploadBytes && u.Sent > u.Received && !BulkUploaders.Contains(name))
            {
                sev = Severity.Medium;
                why = "large upload";
            }
            else continue;

            ctx.Add(new Finding
            {
                Severity = sev, TimeUtc = u.First, LastUtc = u.Last, Count = u.Hours, Source = Source,
                Category = sev <= Severity.High ? "Data sent by suspicious app" : "Large upload",
                Text = $"{name} sent {Size(u.Sent)} (received {Size(u.Received)}) over {u.Hours} hour(s) — {why}" +
                       (u.User.Length > 0 ? $", user {u.User}" : ""),
                Detail = u.Exe,
                Artifact = "SRUDB.dat",
            });
        }
        ctx.AddRange(_ran.Flush());
    }

    private static long Bytes(string s) =>
        long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) && v > 0 ? v : 0;

    internal static string Size(long b) =>
        b >= 1024L * MB ? FormattableString.Invariant($"{b / (1024.0 * MB):0.0} GB")
        : b >= MB ? FormattableString.Invariant($"{b / (double)MB:0.0} MB")
        : FormattableString.Invariant($"{b / 1024.0:0} KB");
}
