using System.Text.RegularExpressions;
using KapeAnalyser.WPF.Analysers;

namespace KapeAnalyser.WPF.Core;

/// <summary>One host's KAPE module output folder.</summary>
public sealed record KapeHost(string Name, string RootPath, int CsvCount);

/// <summary>
/// Finds KAPE module output in a case folder. A "host" is a folder whose
/// files include EZ Tools CSVs, either directly or inside KAPE's category
/// folders (EventLogs, ProgramExecution, FileSystem, …). Typical layouts:
///   Case\Kape\WS01\EventLogs\…_EvtxECmd_Output.csv     (one folder per host)
///   Case\Kape\EventLogs\…                              (single host, no host folder)
///   Case\ORC_WorkStation_WS01_…\2026-11-01T…\EventLogs  (nested, any depth up to 4)
/// </summary>
public static class KapeDiscovery
{
    public static readonly HashSet<string> CategoryFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "EventLogs", "ProgramExecution", "FileSystem", "Registry", "FileFolderAccess", "FileDeletion",
        "FileKnowledge", "BrowserHistory", "SRUMDatabase", "SystemActivity", "Timelines", "LateralMovement",
        "Persistence", "AccountUsage", "NetworkActivity", "SQLDatabases", "ApplicationCompatibility",
        "LiveResponse", "Antivirus", "CloudStorage", "Communication", "Documents", "Executables", "Misc",
    };

    private static readonly IArtifactAnalyser[] Probe = AnalyserRegistry.CreateAll();

    public static bool IsKnownCsv(string fileName) => Probe.Any(a => a.Accepts(fileName));

    public static List<KapeHost> Find(string caseFolder, string outputBase)
    {
        var hosts = new List<KapeHost>();
        if (!Directory.Exists(caseFolder)) return hosts;
        var skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Path.GetFullPath(outputBase).TrimEnd('\\') };

        void Visit(string dir, int depth)
        {
            if (skip.Contains(Path.GetFullPath(dir).TrimEnd('\\'))) return;
            var name = Path.GetFileName(dir);
            if (name.StartsWith('_') || name.StartsWith('.')) return;

            string[] subdirs;
            try { subdirs = Directory.GetDirectories(dir); } catch { return; }

            bool hasCategory = subdirs.Any(s => CategoryFolders.Contains(Path.GetFileName(s)));
            bool hasCsvHere = SafeFiles(dir, SearchOption.TopDirectoryOnly).Any(f => IsKnownCsv(Path.GetFileName(f)));

            if ((hasCategory || hasCsvHere) && depth > 0)
            {
                int n = SafeFiles(dir, SearchOption.AllDirectories).Count(f => IsKnownCsv(Path.GetFileName(f)));
                if (n > 0) { hosts.Add(new KapeHost(name, dir, n)); return; }
            }
            if (depth >= 5) return;
            foreach (var s in subdirs.OrderBy(s => s, StringComparer.OrdinalIgnoreCase))
                Visit(s, depth + 1);
        }

        Visit(caseFolder, 0);

        // A host folder nested in a timestamp folder ("WS01\2026-11-01T101010") is
        // better named after its parent.
        var result = new List<KapeHost>();
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in hosts)
        {
            var name = h.Name;
            if (Regex.IsMatch(name, @"^\d{4}-?\d{2}-?\d{2}") || name.Equals("Kape", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Modules", StringComparison.OrdinalIgnoreCase) || name.Equals("Output", StringComparison.OrdinalIgnoreCase))
            {
                var parent = Path.GetFileName(Path.GetDirectoryName(h.RootPath) ?? "");
                if (!string.IsNullOrEmpty(parent) && !PathEquals(Path.GetDirectoryName(h.RootPath), caseFolder)) name = parent;
            }
            name = Sanitize(name);
            var unique = name;
            for (int i = 2; !used.Add(unique); i++) unique = $"{name}_{i}";
            result.Add(h with { Name = unique });
        }
        return result;
    }

    /// <summary>Host name from a DFIR-ORC style folder name ("ORC_WorkStation_WS01_20261101_…").</summary>
    public static string? HostFromFolderName(string folder)
    {
        var m = Regex.Match(folder, @"^ORC_(?:WorkStation|Server|DomainController|[A-Za-z]+)_(?<h>[^_]+)_", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups["h"].Value.ToUpperInvariant() : null;
    }

    private static IEnumerable<string> SafeFiles(string dir, SearchOption opt)
    {
        try { return Directory.EnumerateFiles(dir, "*.csv", new EnumerationOptions { RecurseSubdirectories = opt == SearchOption.AllDirectories, IgnoreInaccessible = true }); }
        catch { return Array.Empty<string>(); }
    }

    private static string Sanitize(string n)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) n = n.Replace(c, '_');
        return n.Trim();
    }

    private static bool PathEquals(string? a, string? b) =>
        a != null && b != null && string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
}
