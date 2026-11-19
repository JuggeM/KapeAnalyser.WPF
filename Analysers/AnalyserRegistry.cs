using KapeAnalyser.WPF.Core;

namespace KapeAnalyser.WPF.Analysers;

public static class AnalyserRegistry
{
    /// <summary>
    /// Fresh analyser instances (they hold per-host state). Order matters only
    /// for files two analysers could both claim: the first match wins, so
    /// the broad shellbags name match is last.
    /// </summary>
    public static IArtifactAnalyser[] CreateAll() => new IArtifactAnalyser[]
    {
        new EventLogAnalyser(),
        new PrefetchAnalyser(),
        new AmcacheAnalyser(),
        new ShimcacheAnalyser(),
        new RegistryAnalyser(),
        new LnkAnalyser(),
        new JumpListAnalyser(),
        new MftAnalyser(),
        new UsnJournalAnalyser(),
        new RecycleBinAnalyser(),
        new SrumAnalyser(),
        new SigmaAnalyser(),
        new ShellbagsAnalyser(),
    };
}
