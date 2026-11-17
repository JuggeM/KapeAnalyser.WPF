using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Input;
using KapeAnalyser.WPF.Core;
using KapeAnalyser.WPF.Models;
using KapeAnalyser.WPF.Services;

namespace KapeAnalyser.WPF.ViewModels;

public class MainViewModel : ViewModelBase
{
    public AnalyserConfig Config { get; } = new();

    // ── Navigation ───────────────────────────────────────────────────
    private string _activePanel = "CaseSetup";
    public string ActivePanel { get => _activePanel; set => SetField(ref _activePanel, value); }
    public ICommand NavigateCommand { get; }

    // ── Scan ─────────────────────────────────────────────────────────
    private bool _isScanning;
    public bool IsScanning { get => _isScanning; private set => SetField(ref _isScanning, value); }
    private string _scanStatus = "Choose the case folder that holds the KAPE module output.";
    public string ScanStatus { get => _scanStatus; private set => SetField(ref _scanStatus, value); }
    public ObservableCollection<string> DetectedHosts { get; } = new();

    // ── Run ──────────────────────────────────────────────────────────
    public ObservableCollection<LogEntry> LogEntries { get; } = new();
    private bool _isRunning;
    public bool IsRunning
    {
        get => _isRunning;
        private set { SetField(ref _isRunning, value); OnPropertyChanged(nameof(CanRun)); OnPropertyChanged(nameof(ProgressText)); }
    }
    public bool CanRun => !IsRunning;
    private string _runStatusText = "Ready";
    public string RunStatusText { get => _runStatusText; private set => SetField(ref _runStatusText, value); }
    private double _progress;
    public double Progress { get => _progress; private set { SetField(ref _progress, value); OnPropertyChanged(nameof(ProgressText)); } }
    public string ProgressText => IsRunning ? $"{(int)(_progress * 100)} %" : string.Empty;
    private CancellationTokenSource? _cts;

    public ICommand RunCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand BrowseCommand { get; }
    public ICommand BrowseOutputCommand { get; }
    public ICommand RescanCommand { get; }
    public ICommand OpenOutputCommand { get; }

    // ── Detection lists (one entry per line) ─────────────────────────
    public string ExtraKeywordsText
    {
        get => string.Join(Environment.NewLine, Config.ExtraKeywords);
        set => SetList(Config.ExtraKeywords, value);
    }
    public string WhitelistText
    {
        get => string.Join(Environment.NewLine, Config.WhitelistPaths);
        set => SetList(Config.WhitelistPaths, value);
    }
    private static void SetList(ObservableCollection<string> list, string text)
    {
        list.Clear();
        foreach (var l in (text ?? "").Split('\n').Select(s => s.Trim()).Where(s => s.Length > 0)) list.Add(l);
    }

    // ── IOCs ─────────────────────────────────────────────────────────
    private string _iocText = string.Empty;
    private bool _iocDirty;
    public string IocText
    {
        get => _iocText;
        set { if (SetField(ref _iocText, value)) { _iocDirty = true; UpdateIocPreview(); } }
    }
    private string _iocPreview = "No IOCs yet — paste a list above.";
    public string IocPreview { get => _iocPreview; private set => SetField(ref _iocPreview, value); }
    private string _iocStatus = string.Empty;
    public string IocStatus { get => _iocStatus; private set => SetField(ref _iocStatus, value); }
    public ICommand SaveIocsCommand { get; }
    public ICommand SearchIocsCommand { get; }

    public MainViewModel()
    {
        NavigateCommand = new RelayCommand(p => ActivePanel = p as string ?? ActivePanel);
        RunCommand = new RelayCommand(_ => _ = RunAsync(), _ => CanRun);
        CancelCommand = new RelayCommand(_ => { _cts?.Cancel(); RunStatusText = "Cancelling…"; }, _ => IsRunning);
        BrowseCommand = new RelayCommand(_ => BrowseCase());
        BrowseOutputCommand = new RelayCommand(_ => BrowseOutput());
        RescanCommand = new RelayCommand(_ => _ = ScanAsync());
        OpenOutputCommand = new RelayCommand(_ => OpenFolder(Config.ResolveOutputPath()));
        SaveIocsCommand = new RelayCommand(_ => SaveIocs());
        SearchIocsCommand = new RelayCommand(_ => _ = SearchIocsAsync(), _ => CanRun);
    }

    private bool HasCase => !string.IsNullOrWhiteSpace(Config.CaseFolderPath) && Directory.Exists(Config.CaseFolderPath);

    // ── Folders ──────────────────────────────────────────────────────
    private void BrowseCase()
    {
        var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = "Select the case folder (holding the KAPE output)", UseDescriptionForTitle = true };
        if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
        var previous = Config.CaseFolderPath;
        Config.CaseFolderPath = dlg.SelectedPath;
        if (string.IsNullOrWhiteSpace(Config.OutputPath) || !Path.IsPathRooted(Config.OutputPath)
            || (!string.IsNullOrWhiteSpace(previous) && PathEquals(Config.OutputPath, Path.Combine(previous, "Processed"))))
            Config.OutputPath = Path.Combine(dlg.SelectedPath, "Processed");
        OnPropertyChanged(nameof(Config));
        LoadIocs();
        _ = ScanAsync();
    }

    private void BrowseOutput()
    {
        var dlg = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Select the output folder", UseDescriptionForTitle = true,
            SelectedPath = Directory.Exists(Config.ResolveOutputPath()) ? Config.ResolveOutputPath() : Config.CaseFolderPath,
        };
        if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
        Config.OutputPath = dlg.SelectedPath;
        OnPropertyChanged(nameof(Config));
    }

    private static void OpenFolder(string path)
    {
        if (Directory.Exists(path)) Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
    }

    private static bool PathEquals(string a, string b) =>
        string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    // ── Scan ─────────────────────────────────────────────────────────
    private async Task ScanAsync()
    {
        if (!HasCase) return;
        IsScanning = true;
        ScanStatus = "Looking for KAPE module output…";
        DetectedHosts.Clear();
        var outBase = Config.ResolveOutputPath();
        var hosts = await Task.Run(() => KapeDiscovery.Find(Config.CaseFolderPath, outBase));
        foreach (var h in hosts)
        {
            var rel = Path.GetRelativePath(Config.CaseFolderPath, h.RootPath);
            DetectedHosts.Add($"{h.Name,-24} {h.CsvCount,4} module CSV(s)   {rel}" +
                              (AnalysisEngine.IsProcessed(outBase, h.Name) ? "   (already processed — will be skipped)" : ""));
        }
        if (hosts.Count == 0) DetectedHosts.Add("(no KAPE module output found — expected EZ Tools CSVs, e.g. Kape\\<host>\\EventLogs\\*_EvtxECmd_Output.csv)");
        ScanStatus = hosts.Count > 0 ? $"Found {hosts.Count} host(s)" : "No KAPE output found";
        IsScanning = false;
    }

    // ── Run ──────────────────────────────────────────────────────────
    private async Task RunAsync()
    {
        if (!HasCase) { ActivePanel = "CaseSetup"; ScanStatus = "Choose a case folder first."; return; }
        IsRunning = true;
        Progress = 0;
        RunStatusText = "Running…";
        ActivePanel = "Output";
        LogEntries.Clear();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        var progress = new Progress<double>(p => Progress = p);

        try
        {
            Log($"Case: {Config.CaseName}   Analyst: {Config.AnalystName}");
            Log($"Folder: {Config.CaseFolderPath}");
            if (_iocDirty) SaveIocs();
            await Task.Run(() => new AnalysisEngine(Config, LogFromEngine).RunAll(ct, progress), ct);
            Log("Done.", LogLevel.Success);
            RunStatusText = "Complete";
        }
        catch (OperationCanceledException)
        {
            Log("Run cancelled by analyst.", LogLevel.Warning);
            RunStatusText = "Cancelled";
        }
        catch (Exception ex)
        {
            Log($"Fatal error: {ex.Message}", LogLevel.Error);
            RunStatusText = "Failed";
        }
        finally
        {
            IsRunning = false;
            Progress = 0;
            _ = ScanAsync();
        }
    }

    private void LogFromEngine(string m) =>
        Log(m, m.StartsWith("[ERROR]") ? LogLevel.Error : m.StartsWith("[WARN]") ? LogLevel.Warning : LogLevel.Info);

    public void Log(string message, LogLevel level = LogLevel.Info) =>
        System.Windows.Application.Current.Dispatcher.Invoke(() => LogEntries.Add(new LogEntry(DateTime.Now, message, level)));

    // ── IOCs ─────────────────────────────────────────────────────────
    private void LoadIocs()
    {
        if (!HasCase) return;
        var p = CaseIocs.PathFor(Config.CaseFolderPath);
        _iocText = File.Exists(p) ? File.ReadAllText(p) : string.Empty;
        OnPropertyChanged(nameof(IocText));
        _iocDirty = false;
        UpdateIocPreview();
        IocStatus = File.Exists(p) ? $"Loaded {p}" : $"No IOC list yet — it will be saved to {p}";
    }

    private void UpdateIocPreview()
    {
        var (iocs, rejected) = CaseIocs.Parse(_iocText);
        IocPreview = (iocs.Count == 0 ? "No IOCs recognised yet." : CaseIocs.Summary(iocs)) +
                     (rejected.Count > 0 ? $"   |   {rejected.Count} line(s) not recognised (dropped on save): {string.Join("  |  ", rejected.Take(3))}" : "");
    }

    private bool SaveIocs()
    {
        if (!HasCase) { IocStatus = "Choose a case folder first (Case setup)."; return false; }
        var (iocs, _) = CaseIocs.Parse(_iocText);
        var p = CaseIocs.PathFor(Config.CaseFolderPath);
        File.WriteAllText(p, CaseIocs.Serialize(iocs));
        _iocText = File.ReadAllText(p);
        OnPropertyChanged(nameof(IocText));
        _iocDirty = false;
        IocStatus = $"Saved {iocs.Count} IOC(s) to {p}";
        return true;
    }

    private async Task SearchIocsAsync()
    {
        if (!SaveIocs()) return;
        IsRunning = true;
        RunStatusText = "Searching IOCs…";
        ActivePanel = "Output";
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        try
        {
            await Task.Run(() => AnalysisEngine.FinishCase(Config.CaseFolderPath, Config.ResolveOutputPath(),
                Config.CaseName, Config.AnalystName, true, LogFromEngine, ct), ct);
            Log("IOC search done.", LogLevel.Success);
            RunStatusText = "Complete";
        }
        catch (OperationCanceledException) { RunStatusText = "Cancelled"; }
        catch (Exception ex) { Log($"IOC search failed: {ex.Message}", LogLevel.Error); RunStatusText = "Failed"; }
        finally { IsRunning = false; }
    }
}

public enum LogLevel { Info, Success, Warning, Error }

public record LogEntry(DateTime Timestamp, string Message, LogLevel Level)
{
    public string Display => $"[{Timestamp:HH:mm:ss}] {Message}";
}
