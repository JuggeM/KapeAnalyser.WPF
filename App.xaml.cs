using System.Runtime.InteropServices;
using System.Windows;
using KapeAnalyser.WPF.Models;
using KapeAnalyser.WPF.Services;
using Application = System.Windows.Application;

namespace KapeAnalyser.WPF;

/// <summary>
/// Normal start opens the UI. Headless mode for scripted runs:
///   KapeAnalyser.WPF.exe --case &lt;folder&gt; [--out &lt;folder&gt;] [--name &lt;case&gt;] [--analyst &lt;name&gt;]
/// Exit code 0 on success, 1 on failure.
/// </summary>
public partial class App : Application
{
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);

    protected override void OnStartup(StartupEventArgs e)
    {
        int i = Array.FindIndex(e.Args, a => a.Equals("--case", StringComparison.OrdinalIgnoreCase));
        if (i < 0 || i + 1 >= e.Args.Length)
        {
            base.OnStartup(e);
            new MainWindow().Show();
            return;
        }

        AttachConsole(-1);
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        string Arg(string name, string def)
        {
            int j = Array.FindIndex(e.Args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
            return j >= 0 && j + 1 < e.Args.Length ? e.Args[j + 1] : def;
        }

        var config = new AnalyserConfig
        {
            CaseFolderPath = Path.GetFullPath(e.Args[i + 1]),
            OutputPath = Arg("--out", AnalyserConfig.DefaultOutputPath),
            CaseName = Arg("--name", ""),
            AnalystName = Arg("--analyst", Environment.UserName),
            RulesPath = Arg("--rules", ""),
        };
        int code = 0;
        try
        {
            new AnalysisEngine(config, m => Console.WriteLine(m)).RunAll(CancellationToken.None);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERROR] {ex}");
            code = 1;
        }
        Shutdown(code);
    }
}
