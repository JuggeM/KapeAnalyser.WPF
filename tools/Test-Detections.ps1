<#
.SYNOPSIS
  Regression test: builds the synthetic case, runs KapeAnalyser headless and
  checks that the expected findings (and only those for the noise) appear.

.DESCRIPTION
  Uses tools\New-TestCase.ps1, so every detection the test case is built to
  trigger is checked here. Run it after changing a rule. Exit code 1 when a
  check fails.

.EXAMPLE
  dotnet build; .\tools\Test-Detections.ps1
#>
param(
    [string] $Exe = (Join-Path $PSScriptRoot '..\bin\Debug\net8.0-windows\KapeAnalyser.WPF.exe'),
    [string] $WorkFolder = (Join-Path ([IO.Path]::GetTempPath()) 'KapeAnalyserRegression')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) { throw "Build first: $Exe not found." }

# Only ever delete a folder this script created
$marker = Join-Path $WorkFolder '.kape-regression'
if (Test-Path $WorkFolder) {
    if (-not (Test-Path $marker)) { throw "$WorkFolder exists and was not created by this script; choose another -WorkFolder." }
    Remove-Item $WorkFolder -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $WorkFolder | Out-Null
Set-Content -Path $marker -Value 'created by Test-Detections.ps1'

& (Join-Path $PSScriptRoot 'New-TestCase.ps1') -CaseFolder $WorkFolder | Out-Null
$p = Start-Process -FilePath $Exe -ArgumentList "--case `"$WorkFolder`" --name Regression" -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $WorkFolder 'run.log')
if ($p.ExitCode -ne 0) { throw "KapeAnalyser exited with $($p.ExitCode); see $WorkFolder\run.log" }

$processed = Join-Path $WorkFolder 'Processed\Level2'   # results; KAPE output is in Processed\
$findings = Get-ChildItem $processed -Recurse -Filter Findings.csv | ForEach-Object { Import-Csv $_.FullName -Encoding UTF8 }
$summary = Get-Content (Join-Path $processed 'CaseSummary.txt') -Raw -Encoding UTF8
$arrow = [string][char]0x2192

$failed = 0
function Check([bool] $ok, [string] $what) {
    if ($ok) { Write-Host "  PASS  $what" -ForegroundColor Green }
    else { Write-Host "  FAIL  $what" -ForegroundColor Red; $script:failed++ }
}
function Expect($hostName, $severity, $source, $pattern) {
    $hit = $findings | Where-Object { $_.Host -eq $hostName -and $_.Severity -match "^($severity)$" -and $_.Source -eq $source -and $_.Text -match $pattern }
    Check ([bool]$hit) "$hostName $severity [$source] $pattern"
}
function ExpectNone($hostName, $source, $pattern) {
    $hit = $findings | Where-Object { $_.Host -eq $hostName -and $_.Source -eq $source -and $_.Text -match $pattern }
    Check (-not $hit) "no $hostName [$source] $pattern"
}

Write-Host "Findings: $($findings.Count) across $(@($findings | Select-Object -ExpandProperty Host -Unique).Count) host(s)"

Write-Host 'WS01 (RDP brute force, tools, exfiltration)'
Expect WS01 CRITICAL EVTX 'Brute force succeeded: CORP\\jdoe'
Expect WS01 HIGH EVTX 'Brute force: 30 failed logon'
Expect WS01 CRITICAL PREFETCH 'MIMIKATZ'
Expect WS01 CRITICAL USNJRNL 'File deleted: mimikatz'
Expect WS01 CRITICAL AMCACHE 'rclone'
Expect WS01 CRITICAL EVTX 'Security event log cleared'
Expect WS01 HIGH EVTX 'Account created: WS01\\support'
Expect WS01 HIGH EVTX "added to group 'Administrators'"
Expect WS01 HIGH REGISTRY 'Defender exclusion'
Expect WS01 HIGH LNK 'Invoice\.lnk'
Expect WS01 'CRITICAL|HIGH' SRUM 'rclone\.exe sent 2\.1 GB'
Expect WS01 'CRITICAL|HIGH' SRUM 'Ran: rclone\.exe'
ExpectNone WS01 SRUM 'onedrive|chrome|svchost'
Expect WS01 HIGH EVTX 'RDP session from external IP 203\.0\.113\.45 as CORP\\jdoe lasted 42 min'
Expect WS01 HIGH EVTX 'WMI filter bound to consumer'
Expect WS01 HIGH EVTX 'WMI Command Line consumer created: SysUpdate'
Expect WS01 MEDIUM EVTX 'WMI event filter created: SysUpdate'
Expect WS01 HIGH EVTX 'Remote process via WMIC'
Expect WS01 HIGH SIGMA 'Sigma \(Hayabusa\): Windows Defender Exclusion Added'
ExpectNone WS01 SIGMA 'Logon \(Network\)'
Expect WS01 MEDIUM REGISTRY 'Outbound RDP from this host to 10\.10\.1\.30 as CORP\\jdoe'
Expect WS01 MEDIUM REGISTRY 'Network share mapped from this host: \\\\10\.10\.1\.30\\Finance'
Expect WS01 HIGH REGISTRY 'Admin share opened from this host: \\\\FS01\\C\$'
Expect WS01 MEDIUM REGISTRY 'USB storage device: SanDisk Ultra USB Device \(serial 4C530001234567\)'
Expect WS01 MEDIUM EVTX 'Removable disk connected: SanDisk Ultra \(serial 4C530001234567, 59\.6 GB\)'
Expect WS01 SUSPICIOUS EVTX 'unusual hour for this host: CORP\\support \(Interactive\) at 02:40'
ExpectNone WS01 EVTX 'unusual hour for this host: CORP\\jdoe'
$hb = $findings | Where-Object { $_.Host -eq 'WS01' -and $_.Text -match 'Windows Defender Exclusion Added' } | Select-Object -First 1
Check ($hb -and $hb.TimeUtc -eq '2026-11-01 09:11:00') "Hayabusa +01:00 time converted to UTC (got $($hb.TimeUtc))"
$sessions = Import-Csv (Join-Path $processed 'WS01\Sessions.csv') -Encoding UTF8
$rdp = @($sessions | Where-Object { $_.LogonType -eq 'RemoteInteractive' -and $_.SourceIp -eq '203.0.113.45' })
Check ($rdp.Count -eq 2 -and ($rdp | Where-Object { $_.DurationMinutes -eq '42' -and $_.EndedBy -eq '4634' }) -and ($rdp | Where-Object { $_.EndedBy -eq 'RDP 23 logoff' })) "Sessions.csv: RDP session from 4624/4634 (42 min) and from LocalSessionManager (ended by 23)"
Check (@($sessions | Where-Object { $_.Id -eq '0x1A2B' -and $_.LogonType -eq 'Interactive' -and $_.EndedBy -eq '4634' }).Count -eq 1) 'Sessions.csv: local console session with logoff'
Check (@($sessions | Where-Object { $_.LogonType -eq 'Interactive' -and $_.DurationMinutes -eq '45' }).Count -eq 27) 'Sessions.csv: 27 baseline desk sessions of 45 min'

Write-Host 'FS01 (webshell, PsExec, ransomware prep)'
Expect FS01 CRITICAL EVTX 'Web server started a shell: w3wp\.exe started cmd\.exe'
Expect FS01 CRITICAL EVTX 'Shadow copies deleted'
Expect FS01 HIGH EVTX 'PSEXESVC'
Expect FS01 CRITICAL MFT 'ransom note'
Expect FS01 MEDIUM SIGMA 'Sigma \(Chainsaw\): Shadow Copy Deletion Using OS Utilities on FS01'

Write-Host 'DC01 (domain attacks)'
Expect DC01 CRITICAL EVTX 'DCSync: CORP\\jdoe'
Expect DC01 MEDIUM EVTX 'Computer account EVILPC\$ created by jdoe'
Expect DC01 HIGH EVTX 'Kerberoasting'
Expect DC01 HIGH EVTX "support added to group 'Domain Admins'"
Expect DC01 HIGH EVTX 'Password spray: 12 account\(s\) tried from 10\.10\.1\.21 \(WS01\), 2 attempt\(s\) each'
Expect DC01 HIGH EVTX '6 accounts locked out'
Expect DC01 MEDIUM EVTX 'Account locked out: user01 \(caller WS01\)'
Expect FS01 MEDIUM EVTX 'Possible pass-the-hash: NTLM network logon with key length 0 for CORP\\jdoe from 10\.10\.1\.21 \(WS01\)'

Write-Host 'Case'
Check ($summary -match "WS01\s+$arrow FS01") 'lateral WS01 -> FS01'
Check ($summary -match "WS01\s+$arrow DC01") 'lateral WS01 -> DC01'
Check ($summary -notmatch "FS01\s+$arrow WS01") 'no reversed link FS01 -> WS01'
$hits = @(Import-Csv (Join-Path $processed 'WS01\IocHits.csv') -Encoding UTF8)
Check ($hits.Count -eq 5) "WS01 case IOC hits = 5 (got $($hits.Count))"
Check (Test-Path (Join-Path $processed 'WS01\QuickWins.rtf')) 'WS01 QuickWins.rtf written'

Write-Host 'Layout'
$kapeOut = Join-Path $WorkFolder 'Processed'
Check (@(Get-ChildItem $processed -Directory).Count -eq 3) 'three host folders in Processed\Level2'
Check (-not (Test-Path (Join-Path $kapeOut 'CaseSummary.txt'))) 'nothing written into the KAPE output root (Processed\)'
Check (-not (Get-ChildItem $kapeOut -Recurse -Filter 'QuickWins.txt' | Where-Object { $_.FullName -notlike "$processed*" })) 'no results outside Processed\Level2'

if ($failed -gt 0) { Write-Host "$failed check(s) failed. Output kept in $WorkFolder" -ForegroundColor Red; exit 1 }
Write-Host 'All checks passed.' -ForegroundColor Green
