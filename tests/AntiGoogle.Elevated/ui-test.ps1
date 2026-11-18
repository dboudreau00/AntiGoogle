# Drives the real Anti-Google window with UI Automation: every page, a local-only rule, a quarantine,
# Apply and Restore through the real buttons and dialog, a generated report, and the headless --report.
# It reads the machine back with tools that do not share code with the app, and checks that Restore
# leaves the hosts file byte-identical and the journal, vault and firewall group empty.
#
# It MODIFIES the machine it runs on. Run it only in a disposable virtual machine, from an elevated
# PowerShell inside an interactive desktop session (UI Automation and screenshots need one).
#
#   ui-test.ps1 -YesModifyThisMachine [-AppFolder C:\agtest] [-AllowPhysical]
#
# -AppFolder holds the published app (AntiGoogle.exe and the *_cor3.dll files beside it). Results go to
# ui-results.txt, screenshots to shots\ and the generated report to gui-report.html, all in that folder.
# The exit code is the number of failed checks.
param(
    [switch]$YesModifyThisMachine,
    [switch]$AllowPhysical,
    [string]$AppFolder = 'C:\agtest'
)
$appDir = $AppFolder.TrimEnd('\')

function Refuse([string]$why) { Write-Output "Refusing to run: $why"; exit 99 }
if (-not $YesModifyThisMachine) { Refuse 'this applies Anti-Google to the machine it runs on. Pass -YesModifyThisMachine, in a disposable virtual machine.' }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Refuse 'this session is not elevated.' }
$cs = Get-CimInstance Win32_ComputerSystem
if (("$($cs.Manufacturer) $($cs.Model)" -notmatch 'VMware|VirtualBox|Virtual Machine|KVM|QEMU|Xen|Parallels|Hyper-V|innotek|Bochs') -and -not $AllowPhysical) {
    Refuse "this machine does not report itself as a virtual machine ($($cs.Manufacturer) $($cs.Model)). Pass -AllowPhysical only if you accept that."
}
if (-not (Test-Path (Join-Path $appDir 'AntiGoogle.exe'))) { Refuse "AntiGoogle.exe is not in $appDir." }
$journalFile = 'C:\ProgramData\AntiGoogle\journal.json'
if ((Test-Path $journalFile) -and ((Get-Content $journalFile -Raw).Trim() -notin '', '[]')) { Refuse 'Anti-Google state is already present (the journal has entries). Restore it first.' }
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms, System.Drawing
$results = Join-Path $appDir 'ui-results.txt'
$shots = Join-Path $appDir 'shots'
New-Item -ItemType Directory -Force $shots | Out-Null
Set-Content $results "ui test started $(Get-Date)"
$script:fail = 0; $script:pass = 0

function Log([string]$m) { Add-Content $results $m; Write-Output $m }
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    if ($ok) { $script:pass++; Log "  PASS  $name" } else { $script:fail++; Log "  FAIL  $name  $detail" }
}
function Shot([string]$name) {
    try {
        $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
        $bmp.Save("$shots\$name.png", [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
    } catch { Log "  (screenshot $name failed: $($_.Exception.Message))" }
}

$AE = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$PC = [System.Windows.Automation.PropertyCondition]
$CT = [System.Windows.Automation.ControlType]

function Find-Name($root, [string]$name, $type = $null, [int]$timeoutMs = 8000) {
    $deadline = (Get-Date).AddMilliseconds($timeoutMs)
    do {
        $cond = New-Object $PC ($AE::NameProperty), $name
        if ($type) { $cond = New-Object System.Windows.Automation.AndCondition $cond, (New-Object $PC ($AE::ControlTypeProperty), $type) }
        $el = $root.FindFirst($TS::Descendants, $cond)
        if ($el) { return $el }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    return $null
}
function Find-Starts($root, [string]$prefix, [int]$timeoutMs = 8000) {
    $deadline = (Get-Date).AddMilliseconds($timeoutMs)
    do {
        $all = $root.FindAll($TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($e in $all) { if ($e.Current.Name -and $e.Current.Name.StartsWith($prefix)) { return $e } }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $deadline)
    return $null
}
function Click($el) { $el.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
function Select-Item($el) { $el.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select() }
function Set-Toggle($el, [bool]$on) {
    $p = $el.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
    $want = if ($on) { [System.Windows.Automation.ToggleState]::On } else { [System.Windows.Automation.ToggleState]::Off }
    if ($p.Current.ToggleState -ne $want) { $p.Toggle() }
}
function Toggle-State($el) { $el.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern).Current.ToggleState.ToString() }

$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
Log "screen $($b.Width)x$($b.Height)"

# ---- plant one identifier where the marker catalog looks, so the quarantine path can be driven through the window
$androidDir = Join-Path $env:USERPROFILE '.android'
$markerFile = Join-Path $androidDir 'analytics.settings'
$vault = 'C:\ProgramData\AntiGoogle\quarantine'
New-Item -ItemType Directory -Force $androidDir | Out-Null
Set-Content $markerFile '{"userId":"00000000-0000-0000-0000-000000000000","hasOptedIn":true}' -Encoding ASCII
$markerHashBefore = (Get-FileHash $markerFile -Algorithm SHA256).Hash

# ---- launch
Get-Process AntiGoogle -ErrorAction SilentlyContinue | Stop-Process -Force
$hostsBefore = (Get-FileHash C:\Windows\System32\drivers\etc\hosts -Algorithm SHA256).Hash
$proc = Start-Process (Join-Path $appDir 'AntiGoogle.exe') -PassThru
Start-Sleep -Seconds 6
$win = $null
for ($i = 0; $i -lt 120 -and -not $win; $i++) {
    $win = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst($TS::Children,
        (New-Object $PC ($AE::ProcessIdProperty), $proc.Id))
    if (-not $win) { Start-Sleep -Milliseconds 500; $proc.Refresh() }
}
Check 'the main window appears' ($null -ne $win)
if (-not $win) { Log "FATAL: no window"; exit 1 }
# The window is 1180x820 by default and the lab screen is 1024x768: fit it, so the whole window is on screen.
Add-Type -Namespace Win -Name Native -MemberDefinition '[DllImport("user32.dll")] public static extern bool MoveWindow(System.IntPtr h, int x, int y, int w, int hgt, bool repaint);'
[void][Win.Native]::MoveWindow([System.IntPtr]$win.Current.NativeWindowHandle, 0, 0, [Math]::Min(1180, $b.Width), [Math]::Min(820, $b.Height - 48), $true)
Start-Sleep -Milliseconds 800
Shot '00-launch'

# ---- navigation: every page reachable, in order
$expected = 'Dashboard', 'Rules', 'Impact report', 'App containment', 'Markers', 'Report', 'History & restore', 'About'
$pageNames = 'Dashboard', 'Rules', 'Impact report', 'App containment', 'Markers', 'Report', 'History and restore', 'About'
$items = $win.FindAll($TS::Descendants, (New-Object $PC ($AE::ControlTypeProperty), $CT::ListItem))
$names = @(foreach ($i in $items) { $i.Current.Name })
Check 'the navigation rail lists the eight pages in order' (($names -join '|') -eq ($expected -join '|')) ($names -join '|')

for ($k = 0; $k -lt $expected.Count; $k++) {
    $nav = $items | Where-Object { $_.Current.Name -eq $expected[$k] } | Select-Object -First 1
    if (-not $nav) { Check "nav item $($expected[$k]) exists" $false; continue }
    Select-Item $nav
    Start-Sleep -Milliseconds 500
    $page = Find-Name $win $pageNames[$k] $null 4000
    Check "page '$($expected[$k])' renders and is exposed to accessibility tools" ($null -ne $page)
    $others = $pageNames | Where-Object { $_ -ne $pageNames[$k] -and $_ -in 'Rules', 'Markers', 'Report', 'About', 'Dashboard' }
    $leak = @(foreach ($o in $others) { $e = Find-Name $win $o ($CT::Pane) 200; if ($e -and -not $e.Current.IsOffscreen) { $o } })
    Shot ("1{0}-page-{1}" -f $k, ($expected[$k] -replace '[^A-Za-z]', ''))
}

# ---- Rules page: local-only
Select-Item ($items | Where-Object { $_.Current.Name -eq 'Rules' } | Select-Object -First 1)
Start-Sleep -Milliseconds 600
$lo = Find-Name $win 'Keep running, local-only: Update & component delivery CDN' $CT::CheckBox 6000
Check 'the Rules page offers a local-only switch on a hosts rule' ($null -ne $lo)
if ($lo) {
    Check 'the switch starts off' ((Toggle-State $lo) -eq 'Off')
    Set-Toggle $lo $true
    Start-Sleep -Milliseconds 500
    Check 'turning it on sticks' ((Toggle-State $lo) -eq 'On')
    $chip = Find-Name $win 'LOCAL-ONLY' $null 3000
    Check 'a LOCAL-ONLY chip appears on the rule card' ($null -ne $chip)
}
$svcLo = Find-Name $win 'Keep running, local-only: Google Updater services' $CT::CheckBox 4000
Check 'the updater service rule offers local-only too' ($null -ne $svcLo)
$noLo = Find-Name $win 'Keep running, local-only: Chrome policy: no browser sign-in or sync' $CT::CheckBox 800
Check 'a registry-policy rule offers no local-only switch' ($null -eq $noLo)
Shot '20-rules-local-only'

# ---- Impact report states the local-only cost
Select-Item ($items | Where-Object { $_.Current.Name -eq 'Impact report' } | Select-Object -First 1)
Start-Sleep -Milliseconds 600
$retry = Find-Name $win 'Programs may retry faster' $null 5000
Check 'the Impact report states the local-only cost of the rule' ($null -ne $retry)

# ---- verify with nothing confined yet
Select-Item ($items | Where-Object { $_.Current.Name -eq 'App containment' } | Select-Object -First 1)
Start-Sleep -Milliseconds 500
$verify0 = Find-Name $win 'Verify local-only' $CT::Button 4000
Check 'the Containment page has a Verify button' ($null -ne $verify0)
if ($verify0) {
    Click $verify0
    $v0 = Find-Starts $win 'Nothing is confined' 20000
    Check 'verifying with nothing confined says so rather than claiming a pass' ($null -ne $v0)
}

# ---- Markers: find the planted identifier and choose to quarantine it
Select-Item ($items | Where-Object { $_.Current.Name -eq 'Markers' } | Select-Object -First 1)
Start-Sleep -Milliseconds 600
$mscan0 = Find-Name $win 'Scan this machine' $CT::Button 4000
if ($mscan0) { Click $mscan0 }
$q = Find-Name $win 'Quarantine marker: Android Studio and SDK usage ID' $CT::CheckBox 25000
Check 'the scan finds the planted identifier and offers to quarantine it' ($null -ne $q)
if ($q) {
    Set-Toggle $q $true
    Start-Sleep -Milliseconds 500
    Check 'the quarantine switch can be turned on' ((Toggle-State $q) -eq 'On')
    Shot '25-markers-found'
}

# ---- apply the default profile with that one rule local-only
Select-Item ($items | Where-Object { $_.Current.Name -eq 'Dashboard' } | Select-Object -First 1)
Start-Sleep -Milliseconds 500
$apply = Find-Name $win 'Apply protection' $CT::Button 5000
Check 'the Apply button is present' ($null -ne $apply)
if ($apply) {
    Click $apply
    $accept = Find-Name $win 'I have read what will break and I want to apply these changes' $CT::CheckBox 25000
    Check 'the confirmation overlay opens' ($null -ne $accept)
    Shot '30-confirm'
    if ($accept) {
        Set-Toggle $accept $true
        Start-Sleep -Milliseconds 400
        $go = Find-Name $win 'Apply now' $CT::Button 4000
        Click $go
        $banner = $null
        for ($i = 0; $i -lt 180; $i++) {
            Start-Sleep -Seconds 2
            $banner = $win.FindFirst($TS::Descendants, (New-Object $PC ($AE::AutomationIdProperty), 'ResultBannerText'))
            if ($banner -and $banner.Current.Name -like 'Applied*') { break }
        }
        $text = if ($banner) { $banner.Current.Name } else { '' }
        Check 'the apply finishes and the banner says so' ($text -like 'Applied*') $text
        Log "  banner: $text"
        # The banner comes first and the status tiles refresh a moment later.
        [void](Find-Name $win 'Protection active' $null 30000)
        Start-Sleep -Milliseconds 800
        Shot '31-applied'
    }
}

# ---- the machine, read independently of the app
$hosts = Get-Content C:\Windows\System32\drivers\etc\hosts -Raw
Check 'the hosts file carries a managed block' ($hosts -match 'ANTI-GOOGLE BEGIN')
Check 'the local-only rule resolved its names to this machine on both families' (($hosts -match '(?m)^127\.0\.0\.1 update\.googleapis\.com') -and ($hosts -match '(?m)^::1 update\.googleapis\.com'))
Check 'a blocking rule still sinkholed its names' (($hosts -match '(?m)^0\.0\.0\.0 clientservices\.googleapis\.com') -and ($hosts -match '(?m)^:: clientservices\.googleapis\.com'))
$journal = 'C:\ProgramData\AntiGoogle\journal.json'
Check 'the journal holds the reverse of what was done' ((Test-Path $journal) -and ((Get-Content $journal -Raw).Length -gt 10))
Check 'the quarantined identifier left its original place' (-not (Test-Path $markerFile))
Check 'the vault holds it with a manifest and a payload' (@(Get-ChildItem $vault -Recurse -Filter manifest.json -ErrorAction SilentlyContinue).Count -eq 1 -and @(Get-ChildItem $vault -Recurse -Filter analytics.settings -ErrorAction SilentlyContinue).Count -eq 1)
$dash = $win.FindAll($TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
$status = $null; foreach ($e in $dash) { if ($e.Current.Name -like '*looped to this machine*') { $status = $e.Current.Name; break } }
Check 'the dashboard status line reports the looped names' ($null -ne $status) ''
Log "  status: $status"

# ---- Containment: verify after local-only names were applied
Select-Item ($items | Where-Object { $_.Current.Name -eq 'App containment' } | Select-Object -First 1)
Start-Sleep -Milliseconds 500
$verify = Find-Name $win 'Verify local-only' $CT::Button 4000
if ($verify) {
    Click $verify
    $v = Find-Starts $win 'Every check holds.' 20000
    Check 'verifying after apply confirms the looped names' ($null -ne $v)
    if ($v) { Check 'and does not claim a program is confined when none is' (-not ($v.Current.Name -like '*nothing confined*')) $v.Current.Name }
}
$scan = Find-Name $win 'Scan this machine' $CT::Button 3000
if ($scan) { Click $scan; Start-Sleep -Seconds 6 }
Shot '40-containment'

# ---- Markers
Select-Item ($items | Where-Object { $_.Current.Name -eq 'Markers' } | Select-Object -First 1)
Start-Sleep -Milliseconds 600
$net = Find-Name $win 'Network markers' $null 3000
Check 'the Markers page shows the network marker rules' ($null -ne $net)
$mand = Find-Name $win 'Mandiant marketing trackers' $null 3000
Check 'the Mandiant tracker rule is listed' ($null -ne $mand)
$mscan = Find-Name $win 'Scan this machine' $CT::Button 3000
Check 'the Markers page has its own scan button' ($null -ne $mscan)
if ($mscan) {
    Click $mscan
    $sum = Find-Starts $win 'None of the' 20000
    if (-not $sum) { $sum = Find-Starts $win ' of ' 2000 }
    Check 'the marker scan finishes and reports what it found' ($null -ne $sum)
    if ($sum) { Log "  marker summary: $($sum.Current.Name)" }
}
Shot '50-markers'

# ---- Report page
Select-Item ($items | Where-Object { $_.Current.Name -eq 'Report' } | Select-Object -First 1)
Start-Sleep -Milliseconds 600
$gen = Find-Name $win 'Generate report' $CT::Button 3000
Check 'the Report page offers to generate a report' ($null -ne $gen)
if ($gen) {
    Click $gen
    $rb = $null
    for ($i = 0; $i -lt 90 -and -not $rb; $i++) {
        Start-Sleep -Seconds 1
        $b2 = $win.FindFirst($TS::Descendants, (New-Object $PC ($AE::AutomationIdProperty), 'ResultBannerText'))
        if ($b2 -and ($b2.Current.Name -like 'Report saved*' -or $b2.Current.Name -like 'Could not open the report*')) { $rb = $b2 }
    }
    Check 'generating a report finishes and says it saved it' ($null -ne $rb) $(if ($rb) { $rb.Current.Name })
    Start-Sleep -Seconds 2
    Get-Process msedge, chrome, firefox -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $saved = Get-ChildItem 'C:\ProgramData\AntiGoogle\reports' -Filter *.html -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
    Check 'the report file is on disk with a JSON beside it' ($null -ne $saved -and (Test-Path ([IO.Path]::ChangeExtension($saved.FullName, '.json'))))
    if ($saved) {
        $html = Get-Content $saved.FullName -Raw
        Check 'the report names the quarantined identifier' ($html -match 'Android Studio and SDK usage ID')
        Check 'the report shows looped names as local-only' ($html -match 'Local-only')
        Check 'the report passes its own verification' ($html -match 'Verification passed')
        Check 'the safety checks do not blame someone else for the Chrome policy Anti-Google just set' (-not ($html -match 'Chrome already has \d+ policy values set'))
        Check 'the report never carries the home folder' (-not $html.Replace('<wbr>', '').Contains($env:USERPROFILE))
        Copy-Item $saved.FullName (Join-Path $appDir 'gui-report.html') -Force
        Copy-Item ([IO.Path]::ChangeExtension($saved.FullName, '.json')) (Join-Path $appDir 'gui-report.json') -Force
    }
}
Shot '60-report'

# ---- Restore everything through the real button and dialog
Select-Item ($items | Where-Object { $_.Current.Name -eq 'History & restore' } | Select-Object -First 1)
Start-Sleep -Milliseconds 600
$restore = Find-Name $win 'Restore everything' $CT::Button 4000
Check 'the History page has Restore everything' ($null -ne $restore)
if ($restore) {
    Click $restore
    # The confirmation is a native message box. UI Automation does not list it in this lab image, so it is
    # found and answered through its window handle instead.
    Add-Type -Namespace Win -Name Dlg -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern System.IntPtr FindWindow(string cls, string title);
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern System.IntPtr FindWindowEx(System.IntPtr parent, System.IntPtr after, string cls, string title);
[DllImport("user32.dll")] public static extern System.IntPtr SendMessage(System.IntPtr h, uint msg, System.IntPtr w, System.IntPtr l);
'@
    $dlg = [System.IntPtr]::Zero
    for ($i = 0; $i -lt 30 -and $dlg -eq [System.IntPtr]::Zero; $i++) {
        Start-Sleep -Milliseconds 500
        $dlg = [Win.Dlg]::FindWindow('#32770', 'Restore everything')
    }
    Check 'the confirmation dialog appears' ($dlg -ne [System.IntPtr]::Zero)
    if ($dlg -ne [System.IntPtr]::Zero) {
        Shot '70-restore-dialog'
        $yesButton = [Win.Dlg]::FindWindowEx($dlg, [System.IntPtr]::Zero, 'Button', '&Yes')
        Check 'the dialog offers Yes' ($yesButton -ne [System.IntPtr]::Zero)
        [void][Win.Dlg]::SendMessage($yesButton, 0x00F5, [System.IntPtr]::Zero, [System.IntPtr]::Zero)
        for ($i = 0; $i -lt 120; $i++) {
            Start-Sleep -Seconds 2
            $banner = $win.FindFirst($TS::Descendants, (New-Object $PC ($AE::AutomationIdProperty), 'ResultBannerText'))
            if ($banner -and ($banner.Current.Name -like 'Everything restored*' -or $banner.Current.Name -like 'Restored, but*')) { break }
        }
        Log "  banner: $($banner.Current.Name)"
        Check 'the restore finishes cleanly' ($banner.Current.Name -like 'Everything restored*') $banner.Current.Name
        Shot '71-restored'
    }
}

Check 'the quarantined identifier is back, byte for byte' ((Test-Path $markerFile) -and ((Get-FileHash $markerFile -Algorithm SHA256).Hash -eq $markerHashBefore))
Check 'the vault is empty again' (@(Get-ChildItem $vault -Directory -ErrorAction SilentlyContinue).Count -eq 0)
$hostsAfter = (Get-FileHash C:\Windows\System32\drivers\etc\hosts -Algorithm SHA256).Hash
Check 'the hosts file is byte-identical to before the apply' ($hostsAfter -eq $hostsBefore) "$hostsBefore -> $hostsAfter"
$j = if (Test-Path $journal) { (Get-Content $journal -Raw).Trim() } else { '[]' }
Check 'the journal is empty again' ($j -eq '[]' -or $j -eq '') $j
Check 'no Anti-Google firewall rule remains' (@(Get-NetFirewallRule -Group 'Anti-Google' -ErrorAction SilentlyContinue).Count -eq 0)

# ---- headless report, in the same elevated session
$rdir = Join-Path $appDir 'cli-report'
Remove-Item $rdir -Recurse -Force -ErrorAction SilentlyContinue
$p2 = Start-Process (Join-Path $appDir 'AntiGoogle.exe') -ArgumentList '--report', $rdir -PassThru -Wait
Check 'AntiGoogle.exe --report writes a report and exits 0' ($p2.ExitCode -eq 0) "exit $($p2.ExitCode)"
Check 'the headless report is an HTML file with a JSON beside it' ((@(Get-ChildItem $rdir -Filter *.html -ErrorAction SilentlyContinue).Count -eq 1) -and (@(Get-ChildItem $rdir -Filter *.json -ErrorAction SilentlyContinue).Count -eq 1))

try { $proc.CloseMainWindow() | Out-Null; Start-Sleep 2; if (-not $proc.HasExited) { $proc.Kill() } } catch { }
Log ""
Log "=== $($script:pass) passed, $($script:fail) failed ==="
exit $script:fail
