<#
.SYNOPSIS
    Attach the pico2hsm boards and debug probes to WSL with usbipd-win.

.DESCRIPTION
    Finds every connected device with one of the pico2hsm USB IDs:

        1209:27c0  pico2hsm firmware (CCID + CDC serial)
        2e8a:000c  Raspberry Pi Debug Probe (CMSIS-DAP)
        2e8a:000f  RP2350 in BOOTSEL (for picotool)

    For each one it starts `usbipd attach --wsl --auto-attach --busid <id>`
    as a hidden background process, unless one is already running for that
    bus ID.  Auto-attach blocks for as long as it runs and re-attaches the
    port after every detach, so a board that resets, or reboots into
    BOOTSEL and back, returns to WSL by itself.

    2e8a:10fd boards (C pico-keys firmware) are never attached.

    Sharing a device needs administrator rights.  The script binds
    (`usbipd bind --force`) every connected target device that is not
    force-shared yet, and registers a usbipd AutoBind policy for each of the
    IDs above.  When either is needed and the shell is not elevated, the
    script runs that part elevated (one UAC prompt) and carries on
    unelevated.

    The UsbDk filter driver on this host makes a share that is not forced
    fail to attach ("Device in error state"), and an AutoBind policy shares
    without forcing.  So a new device (a board with a new serial number,
    or one in BOOTSEL for the first time) still needs a run of this script
    to be attached.  The policies help on hosts without UsbDk.

.PARAMETER Distribution
    WSL distribution to attach to.  Defaults to the default distribution.

.PARAMETER Bind
    Only register the AutoBind policies and bind the unshared devices, then
    exit.  Needs an elevated shell; the script uses it for its elevated pass.

.PARAMETER Stop
    Stop the auto-attach processes this script starts and their helpers
    inside WSL, detach those devices (they go back to Windows), then exit.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\wsl-usb-attach.ps1
#>
[CmdletBinding()]
param(
    [string]$Distribution = '',
    [switch]$Bind,
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'

$Targets = @{
    '1209:27C0' = 'pico2hsm'
    '2E8A:000C' = 'debug probe'
    '2E8A:000F' = 'RP2350 BOOTSEL'
}

# Resolve the executable by full path: a bare `usbipd` can pick up an
# extensionless file of that name ahead of usbipd.exe.
$Usbipd = (Get-Command usbipd.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1).Source
if (-not $Usbipd) {
    throw 'usbipd-win is not installed (winget install usbipd).'
}

# Running `usbipd attach --auto-attach` processes, keyed by bus ID.
function Get-AttachProcesses {
    $found = @{}
    Get-CimInstance Win32_Process -Filter "Name = 'usbipd.exe'" | ForEach-Object {
        $cmd = $_.CommandLine
        if ($cmd -match '\battach\b' -and $cmd -match '--busid[ =]+"?([0-9]+-[0-9]+)') {
            $found[$Matches[1]] = $_
        }
    }
    $found
}

# Hardware IDs ('VID:PID', upper case) with an AutoBind policy.
function Get-AutoBindIds {
    $ids = @{}
    & $Usbipd policy list | ForEach-Object {
        if ($_ -match '\bAllow\s+AutoBind\b.*\b([0-9A-Fa-f]{4}:[0-9A-Fa-f]{4})\s*$') {
            $ids[$Matches[1].ToUpper()] = $true
        }
    }
    $ids
}

# Connected devices with one of the target IDs.
function Get-TargetDevices {
    (& $Usbipd state | ConvertFrom-Json).Devices |
        Where-Object { $_.BusId } |
        ForEach-Object {
            if ($_.InstanceId -match 'VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') {
                $_ | Add-Member -NotePropertyName HwId -NotePropertyValue "$($Matches[1]):$($Matches[2])" -PassThru
            }
        } |
        Where-Object { $Targets.ContainsKey($_.HwId) }
}

# The administrator part: AutoBind policies for the target IDs, and a forced
# bind for each target device connected now that is not force-shared.
function Invoke-Sharing {
    $policies = Get-AutoBindIds
    foreach ($hwId in $Targets.Keys) {
        if (-not $policies.ContainsKey($hwId)) {
            & $Usbipd policy add --effect Allow --operation AutoBind --hardware-id $hwId
            if ($LASTEXITCODE -eq 0) { Write-Host "$hwId  $($Targets[$hwId])  AutoBind policy added" }
            else { Write-Warning "$hwId AutoBind policy failed." }
        }
    }
    foreach ($dev in @(Get-TargetDevices | Where-Object { -not $_.IsForced })) {
        # --force: the UsbDk filter driver on this host blocks a plain bind.
        & $Usbipd bind --force --busid $dev.BusId
        if ($LASTEXITCODE -eq 0) { Write-Host "$($dev.BusId)  $($dev.HwId)  $($Targets[$dev.HwId])  bound" }
        else { Write-Warning "$($dev.BusId)  $($dev.HwId) bind failed." }
    }
}

if ($Stop) {
    $running = Get-AttachProcesses
    foreach ($busId in $running.Keys) {
        Stop-Process -Id $running[$busId].ProcessId -Force
        Write-Host "stopped auto-attach for $busId (pid $($running[$busId].ProcessId))"
    }
    if ($running.Count -eq 0) { Write-Host 'no auto-attach processes running' }
    # Each attach also runs a helper inside WSL, which outlives the Windows
    # process.  A helper left behind can spin on a stuck port and hold its
    # device, so stop those too.
    $wslArgs = @()
    if ($Distribution) { $wslArgs += @('-d', $Distribution) }
    & wsl.exe @wslArgs -u root -e pkill -x usbip-auto-atta
    & wsl.exe @wslArgs -u root -e pkill -x usbip
    foreach ($busId in $running.Keys) {
        & $Usbipd detach --busid $busId 2>$null
    }
    return
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Bind) {
    if (-not $isAdmin) { throw '-Bind needs an elevated shell.' }
    Invoke-Sharing
    return
}

$policies = Get-AutoBindIds
$missing = @($Targets.Keys | Where-Object { -not $policies.ContainsKey($_) })
$unshared = @(Get-TargetDevices | Where-Object { -not $_.IsForced })
if ($missing -or $unshared) {
    if ($isAdmin) {
        Invoke-Sharing
    } else {
        # Elevate only the sharing; the attach processes stay unelevated, so
        # later unelevated runs can see their command lines.
        Write-Host 'Sharing needs administrator rights; approve the UAC prompt.'
        try {
            $elevated = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Bind')
            if ($elevated.ExitCode -ne 0) { Write-Warning "elevated pass exited with $($elevated.ExitCode)" }
        } catch {
            Write-Warning "elevated pass not run: $($_.Exception.Message)"
        }
    }
    $policies = Get-AutoBindIds
}

$devices = Get-TargetDevices

if (-not $devices) {
    Write-Host 'No pico2hsm boards or debug probes connected.'
    return
}

$running = Get-AttachProcesses
$attachArgs = @('attach', '--auto-attach', '--wsl')
if ($Distribution) { $attachArgs += $Distribution }

foreach ($dev in $devices) {
    $busId = $dev.BusId
    $label = "$busId  $($dev.HwId)  $($Targets[$dev.HwId])"

    if (-not $dev.IsForced) {
        Write-Warning "$label is not force-shared; rerun this script elevated to bind it."
        continue
    }

    if ($running.ContainsKey($busId)) {
        Write-Host "$label auto-attach already running (pid $($running[$busId].ProcessId))"
        continue
    }

    $proc = Start-Process -FilePath $Usbipd -ArgumentList ($attachArgs + @('--busid', $busId)) `
        -WindowStyle Hidden -PassThru
    Write-Host "$label auto-attach started (pid $($proc.Id))"

    # One attach at a time: concurrent attaches race for the same WSL
    # virtual port ("vhci_hcd: port N already used") and one device never
    # arrives, although Windows reports it attached.
    $deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 500
        $now = (& $Usbipd state | ConvertFrom-Json).Devices | Where-Object { $_.BusId -eq $busId }
    } until ($now.ClientIPAddress -or (Get-Date) -gt $deadline)
    if (-not $now.ClientIPAddress) {
        Write-Warning "$label did not attach within 15 s (still retrying in the background)."
    }
}
