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

    A device that has not been shared yet needs `usbipd bind --force`, which
    needs an elevated shell.  Run the script elevated once; later runs work
    unelevated.

.PARAMETER Distribution
    WSL distribution to attach to.  Defaults to the default distribution.

.PARAMETER Stop
    Stop the auto-attach processes this script starts and their helpers
    inside WSL, detach those devices (they go back to Windows), then exit.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\wsl-usb-attach.ps1
#>
[CmdletBinding()]
param(
    [string]$Distribution = '',
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

$devices = (& $Usbipd state | ConvertFrom-Json).Devices |
    Where-Object { $_.BusId } |
    ForEach-Object {
        if ($_.InstanceId -match 'VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') {
            $_ | Add-Member -NotePropertyName HwId -NotePropertyValue "$($Matches[1]):$($Matches[2])" -PassThru
        }
    } |
    Where-Object { $Targets.ContainsKey($_.HwId) }

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

    if (-not $dev.PersistedGuid) {
        if (-not $isAdmin) {
            Write-Warning "$label is not shared; rerun this script elevated to bind it."
            continue
        }
        # --force: the UsbDk filter driver on this host blocks a plain bind.
        & $Usbipd bind --force --busid $busId
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "$label bind failed."
            continue
        }
        Write-Host "$label bound"
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
