<#
.SYNOPSIS
    Detects common registry-based persistence mechanisms.

.DESCRIPTION
    Scans common Run/RunOnce, Services and Winlogon keys for suspicious or unusual entries.
    Outputs results to screen and optionally to a JSON/CSV report.

.NOTES
    Author  : Fareed
    Version : 1.0
#>

[CmdletBinding()]
param(
    [string]$ExportPathJson,
    [string]$ExportPathCsv
)

$PersistenceLocations = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SYSTEM\CurrentControlSet\Services',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
)

$results = @()

foreach ($path in $PersistenceLocations) {
    if (-not (Test-Path $path)) { continue }

    try {
        if ($path -like '*Services') {
            # Enumerate services as persistence
            Get-ChildItem $path | ForEach-Object {
                $svcKey = $_.PsPath
                $props = Get-ItemProperty -Path $svcKey -ErrorAction SilentlyContinue
                if ($props.ImagePath) {
                    $results += [PSCustomObject]@{
                        Location   = $path
                        Name       = $_.PSChildName
                        Type       = 'Service'
                        ValueName  = 'ImagePath'
                        Data       = $props.ImagePath
                    }
                }
            }
        }
        elseif ($path -like '*Winlogon') {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($vn in 'Shell','Userinit') {
                if ($props.$vn) {
                    $results += [PSCustomObject]@{
                        Location   = $path
                        Name       = 'Winlogon'
                        Type       = 'Winlogon'
                        ValueName  = $vn
                        Data       = $props.$vn
                    }
                }
            }
        }
        else {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                if (-not [string]::IsNullOrWhiteSpace($prop.Value)) {
                    $results += [PSCustomObject]@{
                        Location   = $path
                        Name       = $props.PSChildName
                        Type       = 'RunKey'
                        ValueName  = $prop.Name
                        Data       = $prop.Value
                    }
                }
            }
        }
    } catch {
        Write-Warning "Failed to read $path : $($_.Exception.Message)"
    }
}

if (-not $results) {
    Write-Host 'No persistence entries found in monitored locations.' -ForegroundColor Yellow
} else {
    Write-Host "`n[+] Potential persistence entries:" -ForegroundColor Cyan
    $results | Sort-Object Location,Type | Format-Table -AutoSize
}

if ($ExportPathJson) {
    try {
        $results | ConvertTo-Json -Depth 4 | Set-Content -Path $ExportPathJson -Encoding UTF8
        Write-Host "JSON report exported to $ExportPathJson" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export JSON: $($_.Exception.Message)"
    }
}

if ($ExportPathCsv) {
    try {
        $results | Export-Csv -Path $ExportPathCsv -NoTypeInformation -Encoding UTF8
        Write-Host "CSV report exported to $ExportPathCsv" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export CSV: $($_.Exception.Message)"
    }
}
