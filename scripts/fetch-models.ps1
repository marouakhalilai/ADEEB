#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads the pinned ONNX model weights into models/.

.DESCRIPTION
    Model weights are not committed (see .gitignore) — they are large and their licences
    are tracked separately in models/provenance.md.

    Two rules this script exists to enforce:

    1. Every model is pinned by SHA-256. Mirrors and forks of the same nominal model
       differ, and a silently different set of weights invalidates the calibrated
       threshold and the FAR/FRR baseline that CI gates on.

    2. A hash mismatch is a hard failure, never a warning. Downloading unexpected bytes
       and running them against a camera feed is not a situation to continue from.

.NOTES
    This script refuses to run while models/provenance.md still contains PENDING entries.
    That is deliberate: the licence audit is a Phase 3 blocking gate, and fetching weights
    is the moment it stops being theoretical.
#>
[CmdletBinding()]
param(
    # Skip the provenance gate. For CI use once every model row reads VERIFIED.
    [switch]$SkipProvenanceCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$modelsDir = Join-Path $repoRoot 'models'
$provenance = Join-Path $modelsDir 'provenance.md'

# ---------------------------------------------------------------------------
# Pinned models. Fill in Url and Sha256 as each row in provenance.md is VERIFIED.
# ---------------------------------------------------------------------------
$models = @(
    @{
        Name   = 'face_detection_yunet.onnx'
        Url    = ''   # TODO: pin after licence verification
        Sha256 = ''
        Role   = 'detection'
    },
    @{
        Name   = 'face_recognition_sface.onnx'
        Url    = ''   # TODO: pin after licence verification
        Sha256 = ''
        Role   = 'embedding'
    },
    @{
        Name   = 'face_liveness.onnx'
        Url    = ''   # TODO: model not yet selected — highest licence risk of the three
        Sha256 = ''
        Role   = 'liveness'
    }
)

function Test-ProvenanceGate {
    if (-not (Test-Path $provenance)) {
        throw "models/provenance.md is missing. The licence audit is a blocking gate for Phase 3."
    }

    $pending = Select-String -Path $provenance -Pattern 'PENDING|TO VERIFY|TO SELECT' -SimpleMatch:$false
    if ($pending) {
        Write-Host ''
        Write-Host 'Model licence audit is incomplete.' -ForegroundColor Yellow
        Write-Host "  $($pending.Count) unresolved entries in models/provenance.md" -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Model weights carry terms independent of the runtime that executes them.' -ForegroundColor Yellow
        Write-Host 'Resolve every entry before calibrating a threshold against these weights —' -ForegroundColor Yellow
        Write-Host 'discovering a non-commercial licence after Phase 3 costs the FAR/FRR' -ForegroundColor Yellow
        Write-Host 'baseline, the spoof corpus results, and the CI regression gate.' -ForegroundColor Yellow
        Write-Host ''
        throw 'Blocked by provenance gate. Pass -SkipProvenanceCheck once every row reads VERIFIED.'
    }
}

function Get-PinnedModel {
    param([hashtable]$Model)

    $target = Join-Path $modelsDir $Model.Name

    if ([string]::IsNullOrWhiteSpace($Model.Url) -or [string]::IsNullOrWhiteSpace($Model.Sha256)) {
        Write-Host "  SKIP  $($Model.Name) — not yet pinned ($($Model.Role))" -ForegroundColor DarkGray
        return
    }

    if (Test-Path $target) {
        $existing = (Get-FileHash -Path $target -Algorithm SHA256).Hash
        if ($existing -ieq $Model.Sha256) {
            Write-Host "  OK    $($Model.Name) — already present, hash matches" -ForegroundColor Green
            return
        }
        Write-Host "  STALE $($Model.Name) — hash differs, re-downloading" -ForegroundColor Yellow
        Remove-Item $target -Force
    }

    Write-Host "  GET   $($Model.Name)"
    $temp = "$target.partial"
    Invoke-WebRequest -Uri $Model.Url -OutFile $temp -UseBasicParsing

    $actual = (Get-FileHash -Path $temp -Algorithm SHA256).Hash
    if ($actual -ine $Model.Sha256) {
        Remove-Item $temp -Force
        throw "SHA-256 mismatch for $($Model.Name).`n  expected $($Model.Sha256)`n  actual   $actual`nRefusing to install unverified model weights."
    }

    Move-Item $temp $target -Force
    Write-Host "  OK    $($Model.Name) — verified" -ForegroundColor Green
}

if (-not $SkipProvenanceCheck) {
    Test-ProvenanceGate
}

if (-not (Test-Path $modelsDir)) {
    New-Item -ItemType Directory -Path $modelsDir | Out-Null
}

Write-Host "Fetching pinned models into $modelsDir"
foreach ($m in $models) {
    Get-PinnedModel -Model $m
}
Write-Host 'Done.'
