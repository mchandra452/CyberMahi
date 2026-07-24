[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    Write-Host "No project environment found; running setup first ..."
    & (Join-Path $PSScriptRoot "setup.ps1")
}

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    throw "Setup did not create .venv. Review the setup error and try again."
}

function Invoke-LabCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $VenvPython @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Lab command failed with exit code $LASTEXITCODE`: python $($Arguments -join ' ')"
    }
}

Push-Location $ProjectRoot
try {
    Invoke-LabCommand @("-m", "soclab", "validate")
    Invoke-LabCommand @("-m", "soclab", "analyze")
    Invoke-LabCommand @("-m", "soclab", "test-detections")
    Invoke-LabCommand @("-m", "soclab", "build-report")
    Invoke-LabCommand @("-m", "pytest")
    Write-Host "PASS: offline workflow complete. Evidence is in artifacts\latest\."
}
finally {
    Pop-Location
}
