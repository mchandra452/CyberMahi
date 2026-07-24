[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPath = Join-Path $ProjectRoot ".venv"
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($Arguments -join ' ')"
    }
}

if (Get-Command py -ErrorAction SilentlyContinue) {
    $BootstrapPython = (Get-Command py).Source
    $BootstrapArguments = @("-3")
}
elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $BootstrapPython = (Get-Command python3).Source
    $BootstrapArguments = @()
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $BootstrapPython = (Get-Command python).Source
    $BootstrapArguments = @()
}
else {
    throw "Python 3.11 or newer was not found. Install Python, then rerun this script."
}

Push-Location $ProjectRoot
try {
    Invoke-Checked $BootstrapPython ($BootstrapArguments + @(
        "-c",
        "import sys; print(f'Using Python {sys.version.split()[0]}'); raise SystemExit(0 if sys.version_info >= (3, 11) else 'Python 3.11 or newer is required')"
    ))

    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        Write-Host "Creating isolated environment at .venv ..."
        Invoke-Checked $BootstrapPython ($BootstrapArguments + @("-m", "venv", $VenvPath))
    }

    Write-Host "Installing the lab and development checks ..."
    Invoke-Checked $VenvPython @("-m", "pip", "install", "-e", ".[dev]")
    Invoke-Checked $VenvPython @("-m", "soclab", "validate")

    Write-Host "Setup complete. Run .\scripts\run_offline.ps1 to generate and verify the lab evidence."
}
finally {
    Pop-Location
}
