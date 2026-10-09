# Builds dist\LogLens.exe (single file, no Python needed on the target PC).
# Requires: Python 3.9+ on the build machine.  Usage:  powershell -ExecutionPolicy Bypass -File build_windows.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
python -m pip install --quiet pyinstaller
python -m PyInstaller --noconfirm --onefile --name LogLens `
  --add-data "lvx\web;lvx\web" `
  --add-data "lvx\kb_library.json;lvx" `
  --add-data "lvx\case_templates.json;lvx" `
  --collect-submodules lvx `
  launcher.py
Write-Host "Built: $PSScriptRoot\dist\LogLens.exe"
