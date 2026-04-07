$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location ([System.IO.Path]::GetFullPath((Join-Path $root "../prime-gui")))
cargo tauri dev
