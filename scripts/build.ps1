# written_by: claude-code
# 用 Windows 自带的 .NET Framework 4.8 C# 编译器构建，无需安装任何 SDK。
# 输出：dist\ClaudeVPNGuard.exe（GUI）、dist\ClaudeVPNGuard.Service.exe（服务）、dist\ClaudeVPNGuard.Tests.exe（测试）
param([switch]$RunTests)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "未找到 .NET Framework 4.x 编译器：$csc" }
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null

$core = Get-ChildItem (Join-Path $root 'src\Core') -Filter *.cs | ForEach-Object FullName
$refs = @('System.dll','System.Core.dll','System.Web.Extensions.dll','Microsoft.CSharp.dll','System.Management.dll',
          'System.ServiceProcess.dll','System.Windows.Forms.dll','System.Drawing.dll','System.IO.Compression.dll',
          'System.IO.Compression.FileSystem.dll') | ForEach-Object { "/r:$_" }
$common = @('/nologo','/optimize+','/platform:anycpu','/langversion:5','/utf8output','/codepage:65001','/warn:3','/nowarn:1591') + $refs

function Build($out, $target, $files, $extra) {
    $args = $common + @("/target:$target", "/out:$(Join-Path $dist $out)") + $extra + $files
    & $csc @args
    if ($LASTEXITCODE -ne 0) { throw "编译失败：$out" }
    Write-Host "OK  $out"
}

$manifest = Join-Path $root 'src\Service\app.manifest'
$icon = Join-Path $root 'src\Gui\guard.ico'
$svcExtra = @(); if (Test-Path $icon) { $svcExtra += "/win32icon:$icon" }
Build 'ClaudeVPNGuard.Service.exe' 'exe' ($core + (Get-ChildItem (Join-Path $root 'src\Service') -Filter *.cs | ForEach-Object FullName)) $svcExtra
$guiExtra = @()
if (Test-Path $icon) { $guiExtra += "/win32icon:$icon" }
Build 'ClaudeVPNGuard.exe' 'winexe' ($core + (Get-ChildItem (Join-Path $root 'src\Gui') -Filter *.cs | ForEach-Object FullName)) $guiExtra
Build 'ClaudeVPNGuard-Setup.exe' 'winexe' ($core + (Get-ChildItem (Join-Path $root 'src\Setup') -Filter *.cs | ForEach-Object FullName)) $guiExtra
Copy-Item $icon (Join-Path $dist 'guard.ico') -Force
Copy-Item (Join-Path $root 'scripts\full-uninstall.ps1') (Join-Path $dist 'full-uninstall.ps1') -Force
Build 'ClaudeVPNGuard.Tests.exe' 'exe' ($core + (Get-ChildItem (Join-Path $root 'tests') -Filter *.cs | ForEach-Object FullName)) @()

if ($RunTests) {
    & (Join-Path $dist 'ClaudeVPNGuard.Tests.exe')
    if ($LASTEXITCODE -ne 0) { throw "单元测试失败" }
}
