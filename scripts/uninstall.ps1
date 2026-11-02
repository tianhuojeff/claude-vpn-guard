# written_by: claude-code
# 安全卸载（需管理员）：停止删除服务 → 删除规则组 ClaudeVPNGuard 下的全部规则（不碰其他规则）→ 删除程序文件。日志保留。
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""
    return
}
$dst = Join-Path $env:ProgramFiles 'ClaudeVPNGuard'
$exe = Join-Path $dst 'ClaudeVPNGuard.Service.exe'
Get-Process ClaudeVPNGuard -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $exe) { & $exe uninstall }
# 兜底：即使程序文件已丢失，也能按规则组清理
Get-NetFirewallRule -Group 'ClaudeVPNGuard' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name ClaudeVPNGuard -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Claude VPN Guard.lnk') -ErrorAction SilentlyContinue
Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "卸载完成。剩余规则数：$((Get-NetFirewallRule -Group 'ClaudeVPNGuard' -ErrorAction SilentlyContinue | Measure-Object).Count)（应为 0）。日志保留在 $env:ProgramData\ClaudeVPNGuard\logs" -ForegroundColor Green
