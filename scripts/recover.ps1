# written_by: claude-code
# 应急恢复（需管理员）：规则/过滤器导致无法正常使用时，解除本程序的全部网络限制。
# 只删除规则组 ClaudeVPNGuard 与本程序 WFP 子层下的过滤器，不触碰其他任何规则。执行后 Claude 不再受保护。
$ErrorActionPreference = 'Continue'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""; return }
$candidates = @((Join-Path $env:ProgramFiles 'ClaudeVPNGuard\ClaudeVPNGuard.Service.exe'), (Join-Path $env:ProgramData 'ClaudeVPNGuard\recovery\ClaudeVPNGuard.Service.exe'), (Join-Path (Split-Path $PSScriptRoot -Parent) 'dist\ClaudeVPNGuard.Service.exe'))
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($exe) { & $exe recover } else { Write-Warning '找不到服务程序，无法删除 WFP 过滤器；仅清理 Windows 防火墙规则。' }
Get-NetFirewallRule -Group 'ClaudeVPNGuard' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "剩余防火墙规则：$((Get-NetFirewallRule -Group 'ClaudeVPNGuard' -ErrorAction SilentlyContinue | Measure-Object).Count)"
if ($exe) { & $exe audit | Select-String 'WFP|已有过滤器' }
Write-Host '恢复保护：重新运行 scripts\install.ps1' -ForegroundColor Yellow
