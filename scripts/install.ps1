# written_by: claude-code
# Claude VPN Guard 事务性安装（需管理员；仅在用户确认后执行）。
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [-Isolation]
# 步骤：安装前检查 → 备份（防火墙策略导出、现有规则清单、旧版本程序）→ 暂存 → 应用 → 验证
# 失败回滚原则：
#   · 升级安装失败：恢复旧版本程序并重新注册，旧规则从不删除（不会因回滚解除原本有效的保护）
#   · 全新安装失败：删除本次新建的规则/过滤器（安装前本来就没有保护，回到安装前状态）
param([switch]$Isolation)
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $a = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""
    if ($Isolation) { $a += ' -Isolation' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    return
}
$root = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $root 'dist'
$dst = Join-Path $env:ProgramFiles 'ClaudeVPNGuard'
$data = Join-Path $env:ProgramData 'ClaudeVPNGuard'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$bk = Join-Path $data "backup\$stamp"
New-Item -ItemType Directory -Force $bk | Out-Null
$log = Join-Path $bk 'install.log'
function Step($m) { $line = "$(Get-Date -Format 'HH:mm:ss') $m"; Write-Host $line; Add-Content $log $line -Encoding UTF8 }

if (-not (Test-Path (Join-Path $dist 'ClaudeVPNGuard.Service.exe'))) { & (Join-Path $PSScriptRoot 'build.ps1') }

# 1. 安装前检查（只读）
Step '1/5 安装前检查'
& (Join-Path $dist 'ClaudeVPNGuard.Service.exe') preflight (Join-Path $bk 'preflight.txt')
if ($LASTEXITCODE -eq 3) { Step '存在阻止项，未做任何修改，安装中止。'; return }

# 2. 备份
Step '2/5 备份'
& netsh advfirewall export (Join-Path $bk 'firewall-policy.wfw') | Out-Null
Get-NetFirewallRule -Group 'ClaudeVPNGuard' -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Enabled, Action | Export-Csv (Join-Path $bk 'existing-cvg-rules.csv') -NoTypeInformation -Encoding UTF8
$prevSvc = Get-Service ClaudeVPNGuard -ErrorAction SilentlyContinue
$upgrade = $null -ne $prevSvc -and (Test-Path (Join-Path $dst 'ClaudeVPNGuard.Service.exe'))
if ($upgrade) { Copy-Item $dst (Join-Path $bk 'prev-bin') -Recurse -Force; Step "  已备份旧版本程序（升级安装）" }
if (Test-Path (Join-Path $data 'settings.json')) { Copy-Item (Join-Path $data 'settings.json') (Join-Path $bk 'settings.json') }
Step "  备份目录：$bk"

# 3. 暂存
Step '3/5 暂存新版本'
$stage = Join-Path $data "staging-$stamp"
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item (Join-Path $dist 'ClaudeVPNGuard.exe'), (Join-Path $dist 'ClaudeVPNGuard.Service.exe') $stage -Force

try {
    # 4. 应用（服务停止期间锁定规则保持启用）
    Step '4/5 应用'
    if ($prevSvc -and $prevSvc.Status -eq 'Running') { Stop-Service ClaudeVPNGuard -Force; Start-Sleep 1 }
    Get-Process ClaudeVPNGuard -ErrorAction SilentlyContinue | Stop-Process -Force
    New-Item -ItemType Directory -Force $dst | Out-Null
    Copy-Item (Join-Path $stage '*') $dst -Force
    if ($Isolation) {
        $sf = Join-Path $data 'settings.json'
        $s = if (Test-Path $sf) { Get-Content $sf -Raw -Encoding UTF8 | ConvertFrom-Json } else { New-Object psobject }
        $s | Add-Member -NotePropertyName IsolationMode -NotePropertyValue $true -Force
        [IO.File]::WriteAllText($sf, ($s | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
        Step '  已启用隔离模式（Claude 只能经专用入口出网）'
    }
    & (Join-Path $dst 'ClaudeVPNGuard.Service.exe') install
    if ($LASTEXITCODE -ne 0) { throw "服务安装失败（$LASTEXITCODE）" }

    # 5. 验证
    Step '5/5 验证'
    $ok = $false
    for ($i = 0; $i -lt 10 -and -not $ok; $i++) { Start-Sleep 1; & (Join-Path $dst 'ClaudeVPNGuard.Service.exe') verify; $ok = $LASTEXITCODE -eq 0 }
    if (-not $ok) { throw '验证未通过：服务未运行或规则/过滤器不完整' }
    $lnk = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Claude VPN Guard.lnk'
    $ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut($lnk); $sc.TargetPath = Join-Path $dst 'ClaudeVPNGuard.exe'; $sc.Save()
    Step "安装完成：$dst"
    Write-Host "建议执行实测（管理员）：& '$dst\ClaudeVPNGuard.Service.exe' selftest" -ForegroundColor Green
    Start-Process (Join-Path $dst 'ClaudeVPNGuard.exe')
}
catch {
    Step "安装失败：$($_.Exception.Message) → 回滚"
    if ($upgrade) {
        Copy-Item (Join-Path $bk 'prev-bin\*') $dst -Force
        if (Test-Path (Join-Path $bk 'settings.json')) { Copy-Item (Join-Path $bk 'settings.json') (Join-Path $data 'settings.json') -Force }
        & (Join-Path $dst 'ClaudeVPNGuard.Service.exe') install | Out-Null
        Step '  已恢复旧版本并重新启动保护服务；原有规则未被删除。'
    } else {
        if (Test-Path (Join-Path $dst 'ClaudeVPNGuard.Service.exe')) { & (Join-Path $dst 'ClaudeVPNGuard.Service.exe') uninstall | Out-Null }
        Step '  全新安装回滚：已删除本次创建的服务、规则与过滤器（安装前无保护，状态还原）。'
    }
    throw
}
finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
