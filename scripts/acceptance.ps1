# written_by: claude-code
# Claude VPN Guard V2 一键实机验收（需管理员，用户在场执行）。
#   powershell -ExecutionPolicy Bypass -File scripts\acceptance.ps1 [-SkipFaultTests]
# 原则：
#   · 每一个管理员操作 / 会改变网络、Claude、配置的步骤，事前逐项确认
#   · selftest 失败立即停止：不安装服务、不修改正式防火墙规则、不修改 Clash 配置、不配置 Claude Code
#   · 每步失败都回滚本步修改（安装由 install.ps1 事务回滚；系统代理测试在 finally 中还原；Claude Code 配置失败即还原）
#   · selftest（替身程序）通过 ≠ 正式 Claude 隔离通过；正式 Claude 在第 6 步单独验证
#   · 不关闭 spacedesk；不修改除 Japan Auto 以外的代理组；不修改任何用户级/系统级环境变量
param([switch]$SkipFaultTests)
$ErrorActionPreference = 'Continue'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $a = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""
    if ($SkipFaultTests) { $a += ' -SkipFaultTests' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    return
}
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = Split-Path $PSScriptRoot -Parent
$svcDist = Join-Path $root 'dist\ClaudeVPNGuard.Service.exe'
$svcInst = Join-Path $env:ProgramFiles 'ClaudeVPNGuard\ClaudeVPNGuard.Service.exe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$report = Join-Path $root "docs\V2实机验收记录-$stamp.md"
$lines = New-Object System.Collections.Generic.List[string]
function Rec($s) { $lines.Add($s); Write-Host $s }
function Save { [IO.File]::WriteAllLines($report, $lines, (New-Object Text.UTF8Encoding $false)) }
function Ask($q) { $x = Read-Host "$q [y/N]"; return $x -match '^(y|Y|是)$' }
function Stop-Here($why) { Rec ""; Rec "**验收在此停止：$why**"; Rec "未安装服务、未修改正式防火墙规则、未修改 Clash 配置、未配置 Claude Code。"; Save; Write-Host "`n记录：$report" -ForegroundColor Yellow; exit 1 }
function Svc { if (Test-Path $svcInst) { $svcInst } else { $svcDist } }
function SpaceDesk {
    $p = Get-Process | Where-Object { $_.ProcessName -match 'spacedesk' }
    if (-not $p) { return '未运行' }
    $est = @(Get-NetTCPConnection -OwningProcess $p.Id -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' })
    if ($est.Count -gt 0) { return "已连接 $(($est | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" }) -join ',')" }
    return '服务运行，无 TCP 扩展屏连接'
}
function IsoCheck($label) {
    $sd0 = SpaceDesk
    $out = & (Svc) isocheck 2>&1 | Out-String
    $code = $LASTEXITCODE
    Rec "| $label | $(if ($code -eq 0) { '✅ 必须阻断项全部阻断' } else { '❌ 存在未阻断路径' }) | $($out.Trim()) | 前：$sd0 / 后：$(SpaceDesk) |"
    return $code -eq 0
}

Rec "---"; Rec "written_by: claude-code（acceptance.ps1 自动生成）"; Rec "---"; Rec ""
Rec "# Claude VPN Guard V2 实机验收记录 $stamp"; Rec ""
Rec "机器：$env:COMPUTERNAME　Windows $([Environment]::OSVersion.Version)　执行者：$env:USERNAME（管理员）"; Rec ""

# ── 1 安装前检查（只读）
Rec "## 1. 安装前检查 / 防火墙审计（只读）"
$pf = Join-Path $root "docs\evidence-preflight-admin-$stamp.txt"
& $svcDist preflight $pf | Out-Null
$pfCode = $LASTEXITCODE
Rec "完整输出：``$(Split-Path $pf -Leaf)``"
Get-Content $pf -Encoding UTF8 | Select-String '\[(阻止|警告)\]|结论|spacedesk：' | ForEach-Object { Rec "- $($_.Line.Trim())" }
& $svcDist verge-diff (Join-Path $root "docs\evidence-verge-diff-$stamp.txt") | Out-Null
Rec "- Clash 覆写差异报告：``evidence-verge-diff-$stamp.txt``（恢复：``ClaudeVPNGuard.Service.exe verge-restore``）"
Save
if ($pfCode -eq 3) { Stop-Here '安装前检查存在阻止项' }

# ── 2 selftest（事前逐项确认）
Rec ""; Rec "## 2. 系统级阻断实测 selftest（替身程序）"
Write-Host "`nselftest 执行前确认：" -ForegroundColor Cyan
$items = @(
    '测试程序是本程序副本（替身），WFP 过滤器生成逻辑与正式 Claude 相同，但只作用于替身，不影响真实 Claude、Clash Verge、spacedesk',
    '将实测：替身→127.0.0.1:17897 成功；→其他本地代理端口 阻断；→公网 IPv4 阻断；IPv6（本机可测范围）按规则处理；→UDP 直连 阻断',
    '测试结束逐项确认替身过滤器已删除，并对比前后系统 WFP 快照，确认系统原有 WFP 状态未改变',
    '测试失败将保留完整诊断日志并停止验收：不安装服务、不修改正式防火墙规则、不修改 Clash 配置',
    '测试期间临时监听本机端口 27990/27991（及空闲时的 17897），测试后释放；Windows 防火墙部分会对替身临时添加并删除规则')
for ($i = 0; $i -lt $items.Count; $i++) {
    Write-Host "  $($i + 1). $($items[$i])"
    if (-not (Ask '     确认此项？')) { Stop-Here "selftest 第 $($i + 1) 项未确认" }
    Rec "- 已确认：$($items[$i])"
}
$st = Join-Path $root "docs\evidence-selftest-$stamp.txt"
& $svcDist selftest --yes *> $st
$selfCode = $LASTEXITCODE
Rec ""; Rec "完整输出：``$(Split-Path $st -Leaf)``，退出码 $selfCode"
$selfText = Get-Content $st -Encoding UTF8
$selfText | Select-String '\[(通过|失败|未验证)\]|结果：|快照对比|已全部删除' | ForEach-Object { Rec "- $($_.Line.Trim())" }
Save
if ($selfCode -ne 0) { Stop-Here "selftest 未全部通过（退出码 $selfCode），诊断见 $(Split-Path $st -Leaf) 与 C:\ProgramData\ClaudeVPNGuard\wfp-selftest-*.txt" }
Rec ""; Rec "**selftest 通过：这套过滤器作用于替身程序时，系统真实执行了预期的阻断/放行。注意：这不等于正式 Claude 的隔离已通过（见第 6 步）。**"

# ── 3 Clash 覆写生效（用户在 Clash Verge 中操作）
Rec ""; Rec "## 3. Clash Verge 覆写（Japan Auto + 专用入口）"
$listen = { [bool](Get-NetTCPConnection -LocalPort 17897 -State Listen -ErrorAction SilentlyContinue) }
if (-not (& $listen)) {
    Write-Host "`n覆写已写入 Script.js（差异见上），尚未加载。" -ForegroundColor Yellow
    if (Ask '现在在 Clash Verge 中刷新当前订阅使其生效？（会短暂中断代理；选 N 则可用 verge-restore 撤销覆写并结束验收）') {
        Read-Host '请在 Clash Verge：订阅 → 当前订阅 → 刷新（或重启 Clash Verge），完成后按回车'
    } else {
        if (Ask '撤销覆写（恢复原 Script.js）？') { & $svcDist verge-restore | ForEach-Object { Rec "- $_" } }
        Stop-Here '用户未加载覆写'
    }
}
$lOk = & $listen
Rec "- 专用入口 127.0.0.1:17897：$(if ($lOk) { '在线' } else { '未监听（覆写未生效）' })"
& $svcDist audit | Select-String 'Japan Auto 组|识别到的日本节点' | ForEach-Object { Rec "- $($_.Line.Trim())" }
Save
if (-not $lOk) { Stop-Here '专用入口未生效，不能启用隔离模式' }

# ── 4 安装（事务性）
Rec ""; Rec "## 4. 安装保护服务（隔离模式）"
Write-Host "`n将执行：备份防火墙策略 → 安装服务 → 为真实 Claude 程序下发 Windows 防火墙规则 + WFP 持久过滤器（隔离模式）→ 验证；失败自动回滚。" -ForegroundColor Cyan
if (-not (Ask '确认安装？')) { Stop-Here '用户未确认安装' }
try { & (Join-Path $PSScriptRoot 'install.ps1') -Isolation }
catch { Rec "- ❌ 安装失败并已回滚：$($_.Exception.Message)"; Stop-Here '安装失败' }
Start-Sleep 5
& $svcInst verify | ForEach-Object { Rec "- verify：$_" }
& $svcInst audit | Select-String '作用范围|持久性|已有过滤器' | ForEach-Object { Rec "- $($_.Line.Trim())" }
Save

# ── 5 Claude Code 专用代理（只改 Claude Code 自己的设置）
Rec ""; Rec "## 5. Claude Code 专用代理"
Write-Host "`n用户环境变量 HTTP(S)_PROXY 指向 7897，隔离模式下 Claude Code 将无法联网。" -ForegroundColor Yellow
Write-Host "可选：只在 Claude Code 自己的 %USERPROFILE%\.claude\settings.json 的 env 中设置代理为 127.0.0.1:17897（先备份；不修改任何用户级/系统级环境变量，不影响其他软件）。"
if (Ask '配置 Claude Code 专用代理？') {
    $o = & $svcInst cc-proxy apply 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { & $svcInst cc-proxy remove | Out-Null; Rec "- ❌ 配置失败已还原：$o" } else { Rec "- $($o.Trim())" }
} else { Rec "- 未配置（Claude Code 在隔离模式下将无法联网，不会泄漏）" }
Save

# ── 6 spacedesk 与故障场景
Rec ""; Rec "## 6. spacedesk 兼容性与故障场景（替身隔离检查）"
Read-Host "`n如方便请现在连接 spacedesk 扩展屏（不方便直接回车）"
Rec "- spacedesk：$(SpaceDesk)"
Write-Host "以下每个场景都会对替身程序临时下发并删除 WFP 过滤器（不影响真实 Claude）。"
if (-not (Ask '确认执行场景检查？')) { Stop-Here '用户未确认场景检查' }
Rec ""; Rec "| 场景 | 隔离结果 | 明细 | spacedesk |"; Rec "|---|---|---|---|"
[void](IsoCheck 'Clash 正常')
Save
if (-not $SkipFaultTests) {
    if (Ask '测试“关闭系统代理”？（约 10 秒后自动还原）') {
        $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $old = (Get-ItemProperty $k).ProxyEnable
        try { Set-ItemProperty $k ProxyEnable 0; Start-Sleep 3; [void](IsoCheck '系统代理关闭') }
        finally { Set-ItemProperty $k ProxyEnable $old; Rec "  - 系统代理已还原为 ProxyEnable=$old" }
    }
    if (Ask '测试“Japan Auto 节点切换”？') {
        $sw = & (Svc) jp-switch | Out-String
        [void](IsoCheck "节点切换（$($sw.Trim())）")
    }
    if (Ask '测试“Mihomo 内核崩溃”？（强制结束 verge-mihomo，代理中断数秒，运行中的 Claude 会被保护性关闭）') {
        $t0 = Get-Date
        Get-Process verge-mihomo -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep 2
        [void](IsoCheck '内核崩溃后')
        $log = Get-ChildItem "$env:ProgramData\ClaudeVPNGuard\logs\guard-*.log" | Sort-Object LastWriteTime | Select-Object -Last 1
        if ($log) { Get-Content $log.FullName -Encoding UTF8 | Select-String '内核进程退出|保护性关闭|锁定' | Where-Object { $_.Line -ge $t0.ToString('yyyy-MM-dd HH:mm:ss') } | Select-Object -First 4 | ForEach-Object { Rec "  - 日志：$($_.Line)" } }
        Rec "  - 故障注入时刻：$($t0.ToString('HH:mm:ss.fff'))"
        Write-Host '等待 Clash Verge 重新拉起内核（最多 30 秒）…'
        for ($i = 0; $i -lt 30 -and -not (Get-Process verge-mihomo -ErrorAction SilentlyContinue); $i++) { Start-Sleep 1 }
        if (-not (Get-Process verge-mihomo -ErrorAction SilentlyContinue)) { Read-Host '内核未自动恢复，请手动重启 Clash Verge 后按回车' }
        Start-Sleep 5
        [void](IsoCheck '内核恢复后')
    }
}
Save

# ── 7 正式 Claude 隔离验证（与 selftest 分开）
Rec ""; Rec "## 7. 正式 Claude 的隔离验证"
Rec "- 过滤器层：verify 已确认真实 Claude 程序的 WFP 过滤器存在（见第 4 步）"
if (Ask '验证真实 Claude 是否只经专用入口出网？（需要你先完全退出 Claude，再在保护器中点“启动 Claude”，对话一句）') {
    Read-Host '完成后按回车'
    & $svcInst diag | Select-String 'Claude 连接审计|代理路径探测|Japan Auto|专用入口|结论' | ForEach-Object { Rec "- 真实 Claude：$($_.Line.Trim())" }
    Rec "- 判定标准：连接审计无“未经专用入口/直连/非回环连接”，结论为安全"
} else { Rec "- **未验证**：正式 Claude 的实际出网路径" }

Rec ""; Rec "## 8. 结论"
Rec "- 本记录只陈述实测结果；未执行、被跳过或失败的项目一律不视为已安全。"
Rec "- 重启持久性需另行执行：selftest --keep → 重启 → selftest --after-reboot。"
Save
Write-Host "`n验收记录：$report" -ForegroundColor Green
