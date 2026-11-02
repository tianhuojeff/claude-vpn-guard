# written_by: claude-code
# Claude VPN Guard 完全卸载 / 紧急恢复（只用 Windows 自带的 PowerShell、sc.exe、注册表，不调用本程序任何 exe）
# 为什么：本程序的 exe 没有代码签名，可能被 Windows“智能应用控制/应用程序控制策略”拦截，
# 一旦被拦，exe 版卸载就跑不起来，而持久化的 WFP 过滤器会一直挡住 Claude。本脚本不依赖那些 exe。
# 清理内容：
#   1) 结束 GUI / 服务 / 安装程序进程，停止并删除服务 ClaudeVPNGuard
#   2) 删除 WFP 中本程序子层下的全部过滤器、子层、提供程序（反射发射 P/Invoke，不落地 DLL）
#   3) 删除防火墙规则组 ClaudeVPNGuard 的全部规则（不碰其他规则）
#   4) 从 Clash Verge 全局扩展脚本 Script.js 去掉本程序段（先备份）
#   5) 还原 ~/.claude/settings.json 里本程序写入的代理 env（先备份）
#   6) 删除卸载注册表项、开机启动项、开始菜单与桌面快捷方式
#   7) 删除 Program Files\ClaudeVPNGuard；ProgramData\ClaudeVPNGuard 先打包备份到桌面再删除
# 用法：右键“用 PowerShell 运行”，或  powershell -ExecutionPolicy Bypass -File full-uninstall.ps1 [-DryRun] [-KeepData] [-Yes]
#   -Yes      不再询问确认
#   -DryRun   只检查、只报告，不改任何东西
#   -KeepData 保留 ProgramData（设置与日志）
param([switch]$DryRun, [switch]$KeepData, [switch]$Yes, [string]$UserHome = $env:USERPROFILE, [string]$UserAppData = $env:APPDATA, [string]$UserDesktop = [Environment]::GetFolderPath('Desktop'))

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $DryRun) {
    # 提权后仍按当前用户的目录处理 Verge / Claude 设置
    $a = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`" -UserHome `"$UserHome`" -UserAppData `"$UserAppData`" -UserDesktop `"$UserDesktop`""
    if ($DryRun) { $a += ' -DryRun' }
    if ($KeepData) { $a += ' -KeepData' }
    if ($Yes) { $a += ' -Yes' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    return
}

$ErrorActionPreference = 'Continue'
if (-not $DryRun -and -not $Yes) {
    Write-Host '将完全卸载 Claude VPN Guard：服务、WFP 过滤器、防火墙规则组、Clash Verge 扩展脚本段、Claude Code 代理设置、快捷方式、程序文件与数据（数据先打包到桌面）。' -ForegroundColor Yellow
    Write-Host '卸载后 Claude 直接走系统网络/代理，不再受本程序保护。' -ForegroundColor Yellow
    if ((Read-Host '输入 Y 确认卸载') -notmatch '^[Yy]') { Write-Host '已取消，未做任何改动。'; return }
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$report = New-Object System.Collections.Generic.List[string]
function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c; $report.Add($m) }
function Act($what, [scriptblock]$do) {
    if ($DryRun) { Say "  [只检查] 将会：$what" 'Yellow'; return }
    try { & $do; Say "  已完成：$what" 'Green' } catch { Say "  失败：$what —— $($_.Exception.Message)" 'Red' }
}
Say ("Claude VPN Guard 完全卸载  " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + $(if ($DryRun) { '  （只检查模式）' } else { '' })) 'Cyan'

$svc = 'ClaudeVPNGuard'
$installDir = Join-Path $env:ProgramFiles 'ClaudeVPNGuard'
$dataDir = Join-Path $env:ProgramData 'ClaudeVPNGuard'
$providerKey = [Guid]'5d3c2a1e-7b9f-4c61-9e2a-c1a0de5c0a01'
$subLayerKey = [Guid]'5d3c2a1e-7b9f-4c61-9e2a-c1a0de5c0a02'

# ---------- 1. 进程与服务 ----------
Say '1. 进程与服务'
$procs = Get-Process -Name 'ClaudeVPNGuard', 'ClaudeVPNGuard.Service', 'ClaudeVPNGuard-Setup' -ErrorAction SilentlyContinue
if ($procs) { Act ("结束进程 " + (($procs | ForEach-Object { "$($_.Name)($($_.Id))" }) -join ', ')) { $procs | Stop-Process -Force -ErrorAction Stop } }
else { Say '  没有运行中的本程序进程' }
if (Get-Service $svc -ErrorAction SilentlyContinue) {
    Act "停止并删除服务 $svc" {
        sc.exe stop $svc | Out-Null
        for ($i = 0; $i -lt 20 -and (Get-Service $svc -ErrorAction SilentlyContinue).Status -ne 'Stopped'; $i++) { Start-Sleep -Milliseconds 500 }
        Get-Process -Name 'ClaudeVPNGuard.Service' -ErrorAction SilentlyContinue | Stop-Process -Force
        $o = sc.exe delete $svc
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060) { throw "sc delete 返回 $LASTEXITCODE：$o" }
    }
} else { Say '  服务不存在（已删除）' }

# ---------- 2. WFP ----------
Say '2. WFP 过滤器'
function New-WfpApi {
    # 用 Reflection.Emit 在内存里定义 P/Invoke，不编译、不写临时 DLL，避免被应用程序控制拦截
    $asm = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName 'CvgWfp'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $mod = $asm.DefineDynamicModule('CvgWfp')
    $tb = $mod.DefineType('CvgWfp.Api', 'Public, Class')
    $IP = [IntPtr]; $IPr = [IntPtr].MakeByRefType(); $U = [UInt32]; $Ur = [UInt32].MakeByRefType(); $Gr = [Guid].MakeByRefType()
    $defs = @(
        @('FwpmEngineOpen0', @($IP, $U, $IP, $IP, $IPr)),
        @('FwpmEngineClose0', @($IP)),
        @('FwpmFilterCreateEnumHandle0', @($IP, $IP, $IPr)),
        @('FwpmFilterEnum0', @($IP, $IP, $U, $IPr, $Ur)),
        @('FwpmFilterDestroyEnumHandle0', @($IP, $IP)),
        @('FwpmFilterDeleteByKey0', @($IP, $Gr)),
        @('FwpmSubLayerDeleteByKey0', @($IP, $Gr)),
        @('FwpmProviderDeleteByKey0', @($IP, $Gr)),
        @('FwpmSubLayerGetByKey0', @($IP, $Gr, $IPr)),
        @('FwpmProviderGetByKey0', @($IP, $Gr, $IPr)),
        @('FwpmFreeMemory0', @($IPr))
    )
    foreach ($d in $defs) {
        $m = $tb.DefinePInvokeMethod($d[0], 'fwpuclnt.dll', 'Public, Static, PinvokeImpl', 'Standard', $U, [Type[]]$d[1], 'Winapi', 'Unicode')
        $m.SetImplementationFlags('PreserveSig')
    }
    $tb.CreateType()
}
function Read-Guid($p, $off) { $b = New-Object byte[] 16; [Runtime.InteropServices.Marshal]::Copy([IntPtr]($p.ToInt64() + $off), $b, 0, 16); New-Object Guid (, $b) }
try {
    $api = New-WfpApi
    $eng = [IntPtr]::Zero
    $rc = $api::FwpmEngineOpen0([IntPtr]::Zero, 10, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$eng)
    if ($rc -ne 0) { throw ("打开 WFP 引擎失败 0x{0:X8}" -f $rc) }
    try {
        # FWPM_FILTER0（x64）：filterKey@0、providerKey 指针@40、subLayerKey@80
        $ours = New-Object System.Collections.Generic.List[Guid]
        $h = [IntPtr]::Zero
        $rcEnum = $api::FwpmFilterCreateEnumHandle0($eng, [IntPtr]::Zero, [ref]$h)
        if ($rcEnum -ne 0) { Say ("  无法枚举 WFP 过滤器 0x{0:X8}（需要管理员权限）" -f $rcEnum) 'Yellow' }
        else {
            try {
                while ($true) {
                    $entries = [IntPtr]::Zero; [uint32]$n = 0
                    if ($api::FwpmFilterEnum0($eng, $h, 1024, [ref]$entries, [ref]$n) -ne 0 -or $n -eq 0) { break }
                    try {
                        for ($i = 0; $i -lt $n; $i++) {
                            $f = [Runtime.InteropServices.Marshal]::ReadIntPtr($entries, $i * [IntPtr]::Size)
                            $pp = [Runtime.InteropServices.Marshal]::ReadIntPtr($f, 40)
                            $mine = (Read-Guid $f 80) -eq $subLayerKey
                            if (-not $mine -and $pp -ne [IntPtr]::Zero) { $mine = (Read-Guid $pp 0) -eq $providerKey }
                            if ($mine) { $ours.Add((Read-Guid $f 0)) }
                        }
                    } finally { $api::FwpmFreeMemory0([ref]$entries) | Out-Null }
                    if ($n -lt 1024) { break }
                }
            } finally { $api::FwpmFilterDestroyEnumHandle0($eng, $h) | Out-Null }
        }
        $sk = $subLayerKey; $pk = $providerKey; $tmp = [IntPtr]::Zero
        $hasSub = $api::FwpmSubLayerGetByKey0($eng, [ref]$sk, [ref]$tmp) -eq 0; if ($hasSub) { $api::FwpmFreeMemory0([ref]$tmp) | Out-Null }
        $hasProv = $api::FwpmProviderGetByKey0($eng, [ref]$pk, [ref]$tmp) -eq 0; if ($hasProv) { $api::FwpmFreeMemory0([ref]$tmp) | Out-Null }
        Say ("  发现本程序 WFP 过滤器 {0} 条；子层{1}；提供程序{2}" -f $ours.Count, $(if ($hasSub) { '存在' } else { '不存在' }), $(if ($hasProv) { '存在' } else { '不存在' }))
        if ($ours.Count -gt 0 -or $hasSub -or $hasProv) {
            Act "删除本程序 WFP 过滤器 $($ours.Count) 条、子层、提供程序" {
                $bad = 0
                foreach ($k in $ours) { $kk = $k; $r = $api::FwpmFilterDeleteByKey0($eng, [ref]$kk); if ($r -ne 0 -and $r -ne 0x80320003) { $bad++ } }
                $sk = $subLayerKey; $r1 = $api::FwpmSubLayerDeleteByKey0($eng, [ref]$sk)
                $pk = $providerKey; $r2 = $api::FwpmProviderDeleteByKey0($eng, [ref]$pk)
                if ($bad -gt 0) { throw "$bad 条过滤器删除失败" }
                # 0x80320007 子层不存在 / 0x80320005 提供程序不存在 都算成功
                if ($r1 -ne 0 -and $r1 -ne 0x80320007) { throw ("删除子层失败 0x{0:X8}" -f $r1) }
                if ($r2 -ne 0 -and $r2 -ne 0x80320005) { throw ("删除提供程序失败 0x{0:X8}" -f $r2) }
            }
        }
    } finally { $api::FwpmEngineClose0($eng) | Out-Null }
} catch { Say "  WFP 处理出错：$($_.Exception.Message)。备选：重启电脑进入安全模式后再运行本脚本。" 'Red' }

# ---------- 3. 防火墙 ----------
Say '3. 防火墙规则组 ClaudeVPNGuard'
$rules = @(Get-NetFirewallRule -Group 'ClaudeVPNGuard' -ErrorAction SilentlyContinue)
if ($rules.Count -gt 0) { Act "删除规则组 ClaudeVPNGuard 的 $($rules.Count) 条规则" { $rules | Remove-NetFirewallRule -ErrorAction Stop } }
else { Say '  没有本程序的防火墙规则' }

# ---------- 4. Clash Verge 全局扩展脚本 ----------
Say '4. Clash Verge 全局扩展脚本'
$begin = '// ===== ClaudeVPNGuard:BEGIN'
$end = '// ===== ClaudeVPNGuard:END ====='
$script = Join-Path $UserAppData 'io.github.clash-verge-rev.clash-verge-rev\profiles\Script.js'
if (Test-Path $script) {
    $s = [IO.File]::ReadAllText($script, [Text.Encoding]::UTF8)
    $b = $s.IndexOf($begin, [StringComparison]::Ordinal)
    $e = if ($b -ge 0) { $s.IndexOf($end, $b, [StringComparison]::Ordinal) } else { -1 }
    if ($b -ge 0 -and $e -ge 0) {
        Act "去掉 Script.js 中的本程序段（备份为 Script.js.cvg-uninstall-$stamp）" {
            Copy-Item $script "$script.cvg-uninstall-$stamp" -Force
            $after = $s.Substring($e + $end.Length)
            $after = [regex]::Replace($after, '\s*function main\(config, profileName\) \{ return cvgApply\(cvgUserMain\(config, profileName\)\); \}\s*', "`n")
            $r = ($s.Substring(0, $b) + $after).Replace('function cvgUserMain(', 'function main(')
            [IO.File]::WriteAllText($script, $r.TrimEnd() + "`n", (New-Object Text.UTF8Encoding $false))
        }
        Say '  提示：需在 Clash Verge 里点一次“刷新/重新加载配置”，17897 专用入口才会消失（本脚本不会重启 Clash Verge）。' 'Yellow'
    } else { Say '  Script.js 中没有本程序段' }
} else { Say '  未找到 Clash Verge 全局扩展脚本' }

# ---------- 5. Claude Code 代理 env ----------
Say '5. ~/.claude/settings.json 代理设置'
$cc = Join-Path $UserHome '.claude\settings.json'
if (Test-Path $cc) {
    $raw = [IO.File]::ReadAllText($cc, [Text.Encoding]::UTF8)
    try { $j = $raw | ConvertFrom-Json } catch { $j = $null; Say "  settings.json 解析失败，未改动：$($_.Exception.Message)" 'Red' }
    $keys = 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY'
    if ($j -and $j.env -and ([string]$j.env.HTTPS_PROXY) -match ':17897') {
        Act "还原 settings.json 中本程序写入的代理 env（备份为 settings.json.cvg-uninstall-$stamp）" {
            Copy-Item $cc "$cc.cvg-uninstall-$stamp" -Force
            $orig = $null; $of = "$cc.cvg-orig.json"
            if (Test-Path $of) { $orig = [IO.File]::ReadAllText($of, [Text.Encoding]::UTF8) | ConvertFrom-Json }
            foreach ($k in $keys) {
                if ($orig -and $orig.$k) { $j.env.$k = $orig.$k } else { $j.env.PSObject.Properties.Remove($k) }
            }
            if (@($j.env.PSObject.Properties).Count -eq 0) { $j.PSObject.Properties.Remove('env') }
            [IO.File]::WriteAllText($cc, ($j | ConvertTo-Json -Depth 32) + "`n", (New-Object Text.UTF8Encoding $false))
            Remove-Item $of -ErrorAction SilentlyContinue
        }
    } else { Say '  没有指向 17897 的代理 env，未改动' }
} else { Say '  未找到 settings.json' }

# ---------- 6. 注册表与快捷方式 ----------
Say '6. 注册表与快捷方式'
$uk = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeVPNGuard'
if (Test-Path $uk) { Act '删除“应用和功能”卸载项' { Remove-Item $uk -Recurse -Force -ErrorAction Stop } }
foreach ($run in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run') {
    if ((Get-ItemProperty $run -ErrorAction SilentlyContinue).ClaudeVPNGuard) { Act "删除开机启动项 $run\ClaudeVPNGuard" { Remove-ItemProperty $run -Name ClaudeVPNGuard -ErrorAction Stop } }
}
$lnks = @(
    (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Claude VPN Guard'),
    (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Claude VPN Guard.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Claude VPN Guard.lnk'),
    (Join-Path $UserDesktop 'Claude VPN Guard.lnk'),
    (Join-Path $UserAppData 'Microsoft\Windows\Start Menu\Programs\Claude VPN Guard.lnk')
) | Where-Object { Test-Path $_ }
foreach ($l in $lnks) { Act "删除快捷方式 $l" { Remove-Item $l -Recurse -Force -ErrorAction Stop } }

# ---------- 7. 程序文件与数据 ----------
Say '7. 程序文件与数据'
if (Test-Path $installDir) { Act "删除 $installDir" { Remove-Item $installDir -Recurse -Force -ErrorAction Stop } }
else { Say '  程序目录不存在' }
if ((Test-Path $dataDir) -and -not $KeepData) {
    $zip = Join-Path $UserDesktop "ClaudeVPNGuard-卸载备份-$stamp.zip"
    Act "把 $dataDir 打包备份到 $zip 后删除" {
        Compress-Archive -Path (Join-Path $dataDir '*') -DestinationPath $zip -Force -ErrorAction Stop
        Remove-Item $dataDir -Recurse -Force -ErrorAction Stop
    }
}

# ---------- 复查 ----------
Say '复查' 'Cyan'
$left = @()
if (Get-Service $svc -ErrorAction SilentlyContinue) { $left += '服务仍存在' }
if (@(Get-NetFirewallRule -Group 'ClaudeVPNGuard' -ErrorAction SilentlyContinue).Count -gt 0) { $left += '防火墙规则仍存在' }
try {
    $eng = [IntPtr]::Zero
    if ($api -and $api::FwpmEngineOpen0([IntPtr]::Zero, 10, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$eng) -eq 0) {
        $sk = $subLayerKey; $tmp = [IntPtr]::Zero
        if ($api::FwpmSubLayerGetByKey0($eng, [ref]$sk, [ref]$tmp) -eq 0) { $api::FwpmFreeMemory0([ref]$tmp) | Out-Null; $left += 'WFP 子层仍存在' }
        $api::FwpmEngineClose0($eng) | Out-Null
    }
} catch { }
if (Test-Path $installDir) { $left += '程序目录仍存在' }
if ($DryRun) { Say '只检查模式：以上为将要执行的操作，未做任何改动。' 'Yellow' }
elseif ($left.Count -eq 0) { Say '卸载完成：服务、WFP、防火墙规则、程序文件均已清除。Claude 现在直接走系统网络/代理。' 'Green' }
else { Say ('仍有残留：' + ($left -join '；') + '。请重启电脑后再运行一次本脚本。') 'Red' }
$logFile = Join-Path $UserDesktop "ClaudeVPNGuard-卸载报告-$stamp.txt"
try { [IO.File]::WriteAllLines($logFile, $report, (New-Object Text.UTF8Encoding $true)); Write-Host "报告已保存：$logFile" } catch { }
