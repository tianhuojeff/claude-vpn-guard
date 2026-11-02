// written_by: claude-code
// 保护状态机。顺序铁律：先锁定网络（防火墙 Lock 规则）→ 再结束 Claude → 通知 → 记日志。
// 默认拒绝：启动、任何异常、网络切换、休眠恢复 都先进入锁定，验证通过才解锁。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ClaudeVPNGuard
{
    public enum GuardState { Verifying, Protected, Blocked, Tripped, FirewallError }

    public interface IClaudeControl
    {
        List<string> DiscoverExecutables();
        int RunningCount();
        int[] KillAll();
        string LaunchTarget();
    }

    public interface INotifier { void Notify(string title, string msg); }

    public class StatusSnapshot
    {
        public string State;
        public string StateText;
        public bool Locked;
        public bool ClaudeAllowed;
        public int ClaudeProcesses;
        public string LastTrip;
        public string LastTripReason;
        public string LastCheck;
        public string LastFailure;
        public string CoreVersion, Mode, Node, NodeChain, ExitIp, Controller, SysProxy;
        public bool TunEnabled, TunUp, SysProxyOn, VergeRunning, CoreOk;
        public List<Dictionary<string, object>> Checks = new List<Dictionary<string, object>>();
        public int ProtectedExeCount;
        public string LaunchTarget;
        public long TripSeq;
        public string ServiceVersion;
        public string LanDisplay;
        public string ResumeId;        // 待恢复清单 ID（无则为 null）
        public int ResumeSessions;     // 清单中的会话数
        public bool AutoResume;        // 恢复后自动重开并续跑
        public string OverrideScript;  // Script.js 中本程序段：ok / repaired / error
        public string OverrideNote;    // 最近一次自动修复或修复失败的说明
        public bool OverrideRuntime;   // Clash 运行配置已套用当前脚本
    }

    public class GuardEngine
    {
        readonly IFirewall fw;
        readonly IHealthChecker health;
        readonly IClaudeControl claude;
        readonly INotifier notifier;
        readonly GuardSettings st;
        readonly object gate = new object();

        public GuardState State { get; private set; }
        public bool Locked { get; private set; }
        public HealthReport LastReport { get; private set; }
        public DateTime? LastTrip { get; private set; }
        public string LastTripReason { get; private set; }
        public long TripSeq { get; private set; }
        List<string> exes = new List<string>();
        bool manualUnlockPending;
        int softFails;
        bool lockError;
        public bool WantsFastRecheck { get { return softFails == 1; } }
        public Action<string> AfterTripHook; // 测试用：记录动作顺序
        public Action RequestRecheck; // 服务循环：立即做一次完整检测
        public Action<string> BeforeKill;  // 已锁网、结束进程前：写出待恢复清单（使用滚动快照，不阻塞）
        public Timeline Timeline = new Timeline();

        public GuardEngine(GuardSettings s, IFirewall f, IHealthChecker h, IClaudeControl c, INotifier n)
        {
            st = s; fw = f; health = h; claude = c; notifier = n;
            State = GuardState.Verifying;
        }

        public IList<string> ProtectedExe { get { lock (gate) return exes.ToList(); } }

        // 服务启动：第一件事就是确保规则存在且锁定
        public void Startup()
        {
            lock (gate)
            {
                Log.Info("保护服务启动：先锁定 Claude 网络，再进行验证");
                RefreshExecutables(true);
                SetLockSafe(true, "服务启动");
                manualUnlockPending = LoadTripFlag();
                // 上次保护性关闭后尚未手动解锁：重启后仍保持“Claude 已阻断”
                State = manualUnlockPending && st.RequireManualUnlockAfterTrip ? GuardState.Tripped : GuardState.Verifying;
            }
        }

        public void RefreshExecutables(bool forceLockState)
        {
            lock (gate)
            {
                List<string> found;
                try { found = claude.DiscoverExecutables(); }
                catch (Exception ex) { Log.Error("发现 Claude 程序失败：" + ex.Message); return; }
                var added = found.Except(exes, StringComparer.OrdinalIgnoreCase).ToList();
                if (added.Count > 0 || forceLockState)
                {
                    try
                    {
                        // 新出现的路径（如版本更新）按当前锁定状态创建；未知状态则锁定
                        fw.EnsureRules(found, st.FakeIpRange, forceLockState || Locked);
                        foreach (var a in added) Log.Action("纳入保护：" + a);
                    }
                    catch (Exception ex) { Log.Error("创建防火墙规则失败：" + ex.Message); State = GuardState.FirewallError; }
                }
                exes = found;
            }
        }

        // 网络变化 / 休眠恢复 / 会话变化：锁定，等待重新验证（不结束 Claude，验证失败才结束）
        public void OnEnvironmentChanged(string why)
        {
            lock (gate)
            {
                Log.Warn("环境变化：" + why + " → 锁定并重新验证");
                SetLockSafe(true, why);
                if (State == GuardState.Protected) State = GuardState.Verifying;
            }
        }

        // 周期检测入口
        public HealthReport Evaluate(bool full)
        {
            HealthReport rep;
            try { rep = health.Run(full, ProtectedExe); }
            catch (Exception ex)
            {
                rep = new HealthReport { Full = full };
                rep.Add("internal", "保护器内部检测", false, true, "检测异常：" + ex.Message);
            }
            lock (gate)
            {
                LastReport = rep;
                if (rep.Safe)
                {
                    softFails = 0;
                    if (NodePaused) { NodePaused = false; Log.Action("专用入口检测已通过，恢复 Claude 联网"); }
                    if (State == GuardState.Tripped && manualUnlockPending && st.RequireManualUnlockAfterTrip)
                        return rep; // 保持锁定，等待用户手动启动
                    if (Locked || State != GuardState.Protected)
                    {
                        SetLockSafe(false, "检测全部通过");
                        if (!Locked)
                        {
                            if (State != GuardState.Protected) { Log.Info("检测通过，允许 Claude 联网"); Timeline.Mark("guard:protected"); }
                            State = GuardState.Protected;
                        }
                    }
                }
                else
                {
                    var reason = rep.FirstFailure ?? "未知原因";
                    bool fwBroken = rep.Items.Any(i => (i.Id == "fw" || i.Id == "fwrules") && !i.Ok);
                    // 仅“探测超时/测速失败”这类可能抖动的失败：第一次只锁网络不杀进程，连续第二次才保护性关闭
                    bool soft = rep.Items.Where(i => i.Critical && !i.Ok).All(i => i.Id == "probe" || (i.Id == "chain" && i.Detail.Contains("测速失败")));
                    softFails = soft ? softFails + 1 : 99;
                    // 暂停期间“走不通”类失败（内核/专用入口/日本组暂不可用、探测失败）都是预期的；出现直连、非日本节点、防火墙/审计问题照常保护
                    bool deadEnd = rep.Items.Where(i => i.Critical && !i.Ok).All(i => i.Id == "core" || i.Id == "listener" || i.Id == "probe"
                        || (i.Id == "jpgroup" && i.Detail.StartsWith("不存在")) || (i.Id == "chain" && i.Detail.Contains("测速失败")));
                    if (NodePaused && (soft || deadEnd) && !lockError && !fwBroken)
                    {
                        // 节点暂停期间探测失败是预期的：保持锁定，不关闭 Claude
                        SetLockSafe(true, "暂停联网：" + reason);
                        if (State == GuardState.Protected) State = GuardState.Verifying;
                    }
                    else if (claude.RunningCount() > 0 && softFails < 2)
                    {
                        SetLockSafe(true, "可疑抖动：" + reason);
                        if (State == GuardState.Protected) State = GuardState.Verifying;
                        Log.Warn("检测疑似抖动，已锁定网络，等待复检：" + reason);
                    }
                    else if (claude.RunningCount() > 0) Trip(reason);
                    else
                    {
                        if (!Locked) Log.Warn("检测未通过（Claude 未运行）：" + reason);
                        SetLockSafe(true, reason);
                        if (State != GuardState.Tripped) State = fwBroken || lockError ? GuardState.FirewallError : GuardState.Blocked;
                    }
                }
            }
            return rep;
        }

        // 保护性关闭：第一步锁网络，第二步结束进程，第三步禁止自动恢复，第四步通知，第五步日志
        // 内核进程退出（进程句柄等待，毫秒级）：立即锁定并保护性关闭
        public void OnCoreExited(string detail)
        {
            Timeline.Mark("core:exited");
            Log.Error("Mihomo 内核进程退出：" + detail);
            // 隔离模式：Claude 只能经专用入口出网，内核不在 = 走不通而不是泄漏（Clash Verge 重启/更新时内核会被重启）。
            // 锁定成功就只暂停联网、不关闭 Claude；新内核起来、检测全部通过后自动恢复。锁定失败才保护性关闭。
            if (st.IsolationMode && claude.RunningCount() > 0)
            {
                OnNodePause("Mihomo 内核进程退出（等待新内核）");
                if (RequestRecheck != null) RequestRecheck();
                return;
            }
            if (claude.RunningCount() > 0) Trip("Mihomo 内核进程退出");
            else lock (gate) { SetLockSafe(true, "Mihomo 内核进程退出"); if (State != GuardState.Tripped) State = GuardState.Blocked; }
            if (RequestRecheck != null) RequestRecheck();
        }

        // 隔离模式下全部日本节点暂不可用：Claude 只能经专用入口出网，节点不通也不会直连泄漏，
        // 因此只锁网络“暂停联网”、不结束 Claude（保住正在跑的任务）；节点恢复后自动解锁。锁定失败才保护性关闭。
        public bool NodePaused { get; private set; }
        public void OnNodePause(string reason)
        {
            Timeline.Mark("node:pause");
            lock (gate)
            {
                SetLockSafe(true, "暂停联网：" + reason);
                if (lockError) { Trip(reason + "（锁定规则失败）"); return; }
                NodePaused = true;
                if (State == GuardState.Protected) State = GuardState.Verifying;
                Log.Action("暂停 Claude 联网（不关闭 Claude）：" + reason);
                notifier.Notify("Claude VPN Guard", "日本节点暂时都不可用，已暂停 Claude 联网（未关闭 Claude）。节点恢复后自动继续。");
            }
        }
        public void OnNodeResumed(string detail)
        {
            lock (gate)
            {
                if (!NodePaused) return;
                NodePaused = false;
                softFails = 0;
                Log.Action("节点已恢复，复检通过后恢复 Claude 联网：" + detail);
            }
            if (RequestRecheck != null) RequestRecheck();
        }

        // 节点管理器报告：全部日本节点失败 / 组安全异常
        public void OnNodeOutage(string reason)
        {
            Timeline.Mark("node:outage");
            if (claude.RunningCount() > 0) Trip(reason);
            else lock (gate) { SetLockSafe(true, reason); if (State != GuardState.Tripped) State = GuardState.Blocked; }
        }

        public void Trip(string reason)
        {
            lock (gate)
            {
                Timeline.Mark("trip:start");
                SetLockSafe(true, reason);
                Timeline.Mark("trip:locked");
                if (BeforeKill != null) { try { BeforeKill(reason); } catch { } }
                if (AfterTripHook != null) AfterTripHook("lock");
                int[] res;
                try { res = claude.KillAll(); }
                catch (Exception ex) { res = new[] { 0, -1 }; Log.Error("结束 Claude 进程异常：" + ex.Message); }
                Timeline.Mark("trip:killed");
                if (AfterTripHook != null) AfterTripHook("kill");
                State = GuardState.Tripped;
                manualUnlockPending = true;
                SaveTripFlag(true);
                LastTrip = DateTime.Now;
                LastTripReason = reason;
                TripSeq++;
                notifier.Notify("Claude VPN Guard", "代理连接异常，Claude 已被保护性关闭，当前网络访问已阻断。\n原因：" + reason);
                if (AfterTripHook != null) AfterTripHook("notify");
                Log.Action(string.Format("保护性关闭 Claude：原因={0}；结束进程 {1} 个，残留 {2} 个", reason, res[0], res[1]));
                if (res[1] != 0) Log.Error("仍有 Claude 进程残留，网络保持锁定");
            }
        }

        // 新 Claude 进程启动（WMI 事件）。非保护状态下立即结束（防止经回环代理直连）
        public void OnClaudeProcessStarted(string path, int pid)
        {
            lock (gate)
            {
                if (!exes.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    Log.Warn("发现未纳入规则的 Claude 程序：" + path);
                    RefreshExecutables(false);
                    if (!exes.Contains(path, StringComparer.OrdinalIgnoreCase) || State != GuardState.Protected)
                    {
                        Native.Kill(pid, 1000);
                        Log.Action("结束未受保护的 Claude 进程 pid=" + pid);
                        return;
                    }
                }
                if (State == GuardState.Verifying)
                {
                    // 正在重新验证（网络切换/休眠恢复）：网络已锁定，立即复检；确认不安全时由 Evaluate 结束进程
                    if (RequestRecheck != null) RequestRecheck();
                    return;
                }
                if (State != GuardState.Protected)
                {
                    SetLockSafe(true, "保护未通过时启动 Claude");
                    claude.KillAll();
                    Log.Action("保护未通过（" + StateText(State) + "），已阻止 Claude 启动：" + path);
                    notifier.Notify("Claude VPN Guard", "代理未验证安全，已阻止 Claude 启动。请先开启 Clash Verge，再通过保护器启动 Claude。");
                }
            }
        }

        // GUI 的“启动 Claude”：完整检测通过才解锁，返回 null 表示允许
        public string PrepareLaunch()
        {
            RefreshExecutables(false);
            var rep = health.Run(true, ProtectedExe);
            lock (gate)
            {
                LastReport = rep;
                if (!rep.Safe)
                {
                    SetLockSafe(true, "启动前检测未通过");
                    if (State == GuardState.Protected) State = GuardState.Blocked;
                    Log.Warn("拒绝启动 Claude：" + rep.FirstFailure);
                    return rep.FirstFailure ?? "检测未通过";
                }
                manualUnlockPending = false;
                SaveTripFlag(false);
                SetLockSafe(false, "启动前检测通过");
                if (Locked) return "无法解除防火墙锁定";
                State = GuardState.Protected;
                Log.Action("启动前检测通过，允许启动 Claude");
                return null;
            }
        }

        void SetLockSafe(bool on, string why)
        {
            try
            {
                if (on || Locked != on) fw.SetLock(on);
                if (Locked != on) Log.Action((on ? "启用" : "解除") + "锁定规则：" + why);
                Locked = on;
                lockError = false;
            }
            catch (Exception ex)
            {
                Log.Error("设置锁定规则失败（" + why + "）：" + ex.Message);
                if (on) Locked = true; // 失败时按“仍锁定”对待，绝不假定已放开
                lockError = true;
                State = GuardState.FirewallError;
            }
        }

        static bool LoadTripFlag()
        {
            try { return File.Exists(GuardPaths.StateFile) && File.ReadAllText(GuardPaths.StateFile).Contains("\"tripped\":true"); } catch { return true; }
        }
        static void SaveTripFlag(bool v)
        {
            try { Directory.CreateDirectory(GuardPaths.DataDir); File.WriteAllText(GuardPaths.StateFile, "{\"tripped\":" + (v ? "true" : "false") + "}"); } catch { }
        }

        public static string StateText(GuardState s)
        {
            switch (s)
            {
                case GuardState.Protected: return "已保护";
                case GuardState.Verifying: return "检测中";
                case GuardState.Blocked: return "代理异常";
                case GuardState.Tripped: return "Claude 已阻断";
                case GuardState.FirewallError: return "防火墙异常";
            }
            return s.ToString();
        }

        public StatusSnapshot Snapshot()
        {
            lock (gate)
            {
                var r = LastReport;
                var s = new StatusSnapshot
                {
                    State = State.ToString(),
                    StateText = StateText(State),
                    Locked = Locked,
                    ClaudeAllowed = !Locked,
                    LastTrip = LastTrip.HasValue ? LastTrip.Value.ToString("yyyy-MM-dd HH:mm:ss") : null,
                    LastTripReason = LastTripReason,
                    TripSeq = TripSeq,
                    ProtectedExeCount = exes.Count,
                    ServiceVersion = typeof(GuardEngine).Assembly.GetName().Version.ToString()
                };
                try { s.ClaudeProcesses = claude.RunningCount(); s.LaunchTarget = claude.LaunchTarget(); } catch { }
                if (r != null)
                {
                    s.LastCheck = r.Time.ToString("yyyy-MM-dd HH:mm:ss") + (r.Full ? "（完整）" : "（快速）");
                    s.LastFailure = r.FirstFailure;
                    s.CoreVersion = r.CoreVersion; s.Mode = r.Mode; s.Node = r.Node; s.NodeChain = r.NodeChain; s.ExitIp = r.ExitIp;
                    s.Controller = r.ControllerDesc; s.TunEnabled = r.TunEnabled; s.TunUp = r.TunUp; s.SysProxyOn = r.SysProxyOn; s.SysProxy = r.SysProxyServer;
                    s.VergeRunning = r.VergeGuiRunning;
                    s.LanDisplay = r.LanDisplay;
                    s.CoreOk = r.Items.Any(i => i.Id == "core" && i.Ok);
                    foreach (var i in r.Items)
                        s.Checks.Add(new Dictionary<string, object> { { "id", i.Id }, { "name", i.Name }, { "ok", i.Ok }, { "critical", i.Critical }, { "detail", i.Detail } });
                }
                return s;
            }
        }
    }
}
