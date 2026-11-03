// written_by: claude-code
// ClaudeVPNGuard.Service.exe —— 后台保护服务（LocalSystem）+ 管理命令行。
//   无参数          由服务管理器启动
//   install         （管理员）注册服务、创建规则（默认锁定）、启动
//   uninstall       （管理员）停止并删除服务、清除本程序创建的全部防火墙规则
//   recover         （管理员）应急恢复：清除本程序全部规则并停止服务
//   console         （管理员）前台运行，调试用
//   diag            （任意用户）只读诊断：执行全部检测并打印，不修改任何系统设置
//   selftest        （管理员）防火墙实测：用 curl 副本验证 静态规则/锁定规则 的真实阻断效果
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace ClaudeVPNGuard
{
    class ClaudeControl : IClaudeControl
    {
        readonly ClaudeLocator loc;
        public ClaudeControl(ClaudeLocator l) { loc = l; }
        public List<string> DiscoverExecutables() { return loc.DiscoverExecutables(); }
        public int RunningCount() { return loc.RunningClaude().Count; }
        public int[] KillAll() { return loc.KillAll(); }
        public string LaunchTarget()
        {
            if (loc.LastMsixFamily != null) return @"shell:AppsFolder\" + loc.LastMsixFamily + "!Claude";
            return null;
        }
    }

    class ServiceNotifier : INotifier
    {
        public IpcServer Ipc;
        public void Notify(string title, string msg)
        {
            // GUI 在线时由 GUI 弹托盘通知；否则服务直接向桌面会话弹窗
            if (Ipc == null || (DateTime.Now - Ipc.LastClientSeen).TotalSeconds > 10)
                ThreadPool.QueueUserWorkItem(_ => Native.PopupToConsole(title, msg));
        }
    }

    class GuardHost
    {
        public GuardSettings St;
        public ClaudeLocator Loc;
        public static LayeredFirewall Fw;
        public HealthChecker Health;
        public NodeManager Nodes;
        public CoreWatcher Core = new CoreWatcher();
        List<SessionInfo> lastSessions = new List<SessionInfo>();   // 滚动会话快照（约 10 秒一次）
        DateTime lastSnap = DateTime.MinValue;
        public GuardEngine Engine;
        public IpcServer Ipc;
        public SubscriptionSync Subs;
        ManagementEventWatcher procWatcher;
        readonly ManualResetEvent wake = new ManualResetEvent(false);
        volatile bool stop, fullRequested = true;
        DateTime envChangedAt = DateTime.MinValue;
        Thread loop;
        ServiceNotifier notifier;
        string overrideScript = "ok", overrideNote;
        bool overrideRuntime = true;
        DateTime lastOverrideError = DateTime.MinValue;

        public void Start()
        {
            St = GuardSettings.Load();
            Log.RetentionDays = St.LogRetentionDays;
            Log.Cleanup();
            Loc = new ClaudeLocator(St);
            Fw = BuildFirewall(St);
            notifier = new ServiceNotifier();
            Health = new HealthChecker(St, Loc, Fw);
            Engine = new GuardEngine(St, Fw, Health, new ClaudeControl(Loc), notifier);
            Engine.RequestRecheck = () => { fullRequested = true; wake.Set(); };
            // 已锁网、结束进程前：用最近一次快照写出待恢复清单（内存数据，不阻塞关闭）
            Engine.BeforeKill = r =>
            {
                var plan = SessionSnapshot.WritePending(lastSessions, r);
                Log.Action("已记录待恢复会话 " + plan.Sessions.Count + " 个（清单 " + plan.Id + "）");
            };
            Engine.Startup();
            // 内核进程退出：句柄等待，毫秒级
            Core.Exited = d => { if (Nodes != null) Nodes.Suspend(15, "内核退出"); Engine.OnCoreExited(d); };
            // Japan Auto 节点管理（只操作 Japan Auto 组）
            Nodes = new NodeManager(new MihomoNodeApi(() => Health.Client, St), St, Engine.Timeline);
            Nodes.VerifyClaudePath = node => { string d; var ok = Health.VerifyDedicatedPath(node, out d); if (!ok) Log.Warn("节点路径验证失败：" + d); return ok; };
            Nodes.OnAllFailed = r => { if (St.IsolationMode) Engine.OnNodePause(r); else Engine.OnNodeOutage(r); };
            Nodes.OnSecurityFault = r => { if (St.IsolationMode) Engine.OnNodeOutage(r); };
            Nodes.OnRecovered = r => { if (Engine.NodePaused) Engine.OnNodeResumed(r); else notifier.Notify("Claude VPN Guard", r); };
            Subs = new SubscriptionSync(St, () => Health.Client);
            new Thread(NodeLoop) { IsBackground = true, Name = "node-loop" }.Start();
            Ipc = new IpcServer(Handle) { TrustedClientExe = Path.Combine(GuardPaths.ExeDir, "ClaudeVPNGuard.exe") };
            notifier.Ipc = Ipc;
            Ipc.Start();
            NetworkChange.NetworkAddressChanged += (s, e) => EnvChanged("网络地址变化");
            NetworkChange.NetworkAvailabilityChanged += (s, e) => EnvChanged(e.IsAvailable ? "网络恢复可用" : "网络不可用");
            StartProcessWatcher();
            loop = new Thread(Loop) { IsBackground = true, Name = "guard-loop" };
            loop.Start();
        }

        public void Stop()
        {
            stop = true; wake.Set();
            try { if (procWatcher != null) procWatcher.Stop(); } catch { }
            if (Ipc != null) Ipc.Stop();
            // 服务停止时保持锁定（故障安全），不删除任何规则
            try { Fw.SetLock(true); Log.Action("服务停止：锁定规则保持启用"); } catch (Exception ex) { Log.Error("服务停止时锁定失败：" + ex.Message); }
            Core.Dispose();
        }

        // 通用代理端口：从 Clash Verge 配置读取 + 常见默认端口；隔离模式下 Claude 一律禁止连接这些端口
        public static List<int> GeneralPorts(GuardSettings st)
        {
            var ports = new List<int> { 7890, 7891, 7897, 7898, 7899 };
            foreach (var c in VergeConfigInfo.DiscoverAll()) if (c.MixedPort > 0) ports.Add(c.MixedPort);
            try { ports.AddRange(NetEnv.ProxyListenerPorts(st.DedicatedPort)); } catch { }
            return ports.Where(p => p != st.DedicatedPort).Distinct().ToList();
        }

        public static LayeredFirewall BuildFirewall(GuardSettings st)
        {
            var wfp = new WfpFirewall { IsolationMode = st.IsolationMode, GeneralProxyPorts = GeneralPorts(st) };
            return new LayeredFirewall(new WindowsFirewall(), wfp);
        }

        void NodeLoop()
        {
            int n = 0;
            while (!stop)
            {
                // 每 3 秒检查订阅变化（只比对文件时间，变化时才重写汇总文件并热刷新）
                if (n++ % 3 == 0)
                {
                    try { Subs.Tick(); } catch (Exception ex) { Subs.LastError = ex.Message; }
                    EnsureOverride();
                }
                try
                {
                    if (Health.Client != null) Nodes.Tick();
                }
                catch (Exception ex) { Log.Error("节点管理异常：" + ex.Message); }
                Thread.Sleep(1000);
            }
        }

        // 隔离模式依赖 Clash Verge 全局扩展脚本里的本程序段：被删除/改坏（卸载残留、手动编辑、Verge 重置）就立即补写（先备份），
        // 并提醒用户在 Clash Verge 刷新——Clash 只在刷新/更新订阅时重新生成配置，补写后不刷新，下次订阅更新 Japan Auto 就会消失
        void EnsureOverride()
        {
            if (!St.IsolationMode) return;
            var vd = Subs.VergeDir ?? Subscriptions.FindVergeDir();
            if (vd == null) return;
            try
            {
                var bak = VergeOverride.Ensure(vd, St);
                if (bak != null)
                {
                    overrideScript = "repaired";
                    overrideNote = DateTime.Now.ToString("HH:mm") + " 发现全局扩展脚本里本程序的覆写段缺失，已自动重新写入（原文件备份：" + bak + "）";
                    Log.Action(overrideNote);
                }
                else if (overrideScript == "error") overrideScript = "ok";
                overrideRuntime = VergeOverride.RuntimeLoaded(vd);
                if (!overrideRuntime) TryHotLoad(vd, bak != null);
            }
            catch (Exception ex)
            {
                overrideScript = "error";
                overrideNote = "全局扩展脚本缺少本程序段，且自动补写失败：" + ex.Message;
                if ((DateTime.Now - lastOverrideError).TotalMinutes < 10) return;
                lastOverrideError = DateTime.Now;
                Log.Error(overrideNote);
                notifier.Notify("Clash 覆写缺失，无法自动补写", overrideNote + "\n\n" + VergeOverride.WhereGuide + "\n可在保护器“设置”旁点“修复 Clash 覆写”，或用管理员运行 ClaudeVPNGuard.Service.exe verge-apply。");
            }
        }

        // Clash 当前配置没套用覆写（脚本刚补写、Verge 尚未重新生成）：自己套用并重载内核，不用用户去 Verge 刷新。
        // 失败才提醒手动刷新；每 2 分钟最多尝试一次，避免反复重载打断 Clash 连接
        DateTime lastHotLoad = DateTime.MinValue;
        void TryHotLoad(string vd, bool justRepaired)
        {
            if ((DateTime.Now - lastHotLoad).TotalMinutes < 2) return;
            var c = Health.Client;
            if (c == null) return;   // 内核没连上：等它起来再说（Verge 启动时会自己执行脚本）
            lastHotLoad = DateTime.Now;
            try
            {
                if (!VergeOverride.HotLoad(vd, St, c)) return;
                overrideRuntime = VergeOverride.RuntimeLoaded(vd);
                overrideNote = DateTime.Now.ToString("HH:mm") + " Clash 当前配置缺少本程序覆写，已自动套用并重载内核" + (justRepaired ? "（全局扩展脚本也已补写）" : "");
                Subs.ForceNext();
                fullRequested = true; wake.Set();
                notifier.Notify("Clash 覆写已自动恢复", overrideNote + "。无需手动刷新 Clash Verge。");
            }
            catch (Exception ex)
            {
                overrideNote = "Clash 当前配置缺少本程序覆写，自动套用失败：" + ex.Message;
                Log.Error(overrideNote);
                notifier.Notify("Clash 覆写需要手动刷新", overrideNote + "\n\n" + VergeOverride.RefreshGuide);
            }
        }

        public void EnvChanged(string why)
        {
            envChangedAt = DateTime.Now;
            Engine.OnEnvironmentChanged(why);
            fullRequested = true;
            wake.Set();
        }

        void StartProcessWatcher()
        {
            try
            {
                procWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT ProcessID FROM Win32_ProcessStartTrace"));
                procWatcher.EventArrived += (s, e) =>
                {
                    try
                    {
                        int pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
                        var path = Native.ProcessPath(pid);
                        if (path != null && ClaudeLocator.IsClaudeInstallPath(path) && Loc.IsClaudeExe(path))
                            Engine.OnClaudeProcessStarted(path, pid);
                    }
                    catch (Exception ex) { Log.Error("进程事件处理异常：" + ex.Message); }
                };
                procWatcher.Start();
                Log.Info("进程启动事件监控已开启（WMI）");
            }
            catch (Exception ex) { Log.Warn("WMI 进程监控不可用，改用轮询：" + ex.Message); procWatcher = null; }
        }

        void Loop()
        {
            DateTime lastFull = DateTime.MinValue, lastRescan = DateTime.Now;
            var knownPids = new HashSet<int>();
            while (!stop)
            {
                try
                {
                    // 网络刚变化：等 1.5 秒让路由/网卡稳定后再验证（期间保持锁定）
                    var sinceEnv = (DateTime.Now - envChangedAt).TotalMilliseconds;
                    if (sinceEnv < 1500) Thread.Sleep((int)(1500 - sinceEnv));
                    bool full = fullRequested || Engine.State != GuardState.Protected || Engine.WantsFastRecheck
                        || (DateTime.Now - lastFull).TotalSeconds >= St.FullIntervalSec;
                    fullRequested = false;
                    if ((DateTime.Now - lastRescan).TotalSeconds > 120) { Engine.RefreshExecutables(false); lastRescan = DateTime.Now; }
                    if (procWatcher == null) PollNewClaude(knownPids);
                    var rep = Engine.Evaluate(full);
                    if (Engine.State == GuardState.Protected && (DateTime.Now - lastSnap).TotalSeconds >= 10)
                    {
                        lastSnap = DateTime.Now;
                        try { var cap = SessionSnapshot.Capture(); if (cap.Count > 0 || Loc.RunningClaude().Count == 0) lastSessions = cap; } catch { }
                    }
                    // 跟踪内核进程（重启后 pid 会变）
                    var ports = rep.GeneralPorts.Concat(new[] { St.DedicatedPort }).ToArray();
                    var pid = CoreWatcher.FindCorePid(ports);
                    if (pid > 0 && pid != Core.WatchedPid) { Core.Watch(pid); Log.Info("开始监视 Mihomo 内核进程 pid=" + pid); }
                    // 内核端口变化 → 重建 WFP 通用端口阻断
                    if (St.IsolationMode && rep.GeneralPorts.Count > 0 && rep.GeneralPorts.Except(Fw.Wfp.GeneralProxyPorts).Any())
                    {
                        Fw.Wfp.GeneralProxyPorts = Fw.Wfp.GeneralProxyPorts.Union(rep.GeneralPorts).ToList();
                        Engine.RefreshExecutables(true);
                    }
                    if (full) lastFull = DateTime.Now;
                }
                catch (Exception ex)
                {
                    Log.Error("保护循环异常 → 锁定：" + ex);
                    Engine.Timeline.Mark("loop:exception");
                    try { Fw.SetLock(true); } catch { }
                }
                wake.WaitOne(Engine.State == GuardState.Protected ? St.QuickIntervalMs : Math.Min(St.QuickIntervalMs, 3000));
                wake.Reset();
            }
        }

        void PollNewClaude(HashSet<int> known)
        {
            var now = Loc.RunningClaude();
            foreach (var kv in now) if (!known.Contains(kv.Key)) Engine.OnClaudeProcessStarted(kv.Value, kv.Key);
            known.Clear();
            foreach (var k in now.Keys) known.Add(k);
        }

        IpcResponse Handle(IpcRequest req, bool trusted)
        {
            switch ((req.Cmd ?? "").ToLowerInvariant())
            {
                case "status":
                    {
                        var snap = Engine.Snapshot();
                        var plan = SessionSnapshot.ReadPending();
                        snap.AutoResume = St.AutoResumeAfterRecovery;
                        if (plan != null && plan.Status == "pending") { snap.ResumeId = plan.Id; snap.ResumeSessions = plan.Sessions.Count; }
                        snap.OverrideScript = St.IsolationMode ? overrideScript : null;
                        snap.OverrideNote = overrideNote;
                        snap.OverrideRuntime = overrideRuntime;
                        return new IpcResponse { Ok = true, Data = snap };
                    }
                case "resume-plan":
                    {
                        var plan = SessionSnapshot.ReadPending();
                        return new IpcResponse { Ok = plan != null, Error = plan == null ? "无待恢复清单" : null, Data = plan == null ? null : new Dictionary<string, object> { { "Plan", plan }, { "Prompt", SessionSnapshot.CoordinatorPrompt(plan) } } };
                    }
                case "resume-mark":
                    {
                        if (!trusted) return Deny();
                        var plan = SessionSnapshot.ReadPending();
                        if (plan == null) return new IpcResponse { Ok = false, Error = "无待恢复清单" };
                        plan.Status = Convert.ToString(req.Args["status"]);
                        File.WriteAllText(SessionSnapshot.PendingFile, Json.Serialize(plan), new UTF8Encoding(false));
                        Log.Action("待恢复清单 " + plan.Id + " 标记为 " + plan.Status);
                        return new IpcResponse { Ok = true };
                    }
                case "checknow":
                    if (!trusted) return Deny();
                    Engine.Evaluate(true);
                    return new IpcResponse { Ok = true, Data = Engine.Snapshot() };
                case "preparelaunch":
                    if (!trusted) return Deny();
                    var err = Engine.PrepareLaunch();
                    return new IpcResponse { Ok = err == null, Error = err, Data = Engine.Snapshot() };
                case "killclaude":
                    {
                        // 界面结束不了的 Claude 进程（如管理员权限启动的）交给服务结束；只结束指定登录会话里的
                        if (!trusted) return Deny();
                        int session = -1;
                        try { session = Convert.ToInt32(req.Args["session"]); } catch { }
                        if (session < 0) return new IpcResponse { Ok = false, Error = "缺少会话号" };
                        var r = Loc.KillAll(session);
                        Log.Action(string.Format("按界面请求结束会话 {0} 的 Claude 进程：结束 {1} 个，残留 {2} 个", session, r[0], r[1]));
                        return new IpcResponse { Ok = r[1] == 0, Error = r[1] == 0 ? null : "仍有 " + r[1] + " 个 Claude 进程结束不了", Data = new Dictionary<string, object> { { "Killed", r[0] }, { "Left", r[1] } } };
                    }
                case "nodes":
                    return new IpcResponse { Ok = true, Data = NodeSnapshot() };
                case "rescan":
                    if (!trusted) return Deny();
                    return new IpcResponse { Ok = true, Data = Rescan() };
                case "nodetestall":
                    if (!trusted) return Deny();
                    Nodes.TestAllNow();
                    return new IpcResponse { Ok = true, Data = NodeSnapshot() };
                case "nodeselect":
                    if (!trusted) return Deny();
                    var nerr = Nodes.ManualSelect(Convert.ToString(req.Args["node"]));
                    return new IpcResponse { Ok = nerr == null, Error = nerr, Data = NodeSnapshot() };
                case "subset":
                    if (!trusted) return Deny();
                    {
                        // 订阅切换：enable/disable 单个订阅，或 only=uid 只用这一个；只影响候选节点范围，不放宽任何规则
                        var sa = req.Args ?? new Dictionary<string, object>();
                        var all = Subs.Subs.Select(s => s.Uid).ToList();
                        object o;
                        if (sa.TryGetValue("only", out o) && o != null) St.DisabledSubscriptions = all.Where(u => u != Convert.ToString(o)).ToList();
                        else if (sa.TryGetValue("all", out o) && Convert.ToBoolean(o)) St.DisabledSubscriptions = new List<string>();
                        else
                        {
                            var uid = Convert.ToString(sa["uid"]); bool on = Convert.ToBoolean(sa["on"]);
                            St.DisabledSubscriptions.Remove(uid);
                            if (!on) St.DisabledSubscriptions.Add(uid);
                        }
                        St.Save();
                        Log.Action("订阅启用范围已更新，停用：" + (St.DisabledSubscriptions.Count == 0 ? "无" : string.Join("、", Subs.Subs.Where(s => St.DisabledSubscriptions.Contains(s.Uid)).Select(s => s.Name ?? s.Uid))));
                        Subs.ForceNext();
                        try { Subs.Tick(); } catch (Exception ex) { Log.Error("订阅汇总失败：" + ex.Message); }
                        Nodes.ForceRecheck();
                        return new IpcResponse { Ok = true, Data = NodeSnapshot() };
                    }
                case "autoresume":
                    if (!trusted) return Deny();
                    St.AutoResumeAfterRecovery = Convert.ToBoolean(req.Args["on"]);
                    St.Save();
                    Log.Action("恢复后自动重开续跑已" + (St.AutoResumeAfterRecovery ? "开启" : "关闭"));
                    return new IpcResponse { Ok = true };
                case "autoswitch":
                    if (!trusted) return Deny();
                    St.AutoSwitch = Convert.ToBoolean(req.Args["on"]);
                    St.Save();
                    Log.Action("自动切换已" + (St.AutoSwitch ? "开启" : "关闭"));
                    return new IpcResponse { Ok = true, Data = NodeSnapshot() };
                case "setparams":
                    if (!trusted) return Deny();
                    // 故障转移参数只影响节点质量与切换节奏，不放宽任何防直连规则，允许 GUI 修改
                    foreach (var kv in req.Args ?? new Dictionary<string, object>())
                    {
                        int iv = Convert.ToInt32(kv.Value);
                        switch (kv.Key)
                        {
                            case "MaxDelayMs": St.MaxDelayMs = Math.Max(50, iv); break;
                            case "ProbeTimeoutMs": St.ProbeTimeoutMs = Math.Max(500, iv); break;
                            case "FailThreshold": St.FailThreshold = Math.Max(1, iv); break;
                            case "RecoverThreshold": St.RecoverThreshold = Math.Max(1, iv); break;
                            case "HealthIntervalSec": St.HealthIntervalSec = Math.Max(10, iv); break;
                            case "AllFailRetrySec": St.AllFailRetrySec = Math.Max(10, iv); break;
                            case "SwitchCooldownSec": St.SwitchCooldownSec = Math.Max(0, iv); break;
                            case "MinDwellSec": St.MinDwellSec = Math.Max(0, iv); break;
                            case "CurrentNodeCheckSec": St.CurrentNodeCheckSec = Math.Max(1, iv); break;
                        }
                    }
                    St.Save();
                    Log.Info("故障转移参数已由 GUI 更新");
                    return new IpcResponse { Ok = true, Data = St };
                case "getsettings":
                    return new IpcResponse { Ok = true, Data = St };
                case "setsettings":
                    if (!trusted) return Deny();
                    // GUI 只能修改不降低安全性的字段；放宽安全的字段（fake-ip 段、额外程序等）需管理员编辑 settings.json
                    var a = req.Args ?? new Dictionary<string, object>();
                    object v;
                    if (a.TryGetValue("ClashVergePath", out v)) St.ClashVergePath = Convert.ToString(v);
                    if (a.TryGetValue("ExitIpCheck", out v)) St.ExitIpCheck = Convert.ToBoolean(v);
                    if (a.TryGetValue("RequireManualUnlockAfterTrip", out v) && Convert.ToBoolean(v)) St.RequireManualUnlockAfterTrip = true;
                    St.Save();
                    Log.Info("设置已由 GUI 更新");
                    return new IpcResponse { Ok = true, Data = St };
            }
            return new IpcResponse { Ok = false, Error = "未知命令" };
        }

        // 手动“重新扫描梯子”：重新连接内核控制接口 → 重读 Clash Verge 全部订阅并重建日本节点汇总 → 热刷新 provider → 重测全部日本节点
        string Rescan()
        {
            var sb = new StringBuilder();
            Health.Reconnect();
            Engine.Evaluate(true);
            var c = Health.Client;
            sb.AppendLine(c != null ? "内核控制接口：已连接 " + c.Endpoint.Describe() : "内核控制接口：未连接（请确认 Clash Verge 正在运行）");
            Subs.ForceNext();
            try { Subs.Tick(); } catch (Exception ex) { Subs.LastError = ex.Message; }
            if (Subs.LastError != null) sb.AppendLine("订阅：" + Subs.LastError);
            else sb.AppendLine("订阅 " + Subs.Subs.Count + " 个：" + string.Join("，", Subs.Subs.Select(s => (s.Name ?? s.Uid) + " " + (s.Usable ? s.JapanCount + " 个日本节点" : s.Expired ? "已过期" : s.Exhausted ? "流量用完" : !s.Enabled ? "已停用" : "无日本节点"))));
            if (c != null)
            {
                // 内容没变时 Tick 不会刷新，这里无条件让内核重读汇总文件
                var r = c.Request("PUT", "/providers/proxies/" + Subscriptions.ProviderName);
                sb.AppendLine(r.Status == 204 || r.Status == 200 ? "日本节点汇总：内核已重新加载"
                    : r.Status == 404 ? "日本节点汇总：内核里没有 Japan Auto 汇总（Clash Verge 未加载本程序覆写，请在 Clash Verge 刷新一次配置，或在“设置”里重新写入覆写）"
                    : "日本节点汇总：刷新返回 " + r.Status);
                Nodes.ForceRecheck();
                try { Nodes.TestAllNow(); } catch (Exception ex) { sb.AppendLine("节点测试失败：" + ex.Message); }
                var snap = Nodes.Snapshot();
                sb.AppendLine("Japan Auto 当前候选节点 " + snap.Count + " 个，可用 " + snap.Count(d => d.ContainsKey("healthy") && d["healthy"] is bool && (bool)d["healthy"]) + " 个");
            }
            Log.Action("手动重新扫描梯子：" + sb.ToString().Replace("\r\n", "；").Trim());
            return sb.ToString().Trim();
        }

        Dictionary<string, object> NodeSnapshot()
        {
            return new Dictionary<string, object>
            {
                { "Status", Nodes.Status.ToString() }, { "Current", Nodes.Current }, { "Group", St.JapanGroupName },
                { "AutoSwitch", St.AutoSwitch }, { "Isolation", St.IsolationMode }, { "DedicatedPort", St.DedicatedPort },
                { "LastSwitchReason", Nodes.LastSwitchReason }, { "LastSwitchMs", Nodes.LastSwitchMs },
                { "LastSwitchAt", Nodes.LastSwitchAt == DateTime.MinValue ? null : Nodes.LastSwitchAt.ToString("yyyy-MM-dd HH:mm:ss") },
                { "NextRetryIn", Nodes.Status == NodeStatus.AllFailed ? Math.Max(0, (int)(Nodes.NextRetryAt - DateTime.Now).TotalSeconds) : -1 },
                { "ExitIp", Nodes.LastExitIp }, { "ExitCountry", Nodes.LastExitCountry },
                { "LastTrip", Engine.LastTrip.HasValue ? Engine.LastTrip.Value.ToString("yyyy-MM-dd HH:mm:ss") + " " + Engine.LastTripReason : null },
                { "Nodes", Nodes.Snapshot() }, { "Timeline", Engine.Timeline.Dump(30) },
                { "Subscriptions", Subs == null ? new List<object>() : Subs.Subs.Select(s => (object)new Dictionary<string, object> {
                    { "uid", s.Uid }, { "name", s.Name ?? s.Uid }, { "tag", s.Tag }, { "type", s.Type }, { "current", s.Current },
                    { "enabled", s.Enabled }, { "expired", s.Expired }, { "exhausted", s.Exhausted }, { "usable", s.Usable }, { "jp", s.JapanCount },
                    { "usedGB", Math.Round((s.Upload + s.Download) / 1073741824.0, 1) }, { "totalGB", Math.Round(s.Total / 1073741824.0, 1) },
                    { "expire", s.Expire > 0 ? new DateTime(1970, 1, 1).AddSeconds(s.Expire).ToLocalTime().ToString("yyyy-MM-dd") : null } }).ToList() },
                { "SubsError", Subs == null ? null : Subs.LastError },
                { "SubsUpdated", Subs == null || Subs.LastWrite == DateTime.MinValue ? null : Subs.LastWrite.ToString("HH:mm:ss") },
                { "Params", new Dictionary<string, object> {
                    { "MaxDelayMs", St.MaxDelayMs }, { "ProbeTimeoutMs", St.ProbeTimeoutMs }, { "FailThreshold", St.FailThreshold }, { "RecoverThreshold", St.RecoverThreshold },
                    { "HealthIntervalSec", St.HealthIntervalSec }, { "AllFailRetrySec", St.AllFailRetrySec }, { "SwitchCooldownSec", St.SwitchCooldownSec },
                    { "MinDwellSec", St.MinDwellSec }, { "CurrentNodeCheckSec", St.CurrentNodeCheckSec } } }
            };
        }

        static IpcResponse Deny() { return new IpcResponse { Ok = false, Error = "未授权的客户端（必须是安装目录中的 ClaudeVPNGuard.exe）" }; }
    }

    class GuardService : ServiceBase
    {
        GuardHost host;
        public GuardService()
        {
            ServiceName = GuardPaths.ServiceName;
            CanHandlePowerEvent = true;
            CanHandleSessionChangeEvent = true;
            CanShutdown = true;
            CanStop = true;
        }
        protected override void OnStart(string[] args)
        {
            host = new GuardHost();
            host.Start();
        }
        protected override void OnStop() { if (host != null) host.Stop(); }
        protected override void OnShutdown() { if (host != null) host.Stop(); }
        protected override bool OnPowerEvent(PowerBroadcastStatus s)
        {
            if (host == null) return true;
            if (s == PowerBroadcastStatus.Suspend) host.EnvChanged("系统即将休眠");
            else if (s == PowerBroadcastStatus.ResumeSuspend || s == PowerBroadcastStatus.ResumeAutomatic || s == PowerBroadcastStatus.ResumeCritical) host.EnvChanged("休眠恢复");
            return true;
        }
        protected override void OnSessionChange(SessionChangeDescription d)
        {
            if (host == null) return;
            if (d.Reason == SessionChangeReason.SessionLogon || d.Reason == SessionChangeReason.SessionLogoff || d.Reason == SessionChangeReason.ConsoleConnect || d.Reason == SessionChangeReason.SessionUnlock)
                host.EnvChanged("会话变化：" + d.Reason);
        }
    }

    static class Program
    {
        static int Main(string[] args)
        {
            var cmd = args.Length > 0 ? args[0].ToLowerInvariant().TrimStart('-', '/') : "";
            try { if (cmd != "") Console.OutputEncoding = Encoding.UTF8; } catch { }
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                Log.Error("未处理异常（保护器即将退出，规则保持）：" + e.ExceptionObject);
                try { if (GuardHost.Fw != null) GuardHost.Fw.SetLock(true); else new WindowsFirewall().SetLock(true); } catch { }
            };
            try
            {
                switch (cmd)
                {
                    case "": ServiceBase.Run(new GuardService()); return 0;
                    case "install": return Admin(Install);
                    case "uninstall": return Admin(Uninstall);
                    case "recover": return Admin(Recover);
                    case "console": return Admin(RunConsole);
                    case "diag": return Diag();
                    case "probe": Console.WriteLine("ok " + typeof(Program).Assembly.GetName().Version); return 0;
                    case "selftest":
                        if (args.Contains("--after-reboot")) return Admin(() => WfpSelfTest.Run(args));
                        return Admin(() => { if (!WfpSelfTest.Confirm(args)) return 4; int a = SelfTest.Run(); int b = WfpSelfTest.Run(args.Concat(new[] { "--confirmed" }).ToArray()); return a == 0 && b == 0 ? 0 : 1; });
                    case "wfp-add-and-hang": return Admin(() => WfpSelfTest.AddAndHang(args[1]));
                    case "isocheck": return Admin(WfpSelfTest.IsoCheck);
                    case "status":
                        Console.OutputEncoding = Encoding.UTF8;
                        try { Console.WriteLine(Json.Serialize(IpcClient.Call("status", null, 3000))); Console.WriteLine(Json.Serialize(IpcClient.Call("nodes", null, 3000))); return 0; }
                        catch (Exception ex) { Console.WriteLine("{\"error\":\"" + ex.Message.Replace("\"", "'") + "\"}"); return 1; }
                    case "jp-switch": return JpSwitch(args.Length > 1 ? args[1] : null);
                    case "preflight":
                    case "audit": return Audit.Run(args);
                    case "verify": return Admin(Verify);
                    case "version": Console.WriteLine("Claude VPN Guard " + GuardVersion.Text); return 0;
                    case "verge-apply": return VergeApply(true);
                    case "verge-remove": return VergeApply(false);
                    case "verge-hotload":
                        {
                            Console.OutputEncoding = Encoding.UTF8;
                            var vd = VergeOverride.FindVergeDataDir();
                            if (vd == null) { Console.WriteLine("未找到 Clash Verge 数据目录"); return 2; }
                            var st2 = GuardSettings.Load();
                            string d;
                            var cl = MihomoClient.Discover(st2, out d);
                            if (cl == null) { Console.WriteLine("Clash 内核不可用：" + d); return 2; }
                            try
                            {
                                // 汇总文件先就位，否则内核加载 provider 失败
                                new SubscriptionSync(st2, () => cl).Tick();
                                Console.WriteLine(VergeOverride.HotLoad(vd, st2, cl) ? "已自动套用覆写并重载 Clash 内核" : "Clash 当前配置已含本程序覆写，无需重载");
                                return 0;
                            }
                            catch (Exception ex) { Console.WriteLine("自动套用失败：" + ex.Message); return 1; }
                        }
                    case "verge-diff":
                        {
                            Console.OutputEncoding = Encoding.UTF8;
                            var vd = VergeOverride.FindVergeDataDir();
                            if (vd == null) { Console.WriteLine("未找到 Clash Verge 数据目录"); return 2; }
                            var lines = VergeOverride.DiffReport(vd, GuardSettings.Load());
                            foreach (var l in lines) Console.WriteLine(l);
                            if (args.Length > 1) File.WriteAllLines(args[1], lines, new UTF8Encoding(false));
                            return 0;
                        }
                    case "verge-restore":
                        {
                            Console.OutputEncoding = Encoding.UTF8;
                            var vd = VergeOverride.FindVergeDataDir();
                            var used = VergeOverride.Restore(vd, args.Length > 1 ? args[1] : null);
                            Console.WriteLine("已恢复：" + used + "。请在 Clash Verge 中刷新配置。");
                            return 0;
                        }
                    case "cc-proxy":
                        {
                            Console.OutputEncoding = Encoding.UTF8;
                            var st2 = GuardSettings.Load();
                            var sub = args.Length > 1 ? args[1] : "status";
                            var path = ClaudeCodeProxy.DefaultPath;
                            if (sub == "apply") { var b2 = ClaudeCodeProxy.Apply(path, st2.DedicatedPort); Console.WriteLine("已配置 Claude Code 专用代理（" + path + "，备份 " + (b2 ?? "无原文件") + "）。仅影响 Claude Code，新会话生效。"); }
                            else if (sub == "remove") { ClaudeCodeProxy.Remove(path); Console.WriteLine("已移除 Claude Code 专用代理配置并还原原值。"); }
                            Console.WriteLine(ClaudeCodeProxy.Status(path, st2.DedicatedPort));
                            return 0;
                        }
                    case "netprobe": return NetProbe.Run(args);
                    default:
                        Console.WriteLine("用法：ClaudeVPNGuard.Service.exe [install|uninstall|recover|verify|console|diag|preflight|selftest [--keep|--after-reboot]|verge-apply|verge-remove]");
                        return 2;
                }
            }
            catch (Exception ex) { Console.WriteLine("错误：" + ex.Message); Log.Error(cmd + " 失败：" + ex); return 1; }
        }

        static bool IsAdmin() { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }

        static int Admin(Func<int> f)
        {
            if (!IsAdmin()) { Console.WriteLine("此操作需要管理员权限：请在“以管理员身份运行”的终端中执行。"); return 5; }
            Log.EchoConsole = true;
            return f();
        }

        static string Sc(string args)
        {
            var psi = new ProcessStartInfo("sc.exe", args) { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.Default };
            using (var p = Process.Start(psi)) { var o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o.Trim(); }
        }

        static int Install()
        {
            var exe = Process.GetCurrentProcess().MainModule.FileName;
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!exe.StartsWith(pf, StringComparison.OrdinalIgnoreCase))
                Console.WriteLine("警告：建议安装到 Program Files 下（仅管理员可写），当前位置：" + exe);
            Directory.CreateDirectory(GuardPaths.DataDir);
            var st = GuardSettings.Load();
            if (!File.Exists(GuardPaths.SettingsFile)) st.Save();
            // 先建规则（默认锁定），再注册服务：安装过程中也不存在放开窗口
            var loc = new ClaudeLocator(st);
            var exes = loc.DiscoverExecutables();
            var fw = GuardHost.BuildFirewall(st);
            fw.EnsureRules(exes, st.FakeIpRange, true);
            Console.WriteLine("已为 " + exes.Count + " 个 Claude 程序创建 Windows 防火墙规则 + WFP 持久过滤器（锁定状态）");
            // 应急恢复副本：即使安装目录损坏，也能用它删除 WFP 过滤器
            try
            {
                var rec = Path.Combine(GuardPaths.DataDir, "recovery");
                Directory.CreateDirectory(rec);
                File.Copy(exe, Path.Combine(rec, "ClaudeVPNGuard.Service.exe"), true);
            }
            catch (Exception ex) { Console.WriteLine("警告：应急恢复副本保存失败：" + ex.Message); }
            Sc("stop " + GuardPaths.ServiceName);
            Sc("delete " + GuardPaths.ServiceName);
            Thread.Sleep(1000);
            Console.WriteLine(Sc("create " + GuardPaths.ServiceName + " binPath= \"\\\"" + exe + "\\\"\" start= auto DisplayName= \"Claude VPN Guard\""));
            Sc("description " + GuardPaths.ServiceName + " \"Claude VPN Guard：代理异常时阻断并关闭 Claude，防止真实 IP 泄漏\"");
            Sc("failure " + GuardPaths.ServiceName + " reset= 86400 actions= restart/1000/restart/2000/restart/5000");
            Sc("failureflag " + GuardPaths.ServiceName + " 1");
            Console.WriteLine(Sc("start " + GuardPaths.ServiceName));
            Log.Action("安装完成：" + exe);
            return 0;
        }

        static int Uninstall()
        {
            Console.WriteLine(Sc("stop " + GuardPaths.ServiceName));
            Thread.Sleep(1500);
            Console.WriteLine(Sc("delete " + GuardPaths.ServiceName));
            int n = GuardHost.BuildFirewall(GuardSettings.Load()).RemoveAll();
            try { File.Delete(GuardPaths.StateFile); } catch { }
            try { var vd = VergeOverride.FindVergeDataDir(); if (vd != null) { VergeOverride.Remove(vd); Console.WriteLine("已从 Clash Verge 全局扩展脚本移除本程序段（需在 Clash Verge 刷新配置）"); } }
            catch (Exception ex) { Console.WriteLine("移除 Clash Verge 段失败：" + ex.Message); }
            try { if (File.Exists(ClaudeCodeProxy.DefaultPath)) { ClaudeCodeProxy.Remove(ClaudeCodeProxy.DefaultPath); Console.WriteLine("已还原 Claude Code 代理设置"); } }
            catch (Exception ex) { Console.WriteLine("还原 Claude Code 代理设置失败：" + ex.Message); }
            try { Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeVPNGuard", false); } catch { }
            Console.WriteLine("已删除本程序创建的防火墙规则/WFP 过滤器 " + n + " 条（规则组 " + GuardPaths.RuleGroup + "）。日志保留在 " + GuardPaths.LogDir);
            Log.Action("卸载：删除服务与规则 " + n + " 条");
            return 0;
        }

        static int Recover()
        {
            Sc("stop " + GuardPaths.ServiceName);
            Sc("config " + GuardPaths.ServiceName + " start= demand");
            Thread.Sleep(1500);
            int n = GuardHost.BuildFirewall(GuardSettings.Load()).RemoveAll();
            Console.WriteLine("应急恢复：已停止保护服务（改为手动启动），删除规则 " + n + " 条。Claude 现在不受保护！");
            Console.WriteLine("恢复保护：sc config " + GuardPaths.ServiceName + " start= auto  然后  ClaudeVPNGuard.Service.exe install");
            Log.Action("应急恢复：删除规则 " + n + " 条，服务改为手动");
            return 0;
        }

        static bool ServiceRunning()
        {
            try { using (var sc = new ServiceController(GuardPaths.ServiceName)) return sc.Status == ServiceControllerStatus.Running; } catch { return false; }
        }

        // 安装脚本用：服务运行 + 规则/过滤器完整
        static int Verify()
        {
            var st = GuardSettings.Load();
            bool running = false;
            try { using (var sc = new ServiceController(GuardPaths.ServiceName)) running = sc.Status == ServiceControllerStatus.Running; } catch { }
            var exes = new ClaudeLocator(st).DiscoverExecutables();
            string d;
            bool rules = GuardHost.BuildFirewall(st).VerifyRules(exes, st.FakeIpRange, false, out d);
            Console.WriteLine("服务运行：" + (running ? "是" : "否") + "；" + d);
            return running && rules ? 0 : 1;
        }

        // 写入/移除 Clash Verge 全局扩展脚本（修改的是当前用户的 Clash Verge 配置，必须由用户确认后执行）
        static int VergeApply(bool apply)
        {
            var dir = VergeOverride.FindVergeDataDir();
            if (dir == null) { Console.WriteLine("未找到 Clash Verge 数据目录"); return 2; }
            var st = GuardSettings.Load();
            if (apply)
            {
                var bak = VergeOverride.Apply(dir, st);
                Console.WriteLine("已写入 Japan Auto 覆写（备份：" + bak + "）。请在 Clash Verge 中刷新当前订阅或重启 Clash Verge 使其生效。");
            }
            else
            {
                VergeOverride.Remove(dir);
                Console.WriteLine("已移除覆写段。请在 Clash Verge 中刷新配置。");
                if (st.IsolationMode && ServiceRunning())
                    Console.WriteLine("注意：保护服务正在运行（隔离模式），会在几秒内自动补写覆写段。要彻底移除请先卸载（scripts\\full-uninstall.ps1）。");
            }
            return 0;
        }

        // 在 Japan Auto 内切换到另一个日本节点（验收脚本的“节点切换”场景；只动 Japan Auto 组）
        static int JpSwitch(string target)
        {
            Console.OutputEncoding = Encoding.UTF8;
            var st = GuardSettings.Load();
            string d;
            var cl = MihomoClient.Discover(st, out d);
            if (cl == null) { Console.WriteLine("内核不可用：" + d); return 2; }
            var api = new MihomoNodeApi(() => cl, st);
            var mem = api.GroupMembers(st.JapanGroupName);
            if (mem == null) { Console.WriteLine(st.JapanGroupName + " 组不存在（覆写未生效）"); return 2; }
            var cur = api.GroupNow(st.JapanGroupName);
            if (target == null) target = mem.FirstOrDefault(m => m != cur && !NodeManager.IsReject(m));
            if (target == null || !mem.Contains(target)) { Console.WriteLine("目标节点不在 " + st.JapanGroupName + " 中"); return 2; }
            api.Select(st.JapanGroupName, target);
            string ip; var c = api.ExitCountry(out ip);
            Console.WriteLine("已切换：" + cur + " → " + target + "，出口 " + ip + " " + c);
            return string.Equals(c, st.ExpectedExitCountry, StringComparison.OrdinalIgnoreCase) ? 0 : 1;
        }

        static int RunConsole()
        {
            var h = new GuardHost();
            h.Start();
            Console.WriteLine("前台运行中，按回车退出（退出后锁定规则保持启用）");
            Console.ReadLine();
            h.Stop();
            return 0;
        }

        // 只读诊断：不创建/修改任何规则
        static int Diag()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Log.Dir = Path.Combine(Path.GetTempPath(), "ClaudeVPNGuard-diag");
            var st = GuardSettings.Load();
            var loc = new ClaudeLocator(st);
            var exes = loc.DiscoverExecutables();
            Console.WriteLine("Claude 可执行文件（" + exes.Count + "）：");
            foreach (var e in exes) Console.WriteLine("  " + e);
            Console.WriteLine("MSIX 启动目标：" + (loc.LastMsixFamily ?? "(无)"));
            Console.WriteLine("运行中的 Claude 进程：" + loc.RunningClaude().Count);
            var hc = new HealthChecker(st, loc, new WindowsFirewall()) { CheckFirewallRules = IsAdmin() };
            var r = hc.Run(true, exes);
            Console.WriteLine();
            foreach (var i in r.Items)
                Console.WriteLine(string.Format("[{0}]{1} {2}：{3}", i.Ok ? "通过" : "失败", i.Critical ? "" : "(提示)", i.Name, i.Detail));
            Console.WriteLine();
            Console.WriteLine("内核 " + r.CoreVersion + " | 模式 " + r.Mode + " | 节点 " + r.Node + " | TUN " + (r.TunEnabled ? (r.TunUp ? "开/网卡在线" : "开/网卡离线") : "关") + " | 系统代理 " + (r.SysProxyOn ? r.SysProxyServer : "关") + " | 出口 " + r.ExitIp);
            Console.WriteLine("结论：" + (r.Safe ? "安全，允许 Claude 联网" : "不安全 → " + r.FirstFailure));
            return r.Safe ? 0 : 3;
        }
    }
}
