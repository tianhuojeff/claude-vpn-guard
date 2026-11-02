// written_by: claude-code
// 私有 Mihomo 故障注入场景 + 响应时间测量。分类：「模拟故障测试（真实 Mihomo 内核 + 假节点）」。
// 防火墙/WFP 在这里用假实现，所以这些结果不证明系统级阻断——系统级阻断由 selftest（管理员）证明。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace ClaudeVPNGuard
{
    static partial class Lab
    {
        static string J(int i) { return "\U0001F1EF\U0001F1F5Japan 0" + i; }

        static bool WaitFor(Func<bool> cond, int ms)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < ms) { if (cond()) return true; Thread.Sleep(50); }
            return cond();
        }

        static string Ms(DateTime? t, DateTime t0) { return t.HasValue ? ((int)(t.Value - t0).TotalMilliseconds).ToString() + "ms" : "未发生"; }

        static void Reset(List<FakeNode> nodes) { foreach (var n in nodes) { n.Mode = FakeMode.Up; n.Hits = 0; n.SlowMs = 800; n.Country = n.Name.Contains("Korea") ? "KR" : n.Name.Contains("United") ? "US" : "JP"; } }

        static void RunScenarios(List<FakeNode> nodes, string work, string[] args)
        {
            var st = LabSettings();
            st.AllFailRetrySec = 6;   // 实验中缩短重试间隔（默认 60 秒）
            st.MinDwellSec = 8; st.SwitchCooldownSec = 4; st.QuarantineSec = 30;
            Reset(nodes);
            using (var m = StartLab(nodes, "rule", st, work))
            {
                var api = new MihomoNodeApi(() => m.Client(), st);
                var tl = new Timeline();
                var nm = new NodeManager(api, st, tl);
                string allFailed = null, recovered = null, secFault = null;
                nm.OnAllFailed = r => allFailed = r;
                nm.OnRecovered = r => recovered = r;
                nm.OnSecurityFault = r => secFault = r;
                // 慢节点用于固定排序：J01 最快，J02 次之，J04 较慢
                nodes[1].Mode = FakeMode.Slow; nodes[1].SlowMs = 60;
                nodes[3].Mode = FakeMode.Slow; nodes[3].SlowMs = 150;
                m.Client().SelectProxy(st.JapanGroupName, J(3));
                var stop = false;
                var ticker = new Thread(() => { while (!stop) { try { nm.Tick(); } catch (Exception ex) { Out("    tick 异常：" + ex.Message); } Thread.Sleep(1000); } }) { IsBackground = true };
                ticker.Start();
                try
                {
                    WaitFor(() => nm.Status == NodeStatus.Healthy && nm.Current == J(3), 10000);
                    Check("初始：Japan Auto 当前 Japan 03 且健康", nm.Current == J(3) && nm.Status == NodeStatus.Healthy, nm.Status + " " + nm.Current);

                    // 1. Japan 03 断线（连接立即被拒）→ Japan 01
                    Out("\n[S1] Japan 03 断线 → 应切换到 Japan 01");
                    var t0 = DateTime.Now; tl.Clear();
                    nodes[2].Mode = FakeMode.Down;
                    bool sw1 = WaitFor(() => nm.Current == J(1) && nm.Status == NodeStatus.Healthy, 30000);
                    Check("切换到 Japan 01", sw1, nm.Current + " / " + nm.LastSwitchReason);
                    Out("    时间线（相对故障注入）：首次失败 " + Ms(tl.First("fault:first-fail " + J(3), t0), t0) + "，确认故障 " + Ms(tl.First("fault:confirmed " + J(3), t0), t0)
                        + "，开始切换 " + Ms(tl.First("switch:start", t0), t0) + "，选中 " + Ms(tl.First("switch:selected " + J(1), t0), t0)
                        + "，出口验证 " + Ms(tl.First("switch:exit-verified " + J(1), t0), t0) + "，可用 " + Ms(tl.First("switch:ready " + J(1), t0), t0) + "；切换本身耗时 " + nm.LastSwitchMs + "ms");
                    Timing.Add(new[] { "Japan 03 断线(拒绝连接)", Ms(tl.First("fault:first-fail " + J(3), t0), t0), Ms(tl.First("switch:start", t0), t0), Ms(tl.First("switch:ready " + J(1), t0), t0) });
                    var via = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/a", 4000);
                    Check("切换后专用入口实际经 Japan 01", via == J(1), via);
                    Check("出口国家校验 = JP", nm.LastExitCountry == "JP", nm.LastExitCountry + " " + nm.LastExitIp);

                    // 2. Japan 01 卡死（超时）→ Japan 02
                    Out("\n[S2] Japan 01 卡死（每次探测超时 3 秒）→ 应切换到 Japan 02");
                    t0 = DateTime.Now; tl.Clear();
                    nodes[0].Mode = FakeMode.Stall;
                    bool sw2 = WaitFor(() => nm.Current == J(2) && nm.Status == NodeStatus.Healthy, 40000);
                    Check("切换到 Japan 02（Japan 03 仍在隔离期）", sw2, nm.Current + " / " + nm.LastSwitchReason);
                    Out("    时间线：首次失败 " + Ms(tl.First("fault:first-fail " + J(1), t0), t0) + "，开始切换 " + Ms(tl.First("switch:start", t0), t0) + "，可用 " + Ms(tl.First("switch:ready " + J(2), t0), t0));
                    Timing.Add(new[] { "Japan 01 卡死(超时)", Ms(tl.First("fault:first-fail " + J(1), t0), t0), Ms(tl.First("switch:start", t0), t0), Ms(tl.First("switch:ready " + J(2), t0), t0) });

                    // 3. 全部日本节点失败
                    Out("\n[S3] 全部日本节点失败 → 保持阻断，不回退 DIRECT/其他国家");
                    t0 = DateTime.Now; tl.Clear(); allFailed = null;
                    foreach (var n in nodes.Take(4)) n.Mode = FakeMode.Down;
                    foreach (var n in nodes) n.Hits = 0;
                    bool af = WaitFor(() => nm.Status == NodeStatus.AllFailed, 30000);
                    Check("进入“全部失败”并通知保护引擎（阻断 + 关闭 Claude）", af && allFailed != null, nm.Status + " / " + allFailed);
                    Out("    时间线：首次失败 " + Ms(tl.First("fault:first-fail " + J(2), t0), t0) + "，判定全部失败 " + Ms(tl.First("switch:all-failed", t0), t0));
                    Timing.Add(new[] { "全部日本节点断线", Ms(tl.First("fault:first-fail " + J(2), t0), t0), Ms(tl.First("switch:start", t0), t0), "全部失败 @ " + Ms(tl.First("switch:all-failed", t0), t0) });
                    var viaAll = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/b", 4000);
                    Check("全部失败时专用入口请求失败，韩国/美国节点 0 命中", (viaAll == null || viaAll.StartsWith("HTTP5")) && nodes[4].Hits == 0 && nodes[5].Hits == 0, (viaAll ?? "失败") + " KR=" + nodes[4].Hits + " US=" + nodes[5].Hits);
                    var members = api.GroupMembers(st.JapanGroupName);
                    Check("全部失败后组内仍只有日本节点", members.All(x => x.Contains("Japan")), string.Join(",", members));

                    // 4. 节点恢复
                    Out("\n[S4] Japan 02 恢复 → 下一次重试自动选择，发送恢复通知（不自动打开 Claude）");
                    t0 = DateTime.Now; tl.Clear(); recovered = null;
                    nodes[1].Mode = FakeMode.Slow;
                    bool rec = WaitFor(() => nm.Status == NodeStatus.Healthy && recovered != null, 20000);
                    Check("恢复到 Japan 02 并发出恢复通知", rec && nm.Current == J(2), nm.Current + " / " + recovered);
                    Out("    恢复耗时（从节点恢复到可用）：" + Ms(tl.First("switch:ready " + J(2), t0), t0) + "（受重试间隔 " + st.AllFailRetrySec + " 秒约束）");

                    // 5. 节点抖动：当前节点隔次失败，不应切换
                    Out("\n[S5] Japan 02 抖动（每两次请求失败一次，偶发失败）→ 连续失败未达 2 次，不应切换");
                    foreach (var n in nodes.Take(4)) n.Mode = FakeMode.Up;
                    nodes[1].Mode = FakeMode.Up;
                    var before = nm.LastSwitchAt;
                    var flap = true;
                    var flapper = new Thread(() => { nodes[1].Mode = FakeMode.Alternate; while (flap) Thread.Sleep(200); nodes[1].Mode = FakeMode.Up; }) { IsBackground = true };
                    flapper.Start();
                    Thread.Sleep(20000);
                    flap = false; flapper.Join();
                    Check("抖动 20 秒内没有发生切换", nm.LastSwitchAt == before && nm.Current == J(2), "当前 " + nm.Current + "，最近切换 " + nm.LastSwitchAt.ToString("HH:mm:ss"));

                    // 6. 健康时不因别的节点更快而切换
                    nodes[1].Mode = FakeMode.Slow; nodes[1].SlowMs = 120; nodes[0].Mode = FakeMode.Up;
                    Thread.Sleep(8000);
                    Check("当前节点健康（120ms）时，不因 Japan 01 更快而切换", nm.Current == J(2), nm.Current);

                    // 7. 质量故障：延迟超上限，受最短驻留约束
                    Out("\n[S6] Japan 02 延迟升至 450ms（超过 300ms 上限）→ 质量故障，满足驻留/冷却后切换，Claude 不被关闭");
                    t0 = DateTime.Now; tl.Clear(); allFailed = null;
                    nodes[1].SlowMs = 450;
                    bool q = WaitFor(() => nm.Current != J(2) && nm.Status == NodeStatus.Healthy, 40000);
                    Check("质量故障后切换到其他日本节点，且未触发“全部失败”", q && allFailed == null, nm.Current + " / " + nm.LastSwitchReason);

                    // 8. 恢复验证失败：候选节点出口不是日本
                    Out("\n[S7] 恢复验证失败：Japan 01 出口被伪装成 KR → 必须拒绝该节点");
                    foreach (var n in nodes.Take(4)) { n.Mode = FakeMode.Up; }
                    nodes[0].Country = "KR";
                    m.Client().SelectProxy(st.JapanGroupName, J(4));
                    Thread.Sleep(1500);
                    nodes[3].Mode = FakeMode.Down; // 当前 J04 故障，J01 最快但出口错误
                    bool rejected = WaitFor(() => nm.Current != J(4) && nm.Status == NodeStatus.Healthy, 30000);
                    Check("出口国家不符的 Japan 01 被拒绝，选了其他日本节点", rejected && nm.Current != J(1), nm.Current + " / J01 错误：" + (nm.Stats.ContainsKey(J(1)) ? nm.Stats[J(1)].LastError : ""));
                    nodes[0].Country = "JP";

                    // 9. 手动切换
                    Out("\n[S8] 手动切换");
                    foreach (var n in nodes.Take(4)) n.Mode = FakeMode.Up;
                    var err = nm.ManualSelect(J(4));
                    Check("手动选择 Japan 04 成功", err == null && nm.Current == J(4), err);
                    err = nm.ManualSelect(nodes[4].Name);
                    Check("手动选择韩国节点被拒绝", err != null, err);

                    // 10. 订阅更新：删除当前节点 Japan 04，新增 Japan 05
                    Out("\n[S9] 订阅更新：删除当前 Japan 04、新增 Japan 05 → 覆写脚本自动纳入新节点，当前节点被删后立即切换");
                    var j5 = new FakeNode(J(5), 28005); j5.Start(); nodes.Add(j5);
                    var newNodes = nodes.Where(n => n.Name != J(4)).ToList();
                    var script = VergeOverride.Compose("function main(config, profileName) {\n  return config;\n}\n", st);
                    var cfg = MihomoInstance.RunScriptWithNode(script, MihomoInstance.BaseConfig(newNodes, "rule"), work);
                    var newPath = Path.Combine(m.Dir, "config2.json");
                    File.WriteAllText(newPath, cfg, new System.Text.UTF8Encoding(false));
                    t0 = DateTime.Now; tl.Clear();
                    m.Client().ReloadConfig(newPath);
                    bool sub = WaitFor(() => nm.Current != null && nm.Current != J(4) && nm.Status == NodeStatus.Healthy, 20000);
                    var mem2 = api.GroupMembers(st.JapanGroupName);
                    Check("新节点 Japan 05 自动进入 Japan Auto，Japan 04 已移除", mem2.Contains(J(5)) && !mem2.Contains(J(4)), string.Join(",", mem2));
                    Check("当前节点被删除后切换到在册日本节点", sub, nm.Current + "，耗时 " + Ms(tl.First("switch:ready " + nm.Current, t0), t0));

                    // 11. 自动切换关闭：故障时不切换
                    Out("\n[S10] 关闭自动切换：当前节点故障时只报告，不切换");
                    st.AutoSwitch = false;
                    var cur = nm.Current;
                    nodes.First(n => n.Name == cur).Mode = FakeMode.Down;
                    Thread.Sleep(st.CurrentNodeCheckSec * 1000 * 3 + 1500);
                    Check("自动切换关闭时保持当前节点并给出原因", nm.Current == cur && (nm.LastSwitchReason ?? "").Contains("自动切换已关闭"), nm.LastSwitchReason);
                    st.AutoSwitch = true;
                    nodes.First(n => n.Name == cur).Mode = FakeMode.Up;
                    Check("未出现任何安全异常（组缺失/非日本节点）", secFault == null, secFault);
                }
                finally { stop = true; ticker.Join(3000); }

                // 12. 专用入口语义下的保护引擎快速检测（隔离模式）
                Out("\n[S11] 隔离模式快速检测：模式=direct 时 Claude 不受影响；Japan Auto 与专用入口在线");
                m.Client().PatchConfig(new Dictionary<string, object> { { "mode", "direct" } });
                st.IsolationMode = true;
                var fw = new FakeFirewall();
                var hc = new HealthChecker(st, new ClaudeLocator(st), fw) { ForcedClient = m.Client(), CheckFirewallRules = false };
                var rep = hc.Run(false, new List<string>());
                Func<string, CheckItem> item = id => rep.Items.FirstOrDefault(i => i.Id == id);
                Check("检测项：Japan Auto 组通过", item("jpgroup") != null && item("jpgroup").Ok, item("jpgroup") == null ? "无" : item("jpgroup").Detail);
                Check("检测项：专用入口在线", item("listener") != null && item("listener").Ok, item("listener") == null ? "无" : item("listener").Detail);
                Check("模式=direct 在隔离模式下不是关键失败", item("mode") != null && !item("mode").Critical, item("mode") == null ? "无" : item("mode").Detail);

                // 回归（2026-11-01 实机误判）：其他软件（如浏览器）经通用端口访问 claude.ai，不得被判为 Claude 违规
                Out("\n[S11b] 非 Claude 进程经通用端口访问 claude.ai → 隔离模式下不应判定 Claude 违规");
                m.Client().PatchConfig(new Dictionary<string, object> { { "mode", "global" } });
                m.Client().SelectProxy("GLOBAL", J(1));
                nodes[0].Mode = FakeMode.Up; // 假节点应答 CONNECT 后等待内层请求，连接保持打开
                using (var tc = new System.Net.Sockets.TcpClient())
                {
                    tc.Connect(System.Net.IPAddress.Loopback, m.MixedPort);
                    var s = tc.GetStream();
                    var req = System.Text.Encoding.ASCII.GetBytes("CONNECT claude.ai:80 HTTP/1.1\r\nHost: claude.ai:80\r\n\r\n");
                    s.Write(req, 0, req.Length);
                    // 不发送内层请求：实验配置未开启嗅探，Mihomo 收到 CONNECT 即拨号并登记连接
                    bool seen = WaitFor(() => Json.Arr(m.Client().Connections(), "connections").Any(c => Json.Str(Json.Get(c, "metadata"), "host") == "claude.ai"), 5000);
                    Check("测试连接已出现在内核连接表（host=claude.ai，非 Claude 进程）", seen, null);
                    var rep3 = hc.Run(false, new List<string>());
                    var audit = rep3.Items.FirstOrDefault(i => i.Id == "audit");
                    Check("隔离模式：连接审计不把它算作 Claude 违规", audit != null && audit.Ok, audit == null ? "无审计项" : audit.Detail);
                    st.IsolationMode = false;
                    var rep4 = hc.Run(false, new List<string>());
                    var audit4 = rep4.Items.FirstOrDefault(i => i.Id == "audit");
                    Check("非隔离模式：经节点（非直连）访问 claude.ai 也不判违规", audit4 != null && audit4.Ok, audit4 == null ? "无审计项" : audit4.Detail);
                    st.IsolationMode = true;
                }
                nodes[0].Mode = FakeMode.Up;

                // 13. 内核被强制结束：进程句柄等待的检测速度 + 引擎动作顺序
                Out("\n[S12] 私有 Mihomo 进程被强制结束 → 检测耗时与动作时间线（防火墙为模拟实现）");
                var watcher = new CoreWatcher();
                var fakeClaude = new FakeClaude { Running = 2 };
                var engine = new GuardEngine(st, new FakeFirewall(), new FakeHealth { Next = f => FakeHealth.Fail("core", "x") }, fakeClaude, new FakeNotifier());
                engine.Startup();
                DateTime? detected = null;
                watcher.Exited = d => { detected = DateTime.Now; engine.OnCoreExited(d); };
                bool watching = watcher.Watch(CoreWatcher.FindCorePid(m.MixedPort, m.DedicatedPort));
                Check("通过监听端口定位到私有内核进程并开始等待其句柄", watching && watcher.WatchedPid == m.Proc.Id, "pid=" + watcher.WatchedPid + " 实际=" + m.Proc.Id);
                var kill0 = DateTime.Now;
                m.Proc.Kill();
                WaitFor(() => detected.HasValue && fakeClaude.Running == 0, 5000);
                Check("内核退出 1 秒内被发现", detected.HasValue && (detected.Value - kill0).TotalMilliseconds < 1000, Ms(detected, kill0));
                var tl2 = engine.Timeline;
                Out("    时间线：发现 " + Ms(detected, kill0) + "，锁定 " + Ms(tl2.First("trip:locked", kill0), kill0) + "，结束 Claude " + Ms(tl2.First("trip:killed", kill0), kill0));
                Timing.Add(new[] { "Mihomo 进程被强制结束", Ms(detected, kill0), "锁定 @ " + Ms(tl2.First("trip:locked", kill0), kill0), "结束 Claude @ " + Ms(tl2.First("trip:killed", kill0), kill0) });
                Check("动作顺序：先锁定再结束 Claude", tl2.First("trip:locked", kill0) <= tl2.First("trip:killed", kill0) && engine.State == GuardState.Tripped, engine.State.ToString());
                var viaDead = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/c", 2000);
                Check("内核退出后专用入口不可连接（无回退）", viaDead == null, viaDead);
                watcher.Dispose();
            }

            // 14. 专用入口失效：覆写缺少 listener
            Out("\n[S13] 专用入口失效（配置中没有 listener）→ 检测失败；Claude 无路可走而不是直连");
            Reset(nodes);
            var cfgNoListener = MihomoInstance.BaseConfig(nodes.Take(4), "rule");
            using (var m2 = new MihomoInstance())
            {
                m2.Start(cfgNoListener);
                var st2 = LabSettings(); st2.IsolationMode = true;
                var hc2 = new HealthChecker(st2, new ClaudeLocator(st2), new FakeFirewall()) { ForcedClient = m2.Client(), CheckFirewallRules = false };
                var rep2 = hc2.Run(false, new List<string>());
                Check("缺少 Japan Auto / 专用入口 → 判定不安全", !rep2.Safe, rep2.FirstFailure);
                Check("专用入口端口无监听", MihomoInstance.GetVia(st2.DedicatedPort, "http://probe.cvg.test/d", 2000) == null, null);
            }

            Out("\n响应时间汇总（相对故障注入时刻）：");
            Out("  场景 | 首次发现 | 开始切换/锁定 | 恢复可用/结束");
            foreach (var t in Timing) Out("  " + string.Join(" | ", t));
        }

        public static List<string[]> Timing = new List<string[]>();
    }
}
