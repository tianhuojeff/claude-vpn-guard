// written_by: claude-code
// 重复故障注入测量（ClaudeVPNGuard.Tests.exe --lab bench [次数] [输出文件]）
// 真实 Mihomo 内核 + 假节点；保护引擎接入（防火墙/Claude 为模拟实现，用于记录阻断与结束动作的时刻，并断言节点故障不触发误杀）。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace ClaudeVPNGuard
{
    static partial class Lab
    {
        class Sample
        {
            public Dictionary<string, double> T = new Dictionary<string, double>();
            public bool Killed, Locked, StaticTouched, Ok;
            public string Picked;
        }

        static double? Rel(Timeline tl, string what, DateTime t0)
        {
            var t = tl.First(what, t0);
            return t.HasValue ? (t.Value - t0).TotalMilliseconds : (double?)null;
        }

        static string Stat(IEnumerable<double> xs)
        {
            var a = xs.OrderBy(x => x).ToList();
            if (a.Count == 0) return "无数据 | - | - | -";
            int p95 = (int)Math.Ceiling(0.95 * a.Count) - 1;
            return string.Format("{0} | {1:0} | {2:0} | {3:0}", a.Count, a.Average(), a.Max(), a[Math.Max(0, p95)]);
        }

        static GuardSettings BenchSettings()
        {
            var st = LabSettings();
            st.NodeLivenessUrl = "http://probe.cvg.test/generate_204";
            return st; // 其余参数全部为默认值：超时 3000ms、连续失败 2、冷却 30s、驻留 120s、隔离 300s
        }

        // 一次节点故障：返回各阶段相对故障注入的毫秒数
        static Sample OneNodeFault(MihomoInstance m, List<FakeNode> nodes, NodeManager.MonitorStrategy strat, FakeMode fault, Random rnd)
        {
            var st = BenchSettings();
            foreach (var n in nodes) { n.Mode = FakeMode.Up; n.Country = n.Name.Contains("Korea") ? "KR" : n.Name.Contains("United") ? "US" : "JP"; }
            nodes[1].Mode = FakeMode.Slow; nodes[1].SlowMs = 60;
            nodes[3].Mode = FakeMode.Slow; nodes[3].SlowMs = 150;
            m.Client().SelectProxy(st.JapanGroupName, J(3));
            var tl = new Timeline();
            var api = new MihomoNodeApi(() => m.Client(), st);
            var nm = new NodeManager(api, st, tl) { Strategy = strat };
            var fw = new FakeFirewall();
            var claude = new FakeClaude { Running = 1 };
            var engine = new GuardEngine(st, fw, new FakeHealth { Next = f => FakeHealth.Safe() }, claude, new FakeNotifier());
            engine.Startup(); engine.Evaluate(true);
            engine.Timeline = tl;
            int opsAfterProtected = fw.Ops.Count;
            nm.OnAllFailed = r => engine.OnNodeOutage(r);
            // 真实路径验证：经专用入口请求，必须由所选节点应答
            nm.VerifyClaudePath = cand => MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/verify", 5000) == cand;
            bool stop = false;
            var ticker = new Thread(() => { while (!stop) { try { nm.Tick(); } catch { } Thread.Sleep(1000); } }) { IsBackground = true };
            ticker.Start();
            var s = new Sample();
            try
            {
                WaitFor(() => nm.Current == J(3) && nm.Status == NodeStatus.Healthy, 15000);
                Thread.Sleep(rnd.Next(0, 3000)); // 随机相位，避免与探测周期对齐
                var t0 = DateTime.Now;
                tl.Mark("fault:injected");
                nodes[2].Mode = fault;
                s.Ok = WaitFor(() => tl.First("switch:ready", t0).HasValue || tl.First("switch:all-failed", t0).HasValue, 45000);
                foreach (var k in new[] { "fault:first-fail", "fault:confirmed", "cand:start", "cand:done", "cand:reused", "switch:start", "switch:selected", "switch:exit-verified", "switch:path-verified", "switch:ready", "trip:locked", "trip:killed" })
                {
                    var v = Rel(tl, k, t0);
                    if (v.HasValue) s.T[k] = v.Value;
                }
                s.Picked = nm.Current;
                s.Killed = claude.Running == 0;
                s.Locked = fw.Ops.Skip(opsAfterProtected).Contains("lock");
                s.StaticTouched = fw.Ops.Skip(opsAfterProtected).Any(o => o.StartsWith("ensure") || o.StartsWith("remove"));
            }
            finally { stop = true; ticker.Join(3000); nodes[2].Mode = FakeMode.Up; }
            Thread.Sleep(fault == FakeMode.Stall ? 3500 : 500); // 等待残留探测超时结束
            return s;
        }

        public static void Bench(List<FakeNode> nodes, string work, int n)
        {
            var rnd = new Random(20261101);
            var st0 = BenchSettings();
            Out("Claude VPN Guard 节点故障转移重复测量  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            Out(string.Format("参数（均为默认值，未缩短超时）：单次探测超时 {0}ms，连续失败 {1} 次，延迟上限 {2}ms，旧策略检测周期 {3}s，新策略存活探测间隔 {4}ms", st0.ProbeTimeoutMs, st0.FailThreshold, st0.MaxDelayMs, st0.CurrentNodeCheckSec, st0.LivenessIntervalMs));
            Out("每次注入前随机等待 0~3 秒（随机相位）。时间均为相对“故障注入时刻”的毫秒数。\n");
            var summary = new List<string>();
            using (var m = StartLab(nodes, "rule", st0, work))
            {
                foreach (var fault in new[] { FakeMode.Stall, FakeMode.Down })
                {
                    foreach (var strat in new[] { NodeManager.MonitorStrategy.Sequential, NodeManager.MonitorStrategy.Pipelined })
                    {
                        var label = (fault == FakeMode.Stall ? "卡死(探测超时)" : "断线(连接被拒)") + " / " + (strat == NodeManager.MonitorStrategy.Sequential ? "修改前·串行" : "修改后·流水线+并行预检");
                        Out("[" + label + "] 共 " + n + " 次");
                        var samples = new List<Sample>();
                        for (int i = 0; i < n; i++)
                        {
                            var smp = OneNodeFault(m, nodes, strat, fault, rnd);
                            samples.Add(smp);
                            Func<string, string> g = k => smp.T.ContainsKey(k) ? ((int)smp.T[k]).ToString() : "-";
                            Out(string.Format("  #{0,2} 首次发现 {1} | 二次确认 {2} | 候选检测 {3}→{4}{5} | 开始切换 {6} | 选中 {7} | 出口验证 {8} | 路径验证 {9} | 切换完成 {10} | 选中节点 {11} | 网络阻断 {12} | Claude 结束 {13}",
                                i + 1, g("fault:first-fail"), g("fault:confirmed"), g("cand:start"), g("cand:done"), smp.T.ContainsKey("cand:reused") ? "(复用)" : "",
                                g("switch:start"), g("switch:selected"), g("switch:exit-verified"), g("switch:path-verified"), g("switch:ready"), smp.Picked,
                                smp.Locked ? g("trip:locked") : "未触发", smp.Killed ? g("trip:killed") : "未结束"));
                        }
                        Func<string, IEnumerable<double>> col = k => samples.Where(x => x.T.ContainsKey(k)).Select(x => x.T[k]);
                        Check(label + "：全部 " + n + " 次都完成切换", samples.All(x => x.Ok && x.T.ContainsKey("switch:ready")), samples.Count(x => x.T.ContainsKey("switch:ready")) + "/" + n);
                        Check(label + "：节点故障从未误杀 Claude、未触发锁定", samples.All(x => !x.Killed && !x.Locked), "误杀 " + samples.Count(x => x.Killed) + " 次，锁定 " + samples.Count(x => x.Locked) + " 次");
                        Check(label + "：故障转移期间防直连静态规则未被改动", samples.All(x => !x.StaticTouched), null);
                        Check(label + "：只切换到日本节点", samples.All(x => x.Picked != null && x.Picked.Contains("Japan")), string.Join(",", samples.Select(x => x.Picked).Distinct()));
                        summary.Add(label + " | 首次发现 | " + Stat(col("fault:first-fail")));
                        summary.Add(label + " | 二次确认 | " + Stat(col("fault:confirmed")));
                        summary.Add(label + " | 开始切换 | " + Stat(col("switch:start")));
                        summary.Add(label + " | 切换完成（可用） | " + Stat(col("switch:ready")));
                        summary.Add(label + " | 故障转移本身（完成−确认） | " + Stat(samples.Where(x => x.T.ContainsKey("switch:ready") && x.T.ContainsKey("fault:confirmed")).Select(x => x.T["switch:ready"] - x.T["fault:confirmed"])));
                        Out("");
                    }
                }

                // 全部日本节点失败：安全阻断时间线
                Out("[全部日本节点断线 / 流水线] 共 " + n + " 次（记录网络阻断与 Claude 结束时刻）");
                var allS = new List<Sample>();
                for (int i = 0; i < n; i++)
                {
                    var st = BenchSettings();
                    foreach (var x in nodes) { x.Mode = FakeMode.Up; x.Country = x.Name.Contains("Korea") ? "KR" : x.Name.Contains("United") ? "US" : "JP"; }
                    m.Client().SelectProxy(st.JapanGroupName, J(1));
                    var tl = new Timeline();
                    var nm = new NodeManager(new MihomoNodeApi(() => m.Client(), st), st, tl);
                    var fw = new FakeFirewall(); var claude = new FakeClaude { Running = 1 };
                    var engine = new GuardEngine(st, fw, new FakeHealth { Next = f => FakeHealth.Safe() }, claude, new FakeNotifier());
                    engine.Startup(); engine.Evaluate(true); engine.Timeline = tl;
                    nm.OnAllFailed = r => engine.OnNodeOutage(r);
                    bool stop = false;
                    var ticker = new Thread(() => { while (!stop) { try { nm.Tick(); } catch { } Thread.Sleep(1000); } }) { IsBackground = true };
                    ticker.Start();
                    WaitFor(() => nm.Current == J(1) && nm.Status == NodeStatus.Healthy, 15000);
                    Thread.Sleep(rnd.Next(0, 3000));
                    var t0 = DateTime.Now;
                    foreach (var x in nodes.Where(x => x.Name.Contains("Japan"))) x.Mode = FakeMode.Down;
                    WaitFor(() => tl.First("trip:killed", t0).HasValue, 30000);
                    var smp = new Sample();
                    foreach (var k in new[] { "fault:first-fail", "fault:confirmed", "cand:start", "cand:done", "switch:all-failed", "trip:locked", "trip:killed" }) { var v = Rel(tl, k, t0); if (v.HasValue) smp.T[k] = v.Value; }
                    smp.Killed = claude.Running == 0;
                    allS.Add(smp);
                    var viaAll = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/all", 3000);
                    smp.Ok = viaAll == null || viaAll.StartsWith("HTTP5");
                    stop = true; ticker.Join(3000);
                    Func<string, string> g = k => smp.T.ContainsKey(k) ? ((int)smp.T[k]).ToString() : "-";
                    Out(string.Format("  #{0,2} 首次发现 {1} | 二次确认 {2} | 候选检测 {3}→{4} | 判定全部失败 {5} | 网络阻断 {6} | Claude 结束 {7} | 专用入口无回退 {8}",
                        i + 1, g("fault:first-fail"), g("fault:confirmed"), g("cand:start"), g("cand:done"), g("switch:all-failed"), g("trip:locked"), g("trip:killed"), smp.Ok ? "是" : "否"));
                }
                foreach (var x in nodes) x.Mode = FakeMode.Up;
                Func<string, IEnumerable<double>> colA = k => allS.Where(x => x.T.ContainsKey(k)).Select(x => x.T[k]);
                Check("全部失败：每次都先锁定后结束 Claude", allS.All(x => x.Killed && x.T.ContainsKey("trip:locked") && x.T["trip:locked"] <= x.T["trip:killed"]), null);
                Check("全部失败：专用入口从不回退直连/其他国家", allS.All(x => x.Ok), null);
                summary.Add("全部日本节点断线 | 首次发现 | " + Stat(colA("fault:first-fail")));
                summary.Add("全部日本节点断线 | 判定全部失败 | " + Stat(colA("switch:all-failed")));
                summary.Add("全部日本节点断线 | 网络阻断（锁定） | " + Stat(colA("trip:locked")));
                summary.Add("全部日本节点断线 | Claude 结束 | " + Stat(colA("trip:killed")));

                // 抖动：不能误杀 Claude
                Out("\n[网络抖动] 每种 40 秒，Claude 运行中，统计误杀/锁定/切换次数");
                foreach (var kind in new[] { "偶发失败（隔一次失败一次）", "延迟尖峰（100~450ms 随机）", "短暂断线（每 5 秒断 700ms）" })
                {
                    var st = BenchSettings();
                    foreach (var x in nodes) x.Mode = FakeMode.Up;
                    m.Client().SelectProxy(st.JapanGroupName, J(3));
                    var tl = new Timeline();
                    var nm = new NodeManager(new MihomoNodeApi(() => m.Client(), st), st, tl);
                    var fw = new FakeFirewall(); var claude = new FakeClaude { Running = 1 };
                    var engine = new GuardEngine(st, fw, new FakeHealth { Next = f => FakeHealth.Safe() }, claude, new FakeNotifier());
                    engine.Startup(); engine.Evaluate(true); engine.Timeline = tl;
                    int ops0 = fw.Ops.Count;
                    nm.OnAllFailed = r => engine.OnNodeOutage(r);
                    nm.VerifyClaudePath = cand => MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/verify", 5000) == cand;
                    bool stop = false, jit = true;
                    var ticker = new Thread(() => { while (!stop) { try { nm.Tick(); } catch { } Thread.Sleep(1000); } }) { IsBackground = true };
                    ticker.Start();
                    WaitFor(() => nm.Current == J(3) && nm.Status == NodeStatus.Healthy, 15000);
                    var j3 = nodes[2];
                    var jitter = new Thread(() =>
                    {
                        var r2 = new Random(7);
                        while (jit)
                        {
                            if (kind.StartsWith("偶发")) { j3.Mode = FakeMode.Alternate; Thread.Sleep(200); }
                            else if (kind.StartsWith("延迟")) { j3.Mode = FakeMode.Slow; j3.SlowMs = r2.Next(100, 450); Thread.Sleep(500); }
                            else { j3.Mode = FakeMode.Down; Thread.Sleep(700); j3.Mode = FakeMode.Up; Thread.Sleep(4300); }
                        }
                        j3.Mode = FakeMode.Up;
                    }) { IsBackground = true };
                    var t0 = DateTime.Now;
                    jitter.Start();
                    Thread.Sleep(40000);
                    jit = false; jitter.Join(); stop = true; ticker.Join(3000);
                    var switches = tl.Dump(500).Count(x => x.Contains("switch:ready"));
                    bool killed = claude.Running == 0, locked = fw.Ops.Skip(ops0).Contains("lock");
                    Out(string.Format("  {0}：探测 {1} 次，切换 {2} 次，锁定 {3}，误杀 Claude {4}，当前 {5}", kind, nm.ProbesLaunched, switches, locked ? "是" : "否", killed ? "是" : "否", nm.Current));
                    Check("抖动不误杀 Claude、不锁定：" + kind, !killed && !locked, null);
                    summary.Add("抖动·" + kind + " | 切换次数 | " + switches + " | 误杀 " + (killed ? "是" : "否") + " | 锁定 " + (locked ? "是" : "否"));
                    Thread.Sleep(3500);
                }
            }
            Out("\n==== 汇总（毫秒）：场景 | 阶段 | 次数 | 平均 | 最大 | P95 ====");
            foreach (var l in summary) Out("  " + l);
        }
    }
}
