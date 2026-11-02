// written_by: claude-code
// Japan Auto 节点管理与自动故障转移。
// 只操作 Japan Auto 组（select），绝不修改 GLOBAL 或其他组；组内只有日本节点，不存在 DIRECT/其他国家可选。
// 故障分级：
//   质量故障：延迟超过上限 / 偶发超时 —— 不是 IP 泄漏，按迟滞规则切换，不结束 Claude。
//   节点故障：连续失败达到阈值 / 节点被订阅删除 —— 立即切换（不受最短驻留限制）。
//   全部失败：无合格日本节点 —— 交给保护引擎阻断并关闭 Claude，每 N 秒重试，恢复后通知，等待手动启动。
// 防抖：失败计数、恢复需连续成功、切换冷却、最短驻留、故障节点隔离、切换状态锁；
//       当前节点健康时绝不因“别的节点更快”而切换。
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace ClaudeVPNGuard
{
    public interface INodeApi
    {
        List<string> GroupMembers(string group);   // null = 组不存在
        string GroupNow(string group);
        int Delay(string node, string url, int timeoutMs); // 毫秒，-1 失败
        void Select(string group, string node);
        string ExitCountry(out string ip);       // 经专用入口查询出口国家；失败返回 null
    }

    public class MihomoNodeApi : INodeApi
    {
        readonly Func<MihomoClient> client; readonly GuardSettings st;
        public MihomoNodeApi(Func<MihomoClient> c, GuardSettings s) { client = c; st = s; }
        MihomoClient C() { var c = client(); if (c == null) throw new InvalidOperationException("内核控制接口不可用"); return c; }
        public List<string> GroupMembers(string group)
        {
            var r = C().Request("GET", "/proxies/" + Uri.EscapeDataString(group));
            if (r.Status == 404) return null;
            if (r.Status != 200) throw new InvalidOperationException("读取组失败 HTTP " + r.Status);
            return Json.Arr(Json.Parse(r.Body), "all").Select(x => Convert.ToString(x)).ToList();
        }
        public string GroupNow(string group) { return Json.Str(C().GetJson("/proxies/" + Uri.EscapeDataString(group)), "now"); }
        public int Delay(string node, string url, int timeoutMs) { return C().Delay(node, url, timeoutMs); }
        public void Select(string group, string node) { C().SelectProxy(group, node); }
        public string ExitCountry(out string ip)
        {
            ip = null;
            try
            {
                var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(st.ExitTraceUrl);
                req.Proxy = new System.Net.WebProxy("http://127.0.0.1:" + st.DedicatedPort);
                req.Timeout = st.ProbeTimeoutMs + 2000; req.ReadWriteTimeout = st.ProbeTimeoutMs + 2000;
                using (var resp = req.GetResponse())
                using (var sr = new System.IO.StreamReader(resp.GetResponseStream()))
                {
                    string loc = null, line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (line.StartsWith("ip=")) ip = line.Substring(3);
                        if (line.StartsWith("loc=")) loc = line.Substring(4).Trim();
                    }
                    return loc;
                }
            }
            catch { return null; }
        }
    }

    public class NodeStat
    {
        public string Name;
        public int LastDelay = -1;
        public bool Healthy;
        public int ConsecFail, ConsecOk;
        public DateTime QuarantineUntil = DateTime.MinValue;
        public DateTime LastTest = DateTime.MinValue;
        public string LastError;
        public double AvgDelay;                              // 成功测速的平滑平均延迟（ms）
        public double FailRate;                              // 近期失败率（平滑，0~1）
        public DateTime LastFailAt = DateTime.MinValue;

        public void Sample(int d, DateTime now)
        {
            if (d > 0) AvgDelay = AvgDelay <= 0 ? d : AvgDelay * 0.7 + d * 0.3;
            FailRate = FailRate * 0.8 + (d > 0 ? 0 : 0.2);
            if (d <= 0) LastFailAt = now;
        }

        // 选节点用的综合分（越小越好）：平滑延迟 × 失败率惩罚，5 分钟内掉过线再加罚，避免只凭一次测速选中不稳的节点
        public double Score(DateTime now)
        {
            double delay = AvgDelay > 0 ? AvgDelay : (LastDelay > 0 ? LastDelay : 9999);
            double score = delay * (1 + 3 * FailRate);
            if ((now - LastFailAt).TotalMinutes < 5) score += 300;
            return score;
        }
    }

    public enum NodeStatus { Unknown, Healthy, Degraded, Switching, AllFailed, GroupMissing, Manual }

    // 故障响应时间线（毫秒精度），用于响应时间报告
    public class Timeline
    {
        readonly List<KeyValuePair<DateTime, string>> ev = new List<KeyValuePair<DateTime, string>>();
        public void Mark(string what) { lock (ev) { ev.Add(new KeyValuePair<DateTime, string>(DateTime.Now, what)); if (ev.Count > 500) ev.RemoveAt(0); } }
        public DateTime? First(string what, DateTime after)
        {
            lock (ev) { foreach (var e in ev) if ((e.Value == what || e.Value.StartsWith(what + " ")) && e.Key >= after) return e.Key; }
            return null;
        }
        public List<string> Dump(int n)
        {
            lock (ev) return ev.Skip(Math.Max(0, ev.Count - n)).Select(e => e.Key.ToString("HH:mm:ss.fff") + " " + e.Value).ToList();
        }
        public void Clear() { lock (ev) ev.Clear(); }
    }

    public class NodeManager
    {
        readonly INodeApi api;
        readonly GuardSettings st;
        readonly object gate = new object();
        public Func<DateTime> Now = () => DateTime.Now;
        public readonly Timeline Timeline;
        public readonly Dictionary<string, NodeStat> Stats = new Dictionary<string, NodeStat>();
        public NodeStatus Status = NodeStatus.Unknown;
        public string Current;
        public string LastSwitchReason;
        public int LastSwitchMs = -1;
        public DateTime LastSwitchAt = DateTime.MinValue;
        public DateTime NextRetryAt = DateTime.MinValue;
        public string LastExitIp, LastExitCountry;
        DateTime lastCurrentCheck = DateTime.MinValue, lastFullCheck = DateTime.MinValue, currentSince = DateTime.MinValue;
        int switching; // 切换状态锁（Interlocked）
        public Func<string, bool> VerifyClaudePath; // 由服务提供：经专用入口验证实际路径；参数为期望节点
        public Action<string> OnAllFailed;          // → 保护引擎：阻断并关闭 Claude
        public Action<string> OnRecovered;          // → 通知：已恢复，等待手动启动
        public Action<string> OnSecurityFault;      // → 保护引擎：组缺失/组内出现非日本节点
        bool wasAllFailed;

        // ===== 当前节点监控策略 =====
        // Sequential：V2.0 原始实现（按周期串行探测，失败后等下一个周期复检，确认后才测候选）——保留用于修改前后对比
        // Pipelined ：V2.1 每 LivenessIntervalMs 发起一次存活探测（最多 4 个并发，超时仍为 ProbeTimeoutMs，不缩短），
        //             结果按发起顺序处理；首次失败立即追加复检，并行预检其他日本节点；确认故障时直接复用预检结果
        public enum MonitorStrategy { Sequential, Pipelined }
        public MonitorStrategy Strategy = MonitorStrategy.Pipelined;
        readonly object probeLock = new object();
        long probeSeq, processedSeq;
        int inFlight;
        DateTime lastProbeLaunch = DateTime.MinValue;
        readonly SortedDictionary<long, KeyValuePair<string, int>> probeDone = new SortedDictionary<long, KeyValuePair<string, int>>();
        Task prefetch;
        DateTime prefetchAt = DateTime.MinValue;
        public int ProbesLaunched;

        public NodeManager(INodeApi a, GuardSettings s, Timeline t) { api = a; st = s; Timeline = t ?? new Timeline(); }

        Regex jpRe { get { return new Regex(st.JapanNameRegex, RegexOptions.IgnoreCase); } }
        Regex infoRe { get { return new Regex(st.InfoNodeRegex, RegexOptions.IgnoreCase); } }

        // REJECT 与汇总文件的占位节点（127.0.0.1:9，必然连接失败）都视为“拒绝”，不是候选，也不算非日本节点
        public static bool IsReject(string n) { return n == "REJECT" || n == Subscriptions.Placeholder; }

        // 节点名前缀 "[订阅名] " → 订阅名（汇总节点）；没有前缀返回 null
        public static string SubTag(string n)
        {
            if (n == null || !n.StartsWith("[")) return null;
            int e = n.IndexOf("] ", StringComparison.Ordinal);
            return e > 1 ? n.Substring(1, e - 1) : null;
        }

        public bool IsJapanName(string n)
        {
            if (st.JapanExclude.Contains(n)) return false;
            return st.JapanInclude.Contains(n) || (jpRe.IsMatch(n) && !infoRe.IsMatch(n));
        }

        NodeStat S(string n)
        {
            NodeStat s;
            if (!Stats.TryGetValue(n, out s)) { s = new NodeStat { Name = n }; Stats[n] = s; }
            return s;
        }

        // 读取组成员并做安全校验；返回可用候选（日本、未排除）
        List<string> Members(out bool security)
        {
            security = false;
            var m = api.GroupMembers(st.JapanGroupName);
            if (m == null)
            {
                Status = NodeStatus.GroupMissing;
                if (OnSecurityFault != null) OnSecurityFault("Clash 中不存在 " + st.JapanGroupName + " 组（覆写未套用：全局扩展脚本缺少本程序段，或改写后 Clash 尚未刷新）");
                security = true;
                return new List<string>();
            }
            var bad = m.Where(n => !NodeManager.IsReject(n) && !IsJapanName(n) && !st.JapanExclude.Contains(n)).ToList();
            if (bad.Count > 0)
            {
                security = true;
                if (OnSecurityFault != null) OnSecurityFault(st.JapanGroupName + " 组内出现非日本节点：" + string.Join("、", bad.Take(3)));
            }
            foreach (var gone in Stats.Keys.Where(k => !m.Contains(k)).ToList()) Stats.Remove(gone);
            return m.Where(n => !NodeManager.IsReject(n) && IsJapanName(n)).ToList();
        }

        bool TestNode(string n) { return Record(n, api.Delay(n, st.NodeTestUrl, st.ProbeTimeoutMs)); }

        // 记录一次探测结果（d = 毫秒，-1 = 超时/失败）
        bool Record(string n, int d)
        {
            var s = S(n);
            s.LastTest = Now();
            s.LastDelay = d;
            s.Sample(d, s.LastTest);
            bool ok = d > 0 && d <= st.MaxDelayMs;
            if (ok) { s.ConsecOk++; s.ConsecFail = 0; s.LastError = null; }
            else { s.ConsecFail++; s.ConsecOk = 0; s.LastError = d < 0 ? "超时/失败" : "延迟 " + d + "ms 超过上限 " + st.MaxDelayMs + "ms"; }
            // 隔离中的节点需连续成功 RecoverThreshold 次才解除
            if (s.QuarantineUntil > Now() && s.ConsecOk >= st.RecoverThreshold && Now() >= s.QuarantineUntil) s.QuarantineUntil = DateTime.MinValue;
            s.Healthy = ok && (s.QuarantineUntil <= Now() || s.ConsecOk >= st.RecoverThreshold);
            return ok;
        }

        void TestAll(List<string> names)
        {
            var tasks = names.Select(n => Task.Factory.StartNew(() => { try { TestNode(n); } catch { } }, TaskCreationOptions.LongRunning)).ToArray();
            Task.WaitAll(tasks, st.ProbeTimeoutMs + 3000);
        }

        // 内核退出/重启期间暂停节点判定：探测失败是因为内核不在，不是节点坏了（2026-11-01 实机：内核崩溃时误触发一次节点切换）
        public DateTime SuspendUntil = DateTime.MinValue;
        public void Suspend(int seconds, string why)
        {
            SuspendUntil = Now().AddSeconds(seconds);
            lock (probeLock) { probeDone.Clear(); processedSeq = probeSeq; }
            foreach (var s in Stats.Values) { s.ConsecFail = 0; }
            Timeline.Mark("node:suspend " + why);
        }

        // 每秒调用一次
        public void Tick()
        {
            if (Interlocked.CompareExchange(ref switching, 0, 0) != 0) return;
            if (Now() < SuspendUntil) return;
            lock (gate)
            {
                var now = Now();
                bool sec;
                List<string> cands;
                try { cands = Members(out sec); }
                catch (Exception ex) { Status = NodeStatus.Unknown; LastSwitchReason = "无法读取 " + st.JapanGroupName + "：" + ex.Message; return; }
                if (Status == NodeStatus.GroupMissing) return;

                string now0 = null;
                try { now0 = api.GroupNow(st.JapanGroupName); } catch { }
                if (now0 != Current) { Current = now0; currentSince = now; }

                // 全部失败状态：按重试间隔重新检测
                if (Status == NodeStatus.AllFailed)
                {
                    if (now < NextRetryAt) return;
                    Failover("全部失败后的定时重试", true);
                    return;
                }
                // 当前节点被订阅更新删除 / 不是日本节点 / 是 REJECT
                if (Current == null || !cands.Contains(Current))
                {
                    Timeline.Mark("fault:current-missing");
                    Failover(Current == null || NodeManager.IsReject(Current) ? "Japan Auto 无可用当前节点" : "当前节点 " + Current + " 已不在日本节点列表（订阅更新/被排除）", true);
                    return;
                }
                if ((now - lastFullCheck).TotalSeconds >= st.HealthIntervalSec)
                {
                    lastFullCheck = now;
                    TestAll(cands.Where(c => c != Current).ToList());
                }
                if (Strategy == MonitorStrategy.Pipelined) { LaunchProbe(false); return; }
                if ((now - lastCurrentCheck).TotalSeconds >= st.CurrentNodeCheckSec)
                {
                    lastCurrentCheck = now;
                    var ok = TestNode(Current);
                    Evaluate(Current, ok);
                }
            }
        }

        // 对当前节点一次探测结果做判定（两种策略共用）
        void Evaluate(string node, bool ok)
        {
            var now = Now();
            var s = S(node);
            if (ok) { if (Status != NodeStatus.AllFailed) Status = st.AutoSwitch ? NodeStatus.Healthy : NodeStatus.Manual; return; }
            Status = NodeStatus.Degraded;
            if (s.ConsecFail == 1)
            {
                Timeline.Mark("fault:first-fail " + node);
                if (Strategy == MonitorStrategy.Pipelined)
                {
                    LaunchProbe(true);      // 立即复检（不等下一个周期）
                    StartPrefetch(node);     // 同时并行预检其他日本节点
                }
            }
            if (s.ConsecFail < st.FailThreshold) return;
            if (!st.AutoSwitch) { LastSwitchReason = "自动切换已关闭：当前节点 " + node + " 不健康（" + s.LastError + "）"; return; }
            bool hard = s.LastDelay < 0;
            if (!hard)
            {
                // 质量故障：受最短驻留与冷却限制
                if ((now - currentSince).TotalSeconds < st.MinDwellSec || (now - LastSwitchAt).TotalSeconds < st.SwitchCooldownSec) return;
            }
            Timeline.Mark("fault:confirmed " + node);
            Failover((hard ? "节点故障：" : "质量故障：") + node + " 连续 " + s.ConsecFail + " 次失败（" + s.LastError + "）", hard);
        }

        // 流水线：按 LivenessIntervalMs 发起探测；force=首次失败后的立即复检
        void LaunchProbe(bool force)
        {
            var node = Current;
            if (node == null) return;
            lock (probeLock)
            {
                if (!force && (Now() - lastProbeLaunch).TotalMilliseconds < st.LivenessIntervalMs - 50) return;
                if (inFlight >= 4) return;
                inFlight++;
                lastProbeLaunch = Now();
            }
            long seq = Interlocked.Increment(ref probeSeq);
            Interlocked.Increment(ref ProbesLaunched);
            Task.Factory.StartNew(() =>
            {
                int d = -1;
                try { d = api.Delay(node, st.NodeLivenessUrl, st.ProbeTimeoutMs); } catch { }
                lock (probeLock) { inFlight--; probeDone[seq] = new KeyValuePair<string, int>(node, d); }
                ProcessProbes();
            }, TaskCreationOptions.LongRunning);
        }

        // 按发起顺序处理已完成的探测，保证“连续失败”的语义正确
        void ProcessProbes()
        {
            if (Interlocked.CompareExchange(ref switching, 0, 0) != 0) return;
            lock (probeLock)
            {
                // 暂停期间与暂停前发起的探测结果一律丢弃
                foreach (var k in probeDone.Keys.Where(k => k <= processedSeq).ToList()) probeDone.Remove(k);
                if (Now() < SuspendUntil) { probeDone.Clear(); processedSeq = Math.Max(processedSeq, probeSeq); return; }
            }
            lock (gate)
            {
                while (true)
                {
                    KeyValuePair<string, int> r;
                    lock (probeLock)
                    {
                        if (!probeDone.TryGetValue(processedSeq + 1, out r)) return;
                        probeDone.Remove(processedSeq + 1);
                        processedSeq++;
                    }
                    if (r.Key != Current || Status == NodeStatus.Switching || Status == NodeStatus.AllFailed) continue; // 已切走的旧节点结果丢弃
                    bool ok = Record(r.Key, r.Value);
                    Evaluate(r.Key, ok);
                    if (Interlocked.CompareExchange(ref switching, 0, 0) != 0) return;
                }
            }
        }

        void StartPrefetch(string failing)
        {
            if (prefetch != null && !prefetch.IsCompleted) return;
            List<string> others;
            bool sec;
            try { others = Members(out sec).Where(c => c != failing && S(c).QuarantineUntil <= Now()).ToList(); } catch { return; }
            Timeline.Mark("cand:start");
            prefetchAt = Now();
            prefetch = Task.Factory.StartNew(() => { TestAll(others); Timeline.Mark("cand:done"); }, TaskCreationOptions.LongRunning);
        }

        // 故障转移：隔离当前节点 → 并行测试其余日本节点 → 按延迟选择 → 切换 → 验证出口国家 → 验证 Claude 实际路径
        public bool Failover(string reason, bool hard)
        {
            if (Interlocked.CompareExchange(ref switching, 1, 0) != 0) return false;
            var t0 = Now();
            try
            {
                Timeline.Mark("switch:start");
                Status = NodeStatus.Switching;
                Log.Warn("开始日本节点故障转移：" + reason);
                bool sec;
                var cands = Members(out sec);
                if (Current != null && cands.Contains(Current) && reason.IndexOf("定时重试", StringComparison.Ordinal) < 0)
                    // 质量故障（只是慢）短隔离 60 秒；断线/超时才按 QuarantineSec 隔离
                    S(Current).QuarantineUntil = Now().AddSeconds(hard ? st.QuarantineSec : Math.Min(60, st.QuarantineSec));
                var pool = cands.Where(c => S(c).QuarantineUntil <= Now() || reason.Contains("定时重试")).ToList();
                if (prefetch != null && (Now() - prefetchAt).TotalSeconds < 20 && !reason.Contains("定时重试"))
                {
                    // 复用首次失败时并行发起的候选检测（未完成则等待其结束，最多一个探测超时）
                    prefetch.Wait(st.ProbeTimeoutMs + 3000);
                    Timeline.Mark("cand:reused");
                    var untested = pool.Where(c => (Now() - S(c).LastTest).TotalSeconds > 20).ToList();
                    if (untested.Count > 0) TestAll(untested);
                }
                else
                {
                    Timeline.Mark("cand:start");
                    TestAll(pool);
                    Timeline.Mark("cand:done");
                }
                var ranked = pool.Where(c => S(c).LastDelay > 0 && S(c).LastDelay <= st.MaxDelayMs)
                                 .OrderBy(c => S(c).Score(Now())).ToList();
                if (ranked.Count > 1) Log.Info("候选节点排序（综合分）：" + string.Join("、", ranked.Take(5).Select(c => c + "=" + (int)S(c).Score(Now()))));
                if (ranked.Count == 0)
                {
                    // 判定“全部失败”前，把隔离中的节点也实测一遍（2026-11-01 实机：节点都在隔离期，4ms 内误判全部失败）
                    var quarantined = cands.Where(c => !pool.Contains(c) && c != Current).ToList();
                    if (quarantined.Count > 0)
                    {
                        Timeline.Mark("cand:retest-quarantined");
                        TestAll(quarantined);
                        ranked = quarantined.Where(c => S(c).LastDelay > 0 && S(c).LastDelay <= st.MaxDelayMs).OrderBy(c => S(c).Score(Now())).ToList();
                        if (ranked.Count > 0) Log.Warn("非隔离节点均不合格，改用实测通过的隔离中节点：" + string.Join("、", ranked));
                    }
                }
                foreach (var cand in ranked)
                {
                    try
                    {
                        api.Select(st.JapanGroupName, cand);
                        Timeline.Mark("switch:selected " + cand);
                        string ip;
                        var country = api.ExitCountry(out ip);
                        if (!string.Equals(country, st.ExpectedExitCountry, StringComparison.OrdinalIgnoreCase))
                        {
                            S(cand).QuarantineUntil = Now().AddSeconds(st.QuarantineSec);
                            S(cand).LastError = "出口国家校验失败：" + (country ?? "无法获取");
                            Log.Warn("候选节点 " + cand + " 出口校验失败：" + (country ?? "无法获取"));
                            continue;
                        }
                        LastExitIp = ip; LastExitCountry = country;
                        Timeline.Mark("switch:exit-verified " + cand);
                        if (VerifyClaudePath != null && !VerifyClaudePath(cand))
                        {
                            S(cand).QuarantineUntil = Now().AddSeconds(st.QuarantineSec);
                            S(cand).LastError = "Claude 路径验证失败";
                            continue;
                        }
                        Timeline.Mark("switch:path-verified " + cand);
                        var prev = Current;
                        Current = cand; currentSince = Now();
                        LastSwitchAt = Now();
                        LastSwitchMs = (int)(Now() - t0).TotalMilliseconds;
                        LastSwitchReason = reason + " → 已切换到 " + cand + "（" + S(cand).LastDelay + "ms，出口 " + country + "）";
                        S(cand).ConsecFail = 0;
                        Status = st.AutoSwitch ? NodeStatus.Healthy : NodeStatus.Manual;
                        Timeline.Mark("switch:ready " + cand);
                        prefetch = null;
                        Log.Action("节点切换完成：" + (prev ?? "无") + " → " + cand + "，耗时 " + LastSwitchMs + "ms；原因：" + reason);
                        if (wasAllFailed)
                        {
                            wasAllFailed = false;
                            if (OnRecovered != null) OnRecovered("日本节点已恢复：" + cand + "。请手动启动 Claude。");
                        }
                        return true;
                    }
                    catch (Exception ex) { S(cand).LastError = ex.Message; }
                }
                // 全部失败：不回退 DIRECT、不使用其他国家
                Status = NodeStatus.AllFailed;
                NextRetryAt = Now().AddSeconds(st.AllFailRetrySec);
                LastSwitchReason = reason + " → 没有合格的日本节点，保持阻断，" + st.AllFailRetrySec + " 秒后重试";
                Timeline.Mark("switch:all-failed");
                Log.Error(LastSwitchReason);
                if (!wasAllFailed)
                {
                    wasAllFailed = true;
                    if (OnAllFailed != null) OnAllFailed("全部日本节点不可用（" + reason + "）");
                }
                return false;
            }
            finally { Interlocked.Exchange(ref switching, 0); }
        }

        // GUI 手动选择节点：必须是日本节点并通过同样的验证
        public string ManualSelect(string node)
        {
            lock (gate)
            {
                bool sec;
                var cands = Members(out sec);
                if (!cands.Contains(node)) return node + " 不是 " + st.JapanGroupName + " 中的日本节点";
                if (!TestNode(node)) return node + " 测试未通过：" + S(node).LastError;
                var prevAuto = st.AutoSwitch;
                api.Select(st.JapanGroupName, node);
                string ip;
                var c = api.ExitCountry(out ip);
                if (!string.Equals(c, st.ExpectedExitCountry, StringComparison.OrdinalIgnoreCase)) return node + " 出口国家校验失败：" + (c ?? "无法获取");
                if (VerifyClaudePath != null && !VerifyClaudePath(node)) return node + " Claude 路径验证失败";
                Current = node; currentSince = Now(); LastSwitchAt = Now();
                LastExitIp = ip; LastExitCountry = c;
                LastSwitchReason = "手动选择 " + node;
                Log.Action("手动切换日本节点：" + node);
                return null;
            }
        }

        // 候选范围变化（订阅启用/停用）后：下一轮立即重测全部候选；当前节点若已移出组会自动切走
        public void ForceRecheck() { lastFullCheck = DateTime.MinValue; }

        public void TestAllNow()
        {
            bool sec;
            List<string> c;
            lock (gate) c = Members(out sec);
            TestAll(c);
        }

        public List<Dictionary<string, object>> Snapshot()
        {
            lock (gate)
            {
                return Stats.Values.OrderBy(s => s.Name).Select(s => new Dictionary<string, object>
                {
                    { "name", s.Name }, { "sub", SubTag(s.Name) }, { "delay", s.LastDelay }, { "healthy", s.Healthy }, { "fails", s.ConsecFail }, { "oks", s.ConsecOk },
                    { "quarantined", s.QuarantineUntil > Now() }, { "current", s.Name == Current }, { "error", s.LastError }
                }).ToList();
            }
        }
    }
}
