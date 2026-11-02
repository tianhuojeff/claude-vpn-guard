// written_by: claude-code
// 单元测试（无第三方框架）：地址计算、配置解析、HTTP 解析、出站链解析、保护状态机（含动作顺序）。
// 运行：dist\ClaudeVPNGuard.Tests.exe  —— 返回码 0 = 全部通过
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace ClaudeVPNGuard
{
    class FakeFirewall : IFirewall
    {
        public bool Lock = false, ThrowOnLock = false, Enabled = true;
        public List<string> Ops = new List<string>();
        public bool AllProfilesEnabled(out string d) { d = Enabled ? "ok" : "off"; return Enabled; }
        public void EnsureRules(IList<string> exe, string fake, bool lockEnabled) { Ops.Add("ensure:" + exe.Count + ":" + lockEnabled); Lock = lockEnabled; }
        public void SetLock(bool on) { if (ThrowOnLock) throw new Exception("COM 失败"); Ops.Add(on ? "lock" : "unlock"); Lock = on; }
        public bool VerifyRules(IList<string> e, string f, bool x, out string d) { d = "ok"; return true; }
        public int RemoveAll() { return 0; }
    }

    class FakeHealth : IHealthChecker
    {
        public Func<bool, HealthReport> Next;
        public HealthReport Run(bool full, IList<string> exe) { return Next(full); }
        public static HealthReport Safe() { var r = new HealthReport(); r.Add("core", "内核", true, true, "ok"); return r; }
        public static HealthReport Fail(string id, string detail) { var r = new HealthReport(); r.Add(id, id, false, true, detail); return r; }
    }

    class FakeClaude : IClaudeControl
    {
        public int Running = 0;
        public List<string> Log = new List<string>();
        public List<string> DiscoverExecutables() { return new List<string> { @"C:\Program Files\WindowsApps\AnthropicPBC.Claude_1_x64__abc\app\claude.exe" }; }
        public int RunningCount() { return Running; }
        public int[] KillAll() { Log.Add("kill"); int n = Running; Running = 0; return new[] { n, 0 }; }
        public string LaunchTarget() { return null; }
    }

    class FakeNotifier : INotifier { public List<string> Msgs = new List<string>(); public void Notify(string t, string m) { Msgs.Add(m); } }

    static class TestMain
    {
        static int pass, fail;
        static void Check(string name, bool cond, string info = null)
        {
            if (cond) pass++; else fail++;
            Console.WriteLine((cond ? "  [通过] " : "  [失败] ") + name + (cond || info == null ? "" : "  → " + info));
        }

        static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            if (args.Length > 0 && args[0] == "--lab") return Lab.Run(args);
            var tmp = Path.Combine(Path.GetTempPath(), "cvg-test-" + Guid.NewGuid().ToString("N"));
            GuardPaths.DataDirOverride = tmp;
            Log.Dir = Path.Combine(tmp, "logs");
            try
            {
                Console.WriteLine("地址计算");
                var v4 = AddrMath.Complement(4, new[] { "127.0.0.0/8", "198.18.0.0/15" });
                Check("IPv4 补集 = 0.0.0.0-126.255.255.255, 128.0.0.0-198.17.255.255, 198.20.0.0-255.255.255.255",
                    string.Join(",", v4) == "0.0.0.0-126.255.255.255,128.0.0.0-198.17.255.255,198.20.0.0-255.255.255.255", string.Join(",", v4));
                var v6 = AddrMath.Complement(6, new[] { "::1/128" });
                Check("IPv6 补集排除 ::1", string.Join(",", v6) == "::-::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", string.Join(",", v6));
                Check("fake-ip 198.18.0.1/16 也能正确规整", string.Join(",", AddrMath.Complement(4, new[] { "198.18.0.1/16" })) == "0.0.0.0-198.17.255.255,198.19.0.0-255.255.255.255");
                Check("允许 127.0.0.1", AddrMath.IsAllowedDestination(IPAddress.Parse("127.0.0.1"), "198.18.0.0/15"));
                Check("允许 ::1", AddrMath.IsAllowedDestination(IPAddress.IPv6Loopback, "198.18.0.0/15"));
                Check("允许 fake-ip 198.19.3.4", AddrMath.IsAllowedDestination(IPAddress.Parse("198.19.3.4"), "198.18.0.0/15"));
                Check("拒绝 公网 160.79.104.10", !AddrMath.IsAllowedDestination(IPAddress.Parse("160.79.104.10"), "198.18.0.0/15"));
                Check("拒绝 IPv6 公网", !AddrMath.IsAllowedDestination(IPAddress.Parse("2607:6bc0::10"), "198.18.0.0/15"));
                Check("拒绝 IPv4 映射的公网 ::ffff:1.2.3.4", !AddrMath.IsAllowedDestination(IPAddress.Parse("::ffff:1.2.3.4"), "198.18.0.0/15"));
                Check("拒绝 局域网 192.168.1.1", !AddrMath.IsAllowedDestination(IPAddress.Parse("192.168.1.1"), "198.18.0.0/15"));

                Console.WriteLine("配置解析");
                var y = "mode: global\nmixed-port: 7897\nexternal-controller: ''\nsecret: 'abc 123'\nexternal-controller-pipe: \\\\.\\pipe\\verge-mihomo-x\ndns:\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n";
                var vc = VergeConfigInfo.ParseYaml(y, "t");
                Check("secret 去引号", vc.Secret == "abc 123");
                Check("空 external-controller", vc.ExternalController == "");
                Check("管道名", vc.ControllerPipe == @"\\.\pipe\verge-mihomo-x");
                Check("fake-ip-range", vc.FakeIpRange == "198.18.0.1/16");
                Check("mixed-port", vc.MixedPort == 7897);
                Check("日志脱敏 Bearer", !Log.Redact("Authorization: Bearer s3cr3t").Contains("s3cr3t"));
                Check("日志脱敏 uuid", !Log.Redact("vless://0b5f1c7e-1234-4abc-9def-001122334455@x").Contains("0b5f1c7e"));
                var st = new GuardSettings();
                Check("域名匹配 api.anthropic.com", st.IsClaudeHost("api.anthropic.com"));
                Check("域名不误匹配 notanthropic.com", !st.IsClaudeHost("notanthropic.com"));
                Check("系统代理指向内核端口", HealthChecker.PointsToLocalPort("127.0.0.1:7897", 7897) && HealthChecker.PointsToLocalPort("http=127.0.0.1:7897;https=127.0.0.1:7897", 7897));
                Check("系统代理端口不符", !HealthChecker.PointsToLocalPort("127.0.0.1:8080", 7897));

                Console.WriteLine("HTTP 解析");
                var h1 = MiniHttp.Parse(Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
                Check("普通响应", h1.Status == 200 && h1.Body == "hello");
                var h2 = MiniHttp.Parse(Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"));
                Check("chunked 响应", h2.Body == "hello world", h2.Body);
                var h3 = MiniHttp.Parse(Encoding.UTF8.GetBytes("HTTP/1.0 401 Unauthorized\r\n\r\n"));
                Check("401", h3.Status == 401);

                Console.WriteLine("出站链解析");
                var px = new Dictionary<string, ProxyInfo>
                {
                    { "GLOBAL", new ProxyInfo { Name = "GLOBAL", Type = "Selector", Now = "自动选择" } },
                    { "自动选择", new ProxyInfo { Name = "自动选择", Type = "URLTest", Now = "JP 03" } },
                    { "JP 03", new ProxyInfo { Name = "JP 03", Type = "Vless" } },
                    { "DIRECT", new ProxyInfo { Name = "DIRECT", Type = "Direct" } },
                    { "LOOP", new ProxyInfo { Name = "LOOP", Type = "Selector", Now = "LOOP" } },
                };
                List<string> path;
                var leaf = MihomoClient.ResolveLeaf(px, "GLOBAL", out path);
                Check("GLOBAL → 自动选择 → JP 03", leaf != null && leaf.Name == "JP 03" && path.Count == 3);
                px["GLOBAL"].Now = "DIRECT";
                leaf = MihomoClient.ResolveLeaf(px, "GLOBAL", out path);
                Check("GLOBAL → DIRECT 识别为直连", leaf != null && MihomoClient.IsDirectType(leaf.Type));
                Check("环形组 → 不可信(null)", MihomoClient.ResolveLeaf(px, "LOOP", out path) == null);

                Console.WriteLine("保护状态机");
                EngineTests();

                V2Tests.Run((n, ok, info) => Check(n, ok, info), tmp);

                Console.WriteLine("本地通信鉴权（真实命名管道）");
                GuardPaths.PipeName = "ClaudeVPNGuard.test-" + Guid.NewGuid().ToString("N");
                var srv = new IpcServer((req, trusted) =>
                    req.Cmd == "status" ? new IpcResponse { Ok = true, Data = "st" } :
                    trusted ? new IpcResponse { Ok = true } : new IpcResponse { Ok = false, Error = "未授权" })
                { TrustedClientExe = @"C:\Program Files\ClaudeVPNGuard\ClaudeVPNGuard.exe" };
                srv.Start();
                System.Threading.Thread.Sleep(300);
                object stv = null;
                try { stv = IpcClient.Call("status", null, 3000); } catch (Exception ex) { stv = ex.Message; }
                Check("任意本地进程可读状态", Equals(stv, "st"), Convert.ToString(stv));
                string denied = null;
                try { IpcClient.Call("preparelaunch", null, 3000); } catch (Exception ex) { denied = ex.Message; }
                Check("非安装目录 GUI 调用解锁命令 → 拒绝", denied == "未授权", denied);
                srv.Stop();
            }
            finally { try { Directory.Delete(tmp, true); } catch { } }
            Console.WriteLine(string.Format("\n合计：通过 {0}，失败 {1}", pass, fail));
            return fail == 0 ? 0 : 1;
        }

        static GuardEngine NewEngine(out FakeFirewall fw, out FakeHealth h, out FakeClaude c, out FakeNotifier n)
        {
            fw = new FakeFirewall(); h = new FakeHealth(); c = new FakeClaude(); n = new FakeNotifier();
            try { File.Delete(GuardPaths.StateFile); } catch { }
            var e = new GuardEngine(new GuardSettings(), fw, h, c, n);
            e.Startup();
            return e;
        }

        static void EngineTests()
        {
            FakeFirewall fw; FakeHealth h; FakeClaude c; FakeNotifier n;
            var e = NewEngine(out fw, out h, out c, out n);
            Check("启动即锁定（默认拒绝）", fw.Lock && e.Locked && e.State == GuardState.Verifying);
            Check("启动时规则以锁定状态创建", fw.Ops.First() == "ensure:1:True");

            h.Next = full => FakeHealth.Safe();
            e.Evaluate(true);
            Check("检测通过 → 解锁 → 已保护", !fw.Lock && e.State == GuardState.Protected);

            // 代理崩溃，Claude 运行中 → 先锁后杀再通知
            c.Running = 3;
            var order = new List<string>();
            e.AfterTripHook = s => order.Add(s + (s == "lock" ? (fw.Lock ? "+" : "-") : ""));
            h.Next = full => FakeHealth.Fail("core", "控制接口不可用");
            e.Evaluate(false);
            Check("异常 → 顺序：锁定网络 → 结束进程 → 通知", string.Join(",", order) == "lock+,kill,notify", string.Join(",", order));
            Check("异常后状态 = Claude 已阻断，且锁定", e.State == GuardState.Tripped && fw.Lock && c.Running == 0);
            Check("通知文案", n.Msgs.Count == 1 && n.Msgs[0].StartsWith("代理连接异常，Claude 已被保护性关闭，当前网络访问已阻断。"));
            Check("触发标记已持久化", File.ReadAllText(GuardPaths.StateFile).Contains("\"tripped\":true"));

            // 代理恢复：需手动启动，不自动解锁
            h.Next = full => FakeHealth.Safe();
            e.Evaluate(true);
            Check("代理恢复后保持锁定（等待用户手动启动）", fw.Lock && e.State == GuardState.Tripped);
            Check("不会自动重新打开 Claude", c.Running == 0);
            Check("手动启动：完整检测通过 → 允许", e.PrepareLaunch() == null && !fw.Lock && e.State == GuardState.Protected);

            // 服务重启后仍记得 tripped
            var e2 = NewEngine(out fw, out h, out c, out n);
            File.WriteAllText(GuardPaths.StateFile, "{\"tripped\":true}");
            e2 = new GuardEngine(new GuardSettings(), fw, h, c, n); e2.Startup();
            h.Next = full => FakeHealth.Safe();
            e2.Evaluate(true);
            Check("保护性关闭后重启服务，仍需手动解锁", fw.Lock);

            // 隔离模式：全部日本节点暂不可用 → 只暂停联网，不关闭 Claude；探测持续失败也不关；恢复后自动解锁
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            c.Running = 4;
            e.OnNodePause("全部日本节点不可用");
            Check("节点全挂 → 锁定网络但不结束 Claude", fw.Lock && c.Running == 4 && !c.Log.Contains("kill") && e.NodePaused);
            h.Next = full => FakeHealth.Fail("probe", "经代理 TLS 握手失败");
            e.Evaluate(false); e.Evaluate(false); e.Evaluate(false);
            Check("暂停期间探测连续失败 → 仍不关闭 Claude", c.Running == 4 && fw.Lock && e.State != GuardState.Tripped);
            h.Next = full => FakeHealth.Fail("mode", "直连模式（DIRECT）");
            e.Evaluate(false);
            Check("暂停期间出现真正的泄漏风险 → 照常保护性关闭", c.Running == 0 && e.State == GuardState.Tripped);
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            c.Running = 2; e.OnNodePause("x");
            e.OnNodeResumed("JP 03 已恢复");
            e.Evaluate(true);
            Check("节点恢复 → 复检通过自动解锁，Claude 继续运行", !fw.Lock && e.State == GuardState.Protected && c.Running == 2 && !e.NodePaused);

            // 隔离模式：Clash Verge 重启导致内核退出 → 暂停不关闭；内核未起来期间不关；新内核检测通过自动恢复
            NewEngine(out fw, out h, out c, out n);
            var stIso = new GuardSettings(); stIso.IsolationMode = true;
            e = new GuardEngine(stIso, fw, h, c, n); e.Startup();
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            c.Running = 3;
            e.OnCoreExited("pid 1");
            Check("隔离模式内核退出 → 锁定但不结束 Claude", fw.Lock && c.Running == 3 && e.NodePaused && e.State != GuardState.Tripped);
            h.Next = full => FakeHealth.Fail("core", "控制接口不可用");
            e.Evaluate(true); e.Evaluate(true); e.Evaluate(true);
            Check("等新内核期间内核/入口不可用 → 仍不关闭 Claude", c.Running == 3 && fw.Lock && e.State != GuardState.Tripped);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            Check("新内核检测通过 → 自动恢复联网", !fw.Lock && e.State == GuardState.Protected && c.Running == 3 && !e.NodePaused);

            // 启动前检测失败 → 拒绝
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Fail("mode", "直连模式（DIRECT）→ 立即阻断");
            Check("启动前检测失败 → 拒绝并保持锁定", e.PrepareLaunch() != null && fw.Lock);

            // Claude 未运行时异常 → 只锁定，状态=代理异常
            h.Next = full => FakeHealth.Fail("core", "x");
            e.Evaluate(false);
            Check("Claude 未运行时异常 → 锁定，状态 = 代理异常", fw.Lock && e.State == GuardState.Blocked && c.Log.Count == 0);

            // 抖动：仅探测失败，第一次只锁不杀，第二次关闭
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            c.Running = 2;
            h.Next = full => FakeHealth.Fail("probe", "TLS 超时");
            e.Evaluate(true);
            Check("单次探测失败 → 立即锁定但不杀进程", fw.Lock && c.Running == 2 && e.WantsFastRecheck);
            e.Evaluate(true);
            Check("连续第二次 → 保护性关闭", c.Running == 0 && e.State == GuardState.Tripped);

            // 确定性故障（DIRECT）第一次即关闭
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            c.Running = 1;
            h.Next = full => { var r = FakeHealth.Fail("audit", "api.anthropic.com 经 DIRECT 直连"); return r; };
            e.Evaluate(false);
            Check("连接走 DIRECT → 第一次即关闭", c.Running == 0 && e.State == GuardState.Tripped);

            // 网络切换 → 锁定待验证
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            e.OnEnvironmentChanged("Wi-Fi 重连");
            Check("网络切换 → 重新验证前锁定", fw.Lock && e.State == GuardState.Verifying);
            e.Evaluate(true);
            Check("重新验证通过 → 解锁", !fw.Lock && e.State == GuardState.Protected);

            // 锁定失败 → 绝不假定放开
            e = NewEngine(out fw, out h, out c, out n);
            fw.ThrowOnLock = true;
            h.Next = full => FakeHealth.Fail("core", "x");
            e.Evaluate(false);
            Check("设置锁定失败 → 视为锁定 + 防火墙异常", e.Locked && e.State == GuardState.FirewallError);

            // 检测器自身抛异常 → 不可信
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            h.Next = full => { throw new InvalidOperationException("boom"); };
            e.Evaluate(false);
            Check("检测器异常 → 锁定（故障安全）", fw.Lock);

            // 保护未通过时 Claude 启动 → 被结束
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Fail("core", "x"); e.Evaluate(false);
            c.Running = 1;
            e.OnClaudeProcessStarted(@"C:\Program Files\WindowsApps\AnthropicPBC.Claude_1_x64__abc\app\claude.exe", 999999);
            Check("保护未通过时启动 Claude → 立即结束 + 通知", c.Running == 0 && n.Msgs.Any(m => m.Contains("已阻止 Claude 启动")));
            // 检测中（网络切换）启动 → 不杀，请求立即复检
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            e.OnEnvironmentChanged("Wi-Fi 重连");
            bool rechecked = false; e.RequestRecheck = () => rechecked = true;
            c.Running = 1;
            e.OnClaudeProcessStarted(@"C:\Program Files\WindowsApps\AnthropicPBC.Claude_1_x64__abc\app\claude.exe", 999999);
            Check("检测中启动 Claude → 保持锁定、不误杀、立即复检", c.Running == 1 && fw.Lock && rechecked);
            // 已保护时启动 → 放行
            e = NewEngine(out fw, out h, out c, out n);
            h.Next = full => FakeHealth.Safe(); e.Evaluate(true);
            c.Running = 1;
            e.OnClaudeProcessStarted(@"C:\Program Files\WindowsApps\AnthropicPBC.Claude_1_x64__abc\app\claude.exe", 999999);
            Check("已保护时启动 Claude → 放行", c.Running == 1);
        }
    }
}
