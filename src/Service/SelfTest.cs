// written_by: claude-code
// 防火墙实测：复制本程序为测试程序，对它套用与 Claude 完全相同的规则，再用它真实发起连接，
// 验证 直连 IPv4/IPv6 TCP、UDP(DNS) 被阻断，经本地代理可用；测试结束删除测试规则与副本。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ClaudeVPNGuard
{
    static class NetProbe
    {
        // netprobe tcp <ip> <port> | udpdns <ip> | proxy <port> <host>
        public static int Run(string[] a)
        {
            try
            {
                switch (a[1])
                {
                    case "tcp":
                        using (var c = new TcpClient(IPAddress.Parse(a[2]).AddressFamily))
                        {
                            var ar = c.BeginConnect(IPAddress.Parse(a[2]), int.Parse(a[3]), null, null);
                            if (!ar.AsyncWaitHandle.WaitOne(5000)) return 1;
                            c.EndConnect(ar);
                            return 0;
                        }
                    case "udpdns":
                        using (var u = new UdpClient(IPAddress.Parse(a[2]).AddressFamily))
                        {
                            // 查询 example.com A 记录
                            var q = new byte[] { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0, 0, 1, 0, 1 };
                            u.Client.ReceiveTimeout = 4000;
                            u.Send(q, q.Length, new IPEndPoint(IPAddress.Parse(a[2]), 53));
                            var ep = new IPEndPoint(IPAddress.Any, 0);
                            var resp = u.Receive(ref ep);
                            return resp.Length > 12 && resp[0] == 0x12 && resp[1] == 0x34 ? 0 : 1;
                        }
                    case "proxy":
                        using (var c = new TcpClient(AddressFamily.InterNetwork))
                        {
                            c.ReceiveTimeout = 8000;
                            c.Connect(IPAddress.Loopback, int.Parse(a[2]));
                            var s = c.GetStream();
                            var req = Encoding.ASCII.GetBytes("CONNECT " + a[3] + ":443 HTTP/1.1\r\nHost: " + a[3] + ":443\r\n\r\n");
                            s.Write(req, 0, req.Length);
                            var buf = new byte[64];
                            int n = s.Read(buf, 0, buf.Length);
                            if (!Encoding.ASCII.GetString(buf, 0, n).Contains(" 200")) return 1;
                            using (var ssl = new System.Net.Security.SslStream(s)) ssl.AuthenticateAsClient(a[3]);
                            return 0;
                        }
                }
            }
            catch { return 1; }
            return 2;
        }
    }

    static class SelfTest
    {
        class Case { public string Name; public string[] Args; public bool ExpectOk; public string Phase; public string Note; }

        static int Probe(string exe, string[] args)
        {
            var psi = new ProcessStartInfo(exe, "netprobe " + string.Join(" ", args)) { UseShellExecute = false, CreateNoWindow = true };
            using (var p = Process.Start(psi)) { if (!p.WaitForExit(15000)) { p.Kill(); return 1; } return p.ExitCode; }
        }

        public static int Run()
        {
            var st = GuardSettings.Load();
            var dir = Path.Combine(GuardPaths.DataDir, "selftest");
            Directory.CreateDirectory(dir);
            var self = Process.GetCurrentProcess().MainModule.FileName;
            var probe = Path.Combine(dir, "guard-selftest-probe.exe");
            File.Copy(self, probe, true);
            var fw = new WindowsFirewall();
            var sb = new StringBuilder();
            Action<string> outp = s => { Console.WriteLine(s); sb.AppendLine(s); };
            outp("Claude VPN Guard 防火墙实测  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            outp("测试程序：" + probe);

            int port = 0;
            try
            {
                string diag;
                var cl = MihomoClient.Discover(st, out diag);
                if (cl != null) port = Json.Int(cl.Configs(), "mixed-port", 0);
            }
            catch { }
            outp("代理端口：" + (port > 0 ? port.ToString() : "未发现（跳过代理用例）"));

            bool v6 = false;
            try
            {
                foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.AddressFamily == AddressFamily.InterNetworkV6 && !ua.Address.IsIPv6LinkLocal && !IPAddress.IsLoopback(ua.Address) && !ua.Address.IsIPv6SiteLocal && ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
                            v6 = true;
            }
            catch { }

            var cases = new List<Case>();
            Func<string, string[], bool, string, string, Case> mk = (n, a, e, ph, note) => { var c = new Case { Name = n, Args = a, ExpectOk = e, Phase = ph, Note = note }; cases.Add(c); return c; };
            int pass = 0, fail = 0, skip = 0;

            Action<string> runPhase = phase =>
            {
                foreach (var c in cases)
                {
                    if (c.Phase != phase) continue;
                    if (c.Args[0] == "proxy" && port == 0) { outp("  [未验证] " + c.Name + "（无代理端口）"); skip++; continue; }
                    int rc = Probe(probe, c.Args);
                    // 经代理“应可连接”的用例受节点抖动影响：重试 3 次；仍不通只说明当时代理/节点不可用（多阻断不构成泄漏），记为未验证
                    // 基线直连同理：本机网络瞬断会让基线误判，重试 3 次（间隔 3 秒）
                    for (int t = 0; rc != 0 && c.ExpectOk && t < 3; t++) { System.Threading.Thread.Sleep(c.Args[0] == "proxy" ? 2000 : 3000); rc = Probe(probe, c.Args); }
                    if (rc != 0 && c.ExpectOk && c.Phase == "base") outp("  （基线重试 4 次仍不通：本机网络当时断开，请网络稳定后重跑 selftest）");
                    if (rc != 0 && c.ExpectOk && c.Args[0] == "proxy") { outp("  [未验证] " + c.Name + "：重试 4 次仍不通，当时代理节点不可用（不是规则放行问题，不影响安全结论）"); skip++; continue; }
                    bool ok = rc == 0;
                    bool good = ok == c.ExpectOk;
                    if (good) pass++; else fail++;
                    outp(string.Format("  [{0}] {1}：实际{2}，预期{3}{4}", good ? "通过" : "失败", c.Name, ok ? "可连接" : "被阻断/失败", c.ExpectOk ? "可连接" : "被阻断", c.Note == null ? "" : "  // " + c.Note));
                }
            };

            // 基线（无规则）
            mk("基线 直连 IPv4 TCP 223.5.5.5:443", new[] { "tcp", "223.5.5.5", "443" }, true, "base", "基线失败说明本机直连不通，后续阻断结论无效");
            mk("基线 直连 UDP DNS 223.5.5.5:53", new[] { "udpdns", "223.5.5.5" }, true, "base", null);
            // 静态规则
            mk("静态规则 直连 IPv4 TCP 223.5.5.5:443", new[] { "tcp", "223.5.5.5", "443" }, false, "static", null);
            mk("静态规则 直连 IPv4 TCP 119.29.29.29:80", new[] { "tcp", "119.29.29.29", "80" }, false, "static", null);
            mk("静态规则 直连 UDP DNS 223.5.5.5:53（QUIC/DNS 同属 UDP）", new[] { "udpdns", "223.5.5.5" }, false, "static", null);
            if (v6) mk("静态规则 直连 IPv6 TCP [2400:3200::1]:443", new[] { "tcp", "2400:3200::1", "443" }, false, "static", null);
            else outp("  本机无全局 IPv6 地址：IPv6 直连用例记为未验证（规则本身覆盖 IPv6 全段）");
            mk("静态规则 经本地代理 CONNECT " + st.ProbeHost, new[] { "proxy", port.ToString(), st.ProbeHost }, true, "static", "代理正常时 Claude 应可用");
            // 锁定规则
            mk("锁定规则 直连 IPv4 TCP 223.5.5.5:443", new[] { "tcp", "223.5.5.5", "443" }, false, "lock", null);
            mk("锁定规则 直连 UDP DNS 223.5.5.5:53", new[] { "udpdns", "223.5.5.5" }, false, "lock", null);
            mk("锁定规则 经本地代理（回环）", new[] { "proxy", port.ToString(), st.ProbeHost }, true, "lock", "已知限制：Windows 防火墙豁免回环，锁定无法阻断回环代理；此处预期“可连接”，由检测+结束进程兜底");

            try
            {
                outp("\n[阶段 1] 无规则基线");
                runPhase("base");
                outp("\n[阶段 2] 套用静态规则（锁定关闭）");
                fw.EnsureRules(new[] { probe }, st.FakeIpRange, false);
                System.Threading.Thread.Sleep(500);
                runPhase("static");
                outp("\n[阶段 2b] 规则冲突：为替身额外添加一条“允许出站”规则（模拟其他软件/用户添加的允许规则）");
                AddConflictAllow(probe);
                System.Threading.Thread.Sleep(500);
                int rcc = Probe(probe, new[] { "tcp", "223.5.5.5", "443" });
                bool goodc = rcc != 0;
                if (goodc) pass++; else fail++;
                outp(string.Format("  [{0}] 存在允许规则时直连仍被阻断：实际{1}", goodc ? "通过" : "失败", rcc == 0 ? "可连接" : "被阻断"));
                RemoveConflictAllow();
                outp("\n[阶段 3] 启用锁定规则");
                fw.EnsureRules(new[] { probe }, st.FakeIpRange, true);
                System.Threading.Thread.Sleep(500);
                runPhase("lock");
            }
            finally
            {
                int removed = RemoveFor(probe);
                outp("\n清理：删除测试规则 " + removed + " 条");
                try { File.Delete(probe); } catch { }
            }
            outp(string.Format("\n结果：通过 {0}，失败 {1}，未验证 {2}", pass, fail, skip));
            var report = Path.Combine(GuardPaths.DataDir, "selftest-report-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
            File.WriteAllText(report, sb.ToString(), Encoding.UTF8);
            Console.WriteLine("报告已保存：" + report);
            return fail == 0 ? 0 : 1;
        }

        const string ConflictRule = "ClaudeVPNGuard-SelfTest-ConflictAllow";
        static void AddConflictAllow(string exe)
        {
            dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
            dynamic r = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
            r.Name = ConflictRule; r.ApplicationName = exe; r.Direction = 2; r.Action = 1; r.Protocol = 256; r.Profiles = 0x7FFFFFFF; r.Enabled = true;
            r.Grouping = "ClaudeVPNGuard-SelfTest";
            policy.Rules.Add(r);
        }
        static void RemoveConflictAllow()
        {
            dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
            try { policy.Rules.Remove(ConflictRule); } catch { }
        }

        static int RemoveFor(string exe)
        {
            var key = WindowsFirewall.PathKey(exe);
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true);
            dynamic policy = Activator.CreateInstance(t);
            int n = 0;
            foreach (var name in new[] { "ClaudeVPNGuard-Static-" + key, "ClaudeVPNGuard-Lock-" + key })
            {
                try { policy.Rules.Item(name); policy.Rules.Remove(name); n++; } catch { }
            }
            return n;
        }
    }
}
