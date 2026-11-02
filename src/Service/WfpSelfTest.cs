// written_by: claude-code
// WFP 系统级实测（管理员）。只对一个“替身 Claude”（本程序副本）下发与 Claude 完全相同的 WFP 持久过滤器，
// 用该副本真实发起连接，验证：
//   · 直连 IPv4/IPv6 的 TCP 与 UDP(DNS) 被阻断
//   · 回环 127.0.0.1 / ::1 上的“通用代理端口”被阻断（回答“WFP 能否管住回环”）
//   · 回环其他端口、专用入口可用
//   · 未受保护的进程（本自检进程）直连/回环/局域网不受影响 —— 证明作用范围只限 Claude
//   · 下发过滤器的进程被强制结束后过滤器仍然有效（持久过滤器，而非随会话消失的动态过滤器）
//   · --keep 保留过滤器，重启后用 --after-reboot 复测（重启持久性）
// 测试结束删除本次添加的过滤器与副本（--keep 除外）。不修改任何其他程序的规则。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ClaudeVPNGuard
{
    static class WfpSelfTest
    {
        const int GeneralTestPort = 27990, OtherLoopPort = 27991;
        static int pass, fail, skip;
        static Dictionary<Guid, string> snapBefore;
        static TcpListener dedicatedStub;
        static StringBuilder sb = new StringBuilder();
        static void Out(string s) { Console.WriteLine(s); sb.AppendLine(s); }

        static int Probe(string exe, params string[] args)
        {
            var psi = new ProcessStartInfo(exe, "netprobe " + string.Join(" ", args)) { UseShellExecute = false, CreateNoWindow = true };
            using (var p = Process.Start(psi)) { if (!p.WaitForExit(15000)) { p.Kill(); return 1; } return p.ExitCode; }
        }

        static void Case(string name, string exe, bool expectOk, params string[] args)
        {
            int rc = exe == null ? NetProbe.Run(new[] { "netprobe" }.Concat(args).ToArray()) : Probe(exe, args);
            bool ok = rc == 0, good = ok == expectOk;
            if (good) pass++; else fail++;
            Out(string.Format("  [{0}] {1}：实际{2}，预期{3}", good ? "通过" : "失败", name, ok ? "可连接" : "被阻断/失败", expectOk ? "可连接" : "被阻断"));
        }
        static void Skip(string name, string why) { skip++; Out("  [未验证] " + name + "（" + why + "）"); }

        static bool HasGlobalV6()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                    .Any(u => u.Address.AddressFamily == AddressFamily.InterNetworkV6 && !u.Address.IsIPv6LinkLocal && !u.Address.IsIPv6SiteLocal && !IPAddress.IsLoopback(u.Address) && !u.Address.ToString().StartsWith("fd"));
            }
            catch { return false; }
        }

        static IPAddress Gateway()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().GatewayAddresses).Select(g => g.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            }
            catch { return null; }
        }

        static List<TcpListener> StartListeners()
        {
            var ls = new List<TcpListener>();
            foreach (var ep in new[] { new IPEndPoint(IPAddress.Loopback, GeneralTestPort), new IPEndPoint(IPAddress.IPv6Loopback, GeneralTestPort), new IPEndPoint(IPAddress.Loopback, OtherLoopPort), new IPEndPoint(IPAddress.IPv6Loopback, OtherLoopPort) })
            {
                var l = new TcpListener(ep);
                l.Start();
                ls.Add(l);
                new Thread(() => { while (true) { try { l.AcceptTcpClient().Close(); } catch { break; } } }) { IsBackground = true }.Start();
            }
            return ls;
        }

        // 与正式服务完全相同的过滤器生成逻辑（GuardHost.GeneralPorts + WfpFirewall 隔离模式），仅额外加入测试端口
        static WfpFirewall MakeWfp(int realMixed)
        {
            var ports = GuardHost.GeneralPorts(GuardSettings.Load());
            ports.Add(GeneralTestPort);
            if (realMixed > 0) ports.Add(realMixed);
            return new WfpFirewall { IsolationMode = true, GeneralProxyPorts = ports.Distinct().ToList() };
        }

        public static bool Confirm(string[] args)
        {
            var items = new[]
            {
                "测试程序是本程序的副本（替身），WFP 过滤器生成逻辑与正式 Claude 相同，但过滤器的程序条件只指向替身，不作用于真实 Claude、Clash Verge、spacedesk",
                "将实测：替身→127.0.0.1:专用入口 成功；替身→其他本地代理端口 阻断；替身→公网 IPv4 阻断；IPv6（本机可测范围）按规则处理；替身→UDP 直连 阻断",
                "测试结束会逐项确认替身过滤器已删除，并对比测试前后系统全部 WFP 过滤器快照，确认系统原有 WFP 状态未改变",
                "测试失败时保留完整诊断日志；不安装服务、不修改正式防火墙规则、不修改 Clash 配置",
                "测试期间会临时监听本机端口 " + GeneralTestPort + "/" + OtherLoopPort + "（以及空闲时的专用入口端口），测试后释放",
            };
            Out("执行前确认（逐项）：");
            bool auto = args.Contains("--yes");
            for (int i = 0; i < items.Length; i++)
            {
                Out("  " + (i + 1) + ". " + items[i]);
                if (auto) continue;
                Console.Write("     确认此项？[y/N] ");
                var a = Console.ReadLine();
                if (a == null || !(a.Trim() == "y" || a.Trim() == "Y" || a.Trim() == "是")) { Out("  未确认，selftest 已取消，未做任何修改。"); return false; }
            }
            if (auto) Out("  （--yes：由调用方已逐项确认）");
            return true;
        }

        public static int Run(string[] args)
        {
            bool keep = args.Contains("--keep"), afterReboot = args.Contains("--after-reboot");
            var st = GuardSettings.Load();
            var dir = Path.Combine(GuardPaths.DataDir, "selftest");
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, "guard-wfp-probe.exe");
            int realMixed = 0;
            try { string d; var cl = MihomoClient.Discover(st, out d); if (cl != null) realMixed = Json.Int(cl.Configs(), "mixed-port", 0); } catch { }
            var wfp = MakeWfp(realMixed);
            Out("Claude VPN Guard · WFP 系统级实测  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + (afterReboot ? "（重启后复测）" : ""));
            Out("替身程序：" + probe + "；隔离模式；通用代理端口阻断：" + string.Join(",", wfp.GeneralProxyPorts) + "；专用入口 " + st.DedicatedPort);
            var listeners = StartListeners();
            bool v6 = HasGlobalV6();
            var gw = Gateway();
            try
            {
                if (afterReboot)
                {
                    if (!File.Exists(probe)) { Out("未找到 --keep 留下的替身程序，无法复测"); return 2; }
                    Out("\n[重启持久性] 过滤器数量（本程序子层）：" + wfp.CountFilters());
                    Case("重启后 直连 IPv4 TCP 223.5.5.5:443", probe, false, "tcp", "223.5.5.5", "443");
                    Case("重启后 直连 UDP DNS 223.5.5.5:53", probe, false, "udpdns", "223.5.5.5");
                    Case("重启后 回环通用代理端口 127.0.0.1:" + GeneralTestPort, probe, false, "tcp", "127.0.0.1", GeneralTestPort.ToString());
                    Case("重启后 回环其他端口 127.0.0.1:" + OtherLoopPort, probe, true, "tcp", "127.0.0.1", OtherLoopPort.ToString());
                    return Finish(wfp, probe, false);
                }

                if (!args.Contains("--confirmed") && !Confirm(args)) return 4;
                snapBefore = wfp.SnapshotAll();
                Out("测试前系统 WFP 过滤器总数：" + snapBefore.Count + "（本程序子层 " + snapBefore.Values.Count(v => v.EndsWith("本程序子层")) + "）");
                File.Copy(Process.GetCurrentProcess().MainModule.FileName, probe, true);
                // 先清掉替身上可能残留的规则
                wfp.RemoveFor(probe);

                Out("\n[阶段 0] 基线（无过滤器）");
                Case("基线 直连 IPv4 TCP 223.5.5.5:443", probe, true, "tcp", "223.5.5.5", "443");
                Case("基线 直连 UDP DNS 223.5.5.5:53", probe, true, "udpdns", "223.5.5.5");
                Case("基线 回环 127.0.0.1:" + GeneralTestPort, probe, true, "tcp", "127.0.0.1", GeneralTestPort.ToString());

                var sdBefore = SpacedeskInfo.Detect();
                Out("\nspacedesk（下发前）：" + sdBefore.Describe());
                Out("\n[阶段 1] 下发 WFP 持久过滤器（隔离模式），仅作用于替身程序");
                wfp.AddFor(probe, st.FakeIpRange, false);
                Thread.Sleep(300);
                Case("直连 IPv4 TCP 223.5.5.5:443", probe, false, "tcp", "223.5.5.5", "443");
                Case("直连 IPv4 TCP 119.29.29.29:80", probe, false, "tcp", "119.29.29.29", "80");
                Case("直连 UDP DNS 223.5.5.5:53（UDP/QUIC/DNS 同属此类）", probe, false, "udpdns", "223.5.5.5");
                if (v6)
                {
                    Case("直连 IPv6 TCP [2400:3200::1]:443", probe, false, "tcp", "2400:3200::1", "443");
                    Case("直连 IPv6 UDP DNS [2400:3200::1]:53", probe, false, "udpdns", "2400:3200::1");
                }
                else Skip("直连 IPv6", "本机无全局 IPv6 地址；过滤器已覆盖 ALE_AUTH_CONNECT_V6 全部地址");
                if (gw != null) Case("直连 局域网网关 " + gw + ":80", probe, false, "tcp", gw.ToString(), "80");
                // 局域网/虚拟网段绕行：Clash 开了 allow-lan 时，本机网卡 IP 上也有代理端口
                foreach (var ip in NetEnv.OwnAddresses().Where(a => a.AddressFamily == AddressFamily.InterNetwork).Take(4))
                {
                    if (realMixed > 0) Case("经本机网卡 IP " + ip + ":" + realMixed + " 借道代理（allow-lan）", probe, false, "tcp", ip.ToString(), realMixed.ToString());
                }
                var sdNow = SpacedeskInfo.Detect();
                if (sdNow.ListenPorts.Contains(28252))
                {
                    var lanIp = NetEnv.OwnAddresses().FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && gw != null && a.GetAddressBytes()[0] == gw.GetAddressBytes()[0]);
                    if (lanIp != null)
                    {
                        Case("Claude 替身 → spacedesk 端口 " + lanIp + ":28252（Claude 不应触达局域网服务）", probe, false, "tcp", lanIp.ToString(), "28252");
                        Case("未受保护进程 → spacedesk 端口 " + lanIp + ":28252（spacedesk 正常可达）", null, true, "tcp", lanIp.ToString(), "28252");
                    }
                }
                Case("回环 127.0.0.1:" + GeneralTestPort + "（通用代理端口）← WFP 能否管住回环", probe, false, "tcp", "127.0.0.1", GeneralTestPort.ToString());
                Case("回环 [::1]:" + GeneralTestPort + "（通用代理端口，IPv6 回环）", probe, false, "tcp", "::1", GeneralTestPort.ToString());
                Case("回环 127.0.0.1:" + OtherLoopPort + "（其他本地端口，应可用）", probe, true, "tcp", "127.0.0.1", OtherLoopPort.ToString());
                // 其他本地代理端口：正式名单中当前正在监听的每一个端口都要被阻断
                var listening = new HashSet<int>(Native.TcpTable().Where(t => t.State == 2).Select(t => t.LocalPort));
                foreach (var port in wfp.GeneralProxyPorts.Where(pp => pp != GeneralTestPort && listening.Contains(pp)))
                    Case("回环 本地代理端口 127.0.0.1:" + port + "（应被阻断）", probe, false, "tcp", "127.0.0.1", port.ToString());
                // 专用入口：Clash 已加载覆写则经真实入口走 Japan Auto；否则临时监听该端口，只验证 WFP 放行
                if (PortOpen(st.DedicatedPort))
                {
                    Case("专用入口 127.0.0.1:" + st.DedicatedPort + " TCP 连接（应成功）", probe, true, "tcp", "127.0.0.1", st.DedicatedPort.ToString());
                    Case("专用入口 → Japan Auto → " + st.ProbeHost + " TLS（应成功）", probe, true, "proxy", st.DedicatedPort.ToString(), st.ProbeHost);
                }
                else
                {
                    try
                    {
                        dedicatedStub = new TcpListener(IPAddress.Loopback, st.DedicatedPort); dedicatedStub.Start();
                        var stub = dedicatedStub;
                        new Thread(() => { while (true) { try { stub.AcceptTcpClient().Close(); } catch { break; } } }) { IsBackground = true }.Start();
                        Case("专用入口端口 127.0.0.1:" + st.DedicatedPort + " TCP 连接（Clash 未加载覆写，临时监听，只验证 WFP 放行）", probe, true, "tcp", "127.0.0.1", st.DedicatedPort.ToString());
                    }
                    catch (Exception ex) { Skip("专用入口", "无法临时监听：" + ex.Message); }
                    Skip("专用入口 → Japan Auto 实际出网", "Clash 尚未加载覆写（127.0.0.1:" + st.DedicatedPort + " 不是 Mihomo）");
                }
                Out("  —— 作用范围：未受保护的进程（本自检进程）不受影响");
                Case("未受保护进程 直连 223.5.5.5:443", null, true, "tcp", "223.5.5.5", "443");
                Case("未受保护进程 回环 127.0.0.1:" + GeneralTestPort, null, true, "tcp", "127.0.0.1", GeneralTestPort.ToString());
                if (gw != null) Out("  （局域网：未受保护进程访问网关 " + gw + " 的结果取决于网关是否开放端口，此处不作为判定；作用范围由过滤器均带 ALE_APP_ID 条件静态证明，见 audit）");

                Out("\n[阶段 2] 启用锁定过滤器");
                wfp.AddFor(probe, st.FakeIpRange, true);
                Thread.Sleep(300);
                Case("锁定 直连 IPv4 TCP", probe, false, "tcp", "223.5.5.5", "443");
                Case("锁定 回环其他端口 127.0.0.1:" + OtherLoopPort, probe, false, "tcp", "127.0.0.1", OtherLoopPort.ToString());
                if (PortOpen(st.DedicatedPort)) Case("锁定 专用入口", probe, false, "proxy", st.DedicatedPort.ToString(), st.ProbeHost);

                Out("\n[阶段 3] 持久性：由另一个进程下发过滤器后强制结束该进程（模拟服务崩溃）");
                wfp.RemoveFor(probe);
                Case("清除后恢复可连接（确认清除有效）", probe, true, "tcp", "223.5.5.5", "443");
                var self = Process.GetCurrentProcess().MainModule.FileName;
                // 先删除上次留下的就绪标记，否则会在过滤器尚未下发时就结束下发进程（2026-11-01 实测踩坑）
                var flag = Path.Combine(dir, "wfp-added.flag");
                try { File.Delete(flag); } catch { }
                var adder = Process.Start(new ProcessStartInfo(self, "wfp-add-and-hang \"" + probe + "\"") { UseShellExecute = false, CreateNoWindow = true });
                if (!WaitFile(flag, 15000)) Out("  下发进程未就绪");
                adder.Kill(); adder.WaitForExit(5000);
                Out("  下发进程已被强制结束（pid " + adder.Id + "）");
                int present = wfp.RemainingFor(probe).Count;
                if (present == 0)
                {
                    fail++;
                    Out("  [失败] 持久性测试无效：下发进程结束时替身过滤器不存在（下发未完成），不能据此判断崩溃后是否仍阻断");
                }
                else Out("  下发进程结束后，替身过滤器仍存在 " + present + " 个（按 key 查询）");
                Thread.Sleep(300);
                Case("崩溃后 直连 IPv4 TCP 仍被阻断", probe, false, "tcp", "223.5.5.5", "443");
                Case("崩溃后 回环通用代理端口仍被阻断", probe, false, "tcp", "127.0.0.1", GeneralTestPort.ToString());
                Case("崩溃后 UDP DNS 仍被阻断", probe, false, "udpdns", "223.5.5.5");

                var sdAfter = SpacedeskInfo.Detect();
                bool sdOk = sdAfter.ServiceRunning == sdBefore.ServiceRunning && sdBefore.ListenPorts.All(p => sdAfter.ListenPorts.Contains(p)) && sdBefore.Peers.All(p => sdAfter.Peers.Contains(p));
                if (sdBefore.Installed) { if (sdOk) pass++; else fail++; }
                Out(string.Format("  [{0}] spacedesk 在全部阶段后状态不变：下发前 {1}；结束时 {2}", !sdBefore.Installed ? "未验证" : sdOk ? "通过" : "失败", sdBefore.Describe(), sdAfter.Describe()));
                if (sdBefore.Installed && !sdBefore.Connected) Out("  （当前没有扩展屏连接：传输中不断开这一点需在扩展屏连接时再跑一次）");

                if (keep)
                {
                    Out("\n--keep：保留替身与过滤器。请重启 Windows 后以管理员运行：ClaudeVPNGuard.Service.exe selftest --after-reboot");
                    return Finish(wfp, probe, true);
                }
                return Finish(wfp, probe, false);
            }
            finally { foreach (var l in listeners) try { l.Stop(); } catch { } }
        }

        static bool PortOpen(int port)
        {
            try { using (var c = new TcpClient()) { var ar = c.BeginConnect(IPAddress.Loopback, port, null, null); return ar.AsyncWaitHandle.WaitOne(800) && c.Connected; } }
            catch { return false; }
        }

        static bool WaitFile(string f, int ms) { var sw = Stopwatch.StartNew(); while (sw.ElapsedMilliseconds < ms) { if (File.Exists(f)) return true; Thread.Sleep(100); } return false; }

        // 快速隔离检查（验收脚本在各故障场景下调用）：替身套用隔离过滤器 → 测必须阻断/应可用的路径 → 清理
        // 输出一行 JSON，退出码 0 = 所有“必须阻断”的路径都被阻断
        public static int IsoCheck()
        {
            var st = GuardSettings.Load();
            var dir = Path.Combine(GuardPaths.DataDir, "selftest");
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, "guard-isocheck-probe.exe");
            File.Copy(Process.GetCurrentProcess().MainModule.FileName, probe, true);
            int realMixed = 0;
            try { string d; var cl = MihomoClient.Discover(st, out d); if (cl != null) realMixed = Json.Int(cl.Configs(), "mixed-port", 0); } catch { }
            var wfp = new WfpFirewall { IsolationMode = true, GeneralProxyPorts = GuardHost.GeneralPorts(st) };
            var res = new Dictionary<string, object>();
            bool allBlocked = true;
            try
            {
                wfp.AddFor(probe, st.FakeIpRange, false);
                Thread.Sleep(300);
                Func<string[], bool> blocked = a => Probe(probe, a) != 0;
                Action<string, string[]> must = (k, a) => { bool b = blocked(a); res[k] = b ? "阻断" : "可连接"; if (!b) allBlocked = false; };
                must("直连IPv4", new[] { "tcp", "223.5.5.5", "443" });
                must("直连UDP-DNS", new[] { "udpdns", "223.5.5.5" });
                if (realMixed > 0) must("回环通用端口" + realMixed, new[] { "tcp", "127.0.0.1", realMixed.ToString() });
                var lan = NetEnv.OwnAddresses().FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (lan != null && realMixed > 0) must("本机网卡IP借道" + lan + ":" + realMixed, new[] { "tcp", lan.ToString(), realMixed.ToString() });
                var gw = Gateway();
                if (gw != null) must("局域网网关" + gw, new[] { "tcp", gw.ToString(), "80" });
                res["专用入口"] = PortOpen(st.DedicatedPort) ? (Probe(probe, new[] { "proxy", st.DedicatedPort.ToString(), st.ProbeHost }) == 0 ? "可用" : "不可用") : "未监听";
            }
            finally { wfp.RemoveFor(probe); try { File.Delete(probe); } catch { } }
            res["spacedesk"] = SpacedeskInfo.Detect().Describe();
            res["全部必须阻断项已阻断"] = allBlocked;
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine(Json.Serialize(res));
            return allBlocked ? 0 : 1;
        }

        // 子进程：下发持久过滤器后挂起，等待被强制结束
        public static int AddAndHang(string probe)
        {
            var st = GuardSettings.Load();
            var flag = Path.Combine(GuardPaths.DataDir, "selftest", "wfp-added.flag");
            try { File.Delete(flag); } catch { }
            int realMixed = 0;
            try { string d; var cl = MihomoClient.Discover(st, out d); if (cl != null) realMixed = Json.Int(cl.Configs(), "mixed-port", 0); } catch { }
            MakeWfp(realMixed).AddFor(probe, st.FakeIpRange, false);
            File.WriteAllText(flag, "ok");
            Thread.Sleep(Timeout.Infinite);
            return 0;
        }

        static int Finish(WfpFirewall wfp, string probe, bool keep)
        {
            try { if (dedicatedStub != null) dedicatedStub.Stop(); } catch { }
            if (!keep)
            {
                int n = wfp.RemoveFor(probe);
                Out("\n[清理确认]");
                Out("  删除替身过滤器 " + n + " 个");
                var remain = wfp.RemainingFor(probe);
                bool cleanOk = remain.Count == 0;
                if (cleanOk) pass++; else fail++;
                Out(string.Format("  [{0}] 替身过滤器已全部删除（逐个按 key 查询，剩余 {1} 个）", cleanOk ? "通过" : "失败", remain.Count));
                try { File.Delete(probe); } catch { }
                if (snapBefore != null)
                {
                    var after = wfp.SnapshotAll();
                    var added = after.Keys.Except(snapBefore.Keys).ToList();
                    var removed = snapBefore.Keys.Except(after.Keys).ToList();
                    int oursAdded = added.Count(k => after[k].EndsWith("本程序子层")), oursRemoved = removed.Count(k => snapBefore[k].EndsWith("本程序子层"));
                    bool snapOk = oursAdded == 0 && oursRemoved == 0;
                    if (snapOk) pass++; else fail++;
                    Out(string.Format("  [{0}] 系统 WFP 快照对比：测试前 {1} 个，测试后 {2} 个；本程序子层 新增 {3} / 删除 {4}", snapOk ? "通过" : "失败", snapBefore.Count, after.Count, oursAdded, oursRemoved));
                    if (added.Count + removed.Count - oursAdded - oursRemoved > 0)
                    {
                        Out("  其他子层在测试期间的变化（Windows/其他软件的动态过滤器，非本程序造成，列出供核对）：");
                        foreach (var k in added.Where(k => !after[k].EndsWith("本程序子层")).Take(20)) Out("    + " + after[k]);
                        foreach (var k in removed.Where(k => !snapBefore[k].EndsWith("本程序子层")).Take(20)) Out("    - " + snapBefore[k]);
                    }
                }
            }
            Out(string.Format("\nWFP 实测结果：通过 {0}，失败 {1}，未验证 {2}", pass, fail, skip));
            Out("说明：selftest 只证明“这套过滤器作用在替身程序上时”系统的真实执行效果；不等于正式 Claude 的隔离已通过（正式 Claude 需安装后由验收脚本另行验证）。");
            if (fail > 0)
            {
                Out("\n[诊断] 测试未全部通过：不安装服务、不修改正式防火墙规则、不修改 Clash 配置。");
                try
                {
                    int total, unscoped; bool pers;
                    foreach (var l in wfp.AuditFilters(out total, out unscoped, out pers)) Out("  当前本程序子层过滤器：" + l);
                    Out("  本程序子层过滤器总数 " + total + "，无程序条件 " + unscoped + "，全部持久 " + pers);
                }
                catch (Exception ex) { Out("  过滤器枚举失败：" + ex.Message); }
                Out("  网络接口：" + string.Join("；", NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up).Select(n => n.Name + " " + string.Join(",", n.GetIPProperties().UnicastAddresses.Select(u => u.Address)))));
            }
            var report = Path.Combine(GuardPaths.DataDir, "wfp-selftest-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
            File.WriteAllText(report, sb.ToString(), Encoding.UTF8);
            Out("报告已保存：" + report);
            return fail == 0 ? 0 : 1;
        }
    }
}
