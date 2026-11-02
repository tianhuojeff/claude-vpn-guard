// written_by: claude-code
// 安全检测：综合 防火墙、Mihomo 内核、代理模式、出站链路、实际连接、TUN/系统代理 判断是否安全。
// 任何一项无法确认 → 不可信（默认拒绝）。出口 IP 只做展示，不作为安全依据。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace ClaudeVPNGuard
{
    public class CheckItem
    {
        public string Id;
        public string Name;
        public bool Ok;
        public bool Critical;
        public string Detail;
    }

    public class HealthReport
    {
        public DateTime Time = DateTime.Now;
        public bool Full;
        public List<CheckItem> Items = new List<CheckItem>();
        public bool Safe { get { return Items.Count > 0 && Items.Where(i => i.Critical).All(i => i.Ok); } }
        public string FirstFailure { get { var f = Items.FirstOrDefault(i => i.Critical && !i.Ok); return f == null ? null : f.Name + "：" + f.Detail; } }
        // 展示信息
        public string CoreVersion, Mode, Node, NodeChain, ExitIp, ControllerDesc;
        public bool TunEnabled, TunUp, SysProxyOn;
        public string SysProxyServer;
        public int MixedPort;
        public bool VergeGuiRunning;
        public List<string> Violations = new List<string>();
        public List<int> GeneralPorts = new List<int>();
        public string JapanNode;
        public string LanDisplay;

        public CheckItem Add(string id, string name, bool ok, bool critical, string detail)
        {
            var c = new CheckItem { Id = id, Name = name, Ok = ok, Critical = critical, Detail = detail };
            Items.Add(c);
            return c;
        }
    }

    public interface IHealthChecker
    {
        HealthReport Run(bool full, IList<string> protectedExe);
    }

    public class HealthChecker : IHealthChecker
    {
        readonly GuardSettings st;
        readonly ClaudeLocator loc;
        readonly IFirewall fw;
        MihomoClient client;
        public bool CheckFirewallRules = true; // 诊断模式（非管理员）可关闭
        public string LastExitIp;
        public MihomoClient ForcedClient;            // 测试/实验台：固定使用的控制接口
        public MihomoClient Client { get { return client; } }
        // 丢弃当前控制接口连接，下次检查重新发现（Clash Verge 重启后端口/密钥/管道可能已变）
        public void Reconnect() { client = null; }
        DateTime lastExitIpAt = DateTime.MinValue;

        public HealthChecker(GuardSettings s, ClaudeLocator l, IFirewall f) { st = s; loc = l; fw = f; }

        public HealthReport Run(bool full, IList<string> protectedExe)
        {
            var r = new HealthReport { Full = full };
            // 1. 防火墙
            try
            {
                string d;
                bool en = fw.AllProfilesEnabled(out d);
                r.Add("fw", "Windows 防火墙", en, true, d);
                if (CheckFirewallRules)
                {
                    bool rules = protectedExe.Count > 0 && fw.VerifyRules(protectedExe, st.FakeIpRange, false, out d);
                    r.Add("fwrules", "Claude 阻断规则", rules, true, protectedExe.Count == 0 ? "未发现 Claude 可执行文件" : d);
                }
            }
            catch (Exception ex) { r.Add("fw", "Windows 防火墙", false, true, "无法读取防火墙状态：" + ex.Message); }

            // 局域网扩展屏（仅显示，不是代理安全的必要条件）
            try { var sd = SpacedeskInfo.Detect(); r.LanDisplay = sd.Installed ? sd.Describe() : null; if (sd.Installed) r.Add("lan", "局域网扩展屏 spacedesk", true, false, sd.Describe() + "；不受 Claude 隔离规则影响"); } catch { }

            // 2. Clash Verge GUI（非关键：GUI 退出但内核仍正常时可继续，由后续检测决定）
            r.VergeGuiRunning = VergeGuiRunning();
            r.Add("verge", "Clash Verge 主程序", r.VergeGuiRunning, false, r.VergeGuiRunning ? "运行中" : "未运行（仅以内核状态判断）");

            // 3. 内核控制接口
            object cfg = null;
            Dictionary<string, ProxyInfo> proxies = null;
            try
            {
                if (client == null && ForcedClient != null) client = ForcedClient;
                if (client == null)
                {
                    string diag;
                    client = MihomoClient.Discover(st, out diag);
                    r.ControllerDesc = diag;
                    if (client == null) throw new IOException(diag);
                }
                r.CoreVersion = client.Version();
                r.ControllerDesc = client.Endpoint.Describe();
                cfg = client.Configs();
                proxies = client.Proxies();
                r.Add("core", "Mihomo 内核", true, true, "版本 " + r.CoreVersion + "，" + r.ControllerDesc);
            }
            catch (Exception ex)
            {
                client = null; // 下次重新发现（内核重启后管道名可能变化）
                r.Add("core", "Mihomo 内核", false, true, "控制接口不可用 → 视为不可信：" + ex.Message);
                AddSystemPathInfo(r, null, !st.IsolationMode); // 隔离模式下 Claude 不用系统路径
                return r;
            }

            // 4. 代理模式
            r.Mode = (Json.Str(cfg, "mode") ?? "").ToLowerInvariant();
            r.MixedPort = Json.Int(cfg, "mixed-port", 0);
            if (r.MixedPort == 0) r.MixedPort = Json.Int(cfg, "port", 0);
            var tun = Json.Get(cfg, "tun");
            r.TunEnabled = Json.Bool(tun, "enable");
            bool iso = st.IsolationMode;
            r.GeneralPorts = new List<int> { Json.Int(cfg, "mixed-port", 0), Json.Int(cfg, "port", 0), Json.Int(cfg, "socks-port", 0) }.Where(p => p > 0).Distinct().ToList();
            // 隔离模式下 Claude 只走专用入口（listener 的 proxy 优先于模式/规则，已用真实 Mihomo 实验验证），模式只做提示
            r.Add("mode", "代理模式", r.Mode == "rule" || r.Mode == "global", !iso,
                r.Mode == "direct" ? (iso ? "直连模式：其他软件直连；Claude 走专用入口不受影响" : "直连模式（DIRECT）→ 立即阻断") : (r.Mode == "" ? "无法读取模式" : ModeName(r.Mode)));

            // 隔离模式：Japan Auto 组 + 专用入口
            if (iso) CheckIsolation(r);

            // 5. 全局模式：GLOBAL 组最终出站不能是直连，节点需存活（隔离模式下仅提示）
            if (r.Mode == "global" && !iso)
            {
                List<string> path;
                var leaf = MihomoClient.ResolveLeaf(proxies, "GLOBAL", out path);
                r.NodeChain = string.Join(" → ", path);
                if (leaf == null) r.Add("chain", "出站节点", false, true, "无法解析 GLOBAL 出站链");
                else
                {
                    r.Node = leaf.Name;
                    bool direct = MihomoClient.IsDirectType(leaf.Type) || leaf.Name == "DIRECT";
                    bool reject = string.Equals(leaf.Type, "Reject", StringComparison.OrdinalIgnoreCase) || string.Equals(leaf.Type, "RejectDrop", StringComparison.OrdinalIgnoreCase);
                    r.Add("chain", "出站节点", !direct && !reject && leaf.Alive, true,
                        direct ? "全局出站为 DIRECT（直连）" : reject ? "全局出站为 REJECT" :
                        (leaf.Alive ? leaf.Name + "（" + leaf.Type + "，延迟 " + leaf.LastDelay + "ms）" : leaf.Name + " 最近一次测速失败"));
                }
            }

            // 6. 实际连接审计：Claude 的现有连接不得走 DIRECT
            try { AuditConnections(r, proxies); }
            catch (Exception ex) { r.Add("audit", "Claude 连接审计", false, true, "无法读取连接列表：" + ex.Message); }

            // 7. 本机网络路径：TUN 或 系统代理 至少一种有效（隔离模式由专用入口代替）
            AddSystemPathInfo(r, cfg, !iso);

            // 8. 真实探测（全量检测时）：经代理建立到 Claude 域名的 TLS 连接，并核对 Mihomo 实际路由
            if (full)
            {
                try { Probe(r, proxies); }
                catch (Exception ex) { r.Add("probe", "代理路径探测", false, true, "探测失败：" + ex.Message); }
                if (st.ExitIpCheck && r.Safe && (DateTime.Now - lastExitIpAt).TotalMinutes > 10)
                {
                    try { LastExitIp = QueryExitIp(r.MixedPort); lastExitIpAt = DateTime.Now; }
                    catch (Exception ex) { LastExitIp = "查询失败：" + ex.GetType().Name; }
                }
            }
            r.ExitIp = LastExitIp;
            return r;
        }

        static string ModeName(string m) { return m == "rule" ? "规则模式" : m == "global" ? "全局模式" : m; }

        static bool VergeGuiRunning()
        {
            foreach (var p in Native.Processes())
            {
                var n = (p.Name ?? "").ToLowerInvariant();
                if (n.StartsWith("clash-verge") && !n.Contains("service")) return true;
            }
            return false;
        }

        void CheckIsolation(HealthReport r)
        {
            var api = new MihomoNodeApi(() => client, st);
            List<string> members = null;
            try { members = api.GroupMembers(st.JapanGroupName); } catch { }
            if (members == null)
            {
                r.Add("jpgroup", st.JapanGroupName + " 组", false, true, "不存在：Clash 当前配置没有套用本程序的覆写（保护器会自动补写全局扩展脚本；请在 Clash Verge →「订阅」右键当前订阅「刷新」）");
            }
            else
            {
                var nm = new NodeManager(api, st, null);
                var bad = members.Where(n => !NodeManager.IsReject(n) && !nm.IsJapanName(n)).ToList();
                var now = api.GroupNow(st.JapanGroupName);
                r.JapanNode = now;
                r.Node = now; // 隔离模式下 Claude 实际使用的是 Japan Auto 的当前节点
                bool ok = bad.Count == 0 && now != null && !NodeManager.IsReject(now) && nm.IsJapanName(now);
                r.Add("jpgroup", st.JapanGroupName + " 组", ok, true,
                    bad.Count > 0 ? "组内出现非日本节点：" + string.Join("、", bad.Take(3)) :
                    NodeManager.IsReject(now) || members.All(n => NodeManager.IsReject(n)) ? "没有可用日本节点（组内仅 REJECT）" :
                    "当前 " + now + "，共 " + members.Count + " 个日本节点，无 DIRECT/其他国家");
            }
            bool open = false;
            try
            {
                using (var tc = new TcpClient(AddressFamily.InterNetwork))
                {
                    var ar = tc.BeginConnect(IPAddress.Loopback, st.DedicatedPort, null, null);
                    open = ar.AsyncWaitHandle.WaitOne(1500) && tc.Connected;
                }
            }
            catch { }
            r.Add("listener", "Claude 专用入口", open, true, open ? "127.0.0.1:" + st.DedicatedPort + " → " + st.JapanGroupName : "127.0.0.1:" + st.DedicatedPort + " 未监听（Claude 将无法联网，不会直连）");
        }

        void AddSystemPathInfo(HealthReport r, object cfg)
        {
            AddSystemPathInfo(r, cfg, true);
        }

        void AddSystemPathInfo(HealthReport r, object cfg, bool critical)
        {
            // TUN 网卡
            string dev = cfg == null ? "Mihomo" : (Json.Str(Json.Get(cfg, "tun"), "device") ?? "Mihomo");
            try
            {
                r.TunUp = NetworkInterface.GetAllNetworkInterfaces().Any(n =>
                    (string.Equals(n.Name, dev, StringComparison.OrdinalIgnoreCase) || n.Description.IndexOf("wintun", StringComparison.OrdinalIgnoreCase) >= 0 && n.Name.IndexOf(dev, StringComparison.OrdinalIgnoreCase) >= 0)
                    && n.OperationalStatus == OperationalStatus.Up);
            }
            catch { r.TunUp = false; }
            // 系统代理（读取当前控制台用户的 HKCU）
            string server; bool on;
            ReadSystemProxy(out on, out server);
            r.SysProxyOn = on; r.SysProxyServer = server;
            if (cfg == null) return;

            bool tunOk = r.TunEnabled && r.TunUp;
            bool sysOk = on && PointsToLocalPort(server, r.MixedPort);
            string d;
            if (tunOk && sysOk) d = "TUN + 系统代理 均有效";
            else if (tunOk) d = "TUN 模式有效（网卡 " + dev + " 已连接）";
            else if (sysOk) d = "系统代理有效（" + server + "）；安全等级：中（见说明）";
            else if (r.TunEnabled && !r.TunUp) d = "TUN 已开启但虚拟网卡 " + dev + " 未连接";
            else if (on) d = "系统代理指向 " + server + "，与内核端口 " + r.MixedPort + " 不符";
            else d = "TUN 与系统代理均未开启";
            bool ok = tunOk || (sysOk && st.AllowSystemProxyMode);
            r.Add("path", "本机代理路径", ok || !critical, critical, critical ? d : d + "（隔离模式下 Claude 不使用此路径）");
        }

        public static bool PointsToLocalPort(string server, int port)
        {
            if (string.IsNullOrEmpty(server) || port <= 0) return false;
            foreach (var part in server.Split(';'))
            {
                var p = part.Contains("=") ? part.Substring(part.IndexOf('=') + 1) : part;
                p = p.Trim().ToLowerInvariant();
                if (p.StartsWith("http://")) p = p.Substring(7);
                if (p == "127.0.0.1:" + port || p == "localhost:" + port || p == "[::1]:" + port) return true;
            }
            return false;
        }

        public static void ReadSystemProxy(out bool enabled, out string server)
        {
            enabled = false; server = null;
            try
            {
                RegistryKey key = null;
                var me = WindowsIdentity.GetCurrent();
                if (me.IsSystem)
                {
                    var user = Native.ConsoleUser();
                    if (user == null) return;
                    var sid = new NTAccount(user).Translate(typeof(SecurityIdentifier)).Value;
                    key = Registry.Users.OpenSubKey(sid + @"\Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                }
                else key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                if (key == null) return;
                using (key)
                {
                    var v = key.GetValue("ProxyEnable");
                    enabled = v is int && (int)v != 0;
                    server = key.GetValue("ProxyServer") as string;
                }
            }
            catch { }
        }

        // 审计 Mihomo 当前连接：识别属于 Claude 的连接（进程路径 / 本地源端口反查 PID / 域名），出站为 DIRECT 即违规。
        // 同时审计系统 TCP 表：Claude 进程不得有指向 回环/fake-ip 以外地址的连接（说明防火墙失效）。
        void AuditConnections(HealthReport r, Dictionary<string, ProxyInfo> proxies)
        {
            var claudePids = loc.RunningClaude();
            var tcp = Native.TcpTable();
            var conns = client.Connections();
            int claudeCount = 0;
            var portToPid = new Dictionary<int, int>();
            foreach (var t in tcp)
                if (IPAddress.IsLoopback(t.LocalAddr.IsIPv4MappedToIPv6 ? t.LocalAddr.MapToIPv4() : t.LocalAddr) && (t.RemotePort == r.MixedPort || t.RemotePort == st.DedicatedPort) && !portToPid.ContainsKey(t.LocalPort))
                    portToPid[t.LocalPort] = t.Pid;
            foreach (var c in Json.Arr(conns, "connections"))
            {
                var md = Json.Get(c, "metadata");
                var host = Json.Str(md, "host") ?? Json.Str(md, "sniffHost");
                var ppath = Json.Str(md, "processPath");
                int sport = Json.Int(md, "sourcePort", 0);
                int pid;
                // 只有“确认由 Claude 进程发起”的连接才算 Claude 的连接；
                // 仅域名是 claude.ai 等的连接可能来自浏览器/扩展等其他软件，不能据此判定 Claude 违规
                bool byClaudeProc = (!string.IsNullOrEmpty(ppath) && loc.IsClaudeExe(ppath))
                    || (portToPid.TryGetValue(sport, out pid) && claudePids.ContainsKey(pid));
                bool hostOnly = !byClaudeProc && st.IsClaudeHost(host);
                if (!byClaudeProc && !hostOnly) continue;
                // 隔离模式下，其他软件访问 Claude 域名与 Claude 无关（Claude 被 WFP 限制只能走专用入口）
                if (hostOnly && st.IsolationMode) continue;
                if (byClaudeProc) claudeCount++;
                var chains = Json.Arr(c, "chains").Select(x => Convert.ToString(x)).ToList();
                var outbound = chains.FirstOrDefault();
                ProxyInfo pi = null;
                if (outbound != null) proxies.TryGetValue(outbound, out pi);
                bool direct = outbound == null || outbound == "DIRECT" || (pi != null && MihomoClient.IsDirectType(pi.Type));
                if (direct) r.Violations.Add(string.Format("{0} 经 {1} 直连（规则 {2}）", host ?? Json.Str(md, "destinationIP"), outbound ?? "?", Json.Str(c, "rule")));
                else if (st.IsolationMode && byClaudeProc && Json.Str(md, "specialProxy") != st.JapanGroupName)
                    r.Violations.Add(string.Format("Claude 连接 {0} 未经专用入口（经 {1}）→ 隔离保障失效", host ?? "?", outbound));
            }
            foreach (var t in tcp)
            {
                if (!claudePids.ContainsKey(t.Pid) || t.State == 2 /*LISTEN*/) continue;
                var ra = t.RemoteAddr.IsIPv4MappedToIPv6 ? t.RemoteAddr.MapToIPv4() : t.RemoteAddr;
                if (st.IsolationMode)
                {
                    if (!IPAddress.IsLoopback(ra) && !ra.Equals(IPAddress.Any) && !ra.Equals(IPAddress.IPv6Any))
                        r.Violations.Add(string.Format("Claude 进程 {0} 存在非回环连接 {1}:{2}（WFP 未生效？）", t.Pid, ra, t.RemotePort));
                    else if (IPAddress.IsLoopback(ra) && r.GeneralPorts.Contains(t.RemotePort))
                        r.Violations.Add(string.Format("Claude 进程 {0} 连接了通用代理端口 {1}（WFP 回环限制未生效）", t.Pid, t.RemotePort));
                }
                else if (!AddrMath.IsAllowedDestination(t.RemoteAddr, st.FakeIpRange))
                    r.Violations.Add(string.Format("Claude 进程 {0} 存在直连 {1}:{2}（防火墙未生效？）", t.Pid, t.RemoteAddr, t.RemotePort));
            }
            r.Add("audit", "Claude 连接审计", r.Violations.Count == 0, true,
                r.Violations.Count == 0 ? string.Format("Claude 进程 {0} 个，经代理连接 {1} 条，未发现直连", claudePids.Count, claudeCount) : string.Join("；", r.Violations.Take(3)));
        }

        // 经混合端口 CONNECT 到 Claude 域名，连接保持期间查 Mihomo 对该连接的实际出站，再完成 TLS 握手证明节点可用。
        void Probe(HealthReport r, Dictionary<string, ProxyInfo> proxies)
        {
            int port = st.IsolationMode ? st.DedicatedPort : r.MixedPort;
            if (port <= 0) { r.Add("probe", "代理路径探测", false, true, "内核未开放本地代理端口"); return; }
            using (var tc = new TcpClient(AddressFamily.InterNetwork))
            {
                tc.ReceiveTimeout = 8000; tc.SendTimeout = 5000;
                tc.Connect(IPAddress.Loopback, port);
                var s = tc.GetStream();
                var req = Encoding.ASCII.GetBytes("CONNECT " + st.ProbeHost + ":" + st.ProbePort + " HTTP/1.1\r\nHost: " + st.ProbeHost + ":" + st.ProbePort + "\r\n\r\n");
                s.Write(req, 0, req.Length);
                var head = ReadHead(s);
                if (!head.StartsWith("HTTP/1.1 200") && !head.StartsWith("HTTP/1.0 200"))
                {
                    r.Add("probe", "代理路径探测", false, true, "代理拒绝 CONNECT：" + head.Split('\r')[0]);
                    return;
                }
                int lport = ((IPEndPoint)tc.Client.LocalEndPoint).Port;
                // Mihomo 需收到 TLS ClientHello（域名嗅探）后才拨号并登记连接，所以先握手，连接保持期间再查路由
                using (var ssl = new SslStream(s, false))
                {
                    var t0 = DateTime.Now;
                    string tlsErr = null;
                    try { ssl.AuthenticateAsClient(st.ProbeHost, null, (System.Security.Authentication.SslProtocols)(3072 | 12288), false); }
                    catch (Exception ex) { tlsErr = ex.InnerException != null ? ex.Message + " / " + ex.InnerException.Message : ex.Message; }
                    var ms = (DateTime.Now - t0).TotalMilliseconds;
                    string outbound = null, rule = null, special = null;
                    foreach (var c in Json.Arr(client.Connections(), "connections"))
                    {
                        var md = Json.Get(c, "metadata");
                        if (Json.Int(md, "sourcePort", -1) != lport) continue;
                        outbound = Json.Arr(c, "chains").Select(x => Convert.ToString(x)).FirstOrDefault();
                        rule = (Json.Str(c, "rule") + " " + Json.Str(c, "rulePayload")).Trim();
                        special = Json.Str(md, "specialProxy");
                        break;
                    }
                    if (st.IsolationMode && outbound != null)
                    {
                        var nm = new NodeManager(new MihomoNodeApi(() => client, st), st, null);
                        if (special != st.JapanGroupName || !nm.IsJapanName(outbound))
                        {
                            r.Add("probe", "代理路径探测", false, true, "专用入口路由异常：specialProxy=" + (special ?? "无") + "，出站=" + outbound);
                            r.Violations.Add("专用入口未按 " + st.JapanGroupName + " 出站");
                            return;
                        }
                    }
                    ProxyInfo pi = null;
                    if (outbound != null) proxies.TryGetValue(outbound, out pi);
                    if (outbound != null && (outbound == "DIRECT" || (pi != null && MihomoClient.IsDirectType(pi.Type))))
                    {
                        r.Add("probe", "代理路径探测", false, true, st.ProbeHost + " 被路由到 DIRECT（规则：" + rule + "）");
                        r.Violations.Add("Claude 域名规则命中 DIRECT");
                        return;
                    }
                    if (tlsErr != null) { r.Add("probe", "代理路径探测", false, true, "经代理 TLS 握手失败（节点不可用？）：" + tlsErr); return; }
                    if (outbound == null) { r.Add("probe", "代理路径探测", false, true, "在内核连接表中找不到探测连接，无法确认路由"); return; }
                    if (r.Node == null) r.Node = outbound;
                    r.Add("probe", "代理路径探测", true, true, string.Format("{0} → {1}{2}，TLS 握手成功 {3:0}ms", st.ProbeHost, outbound, rule == "" ? "" : "（规则 " + rule + "）", ms));
                }
            }
        }

        // 节点切换后的路径验证：经专用入口建立到 Claude 域名的 TLS 连接，确认 Mihomo 记录的 specialProxy=Japan Auto 且出站=期望节点
        public bool VerifyDedicatedPath(string expectedNode, out string detail)
        {
            detail = null;
            if (client == null) { detail = "内核控制接口不可用"; return false; }
            try
            {
                using (var tc = new TcpClient(AddressFamily.InterNetwork))
                {
                    tc.ReceiveTimeout = st.ProbeTimeoutMs + 5000; tc.SendTimeout = 5000;
                    tc.Connect(IPAddress.Loopback, st.DedicatedPort);
                    var s = tc.GetStream();
                    var req = Encoding.ASCII.GetBytes("CONNECT " + st.ProbeHost + ":" + st.ProbePort + " HTTP/1.1\r\nHost: " + st.ProbeHost + ":" + st.ProbePort + "\r\n\r\n");
                    s.Write(req, 0, req.Length);
                    var head = ReadHead(s);
                    if (!head.Contains(" 200")) { detail = "专用入口拒绝 CONNECT"; return false; }
                    int lport = ((IPEndPoint)tc.Client.LocalEndPoint).Port;
                    using (var ssl = new SslStream(s, false))
                    {
                        ssl.AuthenticateAsClient(st.ProbeHost, null, (System.Security.Authentication.SslProtocols)(3072 | 12288), false);
                        foreach (var c in Json.Arr(client.Connections(), "connections"))
                        {
                            var md = Json.Get(c, "metadata");
                            if (Json.Int(md, "sourcePort", -1) != lport) continue;
                            var outbound = Json.Arr(c, "chains").Select(x => Convert.ToString(x)).FirstOrDefault();
                            var special = Json.Str(md, "specialProxy");
                            detail = "specialProxy=" + special + " 出站=" + outbound;
                            return special == st.JapanGroupName && outbound == expectedNode;
                        }
                        detail = "连接表中找不到验证连接";
                        return false;
                    }
                }
            }
            catch (Exception ex) { detail = ex.Message; return false; }
        }

        static string ReadHead(Stream s)
        {
            var sb = new StringBuilder();
            var one = new byte[1];
            while (sb.Length < 8192)
            {
                int n = s.Read(one, 0, 1);
                if (n <= 0) break;
                sb.Append((char)one[0]);
                if (sb.Length >= 4 && sb.ToString(sb.Length - 4, 4) == "\r\n\r\n") break;
            }
            return sb.ToString();
        }

        // 仅用于显示：经代理访问 cloudflare trace 取出口 IP（不作为安全依据）
        static string QueryExitIp(int port)
        {
            var req = (HttpWebRequest)WebRequest.Create("https://www.cloudflare.com/cdn-cgi/trace");
            req.Proxy = new WebProxy("http://127.0.0.1:" + port);
            req.Timeout = 8000;
            using (var resp = req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream()))
            {
                string ip = null, loc = null, line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (line.StartsWith("ip=")) ip = line.Substring(3);
                    if (line.StartsWith("loc=")) loc = line.Substring(4);
                }
                return ip + (loc != null ? " (" + loc + ")" : "");
            }
        }
    }
}
