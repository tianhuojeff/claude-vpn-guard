// written_by: claude-code
// 局域网与网络环境审计：spacedesk 识别、网卡/默认路由/IP 转发/ICS/代理设置/本机监听代理，
// 目的是找出“未经验证的 Claude 外网出口”。原则：局域网流量本身不是泄漏；只关心 Claude 能否经由它们出网。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;

namespace ClaudeVPNGuard
{
    public class SpacedeskInfo
    {
        public bool Installed, ServiceRunning;
        public List<int> Pids = new List<int>();
        public List<int> ListenPorts = new List<int>();
        public List<string> Peers = new List<string>();   // 已建立的局域网连接 远端 ip:port
        public bool Connected { get { return Peers.Count > 0; } }

        public string Describe()
        {
            if (!Installed) return "未安装 spacedesk";
            if (!ServiceRunning) return "spacedesk 服务未运行";
            return Connected ? "已连接（" + string.Join("、", Peers.Take(3)) + "）" : "服务运行中，当前无扩展屏连接（监听 " + string.Join(",", ListenPorts.Distinct()) + "）";
        }

        public static SpacedeskInfo Detect()
        {
            var s = new SpacedeskInfo();
            try
            {
                using (var sc = new System.ServiceProcess.ServiceController("spacedeskService"))
                {
                    s.Installed = true;
                    s.ServiceRunning = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                }
            }
            catch { }
            foreach (var p in Native.Processes())
                if ((p.Name ?? "").IndexOf("spacedesk", StringComparison.OrdinalIgnoreCase) >= 0) { s.Pids.Add(p.Pid); s.Installed = true; }
            foreach (var t in Native.TcpTable())
            {
                if (!s.Pids.Contains(t.Pid)) continue;
                if (t.State == 2) s.ListenPorts.Add(t.LocalPort);
                else if (t.State == 5 && !IPAddress.IsLoopback(t.RemoteAddr)) s.Peers.Add(t.RemoteAddr + ":" + t.RemotePort);
            }
            return s;
        }
    }

    public class EnvFinding
    {
        public string Area, Detail;
        public bool PotentialEgress;   // 是否构成 Claude 的潜在出网路径
        public string CoveredBy;       // 由哪一层阻断（或“未覆盖”）
    }

    public static class NetEnv
    {
        static readonly string[] ProxyProcNames = { "clash", "mihomo", "verge", "v2ray", "xray", "sing-box", "singbox", "trojan", "ss-local", "sslocal", "shadowsocks", "privoxy", "polipo", "naive", "hysteria", "tuic", "brook", "gost", "frpc", "proxifier", "nekoray", "nekobox", "hiddify", "flclash", "qv2ray", "squid", "cntlm" };

        // 本机代理类进程在监听的全部端口（不含专用入口），供 WFP 阻断 Claude 借道
        public static List<int> ProxyListenerPorts(int exclude)
        {
            var procs = Native.Processes().ToDictionary(p => p.Pid, p => (p.Name ?? "").ToLowerInvariant());
            var res = new List<int>();
            foreach (var t in Native.TcpTable())
            {
                string n;
                if (t.State != 2 || !procs.TryGetValue(t.Pid, out n)) continue;
                if (ProxyProcNames.Any(x => n.Contains(x)) && t.LocalPort != exclude) res.Add(t.LocalPort);
            }
            return res.Distinct().ToList();
        }

        public static List<IPAddress> OwnAddresses()
        {
            var list = new List<IPAddress>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (!IPAddress.IsLoopback(ua.Address) && !ua.Address.IsIPv6LinkLocal) list.Add(ua.Address);
                }
            }
            catch { }
            return list;
        }

        static IEnumerable<ManagementBaseObject> Wmi(string ns, string q)
        {
            var res = new List<ManagementBaseObject>();
            try { using (var s = new ManagementObjectSearcher(ns, q)) foreach (ManagementBaseObject o in s.Get()) res.Add(o); } catch { }
            return res;
        }

        public static List<EnvFinding> Audit(GuardSettings st)
        {
            var f = new List<EnvFinding>();
            Action<string, string, bool, string> add = (a, d, e, c) => f.Add(new EnvFinding { Area = a, Detail = d, PotentialEgress = e, CoveredBy = c });

            // 网卡（含虚拟网卡）
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback || ni.OperationalStatus != OperationalStatus.Up) continue;
                var ips = ni.GetIPProperties().UnicastAddresses.Where(u => !u.Address.IsIPv6LinkLocal).Select(u => u.Address.ToString());
                var gws = ni.GetIPProperties().GatewayAddresses.Select(g => g.Address).Where(a => !a.Equals(IPAddress.Any)).Select(a => a.ToString()).ToList();
                bool virt = ni.Description.IndexOf("Virtual", StringComparison.OrdinalIgnoreCase) >= 0 || ni.Description.IndexOf("Hyper-V", StringComparison.OrdinalIgnoreCase) >= 0 || ni.Description.IndexOf("VMware", StringComparison.OrdinalIgnoreCase) >= 0 || ni.Description.IndexOf("wintun", StringComparison.OrdinalIgnoreCase) >= 0 || ni.Description.IndexOf("TAP", StringComparison.Ordinal) >= 0;
                bool sd = ni.Description.IndexOf("spacedesk", StringComparison.OrdinalIgnoreCase) >= 0;
                add("网卡", string.Format("{0}（{1}）{2} IP {3}{4}", ni.Name, ni.Description, virt ? "[虚拟]" : "", string.Join(",", ips), gws.Count > 0 ? " 网关 " + string.Join(",", gws) : ""),
                    gws.Count > 0 || virt, "WFP：Claude 对任何非回环地址（含局域网、虚拟网段、本机网卡 IP）一律阻断" + (sd ? "；此网卡由 spacedesk 引入" : ""));
            }
            // 默认路由
            var routes = Wmi(@"root\StandardCimv2", "SELECT InterfaceAlias,DestinationPrefix,NextHop,RouteMetric FROM MSFT_NetRoute WHERE DestinationPrefix='0.0.0.0/0' OR DestinationPrefix='::/0'").ToList();
            add("默认路由", routes.Count == 0 ? "无" : string.Join("；", routes.Select(r => r["InterfaceAlias"] + " " + r["DestinationPrefix"] + " → " + r["NextHop"])),
                routes.Count > 0, routes.Count > 1 ? "存在多条默认路由；Claude 无论走哪条都被 WFP 阻断（非回环）" : "WFP 非回环阻断与路由无关");
            // IP 转发
            var fwd = Wmi(@"root\StandardCimv2", "SELECT InterfaceAlias,AddressFamily FROM MSFT_NetIPInterface WHERE Forwarding=1").Select(o => o["InterfaceAlias"] + (Convert.ToInt32(o["AddressFamily"]) == 23 ? "(v6)" : "(v4)")).ToList();
            int router = 0;
            try { using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) router = Convert.ToInt32(k.GetValue("IPEnableRouter", 0)); } catch { }
            add("IP 转发", (fwd.Count == 0 ? "无接口开启转发" : "开启转发的接口：" + string.Join("、", fwd)) + "；IPEnableRouter=" + router,
                fwd.Count > 0 || router != 0, "转发影响的是经本机路由的他机流量；Claude 本机发起的连接仍由 WFP 判定");
            // ICS
            string ics = "未知";
            try { using (var sc = new System.ServiceProcess.ServiceController("SharedAccess")) ics = sc.Status + "/" + sc.StartType; } catch { }
            var shared = new List<string>();
            try
            {
                dynamic mgr = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.HNetShare"));
                foreach (dynamic c in mgr.EnumEveryConnection)
                {
                    dynamic cfg = mgr.INetSharingConfigurationForINetConnection(c);
                    if ((bool)cfg.SharingEnabled) shared.Add((string)mgr.NetConnectionProps(c).Name + (cfg.SharingConnectionType == 0 ? "(公用侧)" : "(专用侧)"));
                }
            }
            catch { }
            add("Internet 连接共享 ICS", "SharedAccess 服务 " + ics + "；已启用共享的连接：" + (shared.Count == 0 ? "无（或无权枚举）" : string.Join("、", shared)) + "。Hyper-V Default Switch 的 NAT 依赖该服务",
                shared.Count > 0, "ICS/NAT 是为其他设备/虚拟机共享本机网络；Claude 本机连接不经 ICS 豁免，仍由 WFP 判定");
            // 代理设置
            string winhttp = "";
            try
            {
                var psi = new ProcessStartInfo("netsh", "winhttp show proxy") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
                using (var p = Process.Start(psi)) { winhttp = p.StandardOutput.ReadToEnd(); p.WaitForExit(5000); }
            }
            catch { }
            bool winhttpDirect = winhttp.IndexOf("Direct access", StringComparison.OrdinalIgnoreCase) >= 0 || winhttp.Contains("直接访问");
            add("WinHTTP 代理", winhttpDirect ? "直接访问（无代理）" : winhttp.Trim().Replace("\r", " ").Replace("\n", " "), !winhttpDirect, "Claude 若使用该代理：回环通用端口与非回环地址均被 WFP 阻断");
            bool on; string server;
            HealthChecker.ReadSystemProxy(out on, out server);
            add("系统代理(WinINET)", on ? server : "关闭", on, st.IsolationMode ? "隔离模式下 Claude 不应使用系统代理；若使用，通用端口被 WFP 阻断（Claude 无法联网而非直连）" : "V1 模式：Claude 经此代理，依赖 Mihomo 路由");
            foreach (var scope in new[] { EnvironmentVariableTarget.User, EnvironmentVariableTarget.Machine })
                foreach (var v in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY" })
                {
                    var val = Environment.GetEnvironmentVariable(v, scope);
                    if (!string.IsNullOrEmpty(val))
                        add("环境变量代理", (scope == EnvironmentVariableTarget.User ? "用户 " : "系统 ") + v + "=" + val, true,
                            "Claude Code 会读取该变量。隔离模式下若它指向通用端口(" + val + ")，Claude Code 连接将被 WFP 阻断——不泄漏但会无法联网；需改为专用入口或另行配置");
                }
            // 本机监听的代理类程序（Claude 可能借道的本机其他代理）
            var procs = Native.Processes().ToDictionary(p => p.Pid, p => p.Name ?? "");
            var listeners = Native.TcpTable().Where(t => t.State == 2).GroupBy(t => t.Pid);
            foreach (var g in listeners)
            {
                string name;
                if (!procs.TryGetValue(g.Key, out name)) continue;
                var ln = name.ToLowerInvariant();
                if (!ProxyProcNames.Any(x => ln.Contains(x))) continue;
                var ports = g.Select(t => t.LocalAddr + ":" + t.LocalPort).Distinct().ToList();
                bool anyLoopback = g.Any(t => IPAddress.IsLoopback(t.LocalAddr) || t.LocalAddr.Equals(IPAddress.Any) || t.LocalAddr.Equals(IPAddress.IPv6Any));
                add("本机代理监听", name + " → " + string.Join(", ", ports.Take(8)), anyLoopback,
                    "这些端口（专用入口 " + st.DedicatedPort + " 除外）自动加入 WFP 通用代理端口阻断名单；非回环地址（含 allow-lan 的本机网卡 IP）由 WFP 非回环阻断覆盖");
            }
            return f;
        }
    }
}
