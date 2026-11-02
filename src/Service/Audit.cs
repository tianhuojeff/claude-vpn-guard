// written_by: claude-code
// 安装前检查 / 防火墙审计（只读，不修改任何系统设置）。
//   ClaudeVPNGuard.Service.exe preflight [报告路径]
// 非管理员可运行，部分项目（WFP 枚举、WindowsApps 扫描）需管理员，会标注“需管理员”。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;

namespace ClaudeVPNGuard
{
    static class Audit
    {
        static StringBuilder sb = new StringBuilder();
        static int warn, bad;
        static void Out(string s) { Console.WriteLine(s); sb.AppendLine(s); }
        static void Item(string level, string name, string detail)
        {
            if (level == "警告") warn++;
            if (level == "阻止") bad++;
            Out(string.Format("  [{0}] {1}：{2}", level, name, detail));
        }

        public static int Run(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            var st = GuardSettings.Load();
            Out("Claude VPN Guard 安装前检查 / 防火墙审计  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            Out("当前权限：" + (admin ? "管理员" : "普通用户（WFP 枚举等项目需管理员，会标注）"));

            Out("\n一、Windows 网络保护服务");
            foreach (var svc in new[] { "mpssvc", "BFE" })
            {
                try
                {
                    using (var sc = new ServiceController(svc))
                        Item(sc.Status == ServiceControllerStatus.Running ? "正常" : "阻止", svc == "BFE" ? "基础筛选引擎 BFE（WFP 执行者）" : "Windows Defender 防火墙 mpssvc", sc.Status + "，启动类型 " + sc.StartType);
                }
                catch (Exception ex) { Item("阻止", svc, "无法查询：" + ex.Message); }
            }

            Out("\n二、Windows 防火墙策略");
            try
            {
                dynamic p = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                int cur = 0;
                try { cur = p.CurrentProfileTypes; } catch { cur = 7; }
                foreach (var kv in new[] { new KeyValuePair<int, string>(1, "域"), new KeyValuePair<int, string>(2, "专用"), new KeyValuePair<int, string>(4, "公用") })
                {
                    bool en = p.FirewallEnabled[kv.Key];
                    bool active = (cur & kv.Key) != 0;
                    int outAct = p.DefaultOutboundAction[kv.Key];
                    // 只有当前网络正在使用的配置文件被关闭才算阻止项（例如未加入域的电脑关闭“域”配置文件不影响任何连接）
                    Item(en ? "正常" : active ? "阻止" : "提示", kv.Value + "配置文件" + (active ? "（当前使用）" : ""),
                        (en ? "已启用" : active ? "已关闭（V1 规则失效；WFP 过滤器仍由 BFE 执行）" : "已关闭（当前没有网络使用该配置文件，不影响）") + "，默认出站：" + (outAct == 1 ? "允许" : "阻止"));
                }
                Out("  说明：Windows 防火墙中“阻止”规则优先于“允许”规则（除非允许规则勾选了“替代阻止规则”，仅对 IPsec 安全连接有效）。");
                var loc = new ClaudeLocator(st);
                var exes = loc.DiscoverExecutables();
                int ours = 0, related = 0, overrideBlock = 0;
                foreach (dynamic r in p.Rules)
                {
                    string app = null, grp = null, name = null;
                    try { app = r.ApplicationName; grp = r.Grouping; name = r.Name; } catch { }
                    if (grp == GuardPaths.RuleGroup) { ours++; continue; }
                    if (app == null) continue;
                    bool claudeRel = exes.Any(e => string.Equals(e, app, StringComparison.OrdinalIgnoreCase)) || ClaudeLocator.IsClaudeInstallPath(app);
                    if (!claudeRel) continue;
                    related++;
                    int action = r.Action; int dir = r.Direction; bool en = r.Enabled;
                    int secure = 0;
                    try { secure = r.SecureFlags; } catch { }
                    if (action == 1 && (secure & 0x1) != 0) overrideBlock++;
                    Item(action == 1 && (secure & 0x1) != 0 ? "阻止" : "提示", "现有 Claude 相关规则", string.Format("{0}｜{1}｜{2}｜{3}", name, dir == 2 ? "出站" : "入站", action == 1 ? "允许" : "阻止", en ? "启用" : "禁用"));
                }
                Item(ours == 0 ? "正常" : "提示", "本程序规则残留（规则组 ClaudeVPNGuard）", ours == 0 ? "无" : ours + " 条（安装时会按路径覆盖更新）");
                Item(overrideBlock == 0 ? "正常" : "阻止", "可替代阻止规则的允许规则", overrideBlock == 0 ? "无冲突" : overrideBlock + " 条，会使阻断失效，需先处理");
                Out("  Claude 可执行文件：" + exes.Count + " 个");
                foreach (var e in exes) Out("    " + e);
            }
            catch (Exception ex) { Item("警告", "防火墙策略", "读取失败：" + ex.Message); }

            Out("\n三、WFP（本程序子层）");
            if (!admin) Item("警告", "WFP 枚举", "需管理员，未检查");
            else
            {
                try
                {
                    int total, unscoped; bool pers;
                    var lines = new WfpFirewall().AuditFilters(out total, out unscoped, out pers);
                    Item(total == 0 ? "正常" : "提示", "已有过滤器", total == 0 ? "无（未安装或已清理）" : total + " 个");
                    if (total > 0)
                    {
                        Item(unscoped == 0 ? "正常" : "阻止", "作用范围", unscoped == 0 ? "全部过滤器都带 ALE_APP_ID 条件：只作用于 Claude 程序，不影响局域网/spacedesk/其他软件" : unscoped + " 个过滤器缺少程序条件！");
                        Item(pers ? "正常" : "警告", "持久性", pers ? "全部为持久过滤器（重启、服务崩溃后仍生效）" : "存在动态过滤器");
                        foreach (var l in lines.Take(40)) Out("    " + l);
                    }
                }
                catch (Exception ex) { Item("警告", "WFP 枚举", ex.Message); }
            }

            Out("\n四、Clash Verge / Mihomo");
            var vdir = VergeOverride.FindVergeDataDir();
            Item(vdir != null ? "正常" : "警告", "Clash Verge 数据目录", vdir ?? "未找到（当前用户）");
            try
            {
                var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Clash Verge\clash-verge.exe");
                if (File.Exists(exe)) Item("正常", "Clash Verge 版本", System.Diagnostics.FileVersionInfo.GetVersionInfo(exe).ProductVersion + "（" + exe + "）");
            }
            catch { }
            if (vdir != null)
            {
                var y = File.ReadAllText(Path.Combine(vdir, "profiles.yaml"));
                bool scriptOk = System.Text.RegularExpressions.Regex.IsMatch(y, @"uid:\s*Script\s*\r?\n\s*type:\s*script");
                Item(scriptOk ? "正常" : "阻止", "全局扩展脚本（覆写机制）", scriptOk ? "支持（profiles\\Script.js，对所有订阅生效，订阅更新不覆盖）" : "未发现，无法自动生成 Japan Auto");
                var sj = Path.Combine(vdir, "profiles", "Script.js");
                bool applied = File.Exists(sj) && File.ReadAllText(sj).Contains(VergeOverride.BeginMark);
                Item(applied ? "正常" : "提示", "Japan Auto 覆写", applied ? "已写入 Script.js" : "尚未写入（verge-apply 需你确认）");
            }
            string diag;
            var cl = MihomoClient.Discover(st, out diag);
            Item(cl != null ? "正常" : "阻止", "内核控制接口", diag);
            if (cl != null)
            {
                try
                {
                    var cfg = cl.Configs();
                    Item("提示", "模式 / 端口", Json.Str(cfg, "mode") + "，mixed-port " + Json.Int(cfg, "mixed-port", 0) + "，TUN " + (Json.Bool(Json.Get(cfg, "tun"), "enable") ? "开" : "关") + "，allow-lan " + Json.Bool(cfg, "allow-lan"));
                    var nm = new NodeManager(new MihomoNodeApi(() => cl, st), st, null);
                    var groupTypes = new[] { "Selector", "URLTest", "Fallback", "LoadBalance", "Relay" };
                    var jp = cl.Proxies().Where(kv => !groupTypes.Contains(kv.Value.Type)).Select(kv => kv.Key).Where(n => !NodeManager.IsReject(n) && nm.IsJapanName(n)).OrderBy(x => x).ToList();
                    Item(jp.Count > 0 ? "正常" : "阻止", "识别到的日本节点", jp.Count + " 个：" + string.Join("、", jp));
                    var mem = new MihomoNodeApi(() => cl, st).GroupMembers(st.JapanGroupName);
                    Item(mem != null ? "正常" : "提示", st.JapanGroupName + " 组", mem == null ? "不存在（应用覆写并在 Clash Verge 刷新后出现）" : string.Join("、", mem));
                }
                catch (Exception ex) { Item("警告", "内核查询", ex.Message); }
            }
            bool dedicated = false;
            try { using (var c = new TcpClient()) { var ar = c.BeginConnect(IPAddress.Loopback, st.DedicatedPort, null, null); dedicated = ar.AsyncWaitHandle.WaitOne(800) && c.Connected; } } catch { }
            Item(dedicated ? "正常" : "提示", "专用入口 127.0.0.1:" + st.DedicatedPort, dedicated ? "在线" : "未监听");
            if (!dedicated)
            {
                var owner = Native.TcpTable().FirstOrDefault(t => t.State == 2 && t.LocalPort == st.DedicatedPort);
                if (owner != null) Item("阻止", "端口占用", st.DedicatedPort + " 被 pid " + owner.Pid + " 占用");
            }

            Out("\n五、spacedesk 与局域网兼容性");
            var sd = SpacedeskInfo.Detect();
            Item(sd.Installed ? "正常" : "提示", "spacedesk", sd.Describe() + (sd.Pids.Count > 0 ? "（进程 " + string.Join(",", sd.Pids) + "）" : ""));
            Item("正常", "隔离独立性", "本程序的全部规则/过滤器都带 Claude 程序条件，不添加局域网放行，也不改系统默认策略；spacedesk 的局域网传输不经过这些规则。反过来，Claude 对局域网（网关、其他设备、本机网卡 IP、虚拟网段）一律阻断，放行 spacedesk 不会放行 Claude。");
            var own = NetEnv.OwnAddresses();
            Item("提示", "本机非回环地址", string.Join("、", own.Select(a => a.ToString())) + "（Claude 连这些地址同样被阻断，含 allow-lan 暴露的代理端口）");
            foreach (var fnd in NetEnv.Audit(st))
                Item(fnd.PotentialEgress ? "提示" : "正常", fnd.Area, fnd.Detail + (fnd.PotentialEgress ? " → 对 Claude 的处理：" + fnd.CoveredBy : ""));
            Item("提示", "本机代理端口阻断名单（隔离模式）", string.Join(",", GuardHost.GeneralPorts(st)));

            Out("\n六、网络环境");
            try
            {
                var v6 = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up).SelectMany(n => n.GetIPProperties().UnicastAddresses)
                    .Where(u => u.Address.AddressFamily == AddressFamily.InterNetworkV6 && !u.Address.IsIPv6LinkLocal && !IPAddress.IsLoopback(u.Address)).ToList();
                Item("提示", "全局 IPv6", v6.Count > 0 ? "有（IPv6 直连测试可实测）" : "无（IPv6 直连测试只能标注未验证）");
            }
            catch { }
            var spacedesk = Native.Processes().Where(p => (p.Name ?? "").IndexOf("spacedesk", StringComparison.OrdinalIgnoreCase) >= 0).Select(p => p.Name).Distinct().ToList();
            Item("提示", "spacedesk", spacedesk.Count > 0 ? "运行中：" + string.Join("、", spacedesk) + "。本程序所有规则/过滤器都限定 Claude 程序，不改系统默认策略，不影响其局域网连接" : "未运行");
            Item("提示", "管理员权限", admin ? "是" : "否：安装/实测需在管理员终端执行");

            Out(string.Format("\n结论：阻止项 {0}，警告 {1}。{2}", bad, warn, bad == 0 ? "可以安装（仍需你确认）。" : "存在阻止项，安装前需先处理。"));
            var file = args.Length > 1 ? args[1] : Path.Combine(Path.GetTempPath(), "ClaudeVPNGuard-preflight-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
            try { File.WriteAllText(file, sb.ToString(), Encoding.UTF8); Console.WriteLine("报告：" + file); } catch { }
            return bad == 0 ? 0 : 3;
        }
    }
}
