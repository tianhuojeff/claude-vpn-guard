// written_by: claude-code
// V2 单元测试：覆写脚本生成/还原、差异、Claude Code 专用代理配置、WFP 过滤器键、日本节点识别、局域网审计（只读）。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ClaudeVPNGuard
{
    class FakeNodeApi : INodeApi
    {
        public List<string> Members = new List<string>();
        public string Now;
        public Dictionary<string, int> Delays = new Dictionary<string, int>();
        public List<string> GroupMembers(string g) { return Members; }
        public string GroupNow(string g) { return Now; }
        public int Delay(string n, string u, int t) { int d; return Delays.TryGetValue(n, out d) ? d : -1; }
        public void Select(string g, string n) { Now = n; }
        public string ExitCountry(out string ip) { ip = "10.0.0.1"; return "JP"; }
    }

    static class V2Tests
    {
        public static void Run(Action<string, bool, string> check, string tmp)
        {
            Console.WriteLine("Clash 覆写脚本");
            var st = new GuardSettings(); st.Normalize();
            var user = "// 用户自己的脚本\nfunction main(config, profileName) {\n  config.mode = config.mode;\n  return config;\n}\n";
            var c1 = VergeOverride.Compose(user, st);
            check("写入后含本程序段与包装 main", c1.Contains(VergeOverride.BeginMark) && c1.Contains("function cvgUserMain(") && c1.Contains("return cvgApply(cvgUserMain(config, profileName))"), null);
            check("用户原逻辑保留", c1.Contains("config.mode = config.mode;") && c1.Contains("// 用户自己的脚本"), null);
            var c2 = VergeOverride.Compose(c1, st);
            check("重复写入幂等（不叠加多段）", c2 == c1 && c2.Split(new[] { VergeOverride.BeginMark }, StringSplitOptions.None).Length == 2, null);
            check("移除后完整还原用户脚本", VergeOverride.StripBlock(c1).Trim() == user.Trim(), VergeOverride.StripBlock(c1));
            var diff = VergeOverride.LineDiff("a\nb\nc", "a\nx\nc");
            check("行级差异", diff.SequenceEqual(new[] { "  a", "- b", "+ x", "  c" }), string.Join("|", diff));
            // 覆写与恢复（临时 Clash Verge 目录）
            var vdir = Path.Combine(tmp, "verge"); Directory.CreateDirectory(Path.Combine(vdir, "profiles"));
            File.WriteAllText(Path.Combine(vdir, "profiles.yaml"), "items:\n- uid: Script\n  type: script\n  file: Script.js\n");
            File.WriteAllText(Path.Combine(vdir, "profiles", "Script.js"), user);
            var bak = VergeOverride.Apply(vdir, st);
            check("Apply 生成备份且备份内容为原文件", File.Exists(bak) && File.ReadAllText(bak) == user, bak);
            var rep = VergeOverride.DiffReport(vdir, st);
            check("差异报告确认用户脚本完整保留", rep.Any(l => l.Contains("完整保留") && l.EndsWith("是")), string.Join(" / ", rep.Take(4)));
            VergeOverride.Restore(vdir, null);
            check("Restore 恢复原文件", File.ReadAllText(Path.Combine(vdir, "profiles", "Script.js")) == user, null);
            File.WriteAllText(Path.Combine(vdir, "profiles.yaml"), "items:\n- uid: Merge\n  type: merge\n");
            string err = null;
            try { VergeOverride.Apply(vdir, st); } catch (Exception ex) { err = ex.Message; }
            check("不支持全局扩展脚本时拒绝写入", err != null, err);

            Console.WriteLine("Claude Code 专用代理（只改 Claude Code 设置）");
            var sp = Path.Combine(tmp, "cc", "settings.json"); Directory.CreateDirectory(Path.GetDirectoryName(sp));
            File.WriteAllText(sp, "{\"agentPushNotifEnabled\": true, \"enableWorkflows\": false, \"env\": {\"FOO\": \"1\", \"NO_PROXY\": \"corp.local\"}}");
            var userEnvBefore = Environment.GetEnvironmentVariable("HTTPS_PROXY", EnvironmentVariableTarget.User);
            ClaudeCodeProxy.Apply(sp, 17897);
            var j = Json.Parse(File.ReadAllText(sp)) as Dictionary<string, object>;
            var env = j["env"] as Dictionary<string, object>;
            check("写入 HTTPS/HTTP/ALL_PROXY = 专用入口", (string)env["HTTPS_PROXY"] == "http://127.0.0.1:17897" && (string)env["ALL_PROXY"] == "http://127.0.0.1:17897", null);
            check("其他设置项与其他 env 原样保留", (bool)j["agentPushNotifEnabled"] && !(bool)j["enableWorkflows"] && (string)env["FOO"] == "1", null);
            check("状态显示已配置", ClaudeCodeProxy.Status(sp, 17897).StartsWith("已配置"), ClaudeCodeProxy.Status(sp, 17897));
            check("生成了备份文件", Directory.GetFiles(Path.GetDirectoryName(sp), "settings.json.cvg-backup-*").Length == 1, null);
            check("未修改用户级环境变量", Environment.GetEnvironmentVariable("HTTPS_PROXY", EnvironmentVariableTarget.User) == userEnvBefore, null);
            ClaudeCodeProxy.Remove(sp);
            j = Json.Parse(File.ReadAllText(sp)) as Dictionary<string, object>;
            env = j["env"] as Dictionary<string, object>;
            check("移除后精确还原：原有 NO_PROXY 恢复、新增键删除", (string)env["NO_PROXY"] == "corp.local" && !env.ContainsKey("HTTPS_PROXY") && (string)env["FOO"] == "1", Json.Serialize(env));

            Console.WriteLine("WFP 过滤器键 / 日本节点识别");
            var k1 = WfpFirewall.FilterKey(@"C:\A\claude.exe", "block4");
            check("过滤器键确定且大小写无关", k1 == WfpFirewall.FilterKey(@"c:\a\CLAUDE.EXE", "block4"), null);
            check("不同角色/路径键不同", k1 != WfpFirewall.FilterKey(@"C:\A\claude.exe", "block6") && k1 != WfpFirewall.FilterKey(@"C:\B\claude.exe", "block4"), null);
            var nm = new NodeManager(null, st, null);
            var names = new[] { "\U0001F1EF\U0001F1F5Japan 01", "\U0001F1EF\U0001F1F5Japan 04", "日本 东京 IEPL", "JP-Osaka-2", "\U0001F1F0\U0001F1F7Korea 01", "\U0001F1FA\U0001F1F8United States 01", "\U0001F1E6\U0001F1F1 剩余流量：860 GB", "日本 套餐到期：2027-06-18", "Singapore 01", "DIRECT" };
            var jp = names.Where(nm.IsJapanName).ToList();
            check("自动识别日本节点（排除信息节点/其他国家/DIRECT）", jp.Count == 4 && !jp.Any(n => n.Contains("Korea") || n.Contains("剩余") || n.Contains("到期") || n == "DIRECT"), string.Join(",", jp));
            st.JapanExclude.Add("JP-Osaka-2"); st.JapanInclude.Add("Singapore 01");
            check("手动排除/手动包含生效", !nm.IsJapanName("JP-Osaka-2") && nm.IsJapanName("Singapore 01"), null);
            st.JapanExclude.Clear(); st.JapanInclude.Clear();

            Console.WriteLine("故障转移：隔离中的节点在判定全部失败前会被重测（实机误判回归）");
            {
                var api = new FakeNodeApi();
                api.Members = new List<string> { "JP 01", "JP 02", "JP 03" };
                api.Now = "JP 01";
                api.Delays["JP 01"] = -1; api.Delays["JP 02"] = -1; api.Delays["JP 03"] = 120; // 03 已恢复
                var st2 = new GuardSettings(); st2.JapanNameRegex = "jp"; st2.Normalize();
                var nm2 = new NodeManager(api, st2, null);
                nm2.Stats["JP 02"] = new NodeStat { Name = "JP 02", QuarantineUntil = DateTime.Now.AddMinutes(5) };
                nm2.Stats["JP 03"] = new NodeStat { Name = "JP 03", QuarantineUntil = DateTime.Now.AddMinutes(5) };
                nm2.Current = "JP 01";
                string allFailed = null; nm2.OnAllFailed = r => allFailed = r;
                bool ok = nm2.Failover("节点故障：JP 01", true);
                check("候选都在隔离期但 JP 03 已恢复 → 切到 JP 03，不判全部失败", ok && api.Now == "JP 03" && allFailed == null, api.Now + " / " + allFailed);
                api.Delays["JP 03"] = -1;
                api.Now = "JP 01";
                nm2.Stats["JP 03"].QuarantineUntil = DateTime.Now.AddMinutes(5);
                ok = nm2.Failover("节点故障：JP 01", true);
                check("隔离中节点重测后确实都失败 → 才判定全部失败", !ok && allFailed != null, allFailed);
            }

            Console.WriteLine("多订阅日本节点汇总");
            {
                var st3 = new GuardSettings(); st3.Normalize();
                var vd = Path.Combine(tmp, "verge-multi"); Directory.CreateDirectory(Path.Combine(vd, "profiles"));
                File.WriteAllText(Path.Combine(vd, "profiles.yaml"),
                    "current: A1\nitems:\n- uid: Script\n  type: script\n  file: Script.js\n" +
                    "- uid: A1\n  type: remote\n  name: Kitty Network\n  file: A1.yaml\n  selected:\n  - name: GLOBAL\n    now: x\n  extra:\n    upload: 10\n    download: 20\n    total: 1000\n    expire: 4102444800\n  option:\n    update_interval: 1440\n" +
                    "- uid: B2\n  type: remote\n  name: '日本专线 果冻'\n  file: B2.yaml\n  extra:\n    upload: 0\n    download: 0\n    total: 0\n    expire: 0\n" +
                    "- uid: C3\n  type: remote\n  name: 折花令\n  file: C3.yaml\n  extra:\n    upload: 1\n    download: 1\n    total: 100\n    expire: 1000\n" +
                    "- uid: D4\n  type: local\n  name: us.yaml\n  file: D4.yaml\n");
                // 块格式（Kitty 风格，条目在 0 列）
                File.WriteAllText(Path.Combine(vd, "profiles", "A1.yaml"),
                    "mixed-port: 7890\nproxies:\n- name: \U0001F1E6\U0001F1F1 剩余流量：859 GB\n  type: vless\n  server: a.example\n- name: \U0001F1EF\U0001F1F5Japan 01\n  type: vless\n  server: jp1.example\n  ws-opts:\n    path: /x\n    headers:\n      name: inner\n- client-fingerprint: chrome\n  name: \U0001F1EF\U0001F1F5Japan 02\n  type: trojan\n- name: \U0001F1FA\U0001F1F8US 01\n  type: ss\nproxy-groups:\n- name: G\n  proxies: [a]\n");
                // 行内格式（缩进条目，名字带引号）
                File.WriteAllText(Path.Combine(vd, "profiles", "B2.yaml"),
                    "proxies:\n    - { name: '剩余流量：68 GB', type: vless, server: s1, port: 1 }\n    - { name: 'Japan-V1', type: vless, server: s2, port: 2, servername: x.jp }\n    - { name: \"\U0001F1F8\U0001F1EC SG 01\", type: ss, server: s3, port: 3 }\nproxy-groups:\n    - { name: g, type: select, proxies: [a] }\n");
                File.WriteAllText(Path.Combine(vd, "profiles", "C3.yaml"), "proxies:\n    - { name: 'JP 01', type: vless, server: s, port: 1 }\n");
                File.WriteAllText(Path.Combine(vd, "profiles", "D4.yaml"), "proxies:\n  - { name: US-1, type: http, server: u, port: 1 }\n");
                var subs3 = Subscriptions.ParseProfiles(File.ReadAllText(Path.Combine(vd, "profiles.yaml")));
                check("解析订阅列表（只含 remote/local，识别当前订阅与流量/到期）", subs3.Count == 4 && subs3[0].Name == "Kitty Network" && subs3[0].Current && subs3[0].Total == 1000 && subs3[1].Name == "日本专线 果冻", string.Join(",", subs3.Select(s => s.Uid + ":" + s.Name)));
                var a1 = Subscriptions.ParseProxies(File.ReadAllText(Path.Combine(vd, "profiles", "A1.yaml")));
                check("块格式节点：名字不在首行、嵌套 name 不误取", a1.Count == 4 && a1[1].Name == "\U0001F1EF\U0001F1F5Japan 01" && a1[2].Name == "\U0001F1EF\U0001F1F5Japan 02", string.Join(" | ", a1.Select(x => x.Name)));
                var content = Subscriptions.Build(vd, subs3, st3, DateTime.Now);
                var names3 = Subscriptions.ParseProxies(content).Select(x => x.Name).ToList();
                check("汇总只含日本节点，名前加订阅名", names3.Contains("[Kitty Network] \U0001F1EF\U0001F1F5Japan 01") && names3.Contains("[Kitty Network] \U0001F1EF\U0001F1F5Japan 02") && !names3.Any(n => n.Contains("US") || n.Contains("SG") || n.Contains("剩余")), string.Join(" | ", names3));
                check("订阅名里的“日本”字样被去掉，不能让前缀把节点伪装成日本节点", subs3[1].Tag == "专线 果冻" && names3.Contains("[专线 果冻] Japan-V1"), subs3[1].Tag);
                check("过期订阅自动跳过；local 美国订阅无日本节点", subs3[2].Expired && !names3.Any(n => n.Contains("折花令")) && subs3[3].JapanCount == 0, null);
                check("占位节点在最后（不会成为默认节点）", names3.Last() == Subscriptions.Placeholder && NodeManager.IsReject(names3.Last()), names3.Last());
                check("节点其余字段原样保留（嵌套块、servername）", content.Contains("      name: inner") && content.Contains("servername: x.jp") && content.Contains("server: jp1.example"), null);
                var nmx = new NodeManager(null, st3, null);
                check("汇总后每个候选都通过日本节点安全校验", names3.Where(n => !NodeManager.IsReject(n)).All(nmx.IsJapanName), null);
                check("节点列表能解析出所属订阅", NodeManager.SubTag("[Kitty Network] JP 1") == "Kitty Network" && NodeManager.SubTag("JP 1") == null, null);
                // 选节点综合分：偶尔测出低延迟但老掉线的节点，排在稳定的稍慢节点后面
                var t0 = DateTime.Now;
                var flaky = new NodeStat { Name = "flaky" }; var steady = new NodeStat { Name = "steady" };
                foreach (var d in new[] { 90, -1, 80, -1, 70 }) flaky.Sample(d, t0);
                foreach (var d in new[] { 160, 150, 170, 160, 150 }) steady.Sample(d, t0.AddMinutes(-10));
                check("综合分：稳定的 160ms 节点优先于老掉线的 70ms 节点", steady.Score(t0) < flaky.Score(t0), (int)steady.Score(t0) + " vs " + (int)flaky.Score(t0));
                var a = new NodeStat(); var b = new NodeStat();
                foreach (var d in new[] { 60, 70, 65 }) a.Sample(d, t0.AddMinutes(-10));
                foreach (var d in new[] { 200, 210, 190 }) b.Sample(d, t0.AddMinutes(-10));
                check("综合分：都稳定时低延迟优先", a.Score(t0) < b.Score(t0), null);
                st3.DisabledSubscriptions.Add("A1");
                var cOff = Subscriptions.Build(vd, subs3, st3, DateTime.Now);
                check("停用订阅后其节点从汇总中移除（订阅切换）", !cOff.Contains("Kitty Network") && cOff.Contains("Japan-V1") && !subs3[0].Enabled, null);
                st3.DisabledSubscriptions = new List<string> { "A1", "B2" };
                var c3 = Subscriptions.ParseProxies(Subscriptions.Build(vd, subs3, st3, DateTime.Now));
                check("全部停用 → 只剩占位节点（等同拒绝，不回退直连）", c3.Count == 1 && c3[0].Name == Subscriptions.Placeholder, null);
                var js = VergeOverride.BuildBlock(st3);
                check("覆写脚本：Japan Auto 引用汇总 provider，且不含 DIRECT", js.Contains("use: [CVG.provider]") && js.Contains("type: \"file\"") && !js.Contains("\"DIRECT\""), null);
            }

            Console.WriteLine("自动套用覆写到 Clash 运行配置（订阅更新后免手动刷新）");
            {
                // 仿 Clash Verge 生成的 clash-verge.yaml：块写法、列表短横线顶格、没有 listeners/proxy-providers
                var rt = "mixed-port: 17990\r\nallow-lan: false\r\nmode: rule\r\nlog-level: warning\r\nproxies:\r\n- name: \"Japan-1\"\r\n  type: socks5\r\n  server: 127.0.0.1\r\n  port: 9\r\nproxy-groups:\r\n- name: 节点选择\r\n  type: select\r\n  proxies:\r\n  - Japan-1\r\n  - DIRECT\r\nrule-providers:\r\n  demo:\r\n    type: inline\r\n    behavior: domain\r\n    payload:\r\n    - example.com\r\nrules:\r\n- RULE-SET,demo,DIRECT\r\n- MATCH,节点选择\r\n";
                var p = VergeOverride.PatchRuntimeYaml(rt, st);
                check("套用后含专用入口、Japan Auto 组、汇总 provider", p != null && p.Contains(VergeOverride.ListenerName) && p.Contains("\"" + st.JapanGroupName + "\"") && p.Contains("\"" + Subscriptions.ProviderName + "\": {type: file"), null);
                var ls = p.Replace("\r", "").Split('\n').ToList();
                int ri = ls.IndexOf("rules:");
                check("Claude 规则插在规则最前，原规则顺序不变", ri >= 0 && ls[ri + 1].Contains("PROCESS-NAME-REGEX") && p.IndexOf("- RULE-SET,demo,DIRECT") < p.IndexOf("- MATCH,节点选择") && p.IndexOf("DOMAIN-SUFFIX,claude.ai") < p.IndexOf("- RULE-SET,demo"), null);
                check("原有组/节点/规则行全部保留", rt.Replace("\r", "").Split('\n').Where(l => l != "").All(l => ls.Contains(l)), null);
                check("已含专用入口时不重复套用", VergeOverride.PatchRuntimeYaml(p, st) == null, null);
                check("保持 CRLF 换行", !p.Replace("\r\n", "").Contains("\n"), null);
                bool threw = false;
                try { VergeOverride.PatchRuntimeYaml(rt.Replace("rules:\r\n- RULE-SET,demo,DIRECT\r\n- MATCH,节点选择\r\n", "rules: [MATCH,DIRECT]\r\n"), st); } catch (InvalidOperationException) { threw = true; }
                check("行内写法不认识 → 拒绝自动套用（改为提示手动刷新）", threw, null);
                var p2 = VergeOverride.PatchRuntimeYaml(rt + "listeners: []\r\nproxy-providers: {}\r\n", st);
                check("空的 listeners: [] / proxy-providers: {} 也能套用", p2 != null && !p2.Contains("listeners: []") && !p2.Contains("proxy-providers: {}") && p2.Contains(VergeOverride.ListenerName), null);

                // 真实内核校验：Clash Verge 自带的 verge-mihomo 能否解析套用后的配置
                var bin = MihomoInstance.FindBinary();
                if (bin != null)
                {
                    var wd = Path.Combine(tmp, "hotload-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                    Directory.CreateDirectory(wd);
                    File.WriteAllText(Path.Combine(wd, Subscriptions.ProviderFile), "proxies:\n- {name: \"[A] Japan-1\", type: socks5, server: 127.0.0.1, port: 9}\n", new UTF8Encoding(false));
                    File.WriteAllText(Path.Combine(wd, "cfg.yaml"), p, new UTF8Encoding(false));
                    var psi = new System.Diagnostics.ProcessStartInfo(bin, "-t -d \"" + wd + "\" -f \"" + Path.Combine(wd, "cfg.yaml") + "\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                    string outp; int code;
                    using (var pr = System.Diagnostics.Process.Start(psi)) { outp = pr.StandardOutput.ReadToEnd() + pr.StandardError.ReadToEnd(); pr.WaitForExit(20000); code = pr.ExitCode; }
                    check("真实 Mihomo 内核能解析套用后的配置（-t 校验）", code == 0, outp.Trim().Split('\n').LastOrDefault());
                }
                else Console.WriteLine("  [跳过] 未找到 verge-mihomo.exe，跳过真实内核解析校验");
            }

            Console.WriteLine("会话快照与待恢复清单");
            var cap = SessionSnapshot.Capture();
            check("真实系统：识别正在运行的 Claude Code 会话（只读）", cap.Any(x => x.LocalId != null) && cap.All(x => x.LocalId == null || x.LocalId.StartsWith("local_")), string.Join(" | ", cap.Select(x => x.LocalId + " " + x.Title + (x.Busy ? " [执行中]" : ""))));
            var plan = SessionSnapshot.WritePending(new List<SessionInfo> { new SessionInfo { LocalId = "local_a", Title = "任务A", Busy = true }, new SessionInfo { LocalId = "local_b", Title = "任务B" }, new SessionInfo { CliId = "x" } }, "测试原因");
            var back = SessionSnapshot.ReadPending();
            check("清单写入/读回（无桌面会话 ID 的条目被丢弃）", back != null && back.Id == plan.Id && back.Sessions.Count == 2 && back.Status == "pending", back == null ? "null" : back.Sessions.Count.ToString());
            var prompt = SessionSnapshot.CoordinatorPrompt(back);
            check("协调提示词包含每个会话 ID、标题与执行状态", prompt.Contains("local_a") && prompt.Contains("任务B") && prompt.Contains("中断时正在执行") && prompt.Contains("SendMessage"), null);
            check("协调提示词长度适合深链接", Uri.EscapeDataString(prompt).Length < 8000, Uri.EscapeDataString(prompt).Length.ToString());

            Console.WriteLine("局域网 / 网络环境审计（真实系统只读）");
            SpacedeskInfo sd = null; string sdErr = null;
            try { sd = SpacedeskInfo.Detect(); } catch (Exception ex) { sdErr = ex.Message; }
            check("spacedesk 识别不抛异常", sd != null, sdErr ?? sd.Describe());
            var fnd = NetEnv.Audit(st);
            check("网络环境审计覆盖：网卡/默认路由/IP 转发/ICS/WinHTTP/系统代理", new[] { "网卡", "默认路由", "IP 转发", "Internet 连接共享 ICS", "WinHTTP 代理", "系统代理(WinINET)" }.All(a => fnd.Any(x => x.Area == a)), string.Join(",", fnd.Select(x => x.Area).Distinct()));
            check("代理监听端口不含专用入口", !NetEnv.ProxyListenerPorts(st.DedicatedPort).Contains(st.DedicatedPort), null);
        }
    }
}
