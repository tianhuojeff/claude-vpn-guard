// written_by: claude-code
// 私有 Mihomo 实验（ClaudeVPNGuard.Tests.exe --lab）：真实 Mihomo 内核 + 假节点，离线、仅回环。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace ClaudeVPNGuard
{
    static partial class Lab
    {
        public static int pass, fail;
        public static StringBuilder Report = new StringBuilder();

        public static void Out(string s) { Console.WriteLine(s); Report.AppendLine(s); }
        public static void Check(string name, bool ok, string info)
        {
            if (ok) pass++; else fail++;
            Out((ok ? "  [通过] " : "  [失败] ") + name + (string.IsNullOrEmpty(info) ? "" : "  → " + info));
        }

        public static List<FakeNode> MakeNodes()
        {
            var list = new List<FakeNode>
            {
                new FakeNode("\U0001F1EF\U0001F1F5Japan 01", 28001), new FakeNode("\U0001F1EF\U0001F1F5Japan 02", 28002),
                new FakeNode("\U0001F1EF\U0001F1F5Japan 03", 28003), new FakeNode("\U0001F1EF\U0001F1F5Japan 04", 28004),
                new FakeNode("\U0001F1F0\U0001F1F7Korea 01", 28011) { Country = "KR" },
                new FakeNode("\U0001F1FA\U0001F1F8United States 01", 28012) { Country = "US" },
                new FakeNode("\U0001F1E6\U0001F1F1 剩余流量：860 GB", 28013),
            };
            foreach (var n in list) n.Start();
            return list;
        }

        public static GuardSettings LabSettings()
        {
            var st = new GuardSettings();
            st.DedicatedPort = 27917;
            st.NodeTestUrl = "http://probe.cvg.test/generate_204";
            st.ExitTraceUrl = "http://trace.cvg.test/cdn-cgi/trace";
            st.Normalize();
            return st;
        }

        public static MihomoInstance StartLab(List<FakeNode> nodes, string mode, GuardSettings st, string workDir)
        {
            var script = VergeOverride.Compose("function main(config, profileName) {\n  return config;\n}\n", st);
            var cfg = MihomoInstance.RunScriptWithNode(script, MihomoInstance.BaseConfig(nodes, mode), workDir);
            var m = new MihomoInstance();
            m.Start(cfg);
            return m;
        }

        // E1：专用入口的路由语义（决定整个隔离方案是否成立）
        public static void Semantics(List<FakeNode> nodes, string work)
        {
            Out("\n[E1] 专用入口语义：模式/规则/GLOBAL 被改成直连时，专用入口是否仍只走 Japan Auto");
            var st = LabSettings();
            using (var m = StartLab(nodes, "direct", st, work))
            {
                var c = m.Client();
                var px = c.Proxies();
                ProxyInfo g;
                bool hasGroup = px.TryGetValue(st.JapanGroupName, out g);
                var all = hasGroup ? Json.Arr(Json.Parse(c.Request("GET", "/proxies/" + Uri.EscapeDataString(st.JapanGroupName)).Body), "all").Select(x => x.ToString()).ToList() : new List<string>();
                Check("覆写脚本生成 Japan Auto 组（select）", hasGroup && g.Type == "Selector", hasGroup ? g.Type : "缺失");
                Check("组内只有 4 个日本节点（排除韩国/美国/流量信息节点/DIRECT）",
                    all.Count == 4 && all.All(n => n.Contains("Japan")), string.Join(",", all));

                foreach (var n in nodes) n.Hits = 0;
                var viaGeneral = MihomoInstance.GetVia(m.MixedPort, "http://probe.cvg.test/x", 4000);
                Check("对照：模式=direct 时通用端口 " + m.MixedPort + " 直连（不经任何节点）", nodes.All(n => n.Hits == 0), "结果=" + (viaGeneral ?? "失败(直连解析不到测试域名)"));
                var viaDedicated = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/x", 4000);
                Check("模式=direct 时专用入口 " + m.DedicatedPort + " 仍走 Japan Auto", viaDedicated != null && viaDedicated.Contains("Japan"), viaDedicated);

                c.PatchConfig(new Dictionary<string, object> { { "mode", "global" } });
                c.SelectProxy("GLOBAL", "DIRECT");
                viaDedicated = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/x", 4000);
                Check("模式=global 且 GLOBAL 选 DIRECT 时专用入口仍走 Japan Auto", viaDedicated != null && viaDedicated.Contains("Japan"), viaDedicated);
                c.SelectProxy("GLOBAL", nodes[4].Name);
                viaDedicated = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/x", 4000);
                Check("GLOBAL 选韩国节点时专用入口仍走日本", viaDedicated != null && viaDedicated.Contains("Japan"), viaDedicated);

                c.PatchConfig(new Dictionary<string, object> { { "mode", "rule" } });
                viaDedicated = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/x", 4000);
                Check("模式=rule 且规则 MATCH,DIRECT 时专用入口仍走日本", viaDedicated != null && viaDedicated.Contains("Japan"), viaDedicated);

                string selErr = null;
                try { c.SelectProxy(st.JapanGroupName, "DIRECT"); } catch (Exception ex) { selErr = ex.Message; }
                Check("无法把 Japan Auto 切到 DIRECT（不在组内）", selErr != null, selErr);
                try { c.SelectProxy(st.JapanGroupName, nodes[4].Name); selErr = null; } catch (Exception ex) { selErr = ex.Message; }
                Check("无法把 Japan Auto 切到韩国节点", selErr != null, selErr);

                // 当前节点断线：专用入口应失败（不回退直连）
                c.SelectProxy(st.JapanGroupName, nodes[0].Name);
                nodes[0].Mode = FakeMode.Down;
                foreach (var n in nodes) n.Hits = 0;
                viaDedicated = MihomoInstance.GetVia(m.DedicatedPort, "http://probe.cvg.test/x", 4000);
                Check("当前日本节点断线 → 专用入口请求失败，不回退直连/其他节点", (viaDedicated == null || viaDedicated.StartsWith("HTTP5")) && nodes.Skip(1).All(n => n.Hits == 0), (viaDedicated ?? "失败") + "，其他节点命中 " + nodes.Skip(1).Sum(n => n.Hits));
                nodes[0].Mode = FakeMode.Up;

                // UDP：专用入口的 socks5 UDP 也受 proxy 约束？HTTP 假节点不支持 UDP，验证不会回退 DIRECT 由文档说明
            }
        }
    }
}
