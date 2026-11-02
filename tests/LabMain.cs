// written_by: claude-code
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace ClaudeVPNGuard
{
    static partial class Lab
    {
        public static int Run(string[] args)
        {
            if (MihomoInstance.FindBinary() == null) { Console.WriteLine("未找到 verge-mihomo.exe，跳过私有 Mihomo 实验"); return 2; }
            var work = Path.Combine(Path.GetTempPath(), "cvg-lab-work-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(work);
            GuardPaths.DataDirOverride = Path.Combine(work, "data");
            Log.Dir = Path.Combine(work, "logs");
            var nodes = args.Length > 1 && args[1] == "verge-dryrun" ? new System.Collections.Generic.List<FakeNode>() : MakeNodes();
            Out("Claude VPN Guard 私有 Mihomo 实验  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  内核：" + MihomoInstance.FindBinary());
            try
            {
                if (args.Length > 1 && args[1] == "verge-dryrun")
                {
                    // 只读：读取真实 Script.js 与真实节点名，在临时目录用 node 执行生成的脚本，不写入 Clash Verge
                    var st = new GuardSettings(); st.Normalize();
                    string d;
                    var cl = MihomoClient.Discover(st, out d);
                    var names = cl.Proxies().Where(kv => kv.Value.Type != "Selector" && kv.Value.Type != "URLTest" && kv.Value.Type != "Fallback" && kv.Value.Type != "LoadBalance")
                        .Select(kv => kv.Key).Where(k => k != "GLOBAL").ToList();
                    var groups = cl.Proxies().Where(kv => kv.Value.Type == "Selector" || kv.Value.Type == "URLTest").Select(kv => kv.Key).Where(k => k != "GLOBAL").ToList();
                    var baseCfg = new System.Collections.Generic.Dictionary<string, object>
                    {
                        { "proxies", names.Where(n => !new[] { "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE" }.Contains(n)).Select(n => new System.Collections.Generic.Dictionary<string, object> { { "name", n }, { "type", "vless" } }).ToList() },
                        { "proxy-groups", groups.Select(g => new System.Collections.Generic.Dictionary<string, object> { { "name", g }, { "type", "select" }, { "proxies", new[] { "DIRECT" } } }).ToList() },
                        { "rules", new[] { "DOMAIN-SUFFIX,example.cn,DIRECT", "MATCH,节点选择" } }
                    };
                    var vdir = VergeOverride.FindVergeDataDir();
                    var userScript = File.ReadAllText(Path.Combine(vdir, "profiles", "Script.js"));
                    var composed = VergeOverride.Compose(userScript, st);
                    var outJson = MihomoInstance.RunScriptWithNode(composed, Json.Serialize(baseCfg), work);
                    var o = Json.Parse(outJson);
                    var jg = Json.Arr(o, "proxy-groups").First(g => Json.Str(g, "name") == st.JapanGroupName);
                    Out("真实节点 " + names.Count + " 个，原有组：" + string.Join("、", groups));
                    Out("Japan Auto 成员：" + string.Join("、", Json.Arr(jg, "proxies").Select(x => x.ToString())));
                    Out("原有组是否保留：" + string.Join("、", groups.Select(g => g + "=" + Json.Arr(o, "proxy-groups").Any(x => Json.Str(x, "name") == g))));
                    Out("listener：" + Json.Serialize(Json.Arr(o, "listeners").First()));
                    Out("规则前 7 条：" + string.Join(" | ", Json.Arr(o, "rules").Take(7).Select(x => x.ToString())));
                    Out("生成的 Script.js（未写入）：\n" + composed);
                    return 0;
                }
                if (args.Length > 1 && args[1] == "bench")
                {
                    int n = args.Length > 2 ? int.Parse(args[2]) : 20;
                    Bench(nodes, work, n);
                    if (args.Length > 3) File.WriteAllText(args[3], Report.ToString(), new UTF8Encoding(false));
                    Out(string.Format("\n测量合计：通过 {0}，失败 {1}", pass, fail));
                    return fail == 0 ? 0 : 1;
                }
                if (args.Length > 1 && args[1] == "delay")
                {
                    using (var m = StartLab(nodes, "rule", LabSettings(), work))
                    {
                        var c = m.Client();
                        for (int i = 0; i < 8; i++)
                        {
                            var sw = System.Diagnostics.Stopwatch.StartNew();
                            var line = string.Join("  ", nodes.Take(4).Select(n => n.Name.Substring(n.Name.Length - 2) + "=" + c.Delay(n.Name, LabSettings().NodeTestUrl, 3000)));
                            Out(line + "  (" + sw.ElapsedMilliseconds + "ms) hits=" + string.Join(",", nodes.Take(4).Select(n => n.Hits)));
                        }
                        Out(c.Request("GET", "/proxies/" + Uri.EscapeDataString(nodes[1].Name) + "/delay?timeout=3000&url=" + Uri.EscapeDataString(LabSettings().NodeTestUrl)).Body); Out("last target: " + nodes[1].LastTarget); foreach (var e in FakeNode.Errors.Take(5)) Out("ERR " + e); foreach (var e in FakeNode.Seen.Take(6)) Out("SEEN " + e);
                    }
                    return 0;
                }
                Semantics(nodes, work);
                RunScenarios(nodes, work, args);
            }
            catch (Exception ex) { fail++; Out("实验异常：" + ex); }
            finally { foreach (var n in nodes) n.Stop(); try { Directory.Delete(work, true); } catch { } }
            Out(string.Format("\n实验合计：通过 {0}，失败 {1}", pass, fail));
            var outFile = args.Length > 1 ? args[1] : null;
            if (outFile != null) File.WriteAllText(outFile, Report.ToString(), new UTF8Encoding(false));
            return fail == 0 ? 0 : 1;
        }
    }
}
