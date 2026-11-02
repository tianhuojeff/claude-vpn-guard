// written_by: claude-code
// Clash Verge Rev 全局扩展脚本（profiles\Script.js，uid=Script）生成与安装。
// 已在 Clash Verge Rev 2.5.8 上核实：profiles.yaml 中存在全局 uid "Script"(type: script) 与 "Merge"，
// 对所有订阅生效，订阅更新不会覆盖。脚本入口 function main(config, profileName)。
// 本脚本只做三件事，不改动任何已有代理组/节点/规则顺序（只在规则最前面插入 Claude 专用规则）：
//   1) 新增 "Japan Auto" select 组：REJECT + 保护器汇总的全部订阅日本节点（proxy-provider 文件，见 Subscriptions.cs），无 DIRECT
//   2) 新增专用入口 listener 127.0.0.1:<端口>，proxy: "Japan Auto" —— 该入口流量跳过模式/规则，直接交给 Japan Auto
//   3) 规则最前插入 Claude 域名/进程 → Japan Auto（规则模式 + TUN 时的额外保障）
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ClaudeVPNGuard
{
    public static class VergeOverride
    {
        public const string BeginMark = "// ===== ClaudeVPNGuard:BEGIN (由 Claude VPN Guard 生成，请勿手改此段) =====";
        public const string EndMark = "// ===== ClaudeVPNGuard:END =====";
        public const string ListenerName = "claude-guard-in";

        static string JsStr(string s)
        {
            var sb = new StringBuilder("\"");
            foreach (var ch in s ?? "")
            {
                if (ch == '"' || ch == '\\') sb.Append('\\').Append(ch);
                else if (ch < 0x20 || ch > 0x7e) sb.AppendFormat("\\u{0:x4}", (int)ch);
                else sb.Append(ch);
            }
            return sb.Append('"').ToString();
        }
        static string JsArr(IEnumerable<string> a) { return "[" + string.Join(", ", (a ?? new string[0]).Select(JsStr)) + "]"; }

        public static string BuildBlock(GuardSettings st)
        {
            var sb = new StringBuilder();
            sb.AppendLine(BeginMark);
            sb.AppendLine("var CVG = {");
            sb.AppendLine("  group: " + JsStr(st.JapanGroupName) + ",");
            sb.AppendLine("  listener: " + JsStr(ListenerName) + ",");
            sb.AppendLine("  port: " + st.DedicatedPort + ",");
            sb.AppendLine("  includeRe: new RegExp(" + JsStr(st.JapanNameRegex) + ", \"i\"),");
            sb.AppendLine("  infoRe: new RegExp(" + JsStr(st.InfoNodeRegex) + ", \"i\"),");
            sb.AppendLine("  extraInclude: " + JsArr(st.JapanInclude) + ",");
            sb.AppendLine("  exclude: " + JsArr(st.JapanExclude) + ",");
            sb.AppendLine("  domains: " + JsArr(st.ClaudeDomains) + ",");
            sb.AppendLine("  provider: " + JsStr(Subscriptions.ProviderName) + ",");
            sb.AppendLine("  providerFile: " + JsStr(Subscriptions.ProviderFile) + ",");
            sb.AppendLine("  placeholder: " + JsStr(Subscriptions.Placeholder) + ",");
            sb.AppendLine("  processRe: \"(?i)^claude\\\\.exe$\"");
            sb.AppendLine("};");
            sb.AppendLine(@"function cvgApply(config) {
  if (!config || typeof config !== ""object"") return config;
  // 节点来自保护器汇总的全部订阅日本节点（内核工作目录 cvg-japan.yaml），订阅变化时由保护器热刷新；
  // 汇总文件最后一项是指向 127.0.0.1:9 的占位节点（连接必被拒绝）：没有日本节点时组内只剩它，等同拒绝，绝不回退 DIRECT / 其他国家
  var pp = config[""proxy-providers""] || {};
  pp[CVG.provider] = { type: ""file"", path: ""./"" + CVG.providerFile };
  config[""proxy-providers""] = pp;
  var groups = config[""proxy-groups""] || [];
  var kept = [];
  for (var g = 0; g < groups.length; g++) if (!groups[g] || groups[g].name !== CVG.group) kept.push(groups[g]);
  kept.push({ name: CVG.group, type: ""select"", use: [CVG.provider] });
  config[""proxy-groups""] = kept;
  var ls = config.listeners || [];
  var keptL = [];
  for (var l = 0; l < ls.length; l++) if (!ls[l] || ls[l].name !== CVG.listener) keptL.push(ls[l]);
  keptL.push({ name: CVG.listener, type: ""mixed"", listen: ""127.0.0.1"", port: CVG.port, udp: true, proxy: CVG.group });
  config.listeners = keptL;
  var rules = config.rules || [];
  var pre = [""PROCESS-NAME-REGEX,"" + CVG.processRe + "","" + CVG.group];
  for (var d = 0; d < CVG.domains.length; d++) pre.push(""DOMAIN-SUFFIX,"" + CVG.domains[d] + "","" + CVG.group);
  var rest = [];
  for (var r = 0; r < rules.length; r++) if (pre.indexOf(rules[r]) < 0) rest.push(rules[r]);
  config.rules = pre.concat(rest);
  return config;
}");
            sb.AppendLine(EndMark);
            return sb.ToString();
        }

        // 组装完整 Script.js：保留用户原有 main 的逻辑（重命名为 cvgUserMain），在其返回值上再套用本段
        public static string Compose(string existing, GuardSettings st)
        {
            var user = StripBlock(existing ?? "");
            user = user.Replace("function main(", "function cvgUserMain(");
            if (!user.Contains("function cvgUserMain(")) user += "\nfunction cvgUserMain(config, profileName) { return config; }\n";
            return user.TrimEnd() + "\n\n" + BuildBlock(st) + MainWrapper + "\n";
        }

        public static string StripBlock(string s)
        {
            int b = s.IndexOf(BeginMark, StringComparison.Ordinal);
            if (b < 0) return s;
            int e = s.IndexOf(EndMark, b, StringComparison.Ordinal);
            if (e < 0) return s;
            var before = s.Substring(0, b);
            var after = s.Substring(e + EndMark.Length);
            // 去掉我们追加的 main 包装
            after = System.Text.RegularExpressions.Regex.Replace(after, @"\s*function main\(config, profileName\) \{ return cvgApply\(cvgUserMain\(config, profileName\)\); \}\s*", "\n");
            var r = (before + after).Replace("function cvgUserMain(", "function main(");
            return r.TrimEnd() + "\n";
        }

        public static string FindVergeDataDir()
        {
            var me = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var d = Path.Combine(me, "io.github.clash-verge-rev.clash-verge-rev");
            return Directory.Exists(d) ? d : null;
        }

        // 写入全局 Script.js（先备份原文件）。返回备份路径。需要用户在 Clash Verge 中刷新配置后生效。
        public static string Apply(string vergeDir, GuardSettings st)
        {
            var profiles = Path.Combine(vergeDir, "profiles");
            var yaml = File.ReadAllText(Path.Combine(vergeDir, "profiles.yaml"), Encoding.UTF8);
            if (!System.Text.RegularExpressions.Regex.IsMatch(yaml, @"uid:\s*Script\s*\r?\n\s*type:\s*script"))
                throw new InvalidOperationException("当前 Clash Verge 未发现全局扩展脚本（uid: Script），不支持自动写入");
            var file = Path.Combine(profiles, "Script.js");
            var old = File.Exists(file) ? File.ReadAllText(file, Encoding.UTF8) : "function main(config, profileName) {\n  return config;\n}\n";
            var backup = file + ".cvg-backup-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
            File.WriteAllText(backup, old, new UTF8Encoding(false));
            File.WriteAllText(file, Compose(old, st), new UTF8Encoding(false));
            Log.Action("已写入 Clash Verge 全局扩展脚本（Japan Auto + 专用入口），备份：" + backup);
            return backup;
        }

        public const string MainWrapper = "function main(config, profileName) { return cvgApply(cvgUserMain(config, profileName)); }";

        // 用户找覆写时容易看错地方：本程序写的是「全局扩展脚本」，不是「全局扩展覆写配置」(Merge)
        public const string WhereGuide = "本程序的覆写写在 Clash Verge →「订阅」页 →「全局扩展脚本」(Script.js) 里，段首是 “ClaudeVPNGuard:BEGIN”；不在「全局扩展覆写配置」(Merge)。";
        public const string RefreshGuide = "请打开 Clash Verge →「订阅」→ 在当前使用的订阅上右键「刷新」（或重启 Clash Verge），Clash 重新生成配置后 Japan Auto 组和专用入口 127.0.0.1:17897 才会出现。刷新会短暂中断代理；在此之前 Claude 保持断网，不会直连。";

        public static string ScriptFile(string vergeDir) { return Path.Combine(vergeDir, "profiles", "Script.js"); }

        // 脚本里有与当前设置一致的本程序段（含 main 包装）
        public static bool HasCurrentBlock(string script, GuardSettings st)
        {
            var s = (script ?? "").Replace("\r", "");
            return s.Contains(BuildBlock(st).Replace("\r", "")) && s.Contains(MainWrapper);
        }

        // 覆写段缺失或与当前设置不一致时重新写入（先备份）；已正确返回 null，否则返回备份路径
        public static string Ensure(string vergeDir, GuardSettings st)
        {
            var file = ScriptFile(vergeDir);
            if (File.Exists(file) && HasCurrentBlock(File.ReadAllText(file, Encoding.UTF8), st)) return null;
            return Apply(vergeDir, st);
        }

        // Clash Verge 生成的运行配置（clash-verge.yaml）是否已套用当前脚本：含专用入口，且生成时间不早于脚本
        public static bool RuntimeLoaded(string vergeDir)
        {
            var rt = Path.Combine(vergeDir, "clash-verge.yaml");
            var sc = ScriptFile(vergeDir);
            if (!File.Exists(rt) || !File.Exists(sc)) return false;
            return File.ReadAllText(rt, Encoding.UTF8).Contains(ListenerName) && File.GetLastWriteTimeUtc(rt) >= File.GetLastWriteTimeUtc(sc);
        }

        // ── 自动套用：Verge 只在刷新/更新订阅时执行脚本；脚本刚补写、Clash 还没重新生成时，
        // 保护器自己对 Verge 当前运行配置做与 cvgApply 相同的改动，再让内核重载（PUT /configs payload）。
        // 之后 Verge 再生成配置时会执行 Script.js，结果一致。只做加法：新增 provider/组/入口，规则最前插入。
        static readonly System.Text.RegularExpressions.Regex TopKey = new System.Text.RegularExpressions.Regex(@"^([A-Za-z0-9_-]+):(.*)$");

        static int FindTopKey(List<string> lines, string key, out string rest)
        {
            rest = null;
            for (int i = 0; i < lines.Count; i++)
            {
                var m = TopKey.Match(lines[i]);
                if (m.Success && m.Groups[1].Value == key) { rest = m.Groups[2].Value.Trim(); return i; }
            }
            return -1;
        }

        // 在顶层 key 下插入条目；items 为不带缩进的行（"- {...}" 或 "name: {...}"），按下一行的缩进对齐
        static void InsertUnder(List<string> lines, string key, List<string> items, string emptyFlow, bool isList)
        {
            string rest;
            int i = FindTopKey(lines, key, out rest);
            if (i < 0) { lines.Add(key + ":"); lines.AddRange(items.Select(x => (isList ? "" : "  ") + x)); return; }
            if (rest == emptyFlow || rest == "" && (i + 1 >= lines.Count || TopKey.IsMatch(lines[i + 1])))
            {
                lines[i] = key + ":";
                lines.InsertRange(i + 1, items.Select(x => (isList ? "" : "  ") + x));
                return;
            }
            if (rest != "" && !rest.StartsWith("#")) throw new InvalidOperationException("运行配置中 " + key + " 为行内写法，不支持自动套用");
            var next = lines[i + 1];
            var indent = next.Substring(0, next.Length - next.TrimStart().Length);
            lines.InsertRange(i + 1, items.Select(x => indent + x));
        }

        // 返回套用后的 YAML；已含专用入口返回 null
        public static string PatchRuntimeYaml(string yaml, GuardSettings st)
        {
            if (yaml == null) throw new ArgumentNullException("yaml");
            if (yaml.Contains(ListenerName)) return null;
            var nl = yaml.Contains("\r\n") ? "\r\n" : "\n";
            var lines = yaml.Replace("\r\n", "\n").Split('\n').ToList();
            while (lines.Count > 0 && lines[lines.Count - 1] == "") lines.RemoveAt(lines.Count - 1);
            var q = (Func<string, string>)JsStr; // JSON 风格双引号串即合法 YAML 双引号串
            var gname = q(st.JapanGroupName);
            if (System.Text.RegularExpressions.Regex.IsMatch(yaml, @"(?m)^\s*-?\s*name:\s*(" + System.Text.RegularExpressions.Regex.Escape(st.JapanGroupName) + "|" + System.Text.RegularExpressions.Regex.Escape(gname) + @")\s*$"))
                throw new InvalidOperationException("运行配置里已有同名组 " + st.JapanGroupName + "，不自动套用");
            InsertUnder(lines, "proxy-providers", new List<string> { q(Subscriptions.ProviderName) + ": {type: file, path: " + q("./" + Subscriptions.ProviderFile) + "}" }, "{}", false);
            InsertUnder(lines, "proxy-groups", new List<string> { "- {name: " + gname + ", type: select, use: [" + q(Subscriptions.ProviderName) + "]}" }, "[]", true);
            InsertUnder(lines, "listeners", new List<string> { "- {name: " + q(ListenerName) + ", type: mixed, listen: \"127.0.0.1\", port: " + st.DedicatedPort + ", udp: true, proxy: " + gname + "}" }, "[]", true);
            var pre = new List<string> { "- " + q("PROCESS-NAME-REGEX,(?i)^claude\\.exe$," + st.JapanGroupName) };
            pre.AddRange(st.ClaudeDomains.Select(d => "- " + q("DOMAIN-SUFFIX," + d + "," + st.JapanGroupName)));
            InsertUnder(lines, "rules", pre, "[]", true);
            return string.Join(nl, lines) + nl;
        }

        public static string RuntimeFile(string vergeDir) { return Path.Combine(vergeDir, "clash-verge.yaml"); }

        // 对运行配置套用并让内核重载；已套用返回 false。会短暂断开 Clash 现有连接。
        public static bool HotLoad(string vergeDir, GuardSettings st, MihomoClient c)
        {
            var rt = RuntimeFile(vergeDir);
            if (!File.Exists(rt)) throw new FileNotFoundException("没有 Clash Verge 运行配置 clash-verge.yaml");
            var patched = PatchRuntimeYaml(File.ReadAllText(rt, Encoding.UTF8), st);
            if (patched == null) return false;
            if (c == null) throw new InvalidOperationException("Clash 内核控制接口不可用");
            var saved = c.TimeoutMs;
            try
            {
                c.TimeoutMs = Math.Max(saved, 10000);
                var r = c.Request("PUT", "/configs?force=true", Json.Serialize(new Dictionary<string, object> { { "path", "" }, { "payload", patched } }));
                if (r.Status != 204 && r.Status != 200) throw new IOException("内核重载配置失败 HTTP " + r.Status + " " + r.Body);
            }
            finally { c.TimeoutMs = saved; }
            // 写回运行配置，状态判断与 Verge 下次直接重载都以它为准（Verge 重新生成时会覆盖，结果相同）
            var tmp = rt + ".cvg-tmp";
            File.WriteAllText(tmp, patched, new UTF8Encoding(false));
            File.Replace(tmp, rt, null);
            Log.Action("已自动把覆写套用到 Clash 当前配置并重载内核（Japan Auto + 专用入口 " + st.DedicatedPort + "），无需在 Clash Verge 手动刷新");
            return true;
        }

        public static string LatestBackup(string vergeDir)
        {
            var d = Path.Combine(vergeDir, "profiles");
            return Directory.GetFiles(d, "Script.js.cvg-backup-*").OrderByDescending(f => f).FirstOrDefault();
        }

        // 行级差异（LCS），返回 "+ 行" / "- 行" / "  行"
        public static List<string> LineDiff(string a, string b)
        {
            var x = (a ?? "").Replace("\r", "").Split('\n'); var y = (b ?? "").Replace("\r", "").Split('\n');
            var L = new int[x.Length + 1, y.Length + 1];
            for (int i = x.Length - 1; i >= 0; i--) for (int j = y.Length - 1; j >= 0; j--)
                    L[i, j] = x[i] == y[j] ? L[i + 1, j + 1] + 1 : Math.Max(L[i + 1, j], L[i, j + 1]);
            var res = new List<string>();
            int p = 0, q = 0;
            while (p < x.Length && q < y.Length)
            {
                if (x[p] == y[q]) { res.Add("  " + x[p]); p++; q++; }
                else if (L[p + 1, q] >= L[p, q + 1]) res.Add("- " + x[p++]);
                else res.Add("+ " + y[q++]);
            }
            while (p < x.Length) res.Add("- " + x[p++]);
            while (q < y.Length) res.Add("+ " + y[q++]);
            return res;
        }

        // 差异报告：文件级差异 + 语义变化说明
        public static List<string> DiffReport(string vergeDir, GuardSettings st)
        {
            var r = new List<string>();
            var file = Path.Combine(vergeDir, "profiles", "Script.js");
            var cur = File.Exists(file) ? File.ReadAllText(file, Encoding.UTF8) : "";
            var bak = LatestBackup(vergeDir);
            var old = bak != null ? File.ReadAllText(bak, Encoding.UTF8) : StripBlock(cur);
            r.Add("当前文件：" + file);
            r.Add("对比基准：" + (bak ?? "（无备份，以去除本程序段后的内容为基准）"));
            r.Add("本程序段：" + (cur.Contains(BeginMark) ? "已写入" : "未写入"));
            r.Add("用户原脚本是否完整保留（去除本程序段后与备份一致）：" + (StripBlock(cur).Replace("\r", "").Trim() == old.Replace("\r", "").Trim() ? "是" : "否（备份后用户又改过脚本，或备份不是最近一次写入前的版本）"));
            r.Add("语义变化（Clash 刷新后生效）：");
            r.Add("  + 新增代理组 " + st.JapanGroupName + "（select）：REJECT + 汇总文件 " + Subscriptions.ProviderFile + "（全部已启用订阅中节点名匹配 /" + st.JapanNameRegex + "/i 且不匹配 /" + st.InfoNodeRegex + "/i 的节点，名前加 [订阅名]）；不含 DIRECT");
            r.Add("  + 新增 proxy-provider " + Subscriptions.ProviderName + "：type file，路径为内核工作目录内的 " + Subscriptions.ProviderFile + "，订阅变化时由保护器热刷新");
            r.Add("  + 新增 listener " + ListenerName + "：mixed 127.0.0.1:" + st.DedicatedPort + "，proxy=" + st.JapanGroupName);
            r.Add("  + 规则最前插入：PROCESS-NAME-REGEX claude.exe 与 " + string.Join("、", st.ClaudeDomains) + " → " + st.JapanGroupName);
            r.Add("  = 不修改：GLOBAL、其他所有代理组、节点、订阅、原有规则顺序、端口、DNS、TUN 设置");
            r.Add("文件差异：");
            r.AddRange(LineDiff(old, cur).Where(l => !l.StartsWith("  ")).Select(l => "  " + l));
            return r;
        }

        // 用备份恢复（恢复前先把当前文件再备份一次）
        public static string Restore(string vergeDir, string backup)
        {
            var file = Path.Combine(vergeDir, "profiles", "Script.js");
            backup = backup ?? LatestBackup(vergeDir);
            if (backup == null || !File.Exists(backup)) throw new FileNotFoundException("没有可用的备份");
            if (File.Exists(file)) File.Copy(file, file + ".cvg-before-restore-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"), true);
            File.Copy(backup, file, true);
            Log.Action("已用备份恢复 Clash Verge 全局扩展脚本：" + backup);
            return backup;
        }

        public static void Remove(string vergeDir)
        {
            var file = Path.Combine(vergeDir, "profiles", "Script.js");
            if (!File.Exists(file)) return;
            var s = File.ReadAllText(file, Encoding.UTF8);
            File.WriteAllText(file, StripBlock(s), new UTF8Encoding(false));
            Log.Action("已从 Clash Verge 全局扩展脚本移除 Claude VPN Guard 段");
        }
    }
}
