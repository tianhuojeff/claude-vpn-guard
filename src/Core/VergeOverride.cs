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
            return user.TrimEnd() + "\n\n" + BuildBlock(st) +
                "function main(config, profileName) { return cvgApply(cvgUserMain(config, profileName)); }\n";
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
