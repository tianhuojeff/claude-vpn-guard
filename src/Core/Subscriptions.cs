// written_by: claude-code
// 多订阅日本节点汇总：读取 Clash Verge 的全部订阅（profiles.yaml），从每个订阅中挑出日本节点，
// 节点名加 "[订阅名] " 前缀后写入内核工作目录的 cvg-japan.yaml（proxy-provider 文件）。
// Japan Auto 组通过 use: [cvg-japan] 引用；订阅增删/更新后由服务重写文件并调用 PUT /providers/proxies/cvg-japan 热刷新。
// 节点内容逐字复制，不解析不改写除 name 以外的字段；文件只在本机内核目录，不外传。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ClaudeVPNGuard
{
    public class SubInfo
    {
        public string Uid, Name, Type, File;
        public long Upload, Download, Total, Expire;   // expire = unix 秒，0 = 未知
        public bool Current, Enabled, Expired, Exhausted;
        public int JapanCount;
        public string Tag;                               // 节点名前缀中显示的订阅名（已去掉会被误判为日本的字样）
        public bool Usable { get { return Enabled && !Expired && !Exhausted && JapanCount > 0; } }
    }

    public class ProxyItem { public string Name; public List<string> Lines = new List<string>(); public bool Flow; public int Indent; }

    public static class Subscriptions
    {
        public const string ProviderName = "cvg-japan";
        public const string ProviderFile = "cvg-japan.yaml";
        public const string Placeholder = "cvg-placeholder";

        // ===== profiles.yaml =====
        public static List<SubInfo> ParseProfiles(string yaml)
        {
            var res = new List<SubInfo>();
            string current = null;
            SubInfo cur = null;
            bool inExtra = false;
            foreach (var raw in yaml.Replace("\r", "").Split('\n'))
            {
                var line = raw.TrimEnd();
                if (line.Length == 0 || line.TrimStart().StartsWith("#")) continue;
                var m = Regex.Match(line, @"^current:\s*(\S+)");
                if (m.Success) { current = Unq(m.Groups[1].Value); continue; }
                if (line.StartsWith("- uid:")) { cur = new SubInfo { Uid = Unq(line.Substring(6).Trim()) }; res.Add(cur); inExtra = false; continue; }
                if (cur == null) continue;
                if (!line.StartsWith(" ")) { cur = null; continue; }
                var kv = Regex.Match(line, @"^(\s+)([\w-]+):\s*(.*)$");
                if (!kv.Success) continue;
                int ind = kv.Groups[1].Value.Length; var k = kv.Groups[2].Value; var v = Unq(kv.Groups[3].Value.Trim());
                if (ind == 2) { inExtra = k == "extra"; if (k == "type") cur.Type = v; else if (k == "name") cur.Name = v == "null" ? null : v; else if (k == "file") cur.File = v; }
                else if (ind == 4 && inExtra)
                {
                    long n; long.TryParse(v, out n);
                    if (k == "upload") cur.Upload = n; else if (k == "download") cur.Download = n; else if (k == "total") cur.Total = n; else if (k == "expire") cur.Expire = n;
                }
            }
            var subs = res.Where(s => (s.Type == "remote" || s.Type == "local") && s.File != null).ToList();
            foreach (var s in subs) s.Current = s.Uid == current;
            return subs;
        }

        static string Unq(string v)
        {
            v = v.Trim();
            if (v.Length >= 2 && v[0] == '\'' && v[v.Length - 1] == '\'') return v.Substring(1, v.Length - 2).Replace("''", "'");
            if (v.Length >= 2 && v[0] == '"' && v[v.Length - 1] == '"') return v.Substring(1, v.Length - 2).Replace("\\\"", "\"").Replace("\\\\", "\\");
            return v;
        }

        // ===== 订阅文件中的 proxies 段 =====
        static readonly Regex FlowName = new Regex(@"(?<=[{,]\s*)name:\s*('(?:[^']|'')*'|""(?:[^""\\]|\\.)*""|[^,}]+)");
        static readonly Regex BlockName = new Regex(@"^(\s*(?:-\s+)?)name:\s*(.+?)\s*$");

        public static List<ProxyItem> ParseProxies(string yaml)
        {
            var items = new List<ProxyItem>();
            var lines = yaml.Replace("\r", "").Split('\n');
            int i = Array.FindIndex(lines, l => Regex.IsMatch(l, @"^proxies:\s*$"));
            if (i < 0) return items;
            ProxyItem cur = null; int itemIndent = -1;
            for (i = i + 1; i < lines.Length; i++)
            {
                var l = lines[i];
                if (l.Trim().Length == 0 || l.TrimStart().StartsWith("#")) continue;
                int ind = l.Length - l.TrimStart().Length;
                bool dash = l.TrimStart().StartsWith("- ") || l.TrimStart() == "-";
                if (ind == 0 && !dash) break;                       // 下一个顶层键
                if (dash && (itemIndent < 0 || ind == itemIndent))
                {
                    itemIndent = ind;
                    cur = new ProxyItem { Indent = ind, Flow = l.TrimStart().Substring(1).TrimStart().StartsWith("{") };
                    cur.Lines.Add(l); items.Add(cur);
                    continue;
                }
                if (ind < itemIndent) break;
                if (cur != null) cur.Lines.Add(l);
            }
            foreach (var it in items)
            {
                if (it.Flow) { var m = FlowName.Match(string.Join(" ", it.Lines)); if (m.Success) it.Name = Unq(m.Groups[1].Value.Trim()); }
                else foreach (var l in it.Lines)
                    {
                        var m = BlockName.Match(l);
                        int ind = m.Success ? m.Groups[1].Value.Replace("-", " ").Length : -1;
                        if (m.Success && (ind == it.Indent + 2 || l.TrimStart().StartsWith("- "))) { it.Name = Unq(m.Groups[2].Value); break; }
                    }
            }
            return items.Where(x => !string.IsNullOrEmpty(x.Name)).ToList();
        }

        static string Q(string s) { return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\""; }

        // 把一个节点改名并重新缩进为 provider 文件中的条目（"  - ..."）
        public static string Render(ProxyItem it, string newName)
        {
            if (it.Flow)
            {
                var one = string.Join(" ", it.Lines.Select(x => x.Trim()));
                one = one.Substring(one.IndexOf('-') + 1).Trim();
                var m = FlowName.Match(one);
                one = one.Substring(0, m.Groups[1].Index) + Q(newName) + one.Substring(m.Groups[1].Index + m.Groups[1].Length);
                return "  - " + one + "\n";
            }
            var sb = new StringBuilder();
            bool done = false;
            foreach (var l in it.Lines)
            {
                var t = l.Length > it.Indent ? l.Substring(Math.Min(it.Indent, l.Length - l.TrimStart().Length)) : l.TrimStart();
                var m = BlockName.Match(t);
                // 只改条目本层的 name（缩进 2），不碰 ws-opts.headers 之类嵌套里的 name
                if (!done && m.Success && m.Groups[1].Value.Replace("-", " ").Length == 2) { t = m.Groups[1].Value + "name: " + Q(newName); done = true; }
                sb.Append("  ").Append(t).Append('\n');
            }
            return sb.ToString();
        }

        // 订阅名中会被识别为日本/信息节点的字样去掉，防止前缀把非日本节点“伪装”成日本节点
        public static string MakeTag(string name, GuardSettings st)
        {
            var t = name ?? "订阅";
            t = Regex.Replace(t, st.JapanNameRegex, "", RegexOptions.IgnoreCase);
            t = Regex.Replace(t, st.InfoNodeRegex, "", RegexOptions.IgnoreCase);
            t = Regex.Replace(t, @"[\[\]\r\n]", "").Trim();
            return t.Length == 0 ? "订阅" : t;
        }

        static bool IsJp(string n, GuardSettings st)
        {
            if (st.JapanExclude.Contains(n)) return false;
            if (st.JapanInclude.Contains(n)) return true;
            return Regex.IsMatch(n, st.JapanNameRegex, RegexOptions.IgnoreCase) && !Regex.IsMatch(n, st.InfoNodeRegex, RegexOptions.IgnoreCase);
        }

        // 汇总：返回 provider 文件内容；subs 的 JapanCount/Expired/Exhausted/Enabled/Tag 会被填好
        public static string Build(string vergeDir, List<SubInfo> subs, GuardSettings st, DateTime now)
        {
            var sb = new StringBuilder();
            sb.Append("# 由 Claude VPN Guard 生成：全部已启用订阅中的日本节点（").Append(now.ToString("yyyy-MM-dd HH:mm:ss")).Append("），请勿手改\n");
            sb.Append("proxies:\n");
            long unixNow = (long)(now.ToUniversalTime() - new DateTime(1970, 1, 1)).TotalSeconds;
            var used = new HashSet<string>();
            var tags = new HashSet<string>();
            foreach (var s in subs)
            {
                s.Enabled = !st.DisabledSubscriptions.Contains(s.Uid);
                s.Expired = s.Expire > 0 && s.Expire < unixNow;
                s.Exhausted = s.Total > 0 && s.Upload + s.Download >= s.Total;
                var tag = MakeTag(s.Name ?? s.Uid, st);
                for (int k = 2; tags.Contains(tag); k++) tag = MakeTag(s.Name ?? s.Uid, st) + k;
                tags.Add(tag); s.Tag = tag;
                List<ProxyItem> items;
                try { items = ParseProxies(File.ReadAllText(Path.Combine(vergeDir, "profiles", s.File), Encoding.UTF8)); }
                catch { items = new List<ProxyItem>(); }
                var jp = items.Where(x => IsJp(x.Name, st) || IsJp("[" + tag + "] " + x.Name, st)).ToList();
                s.JapanCount = jp.Count;
                if (!s.Usable) continue;
                foreach (var it in jp)
                {
                    var nn = "[" + tag + "] " + it.Name;
                    if (st.JapanExclude.Contains(nn) || !used.Add(nn)) continue;
                    sb.Append(Render(it, nn));
                }
            }
            // 占位放最后（不会成为默认节点）；文件永不为空，provider 不会加载失败
            sb.Append("  - {name: ").Append(Q(Placeholder)).Append(", type: http, server: 127.0.0.1, port: 9}\n");
            return sb.ToString();
        }

        // ===== 位置发现（服务以 SYSTEM 运行：扫描所有用户） =====
        public static string FindVergeDir()
        {
            var cands = new List<string>();
            var mine = VergeOverride.FindVergeDataDir();
            if (mine != null) cands.Add(mine);
            try
            {
                foreach (var u in Directory.GetDirectories(@"C:\Users"))
                {
                    var d = Path.Combine(u, @"AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev");
                    if (File.Exists(Path.Combine(d, "profiles.yaml"))) cands.Add(d);
                }
            }
            catch { }
            return cands.Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(d => File.GetLastWriteTime(Path.Combine(d, "profiles.yaml"))).FirstOrDefault();
        }

        // 内核工作目录（-d 参数）：provider 文件必须放在这里（Mihomo 只允许读取工作目录内的文件）
        public static string FindCoreHome()
        {
            try
            {
                using (var q = new System.Management.ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE Name LIKE 'verge-mihomo%'"))
                    foreach (System.Management.ManagementObject o in q.Get())
                    {
                        var cl = Convert.ToString(o["CommandLine"]);
                        var m = Regex.Match(cl ?? "", @"\s-d\s+(""[^""]+""|\S+)");
                        if (m.Success) return m.Groups[1].Value.Trim('"');
                    }
            }
            catch { }
            return null;
        }
    }

    // 服务端同步器：订阅/设置有变化就重写 provider 文件并热刷新
    public class SubscriptionSync
    {
        readonly GuardSettings st;
        readonly Func<MihomoClient> client;
        string lastSig, lastContent;
        DateTime lastHomeLookup = DateTime.MinValue;
        string home;
        public List<SubInfo> Subs = new List<SubInfo>();
        public string VergeDir, LastError;
        public DateTime LastWrite;
        public Action<string> Changed;

        public SubscriptionSync(GuardSettings st, Func<MihomoClient> client) { this.st = st; this.client = client; }

        public void ForceNext() { lastSig = null; }

        public void Tick()
        {
            VergeDir = Subscriptions.FindVergeDir();
            if (VergeDir == null) { LastError = "未找到 Clash Verge 数据目录"; return; }
            if (home == null || (DateTime.Now - lastHomeLookup).TotalSeconds > 30 || !Directory.Exists(home)) { home = Subscriptions.FindCoreHome(); lastHomeLookup = DateTime.Now; }
            if (home == null) { LastError = "未找到 Mihomo 内核工作目录"; return; }
            var py = Path.Combine(VergeDir, "profiles.yaml");
            var subs = Subscriptions.ParseProfiles(File.ReadAllText(py, Encoding.UTF8));
            var sig = new StringBuilder(home).Append('|').Append(string.Join(",", st.DisabledSubscriptions)).Append('|')
                .Append(string.Join(",", st.JapanInclude)).Append('|').Append(string.Join(",", st.JapanExclude)).Append('|').Append(DateTime.Now.ToString("yyyyMMddHH"));
            foreach (var s in subs) { var f = Path.Combine(VergeDir, "profiles", s.File); sig.Append('|').Append(s.Uid).Append(s.Name).Append(File.Exists(f) ? File.GetLastWriteTimeUtc(f).Ticks : 0); }
            var target = Path.Combine(home, Subscriptions.ProviderFile);
            if (sig.ToString() == lastSig && File.Exists(target)) return;
            var content = Subscriptions.Build(VergeDir, subs, st, DateTime.Now);
            Subs = subs;
            lastSig = sig.ToString();
            if (content == lastContent && File.Exists(target) && File.ReadAllText(target, Encoding.UTF8) == content) return;
            var tmp = target + ".tmp";
            File.WriteAllText(tmp, content, new UTF8Encoding(false));
            if (File.Exists(target)) File.Replace(tmp, target, null); else File.Move(tmp, target);
            lastContent = content;
            LastWrite = DateTime.Now;
            var c = client();
            string refresh = "内核未连接";
            if (c != null)
            {
                var r = c.Request("PUT", "/providers/proxies/" + Subscriptions.ProviderName);
                refresh = r.Status == 204 || r.Status == 200 ? "已热刷新" : r.Status == 404 ? "Japan Auto 尚未引用汇总文件（需重新写入覆写并在 Clash Verge 刷新一次）" : "刷新返回 " + r.Status;
            }
            LastError = null;
            var msg = "日本节点汇总已更新：" + string.Join("，", subs.Select(s => s.Tag + " " + (s.Usable ? s.JapanCount + " 个" : s.Expired ? "已过期" : s.Exhausted ? "流量用完" : !s.Enabled ? "已停用" : "无日本节点"))) + "；" + refresh;
            Log.Action(msg);
            if (Changed != null) Changed(msg);
        }
    }
}
