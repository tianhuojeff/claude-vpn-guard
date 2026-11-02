// written_by: claude-code
// Claude 桌面版 / Claude Code 可执行文件发现、身份核实（路径 + Anthropic 签名）与进程结束。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace ClaudeVPNGuard
{
    public class ClaudeLocator
    {
        readonly GuardSettings st;
        readonly Dictionary<string, KeyValuePair<DateTime, bool>> sigCache = new Dictionary<string, KeyValuePair<DateTime, bool>>(StringComparer.OrdinalIgnoreCase);
        public string LastMsixFamily;

        public ClaudeLocator(GuardSettings s) { st = s; }

        // 签名者必须是 Anthropic, PBC 且签名有效
        public bool IsAnthropicSigned(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
                var wt = File.GetLastWriteTimeUtc(path);
                KeyValuePair<DateTime, bool> c;
                lock (sigCache) if (sigCache.TryGetValue(path, out c) && c.Key == wt) return c.Value;
                bool ok = false;
                try
                {
                    var cert = X509Certificate.CreateFromSignedFile(path);
                    var subj = cert.Subject ?? "";
                    ok = (subj.Contains("O=\"Anthropic, PBC\"") || subj.Contains("O=Anthropic")) && Native.SignatureValid(path);
                }
                catch { ok = false; }
                lock (sigCache) sigCache[path] = new KeyValuePair<DateTime, bool>(wt, ok);
                return ok;
            }
            catch { return false; }
        }

        // 是否属于 Claude 安装目录（即使签名未知也认定为 Claude 相关）
        public static bool IsClaudeInstallPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var p = path.ToLowerInvariant();
            return p.Contains(@"\windowsapps\anthropicpbc.claude_")
                || p.Contains(@"\appdata\local\anthropicclaude\")
                || (p.Contains(@"\claude-data\") && p.Contains(@"\claude-code\"))
                || p.Contains(@"\appdata\roaming\claude\claude-code\")
                || p.Contains(@"\appdata\local\anthropic\");
        }

        public bool IsClaudeExe(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            if (st.ExtraProtectedExe.Any(e => string.Equals(e, path, StringComparison.OrdinalIgnoreCase))) return true;
            return IsClaudeInstallPath(path) && IsAnthropicSigned(path);
        }

        IEnumerable<string> Roots()
        {
            var roots = new List<string>();
            var sysRoot = Path.GetPathRoot(Environment.SystemDirectory);
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            try
            {
                var wa = Path.Combine(pf, "WindowsApps");
                if (Directory.Exists(wa)) roots.AddRange(Directory.GetDirectories(wa, "AnthropicPBC.Claude_*"));
            }
            catch (UnauthorizedAccessException) { } // 非管理员无法列举 WindowsApps，靠运行中进程补齐
            try
            {
                foreach (var u in Directory.GetDirectories(Path.Combine(sysRoot, "Users")))
                {
                    foreach (var rel in new[] { @"AppData\Local\AnthropicClaude", @"AppData\Roaming\Claude\claude-code" })
                    {
                        var d = Path.Combine(u, rel);
                        if (Directory.Exists(d)) roots.Add(d);
                    }
                    var cd = Path.Combine(u, @"AppData\Local\Claude-Data");
                    if (Directory.Exists(cd))
                        foreach (var sub in SafeDirs(cd))
                        {
                            var cc = Path.Combine(sub, "claude-code");
                            if (Directory.Exists(cc)) roots.Add(cc);
                        }
                }
            }
            catch { }
            return roots;
        }

        static string[] SafeDirs(string d) { try { return Directory.GetDirectories(d); } catch { return new string[0]; } }

        // 发现所有需要加防火墙规则的 Claude 可执行文件
        public List<string> DiscoverExecutables()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in Roots())
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(r, "*.exe", SearchOption.AllDirectories))
                        if (IsAnthropicSigned(f)) set.Add(f);
                }
                catch { }
            }
            foreach (var p in RunningClaude()) set.Add(p.Value);
            foreach (var e in st.ExtraProtectedExe) if (File.Exists(e)) set.Add(e);
            foreach (var f in set)
            {
                var m = System.Text.RegularExpressions.Regex.Match(f, @"\\WindowsApps\\(AnthropicPBC\.Claude)_[^_\\]+_[^_\\]+__([a-z0-9]+)\\", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success) LastMsixFamily = m.Groups[1].Value + "_" + m.Groups[2].Value;
            }
            return set.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // 运行中的 Claude 进程：pid → 路径（路径+签名双重核实，不凭进程名）
        public Dictionary<int, string> RunningClaude()
        {
            var res = new Dictionary<int, string>();
            foreach (var p in Native.Processes())
            {
                if (p.Pid <= 4) continue;
                var path = Native.ProcessPath(p.Pid);
                if (path != null && IsClaudeExe(path)) res[p.Pid] = path;
            }
            return res;
        }

        // 结束所有 Claude 进程及其子进程树；返回 (结束数, 残留数)
        public int[] KillAll()
        {
            int killed = 0;
            for (int round = 0; round < 3; round++)
            {
                var procs = Native.Processes();
                var claude = RunningClaude();
                if (claude.Count == 0) return new[] { killed, 0 };
                var targets = new HashSet<int>(claude.Keys);
                bool grew = true;
                while (grew) // 加入所有后代（Claude Code 派生的 node/git/shell 等）
                {
                    grew = false;
                    foreach (var p in procs)
                        if (!targets.Contains(p.Pid) && targets.Contains(p.ParentPid) && p.Pid > 4) { targets.Add(p.Pid); grew = true; }
                }
                // 先结束根（父进程不在集合中），避免主进程重新拉起子进程
                var order = targets.OrderBy(pid => procs.Any(x => x.Pid == pid && targets.Contains(x.ParentPid)) ? 1 : 0).ToList();
                foreach (var pid in order)
                    if (Native.Kill(pid, 1500)) killed++;
            }
            var left = RunningClaude().Count;
            return new[] { killed, left };
        }
    }
}
