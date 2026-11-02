// written_by: claude-code
// Claude 会话快照与“待恢复清单”：保护性关闭前记录正在运行的 Claude Code 会话，代理恢复后据此接续。
// 依据（2026-11-01 实机调研）：
//   · 桌面版为每个正在运行的 Claude Code 会话拉起一个 claude-code\...\claude.exe 子进程，命令行含 --resume=<cliSessionId>
//   · 会话元数据：%LOCALAPPDATA%\Claude-Data\<pkg>\claude-code-sessions\<acct>\<org>\local_<id>.json（sessionId/cliSessionId/title/cwd…）
//   · 对话记录：%USERPROFILE%\.claude\projects\<cwd编码>\<cliSessionId>.jsonl（最近写入 = 正在执行）
// 只读取元数据字段，不读取对话内容。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;

namespace ClaudeVPNGuard
{
    public class SessionInfo
    {
        public string LocalId;     // local_xxx（桌面版会话 ID，供 send_message / 深链接使用）
        public string CliId;       // Claude Code 会话 ID
        public string Title;
        public string Cwd;
        public bool Busy;          // 关闭时是否正在执行（对话记录最近 120 秒内有写入）
        public string LastWrite;   // 对话记录最后写入时间
    }

    public class ResumePlan
    {
        public string Id;
        public string CreatedAt;
        public string Reason;
        public string Status = "pending";   // pending / dispatched / done
        public List<SessionInfo> Sessions = new List<SessionInfo>();
    }

    public static class SessionSnapshot
    {
        public static string ResumeDir { get { return Path.Combine(GuardPaths.DataDir, "resume"); } }
        public static string PendingFile { get { return Path.Combine(ResumeDir, "pending.json"); } }

        static readonly Regex ResumeArg = new Regex(@"--resume[= ]([0-9a-f\-]{36})", RegexOptions.IgnoreCase);

        static string Field(string json, string name)
        {
            var m = Regex.Match(json, "\"" + name + "\":\"((?:[^\"\\\\]|\\\\.)*)\"");
            return m.Success ? Regex.Unescape(m.Groups[1].Value) : null;
        }

        // 只读文件开头：元数据字段都在前部，避免反复读取几百 KB 的文件
        static string Head(string path, int bytes)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var buf = new byte[Math.Min(bytes, (int)Math.Min(fs.Length, int.MaxValue))];
                int n = fs.Read(buf, 0, buf.Length);
                return Encoding.UTF8.GetString(buf, 0, n);
            }
        }

        static IEnumerable<string> UserRoots()
        {
            var root = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Users");
            string[] users;
            try { users = Directory.GetDirectories(root); } catch { yield break; }
            foreach (var u in users) yield return u;
        }

        // 正在运行的 Claude Code 会话 ID（来自子进程命令行）
        public static List<string> RunningCliIds()
        {
            var ids = new List<string>();
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT CommandLine, ExecutablePath FROM Win32_Process WHERE Name='claude.exe'"))
                    foreach (ManagementObject o in s.Get())
                    {
                        var path = Convert.ToString(o["ExecutablePath"]) ?? "";
                        if (path.IndexOf(@"\claude-code\", StringComparison.OrdinalIgnoreCase) < 0) continue;
                        var m = ResumeArg.Match(Convert.ToString(o["CommandLine"]) ?? "");
                        if (m.Success && !ids.Contains(m.Groups[1].Value)) ids.Add(m.Groups[1].Value);
                    }
            }
            catch { }
            return ids;
        }

        // cliSessionId → 元数据（扫描所有用户的 claude-code-sessions）
        public static Dictionary<string, SessionInfo> IndexMetadata(IEnumerable<string> wanted)
        {
            var want = new HashSet<string>(wanted, StringComparer.OrdinalIgnoreCase);
            var res = new Dictionary<string, SessionInfo>(StringComparer.OrdinalIgnoreCase);
            if (want.Count == 0) return res;
            foreach (var u in UserRoots())
            {
                var cd = Path.Combine(u, @"AppData\Local\Claude-Data");
                if (!Directory.Exists(cd)) continue;
                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(cd, "local_*.json", SearchOption.AllDirectories).Where(f => f.Contains(@"\claude-code-sessions\")).ToList(); }
                catch { continue; }
                foreach (var f in files)
                {
                    try
                    {
                        var head = Head(f, 8192);
                        var cli = Field(head, "cliSessionId");
                        if (cli == null || !want.Contains(cli) || res.ContainsKey(cli)) continue;
                        res[cli] = new SessionInfo { LocalId = Field(head, "sessionId"), CliId = cli, Title = Field(head, "title"), Cwd = Field(head, "cwd") };
                    }
                    catch { }
                }
            }
            return res;
        }

        static DateTime? TranscriptWrite(string cli)
        {
            foreach (var u in UserRoots())
            {
                var p = Path.Combine(u, @".claude\projects");
                if (!Directory.Exists(p)) continue;
                try
                {
                    foreach (var d in Directory.GetDirectories(p))
                    {
                        var f = Path.Combine(d, cli + ".jsonl");
                        if (File.Exists(f)) return File.GetLastWriteTime(f);
                    }
                }
                catch { }
            }
            return null;
        }

        public static List<SessionInfo> Capture()
        {
            var ids = RunningCliIds();
            var meta = IndexMetadata(ids);
            var list = new List<SessionInfo>();
            foreach (var id in ids)
            {
                SessionInfo s;
                if (!meta.TryGetValue(id, out s)) s = new SessionInfo { CliId = id };
                var w = TranscriptWrite(id);
                s.LastWrite = w.HasValue ? w.Value.ToString("yyyy-MM-dd HH:mm:ss") : null;
                s.Busy = w.HasValue && (DateTime.Now - w.Value).TotalSeconds < 120;
                list.Add(s);
            }
            return list;
        }

        public static ResumePlan WritePending(List<SessionInfo> sessions, string reason)
        {
            var plan = new ResumePlan
            {
                Id = DateTime.Now.ToString("yyyyMMdd-HHmmss"),
                CreatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                Reason = reason,
                Sessions = sessions.Where(s => s.LocalId != null).ToList()
            };
            Directory.CreateDirectory(ResumeDir);
            var tmp = PendingFile + ".tmp";
            File.WriteAllText(tmp, Json.Serialize(plan), new UTF8Encoding(false));
            if (File.Exists(PendingFile)) File.Copy(PendingFile, Path.Combine(ResumeDir, "previous-" + plan.Id + ".json"), true);
            File.Copy(tmp, PendingFile, true);
            File.Delete(tmp);
            return plan;
        }

        public static ResumePlan ReadPending()
        {
            try { return File.Exists(PendingFile) ? Json.Deserialize<ResumePlan>(File.ReadAllText(PendingFile, Encoding.UTF8)) : null; }
            catch { return null; }
        }

        // 恢复协调会话的提示词（经 claude://code/new?q= 传入；不含任何对话内容）
        public static string CoordinatorPrompt(ResumePlan plan)
        {
            var sb = new StringBuilder();
            sb.Append("【Claude VPN Guard 自动续跑】代理异常时 Claude 被保护性关闭（").Append(plan.Reason).Append("，").Append(plan.CreatedAt).Append("），现在代理已恢复并通过检测。");
            sb.Append("请对下列每个会话各调用一次 SendMessage（to=会话 ID）发送：“网络保护已恢复：刚才 Claude 因代理异常被保护性关闭，你的任务被中断。请从中断处继续之前的任务；如果已经完成，简短说明即可。”");
            sb.Append("只发这一条，不要做其他改动。会话：");
            foreach (var s in plan.Sessions) sb.Append(s.LocalId).Append("（").Append(s.Title ?? "未命名").Append(s.Busy ? "，中断时正在执行" : "，中断时空闲").Append("）；");
            sb.Append("全部发完后用一句话汇报结果。清单文件：").Append(PendingFile);
            return sb.ToString();
        }
    }
}
