// written_by: claude-code
// Claude Code 专用代理配置：只修改 Claude Code 自己的用户设置 %USERPROFILE%\.claude\settings.json 的 "env" 段，
// 让 Claude Code 使用专用入口；不修改任何用户级/系统级环境变量，不影响其他软件。
// 修改前备份；记录原值，移除时精确还原。其余设置项原样保留。
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace ClaudeVPNGuard
{
    public static class ClaudeCodeProxy
    {
        public static readonly string[] Keys = { "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY" };

        public static string DefaultPath { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude", "settings.json"); } }

        static Dictionary<string, object> Load(string path)
        {
            if (!File.Exists(path)) return new Dictionary<string, object>();
            var o = Json.Parse(File.ReadAllText(path, Encoding.UTF8)) as Dictionary<string, object>;
            if (o == null) throw new InvalidDataException("settings.json 不是 JSON 对象，拒绝修改");
            return o;
        }

        public static Dictionary<string, string> Wanted(int port)
        {
            var u = "http://127.0.0.1:" + port;
            return new Dictionary<string, string> { { "HTTPS_PROXY", u }, { "HTTP_PROXY", u }, { "ALL_PROXY", u }, { "NO_PROXY", "127.0.0.1,localhost,::1" } };
        }

        public static string Status(string path, int port)
        {
            try
            {
                var env = Json.Get(Load(path), "env") as Dictionary<string, object>;
                var want = Wanted(port);
                if (env != null && want.All(kv => env.ContainsKey(kv.Key) && Convert.ToString(env[kv.Key]) == kv.Value)) return "已配置：Claude Code 使用专用入口 127.0.0.1:" + port;
                if (env != null && env.ContainsKey("HTTPS_PROXY")) return "Claude Code 自定义代理：" + env["HTTPS_PROXY"];
                return "未配置（Claude Code 沿用进程环境变量代理）";
            }
            catch (Exception ex) { return "无法读取：" + ex.Message; }
        }

        // 返回备份文件路径
        public static string Apply(string path, int port)
        {
            var root = Load(path);
            var backup = path + ".cvg-backup-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
            if (File.Exists(path)) File.Copy(path, backup, true);
            var env = Json.Get(root, "env") as Dictionary<string, object>;
            if (env == null) { env = new Dictionary<string, object>(); root["env"] = env; }
            // 记录原值（null = 原来不存在），供精确还原
            var origFile = path + ".cvg-orig.json";
            if (!File.Exists(origFile))
            {
                var orig = Keys.ToDictionary(k => k, k => env.ContainsKey(k) ? env[k] : null);
                File.WriteAllText(origFile, Json.Serialize(orig), new UTF8Encoding(false));
            }
            foreach (var kv in Wanted(port)) env[kv.Key] = kv.Value;
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, Pretty(root, 0) + "\n", new UTF8Encoding(false));
            return File.Exists(backup) ? backup : null;
        }

        public static void Remove(string path)
        {
            var root = Load(path);
            var env = Json.Get(root, "env") as Dictionary<string, object>;
            var origFile = path + ".cvg-orig.json";
            var orig = File.Exists(origFile) ? Json.Parse(File.ReadAllText(origFile, Encoding.UTF8)) as Dictionary<string, object> : null;
            if (env != null)
            {
                foreach (var k in Keys)
                {
                    object o = null;
                    if (orig != null && orig.TryGetValue(k, out o) && o != null) env[k] = o;
                    else env.Remove(k);
                }
                if (env.Count == 0) root.Remove("env");
            }
            File.WriteAllText(path, Pretty(root, 0) + "\n", new UTF8Encoding(false));
            try { File.Delete(origFile); } catch { }
        }

        // 2 空格缩进的 JSON 输出（保持 settings.json 可读）
        public static string Pretty(object o, int ind)
        {
            var pad = new string(' ', ind * 2);
            var pad1 = new string(' ', (ind + 1) * 2);
            var d = o as IDictionary<string, object>;
            if (d != null)
            {
                if (d.Count == 0) return "{}";
                return "{\n" + string.Join(",\n", d.Select(kv => pad1 + Json.Serialize(kv.Key) + ": " + Pretty(kv.Value, ind + 1))) + "\n" + pad + "}";
            }
            if (o is string || o == null || o is bool) return Json.Serialize(o);
            var e = o as IEnumerable;
            if (e != null)
            {
                var items = e.Cast<object>().ToList();
                if (items.Count == 0) return "[]";
                return "[\n" + string.Join(",\n", items.Select(x => pad1 + Pretty(x, ind + 1))) + "\n" + pad + "]";
            }
            return Convert.ToString(o, CultureInfo.InvariantCulture);
        }
    }
}
