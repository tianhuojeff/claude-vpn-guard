// written_by: claude-code
// 公共基础：路径、日志、JSON、设置。目标 .NET Framework 4.8 / C# 5（Windows 自带 csc 可编译）。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace ClaudeVPNGuard
{
    public static class GuardPaths
    {
        public const string ProductName = "ClaudeVPNGuard";
        public const string ServiceName = "ClaudeVPNGuard";
        public static string PipeName = "ClaudeVPNGuard.v1"; // 测试时改为独立名称，避免与正在运行的正式服务冲突
        public const string RuleGroup = "ClaudeVPNGuard";

        public static string DataDirOverride; // 测试用
        public static string DataDir
        {
            get { return DataDirOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), ProductName); }
        }
        public static string LogDir { get { return Path.Combine(DataDir, "logs"); } }
        public static string SettingsFile { get { return Path.Combine(DataDir, "settings.json"); } }
        public static string StateFile { get { return Path.Combine(DataDir, "state.json"); } }
        public static string ExeDir { get { return AppDomain.CurrentDomain.BaseDirectory; } }
        public static string InstallDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), ProductName); } }
    }

    // 完全卸载走 full-uninstall.ps1：只用 Windows 自带的 PowerShell，不依赖本程序 exe（exe 无签名，可能被“应用程序控制策略”拦截）
    public static class AppControl
    {
        // ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION(4551)、ERROR_SYSTEM_INTEGRITY_REPUTATION_*(4553~4556)、组策略阻止(1260)、病毒/潜在垃圾(225)
        public static bool IsBlock(Exception ex)
        {
            var w = ex as System.ComponentModel.Win32Exception;
            if (w == null) return false;
            int c = w.NativeErrorCode;
            return c == 4551 || (c >= 4553 && c <= 4556) || c == 1260 || c == 225;
        }

        public const string Advice =
            "Windows 的“智能应用控制 / 应用程序控制策略”拦截了本程序（exe 没有代码签名、也没有下载信誉）。\n" +
            "这不是程序损坏。可选办法：\n" +
            "1) 不安装，继续用 Clash Verge 系统代理（Claude 正常可用，只是没有防泄漏隔离）；\n" +
            "2) 设置 → 隐私和安全性 → Windows 安全中心 → 应用和浏览器控制 → 智能应用控制：关闭（注意：关闭后无法再直接打开，需重置系统）。\n" +
            "安装程序没有停掉现有保护，也没有改动任何规则。";
    }

    public static class FullUninstall
    {
        public const string ScriptName = "full-uninstall.ps1";
        public static string PowerShellExe { get { return Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"); } }

        public static string FindScript()
        {
            foreach (var d in new[] { GuardPaths.ExeDir, GuardPaths.InstallDir })
            {
                var p = Path.Combine(d, ScriptName);
                if (File.Exists(p)) return p;
            }
            return null;
        }

        public static string CommandLine(string script) { return "-NoProfile -ExecutionPolicy Bypass -NoExit -File \"" + script + "\""; }

        // 复制到临时目录再运行（脚本会删除安装目录）。脚本自己提权并询问确认。
        public static bool Launch(bool yes)
        {
            var src = FindScript();
            if (src == null) return false;
            var tmp = Path.Combine(Path.GetTempPath(), "ClaudeVPNGuard-Uninstall");
            Directory.CreateDirectory(tmp);
            var dst = Path.Combine(tmp, ScriptName);
            File.Copy(src, dst, true);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(PowerShellExe, CommandLine(dst) + (yes ? " -Yes" : "")) { UseShellExecute = true });
            return true;
        }
    }

    public static class Json
    {
        static JavaScriptSerializer Make()
        {
            var s = new JavaScriptSerializer();
            s.MaxJsonLength = 64 * 1024 * 1024;
            s.RecursionLimit = 256;
            return s;
        }
        public static string Serialize(object o) { return Make().Serialize(o); }
        public static T Deserialize<T>(string s) { return Make().Deserialize<T>(s); }
        public static object Parse(string s) { return Make().DeserializeObject(s); }

        // 便捷读取 Dictionary/ArrayList 结构
        public static object Get(object node, string key)
        {
            var d = node as IDictionary<string, object>;
            if (d == null) return null;
            object v;
            return d.TryGetValue(key, out v) ? v : null;
        }
        public static string Str(object node, string key)
        {
            var v = Get(node, key);
            return v == null ? null : Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture);
        }
        public static bool Bool(object node, string key)
        {
            var v = Get(node, key);
            return v is bool && (bool)v;
        }
        public static int Int(object node, string key, int def)
        {
            var v = Get(node, key);
            if (v == null) return def;
            try { return Convert.ToInt32(v, System.Globalization.CultureInfo.InvariantCulture); } catch { return def; }
        }
        public static IEnumerable<object> Arr(object node, string key)
        {
            var v = Get(node, key) as System.Collections.IEnumerable;
            if (v == null || v is string) return Enumerable.Empty<object>();
            return v.Cast<object>();
        }
    }

    public enum LogLevel { Info, Warn, Error, Action }

    // 简单文本日志：按天分文件，保留 N 天。不记录任何密钥 / 对话内容。
    public static class Log
    {
        static readonly object Gate = new object();
        public static string Dir = GuardPaths.LogDir;
        public static int RetentionDays = 14;
        public static bool EchoConsole = false;
        public static event Action<string> Written;

        public static void Info(string m) { Write(LogLevel.Info, m); }
        public static void Warn(string m) { Write(LogLevel.Warn, m); }
        public static void Error(string m) { Write(LogLevel.Error, m); }
        public static void Action(string m) { Write(LogLevel.Action, m); }

        public static void Write(LogLevel lv, string msg)
        {
            var line = string.Format("{0:yyyy-MM-dd HH:mm:ss.fff} [{1}] {2}", DateTime.Now, lv.ToString().ToUpperInvariant(), Redact(msg));
            lock (Gate)
            {
                try
                {
                    Directory.CreateDirectory(Dir);
                    File.AppendAllText(Path.Combine(Dir, "guard-" + DateTime.Now.ToString("yyyyMMdd") + ".log"), line + Environment.NewLine, Encoding.UTF8);
                }
                catch { }
                if (EchoConsole) { try { Console.WriteLine(line); } catch { } }
            }
            var h = Written;
            if (h != null) { try { h(line); } catch { } }
        }

        // 兜底脱敏：Bearer token / secret= / uuid 形式的节点认证
        public static string Redact(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            s = System.Text.RegularExpressions.Regex.Replace(s, @"(?i)(bearer\s+)\S+", "$1<redacted>");
            s = System.Text.RegularExpressions.Regex.Replace(s, @"(?i)(secret\s*[:=]\s*)\S+", "$1<redacted>");
            s = System.Text.RegularExpressions.Regex.Replace(s, @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<uuid>");
            return s;
        }

        public static void Cleanup()
        {
            try
            {
                if (!Directory.Exists(Dir)) return;
                foreach (var f in Directory.GetFiles(Dir, "guard-*.log"))
                    if (File.GetLastWriteTime(f) < DateTime.Now.AddDays(-RetentionDays)) File.Delete(f);
            }
            catch { }
        }

        public static string[] Tail(int maxLines)
        {
            try
            {
                if (!Directory.Exists(Dir)) return new string[0];
                var files = Directory.GetFiles(Dir, "guard-*.log").OrderByDescending(f => f).Take(2).Reverse();
                var lines = new List<string>();
                foreach (var f in files)
                {
                    using (var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        string l;
                        while ((l = sr.ReadLine()) != null) lines.Add(l);
                    }
                }
                return lines.Skip(Math.Max(0, lines.Count - maxLines)).ToArray();
            }
            catch { return new string[0]; }
        }
    }

    public class GuardSettings
    {
        // Clash Verge 安装路径（可空 = 自动发现）
        public string ClashVergePath;
        // Mihomo 控制接口手动覆盖：tcp 形如 127.0.0.1:9097，或 pipe 名称；空 = 自动发现
        public string ControllerOverride;
        // Mihomo fake-ip 段。Claude 只被允许连接到 回环 + 此网段（TUN fake-ip 模式下的流量）
        public string FakeIpRange = "198.18.0.0/15";
        // 用于“代理路径探测”的 Claude 域名
        public string ProbeHost = "api.anthropic.com";
        public int ProbePort = 443;
        // Claude 相关域名：Mihomo 连接审计时，这些域名走 DIRECT 也视为泄漏
        public List<string> ClaudeDomains = new List<string> { "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com", "clau.de" };
        // 额外需要保护的可执行文件（完整路径）
        public List<string> ExtraProtectedExe = new List<string>();
        // 是否查询出口 IP（经代理访问 cloudflare trace，仅用于显示）
        public bool ExitIpCheck = true;
        // 触发保护性关闭后，需用户在保护器里点“启动 Claude”才解除锁定
        public bool RequireManualUnlockAfterTrip = true;
        // 允许 TUN 模式外仅系统代理模式（安全等级较低，见文档）
        public bool AllowSystemProxyMode = true;
        // ===== V2：专用入口隔离 + 日本节点 =====
        // 隔离模式：Claude 只能经专用入口(listener, proxy=Japan Auto)出网；WFP 阻断 Claude 连接通用代理端口与一切非回环地址
        public bool IsolationMode = false;
        public int DedicatedPort = 17897;
        public string JapanGroupName = "Japan Auto";
        public string JapanNameRegex = "(\U0001F1EF\U0001F1F5|日本|japan|\\bjp\\b|东京|東京|tokyo|大阪|osaka)";
        public string InfoNodeRegex = "(剩余|到期|官网|官網|重置|流量|套餐|expire|traffic|reset)";
        public List<string> JapanInclude = new List<string>();
        public List<string> JapanExclude = new List<string>();
        public bool AutoSwitch = true;
        // 多订阅：Japan Auto 汇总所有订阅的日本节点；这里列出被停用的订阅 uid（过期/流量用完的订阅自动跳过）
        public List<string> DisabledSubscriptions = new List<string>();
        // 保护性关闭后：代理恢复且检测通过时自动重开 Claude，并通过“恢复协调”会话让被中断的会话继续
        public bool AutoResumeAfterRecovery = true;
        public int MaxDelayMs = 300;
        public int ProbeTimeoutMs = 3000;
        public int FailThreshold = 2;
        public int RecoverThreshold = 2;
        public int HealthIntervalSec = 60;
        public int AllFailRetrySec = 60;
        public int SwitchCooldownSec = 30;
        public int MinDwellSec = 120;
        public int CurrentNodeCheckSec = 3;       // 旧串行策略的检测周期
        public int LivenessIntervalMs = 1000;     // 流水线策略：当前节点存活探测发起间隔
        public string NodeLivenessUrl = "http://cp.cloudflare.com/generate_204"; // 高频存活探测用轻量地址；候选/验证仍用 NodeTestUrl
        public int QuarantineSec = 300;
        public string NodeTestUrl = "https://api.anthropic.com/";
        public string ExitTraceUrl = "https://www.cloudflare.com/cdn-cgi/trace";
        public string ExpectedExitCountry = "JP";
        public int QuickIntervalMs = 2000;
        public int FullIntervalSec = 60;
        public int LogRetentionDays = 14;

        public static GuardSettings Load()
        {
            try
            {
                if (File.Exists(GuardPaths.SettingsFile))
                {
                    var s = Json.Deserialize<GuardSettings>(File.ReadAllText(GuardPaths.SettingsFile, Encoding.UTF8));
                    if (s != null) { s.Normalize(); return s; }
                }
            }
            catch (Exception ex) { Log.Warn("读取设置失败，使用默认值：" + ex.Message); }
            var d = new GuardSettings();
            d.Normalize();
            return d;
        }

        public void Normalize()
        {
            if (ClaudeDomains == null || ClaudeDomains.Count == 0) ClaudeDomains = new GuardSettings().ClaudeDomains;
            if (ExtraProtectedExe == null) ExtraProtectedExe = new List<string>();
            if (JapanInclude == null) JapanInclude = new List<string>();
            if (JapanExclude == null) JapanExclude = new List<string>();
            if (DisabledSubscriptions == null) DisabledSubscriptions = new List<string>();
            if (string.IsNullOrWhiteSpace(JapanGroupName)) JapanGroupName = "Japan Auto";
            if (DedicatedPort <= 0 || DedicatedPort > 65535) DedicatedPort = 17897;
            if (FailThreshold < 1) FailThreshold = 1;
            if (RecoverThreshold < 1) RecoverThreshold = 1;
            if (ProbeTimeoutMs < 500) ProbeTimeoutMs = 500;
            if (CurrentNodeCheckSec < 1) CurrentNodeCheckSec = 1;
            if (string.IsNullOrWhiteSpace(FakeIpRange)) FakeIpRange = "198.18.0.0/15";
            if (string.IsNullOrWhiteSpace(ProbeHost)) ProbeHost = "api.anthropic.com";
            if (QuickIntervalMs < 500) QuickIntervalMs = 500;
            if (FullIntervalSec < 15) FullIntervalSec = 15;
        }

        public void Save()
        {
            Directory.CreateDirectory(GuardPaths.DataDir);
            var tmp = GuardPaths.SettingsFile + ".tmp";
            File.WriteAllText(tmp, Json.Serialize(this), Encoding.UTF8);
            if (File.Exists(GuardPaths.SettingsFile)) File.Replace(tmp, GuardPaths.SettingsFile, null);
            else File.Move(tmp, GuardPaths.SettingsFile);
        }

        public bool IsClaudeHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            host = host.ToLowerInvariant().TrimEnd('.');
            foreach (var d in ClaudeDomains)
            {
                var dd = d.ToLowerInvariant();
                if (host == dd || host.EndsWith("." + dd)) return true;
            }
            return false;
        }
    }
}
