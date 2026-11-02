// written_by: claude-code
// Mihomo(Clash Meta) 控制接口客户端：自动发现命名管道 / TCP 控制口，只读查询。
// 绝不修改 Clash Verge 的订阅、节点或配置。
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace ClaudeVPNGuard
{
    public class HttpResult
    {
        public int Status;
        public string Body;
    }

    public static class MiniHttp
    {
        // 用 HTTP/1.0 发请求（服务端会直接 close，避免长连接与分块）；仍兼容 chunked。
        public static HttpResult Send(Stream s, string method, string path, string bearer)
        {
            return Send(s, method, path, bearer, null);
        }

        public static HttpResult Send(Stream s, string method, string path, string bearer, string body)
        {
            var sb = new StringBuilder();
            sb.Append(method).Append(' ').Append(path).Append(" HTTP/1.0\r\nHost: 127.0.0.1\r\nAccept: application/json\r\n");
            if (!string.IsNullOrEmpty(bearer)) sb.Append("Authorization: Bearer ").Append(bearer).Append("\r\n");
            var bodyBytes = body == null ? new byte[0] : Encoding.UTF8.GetBytes(body);
            if (body != null) sb.Append("Content-Type: application/json\r\nContent-Length: ").Append(bodyBytes.Length).Append("\r\n");
            sb.Append("\r\n");
            var req = Encoding.UTF8.GetBytes(sb.ToString());
            s.Write(req, 0, req.Length);
            if (bodyBytes.Length > 0) s.Write(bodyBytes, 0, bodyBytes.Length);
            s.Flush();
            var ms = new MemoryStream();
            var buf = new byte[65536];
            int n;
            while ((n = s.Read(buf, 0, buf.Length)) > 0)
            {
                ms.Write(buf, 0, n);
                if (ms.Length > 64 * 1024 * 1024) throw new IOException("响应过大");
            }
            return Parse(ms.ToArray());
        }

        public static HttpResult Parse(byte[] raw)
        {
            int sep = IndexOf(raw, new byte[] { 13, 10, 13, 10 });
            if (sep < 0) throw new IOException("HTTP 响应不完整");
            var head = Encoding.ASCII.GetString(raw, 0, sep);
            var lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None);
            var m = Regex.Match(lines[0], @"^HTTP/\d\.\d\s+(\d{3})");
            if (!m.Success) throw new IOException("HTTP 状态行无效");
            var r = new HttpResult { Status = int.Parse(m.Groups[1].Value) };
            bool chunked = lines.Any(l => Regex.IsMatch(l, @"^transfer-encoding:\s*chunked", RegexOptions.IgnoreCase));
            int start = sep + 4;
            byte[] body;
            if (!chunked)
            {
                body = new byte[raw.Length - start];
                Buffer.BlockCopy(raw, start, body, 0, body.Length);
            }
            else
            {
                var outp = new MemoryStream();
                int p = start;
                while (p < raw.Length)
                {
                    int le = IndexOf(raw, new byte[] { 13, 10 }, p);
                    if (le < 0) break;
                    var sizeStr = Encoding.ASCII.GetString(raw, p, le - p).Split(';')[0].Trim();
                    int size = Convert.ToInt32(sizeStr, 16);
                    if (size == 0) break;
                    p = le + 2;
                    if (p + size > raw.Length) throw new IOException("chunk 不完整");
                    outp.Write(raw, p, size);
                    p += size + 2;
                }
                body = outp.ToArray();
            }
            r.Body = Encoding.UTF8.GetString(body);
            return r;
        }

        static int IndexOf(byte[] a, byte[] pat, int from = 0)
        {
            for (int i = from; i <= a.Length - pat.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < pat.Length; j++) if (a[i + j] != pat[j]) { ok = false; break; }
                if (ok) return i;
            }
            return -1;
        }
    }

    // 从 Clash Verge 配置文件中读出的控制接口信息（secret 只在内存中，不写日志）
    public class VergeConfigInfo
    {
        public string SourceFile;
        public string ExternalController;
        public string ControllerPipe;
        public string Secret;
        public string FakeIpRange;
        public string EnhancedMode;
        public int MixedPort;

        public static VergeConfigInfo ParseYaml(string text, string file)
        {
            var v = new VergeConfigInfo { SourceFile = file };
            foreach (var raw in text.Split('\n'))
            {
                var line = raw.TrimEnd('\r');
                Match m;
                if ((m = Regex.Match(line, @"^external-controller:\s*(.*)$")).Success) v.ExternalController = Unquote(m.Groups[1].Value);
                else if ((m = Regex.Match(line, @"^external-controller-pipe:\s*(.*)$")).Success) v.ControllerPipe = Unquote(m.Groups[1].Value);
                else if ((m = Regex.Match(line, @"^secret:\s*(.*)$")).Success) v.Secret = Unquote(m.Groups[1].Value);
                else if ((m = Regex.Match(line, @"^mixed-port:\s*(\d+)")).Success) v.MixedPort = int.Parse(m.Groups[1].Value);
                else if ((m = Regex.Match(line, @"^\s+fake-ip-range:\s*(.*)$")).Success) v.FakeIpRange = Unquote(m.Groups[1].Value);
                else if ((m = Regex.Match(line, @"^\s+enhanced-mode:\s*(.*)$")).Success) v.EnhancedMode = Unquote(m.Groups[1].Value);
            }
            return v;
        }

        static string Unquote(string s)
        {
            s = s.Trim();
            int hash = s.IndexOf(" #", StringComparison.Ordinal);
            if (hash >= 0 && !s.StartsWith("'") && !s.StartsWith("\"")) s = s.Substring(0, hash).Trim();
            if (s.Length >= 2 && ((s[0] == '\'' && s[s.Length - 1] == '\'') || (s[0] == '"' && s[s.Length - 1] == '"')))
                s = s.Substring(1, s.Length - 2);
            return s;
        }

        // 枚举所有用户的 Clash Verge 数据目录（服务以 SYSTEM 运行时需要跨用户查找）
        public static List<VergeConfigInfo> DiscoverAll()
        {
            var list = new List<VergeConfigInfo>();
            var dirs = new List<string>();
            try
            {
                var usersRoot = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Users");
                foreach (var u in Directory.GetDirectories(usersRoot))
                {
                    var roaming = Path.Combine(u, @"AppData\Roaming");
                    if (!Directory.Exists(roaming)) continue;
                    try { dirs.AddRange(Directory.GetDirectories(roaming, "*clash-verge*")); } catch { }
                    try { dirs.AddRange(Directory.GetDirectories(roaming, "*clashverge*")); } catch { }
                }
            }
            catch { }
            try
            {
                var me = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (!string.IsNullOrEmpty(me)) dirs.AddRange(Directory.GetDirectories(me, "*clash-verge*"));
            }
            catch { }
            foreach (var d in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                // clash-verge.yaml 为运行时生成配置，优先；config.yaml 次之
                foreach (var f in new[] { "clash-verge.yaml", "config.yaml" })
                {
                    var p = Path.Combine(d, f);
                    try { if (File.Exists(p)) list.Add(ParseYaml(File.ReadAllText(p), p)); } catch { }
                }
            }
            return list;
        }
    }

    public class MihomoEndpoint
    {
        public string Pipe;        // 管道名（不含 \\.\pipe\）
        public string TcpHost;
        public int TcpPort;
        public string Secret;
        public string Describe() { return Pipe != null ? "pipe:" + Pipe : "tcp:" + TcpHost + ":" + TcpPort; }
    }

    public class ProxyInfo
    {
        public string Name;
        public string Type;
        public string Now;
        public bool Alive = true;
        public int LastDelay;
    }

    public class MihomoClient
    {
        public MihomoEndpoint Endpoint;
        public int TimeoutMs = 3000;

        public MihomoClient(MihomoEndpoint ep) { Endpoint = ep; }

        public HttpResult Request(string method, string path)
        {
            return Request(method, path, null);
        }

        public HttpResult Request(string method, string path, string body)
        {
            if (Endpoint.Pipe != null)
            {
                using (var c = new NamedPipeClientStream(".", Endpoint.Pipe, PipeDirection.InOut))
                {
                    c.Connect(TimeoutMs);
                    return MiniHttp.Send(new TimeoutStream(c, TimeoutMs * 3), method, path, Endpoint.Secret, body);
                }
            }
            using (var tc = new TcpClient())
            {
                var ar = tc.BeginConnect(Endpoint.TcpHost, Endpoint.TcpPort, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(TimeoutMs)) throw new IOException("控制接口连接超时");
                tc.EndConnect(ar);
                tc.ReceiveTimeout = TimeoutMs * 3;
                tc.SendTimeout = TimeoutMs;
                return MiniHttp.Send(tc.GetStream(), method, path, Endpoint.Secret, body);
            }
        }

        public object GetJson(string path)
        {
            var r = Request("GET", path);
            if (r.Status == 401) throw new UnauthorizedAccessException("控制接口鉴权失败(401)");
            if (r.Status != 200) throw new IOException("控制接口返回 HTTP " + r.Status + " (" + path + ")");
            return Json.Parse(r.Body);
        }

        public string Version() { return Json.Str(GetJson("/version"), "version"); }

        // 选择 Selector 组的当前节点（仅用于 Japan Auto 组）
        public void SelectProxy(string group, string node)
        {
            var r = Request("PUT", "/proxies/" + Uri.EscapeDataString(group), Json.Serialize(new Dictionary<string, object> { { "name", node } }));
            if (r.Status != 204 && r.Status != 200) throw new IOException("切换节点失败 HTTP " + r.Status + " " + r.Body);
        }

        // 经指定节点做一次 URL 测试（Mihomo 内置 delay 接口）；返回毫秒，失败返回 -1
        public int Delay(string node, string url, int timeoutMs)
        {
            var saved = TimeoutMs;
            try
            {
                TimeoutMs = Math.Max(saved, timeoutMs / 2 + 500);
                var q = "?timeout=" + timeoutMs + "&url=" + Uri.EscapeDataString(url);
                var r = Request("GET", "/proxies/" + Uri.EscapeDataString(node) + "/delay" + q);
                // 汇总文件（proxy-provider）里的节点不在 /proxies 下，要走 provider 的 healthcheck 接口
                if (r.Status == 404) r = Request("GET", "/providers/proxies/" + Subscriptions.ProviderName + "/" + Uri.EscapeDataString(node) + "/healthcheck" + q);
                if (r.Status != 200) return -1;
                return Json.Int(Json.Parse(r.Body), "delay", -1);
            }
            catch { return -1; }
            finally { TimeoutMs = saved; }
        }

        public void PatchConfig(Dictionary<string, object> patch)
        {
            var r = Request("PATCH", "/configs", Json.Serialize(patch));
            if (r.Status != 204 && r.Status != 200) throw new IOException("修改配置失败 HTTP " + r.Status);
        }

        public void ReloadConfig(string path)
        {
            var r = Request("PUT", "/configs?force=true", Json.Serialize(new Dictionary<string, object> { { "path", path } }));
            if (r.Status != 204 && r.Status != 200) throw new IOException("重载配置失败 HTTP " + r.Status + " " + r.Body);
        }
        public object Configs() { return GetJson("/configs"); }
        public object Connections() { return GetJson("/connections"); }

        public Dictionary<string, ProxyInfo> Proxies()
        {
            var root = GetJson("/proxies");
            var dict = new Dictionary<string, ProxyInfo>(StringComparer.Ordinal);
            var px = Json.Get(root, "proxies") as IDictionary<string, object>;
            if (px == null) return dict;
            foreach (var kv in px) dict[kv.Key] = ToProxy(kv.Key, kv.Value);
            return dict;
        }

        public static ProxyInfo ToProxy(string name, object node)
        {
            var p = new ProxyInfo { Name = name, Type = Json.Str(node, "type"), Now = Json.Str(node, "now") };
            var alive = Json.Get(node, "alive");
            if (alive is bool) p.Alive = (bool)alive;
            var hist = Json.Arr(node, "history").LastOrDefault();
            if (hist != null) p.LastDelay = Json.Int(hist, "delay", 0);
            return p;
        }

        // 从组名沿 now 递归找到实际出站（叶子）节点
        public static ProxyInfo ResolveLeaf(Dictionary<string, ProxyInfo> all, string start, out List<string> path)
        {
            path = new List<string>();
            var cur = start;
            for (int i = 0; i < 16 && cur != null; i++)
            {
                path.Add(cur);
                ProxyInfo p;
                if (!all.TryGetValue(cur, out p)) return null;
                if (string.IsNullOrEmpty(p.Now)) return p;
                cur = p.Now;
            }
            return null; // 环或过深：视为不可信
        }

        public static bool IsDirectType(string type)
        {
            return string.Equals(type, "Direct", StringComparison.OrdinalIgnoreCase)
                || string.Equals(type, "Compatible", StringComparison.OrdinalIgnoreCase); // Compatible = 兼容直连
        }

        // 自动发现：配置覆盖 → 系统里所有 mihomo 管道 → 配置文件中的管道/TCP。逐个以 /version 验证。
        public static MihomoClient Discover(GuardSettings st, out string diag)
        {
            var cfgs = VergeConfigInfo.DiscoverAll();
            var secrets = cfgs.Select(c => c.Secret).Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();
            secrets.Add(null);
            var cands = new List<MihomoEndpoint>();
            Action<string> addPipe = name =>
            {
                if (string.IsNullOrEmpty(name)) return;
                name = Regex.Replace(name, @"^\\\\\.\\pipe\\", "", RegexOptions.IgnoreCase);
                foreach (var s in secrets) cands.Add(new MihomoEndpoint { Pipe = name, Secret = s });
            };
            Action<string> addTcp = hp =>
            {
                if (string.IsNullOrEmpty(hp)) return;
                var m = Regex.Match(hp.Trim(), @"^\[?([^\]]*?)\]?:(\d+)$");
                if (!m.Success) return;
                var h = m.Groups[1].Value;
                if (h == "" || h == "0.0.0.0" || h == "::") h = "127.0.0.1";
                foreach (var s in secrets) cands.Add(new MihomoEndpoint { TcpHost = h, TcpPort = int.Parse(m.Groups[2].Value), Secret = s });
            };
            if (!string.IsNullOrWhiteSpace(st.ControllerOverride))
            {
                if (st.ControllerOverride.Contains(":")) addTcp(st.ControllerOverride); else addPipe(st.ControllerOverride);
            }
            try
            {
                foreach (var p in Directory.GetFiles(@"\\.\pipe\"))
                {
                    var n = p.Substring(@"\\.\pipe\".Length);
                    if (n.IndexOf("mihomo", StringComparison.OrdinalIgnoreCase) >= 0 || n.IndexOf("clash", StringComparison.OrdinalIgnoreCase) >= 0 && n.IndexOf("service", StringComparison.OrdinalIgnoreCase) < 0)
                        addPipe(n);
                }
            }
            catch { }
            foreach (var c in cfgs) { addPipe(c.ControllerPipe); addTcp(c.ExternalController); }

            var tried = new HashSet<string>();
            var sb = new StringBuilder();
            foreach (var ep in cands)
            {
                var key = ep.Describe() + "|" + (ep.Secret == null ? "-" : ep.Secret.GetHashCode().ToString());
                if (!tried.Add(key)) continue;
                try
                {
                    var cl = new MihomoClient(ep) { TimeoutMs = 1500 };
                    var r = cl.Request("GET", "/version");
                    if (r.Status == 200 && r.Body.Contains("version"))
                    {
                        diag = "控制接口 " + ep.Describe();
                        cl.TimeoutMs = 3000;
                        return cl;
                    }
                    sb.Append(ep.Describe()).Append("=HTTP").Append(r.Status).Append("; ");
                }
                catch (Exception ex) { sb.Append(ep.Describe()).Append("=").Append(ex.GetType().Name).Append("; "); }
            }
            diag = cands.Count == 0 ? "未发现任何 Mihomo 控制接口（Clash Verge 未运行？）" : "控制接口均不可用：" + sb.ToString();
            return null;
        }
    }

    // 给管道流加读超时（NamedPipeClientStream 不支持 ReadTimeout）
    public class TimeoutStream : Stream
    {
        readonly Stream inner; readonly int timeout;
        public TimeoutStream(Stream s, int ms) { inner = s; timeout = ms; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var t = inner.ReadAsync(buffer, offset, count);
            if (!t.Wait(timeout)) throw new IOException("读取超时");
            return t.Result;
        }
        public override void Write(byte[] buffer, int offset, int count) { inner.Write(buffer, offset, count); }
        public override void Flush() { inner.Flush(); }
        public override bool CanRead { get { return true; } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override long Seek(long o, SeekOrigin so) { throw new NotSupportedException(); }
        public override void SetLength(long v) { throw new NotSupportedException(); }
    }
}
