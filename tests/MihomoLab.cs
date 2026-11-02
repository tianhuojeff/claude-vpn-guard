// written_by: claude-code
// 离线故障注入实验台：假节点（本机 HTTP 代理，可断线/卡死/变慢/伪装国家）+ 私有 Mihomo 实例。
// 私有实例使用独立端口(27xxx/29xxx)、独立临时目录、仅回环，不联网，不影响用户正在运行的 Clash Verge。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ClaudeVPNGuard
{
    public enum FakeMode { Up, Down, Stall, Slow, Alternate }

    public class FakeNode
    {
        public string Name; public int Port; public string Country = "JP";
        public volatile FakeMode Mode = FakeMode.Up;
        public int SlowMs = 800;
        public int Hits; int altSeq;
        public string LastTarget;
        TcpListener lis; volatile bool stop;
        static int ipSeq = 10;
        public readonly string ExitIp;

        public FakeNode(string name, int port) { Name = name; Port = port; ExitIp = "10.9.0." + (ipSeq++); }

        public void Start()
        {
            lis = new TcpListener(IPAddress.Loopback, Port);
            lis.Start();
            new Thread(() =>
            {
                while (!stop)
                {
                    TcpClient c;
                    try { c = lis.AcceptTcpClient(); } catch { break; }
                    ThreadPool.QueueUserWorkItem(_ => Handle(c));
                }
            }) { IsBackground = true }.Start();
        }
        public void Stop() { stop = true; try { lis.Stop(); } catch { } }

        static string ReadHead(Stream s)
        {
            var sb = new StringBuilder(); var b = new byte[1];
            while (sb.Length < 16384) { int n = s.Read(b, 0, 1); if (n <= 0) break; sb.Append((char)b[0]); if (sb.Length >= 4 && sb.ToString(sb.Length - 4, 4) == "\r\n\r\n") break; }
            return sb.ToString();
        }

        void Handle(TcpClient c)
        {
            using (c)
            {
                try
                {
                    var m = Mode;
                    if (m == FakeMode.Down) return; // 立即断开 = 节点故障
                    if (m == FakeMode.Alternate && Interlocked.Increment(ref altSeq) % 2 == 0) return; // 偶发失败：隔一次失败一次
                    c.ReceiveTimeout = 15000;
                    var s = c.GetStream();
                    var head = ReadHead(s);
                    var first = head.Split('\r')[0];
                    Interlocked.Increment(ref Hits);
                    LastTarget = first; Seen.Add(Name + " | " + head.Replace("\r\n"," / "));
                    if (m == FakeMode.Stall) { Thread.Sleep(20000); return; }
                    Thread.Sleep(m == FakeMode.Slow ? SlowMs : 20); // 模拟网络延迟：Mihomo 把 0ms 结果视为失败
                    string path = "/";
                    if (first.StartsWith("CONNECT "))
                    {
                        var ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
                        s.Write(ok, 0, ok.Length);
                        var inner = ReadHead(s); Seen.Add(Name + " inner | " + inner.Replace("\r\n"," / "));
                        var parts = inner.Split(' ');
                        if (parts.Length > 1) path = parts[1];
                    }
                    else
                    {
                        var parts = first.Split(' ');
                        if (parts.Length > 1) { path = parts[1]; try { path = new Uri(path).AbsolutePath; } catch { } }
                    }
                    if (path.Contains("generate_204"))
                    {
                        var r204 = Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\nX-Fake-Node: " + Uri.EscapeDataString(Name) + "\r\nContent-Length: 0\r\n\r\n");
                        s.Write(r204, 0, r204.Length);
                        s.Flush();
                        Thread.Sleep(200); // 给对端读完响应的时间，再关闭
                        return;
                    }
                    string body = path.Contains("trace") ? "ip=" + ExitIp + "\nloc=" + Country + "\n" : "fake-node " + Name;
                    var resp = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Fake-Node: " + Uri.EscapeDataString(Name) + "\r\nContent-Length: " + Encoding.UTF8.GetByteCount(body) + "\r\nConnection: close\r\n\r\n" + body);
                    s.Write(resp, 0, resp.Length);
                }
                catch (Exception ex) { Errors.Add(Name + ": " + ex.GetType().Name + " " + ex.Message); }
            }
        }
        public static System.Collections.Concurrent.ConcurrentBag<string> Errors = new System.Collections.Concurrent.ConcurrentBag<string>();
        public static System.Collections.Concurrent.ConcurrentBag<string> Seen = new System.Collections.Concurrent.ConcurrentBag<string>();
    }

    public class MihomoInstance : IDisposable
    {
        public string Dir; public Process Proc;
        public int MixedPort = 27897, ControllerPort = 29097, DedicatedPort = 27917;
        public const string Secret = "cvg-lab-secret";
        public string ConfigPath { get { return Path.Combine(Dir, "config.json"); } }

        public static string FindBinary()
        {
            var p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Clash Verge\verge-mihomo.exe");
            return File.Exists(p) ? p : null;
        }

        // 用 node 执行 Claude VPN Guard 生成的 Script.js，得到最终配置（真实验证覆写脚本）
        public static string RunScriptWithNode(string scriptJs, string baseConfigJson, string workDir)
        {
            var node = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"nodejs\node.exe");
            if (!File.Exists(node)) throw new FileNotFoundException("未找到 node.exe，无法执行覆写脚本测试");
            File.WriteAllText(Path.Combine(workDir, "Script.js"), scriptJs, new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(workDir, "base.json"), baseConfigJson, new UTF8Encoding(false));
            var runner = "const fs=require('fs'),vm=require('vm');const s=fs.readFileSync(process.argv[2],'utf8');const cfg=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));const ctx={cfg:cfg};vm.createContext(ctx);vm.runInContext(s+'\\n;__out=main(cfg,\"lab\");',ctx);fs.writeFileSync(process.argv[4],JSON.stringify(ctx.__out,null,1));";
            File.WriteAllText(Path.Combine(workDir, "run.js"), runner, new UTF8Encoding(false));
            var psi = new ProcessStartInfo(node, "run.js Script.js base.json out.json") { WorkingDirectory = workDir, UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true };
            using (var p = Process.Start(psi))
            {
                var err = p.StandardError.ReadToEnd();
                p.WaitForExit(20000);
                if (p.ExitCode != 0) throw new Exception("覆写脚本执行失败：" + err);
            }
            return File.ReadAllText(Path.Combine(workDir, "out.json"), Encoding.UTF8);
        }

        public static string BaseConfig(IEnumerable<FakeNode> nodes, string mode)
        {
            var proxies = nodes.Select(n => new Dictionary<string, object> { { "name", n.Name }, { "type", "http" }, { "server", "127.0.0.1" }, { "port", n.Port } }).ToList();
            var cfg = new Dictionary<string, object>
            {
                { "mixed-port", 27897 }, { "allow-lan", false }, { "bind-address", "127.0.0.1" }, { "mode", mode },
                { "log-level", "warning" }, { "ipv6", false }, { "external-controller", "127.0.0.1:29097" }, { "secret", Secret },
                { "profile", new Dictionary<string, object> { { "store-selected", false } } },
                { "proxies", proxies },
                { "proxy-groups", new object[] {
                    new Dictionary<string, object> { { "name", "节点选择" }, { "type", "select" }, { "proxies", new[] { "DIRECT" }.Concat(nodes.Select(n => n.Name)).ToArray() } } } },
                { "rules", new[] { "MATCH,DIRECT" } }
            };
            return Json.Serialize(cfg);
        }

        public void Start(string configJson)
        {
            var bin = FindBinary();
            if (bin == null) throw new FileNotFoundException("未找到 verge-mihomo.exe");
            Dir = Path.Combine(Path.GetTempPath(), "cvg-lab-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(Dir);
            File.WriteAllText(ConfigPath, configJson, new UTF8Encoding(false));
            var psi = new ProcessStartInfo(bin, "-d \"" + Dir + "\" -f \"" + ConfigPath + "\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            Proc = Process.Start(psi);
            Proc.OutputDataReceived += (s, e) => { if (e.Data != null) try { File.AppendAllText(Path.Combine(Dir, "mihomo.log"), e.Data + "\n"); } catch { } };
            Proc.ErrorDataReceived += (s, e) => { if (e.Data != null) try { File.AppendAllText(Path.Combine(Dir, "mihomo.log"), e.Data + "\n"); } catch { } };
            Proc.BeginOutputReadLine(); Proc.BeginErrorReadLine();
            var until = DateTime.Now.AddSeconds(15);
            while (DateTime.Now < until)
            {
                if (Proc.HasExited) throw new Exception("私有 Mihomo 启动失败：" + SafeLog());
                try { if (Client().Version() != null) return; } catch { }
                Thread.Sleep(200);
            }
            throw new Exception("私有 Mihomo 控制接口未就绪：" + SafeLog());
        }

        public string SafeLog() { try { return File.ReadAllText(Path.Combine(Dir, "mihomo.log")); } catch { return ""; } }

        public MihomoClient Client() { return new MihomoClient(new MihomoEndpoint { TcpHost = "127.0.0.1", TcpPort = ControllerPort, Secret = Secret }) { TimeoutMs = 3000 }; }

        public void Dispose()
        {
            try { if (Proc != null && !Proc.HasExited) { Proc.Kill(); Proc.WaitForExit(3000); } } catch { }
            try { Directory.Delete(Dir, true); } catch { }
        }

        // 经指定本地端口发起 HTTP 代理请求（绝对 URI），返回 X-Fake-Node（null=失败/直连）
        public static string GetVia(int port, string url, int timeoutMs)
        {
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(url);
                req.Proxy = new WebProxy("http://127.0.0.1:" + port);
                req.Timeout = timeoutMs; req.ReadWriteTimeout = timeoutMs;
                using (var resp = (HttpWebResponse)req.GetResponse())
                    return Uri.UnescapeDataString(resp.Headers["X-Fake-Node"] ?? "(无标记=未经假节点)");
            }
            catch (WebException ex)
            {
                var r = ex.Response as HttpWebResponse;
                return r == null ? null : "HTTP" + (int)r.StatusCode;
            }
        }
    }
}
