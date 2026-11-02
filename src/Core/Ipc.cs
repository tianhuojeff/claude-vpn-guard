// written_by: claude-code
// GUI ⇄ 服务 本地通信：命名管道，单行 JSON 请求/响应。
// 身份验证：管道 ACL 仅允许 SYSTEM/管理员/交互式用户；服务端用 GetNamedPipeClientProcessId 核实
// 调用方可执行文件必须是安装目录下的 ClaudeVPNGuard.exe（Program Files 仅管理员可写）。
// 协议中不存在“关闭保护”命令：解除规则只能由管理员运行服务程序的 uninstall/recover。
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace ClaudeVPNGuard
{
    public class IpcRequest { public string Cmd; public Dictionary<string, object> Args; }
    public class IpcResponse { public bool Ok; public string Error; public object Data; }

    public class IpcServer
    {
        readonly Func<IpcRequest, bool, IpcResponse> handler;
        volatile bool stop;
        Thread th;
        public string TrustedClientExe;
        public DateTime LastClientSeen = DateTime.MinValue;

        public IpcServer(Func<IpcRequest, bool, IpcResponse> h) { handler = h; }

        public void Start()
        {
            th = new Thread(Loop) { IsBackground = true, Name = "ipc" };
            th.Start();
        }
        public void Stop()
        {
            stop = true;
            try { using (var c = new NamedPipeClientStream(".", GuardPaths.PipeName)) c.Connect(200); } catch { }
        }

        static PipeSecurity Security()
        {
            var ps = new PipeSecurity();
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
            return ps;
        }

        void Loop()
        {
            while (!stop)
            {
                NamedPipeServerStream srv = null;
                try
                {
                    srv = new NamedPipeServerStream(GuardPaths.PipeName, PipeDirection.InOut, 4, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 65536, 65536, Security());
                    srv.WaitForConnection();
                    if (stop) break;
                    var s = srv;
                    srv = null;
                    ThreadPool.QueueUserWorkItem(_ => Serve(s));
                }
                catch (Exception ex) { Log.Error("IPC 监听异常：" + ex.Message); Thread.Sleep(1000); }
                finally { if (srv != null) srv.Dispose(); }
            }
        }

        void Serve(NamedPipeServerStream s)
        {
            using (s)
            {
                try
                {
                    bool trusted = false;
                    uint pid;
                    if (Native.GetNamedPipeClientProcessId(s.SafePipeHandle.DangerousGetHandle(), out pid))
                    {
                        var path = Native.ProcessPath((int)pid);
                        trusted = path != null && TrustedClientExe != null && string.Equals(Path.GetFullPath(path), Path.GetFullPath(TrustedClientExe), StringComparison.OrdinalIgnoreCase);
                    }
                    var sr = new StreamReader(s, new UTF8Encoding(false));
                    var line = sr.ReadLine();
                    if (line == null) return;
                    IpcResponse resp;
                    try
                    {
                        var req = Json.Deserialize<IpcRequest>(line);
                        if (trusted) LastClientSeen = DateTime.Now;
                        resp = handler(req, trusted);
                    }
                    catch (Exception ex) { resp = new IpcResponse { Ok = false, Error = ex.Message }; }
                    var bytes = new UTF8Encoding(false).GetBytes(Json.Serialize(resp) + "\n");
                    s.Write(bytes, 0, bytes.Length);
                    s.Flush();
                    s.WaitForPipeDrain();
                }
                catch { }
            }
        }
    }

    public static class IpcClient
    {
        public static object Call(string cmd, Dictionary<string, object> args, int timeoutMs)
        {
            using (var c = new NamedPipeClientStream(".", GuardPaths.PipeName, PipeDirection.InOut))
            {
                c.Connect(timeoutMs);
                var req = Json.Serialize(new IpcRequest { Cmd = cmd, Args = args }) + "\n";
                var b = new UTF8Encoding(false).GetBytes(req);
                c.Write(b, 0, b.Length);
                c.Flush();
                var sr = new StreamReader(new TimeoutStream(c, timeoutMs > 0 ? Math.Max(timeoutMs, 30000) : 30000), new UTF8Encoding(false));
                var line = sr.ReadLine();
                if (line == null) throw new IOException("服务无响应");
                var resp = Json.Parse(line);
                if (!Json.Bool(resp, "Ok")) throw new InvalidOperationException(Json.Str(resp, "Error") ?? "服务返回错误");
                return Json.Get(resp, "Data");
            }
        }
    }
}
