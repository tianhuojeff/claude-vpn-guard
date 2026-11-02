// written_by: claude-code
// Mihomo 内核退出的即时检测：找到监听代理端口的进程，等待其进程句柄（内核对象信号，毫秒级），不靠轮询。
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace ClaudeVPNGuard
{
    public class CoreWatcher : IDisposable
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        const uint SYNCHRONIZE = 0x100000, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public int WatchedPid { get; private set; }
        public Action<string> Exited;
        RegisteredWaitHandle reg;
        ManualResetEvent ev;
        readonly object gate = new object();

        // 根据监听端口定位内核进程（任一通用端口或专用端口）
        public static int FindCorePid(params int[] ports)
        {
            foreach (var t in Native.TcpTable())
                if (t.State == 2 /*LISTEN*/ && ports.Contains(t.LocalPort) && t.Pid > 4) return t.Pid;
            return 0;
        }

        // 确保正在监视 pid；pid 变化（内核重启）则切换监视对象
        public bool Watch(int pid)
        {
            lock (gate)
            {
                if (pid <= 0) return false;
                if (pid == WatchedPid && reg != null) return true;
                Stop();
                var h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return false;
                ev = new ManualResetEvent(false) { SafeWaitHandle = new SafeWaitHandle(h, true) };
                WatchedPid = pid;
                reg = ThreadPool.RegisterWaitForSingleObject(ev, (state, timedOut) =>
                {
                    int p = (int)state;
                    lock (gate) { if (WatchedPid == p) { WatchedPid = 0; } }
                    var cb = Exited;
                    if (cb != null) cb("pid " + p);
                }, pid, Timeout.Infinite, true);
                return true;
            }
        }

        void Stop()
        {
            if (reg != null) { reg.Unregister(null); reg = null; }
            if (ev != null) { ev.Dispose(); ev = null; }
            WatchedPid = 0;
        }

        public void Dispose() { lock (gate) Stop(); }
    }
}
