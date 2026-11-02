// written_by: claude-code
// 代理恢复后的自动重开与续跑（在用户桌面会话中执行）：
//   ① 启动前完整检测（preparelaunch）通过才解锁 → ② 经专用入口重开 Claude → ③ 等 Claude 联网就绪
//   → ④ 用 claude://code/new?q= 打开“恢复协调”会话（提示词已填好）→ ⑤ 替用户按回车发送
//   → ⑥ 核实协调会话已开始；失败则提示用户手动按回车。每份清单只处理一次，避免循环重开。
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace ClaudeVPNGuard
{
    static class AutoResume
    {
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);
        [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll")] static extern bool AttachThreadInput(uint a, uint b, bool attach);
        [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();

        static string HandledFile { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ClaudeVPNGuard", "resume-handled.txt"); } }
        static volatile bool running;

        public static bool AlreadyHandled(string id)
        {
            try { return File.Exists(HandledFile) && File.ReadAllText(HandledFile).Trim() == id; } catch { return false; }
        }
        static void MarkHandled(string id)
        {
            try { Directory.CreateDirectory(Path.GetDirectoryName(HandledFile)); File.WriteAllText(HandledFile, id); } catch { }
        }

        static Process ClaudeMain()
        {
            foreach (var p in Process.GetProcessesByName("claude"))
            {
                try { if (p.MainWindowHandle != IntPtr.Zero && p.MainModule.FileName.IndexOf(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) >= 0) return p; } catch { }
            }
            return null;
        }

        static bool ClaudeOnline(int port)
        {
            var pids = Process.GetProcessesByName("claude").Select(p => p.Id).ToList();
            return Native.TcpTable().Any(t => pids.Contains(t.Pid) && t.State == 5 && t.RemotePort == port);
        }

        static void Foreground(IntPtr h)
        {
            ShowWindow(h, 9); // SW_RESTORE
            uint pid;
            uint fg = GetWindowThreadProcessId(GetForegroundWindow(), out pid);
            uint me = GetCurrentThreadId();
            if (fg != me) AttachThreadInput(me, fg, true);
            SetForegroundWindow(h);
            if (fg != me) AttachThreadInput(me, fg, false);
        }

        // 协调会话是否已开始：在打开深链接之后出现、且已生成标题的新会话
        static bool CoordinatorStarted(DateTime since)
        {
            try
            {
                var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Claude-Data");
                foreach (var f in Directory.EnumerateFiles(root, "local_*.json", SearchOption.AllDirectories))
                {
                    if (!f.Contains(@"\claude-code-sessions\") || File.GetCreationTime(f) < since) continue;
                    var head = File.ReadAllText(f);
                    if (System.Text.RegularExpressions.Regex.IsMatch(head, "\"title\":\"[^\"]+\"")) return true;
                }
            }
            catch { }
            return false;
        }

        // status：服务返回的状态快照；notify：托盘通知
        public static void Maybe(object status, Action<string, string, ToolTipIcon> notify)
        {
            if (running) return;
            var id = Json.Str(status, "ResumeId");
            if (id == null || !Json.Bool(status, "AutoResume") || AlreadyHandled(id)) return;
            if (Json.Str(status, "State") != "Tripped" || Json.Str(status, "LastFailure") != null || Json.Int(status, "ClaudeProcesses", 0) > 0) return;
            running = true;
            var th = new Thread(() =>
            {
                try { Run(id, status, notify); }
                catch (Exception ex) { notify("自动续跑失败", ex.Message, ToolTipIcon.Error); }
                finally { running = false; }
            }) { IsBackground = true };
            th.SetApartmentState(ApartmentState.STA); // SendKeys 需要 STA
            th.Start();
        }

        static void Run(string id, object status, Action<string, string, ToolTipIcon> notify)
        {
            MarkHandled(id); // 先标记：无论成败都不重复自动重开
            object data;
            try { data = IpcClient.Call("preparelaunch", null, 30000); }
            catch (Exception ex) { notify("暂不自动重开", "启动前检测未通过：" + ex.Message, ToolTipIcon.Warning); return; }
            var target = Json.Str(data, "LaunchTarget");
            bool iso = false; int port = 17897;
            try { var nd = IpcClient.Call("nodes", null, 1500); iso = Json.Bool(nd, "Isolation"); port = Json.Int(nd, "DedicatedPort", 17897); } catch { }
            if (string.IsNullOrEmpty(target)) { notify("自动重开失败", "未找到 Claude 启动入口", ToolTipIcon.Error); return; }
            ClaudeLauncher.Launch(target, iso, port);
            notify("代理已恢复", "已自动重新打开 Claude，正在恢复被中断的会话…", ToolTipIcon.Info);

            var sw = Stopwatch.StartNew();
            while (sw.Elapsed.TotalSeconds < 60 && !(ClaudeMain() != null && (!iso || ClaudeOnline(port)))) Thread.Sleep(1000);
            Thread.Sleep(4000); // 让会话列表加载完成

            var planData = IpcClient.Call("resume-plan", null, 3000);
            var prompt = Json.Str(planData, "Prompt");
            var plan = Json.Get(planData, "Plan");
            var sessions = Json.Arr(plan, "Sessions").ToList();
            if (sessions.Count == 0) { IpcClient.Call("resume-mark", new System.Collections.Generic.Dictionary<string, object> { { "status", "done" } }, 3000); notify("Claude 已重开", "关闭前没有正在运行的会话，无需续跑。", ToolTipIcon.Info); return; }
            var folder = Json.Str(sessions[0], "Cwd") ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            var t0 = DateTime.Now.AddSeconds(-1);
            Process.Start("claude://code/new?q=" + Uri.EscapeDataString(prompt) + "&folder=" + Uri.EscapeDataString(folder));
            Thread.Sleep(5000);
            bool started = false;
            for (int attempt = 0; attempt < 3 && !started; attempt++)
            {
                var main = ClaudeMain();
                if (main != null)
                {
                    Foreground(main.MainWindowHandle);
                    Thread.Sleep(600);
                    SendKeys.SendWait("{ENTER}");
                }
                for (int i = 0; i < 10 && !started; i++) { Thread.Sleep(1000); started = CoordinatorStarted(t0); }
            }
            if (started)
            {
                IpcClient.Call("resume-mark", new System.Collections.Generic.Dictionary<string, object> { { "status", "dispatched" } }, 3000);
                notify("已自动续跑", "恢复协调会话已开始，将通知 " + sessions.Count + " 个被中断的会话继续。", ToolTipIcon.Info);
            }
            else notify("请按一次回车", "已打开恢复协调会话（提示词已填好），自动发送未成功，请在 Claude 中按回车。", ToolTipIcon.Warning);
        }
    }
}
