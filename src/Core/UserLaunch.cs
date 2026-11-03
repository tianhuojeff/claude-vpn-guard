// written_by: claude-code
// 以普通用户权限（非管理员）启动程序。
// 原因：安装程序是管理员权限，直接 Process.Start 卫士界面会把管理员权限传下去；
// 之后界面里「启动 Claude」也会让 Claude 变成管理员进程，Windows 会拦截从资源管理器往 Claude 拖放文件（禁止图标）。
// 做法：交给已在运行的资源管理器（普通权限）去打开，新进程就拿到资源管理器的普通权限。
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;

namespace ClaudeVPNGuard
{
    public static class UserLaunch
    {
        public static bool IsElevated()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        // 通过资源管理器打开 exe（不能带参数）。成功交出去返回 true。
        public static bool StartViaExplorer(string exe)
        {
            try
            {
                var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                Process.Start(new ProcessStartInfo(explorer, "\"" + exe + "\"") { UseShellExecute = false });
                return true;
            }
            catch { return false; }
        }

        // 界面以管理员权限启动时，改由资源管理器以普通权限重开自己。
        // 防止死循环：资源管理器本身也是管理员（如关闭了 UAC）时，重开后仍是管理员，这时 30 秒内不再重开，直接继续运行。
        public static bool RelaunchUnelevatedIfNeeded(string exe)
        {
            if (!IsElevated()) return false;
            var marker = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ClaudeVPNGuard", "relaunch-unelevated.marker");
            try
            {
                if (File.Exists(marker) && (DateTime.UtcNow - File.GetLastWriteTimeUtc(marker)).TotalSeconds < 30) return false;
                Directory.CreateDirectory(Path.GetDirectoryName(marker));
                File.WriteAllText(marker, DateTime.UtcNow.ToString("o"));
            }
            catch { return false; }
            return StartViaExplorer(exe);
        }
    }
}
