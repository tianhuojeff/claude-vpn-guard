// written_by: claude-code
// Win32 P/Invoke：TCP 连接表、进程快照、Authenticode 校验、会话信息、管道客户端 PID。
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace ClaudeVPNGuard
{
    public class TcpConn
    {
        public IPAddress LocalAddr; public int LocalPort;
        public IPAddress RemoteAddr; public int RemotePort;
        public int State; public int Pid;
        public override string ToString() { return string.Format("{0}:{1}->{2}:{3} pid={4} st={5}", LocalAddr, LocalPort, RemoteAddr, RemotePort, Pid, State); }
    }

    public class ProcEntry { public int Pid; public int ParentPid; public string Name; }

    public static class Native
    {
        // ---------- TCP 表 ----------
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);
        const int AF_INET = 2, AF_INET6 = 23, TCP_TABLE_OWNER_PID_ALL = 5;

        static int Port(uint raw) { return ((int)(raw & 0xFF) << 8) | (int)((raw >> 8) & 0xFF); }

        public static List<TcpConn> TcpTable()
        {
            var list = new List<TcpConn>();
            ReadTable(AF_INET, list);
            ReadTable(AF_INET6, list);
            return list;
        }

        static void ReadTable(int af, List<TcpConn> list)
        {
            int len = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref len, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
            for (int attempt = 0; attempt < 4; attempt++)
            {
                len += 4096;
                var buf = Marshal.AllocHGlobal(len);
                try
                {
                    uint rc = GetExtendedTcpTable(buf, ref len, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
                    if (rc == 122) continue; // ERROR_INSUFFICIENT_BUFFER
                    if (rc != 0) return;
                    int n = Marshal.ReadInt32(buf);
                    IntPtr row = buf + 4;
                    if (af == AF_INET)
                    {
                        for (int i = 0; i < n; i++)
                        {
                            var c = new TcpConn
                            {
                                State = Marshal.ReadInt32(row, 0),
                                LocalAddr = new IPAddress((uint)Marshal.ReadInt32(row, 4)),
                                LocalPort = Port((uint)Marshal.ReadInt32(row, 8)),
                                RemoteAddr = new IPAddress((uint)Marshal.ReadInt32(row, 12)),
                                RemotePort = Port((uint)Marshal.ReadInt32(row, 16)),
                                Pid = Marshal.ReadInt32(row, 20)
                            };
                            list.Add(c);
                            row += 24;
                        }
                    }
                    else
                    {
                        // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid = 56 字节
                        for (int i = 0; i < n; i++)
                        {
                            var la = new byte[16]; var ra = new byte[16];
                            Marshal.Copy(row, la, 0, 16);
                            Marshal.Copy(row + 24, ra, 0, 16);
                            var c = new TcpConn
                            {
                                LocalAddr = new IPAddress(la),
                                LocalPort = Port((uint)Marshal.ReadInt32(row, 20)),
                                RemoteAddr = new IPAddress(ra),
                                RemotePort = Port((uint)Marshal.ReadInt32(row, 44)),
                                State = Marshal.ReadInt32(row, 48),
                                Pid = Marshal.ReadInt32(row, 52)
                            };
                            list.Add(c);
                            row += 56;
                        }
                    }
                    return;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }

        // ---------- 进程快照 ----------
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W pe);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W pe);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32W
        {
            public uint dwSize, cntUsage, th32ProcessID; public IntPtr th32DefaultHeapID;
            public uint th32ModuleID, cntThreads, th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }

        public static List<ProcEntry> Processes()
        {
            var list = new List<ProcEntry>();
            var snap = CreateToolhelp32Snapshot(2, 0);
            if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return list;
            try
            {
                var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W)) };
                if (!Process32FirstW(snap, ref pe)) return list;
                do list.Add(new ProcEntry { Pid = (int)pe.th32ProcessID, ParentPid = (int)pe.th32ParentProcessID, Name = pe.szExeFile });
                while (Process32NextW(snap, ref pe));
            }
            finally { CloseHandle(snap); }
            return list;
        }

        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageNameW(IntPtr h, int flags, StringBuilder sb, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, PROCESS_TERMINATE = 0x1, SYNCHRONIZE = 0x100000;

        [DllImport("kernel32.dll")] static extern bool ProcessIdToSessionId(uint pid, out uint session);

        // 进程所在的登录会话；查不到返回 -1
        public static int SessionOf(int pid)
        {
            uint sid;
            return ProcessIdToSessionId((uint)pid, out sid) ? (int)sid : -1;
        }

        public static string ProcessPath(int pid)
        {
            var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(1024); int sz = sb.Capacity;
                return QueryFullProcessImageNameW(h, 0, sb, ref sz) ? sb.ToString() : null;
            }
            finally { CloseHandle(h); }
        }

        public static bool Kill(int pid, int waitMs)
        {
            var h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, false, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                TerminateProcess(h, 0xC0DE);
                return WaitForSingleObject(h, (uint)waitMs) == 0;
            }
            finally { CloseHandle(h); }
        }

        // ---------- Authenticode ----------
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_FILE_INFO { public uint cbStruct; [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData; public uint dwUIChoice;
            public uint fdwRevocationChecks; public uint dwUnionChoice; public IntPtr pFile; public uint dwStateAction;
            public IntPtr hWVTStateData; public IntPtr pwszURLReference; public uint dwProvFlags; public uint dwUIContext; public IntPtr pSignatureSettings;
        }

        static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        // 校验文件签名有效（不联网吊销检查，避免离线/阻断时卡住）
        public static bool SignatureValid(string path)
        {
            var fi = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
            var pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fi));
            try
            {
                Marshal.StructureToPtr(fi, pFile, false);
                var wd = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    dwUIChoice = 2, fdwRevocationChecks = 0, dwUnionChoice = 1, pFile = pFile,
                    dwStateAction = 0, dwProvFlags = 0x00000080 /*CACHE_ONLY_URL_RETRIEVAL*/ | 0x00001000 /*DISABLE_MD2_MD4*/
                };
                return WinVerifyTrust(new IntPtr(-1), WINTRUST_ACTION_GENERIC_VERIFY_V2, ref wd) == 0;
            }
            finally { Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO)); Marshal.FreeHGlobal(pFile); }
        }

        // ---------- 会话 ----------
        [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode)] static extern bool WTSQuerySessionInformationW(IntPtr server, uint session, int infoClass, out IntPtr buf, out int bytes);
        [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode)]
        static extern bool WTSSendMessageW(IntPtr server, uint session, string title, int titleLen, string msg, int msgLen, uint style, uint timeout, out uint resp, bool wait);

        static string SessionString(uint session, int cls)
        {
            IntPtr p; int n;
            if (!WTSQuerySessionInformationW(IntPtr.Zero, session, cls, out p, out n)) return null;
            try { return Marshal.PtrToStringUni(p); } finally { WTSFreeMemory(p); }
        }

        // 当前控制台会话用户 → DOMAIN\user
        public static string ConsoleUser()
        {
            var s = WTSGetActiveConsoleSessionId();
            if (s == 0xFFFFFFFF) return null;
            var u = SessionString(s, 5); var d = SessionString(s, 7);
            if (string.IsNullOrEmpty(u)) return null;
            return string.IsNullOrEmpty(d) ? u : d + "\\" + u;
        }

        // 服务在 Session 0，用 WTSSendMessage 向用户桌面弹出提示（不等待）
        public static void PopupToConsole(string title, string msg)
        {
            try
            {
                uint resp;
                var s = WTSGetActiveConsoleSessionId();
                if (s == 0xFFFFFFFF) return;
                WTSSendMessageW(IntPtr.Zero, s, title, title.Length * 2, msg, msg.Length * 2, 0x40 /*MB_ICONINFORMATION*/ | 0x40000 /*TOPMOST*/, 30, out resp, false);
            }
            catch { }
        }

        // ---------- 命名管道 ----------
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
    }
}
