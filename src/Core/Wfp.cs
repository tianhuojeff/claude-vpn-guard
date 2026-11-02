// written_by: claude-code
// Windows Filtering Platform（用户态 API fwpuclnt.dll，无需内核驱动）持久过滤器。
// 自有 provider + sublayer（最高子层权重），每个 Claude 可执行文件、IPv4/IPv6 各一组（ALE_AUTH_CONNECT 层，覆盖 TCP 与 UDP）：
//   权重15 LOCK     阻断全部（锁定时才存在）
//   权重12 PROXYBLK 阻断 回环:通用代理端口（隔离模式）——迫使 Claude 只能走专用入口
//   权重10 LOOPOK   允许 回环（其余端口，含专用入口）
//   权重10 FAKEOK   允许 fake-ip 段（仅非隔离模式，供 TUN 使用）
//   权重 1 BLOCK    阻断其余一切（真实网卡、IPv6、UDP/QUIC/DNS）
// 过滤器带 PERSISTENT 标志：重启后、保护服务崩溃后仍由系统执行。
// 注意：Windows 防火墙的回环豁免是否会压过本子层的阻断，必须用 selftest 实测（不同 Windows 版本行为需验证）。
// 结构体偏移按 x64 布局；32 位进程拒绝使用。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ClaudeVPNGuard
{
    public class WfpFirewall : IFirewall
    {
        public static readonly Guid ProviderKey = new Guid("5d3c2a1e-7b9f-4c61-9e2a-c1a0de5c0a01");
        public static readonly Guid SubLayerKey = new Guid("5d3c2a1e-7b9f-4c61-9e2a-c1a0de5c0a02");
        static readonly Guid LayerConnectV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        static readonly Guid LayerConnectV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        static readonly Guid CondAppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        static readonly Guid CondRemoteAddr = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        static readonly Guid CondRemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");

        const uint FWP_UINT8 = 1, FWP_UINT16 = 2, FWP_BYTE_BLOB_TYPE = 12, FWP_V4_ADDR_MASK = 0x100, FWP_V6_ADDR_MASK = 0x101;
        const uint FWP_MATCH_EQUAL = 0;
        const uint ACTION_BLOCK = 0x1001, ACTION_PERMIT = 0x1002;
        const uint FILTER_FLAG_PERSISTENT = 1, PROVIDER_FLAG_PERSISTENT = 1, SUBLAYER_FLAG_PERSISTENT = 1;
        const uint FWP_E_ALREADY_EXISTS = 0x80320009, FWP_E_FILTER_NOT_FOUND = 0x80320003, FWP_E_NOT_FOUND = 0x80320008;

        // 由服务设置
        public bool IsolationMode;
        public List<int> GeneralProxyPorts = new List<int>();
        public bool Available { get { return IntPtr.Size == 8; } }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server, uint authn, IntPtr authId, IntPtr session, out IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderAdd0(IntPtr engine, IntPtr provider, IntPtr sd);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine, IntPtr subLayer, IntPtr sd);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine, IntPtr filter, IntPtr sd, out ulong id);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr sub);
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file, out IntPtr appId);
        [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr p);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr h);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr h, uint n, out IntPtr entries, out uint returned);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr h);

        static void Ok(uint rc, string what)
        {
            if (rc != 0) throw new InvalidOperationException(string.Format("WFP {0} 失败 0x{1:X8}", what, rc));
        }

        // 非托管内存分配器，统一释放
        class Arena : IDisposable
        {
            readonly List<IntPtr> ptrs = new List<IntPtr>();
            public IntPtr Alloc(int n) { var p = Marshal.AllocHGlobal(n); for (int i = 0; i < n; i++) Marshal.WriteByte(p, i, 0); ptrs.Add(p); return p; }
            public IntPtr Str(string s) { var p = Marshal.StringToHGlobalUni(s); ptrs.Add(p); return p; }
            public IntPtr Guid(Guid g) { var p = Alloc(16); Marshal.Copy(g.ToByteArray(), 0, p, 16); return p; }
            public void Dispose() { foreach (var p in ptrs) Marshal.FreeHGlobal(p); }
        }

        static void WriteGuid(IntPtr p, int off, Guid g) { Marshal.Copy(g.ToByteArray(), 0, p + off, 16); }
        static Guid ReadGuid(IntPtr p, int off) { var b = new byte[16]; Marshal.Copy(p + off, b, 0, 16); return new Guid(b); }

        T WithEngine<T>(Func<IntPtr, T> f)
        {
            if (!Available) throw new PlatformNotSupportedException("WFP 模块仅支持 64 位进程");
            IntPtr eng;
            Ok(FwpmEngineOpen0(null, 10 /*RPC_C_AUTHN_WINNT*/, IntPtr.Zero, IntPtr.Zero, out eng), "打开引擎");
            try { return f(eng); } finally { FwpmEngineClose0(eng); }
        }

        void EnsureProviderAndSublayer(IntPtr eng, Arena a)
        {
            // FWPM_PROVIDER0 (x64, 64 字节)
            var prov = a.Alloc(64);
            WriteGuid(prov, 0, ProviderKey);
            Marshal.WriteIntPtr(prov, 16, a.Str("Claude VPN Guard"));
            Marshal.WriteIntPtr(prov, 24, a.Str("Claude 代理防泄漏保护"));
            Marshal.WriteInt32(prov, 32, (int)PROVIDER_FLAG_PERSISTENT);
            uint rc = FwpmProviderAdd0(eng, prov, IntPtr.Zero);
            if (rc != 0 && rc != FWP_E_ALREADY_EXISTS) Ok(rc, "添加 provider");
            // FWPM_SUBLAYER0 (x64, 72 字节)
            var sub = a.Alloc(72);
            WriteGuid(sub, 0, SubLayerKey);
            Marshal.WriteIntPtr(sub, 16, a.Str("Claude VPN Guard"));
            Marshal.WriteIntPtr(sub, 24, a.Str("Claude 代理防泄漏保护子层"));
            Marshal.WriteInt32(sub, 32, (int)SUBLAYER_FLAG_PERSISTENT);
            Marshal.WriteIntPtr(sub, 40, a.Guid(ProviderKey));
            Marshal.WriteInt16(sub, 64, unchecked((short)0xFFFF));
            rc = FwpmSubLayerAdd0(eng, sub, IntPtr.Zero);
            if (rc != 0 && rc != FWP_E_ALREADY_EXISTS) Ok(rc, "添加 sublayer");
        }

        public static Guid FilterKey(string exe, string role)
        {
            using (var md5 = MD5.Create())
            {
                var h = md5.ComputeHash(Encoding.UTF8.GetBytes("cvg-wfp|" + role + "|" + exe.ToLowerInvariant()));
                h[7] = (byte)((h[7] & 0x0F) | 0x30); // 版本位
                return new Guid(h);
            }
        }

        class Cond { public Guid Field; public uint Type; public IntPtr Value; }

        // 构造并添加一个过滤器（FWPM_FILTER0 x64 = 200 字节）
        void AddFilter(IntPtr eng, Arena a, Guid key, string name, Guid layer, byte weight, uint action, List<Cond> conds)
        {
            var f = a.Alloc(200);
            WriteGuid(f, 0, key);
            Marshal.WriteIntPtr(f, 16, a.Str(name));
            Marshal.WriteIntPtr(f, 24, a.Str("Claude VPN Guard"));
            Marshal.WriteInt32(f, 32, (int)FILTER_FLAG_PERSISTENT);
            Marshal.WriteIntPtr(f, 40, a.Guid(ProviderKey));
            WriteGuid(f, 64, layer);
            WriteGuid(f, 80, SubLayerKey);
            Marshal.WriteInt32(f, 96, (int)FWP_UINT8);          // weight.type
            Marshal.WriteIntPtr(f, 104, new IntPtr(weight));     // weight.uint8
            var arr = a.Alloc(40 * conds.Count);
            for (int i = 0; i < conds.Count; i++)
            {
                var c = arr + 40 * i;
                WriteGuid(c, 0, conds[i].Field);
                Marshal.WriteInt32(c, 16, (int)FWP_MATCH_EQUAL);
                Marshal.WriteInt32(c, 24, (int)conds[i].Type);
                Marshal.WriteIntPtr(c, 32, conds[i].Value);
            }
            Marshal.WriteInt32(f, 112, conds.Count);
            Marshal.WriteIntPtr(f, 120, arr);
            Marshal.WriteInt32(f, 128, (int)action);
            ulong id;
            uint rc = FwpmFilterAdd0(eng, f, IntPtr.Zero, out id);
            if (rc == FWP_E_ALREADY_EXISTS) return;
            Ok(rc, "添加过滤器 " + name);
        }

        static IntPtr V4Mask(Arena a, IPAddress ip, int prefix)
        {
            var p = a.Alloc(8);
            var b = ip.GetAddressBytes();
            uint addr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; // 主机字节序
            uint mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
            Marshal.WriteInt32(p, 0, unchecked((int)addr));
            Marshal.WriteInt32(p, 4, unchecked((int)mask));
            return p;
        }
        static IntPtr V6Mask(Arena a, IPAddress ip, int prefix)
        {
            var p = a.Alloc(17);
            Marshal.Copy(ip.GetAddressBytes(), 0, p, 16);
            Marshal.WriteByte(p, 16, (byte)prefix);
            return p;
        }

        List<Guid> KeysFor(string exe)
        {
            var roles = new[] { "lock4", "lock6", "block4", "block6", "loop4", "loop6", "fake4" }.ToList();
            for (int i = 0; i < 32; i++) { roles.Add("pblk4-" + i); roles.Add("pblk6-" + i); }
            return roles.Select(r => FilterKey(exe, r)).ToList();
        }

        void AddStatic(IntPtr eng, Arena a, string exe)
        {
            IntPtr appId;
            Ok(FwpmGetAppIdFromFileName0(exe, out appId), "获取 AppId " + exe);
            try
            {
                // 复制 appId blob 到 arena，便于统一生命周期
                Func<Cond> app = () => new Cond { Field = CondAppId, Type = FWP_BYTE_BLOB_TYPE, Value = appId };
                var name = Path.GetFileName(exe);
                AddFilter(eng, a, FilterKey(exe, "block4"), "CVG 阻断 " + name + " v4", LayerConnectV4, 1, ACTION_BLOCK, new List<Cond> { app() });
                AddFilter(eng, a, FilterKey(exe, "block6"), "CVG 阻断 " + name + " v6", LayerConnectV6, 1, ACTION_BLOCK, new List<Cond> { app() });
                AddFilter(eng, a, FilterKey(exe, "loop4"), "CVG 允许回环 " + name + " v4", LayerConnectV4, 10, ACTION_PERMIT,
                    new List<Cond> { app(), new Cond { Field = CondRemoteAddr, Type = FWP_V4_ADDR_MASK, Value = V4Mask(a, IPAddress.Parse("127.0.0.0"), 8) } });
                AddFilter(eng, a, FilterKey(exe, "loop6"), "CVG 允许回环 " + name + " v6", LayerConnectV6, 10, ACTION_PERMIT,
                    new List<Cond> { app(), new Cond { Field = CondRemoteAddr, Type = FWP_V6_ADDR_MASK, Value = V6Mask(a, IPAddress.IPv6Loopback, 128) } });
                if (!IsolationMode && FakeIpRange != null)
                {
                    var parts = FakeIpRange.Split('/');
                    AddFilter(eng, a, FilterKey(exe, "fake4"), "CVG 允许 fake-ip " + name, LayerConnectV4, 10, ACTION_PERMIT,
                        new List<Cond> { app(), new Cond { Field = CondRemoteAddr, Type = FWP_V4_ADDR_MASK, Value = V4Mask(a, IPAddress.Parse(parts[0]), parts.Length > 1 ? int.Parse(parts[1]) : 32) } });
                }
                if (IsolationMode)
                {
                    var ports = GeneralProxyPorts.Distinct().Take(32).ToList();
                    for (int i = 0; i < ports.Count; i++)
                    {
                        var pv = new IntPtr(ports[i]);
                        AddFilter(eng, a, FilterKey(exe, "pblk4-" + i), "CVG 禁止 " + name + " 使用通用代理端口 " + ports[i], LayerConnectV4, 12, ACTION_BLOCK,
                            new List<Cond> { app(), new Cond { Field = CondRemoteAddr, Type = FWP_V4_ADDR_MASK, Value = V4Mask(a, IPAddress.Parse("127.0.0.0"), 8) }, new Cond { Field = CondRemotePort, Type = FWP_UINT16, Value = pv } });
                        AddFilter(eng, a, FilterKey(exe, "pblk6-" + i), "CVG 禁止 " + name + " 使用通用代理端口 " + ports[i] + " v6", LayerConnectV6, 12, ACTION_BLOCK,
                            new List<Cond> { app(), new Cond { Field = CondRemoteAddr, Type = FWP_V6_ADDR_MASK, Value = V6Mask(a, IPAddress.IPv6Loopback, 128) }, new Cond { Field = CondRemotePort, Type = FWP_UINT16, Value = pv } });
                    }
                }
            }
            finally { FwpmFreeMemory0(ref appId); }
        }

        void SetLockFor(IntPtr eng, Arena a, string exe, bool on)
        {
            var k4 = FilterKey(exe, "lock4"); var k6 = FilterKey(exe, "lock6");
            if (!on) { FwpmFilterDeleteByKey0(eng, ref k4); FwpmFilterDeleteByKey0(eng, ref k6); return; }
            IntPtr appId;
            Ok(FwpmGetAppIdFromFileName0(exe, out appId), "获取 AppId");
            try
            {
                var name = Path.GetFileName(exe);
                AddFilter(eng, a, k4, "CVG 锁定 " + name + " v4", LayerConnectV4, 15, ACTION_BLOCK, new List<Cond> { new Cond { Field = CondAppId, Type = FWP_BYTE_BLOB_TYPE, Value = appId } });
                AddFilter(eng, a, k6, "CVG 锁定 " + name + " v6", LayerConnectV6, 15, ACTION_BLOCK, new List<Cond> { new Cond { Field = CondAppId, Type = FWP_BYTE_BLOB_TYPE, Value = appId } });
            }
            finally { FwpmFreeMemory0(ref appId); }
        }

        string FakeIpRange;
        List<string> lastExes = new List<string>();

        public bool AllProfilesEnabled(out string detail)
        {
            // BFE（基础筛选引擎）服务必须运行，WFP 过滤器才被执行
            try
            {
                using (var sc = new System.ServiceProcess.ServiceController("BFE"))
                {
                    bool run = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                    detail = run ? "基础筛选引擎(BFE)运行中" : "基础筛选引擎(BFE)未运行：" + sc.Status;
                    return run;
                }
            }
            catch (Exception ex) { detail = "无法查询 BFE：" + ex.Message; return false; }
        }

        // 原子重建：在一个 WFP 事务中删除旧的本程序过滤器并按当前配置重建；任一步失败整体回滚，原有过滤器保持不变
        public void EnsureRules(IList<string> exePaths, string fakeIpRange, bool lockEnabled)
        {
            FakeIpRange = fakeIpRange;
            WithEngine(eng =>
            {
                using (var a = new Arena())
                {
                    Ok(FwpmTransactionBegin0(eng, 0), "开始事务");
                    try
                    {
                        EnsureProviderAndSublayer(eng, a);
                        foreach (var key in OurFilterKeys(eng)) { var k = key; FwpmFilterDeleteByKey0(eng, ref k); }
                        foreach (var exe in exePaths)
                        {
                            AddStatic(eng, a, exe);
                            if (lockEnabled) SetLockFor(eng, a, exe, true);
                        }
                        Ok(FwpmTransactionCommit0(eng), "提交事务");
                    }
                    catch { FwpmTransactionAbort0(eng); throw; }
                }
                return 0;
            });
            lastExes = exePaths.ToList();
        }

        public void SetLock(bool enabled)
        {
            WithEngine(eng =>
            {
                using (var a = new Arena())
                {
                    Ok(FwpmTransactionBegin0(eng, 0), "开始事务");
                    try
                    {
                        foreach (var exe in lastExes) SetLockFor(eng, a, exe, enabled);
                        Ok(FwpmTransactionCommit0(eng), "提交事务");
                    }
                    catch { FwpmTransactionAbort0(eng); throw; }
                }
                return 0;
            });
        }

        bool Exists(IntPtr eng, Guid key)
        {
            IntPtr f;
            var k = key;
            uint rc = FwpmFilterGetByKey0(eng, ref k, out f);
            if (rc == 0) { FwpmFreeMemory0(ref f); return true; }
            return false;
        }

        public bool VerifyRules(IList<string> exePaths, string fakeIpRange, bool expectLock, out string detail)
        {
            var problems = new List<string>();
            try
            {
                WithEngine(eng =>
                {
                    IntPtr sub; var sk = SubLayerKey;
                    if (FwpmSubLayerGetByKey0(eng, ref sk, out sub) != 0) problems.Add("WFP 子层不存在");
                    else FwpmFreeMemory0(ref sub);
                    foreach (var exe in exePaths)
                    {
                        var n = Path.GetFileName(exe);
                        if (!Exists(eng, FilterKey(exe, "block4")) || !Exists(eng, FilterKey(exe, "block6"))) problems.Add("缺少 WFP 阻断：" + n);
                        if (!Exists(eng, FilterKey(exe, "loop4"))) problems.Add("缺少 WFP 回环允许：" + n);
                        if (IsolationMode && GeneralProxyPorts.Count > 0 && !Exists(eng, FilterKey(exe, "pblk4-0"))) problems.Add("缺少 WFP 通用端口阻断：" + n);
                        if (expectLock && !Exists(eng, FilterKey(exe, "lock4"))) problems.Add("WFP 锁定未生效：" + n);
                    }
                    return 0;
                });
            }
            catch (Exception ex) { problems.Add(ex.Message); }
            detail = problems.Count == 0 ? string.Format("WFP 持久过滤器完整（{0} 个程序{1}）", exePaths.Count, IsolationMode ? "，隔离模式" : "") : string.Join("；", problems.Take(5));
            return problems.Count == 0;
        }

        // 枚举本子层下的全部过滤器（FWPM_FILTER0：subLayerKey 偏移 80，filterKey 偏移 0）
        List<Guid> OurFilterKeys(IntPtr eng)
        {
            var keys = new List<Guid>();
            IntPtr h;
            if (FwpmFilterCreateEnumHandle0(eng, IntPtr.Zero, out h) != 0) return keys;
            try
            {
                while (true)
                {
                    IntPtr entries; uint n;
                    if (FwpmFilterEnum0(eng, h, 512, out entries, out n) != 0 || n == 0) break;
                    try
                    {
                        for (int i = 0; i < n; i++)
                        {
                            var f = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                            if (ReadGuid(f, 80) == SubLayerKey) keys.Add(ReadGuid(f, 0));
                        }
                    }
                    finally { FwpmFreeMemory0(ref entries); }
                    if (n < 512) break;
                }
            }
            finally { FwpmFilterDestroyEnumHandle0(eng, h); }
            return keys;
        }

        public int CountFilters() { return WithEngine(eng => OurFilterKeys(eng).Count); }

        // 系统全部 WFP 过滤器快照（key → 名称|子层），用于 selftest 前后对比“系统原有 WFP 状态未改变”
        public Dictionary<Guid, string> SnapshotAll()
        {
            var map = new Dictionary<Guid, string>();
            WithEngine(eng =>
            {
                IntPtr h;
                if (FwpmFilterCreateEnumHandle0(eng, IntPtr.Zero, out h) != 0) return 0;
                try
                {
                    while (true)
                    {
                        IntPtr entries; uint n;
                        if (FwpmFilterEnum0(eng, h, 1024, out entries, out n) != 0 || n == 0) break;
                        try
                        {
                            for (int i = 0; i < n; i++)
                            {
                                var f = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                                var np = Marshal.ReadIntPtr(f, 16);
                                map[ReadGuid(f, 0)] = (np == IntPtr.Zero ? "(无名)" : Marshal.PtrToStringUni(np)) + "|" + (ReadGuid(f, 80) == SubLayerKey ? "本程序子层" : "其他子层");
                            }
                        }
                        finally { FwpmFreeMemory0(ref entries); }
                        if (n < 1024) break;
                    }
                }
                finally { FwpmFilterDestroyEnumHandle0(eng, h); }
                return 0;
            });
            return map;
        }

        // 某程序的过滤器是否已全部删除
        public List<string> RemainingFor(string exe)
        {
            return WithEngine(eng => KeysFor(exe).Where(k => Exists(eng, k)).Select(k => k.ToString()).ToList());
        }

        // 审计：列出本子层全部过滤器，并证明每一个都带 ALE_APP_ID 条件（只作用于指定程序，不影响局域网/其他软件）
        public List<string> AuditFilters(out int total, out int unscoped, out bool persistentAll)
        {
            var lines = new List<string>();
            int t = 0, u = 0; bool pAll = true;
            WithEngine(eng =>
            {
                IntPtr h;
                if (FwpmFilterCreateEnumHandle0(eng, IntPtr.Zero, out h) != 0) return 0;
                try
                {
                    while (true)
                    {
                        IntPtr entries; uint n;
                        if (FwpmFilterEnum0(eng, h, 512, out entries, out n) != 0 || n == 0) break;
                        try
                        {
                            for (int i = 0; i < n; i++)
                            {
                                var f = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                                if (ReadGuid(f, 80) != SubLayerKey) continue;
                                t++;
                                var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(f, 16));
                                uint flags = (uint)Marshal.ReadInt32(f, 32);
                                if ((flags & FILTER_FLAG_PERSISTENT) == 0) pAll = false;
                                int nc = Marshal.ReadInt32(f, 112);
                                var conds = Marshal.ReadIntPtr(f, 120);
                                bool app = false;
                                for (int c = 0; c < nc; c++) if (ReadGuid(conds + 40 * c, 0) == CondAppId) app = true;
                                if (!app) u++;
                                var layer = ReadGuid(f, 64) == LayerConnectV4 ? "CONNECT_V4" : ReadGuid(f, 64) == LayerConnectV6 ? "CONNECT_V6" : ReadGuid(f, 64).ToString();
                                uint act = (uint)Marshal.ReadInt32(f, 128);
                                lines.Add(string.Format("{0} | {1} | 权重 {2} | {3} | 条件 {4} 个{5} | {6}", name, layer, Marshal.ReadByte(f, 104), act == ACTION_BLOCK ? "阻断" : act == ACTION_PERMIT ? "允许" : act.ToString("X"), nc, app ? "（含程序条件）" : "（⚠无程序条件）", (flags & FILTER_FLAG_PERSISTENT) != 0 ? "持久" : "动态"));
                            }
                        }
                        finally { FwpmFreeMemory0(ref entries); }
                        if (n < 512) break;
                    }
                }
                finally { FwpmFilterDestroyEnumHandle0(eng, h); }
                return 0;
            });
            total = t; unscoped = u; persistentAll = pAll;
            return lines;
        }

        public int RemoveAll()
        {
            return WithEngine(eng =>
            {
                int n = 0;
                Ok(FwpmTransactionBegin0(eng, 0), "开始事务");
                try
                {
                    foreach (var key in OurFilterKeys(eng)) { var k = key; if (FwpmFilterDeleteByKey0(eng, ref k) == 0) n++; }
                    var sk = SubLayerKey; FwpmSubLayerDeleteByKey0(eng, ref sk);
                    var pk = ProviderKey; FwpmProviderDeleteByKey0(eng, ref pk);
                    Ok(FwpmTransactionCommit0(eng), "提交事务");
                }
                catch { FwpmTransactionAbort0(eng); throw; }
                return n;
            });
        }

        // 测试/自检：只删除某个程序的过滤器
        public int RemoveFor(string exe)
        {
            return WithEngine(eng =>
            {
                int n = 0;
                foreach (var key in KeysFor(exe)) { var k = key; if (FwpmFilterDeleteByKey0(eng, ref k) == 0) n++; }
                return n;
            });
        }

        // 只给指定程序加规则（不删别的过滤器），自检用
        public void AddFor(string exe, string fakeIpRange, bool lockEnabled)
        {
            FakeIpRange = fakeIpRange;
            WithEngine(eng =>
            {
                using (var a = new Arena())
                {
                    Ok(FwpmTransactionBegin0(eng, 0), "开始事务");
                    try
                    {
                        EnsureProviderAndSublayer(eng, a);
                        foreach (var key in KeysFor(exe)) { var k = key; FwpmFilterDeleteByKey0(eng, ref k); }
                        AddStatic(eng, a, exe);
                        if (lockEnabled) SetLockFor(eng, a, exe, true);
                        Ok(FwpmTransactionCommit0(eng), "提交事务");
                    }
                    catch { FwpmTransactionAbort0(eng); throw; }
                }
                return 0;
            });
        }
    }

    // 组合：Windows 防火墙持久规则（V1）+ WFP 持久过滤器（V2），任一层失败都按不安全处理
    public class LayeredFirewall : IFirewall
    {
        public readonly WindowsFirewall Win;
        public readonly WfpFirewall Wfp;
        public LayeredFirewall(WindowsFirewall w, WfpFirewall f) { Win = w; Wfp = f; }

        public bool AllProfilesEnabled(out string detail)
        {
            string d1, d2;
            bool a = Win.AllProfilesEnabled(out d1);
            bool b = Wfp.AllProfilesEnabled(out d2);
            detail = d1 + "；" + d2;
            return a && b;
        }
        public void EnsureRules(IList<string> exe, string fake, bool lockEnabled)
        {
            Exception first = null;
            try { Win.EnsureRules(exe, fake, lockEnabled); } catch (Exception ex) { first = ex; }
            try { Wfp.EnsureRules(exe, fake, lockEnabled); } catch (Exception ex) { if (first == null) first = ex; }
            if (first != null) throw first;
        }
        public void SetLock(bool on)
        {
            Exception first = null;
            // 锁定时两层都尝试；解锁时任一层失败即抛出（上层按“仍锁定”处理）
            try { Wfp.SetLock(on); } catch (Exception ex) { first = ex; }
            try { Win.SetLock(on); } catch (Exception ex) { if (first == null) first = ex; }
            if (first != null) throw first;
        }
        public bool VerifyRules(IList<string> exe, string fake, bool expectLock, out string detail)
        {
            string d1, d2;
            bool a = Win.VerifyRules(exe, fake, expectLock, out d1);
            bool b = Wfp.VerifyRules(exe, fake, expectLock, out d2);
            detail = "防火墙：" + d1 + "；" + d2;
            return a && b;
        }
        public int RemoveAll() { int n = 0; try { n += Wfp.RemoveAll(); } catch (Exception ex) { Log.Error("删除 WFP 过滤器失败：" + ex.Message); } n += Win.RemoveAll(); return n; }
    }
}
