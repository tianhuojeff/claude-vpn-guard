// written_by: claude-code
// Windows Defender 防火墙规则管理（COM HNetCfg.FwPolicy2，持久化规则，重启/崩溃后仍生效）。
// 两层规则，均只作用于已核实的 Claude 可执行文件路径：
//   Static：永久阻断 Claude 连接 除 [回环, fake-ip 段] 以外的任何地址（IPv4/IPv6、TCP/UDP/QUIC 全协议）。
//           => Claude 永远不能直连真实出口，只能走 本地代理端口 或 TUN fake-ip。
//   Lock  ：阻断 Claude 连接 任何地址。未验证安全时启用；验证通过才禁用。
// 注意：Windows 防火墙对回环流量默认豁免，Lock 无法阻断 Claude→127.0.0.1:代理端口。
//       因此“Mihomo 把 Claude 流量直连出去”只能靠检测 + 结束进程处理（见 docs/设计说明.md）。
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace ClaudeVPNGuard
{
    public static class AddrMath
    {
        // 解析 CIDR → [起, 止]（大端字节）
        public static void Cidr(string cidr, out byte[] lo, out byte[] hi)
        {
            var parts = cidr.Trim().Split('/');
            var ip = IPAddress.Parse(parts[0]).GetAddressBytes();
            int bits = parts.Length > 1 ? int.Parse(parts[1]) : ip.Length * 8;
            lo = (byte[])ip.Clone(); hi = (byte[])ip.Clone();
            for (int i = 0; i < ip.Length * 8; i++)
            {
                if (i < bits) continue;
                int b = i / 8, m = 0x80 >> (i % 8);
                lo[b] = (byte)(lo[b] & ~m);
                hi[b] = (byte)(hi[b] | m);
            }
        }

        static byte[] Add(byte[] a, int d)
        {
            var r = (byte[])a.Clone();
            for (int i = r.Length - 1; i >= 0; i--)
            {
                int v = r[i] + d;
                if (d > 0) { if (v <= 255) { r[i] = (byte)v; return r; } r[i] = 0; }
                else { if (v >= 0) { r[i] = (byte)v; return r; } r[i] = 255; }
            }
            return null; // 溢出
        }
        static int Cmp(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return a[i].CompareTo(b[i]);
            return 0;
        }

        // 求全地址空间减去 excludes 后的区间列表，格式 "a-b"
        public static List<string> Complement(int family, IEnumerable<string> excludesCidr)
        {
            int len = family == 4 ? 4 : 16;
            var ex = new List<byte[][]>();
            foreach (var c in excludesCidr)
            {
                byte[] lo, hi;
                Cidr(c, out lo, out hi);
                if (lo.Length == len) ex.Add(new[] { lo, hi });
            }
            ex.Sort((x, y) => Cmp(x[0], y[0]));
            var res = new List<string>();
            var cur = new byte[len];
            var max = Enumerable.Repeat((byte)255, len).ToArray();
            bool done = false;
            foreach (var e in ex)
            {
                if (done) break;
                if (Cmp(e[1], cur) < 0) continue;
                if (Cmp(e[0], cur) > 0) res.Add(Fmt(cur) + "-" + Fmt(Add(e[0], -1)));
                var nx = Add(e[1], 1);
                if (nx == null) { done = true; break; }
                if (Cmp(nx, cur) > 0) cur = nx;
            }
            if (!done) res.Add(Fmt(cur) + "-" + Fmt(max));
            return res;
        }

        static string Fmt(byte[] b) { return new IPAddress(b).ToString(); }

        public static bool InCidr(IPAddress ip, string cidr)
        {
            byte[] lo, hi;
            Cidr(cidr, out lo, out hi);
            var b = ip.GetAddressBytes();
            if (b.Length != lo.Length) return false;
            return Cmp(b, lo) >= 0 && Cmp(b, hi) <= 0;
        }

        // Claude 被允许连接的目的地：回环 + fake-ip 段
        public static bool IsAllowedDestination(IPAddress ip, string fakeIpRange)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (IPAddress.IsLoopback(ip)) return true;
            if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true; // 未连接/监听
            return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && InCidr(ip, fakeIpRange);
        }

        public static string StaticBlockRemoteAddresses(string fakeIpRange)
        {
            var v4 = Complement(4, new[] { "127.0.0.0/8", fakeIpRange });
            var v6 = Complement(6, new[] { "::1/128" });
            return string.Join(",", v4.Concat(v6));
        }
    }

    public interface IFirewall
    {
        bool AllProfilesEnabled(out string detail);
        void EnsureRules(IList<string> exePaths, string fakeIpRange, bool lockEnabled);
        void SetLock(bool enabled);
        bool VerifyRules(IList<string> exePaths, string fakeIpRange, bool expectLock, out string detail);
        int RemoveAll();
    }

    public class WindowsFirewall : IFirewall
    {
        const int DirOut = 2, ActBlock = 0, ProtoAny = 256, ProfilesAll = 0x7FFFFFFF;
        const string StaticPrefix = "ClaudeVPNGuard-Static-";
        const string LockPrefix = "ClaudeVPNGuard-Lock-";

        static dynamic Policy()
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true);
            return Activator.CreateInstance(t);
        }

        public static string PathKey(string exe)
        {
            using (var sha = SHA1.Create())
            {
                var h = sha.ComputeHash(Encoding.UTF8.GetBytes(exe.ToLowerInvariant()));
                return BitConverter.ToString(h, 0, 6).Replace("-", "");
            }
        }

        public bool AllProfilesEnabled(out string detail)
        {
            var p = Policy();
            var off = new List<string>();
            foreach (var kv in new[] { new KeyValuePair<int, string>(1, "域"), new KeyValuePair<int, string>(2, "专用"), new KeyValuePair<int, string>(4, "公用") })
            {
                bool en = p.FirewallEnabled[kv.Key];
                if (!en) off.Add(kv.Value);
            }
            detail = off.Count == 0 ? "防火墙三个配置文件均已启用" : "防火墙已关闭的配置文件：" + string.Join("、", off);
            return off.Count == 0;
        }

        List<dynamic> OurRules(dynamic policy)
        {
            var list = new List<dynamic>();
            foreach (dynamic r in policy.Rules)
            {
                string g = null;
                try { g = r.Grouping; } catch { }
                if (g == GuardPaths.RuleGroup) list.Add(r);
            }
            return list;
        }

        public void EnsureRules(IList<string> exePaths, string fakeIpRange, bool lockEnabled)
        {
            var policy = Policy();
            List<dynamic> ours = OurRules(policy);
            var existing = ours.ToDictionary(r => (string)r.Name, r => r);
            var remote = AddrMath.StaticBlockRemoteAddresses(fakeIpRange);
            foreach (var exe in exePaths)
            {
                var key = PathKey(exe);
                Upsert(policy, existing, StaticPrefix + key, exe, remote, true, "Claude VPN Guard：禁止 Claude 绕过代理直连真实网络");
                Upsert(policy, existing, LockPrefix + key, exe, "*", lockEnabled, "Claude VPN Guard：代理未验证安全时阻断 Claude 全部网络");
            }
        }

        static void Upsert(dynamic policy, Dictionary<string, dynamic> existing, string name, string exe, string remote, bool enabled, string desc)
        {
            dynamic r;
            if (existing.TryGetValue(name, out r))
            {
                bool changed = false;
                if (!string.Equals((string)r.ApplicationName, exe, StringComparison.OrdinalIgnoreCase)) { r.ApplicationName = exe; changed = true; }
                if (remote != "*" && (string)r.RemoteAddresses == "*") changed = true;
                if ((int)r.Action != ActBlock || (int)r.Direction != DirOut) { r.Action = ActBlock; r.Direction = DirOut; }
                if (changed) r.RemoteAddresses = remote;
                if ((bool)r.Enabled != enabled) r.Enabled = enabled;
                return;
            }
            var t = Type.GetTypeFromProgID("HNetCfg.FWRule", true);
            dynamic nr = Activator.CreateInstance(t);
            nr.Name = name;
            nr.Description = desc;
            nr.Grouping = GuardPaths.RuleGroup;
            nr.ApplicationName = exe;
            nr.Protocol = ProtoAny;
            nr.Direction = DirOut;
            nr.Action = ActBlock;
            nr.Profiles = ProfilesAll;
            nr.InterfaceTypes = "All";
            if (remote != "*") nr.RemoteAddresses = remote;
            nr.Enabled = enabled;
            policy.Rules.Add(nr);
            Log.Action("创建防火墙规则 " + name + " → " + exe + (enabled ? "（启用）" : "（禁用）"));
        }

        public void SetLock(bool enabled)
        {
            var policy = Policy();
            List<dynamic> ours = OurRules(policy);
            foreach (var r in ours)
            {
                string n = r.Name;
                if (n.StartsWith(LockPrefix) && (bool)r.Enabled != enabled) r.Enabled = enabled;
            }
        }

        public bool VerifyRules(IList<string> exePaths, string fakeIpRange, bool expectLock, out string detail)
        {
            var policy = Policy();
            List<dynamic> ours = OurRules(policy);
            var rules = ours.ToDictionary(r => (string)r.Name, r => r);
            var problems = new List<string>();
            foreach (var exe in exePaths)
            {
                var key = PathKey(exe);
                dynamic s, l;
                if (!rules.TryGetValue(StaticPrefix + key, out s) || !(bool)s.Enabled || (int)s.Action != ActBlock || !string.Equals((string)s.ApplicationName, exe, StringComparison.OrdinalIgnoreCase))
                    problems.Add("缺少/失效静态规则：" + System.IO.Path.GetFileName(exe));
                if (!rules.TryGetValue(LockPrefix + key, out l))
                    problems.Add("缺少锁定规则：" + System.IO.Path.GetFileName(exe));
                else if (expectLock && !(bool)l.Enabled)
                    problems.Add("锁定规则未启用：" + System.IO.Path.GetFileName(exe));
            }
            detail = problems.Count == 0 ? string.Format("{0} 个 Claude 程序的规则完整", exePaths.Count) : string.Join("；", problems.Take(5));
            return problems.Count == 0;
        }

        public int RemoveAll()
        {
            var policy = Policy();
            int n = 0;
            List<dynamic> ours = OurRules(policy);
            foreach (var r in ours)
            {
                string name = r.Name;
                policy.Rules.Remove(name);
                n++;
            }
            return n;
        }
    }
}
