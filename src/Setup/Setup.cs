// written_by: claude-code
// ClaudeVPNGuard-Setup.exe —— 图形化“安装与验收”程序（像普通软件一样：双击 → UAC → 按步骤点按钮）。
//   1 安装前检查（只读） 2 系统实测 selftest（逐项勾选确认，失败即停） 3 Clash 覆写（差异/生效/撤销）
//   4 安装（事务：备份→复制→注册服务→验证，失败回滚）+ 桌面/开始菜单快捷方式 + “应用和功能”卸载入口
//   5 场景验收（spacedesk、关闭系统代理、节点切换、内核崩溃、真实 Claude）
//   /uninstall 卸载；/smoke 仅构建界面后退出（冒烟测试，不提权、不执行任何操作）
// 所有步骤结果写入验收记录（%ProgramData%\ClaudeVPNGuard\acceptance\ 与源码 docs\ 目录）。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ClaudeVPNGuard
{
    static class SetupProgram
    {
        [STAThread]
        static int Main(string[] args)
        {
            bool smoke = args.Contains("/smoke"), uninstall = args.Contains("/uninstall");
            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            if (!admin && !smoke)
            {
                try
                {
                    Process.Start(new ProcessStartInfo(Application.ExecutablePath, string.Join(" ", args)) { UseShellExecute = true, Verb = "runas" });
                }
                catch { MessageBox.Show("需要管理员权限才能安装与验收。", "Claude VPN Guard"); }
                return 0;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (uninstall) return SetupForm.RunUninstall(smoke) ? 0 : 1;
            var f = new SetupForm();
            if (smoke) { f.Shown += (s, e) => { var t = new System.Windows.Forms.Timer { Interval = 1500 }; t.Tick += (a, b) => f.Close(); t.Start(); }; }
            Application.Run(f);
            return 0;
        }
    }

    class SetupForm : Form
    {
        public static readonly string InstallDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClaudeVPNGuard");
        static readonly string SrcDir = AppDomain.CurrentDomain.BaseDirectory;
        const string UninstKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeVPNGuard";
        static readonly string[] AppFiles = { "ClaudeVPNGuard.exe", "ClaudeVPNGuard.Service.exe", "ClaudeVPNGuard-Setup.exe" };

        readonly TextBox log = new TextBox();
        readonly Dictionary<int, Label> stateLbl = new Dictionary<int, Label>();
        readonly Dictionary<int, Button> stepBtn = new Dictionary<int, Button>();
        readonly StringBuilder rec = new StringBuilder();
        readonly string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        bool busy, selftestOk, loopbackOk, listenerOk, installed;
        string recordFile;

        public SetupForm()
        {
            Text = "Claude VPN Guard v" + GuardVersion.Text + " 安装与验收";
            Font = new Font("Microsoft YaHei UI", 9F);
            Size = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            var left = new TableLayoutPanel { Dock = DockStyle.Left, Width = 330, ColumnCount = 1, Padding = new Padding(12), AutoScroll = true };
            var head = new Label { Text = "按顺序点击每一步。\n每个会改变系统、网络或 Claude 的操作都会先请你确认；任一步失败会停止并回滚，不会继续安装。", AutoSize = false, Height = 70, Dock = DockStyle.Top, ForeColor = Color.DimGray };
            left.Controls.Add(head);
            AddStep(left, 1, "1. 安装前检查（只读）", Step1);
            AddStep(left, 2, "2. 系统实测 selftest（替身程序）", Step2);
            AddStep(left, 3, "3. Clash 覆写（Japan Auto + 专用入口）", Step3);
            AddStep(left, 4, "4. 安装保护服务与快捷方式", Step4);
            AddStep(left, 5, "5. 场景验收（spacedesk / 故障 / 真实 Claude）", Step5);
            var tools = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 80, FlowDirection = FlowDirection.LeftToRight };
            var bRec = new Button { Text = "打开验收记录", Width = 140, Height = 30 }; bRec.Click += (s, e) => { SaveRec(); try { Process.Start("notepad.exe", "\"" + recordFile + "\""); } catch { } };
            var bUn = new Button { Text = "卸载", Width = 140, Height = 30 }; bUn.Click += (s, e) => { if (RunUninstall(false)) Close(); };
            tools.Controls.Add(bRec); tools.Controls.Add(bUn);
            left.Controls.Add(tools);
            log.Multiline = true; log.ReadOnly = true; log.ScrollBars = ScrollBars.Vertical; log.Dock = DockStyle.Fill; log.Font = new Font("Consolas", 9F); log.BackColor = Color.White;
            Controls.Add(log); Controls.Add(left);
            for (int i = 2; i <= 5; i++) stepBtn[i].Enabled = false;
            installed = File.Exists(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"));
            Rec("# Claude VPN Guard V2 实机验收记录 " + stamp);
            Rec("");
            Rec("written_by: claude-code（ClaudeVPNGuard-Setup.exe 自动生成）　机器：" + Environment.MachineName + "　执行者：" + Environment.UserName);
            Rec("");
            Rec("> selftest（替身程序）通过 ≠ 正式 Claude 隔离通过；正式 Claude 在第 5 步单独验证。未执行、跳过或失败的项目不视为已安全。");
            Line("安装来源：" + SrcDir + (installed ? "\r\n检测到已安装版本：" + InstallDir : ""));
        }

        void AddStep(TableLayoutPanel p, int n, string text, Action act)
        {
            var b = new Button { Text = text, Width = 300, Height = 40, TextAlign = ContentAlignment.MiddleLeft };
            var l = new Label { Text = "未执行", AutoSize = true, ForeColor = Color.Gray, Margin = new Padding(6, 0, 3, 10) };
            b.Click += (s, e) => { if (!busy) act(); };
            p.Controls.Add(b); p.Controls.Add(l);
            stepBtn[n] = b; stateLbl[n] = l;
        }

        void State(int n, string text, Color c) { Ui(() => { stateLbl[n].Text = text; stateLbl[n].ForeColor = c; }); }
        void Enable(int n) { Ui(() => stepBtn[n].Enabled = true); }
        void Ui(Action a) { if (InvokeRequired) BeginInvoke(a); else a(); }
        void Line(string s) { Ui(() => { log.AppendText(s + "\r\n"); }); }
        void Rec(string s) { lock (rec) rec.AppendLine(s); }

        void SaveRec()
        {
            var dir = Path.Combine(GuardPaths.DataDir, "acceptance");
            Directory.CreateDirectory(dir);
            recordFile = Path.Combine(dir, "V2实机验收记录-" + stamp + ".md");
            string text; lock (rec) text = rec.ToString();
            File.WriteAllText(recordFile, "---\nwritten_by: claude-code\n---\n\n" + text, new UTF8Encoding(false));
            // 若从源码 dist 目录运行，同时写入源码 docs
            var docs = Path.GetFullPath(Path.Combine(SrcDir, "..", "docs"));
            if (Directory.Exists(docs)) try { File.Copy(recordFile, Path.Combine(docs, Path.GetFileName(recordFile)), true); } catch { }
        }

        static bool Confirm(string title, string text) { return MessageBox.Show(text, title, MessageBoxButtons.OKCancel, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) == DialogResult.OK; }

        // 始终使用本安装包自带的服务程序（与安装后复制过去的是同一版本）；
        // 不能用安装目录里可能残留的旧版本（2026-11-01 实测：残留旧版导致 selftest 跑的是旧代码）
        string Svc()
        {
            var src = Path.Combine(SrcDir, "ClaudeVPNGuard.Service.exe");
            return File.Exists(src) ? src : Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe");
        }

        // 运行子命令，输出实时显示；返回 (退出码, 全部输出)
        int Run(string exe, string args, out string output)
        {
            Line("> " + Path.GetFileName(exe) + " " + args);
            var sb = new StringBuilder();
            var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
            using (var p = new Process { StartInfo = psi })
            {
                p.OutputDataReceived += (s, e) => { if (e.Data != null) { lock (sb) sb.AppendLine(e.Data); Line(e.Data); } };
                p.ErrorDataReceived += (s, e) => { if (e.Data != null) { lock (sb) sb.AppendLine(e.Data); Line(e.Data); } };
                p.Start(); p.BeginOutputReadLine(); p.BeginErrorReadLine();
                p.WaitForExit();
                p.WaitForExit(500);
                output = sb.ToString();
                return p.ExitCode;
            }
        }

        void Background(Action a)
        {
            busy = true;
            UseWaitCursor = true;
            new Thread(() =>
            {
                try { a(); }
                catch (Exception ex) { Line("异常：" + ex.Message); Rec("- ❌ 异常：" + ex.Message); }
                finally { SaveRec(); Ui(() => { busy = false; UseWaitCursor = false; }); }
            }) { IsBackground = true }.Start();
        }

        static string SpaceDesk() { try { return SpacedeskInfo.Detect().Describe(); } catch (Exception ex) { return "检测失败：" + ex.Message; } }
        static bool ListenerUp() { return Native.TcpTable().Any(t => t.State == 2 && t.LocalPort == GuardSettings.Load().DedicatedPort); }

        // ── 1
        void Step1()
        {
            Background(() =>
            {
                Rec(""); Rec("## 1. 安装前检查 / 防火墙审计（只读）");
                var pf = Path.Combine(GuardPaths.DataDir, "acceptance", "preflight-" + stamp + ".txt");
                Directory.CreateDirectory(Path.GetDirectoryName(pf));
                string o;
                int rc = Run(Svc(), "preflight \"" + pf + "\"", out o);
                foreach (var l in o.Split('\n').Where(x => x.Contains("[阻止]") || x.Contains("[警告]") || x.Contains("结论") || x.Contains("spacedesk：") || x.Contains("作用范围") || x.Contains("ICS"))) Rec("- " + l.Trim());
                Run(Svc(), "verge-diff \"" + Path.Combine(GuardPaths.DataDir, "acceptance", "verge-diff-" + stamp + ".txt") + "\"", out o);
                Rec("- Clash 覆写差异报告：acceptance\\verge-diff-" + stamp + ".txt");
                if (rc == 3) { State(1, "存在阻止项，已停止", Color.Firebrick); Rec("**存在阻止项，验收停止，未做任何修改。**"); return; }
                State(1, "通过", Color.ForestGreen);
                Enable(2);
                if (installed) { Enable(5); }
            });
        }

        // ── 2
        void Step2()
        {
            var items = new[]
            {
                "测试程序是本程序副本（替身），WFP 过滤器生成逻辑与正式 Claude 相同，但只作用于替身，不影响真实 Claude、Clash Verge、spacedesk",
                "将实测：替身→127.0.0.1:17897 成功；→其他本地代理端口 阻断；→公网 IPv4 阻断；IPv6（本机可测范围）按规则处理；→UDP 直连 阻断",
                "测试结束逐项确认替身过滤器已删除，并对比前后系统 WFP 快照，确认系统原有 WFP 状态未改变",
                "测试失败将保留完整诊断日志并停止：不安装服务、不修改正式防火墙规则、不修改 Clash 配置",
                "测试期间临时监听本机端口 27990/27991（及空闲时的 17897），Windows 防火墙部分会对替身临时添加并删除规则",
            };
            if (!ChecklistDialog("selftest 执行前逐项确认", items)) return;
            Background(() =>
            {
                Rec(""); Rec("## 2. 系统级阻断实测 selftest（替身程序）");
                foreach (var it in items) Rec("- 已确认：" + it);
                string o;
                int rc = Run(Svc(), "selftest --yes", out o);
                var file = Path.Combine(GuardPaths.DataDir, "acceptance", "selftest-" + stamp + ".txt");
                File.WriteAllText(file, o, new UTF8Encoding(false));
                foreach (var l in o.Split('\n').Where(x => x.Contains("[通过]") || x.Contains("[失败]") || x.Contains("[未验证]") || x.Contains("结果：") || x.Contains("快照对比"))) Rec("- " + l.Trim());
                Rec("- 完整输出：acceptance\\selftest-" + stamp + ".txt，退出码 " + rc);
                loopbackOk = o.Split('\n').Any(x => x.Contains("WFP 能否管住回环") && x.Contains("[通过]"));
                if (rc != 0)
                {
                    selftestOk = false;
                    State(2, "未通过，已停止（诊断已保存）", Color.Firebrick);
                    Rec("**selftest 未全部通过：验收停止。未安装服务、未修改正式防火墙规则、未修改 Clash 配置。**");
                    Ui(() => MessageBox.Show("selftest 未全部通过，已停止。\n诊断：" + file + "\n以及 C:\\ProgramData\\ClaudeVPNGuard\\wfp-selftest-*.txt", "Claude VPN Guard"));
                    return;
                }
                selftestOk = true;
                Rec("**selftest 通过（替身程序）。这不等于正式 Claude 隔离已通过。**");
                State(2, "通过" + (loopbackOk ? "（回环可控）" : "（回环不可控！）"), loopbackOk ? Color.ForestGreen : Color.DarkOrange);
                Enable(3);
            });
        }

        bool ChecklistDialog(string title, string[] items)
        {
            var f = new Form { Text = title, Size = new Size(760, 120 + items.Length * 58), StartPosition = FormStartPosition.CenterParent, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false, Font = Font };
            var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(12), WrapContents = false };
            var boxes = items.Select(t => new CheckBox { Text = t, AutoSize = false, Width = 710, Height = 50 }).ToList();
            foreach (var b in boxes) panel.Controls.Add(b);
            var ok = new Button { Text = "全部确认，开始", Enabled = false, Width = 160, Height = 32, DialogResult = DialogResult.OK };
            var cancel = new Button { Text = "取消", Width = 100, Height = 32, DialogResult = DialogResult.Cancel };
            foreach (var b in boxes) b.CheckedChanged += (s, e) => ok.Enabled = boxes.All(x => x.Checked);
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 48, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            bar.Controls.Add(cancel); bar.Controls.Add(ok);
            f.Controls.Add(panel); f.Controls.Add(bar); f.AcceptButton = ok; f.CancelButton = cancel;
            return f.ShowDialog(this) == DialogResult.OK;
        }

        // ── 3
        void Step3()
        {
            Background(() =>
            {
                Rec(""); Rec("## 3. Clash 覆写（Japan Auto + 专用入口）");
                string o;
                // 只看专用入口在线不够：Clash 可能还在用旧配置，脚本段其实已丢（11-02 卸载后重装即如此，更新订阅后 Japan Auto 消失）
                var vd = VergeOverride.FindVergeDataDir();
                if (vd == null) { State(3, "未找到 Clash Verge", Color.DarkOrange); Rec("- 未找到 Clash Verge 数据目录"); return; }
                var sf = VergeOverride.ScriptFile(vd);
                if (!(File.Exists(sf) && VergeOverride.HasCurrentBlock(File.ReadAllText(sf, Encoding.UTF8), GuardSettings.Load())))
                {
                    bool go = false;
                    Ui(() => go = Confirm("写入 Clash 覆写", "Clash Verge「全局扩展脚本」(Script.js) 里没有本程序段（或与当前设置不一致）。\n\n将写入：Japan Auto 组 + 专用入口 127.0.0.1:17897 + Claude 规则；不改其他组/节点/规则。写入前自动备份原文件。\n\n" + VergeOverride.WhereGuide));
                    if (!go) { State(3, "未写入覆写", Color.DarkOrange); Rec("- 用户取消写入覆写"); return; }
                    Run(Svc(), "verge-apply", out o);
                    Rec("- " + o.Trim());
                }
                Run(Svc(), "verge-diff", out o);
                listenerOk = ListenerUp() && VergeOverride.RuntimeLoaded(vd);
                if (!listenerOk)
                {
                    // 不用用户去 Verge 刷新：保护器自己把覆写套进当前配置并重载内核（会短暂断开 Clash 现有连接）
                    Run(Svc(), "verge-hotload", out o);
                    Rec("- " + o.Trim());
                    for (int i = 0; i < 10 && !listenerOk; i++) { Thread.Sleep(500); listenerOk = ListenerUp() && VergeOverride.RuntimeLoaded(vd); }
                }
                while (!listenerOk)
                {
                    var r = DialogResult.None;
                    Ui(() => r = MessageBox.Show(this, "覆写已写入 Script.js（差异见右侧），自动套用也没成功（见右侧记录），Clash Verge 当前配置还没套用它。\n\n" + VergeOverride.RefreshGuide + "\n\n【是】我已刷新，重新检测\n【否】撤销覆写（恢复原 Script.js）并停止\n【取消】稍后再说", "加载 Clash 覆写", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question));
                    while (r == DialogResult.None) Thread.Sleep(100);
                    if (r == DialogResult.Yes) { Thread.Sleep(1500); listenerOk = ListenerUp() && VergeOverride.RuntimeLoaded(vd); continue; }
                    if (r == DialogResult.No) { Run(Svc(), "verge-restore", out o); Rec("- 用户撤销覆写：" + o.Trim()); }
                    State(3, "覆写未生效，已停止", Color.DarkOrange);
                    Rec("- 专用入口未生效，验收停止");
                    return;
                }
                Rec("- 专用入口 127.0.0.1:17897：在线");
                Run(Svc(), "audit", out o);
                foreach (var l in o.Split('\n').Where(x => x.Contains("Japan Auto 组") || x.Contains("识别到的日本节点"))) Rec("- " + l.Trim());
                State(3, "已生效", Color.ForestGreen);
                Enable(4);
            });
        }

        // ── 4
        void Step4()
        {
            bool iso = selftestOk && loopbackOk && listenerOk;
            var f = new Form { Text = "安装保护服务", Size = new Size(640, 360), StartPosition = FormStartPosition.CenterParent, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false, Font = Font };
            var p = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(14), WrapContents = false };
            var rIso = new RadioButton { Text = "隔离模式（推荐）：Claude 只能经专用入口 → Japan Auto 出网", AutoSize = true, Enabled = iso, Checked = iso };
            var rV1 = new RadioButton { Text = "V1 兼容模式：Claude 经系统代理；防直连规则 + 检测", AutoSize = true, Checked = !iso };
            var cc = new CheckBox { Text = "另为独立命令行版 Claude Code 写入专用代理（~/.claude/settings.json，可选）。\n桌面版内置 Claude Code 实测不读取该设置，已改由“启动 Claude”单独为 Claude 进程设置代理。", AutoSize = false, Width = 590, Height = 46, Enabled = iso, Checked = false };
            var note = new Label { AutoSize = false, Width = 590, Height = 110, ForeColor = Color.DimGray, Text = (iso ? "" : "隔离模式不可用：需要 selftest 通过且回环可控、专用入口在线。\n") + "将执行：备份防火墙策略 → 复制程序到 " + InstallDir + " → 注册服务 → 为真实 Claude 下发防火墙规则 + WFP 持久过滤器（先锁定，验证后放行）→ 验证。失败自动回滚。\n完成后创建桌面与开始菜单快捷方式，并在“设置 → 应用”中登记卸载入口。" };
            p.Controls.Add(rIso); p.Controls.Add(rV1); p.Controls.Add(cc); p.Controls.Add(note);
            var ok = new Button { Text = "确认安装", Width = 120, Height = 32, DialogResult = DialogResult.OK };
            var cancel = new Button { Text = "取消", Width = 100, Height = 32, DialogResult = DialogResult.Cancel };
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 48, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            bar.Controls.Add(cancel); bar.Controls.Add(ok);
            f.Controls.Add(p); f.Controls.Add(bar);
            if (f.ShowDialog(this) != DialogResult.OK) return;
            bool useIso = rIso.Checked, useCc = cc.Checked && useIso;
            Background(() => Install(useIso, useCc));
        }

        void Install(bool iso, bool cc)
        {
            Rec(""); Rec("## 4. 安装（" + (iso ? "隔离模式" : "V1 兼容模式") + "）");
            var bk = Path.Combine(GuardPaths.DataDir, "backup", stamp);
            Directory.CreateDirectory(bk);
            string o;
            Run("netsh.exe", "advfirewall export \"" + Path.Combine(bk, "firewall-policy.wfw") + "\"", out o);
            bool upgrade = File.Exists(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"));
            var prevBin = Path.Combine(bk, "prev-bin");
            var settingsBak = Path.Combine(bk, "settings.json");
            if (File.Exists(GuardPaths.SettingsFile)) File.Copy(GuardPaths.SettingsFile, settingsBak, true);
            if (upgrade) { Directory.CreateDirectory(prevBin); foreach (var fn in AppFiles.Concat(new[] { "guard.ico", FullUninstall.ScriptName })) { var src = Path.Combine(InstallDir, fn); if (File.Exists(src)) File.Copy(src, Path.Combine(prevBin, fn), true); } }
            Rec("- 备份：" + bk + (upgrade ? "（含旧版本程序）" : ""));
            // 先确认新版服务程序能被 Windows 加载（未签名 exe 可能被应用程序控制拦截）。
            // 必须在停旧服务、动规则之前确认，否则会出现“旧服务已停、新服务起不来、持久化规则还在挡网”的断网状态。
            try
            {
                string po;
                int prc = Run(Path.Combine(SrcDir, "ClaudeVPNGuard.Service.exe"), "probe", out po);
                if (prc != 0) throw new Exception("新版服务程序自检返回 " + prc + "：" + po.Trim());
                Rec("- 预检：新版服务程序可正常加载（" + po.Trim() + "）");
            }
            catch (Exception ex)
            {
                bool blocked = AppControl.IsBlock(ex);
                Rec("- ❌ 预检失败，未做任何改动：" + (blocked ? "被 Windows 应用程序控制拦截" : ex.Message));
                State(4, blocked ? "被 Windows 应用程序控制拦截，未安装" : "预检失败，未安装", Color.Firebrick);
                Invoke((Action)(() => MessageBox.Show(this, blocked ? AppControl.Advice : "新版服务程序无法运行：" + ex.Message + "\n\n安装程序没有停掉现有保护，也没有改动任何规则。", "安装前预检", MessageBoxButtons.OK, MessageBoxIcon.Warning)));
                return;
            }
            try
            {
                foreach (var pr in Process.GetProcessesByName("ClaudeVPNGuard")) try { pr.Kill(); } catch { }
                Run("sc.exe", "stop ClaudeVPNGuard", out o);
                Thread.Sleep(1500);
                Directory.CreateDirectory(InstallDir);
                if (!string.Equals(Path.GetFullPath(SrcDir).TrimEnd('\\'), Path.GetFullPath(InstallDir).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                    foreach (var fn in AppFiles.Concat(new[] { "guard.ico", FullUninstall.ScriptName })) { var src = Path.Combine(SrcDir, fn); if (File.Exists(src)) File.Copy(src, Path.Combine(InstallDir, fn), true); }
                var st = GuardSettings.Load();
                st.IsolationMode = iso;
                st.Save();
                installed = true;
                int rc = Run(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"), "install", out o);
                if (rc != 0) throw new Exception("服务安装失败（" + rc + "）");
                bool ok = false;
                for (int i = 0; i < 10 && !ok; i++) { Thread.Sleep(1000); ok = Run(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"), "verify", out o) == 0; }
                foreach (var l in o.Split('\n').Where(x => x.Trim().Length > 0)) Rec("- verify：" + l.Trim());
                if (!ok) throw new Exception("验证未通过：服务未运行或规则/过滤器不完整");
            }
            catch (Exception ex)
            {
                Rec("- ❌ 安装失败：" + ex.Message + " → 回滚");
                if (upgrade)
                {
                    foreach (var fn in Directory.GetFiles(prevBin)) try { File.Copy(fn, Path.Combine(InstallDir, Path.GetFileName(fn)), true); } catch { }
                    if (File.Exists(settingsBak)) File.Copy(settingsBak, GuardPaths.SettingsFile, true);
                    Run(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"), "install", out o);
                    Rec("- 已恢复旧版本并重新注册；原有规则未删除");
                }
                else
                {
                    int urc = -1;
                    try { urc = Run(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"), "uninstall", out o); } catch (Exception uex) { Rec("- 回滚时服务程序无法运行：" + uex.Message); }
                    if (urc != 0)
                    {
                        // 服务程序跑不起来时，用系统自带 PowerShell 的完全卸载脚本兜底，保证不留下挡网的规则
                        try { FullUninstall.Launch(true); Rec("- 已改用 full-uninstall.ps1 完全清理（会弹出 PowerShell 窗口）"); } catch (Exception lex) { Rec("- 无法启动卸载脚本：" + lex.Message); }
                    }
                    installed = false;
                    Rec("- 全新安装回滚：已删除本次创建的服务、规则与过滤器");
                }
                State(4, "安装失败，已回滚", Color.Firebrick);
                return;
            }
            Run(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"), "audit", out o);
            foreach (var l in o.Split('\n').Where(x => x.Contains("作用范围") || x.Contains("持久性") || x.Contains("已有过滤器"))) Rec("- " + l.Trim());
            if (cc)
            {
                int rc = Run(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"), "cc-proxy apply", out o);
                if (rc != 0) { Run(Path.Combine(InstallDir, "ClaudeVPNGuard.Service.exe"), "cc-proxy remove", out o); Rec("- ❌ Claude Code 专用代理配置失败，已还原"); }
                else Rec("- " + o.Trim().Replace("\r\n", " / "));
            }
            CreateShortcutsAndRegistry();
            Rec("- 已创建桌面与开始菜单快捷方式，已登记“应用和功能”卸载入口");
            State(4, "已安装（" + (iso ? "隔离模式" : "V1 兼容") + "）", Color.ForestGreen);
            Enable(5);
            try { Process.Start(Path.Combine(InstallDir, "ClaudeVPNGuard.exe")); } catch { }
        }

        static void Shortcut(string lnk, string target, string args, string desc)
        {
            dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            dynamic s = sh.CreateShortcut(lnk);
            s.TargetPath = target; s.Arguments = args ?? ""; s.WorkingDirectory = Path.GetDirectoryName(target); s.Description = desc;
            var ico = Path.Combine(InstallDir, "guard.ico");
            s.IconLocation = File.Exists(ico) ? ico + ",0" : target + ",0";
            s.Save();
        }

        static string StartMenuDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Claude VPN Guard"); } }
        static string DesktopLnk { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "Claude VPN Guard.lnk"); } }

        static void CreateShortcutsAndRegistry()
        {
            var gui = Path.Combine(InstallDir, "ClaudeVPNGuard.exe");
            var setup = Path.Combine(InstallDir, "ClaudeVPNGuard-Setup.exe");
            Shortcut(DesktopLnk, gui, null, "Claude 代理防泄漏保护");
            Directory.CreateDirectory(StartMenuDir);
            Shortcut(Path.Combine(StartMenuDir, "Claude VPN Guard.lnk"), gui, null, "Claude 代理防泄漏保护");
            Shortcut(Path.Combine(StartMenuDir, "安装与验收.lnk"), setup, null, "重新运行安装与验收");
            var ps = FullUninstall.PowerShellExe;
            var unScript = Path.Combine(InstallDir, FullUninstall.ScriptName);
            // 卸载入口直接用系统自带 PowerShell 运行脚本：即使本程序 exe 被应用程序控制拦截，也能完全卸载
            Shortcut(Path.Combine(StartMenuDir, "卸载 Claude VPN Guard.lnk"), ps, FullUninstall.CommandLine(unScript), "完全卸载：服务、WFP、防火墙规则、Clash 覆写、代理设置、程序文件");
            Shortcut(Path.Combine(StartMenuDir, "卸载前检查（只看不改）.lnk"), ps, FullUninstall.CommandLine(unScript) + " -DryRun", "只检查残留，不做改动");
            // 旧版 install.ps1 创建的单个快捷方式
            try { File.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Claude VPN Guard.lnk")); } catch { }
            using (var k = Registry.LocalMachine.CreateSubKey(UninstKey))
            {
                k.SetValue("DisplayName", "Claude VPN Guard");
                k.SetValue("DisplayVersion", typeof(SetupForm).Assembly.GetName().Version.ToString());
                k.SetValue("Publisher", "tianhuojeff");
                k.SetValue("InstallLocation", InstallDir);
                k.SetValue("DisplayIcon", Path.Combine(InstallDir, "guard.ico"));
                k.SetValue("UninstallString", "\"" + ps + "\" " + FullUninstall.CommandLine(unScript));
                k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                k.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
            }
        }

        // ── 5
        void Step5()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("隔离检查：Clash 正常（含 spacedesk 状态）", null, (s, e) => Scenario("Clash 正常", null, null));
            menu.Items.Add("关闭系统代理（约 10 秒后自动还原）", null, (s, e) =>
            {
                if (!Confirm("关闭系统代理", "将临时关闭系统代理约 10 秒，期间其他软件可能无法联网，结束后自动还原。继续？")) return;
                int old = 0;
                Scenario("系统代理关闭", () =>
                {
                    using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true)) { old = Convert.ToInt32(k.GetValue("ProxyEnable", 0)); k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord); }
                    Thread.Sleep(3000);
                }, () => { using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true)) k.SetValue("ProxyEnable", old, RegistryValueKind.DWord); Rec("  - 系统代理已还原为 ProxyEnable=" + old); });
            });
            menu.Items.Add("Japan Auto 节点切换", null, (s, e) =>
            {
                if (!Confirm("节点切换", "将把 Japan Auto 切换到另一个日本节点（只动 Japan Auto 组）。继续？")) return;
                Scenario("节点切换", () => { string o; Run(Svc(), "jp-switch", out o); Rec("  - " + o.Trim()); }, null);
            });
            menu.Items.Add("Mihomo 内核崩溃（强制结束 verge-mihomo）", null, (s, e) =>
            {
                if (!Confirm("内核崩溃", "将强制结束 verge-mihomo：代理中断数秒，运行中的 Claude 会被保护性关闭。之后等待 Clash Verge 重新拉起内核。继续？")) return;
                Scenario("内核崩溃", () =>
                {
                    Rec("  - 故障注入：" + DateTime.Now.ToString("HH:mm:ss.fff"));
                    foreach (var pr in Process.GetProcessesByName("verge-mihomo")) try { pr.Kill(); } catch { }
                    Thread.Sleep(2000);
                }, () =>
                {
                    for (int i = 0; i < 30 && Process.GetProcessesByName("verge-mihomo").Length == 0; i++) Thread.Sleep(1000);
                    bool back = Process.GetProcessesByName("verge-mihomo").Length > 0;
                    Rec("  - 内核" + (back ? "已自动恢复" : "未自动恢复，请手动重启 Clash Verge"));
                    if (back)
                    {
                        Thread.Sleep(5000);
                        string o2;
                        int rc2 = Run(Svc(), "isocheck", out o2);
                        Rec("| 内核恢复后 | " + (rc2 == 0 ? "✅ 必须阻断项全部阻断" : "❌ 存在未阻断路径") + " | " + o2.Trim().Replace("\r\n", " ") + " | " + SpaceDesk() + " |");
                    }
                    try
                    {
                        var logf = Directory.GetFiles(GuardPaths.LogDir, "guard-*.log").OrderBy(x => x).LastOrDefault();
                        if (logf != null) foreach (var l in File.ReadAllLines(logf).Where(x => x.Contains("内核进程退出") || x.Contains("保护性关闭")).Reverse().Take(3)) Rec("  - 日志：" + l);
                    }
                    catch { }
                });
            });
            menu.Items.Add("真实 Claude 验证（需先完全退出 Claude）", null, (s, e) =>
            {
                if (!Confirm("真实 Claude", "请先完全退出 Claude（托盘也退出），然后点确定；稍后在 Claude VPN Guard 主界面点“启动 Claude”并对话一句，再回来点下一个对话框的确定。")) return;
                MessageBox.Show(this, "Claude 已由保护器启动并对话一句后，点确定开始检查。", "真实 Claude");
                Background(() =>
                {
                    Rec(""); Rec("### 真实 Claude 的隔离验证（正式 Claude，非替身）");
                    string o;
                    Run(Svc(), "diag", out o);
                    foreach (var l in o.Split('\n').Where(x => x.Contains("Claude 连接审计") || x.Contains("代理路径探测") || x.Contains("专用入口") || x.Contains("Japan Auto") || x.Contains("结论"))) Rec("- " + l.Trim());
                    // 明确判定：Claude 必须在运行，且只连专用入口、审计通过、结论安全
                    var procs = new ClaudeLocator(GuardSettings.Load()).RunningClaude();
                    var port = GuardSettings.Load().DedicatedPort;
                    var conns = Native.TcpTable().Where(t => procs.ContainsKey(t.Pid) && t.State != 2 && !t.RemoteAddr.Equals(System.Net.IPAddress.Any) && !t.RemoteAddr.Equals(System.Net.IPAddress.IPv6Any)).ToList();
                    var other = conns.Where(t => t.RemotePort != port || !System.Net.IPAddress.IsLoopback(t.RemoteAddr)).ToList();
                    bool auditOk = o.Split('\n').Any(x => x.Contains("Claude 连接审计") && x.Contains("[通过]"));
                    bool safe = o.Contains("结论：安全");
                    string verdict;
                    if (procs.Count == 0) verdict = "无法验证：Claude 未运行（请先在保护器中点“启动 Claude”）";
                    else if (conns.Count == 0) verdict = "无法验证：Claude 当前没有网络连接（请先对话一句再验证）";
                    else if (other.Count == 0 && auditOk && safe) verdict = "通过：Claude " + procs.Count + " 个进程的 " + conns.Count + " 条连接全部只走专用入口 127.0.0.1:" + port;
                    else verdict = "未通过：" + (other.Count > 0 ? "存在 " + other.Count + " 条非专用入口连接（如 " + other[0] + "）" : "审计/结论未通过");
                    Rec("- **判定：" + verdict + "**");
                    State(5, "真实 Claude：" + verdict.Split('：')[0], verdict.StartsWith("通过") ? Color.ForestGreen : verdict.StartsWith("未通过") ? Color.Firebrick : Color.DarkOrange);
                    Ui(() => MessageBox.Show(this, verdict, "真实 Claude 验证结果"));
                });
            });
            menu.Show(stepBtn[5], new Point(0, stepBtn[5].Height));
        }

        void Scenario(string name, Action inject, Action restore)
        {
            if (!Confirm("场景：" + name, "该场景会对替身程序临时下发并删除 WFP 过滤器（不影响真实 Claude）。如方便请先连接 spacedesk 扩展屏。继续？")) return;
            Background(() =>
            {
                if (!rec.ToString().Contains("## 5.")) { Rec(""); Rec("## 5. 场景验收（替身隔离检查 + spacedesk）"); Rec(""); Rec("| 场景 | 隔离结果 | 明细 | spacedesk |"); Rec("|---|---|---|---|"); }
                var sd0 = SpaceDesk();
                try
                {
                    if (inject != null) inject();
                    string o;
                    int rc = Run(Svc(), "isocheck", out o);
                    Rec("| " + name + " | " + (rc == 0 ? "✅ 必须阻断项全部阻断" : "❌ 存在未阻断路径") + " | " + o.Trim().Replace("\r\n", " ") + " | 前：" + sd0 + " / 后：" + SpaceDesk() + " |");
                    State(5, name + "：" + (rc == 0 ? "通过" : "未通过"), rc == 0 ? Color.ForestGreen : Color.Firebrick);
                }
                finally { if (restore != null) restore(); }
            });
        }

        // ── 卸载
        public static bool RunUninstall(bool smoke)
        {
            if (smoke) return true;
            // 统一交给 full-uninstall.ps1（系统自带 PowerShell 执行，自己提权、确认、清理全部内容并复查）
            try { if (FullUninstall.Launch(false)) return true; }
            catch (Exception ex) { MessageBox.Show("无法启动卸载脚本：" + ex.Message, "Claude VPN Guard"); return false; }
            MessageBox.Show("找不到卸载脚本 " + FullUninstall.ScriptName + "。\n请在源码目录 scripts 里右键它“用 PowerShell 运行”。", "Claude VPN Guard");
            return false;
        }
    }
}
