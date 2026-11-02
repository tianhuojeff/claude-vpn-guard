// written_by: claude-code
// ClaudeVPNGuard.exe —— 中文图形界面 + 系统托盘。以普通用户权限运行，所有高权限动作交给服务或经 UAC 提权。
// GUI 关闭/崩溃不影响保护：保护逻辑全部在服务与持久化防火墙规则中。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ClaudeVPNGuard
{
    static class GuiProgram
    {
        [STAThread]
        static void Main(string[] args)
        {
            bool created;
            using (var mtx = new Mutex(true, "Local\\ClaudeVPNGuard.Gui", out created))
            {
                if (!created) { MessageBox.Show("Claude VPN Guard 已在运行（见系统托盘）。", "Claude VPN Guard"); return; }
                Log.Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ClaudeVPNGuard", "gui-logs");
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm(args.Contains("--tray")));
            }
        }
    }

    class MainForm : Form
    {
        readonly NotifyIcon tray = new NotifyIcon();
        readonly Label stateLabel = new Label(), stateSub = new Label();
        readonly Dictionary<string, Label> fields = new Dictionary<string, Label>();
        readonly ListView checks = new ListView();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly bool startHidden;
        readonly NodePage nodePage = new NodePage();
        long lastTripSeq = -1;
        string lastState;
        bool polling, reallyExit;
        object lastStatus;

        static readonly string ServiceExe = Path.Combine(GuardPaths.ExeDir, "ClaudeVPNGuard.Service.exe");

        public MainForm(bool tray)
        {
            startHidden = tray;
            Text = "Claude VPN Guard v" + GuardVersion.Text + " — Claude 代理防泄漏保护";
            Font = new Font("Microsoft YaHei UI", 9F);
            Size = new Size(820, 760);
            MinimumSize = new Size(640, 560);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(248, 249, 251);
            Icon = MakeIcon(Color.Gray);
            BuildUi();
            BuildTray();
            timer.Interval = 2000;
            timer.Tick += (s, e) => Poll(false);
            timer.Start();
            Poll(false);
        }

        protected override void SetVisibleCore(bool value)
        {
            if (startHidden && !IsHandleCreated) { CreateHandle(); value = false; }
            base.SetVisibleCore(value);
        }

        void BuildUi()
        {
            var top = new Panel { Dock = DockStyle.Top, Height = 92, Padding = new Padding(18, 12, 18, 8), BackColor = Color.White };
            stateLabel.Font = new Font("Microsoft YaHei UI", 20F, FontStyle.Bold);
            stateLabel.AutoSize = true; stateLabel.Location = new Point(18, 10); stateLabel.Text = "连接保护服务…";
            stateSub.AutoSize = false; stateSub.Location = new Point(20, 56); stateSub.Size = new Size(700, 30);
            stateSub.ForeColor = Color.FromArgb(90, 90, 90); stateSub.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top;
            top.Controls.Add(stateLabel); top.Controls.Add(stateSub);

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 84, Padding = new Padding(12, 8, 12, 8), BackColor = Color.White, WrapContents = true };
            AddButton(buttons, "启动 Claude", LaunchClaude, true);
            AddButton(buttons, "打开 Clash Verge", OpenClashVerge, false);
            AddButton(buttons, "立即检测", () => Poll(true), false);
            AddButton(buttons, "查看日志", ShowLogs, false);
            AddButton(buttons, "设置", ShowSettings, false);
            AddButton(buttons, "修复保护", Repair, false);
            AddButton(buttons, "修复 Clash 覆写", FixOverride, false);
            AddButton(buttons, "安全卸载", Uninstall, false);

            var mid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, Padding = new Padding(12) };
            mid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55));
            mid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
            mid.RowStyles.Add(new RowStyle(SizeType.Absolute, 290));
            mid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            mid.Controls.Add(Group("代理信息", new[] { "Clash Verge", "Mihomo 内核", "代理模式", "当前节点", "TUN 状态", "系统代理", "出口 IP", "最近检测" }), 0, 0);
            mid.Controls.Add(Group("Claude 信息", new[] { "Claude 运行", "允许联网", "进程数量", "受保护程序", "最近保护性关闭", "关闭原因", "局域网扩展屏", "Clash 覆写", "Claude Code 代理" }), 1, 0);

            var gb = new GroupBox { Text = "检测明细", Dock = DockStyle.Fill };
            checks.View = View.Details; checks.FullRowSelect = true; checks.Dock = DockStyle.Fill; checks.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            checks.Columns.Add("结果", 60); checks.Columns.Add("项目", 130); checks.Columns.Add("说明", 480);
            gb.Controls.Add(checks);
            mid.Controls.Add(gb, 0, 1);
            mid.SetColumnSpan(gb, 2);

            var tabs = new TabControl { Dock = DockStyle.Fill };
            var overview = new TabPage("保护总览");
            overview.Controls.Add(mid);
            tabs.TabPages.Add(overview);
            tabs.TabPages.Add(nodePage);
            tabs.SelectedIndexChanged += (s, e) => { if (tabs.SelectedTab == nodePage) nodePage.Refresh2(); };
            timer.Tick += (s, e) => { if (tabs.SelectedTab == nodePage && Visible) nodePage.Refresh2(); };
            Controls.Add(tabs); Controls.Add(buttons); Controls.Add(top);
        }

        static void AddButton(FlowLayoutPanel p, string text, Action a, bool primary)
        {
            var b = new Button { Text = text, AutoSize = false, Size = new Size(text.Length > 5 ? 128 : 96, 30), Margin = new Padding(4), FlatStyle = FlatStyle.System };
            if (primary) b.Font = new Font(b.Font, FontStyle.Bold);
            b.Click += (s, e) => a();
            p.Controls.Add(b);
        }

        GroupBox Group(string title, string[] keys)
        {
            var gb = new GroupBox { Text = title, Dock = DockStyle.Fill, Padding = new Padding(8) };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = keys.Length };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 104));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < keys.Length; i++)
            {
                t.Controls.Add(new Label { Text = keys[i], AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(2, 4, 2, 2) }, 0, i);
                var v = new Label { Text = "—", AutoSize = true, AutoEllipsis = true, MaximumSize = new Size(300, 0), Margin = new Padding(2, 4, 2, 2) };
                t.Controls.Add(v, 1, i);
                fields[keys[i]] = v;
            }
            gb.Controls.Add(t);
            return gb;
        }

        void BuildTray()
        {
            tray.Icon = MakeIcon(Color.Gray);
            tray.Text = "Claude VPN Guard";
            tray.Visible = true;
            var m = new ContextMenuStrip();
            m.Items.Add("打开主界面", null, (s, e) => ShowMain());
            m.Items.Add("启动 Claude", null, (s, e) => LaunchClaude());
            m.Items.Add("立即检测", null, (s, e) => Poll(true));
            m.Items.Add("打开 Clash Verge", null, (s, e) => OpenClashVerge());
            m.Items.Add(new ToolStripSeparator());
            m.Items.Add("退出界面（保护继续运行）", null, (s, e) => { reallyExit = true; Close(); });
            tray.ContextMenuStrip = m;
            tray.DoubleClick += (s, e) => ShowMain();
        }

        void ShowMain() { Show(); WindowState = FormWindowState.Normal; Activate(); }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!reallyExit && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true; Hide();
                tray.ShowBalloonTip(2000, "Claude VPN Guard", "界面已最小化到托盘，保护服务持续运行。", ToolTipIcon.Info);
                return;
            }
            tray.Visible = false;
            base.OnFormClosing(e);
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            if (WindowState == FormWindowState.Minimized) Hide();
        }

        // ---------- 状态轮询 ----------
        void Poll(bool checkNow)
        {
            if (polling) return;
            polling = true;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                object data = null; string err = null;
                try { data = IpcClient.Call(checkNow ? "checknow" : "status", null, checkNow ? 30000 : 1500); }
                catch (Exception ex) { err = ex.Message; }
                try { BeginInvoke(new Action(() => { polling = false; Render(data, err); })); } catch { polling = false; }
            });
        }

        void Render(object s, string err)
        {
            lastStatus = s;
            if (s == null)
            {
                SetState("保护服务停止", Color.FromArgb(200, 40, 40), "无法连接后台保护服务：" + err + "。持久化防火墙规则仍然有效；请点“修复保护”。");
                if (lastState != "ServiceDown" && lastState != null) tray.ShowBalloonTip(5000, "Claude VPN Guard", "保护服务已停止！防火墙规则仍生效，请点“修复保护”。", ToolTipIcon.Error);
                lastState = "ServiceDown";
                return;
            }
            var state = Json.Str(s, "State");
            var text = Json.Str(s, "StateText");
            Color c = state == "Protected" ? Color.FromArgb(22, 140, 70) : state == "Verifying" ? Color.FromArgb(200, 130, 0) : Color.FromArgb(200, 40, 40);
            var sub = state == "Protected" ? "代理路径已验证，Claude 允许联网（仅能经代理）。" : (Json.Str(s, "LastFailure") ?? "正在验证代理安全…") + (Json.Bool(s, "Locked") ? "  —— Claude 网络已锁定" : "");
            SetState(text, c, sub);

            Func<bool, string> yn = b => b ? "是" : "否";
            fields["Clash Verge"].Text = Json.Bool(s, "VergeRunning") ? "运行中" : "未运行";
            fields["Mihomo 内核"].Text = Json.Bool(s, "CoreOk") ? "正常 " + Json.Str(s, "CoreVersion") : "不可用";
            var mode = Json.Str(s, "Mode");
            fields["代理模式"].Text = mode == "rule" ? "规则（Rule）" : mode == "global" ? "全局（Global）" : mode == "direct" ? "直连（Direct）⚠" : (mode ?? "—");
            fields["当前节点"].Text = Json.Str(s, "Node") ?? "—";
            fields["TUN 状态"].Text = Json.Bool(s, "TunEnabled") ? (Json.Bool(s, "TunUp") ? "已开启，网卡在线" : "已开启，网卡离线 ⚠") : "未开启";
            fields["系统代理"].Text = Json.Bool(s, "SysProxyOn") ? "已开启 " + Json.Str(s, "SysProxy") : "未开启";
            fields["出口 IP"].Text = Json.Str(s, "ExitIp") ?? "—";
            fields["最近检测"].Text = Json.Str(s, "LastCheck") ?? "—";
            int n = Json.Int(s, "ClaudeProcesses", 0);
            fields["Claude 运行"].Text = n > 0 ? "运行中" : "未运行";
            fields["允许联网"].Text = Json.Bool(s, "ClaudeAllowed") ? "允许（仅经代理）" : "已阻断";
            fields["进程数量"].Text = n.ToString();
            fields["受保护程序"].Text = Json.Int(s, "ProtectedExeCount", 0) + " 个可执行文件";
            fields["最近保护性关闭"].Text = Json.Str(s, "LastTrip") ?? "无";
            fields["关闭原因"].Text = Json.Str(s, "LastTripReason") ?? "—";
            var lan = Json.Str(s, "LanDisplay");
            fields["局域网扩展屏"].Text = lan == null ? "未检测到 spacedesk" : (lan.StartsWith("已连接") ? "已连接 " + lan.Substring(3) : lan);
            fields["Clash 覆写"].Text = OverrideStatus();
            fields["Claude Code 代理"].Text = ClaudeCodeProxy.Status(ClaudeCodeProxy.DefaultPath, 17897).Replace("已配置：", "");

            checks.BeginUpdate();
            checks.Items.Clear();
            foreach (var ci in Json.Arr(s, "Checks"))
            {
                bool ok = Json.Bool(ci, "ok");
                var it = new ListViewItem(new[] { ok ? "✔ 通过" : (Json.Bool(ci, "critical") ? "✘ 失败" : "! 提示"), Json.Str(ci, "name"), Json.Str(ci, "detail") });
                it.ForeColor = ok ? Color.FromArgb(22, 120, 60) : (Json.Bool(ci, "critical") ? Color.FromArgb(190, 30, 30) : Color.FromArgb(170, 110, 0));
                checks.Items.Add(it);
            }
            checks.EndUpdate();

            long seq = Convert.ToInt64(Json.Get(s, "TripSeq") ?? 0L);
            if (lastTripSeq >= 0 && seq > lastTripSeq)
                tray.ShowBalloonTip(10000, "Claude 已被保护性关闭", "代理连接异常，Claude 已被保护性关闭，当前网络访问已阻断。\n原因：" + Json.Str(s, "LastTripReason"), ToolTipIcon.Error);
            else if (lastState != null && lastState != "Protected" && lastState != "ServiceDown" && state == "Protected")
                tray.ShowBalloonTip(4000, "保护已恢复", "代理验证通过。如需使用 Claude，请手动启动。", ToolTipIcon.Info);
            lastTripSeq = seq;
            CheckOverrideAlert(s);
            // 保护性关闭后代理恢复：自动重开 Claude 并续跑被中断的会话
            AutoResume.Maybe(s, (t, m, i) => { try { BeginInvoke(new Action(() => tray.ShowBalloonTip(8000, t, m, i))); } catch { } });
            var rid = Json.Str(s, "ResumeId");
            if (rid != null && !AutoResume.AlreadyHandled(rid) && state == "Tripped")
                stateSub.Text = "已记录 " + Json.Int(s, "ResumeSessions", 0) + " 个待恢复会话；代理恢复并通过检测后将自动重开 Claude 并续跑。" + (Json.Str(s, "LastFailure") != null ? "  当前：" + Json.Str(s, "LastFailure") : "");
            lastState = state;
        }

        static string OverrideStatus()
        {
            try
            {
                var d = VergeOverride.FindVergeDataDir();
                if (d == null) return "未找到 Clash Verge";
                var f = VergeOverride.ScriptFile(d);
                bool written = System.IO.File.Exists(f) && System.IO.File.ReadAllText(f).Contains(VergeOverride.BeginMark);
                if (!written) return "全局扩展脚本里没有本程序段 ⚠";
                return VergeOverride.RuntimeLoaded(d) ? "已写入，Clash 已套用" : "已写入，Clash 未刷新 ⚠";
            }
            catch (Exception ex) { return "无法读取：" + ex.Message; }
        }

        // 覆写缺失/未套用时弹窗说清楚缺什么、去哪看、怎么修（同一问题只弹一次，恢复后复位）
        string overrideAlertKey;
        bool overrideDialogOpen;
        DateTime overrideProblemSince = DateTime.MinValue;
        void CheckOverrideAlert(object s)
        {
            var script = Json.Str(s, "OverrideScript");
            if (script == null) return; // 非隔离模式，或本次数据不含覆写状态
            bool core = Json.Bool(s, "CoreOk"), groupMissing = false, listenerDown = false;
            foreach (var ci in Json.Arr(s, "Checks"))
            {
                if (Json.Bool(ci, "ok")) continue;
                var id = Json.Str(ci, "id");
                if (id == "jpgroup" && (Json.Str(ci, "detail") ?? "").StartsWith("不存在")) groupMissing = true;
                if (id == "listener" && core) listenerDown = true;
            }
            bool stale = core && !Json.Bool(s, "OverrideRuntime");
            var note = Json.Str(s, "OverrideNote");
            var problems = new List<string>();
            if (groupMissing) problems.Add("Clash 里找不到 Japan Auto 组");
            if (listenerDown) problems.Add("专用入口 127.0.0.1:17897 没有在监听");
            if (script == "error") problems.Add(note);
            else if (script == "repaired" && stale) problems.Add(note + "，Clash 还没刷新");
            else if (stale) problems.Add("全局扩展脚本已改，但 Clash 当前配置还没套用；下次更新订阅前 Japan Auto 可能消失");
            if (problems.Count == 0) { overrideAlertKey = null; overrideProblemSince = DateTime.MinValue; return; }
            // 服务会在几秒内自动补写并套用；问题持续 15 秒还在才打扰用户
            if (overrideProblemSince == DateTime.MinValue) overrideProblemSince = DateTime.Now;
            if ((DateTime.Now - overrideProblemSince).TotalSeconds < 15) return;
            var key = string.Join("|", problems);
            if (key == overrideAlertKey || overrideDialogOpen) return;
            overrideAlertKey = key;
            overrideDialogOpen = true;
            tray.ShowBalloonTip(8000, "Clash 覆写需要处理", problems[0], ToolTipIcon.Warning);
            BeginInvoke(new Action(() =>
            {
                var r = MessageBox.Show("检测到 Clash 覆写问题：\n\n• " + string.Join("\n• ", problems) + "\n\n" + VergeOverride.WhereGuide +
                    "\n保护器每 3 秒检查这段脚本，缺了会自动补写（先备份原文件）并自动套用到 Clash；这次自动处理没有成功（原因见上），需要手动刷新。\n\n" + VergeOverride.RefreshGuide +
                    "\n\n【是】打开 Clash Verge　【否】稍后处理", "Clash 覆写需要处理", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                overrideDialogOpen = false;
                if (r == DialogResult.Yes) OpenClashVerge();
            }));
        }

        // 手动补写 Clash Verge 全局扩展脚本（用户自己的配置，无需管理员；先备份）
        void FixOverride()
        {
            try
            {
                var d = VergeOverride.FindVergeDataDir();
                if (d == null) { MessageBox.Show("未找到 Clash Verge 数据目录。", "修复 Clash 覆写"); return; }
                GuardSettings st = null;
                try { st = Json.Deserialize<GuardSettings>(Json.Serialize(IpcClient.Call("getsettings", null, 1500))); } catch { }
                if (st == null) st = GuardSettings.Load();
                var bak = VergeOverride.Ensure(d, st);
                var head = bak == null ? "全局扩展脚本里的本程序段完整，无需补写。" : "已重新写入全局扩展脚本（原文件备份：" + bak + "）。";
                string tail;
                if (VergeOverride.RuntimeLoaded(d)) tail = "Clash 当前配置也已套用，无需刷新。";
                else
                {
                    try
                    {
                        string diag;
                        var cl = MihomoClient.Discover(st, out diag);
                        if (cl == null) throw new InvalidOperationException("Clash 内核不可用：" + diag);
                        VergeOverride.HotLoad(d, st, cl);
                        tail = "已自动把覆写套用到 Clash 当前配置并重载内核，无需手动刷新。";
                    }
                    catch (Exception ex) { tail = "自动套用失败：" + ex.Message + "\n\n" + VergeOverride.RefreshGuide; }
                }
                if (tail.StartsWith("自动套用失败"))
                {
                    if (MessageBox.Show(head + "\n\n" + VergeOverride.WhereGuide + "\n\n" + tail + "\n\n现在打开 Clash Verge？", "修复 Clash 覆写", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) OpenClashVerge();
                }
                else MessageBox.Show(head + "\n\n" + VergeOverride.WhereGuide + "\n\n" + tail, "修复 Clash 覆写", MessageBoxButtons.OK, MessageBoxIcon.Information);
                overrideAlertKey = null;
                Poll(false);
            }
            catch (Exception ex) { MessageBox.Show("补写失败：" + ex.Message + "\n\n" + VergeOverride.WhereGuide, "修复 Clash 覆写"); }
        }

        void SetState(string text, Color c, string sub)
        {
            stateLabel.Text = text; stateLabel.ForeColor = c; stateSub.Text = sub;
            var ic = MakeIcon(c);
            tray.Icon = ic; Icon = ic;
            var tip = "Claude VPN Guard：" + text;
            tray.Text = tip.Length > 63 ? tip.Substring(0, 63) : tip;
        }

        static readonly Dictionary<int, Icon> iconCache = new Dictionary<int, Icon>();
        static Icon MakeIcon(Color c)
        {
            Icon ic;
            if (iconCache.TryGetValue(c.ToArgb(), out ic)) return ic;
            using (var bmp = new Bitmap(32, 32))
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                var shield = new GraphicsPath();
                shield.AddLines(new[] { new Point(16, 2), new Point(29, 7), new Point(27, 19), new Point(16, 30), new Point(5, 19), new Point(3, 7) });
                shield.CloseFigure();
                using (var b = new SolidBrush(c)) g.FillPath(b, shield);
                using (var p = new Pen(Color.White, 3f)) g.DrawLines(p, new[] { new Point(10, 16), new Point(15, 21), new Point(23, 11) });
                ic = Icon.FromHandle(bmp.GetHicon());
            }
            iconCache[c.ToArgb()] = ic;
            return ic;
        }

        // ---------- 操作 ----------
        void LaunchClaude()
        {
            Cursor = Cursors.WaitCursor;
            stateSub.Text = "正在执行启动前完整检测…";
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string err = null; object data = null;
                try { data = IpcClient.Call("preparelaunch", null, 30000); }
                catch (Exception ex) { err = ex.Message; }
                BeginInvoke(new Action(() =>
                {
                    Cursor = Cursors.Default;
                    if (err != null)
                    {
                        Poll(false);
                        var hint = err.Contains("Japan Auto") || err.Contains("专用入口") ? "\n\n" + VergeOverride.WhereGuide + "\n" + VergeOverride.RefreshGuide : "";
                        var r = MessageBox.Show("启动前安全检测未通过，已禁止 Claude 联网：\n\n" + err + hint + "\n\n是否打开 Clash Verge？", "无法启动 Claude", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                        if (r == DialogResult.Yes) OpenClashVerge();
                        return;
                    }
                    Render(data, null);
                    var target = Json.Str(data, "LaunchTarget");
                    try
                    {
                        bool iso = false; int port = 17897;
                        try { var nd = IpcClient.Call("nodes", null, 1500); iso = Json.Bool(nd, "Isolation"); port = Json.Int(nd, "DedicatedPort", 17897); } catch { }
                        if (iso && Json.Int(data, "ClaudeProcesses", 0) > 0)
                            MessageBox.Show("Claude 已在运行。隔离模式需要由保护器启动 Claude 才能带上专用入口参数，请先完全退出 Claude 再点“启动 Claude”。\n（在此之前 WFP 会阻止它使用通用代理端口，不会直连。）", "Claude VPN Guard");
                        else if (!string.IsNullOrEmpty(target)) ClaudeLauncher.Launch(target, iso, port);
                        else MessageBox.Show("检测已通过，但未找到 Claude 的启动入口，请从开始菜单启动 Claude。", "Claude VPN Guard");
                    }
                    catch (Exception ex) { MessageBox.Show("启动 Claude 失败：" + ex.Message); }
                }));
            });
        }

        void OpenClashVerge()
        {
            var path = FindClashVerge();
            if (path == null) { MessageBox.Show("未找到 Clash Verge，请在“设置”中指定安装路径。", "Claude VPN Guard"); return; }
            try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show("打开 Clash Verge 失败：" + ex.Message); }
        }

        static string FindClashVerge()
        {
            try
            {
                var st = Json.Deserialize<GuardSettings>(Json.Serialize(IpcClient.Call("getsettings", null, 1500)));
                if (st != null && !string.IsNullOrEmpty(st.ClashVergePath) && File.Exists(st.ClashVergePath)) return st.ClashVergePath;
            }
            catch { }
            foreach (var p in Process.GetProcesses())
            {
                try { if (p.ProcessName.StartsWith("clash-verge", StringComparison.OrdinalIgnoreCase) && !p.ProcessName.Contains("service")) return p.MainModule.FileName; }
                catch { }
            }
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                foreach (var root in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
                {
                    try
                    {
                        using (var k = hive.OpenSubKey(root))
                        {
                            if (k == null) continue;
                            foreach (var sub in k.GetSubKeyNames())
                                using (var sk = k.OpenSubKey(sub))
                                {
                                    var name = sk.GetValue("DisplayName") as string;
                                    if (name == null || name.IndexOf("Clash Verge", StringComparison.OrdinalIgnoreCase) < 0) continue;
                                    var loc = sk.GetValue("InstallLocation") as string;
                                    if (!string.IsNullOrEmpty(loc))
                                    {
                                        var exe = Directory.GetFiles(loc.Trim('"'), "clash-verge*.exe").FirstOrDefault(f => !f.Contains("service") && !f.Contains("uninstall"));
                                        if (exe != null) return exe;
                                    }
                                }
                        }
                    }
                    catch { }
                }
            }
            var def = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Clash Verge\clash-verge.exe");
            return File.Exists(def) ? def : null;
        }

        void ShowLogs()
        {
            var f = new Form { Text = "保护日志", Size = new Size(900, 600), StartPosition = FormStartPosition.CenterParent, Font = Font };
            var tb = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9F) };
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 42, Padding = new Padding(6) };
            Action load = () =>
            {
                Log.Dir = GuardPaths.LogDir;
                var lines = Log.Tail(800);
                tb.Text = lines.Length == 0 ? "（暂无日志，或无权读取 " + GuardPaths.LogDir + "）" : string.Join(Environment.NewLine, lines);
                tb.SelectionStart = tb.Text.Length; tb.ScrollToCaret();
            };
            var b1 = new Button { Text = "刷新", Size = new Size(90, 28) }; b1.Click += (s, e) => load();
            var b2 = new Button { Text = "导出日志", Size = new Size(90, 28) }; b2.Click += (s, e) => ExportLogs();
            var b3 = new Button { Text = "打开目录", Size = new Size(90, 28) }; b3.Click += (s, e) => { try { Process.Start("explorer.exe", GuardPaths.LogDir); } catch { } };
            bar.Controls.AddRange(new Control[] { b1, b2, b3 });
            f.Controls.Add(tb); f.Controls.Add(bar);
            load();
            f.Show(this);
        }

        static void ExportLogs()
        {
            try
            {
                var dst = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "ClaudeVPNGuard-logs-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".zip");
                using (var z = ZipFile.Open(dst, ZipArchiveMode.Create))
                {
                    foreach (var file in Directory.GetFiles(GuardPaths.LogDir, "*.log"))
                        using (var src = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (var e = z.CreateEntry(Path.GetFileName(file)).Open()) src.CopyTo(e);
                    foreach (var file in Directory.GetFiles(GuardPaths.DataDir, "selftest-report-*.txt"))
                        z.CreateEntryFromFile(file, Path.GetFileName(file));
                }
                MessageBox.Show("日志已导出到桌面：\n" + dst + "\n\n日志不含对话内容、密码、API Key、订阅或节点认证信息。", "导出完成");
            }
            catch (Exception ex) { MessageBox.Show("导出失败：" + ex.Message); }
        }

        const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

        void ShowSettings()
        {
            GuardSettings st = null;
            try { st = Json.Deserialize<GuardSettings>(Json.Serialize(IpcClient.Call("getsettings", null, 1500))); } catch { }
            if (st == null) st = GuardSettings.Load();
            var f = new Form { Text = "设置", Size = new Size(620, 360), StartPosition = FormStartPosition.CenterParent, Font = Font, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, Padding = new Padding(12) };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150)); t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            var path = new TextBox { Text = st.ClashVergePath ?? "", Dock = DockStyle.Fill };
            var browse = new Button { Text = "浏览…" };
            browse.Click += (s, e) => { using (var d = new OpenFileDialog { Filter = "Clash Verge|clash-verge*.exe|程序|*.exe" }) if (d.ShowDialog() == DialogResult.OK) path.Text = d.FileName; };
            var exitIp = new CheckBox { Text = "显示代理出口 IP（经代理访问 cloudflare trace，每 10 分钟最多一次）", Checked = st.ExitIpCheck, AutoSize = true };
            bool auto = false;
            try { using (var k = Registry.CurrentUser.OpenSubKey(RunKey)) auto = k != null && k.GetValue("ClaudeVPNGuard") != null; } catch { }
            var autostart = new CheckBox { Text = "开机自启界面（托盘）", Checked = auto, AutoSize = true };
            var info = new Label
            {
                AutoSize = false, Dock = DockStyle.Fill, ForeColor = Color.DimGray,
                Text = "保护服务本身随 Windows 自动启动，与此选项无关。\n会降低安全性的设置（fake-ip 网段、额外受保护程序、仅系统代理模式开关、触发后需手动解锁）只能由管理员编辑：\n" + GuardPaths.SettingsFile + "，改后重启服务生效。"
            };
            t.Controls.Add(new Label { Text = "Clash Verge 路径", AutoSize = true, Margin = new Padding(3, 8, 3, 3) }, 0, 0); t.Controls.Add(path, 1, 0); t.Controls.Add(browse, 2, 0);
            t.Controls.Add(exitIp, 0, 1); t.SetColumnSpan(exitIp, 3);
            t.Controls.Add(autostart, 0, 2); t.SetColumnSpan(autostart, 3);
            t.Controls.Add(info, 0, 3); t.SetColumnSpan(info, 3);
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 36)); t.RowStyles.Add(new RowStyle(SizeType.Absolute, 30)); t.RowStyles.Add(new RowStyle(SizeType.Absolute, 30)); t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var ok = new Button { Text = "保存", DialogResult = DialogResult.OK, Size = new Size(90, 30) };
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            bar.Controls.Add(ok);
            f.Controls.Add(t); f.Controls.Add(bar); f.AcceptButton = ok;
            if (f.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(RunKey))
                {
                    if (autostart.Checked) k.SetValue("ClaudeVPNGuard", "\"" + Application.ExecutablePath + "\" --tray");
                    else if (k.GetValue("ClaudeVPNGuard") != null) k.DeleteValue("ClaudeVPNGuard");
                }
                IpcClient.Call("setsettings", new Dictionary<string, object> { { "ClashVergePath", path.Text.Trim() }, { "ExitIpCheck", exitIp.Checked } }, 3000);
            }
            catch (Exception ex) { MessageBox.Show("保存设置失败：" + ex.Message); }
        }

        static bool RunElevated(string args)
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo(ServiceExe, args) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden });
                p.WaitForExit(60000);
                return p.ExitCode == 0;
            }
            catch (System.ComponentModel.Win32Exception) { MessageBox.Show("需要管理员授权才能执行此操作。", "Claude VPN Guard"); return false; }
        }

        void Repair()
        {
            if (MessageBox.Show("将以管理员权限重新注册保护服务并重建 Claude 防火墙规则（重建期间 Claude 网络保持锁定）。继续？", "修复保护", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            MessageBox.Show(RunElevated("install") ? "修复完成，保护服务已重新启动。" : "修复未成功，请查看日志。", "修复保护");
            Poll(true);
        }

        void Uninstall()
        {
            // 完全卸载交给 full-uninstall.ps1（系统自带 PowerShell，不依赖本程序 exe），它会自己提权、确认并复查
            try
            {
                if (!FullUninstall.Launch(false)) { MessageBox.Show("找不到卸载脚本 " + FullUninstall.ScriptName + "，请重新安装或从源码 scripts 目录运行。", "安全卸载"); return; }
            }
            catch (Exception ex) { MessageBox.Show("无法启动卸载脚本：" + ex.Message, "安全卸载"); return; }
            try { using (var k = Registry.CurrentUser.CreateSubKey(RunKey)) if (k.GetValue("ClaudeVPNGuard") != null) k.DeleteValue("ClaudeVPNGuard"); } catch { }
            reallyExit = true; Close();
        }
    }
}
