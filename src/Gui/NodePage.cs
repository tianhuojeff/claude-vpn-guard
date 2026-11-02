// written_by: claude-code
// “日本节点管理”页 + 隔离模式下带代理参数启动 Claude（MSIX 应用激活接口）。
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace ClaudeVPNGuard
{
    [ComImport, Guid("2e941141-7f97-4756-ba1d-9decde894a3d"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IApplicationActivationManager
    {
        int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId, [MarshalAs(UnmanagedType.LPWStr)] string arguments, int options, out uint processId);
        int ActivateForFile(IntPtr a, IntPtr b, IntPtr c, out uint d);
        int ActivateForProtocol(IntPtr a, IntPtr b, out uint c);
    }
    [ComImport, Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")] class ApplicationActivationManager { }

    static class ClaudeLauncher
    {
        // 隔离模式：让 Claude（Chromium 内核）只使用专用入口；若 Claude 忽略该参数，WFP 会阻断它连接通用端口 → 无法联网而不是直连
        public static uint Launch(string launchTarget, bool isolation, int dedicatedPort)
        {
            var aumid = launchTarget.Replace(@"shell:AppsFolder\", "");
            if (!isolation)
            {
                System.Diagnostics.Process.Start("explorer.exe", launchTarget);
                return 0;
            }
            var proxy = "http://127.0.0.1:" + dedicatedPort;
            var args = "--proxy-server=" + proxy + " --proxy-bypass-list=<-loopback>";
            // 优先用应用执行别名启动：可以只为 Claude 这一个进程（及其子进程，如内置 Claude Code）设置代理环境变量，
            // 不修改任何用户级/系统级环境变量（实测：内置 Claude Code 不读取 ~/.claude/settings.json 的代理设置，而是继承进程环境）
            var alias = FindAlias();
            if (alias != null)
            {
                var psi = new System.Diagnostics.ProcessStartInfo(alias, args) { UseShellExecute = false };
                foreach (var k in new[] { "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy" }) psi.EnvironmentVariables[k] = proxy;
                psi.EnvironmentVariables["NO_PROXY"] = "127.0.0.1,localhost,::1";
                psi.EnvironmentVariables["no_proxy"] = "127.0.0.1,localhost,::1";
                var p = System.Diagnostics.Process.Start(psi);
                return p == null ? 0u : (uint)p.Id;
            }
            var mgr = (IApplicationActivationManager)new ApplicationActivationManager();
            uint pid;
            int hr = mgr.ActivateApplication(aumid, args, 0, out pid);
            if (hr != 0) Marshal.ThrowExceptionForHR(hr);
            return pid;
        }

        // Claude 桌面版的应用执行别名（%LOCALAPPDATA%\Microsoft\WindowsApps\claude-desktop-msstore.exe 等）
        public static string FindAlias()
        {
            var dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\WindowsApps");
            foreach (var name in new[] { "claude-desktop-msstore.exe", "claude-desktop.exe" })
            {
                var f = System.IO.Path.Combine(dir, name);
                if (System.IO.File.Exists(f)) return f;
            }
            try
            {
                foreach (var sub in System.IO.Directory.GetDirectories(dir, "AnthropicPBC.Claude_*"))
                    foreach (var f in System.IO.Directory.GetFiles(sub, "*.exe")) return f;
            }
            catch { }
            return null;
        }
    }

    class NodePage : TabPage
    {
        readonly Dictionary<string, Label> f = new Dictionary<string, Label>();
        readonly ListView list = new ListView();
        readonly TextBox timeline = new TextBox();
        bool busy;
        public object LastData;

        public NodePage() : base("日本节点管理")
        {
            Padding = new Padding(8);
            var top = new TableLayoutPanel { Dock = DockStyle.Top, Height = 168, ColumnCount = 4 };
            for (int i = 0; i < 4; i++) top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            top.RowCount = 3; for (int i = 0; i < 3; i++) top.RowStyles.Add(new RowStyle(SizeType.Percent, 33.3F));
            var keys = new[] { "当前节点", "代理组状态", "自动切换", "出口 IP", "当前节点延迟", "当前失败次数", "最近切换", "切换耗时", "切换原因", "最近安全阻断", "下次重试", "专用入口" };
            for (int i = 0; i < keys.Length; i++)
            {
                var p = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(2) };
                p.Controls.Add(new Label { Text = keys[i], ForeColor = Color.DimGray, AutoSize = true });
                var v = new Label { Text = "—", AutoSize = true, MaximumSize = new Size(170, 0) };
                p.Controls.Add(v);
                f[keys[i]] = v;
                top.Controls.Add(p, i % 4, i / 4);
            }
            // 订阅：勾选 = 参与 Japan Auto；过期/流量用完的订阅自动跳过。Clash Verge 新加的订阅几秒内出现在这里
            var subBox = new GroupBox { Text = "订阅（勾选的订阅里的日本节点都参与自动切换）", Dock = DockStyle.Fill, Padding = new Padding(6), Margin = new Padding(0, 0, 0, 4) };
            subs.View = View.Details; subs.CheckBoxes = true; subs.FullRowSelect = true; subs.Dock = DockStyle.Fill; subs.MultiSelect = false;
            subs.Columns.Add("订阅", 150); subs.Columns.Add("状态", 110); subs.Columns.Add("日本节点", 70); subs.Columns.Add("已用流量", 110); subs.Columns.Add("到期", 90);
            subs.ItemChecked += (s, e) =>
            {
                if (rendering) return;
                Call("subset", new Dictionary<string, object> { { "uid", (string)e.Item.Tag }, { "on", e.Item.Checked } }, 8000);
            };
            var subBar = new FlowLayoutPanel { Dock = DockStyle.Right, Width = 130, FlowDirection = FlowDirection.TopDown, WrapContents = false };
            Btn(subBar, "只用选中的订阅", () =>
            {
                if (subs.SelectedItems.Count == 0) { MessageBox.Show("请先在订阅列表中点选一个订阅。"); return; }
                Call("subset", new Dictionary<string, object> { { "only", (string)subs.SelectedItems[0].Tag } }, 8000);
            });
            Btn(subBar, "启用全部订阅", () => Call("subset", new Dictionary<string, object> { { "all", true } }, 8000));
            subStatus.AutoSize = true; subStatus.ForeColor = Color.DimGray; subStatus.MaximumSize = new Size(125, 0);
            subBar.Controls.Add(subStatus);
            subBox.Controls.Add(subs); subBox.Controls.Add(subBar);

            list.View = View.Details; list.FullRowSelect = true; list.Dock = DockStyle.Fill; list.MultiSelect = false;
            list.Columns.Add("节点", 200); list.Columns.Add("订阅", 90); list.Columns.Add("延迟", 70); list.Columns.Add("健康", 60); list.Columns.Add("连续失败", 70); list.Columns.Add("隔离中", 60); list.Columns.Add("最近错误", 260);
            timeline.Multiline = true; timeline.ReadOnly = true; timeline.ScrollBars = ScrollBars.Vertical; timeline.Dock = DockStyle.Fill; timeline.Font = new Font("Consolas", 8.5F);
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40 };
            // 自动切换：一个开关按钮，按下=开启（绿色），弹起=关闭；文字始终显示当前状态
            autoSw.Appearance = Appearance.Button; autoSw.AutoSize = true; autoSw.Height = 28; autoSw.Margin = new Padding(3, 3, 12, 3);
            autoSw.CheckedChanged += (s, e) =>
            {
                PaintSwitch();
                if (!rendering) Call("autoswitch", new Dictionary<string, object> { { "on", autoSw.Checked } }, 3000);
            };
            bar.Controls.Add(autoSw); PaintSwitch();
            Btn(bar, "重新扫描梯子", Rescan);
            Btn(bar, "测试全部日本节点", () => Call("nodetestall", null, 20000));
            Btn(bar, "手动选择节点", ManualSelect);
            Btn(bar, "立即重新验证", () => Call("checknow", null, 30000));
            Btn(bar, "切换参数", EditParams);
            Btn(bar, "节点故障日志", () => MessageBox.Show(timeline.Text.Length == 0 ? "暂无" : timeline.Text, "节点故障时间线"));
            // 订阅 / 节点 / 时间线按比例分高度，窗口再小节点列表也不会被挤没
            var body = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            body.RowStyles.Add(new RowStyle(SizeType.Absolute, 132));   // 订阅框固定高度，右侧两个按钮能竖排放下
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 65));
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 35));
            list.Margin = new Padding(0, 0, 0, 4); timeline.Margin = new Padding(0);
            body.Controls.Add(subBox, 0, 0); body.Controls.Add(list, 0, 1); body.Controls.Add(timeline, 0, 2);
            Controls.Add(body); Controls.Add(bar); Controls.Add(top);
        }

        readonly ListView subs = new ListView();
        readonly Label subStatus = new Label();
        readonly CheckBox autoSw = new NoCueCheck();
        bool rendering;

        void PaintSwitch()
        {
            autoSw.Text = autoSw.Checked ? "● 自动切换：已开启" : "○ 自动切换：已关闭";
            autoSw.BackColor = autoSw.Checked ? Color.FromArgb(214, 240, 218) : SystemColors.Control;
            autoSw.ForeColor = autoSw.Checked ? Color.FromArgb(20, 110, 40) : Color.FromArgb(150, 60, 40);
        }

        // 普通动作按钮：不显示焦点框，避免点过的按钮看起来像“选中状态”
        class NoCueButton : Button { protected override bool ShowFocusCues { get { return false; } } }
        class NoCueCheck : CheckBox { protected override bool ShowFocusCues { get { return false; } } }
        static void Btn(FlowLayoutPanel p, string t, Action a) { var b = new NoCueButton { Text = t, AutoSize = true, Height = 28 }; b.Click += (s, e) => a(); p.Controls.Add(b); }

        void Call(string cmd, Dictionary<string, object> args, int timeout)
        {
            if (busy) return;
            busy = true;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string err = null;
                try { IpcClient.Call(cmd, args, timeout); } catch (Exception ex) { err = ex.Message; }
                try { BeginInvoke(new Action(() => { busy = false; if (err != null) MessageBox.Show(err, "操作未成功"); Refresh2(); })); } catch { busy = false; }
            });
        }

        // 重新连接 Clash Verge 内核、重读全部订阅、刷新所有新加或已有的日本节点并重测
        void Rescan()
        {
            if (busy) return;
            busy = true;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string msg;
                try { msg = Convert.ToString(IpcClient.Call("rescan", null, 90000)); }
                catch (Exception ex) { msg = "重新扫描未成功：" + ex.Message + "\n\n如果保护服务没在运行，请先在首页点“修复保护”。"; }
                try { BeginInvoke(new Action(() => { busy = false; MessageBox.Show(msg, "重新扫描梯子"); Refresh2(); })); } catch { busy = false; }
            });
        }

        void ManualSelect()
        {
            if (list.SelectedItems.Count == 0) { MessageBox.Show("请先在列表中选中一个日本节点。"); return; }
            var node = list.SelectedItems[0].Text;
            if (MessageBox.Show("切换到 " + node + "？将先测试该节点、验证出口国家和 Claude 路径，未通过则不切换。", "手动选择节点", MessageBoxButtons.OKCancel) == DialogResult.OK)
                Call("nodeselect", new Dictionary<string, object> { { "node", node } }, 30000);
        }

        void EditParams()
        {
            var pr = Json.Get(LastData, "Params") as IDictionary<string, object>;
            if (pr == null) { MessageBox.Show("暂未获取到参数"); return; }
            var names = new Dictionary<string, string>
            {
                { "MaxDelayMs", "节点延迟上限 (ms)" }, { "ProbeTimeoutMs", "单次探测超时 (ms)" }, { "FailThreshold", "连续失败次数" }, { "RecoverThreshold", "恢复前连续成功次数" },
                { "HealthIntervalSec", "常规健康检测间隔 (s)" }, { "AllFailRetrySec", "全部失败后重试间隔 (s)" }, { "SwitchCooldownSec", "节点切换冷却 (s)" }, { "MinDwellSec", "最短节点驻留 (s)" }, { "CurrentNodeCheckSec", "旧策略检测周期 (s)" }
            };
            var form = new Form { Text = "故障转移参数", Size = new Size(380, 420), StartPosition = FormStartPosition.CenterParent, FormBorderStyle = FormBorderStyle.FixedDialog, Font = Font };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new Padding(10) };
            var boxes = new Dictionary<string, NumericUpDown>();
            foreach (var kv in names)
            {
                t.Controls.Add(new Label { Text = kv.Value, AutoSize = true, Margin = new Padding(3, 7, 3, 3) });
                var nb = new NumericUpDown { Maximum = 100000, Minimum = 0, Width = 100 };
                object v; if (pr.TryGetValue(kv.Key, out v)) nb.Value = Convert.ToDecimal(v);
                boxes[kv.Key] = nb; t.Controls.Add(nb);
            }
            var ok = new Button { Text = "保存", DialogResult = DialogResult.OK, Dock = DockStyle.Bottom, Height = 32 };
            form.Controls.Add(t); form.Controls.Add(ok); form.AcceptButton = ok;
            if (form.ShowDialog(this) == DialogResult.OK)
                Call("setparams", boxes.ToDictionary(k => k.Key, k => (object)(int)k.Value.Value), 3000);
        }

        public void Refresh2()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                object d = null;
                try { d = IpcClient.Call("nodes", null, 1500); } catch { }
                try { BeginInvoke(new Action(() => Render(d))); } catch { }
            });
        }

        void Render(object d)
        {
            if (d == null) return;
            LastData = d;
            var cur = Json.Str(d, "Current");
            f["当前节点"].Text = cur ?? "—";
            var stx = Json.Str(d, "Status");
            f["代理组状态"].Text = Json.Str(d, "Group") + "：" + (stx == "Healthy" ? "健康" : stx == "Degraded" ? "异常（确认中）" : stx == "Switching" ? "切换中" : stx == "AllFailed" ? "全部失败（保持阻断）" : stx == "GroupMissing" ? "组不存在" : stx == "Manual" ? "手动模式" : stx);
            f["自动切换"].Text = Json.Bool(d, "AutoSwitch") ? "开启" : "关闭";
            rendering = true;
            try
            {
                autoSw.Checked = Json.Bool(d, "AutoSwitch");
                var keep = subs.SelectedItems.Count > 0 ? (string)subs.SelectedItems[0].Tag : null;
                subs.BeginUpdate();
                subs.Items.Clear();
                foreach (var s in Json.Arr(d, "Subscriptions"))
                {
                    var state = Json.Bool(s, "expired") ? "已过期（自动跳过）" : Json.Bool(s, "exhausted") ? "流量用完（自动跳过）" : !Json.Bool(s, "enabled") ? "已停用" :
                        Json.Int(s, "jp", 0) == 0 ? "无日本节点" : "使用中";
                    if (Json.Bool(s, "current")) state += " · Clash 当前";
                    double used = Convert.ToDouble(Json.Get(s, "usedGB") ?? 0), total = Convert.ToDouble(Json.Get(s, "totalGB") ?? 0);
                    var it = new ListViewItem(new[] { Json.Str(s, "name"), state, Json.Int(s, "jp", 0).ToString(), total > 0 ? used + " / " + total + " GB" : "—", Json.Str(s, "expire") ?? "—" });
                    it.Tag = Json.Str(s, "uid");
                    it.Checked = Json.Bool(s, "enabled");
                    if (!Json.Bool(s, "usable")) it.ForeColor = Color.Gray;
                    if (it.Tag as string == keep) it.Selected = true;
                    subs.Items.Add(it);
                }
                subs.EndUpdate();
                var se = Json.Str(d, "SubsError");
                subStatus.Text = se != null ? "⚠ " + se : "汇总更新：" + (Json.Str(d, "SubsUpdated") ?? "—");
                subStatus.ForeColor = se != null ? Color.FromArgb(180, 40, 40) : Color.DimGray;
            }
            finally { rendering = false; }
            f["出口 IP"].Text = (Json.Str(d, "ExitIp") ?? "—") + " " + (Json.Str(d, "ExitCountry") ?? "");
            f["最近切换"].Text = Json.Str(d, "LastSwitchAt") ?? "无";
            int ms = Json.Int(d, "LastSwitchMs", -1);
            f["切换耗时"].Text = ms < 0 ? "—" : ms + " ms";
            f["切换原因"].Text = Json.Str(d, "LastSwitchReason") ?? "—";
            f["最近安全阻断"].Text = Json.Str(d, "LastTrip") ?? "无";
            int retry = Json.Int(d, "NextRetryIn", -1);
            f["下次重试"].Text = retry < 0 ? "—" : retry + " 秒后";
            f["专用入口"].Text = (Json.Bool(d, "Isolation") ? "隔离模式 " : "未启用隔离 ") + "127.0.0.1:" + Json.Int(d, "DedicatedPort", 0);
            list.BeginUpdate();
            list.Items.Clear();
            foreach (var n in Json.Arr(d, "Nodes"))
            {
                int dl = Json.Int(n, "delay", -1);
                var it = new ListViewItem(new[] { Json.Str(n, "name"), Json.Str(n, "sub") ?? "", dl < 0 ? "失败" : dl + "ms", Json.Bool(n, "healthy") ? "是" : "否", Json.Int(n, "fails", 0).ToString(), Json.Bool(n, "quarantined") ? "是" : "", Json.Str(n, "error") ?? "" });
                if (Json.Bool(n, "current")) { it.Font = new Font(list.Font, FontStyle.Bold); f["当前节点延迟"].Text = dl < 0 ? "失败" : dl + " ms"; f["当前失败次数"].Text = Json.Int(n, "fails", 0).ToString(); }
                if (!Json.Bool(n, "healthy")) it.ForeColor = Color.FromArgb(180, 40, 40);
                list.Items.Add(it);
            }
            list.EndUpdate();
            timeline.Text = string.Join(Environment.NewLine, Json.Arr(d, "Timeline").Select(x => Convert.ToString(x)));
        }
    }
}
