package com.tianhuo.vpnguard

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView

/** 首次设置向导：每一步显示是否完成，可在设置里重走。 */
class SetupActivity : Activity() {
    private class Step(val title: String, val hint: String, val done: () -> Boolean?, val label: String, val act: () -> Unit) {
        lateinit var view: TextView
    }

    @Volatile private var usingGuard: Boolean? = null
    @Volatile private var node: String? = null
    private lateinit var steps: List<Step>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val ui = Ui(this)
        ui.text(22f, true).text = "设置向导"
        ui.text(13f).text = "按顺序完成下面各步；完成的显示 ✓。以后可在「设置 → 重走设置向导」再来。"

        steps = listOf(
            Step("1. 授权 root 或 Shizuku", "用来给 Claude 断网/放行。没有就用第 3 步兜底。", { Shell.permitted() }, "授权 Shizuku") { Actions.requestShizuku(this) },
            Step("2. 省电设为无限制", "防止系统杀掉卫士。", { Actions.batteryUnrestricted(this) }, "去设置") { Actions.askBatteryExemption(this) },
            Step("3. 兜底无障碍（可选）", "没有 root/Shizuku 时：出口不安全就把 Claude 关掉。", { ClaudeBlocker.enabled() }, "打开无障碍") { Actions.openAccessibility(this) },
            Step("4. 导入订阅", "把机场订阅链接粘贴进卫士，只存在本机。", { Subs.list(this).isNotEmpty() && Subs.configFile(this).exists() }, "订阅与节点") {
                startActivity(Intent(this, SubsActivity::class.java))
            },
            Step("5. FlClash 导入卫士配置", "会跳到 FlClash 弹确认框，点确定。", { Prefs.lastServed(this) > 0 }, "导入到 FlClash") { Actions.importToFlClash(this) },
            Step("6. 在 FlClash 选中「网关卫士」配置并连接", "配置页点选它，再打开 VPN。", { usingGuard }, "打开 FlClash") { Actions.openFlClash(this) },
            Step("7. 启动卫士", "持续检测出口，异常立刻给 Claude 断网。", { GuardService.running }, "启动卫士") { Actions.startGuard(this) },
            Step("8. FlClash 外部控制器（可选）", "FlClash 工具 → 常规 → 入站 → 外部控制器打开，看板才能显示当前节点。", { node != null }, "打开 FlClash") { Actions.openFlClash(this) },
        )
        for (s in steps) {
            val card = ui.card(s.title)
            s.view = ui.text(13f, parent = card)
            ui.button(s.label, card, s.act)
        }
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        ui.root.addView(row)
        ui.button("刷新状态", row) { refreshSlow() }
        ui.button("完成", row) {
            Prefs.setSetupDone(this, true)
            finish()
        }
        ui.show()
    }

    override fun onResume() {
        super.onResume()
        refresh()
        refreshSlow()
        if (!Shell.rooted) Thread { if (Shell.probeRoot()) runOnUiThread { refresh() } }.start()
    }

    private fun refreshSlow() = Thread {
        usingGuard = ConfigServer.flclashUsingGuard(this)
        node = ConfigServer.currentNode()
        runOnUiThread { refresh() }
    }.start()

    private fun refresh() {
        for (s in steps) {
            val d = s.done()
            s.view.text = (when (d) { true -> "✓ 已完成"; false -> "○ 未完成"; null -> "… 检测中" }) + "\n" + s.hint
            s.view.setTextColor(if (d == true) Actions.GREEN else Color.DKGRAY)
        }
    }
}
