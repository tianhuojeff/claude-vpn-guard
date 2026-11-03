package com.tianhuo.vpnguard

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.TextView
import rikka.shizuku.Shizuku

/** 首页：简洁状态看板，对齐桌面端「保护总览」。设置步骤在 SetupActivity，杂项在 SettingsActivity。 */
class MainActivity : Activity() {
    private lateinit var statusView: TextView
    private lateinit var proxyView: TextView
    private lateinit var subsView: TextView
    private lateinit var claudeView: TextView
    private lateinit var envView: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val poll = object : Runnable {
        override fun run() { refreshSlow(); handler.postDelayed(this, 10_000) }
    }

    // 后台探测结果（FlClash 是否在用卫士配置、当前节点）
    @Volatile private var usingGuard: Boolean? = null
    @Volatile private var node: String? = null

    private val permListener = Shizuku.OnRequestPermissionResultListener { _, result ->
        Actions.toast(this, if (result == PackageManager.PERMISSION_GRANTED) "Shizuku 已授权" else "Shizuku 授权被拒绝")
        refresh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val ui = Ui(this)
        ui.text(22f, true).text = "网关卫士"
        statusView = ui.text(18f, true)

        proxyView = ui.text(13f, parent = ui.card("代理"))
        val subsCard = ui.card("订阅")
        subsView = ui.text(13f, parent = subsCard)
        claudeView = ui.text(13f, parent = ui.card("Claude"))
        envView = ui.text(13f).apply { setTextColor(Actions.RED) }

        ui.button("启动 Claude（先检测，通过才放行）") { Actions.launchClaude(this) { refresh() } }
        ui.button("立即检测") { Actions.check(this) { refresh(); refreshSlow() } }
        ui.button("订阅与节点") { startActivity(Intent(this, SubsActivity::class.java)) }
        ui.button("设置") { startActivity(Intent(this, SettingsActivity::class.java)) }
        ui.show()

        ConfigServer.ensure(this)
        Shizuku.addRequestPermissionResultListener(permListener)
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
        }
        if (!Prefs.setupDone(this)) startActivity(Intent(this, SetupActivity::class.java))
    }

    override fun onResume() {
        super.onResume()
        GuardService.onChange = { runOnUiThread { refresh() } }
        refresh()
        handler.post(poll)
        if (!Shell.rooted) Thread { if (Shell.probeRoot()) runOnUiThread { refresh() } }.start()
    }

    override fun onPause() {
        GuardService.onChange = null
        handler.removeCallbacks(poll)
        super.onPause()
    }

    override fun onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permListener)
        super.onDestroy()
    }

    private fun refreshSlow() = Thread {
        usingGuard = ConfigServer.flclashUsingGuard(this)
        node = ConfigServer.currentNode()
        runOnUiThread { refresh() }
    }.start()

    private fun refresh() {
        statusView.text = when {
            !GuardService.running -> "● 卫士未运行"
            GuardService.locked -> "● 已锁定：" + GuardService.status
            else -> "● " + GuardService.status
        }
        statusView.setTextColor(
            when {
                !GuardService.running -> Color.GRAY
                GuardService.locked -> Actions.RED
                else -> Actions.GREEN
            }
        )

        val vpn = Checker.hasVpnNetwork(this)
        val owners = Subs.owners(this)
        proxyView.text = listOf(
            "FlClash：" + (if (vpn) "VPN 已连接" else "VPN 未连接"),
            "使用配置：" + when (usingGuard) {
                true -> "网关卫士总配置 ✓"
                false -> "不是卫士配置（在 FlClash 选中「网关卫士」）"
                null -> "检测中…"
            },
            "Claude 线路：${Subs.GROUP}（只走日本，全挂即断开，不换国家不直连）",
            "当前节点：" + (node?.let { n -> if (n == "REJECT") "REJECT（没有日本节点，Claude 被拒绝）" else n + (owners[n]?.let { "（$it）" } ?: "") }
                ?: "未知（FlClash 打开外部控制器后显示）"),
            "出口：" + (GuardService.exit ?: "—"),
            "最近检测：" + Actions.time(GuardService.lastCheckAt, "HH:mm:ss"),
        ).joinToString("\n")

        val subs = Subs.list(this)
        subsView.text = if (subs.isEmpty()) "还没有订阅，点「订阅与节点」导入" else
            subs.mapIndexed { i, s ->
                (if (i == 0) "★ " else "· ") + s.name + "　日本 ${s.jp}/${s.total}" + (s.info?.let { "\n　$it" } ?: "") + (s.error?.let { "\n　更新失败：$it" } ?: "")
            }.joinToString("\n") + "\n生成：" + Actions.time(Subs.lastBuild(this)) + "　FlClash 拉取：" + Actions.time(Prefs.lastServed(this))

        claudeView.text = "允许联网：" + (if (GuardService.running && !GuardService.locked) "是" else "否（已锁定）") +
            "\n最近保护性关闭：" + (Prefs.lastProtect(this)?.let { (t, why) -> Actions.time(t) + "　" + why } ?: "无")

        val problems = mutableListOf<String>()
        if (!Shell.permitted()) problems += if (ClaudeBlocker.enabled()) "没有 root/Shizuku：兜底模式" else "没有 root/Shizuku，兜底也没开"
        if (!Actions.batteryUnrestricted(this)) problems += "省电未设为无限制"
        envView.text = if (problems.isEmpty()) "" else "卫士：" + problems.joinToString("；") + "（设置 → 重走设置向导）"
    }
}
