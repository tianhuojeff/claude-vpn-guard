package com.tianhuo.vpnguard

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import rikka.shizuku.Shizuku
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 各页面共用的代码布局小工具（不用 XML）。 */
class Ui(private val act: Activity) {
    val dp = act.resources.displayMetrics.density
    val pad = (16 * dp).toInt()
    val root = LinearLayout(act).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(pad, pad * 2, pad, pad)
    }

    fun text(size: Float, bold: Boolean = false, parent: ViewGroup = root) = TextView(act).apply {
        textSize = size
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setPadding(0, pad / 4, 0, pad / 4)
        parent.addView(this)
    }

    fun button(label: String, parent: ViewGroup = root, onClick: () -> Unit) = Button(act).apply {
        text = label
        isAllCaps = false
        setOnClickListener { onClick() }
        parent.addView(this)
    }

    /** 圆角浅色卡片。 */
    fun card(title: String? = null, parent: ViewGroup = root) = LinearLayout(act).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(pad, pad / 2, pad, pad / 2)
        background = GradientDrawable().apply { cornerRadius = 12 * dp; setColor(Color.rgb(0xF1, 0xF3, 0xF4)) }
        parent.addView(this, LinearLayout.LayoutParams(-1, -2).apply { topMargin = pad / 2; bottomMargin = pad / 4 })
        title?.let { text(15f, true, this).text = it }
    }

    fun show() = act.setContentView(ScrollView(act).apply { addView(root) })
}

/** 向导、看板、设置共用的动作。 */
object Actions {
    val GREEN = Color.rgb(0x1E, 0x6B, 0x52)
    val RED = Color.rgb(0xC6, 0x28, 0x28)

    fun time(t: Long, pattern: String = "MM-dd HH:mm") = if (t <= 0) "—" else SimpleDateFormat(pattern, Locale.US).format(Date(t))

    fun toast(act: Activity, s: String) = act.runOnUiThread { Toast.makeText(act, s, Toast.LENGTH_LONG).show() }

    fun requestShizuku(act: Activity) {
        when {
            !Shell.shizukuRunning() -> {
                toast(act, "Shizuku 没有运行：打开 Shizuku → 无线调试启动")
                act.packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api")?.let { act.startActivity(it) }
            }
            Shizuku.isPreV11() -> toast(act, "Shizuku 版本过旧")
            Shell.shizukuPermitted() -> toast(act, "已授权")
            else -> Shizuku.requestPermission(1)
        }
    }

    fun batteryUnrestricted(act: Activity) = act.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(act.packageName)

    fun askBatteryExemption(act: Activity) {
        if (batteryUnrestricted(act)) return toast(act, "已是无限制")
        @Suppress("BatteryLife")
        act.startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${act.packageName}")))
    }

    fun openAccessibility(act: Activity) {
        toast(act, "在「已下载的应用」里找到「网关卫士兜底」并打开")
        act.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
    }

    fun startGuard(act: Activity) {
        if (!Shell.permitted() && !ClaudeBlocker.enabled()) toast(act, "请先授予 root，或启动 Shizuku 并授权，或开启兜底") else GuardService.start(act)
    }

    /** 让 FlClash 导入卫士配置（会弹确认框）。 */
    fun importToFlClash(act: Activity) {
        ConfigServer.ensure(act)
        if (!Subs.configFile(act).exists()) return toast(act, "先导入订阅并生成配置")
        try {
            act.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("clash://install-config?url=" + Uri.encode(Subs.localUrl(act)))))
        } catch (e: ActivityNotFoundException) {
            toast(act, "没找到 FlClash")
        }
    }

    fun openFlClash(act: Activity) {
        act.packageManager.getLaunchIntentForPackage(Prefs.FLCLASH)?.let { act.startActivity(it) } ?: toast(act, "没找到 FlClash")
    }

    fun check(act: Activity, after: () -> Unit) = background(act) {
        if (GuardService.running) {
            GuardService.checkNow(act)
        } else {
            val r = Checker.check(act)
            GuardService.lastCheckAt = System.currentTimeMillis()
            GuardService.exit = if (r.safe) r.exit else null
            GuardService.addLog((if (r.safe) "检测通过：" else "检测未通过：") + r.reason)
            r.traces.forEach { GuardService.addLog("  $it") }
        }
        act.runOnUiThread(after)
    }

    fun launchClaude(act: Activity, after: () -> Unit) = background(act) {
        val r = GuardService.checkAndUnlockNow(act)
        GuardService.lastCheckAt = System.currentTimeMillis()
        r.traces.forEach { GuardService.addLog("  $it") }
        act.runOnUiThread {
            after()
            if (!r.safe) {
                toast(act, "出口不安全，Claude 保持断网：" + r.reason)
            } else {
                val i = act.packageManager.getLaunchIntentForPackage(Prefs.CLAUDE)
                if (i == null) toast(act, "没找到 Claude App") else act.startActivity(i)
            }
        }
    }

    private fun background(act: Activity, block: () -> Unit) {
        toast(act, "检测中…")
        Thread(block, "check").start()
    }
}
