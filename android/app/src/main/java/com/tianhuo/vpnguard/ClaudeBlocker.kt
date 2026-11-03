package com.tianhuo.vpnguard

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Toast

/**
 * 兜底模式（无障碍）：没有 root、Shizuku 也不在时（比如开机只有流量），卫士没法给 Claude 断网，
 * 就在 Claude 被锁定期间把它退回桌面，并到系统「应用信息」页点「结束运行」把后台也结束掉。
 * 平时只看前台应用的包名；只有结束应用那几秒会读系统设置页上的按钮。
 * root 或 Shizuku 在时也生效：锁定期间打开 Claude 会被退回桌面，和桌面端「只在安全时启动 Claude」一致。
 */
class ClaudeBlocker : AccessibilityService() {
    companion object {
        @Volatile private var instance: ClaudeBlocker? = null
        @Volatile private var foreground: String? = null
        private val main = Handler(Looper.getMainLooper())

        /** 只在这些系统页面里点按钮，防止误点别的应用。 */
        private val SETTINGS_PKGS = setOf("com.miui.securitycenter", "com.android.settings")
        private val STOP_TEXTS = listOf("结束运行", "强行停止", "Force stop")
        private val OK_TEXTS = listOf("确定", "OK")
        private const val KILL_TIMEOUT = 6000L

        fun enabled() = instance != null

        /** 卫士判定不安全时调用：Claude 正在前台就退回桌面。 */
        fun kickIfForeground() {
            val s = instance ?: return
            val fg = foreground ?: return
            if (fg in Prefs.packages(s)) main.post { s.kick() }
        }

        /** root 和 Shizuku 都不在时代替 am force-stop：逐个打开应用信息页点「结束运行」。 */
        fun stopApps(pkgs: Collection<String>) {
            val s = instance ?: return
            main.post { s.enqueue(pkgs) }
        }

        /** 卫士开着且处于锁定（或卫士应该开着但还没起来）时，受保护应用不能停在前台。 */
        fun blocked(ctx: Context) = Prefs.enabled(ctx) && (!GuardService.running || GuardService.locked)
    }

    // 以下状态只在主线程读写
    private val queue = ArrayDeque<String>()
    private var target: String? = null
    private var confirming = false
    private val giveUp = Runnable { finishKill() }

    override fun onServiceConnected() {
        instance = this
        // 开机时无障碍服务会被系统拉起；卫士应该开着却没起来时顺手拉起
        if (Prefs.enabled(this) && !GuardService.running) {
            try {
                GuardService.start(this)
            } catch (_: Exception) {
            }
        }
    }

    override fun onAccessibilityEvent(e: AccessibilityEvent) {
        val pkg = e.packageName?.toString() ?: return
        if (target != null) {
            if (pkg in SETTINGS_PKGS) drive()
            return
        }
        if (e.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        if (pkg == "com.android.systemui") return
        foreground = pkg
        if (pkg in Prefs.packages(this) && blocked(this)) kick()
    }

    private fun kick() {
        performGlobalAction(GLOBAL_ACTION_HOME)
        Toast.makeText(this, "网关卫士：出口还没通过检测，Claude 暂不可用", Toast.LENGTH_SHORT).show()
        if (!Shell.permitted()) foreground?.let { if (it in Prefs.packages(this)) enqueue(listOf(it)) }
    }

    private fun enqueue(pkgs: Collection<String>) {
        for (p in pkgs) if (p != target && p !in queue) queue.addLast(p)
        if (target == null) nextKill()
    }

    private fun nextKill() {
        val p = queue.removeFirstOrNull() ?: return
        target = p
        confirming = false
        try {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$p"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            )
        } catch (_: Exception) {
            finishKill()
            return
        }
        main.postDelayed(giveUp, KILL_TIMEOUT)
        main.postDelayed({ drive() }, 800)
    }

    /** 在应用信息页点「结束运行」，再在确认框点「确定」。按钮是灰的说明应用没在运行。 */
    private fun drive() {
        if (target == null) return
        val root = rootInActiveWindow ?: return
        if (root.packageName?.toString() !in SETTINGS_PKGS) return
        if (!confirming) {
            val btn = find(root, STOP_TEXTS) ?: return
            if (!btn.isEnabled || !click(btn)) {
                finishKill()
                return
            }
            confirming = true
        } else {
            val ok = root.findAccessibilityNodeInfosByViewId("android:id/button1").firstOrNull()
                ?: find(root, OK_TEXTS) ?: return
            click(ok)
            finishKill()
        }
    }

    private fun find(root: AccessibilityNodeInfo, texts: List<String>): AccessibilityNodeInfo? {
        for (t in texts) {
            root.findAccessibilityNodeInfosByText(t).firstOrNull { it.text?.toString() == t }?.let { return it }
        }
        return null
    }

    /** 文字本身常常不可点，往上找可点的父节点。 */
    private fun click(node: AccessibilityNodeInfo): Boolean {
        var n: AccessibilityNodeInfo? = node
        while (n != null) {
            if (n.isClickable) return n.isEnabled && n.performAction(AccessibilityNodeInfo.ACTION_CLICK)
            n = n.parent
        }
        return false
    }

    private fun finishKill() {
        main.removeCallbacks(giveUp)
        target = null
        confirming = false
        if (queue.isEmpty()) performGlobalAction(GLOBAL_ACTION_HOME) else nextKill()
    }

    override fun onInterrupt() {}

    override fun onUnbind(intent: Intent?): Boolean {
        instance = null
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        instance = null
        super.onDestroy()
    }
}
