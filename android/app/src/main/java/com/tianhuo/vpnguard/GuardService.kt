package com.tianhuo.vpnguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import rikka.shizuku.Shizuku
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 常驻卫士，对齐桌面端：
 * - 启动即锁（fail-closed）：受保护应用先断网，连续 2 次检测安全才放行；
 * - 不安全：先锁网，再结束受保护应用，再通知；
 * - VPN 网络消失/变化时立即触发，不等轮询；
 * - 只动受保护包名的拒绝位，其他应用不受影响。
 */
class GuardService : Service() {
    companion object {
        private const val ACTION_START = "start"
        private const val ACTION_STOP = "stop"
        private const val ACTION_CHECK = "check"
        private const val CH_STATUS = "status"
        private const val CH_ALERT = "alert"
        private const val NOTI_STATUS = 1
        private const val NOTI_ALERT = 2
        private const val NOTI_UNPROTECTED = 3
        private const val SAFE_STREAK = 2
        private const val INTERVAL_SAFE = 30_000L
        private const val INTERVAL_LOCKED = 10_000L

        /** 所有防火墙状态变更都串行化。 */
        val stateLock = Any()

        @Volatile var running = false
        @Volatile var locked = true
        @Volatile var status = "未启动"
        @Volatile var exit: String? = null
        @Volatile var lastCheckAt = 0L
        val log = ArrayDeque<String>()
        @Volatile var onChange: (() -> Unit)? = null

        fun start(ctx: Context) = send(ctx, ACTION_START)
        fun stop(ctx: Context) = send(ctx, ACTION_STOP)
        fun checkNow(ctx: Context) = send(ctx, ACTION_CHECK)

        private fun send(ctx: Context, action: String) {
            ctx.startForegroundService(Intent(ctx, GuardService::class.java).setAction(action))
        }

        /** 放行。root 和 Shizuku 都不在时没有拒绝位可解，只解除逻辑锁定（兜底模式由 ClaudeBlocker 执行）。 */
        fun release(ctx: Context, pkgs: Collection<String>) =
            if (Shell.permitted()) Firewall.unlock(ctx, pkgs) else true

        fun addLog(msg: String) {
            val line = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date()) + " " + msg
            synchronized(log) {
                log.addFirst(line)
                while (log.size > 80) log.removeLast()
            }
            onChange?.invoke()
        }

        /**
         * 「启动 Claude」前调用（在工作线程）：检测一次，安全才放行；不安全时保持锁定。
         */
        fun checkAndUnlockNow(ctx: Context): Checker.Report {
            val r = Checker.check(ctx)
            synchronized(stateLock) {
                if (r.safe) {
                    val pkgs = Prefs.packages(ctx)
                    if (release(ctx, pkgs)) {
                        locked = false
                        exit = r.exit
                        status = "安全 · 出口 ${r.exit}"
                        addLog("手动检测通过，已放行：" + pkgs.joinToString())
                    }
                } else {
                    addLog("手动检测未通过：" + r.reason)
                }
            }
            return r
        }
    }

    private lateinit var worker: Handler
    private lateinit var thread: HandlerThread
    private var safeStreak = 0
    private var callback: ConnectivityManager.NetworkCallback? = null
    private val tickRunnable = Runnable { tick() }
    private val binderListener = Shizuku.OnBinderReceivedListener {
        if (running) worker.post { relock("Shizuku 已连接") }
    }
    private val binderDeadListener = Shizuku.OnBinderDeadListener {
        if (running) worker.post { relock("Shizuku 断开") }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        thread = HandlerThread("guard").also { it.start() }
        worker = Handler(thread.looper)
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_STATUS, "卫士状态", NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(CH_ALERT, "保护性断网提醒", NotificationManager.IMPORTANCE_HIGH))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTI_STATUS, buildStatus(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        when (intent?.action) {
            ACTION_STOP -> worker.post { shutdown() }
            ACTION_CHECK -> if (running) reschedule(0) else begin()
            else -> if (!running) begin() // START，或系统重建服务（intent 为 null）
        }
        return START_STICKY
    }

    private fun begin() {
        running = true
        Prefs.setEnabled(this, true)
        Shizuku.addBinderReceivedListenerSticky(binderListener, Handler(Looper.getMainLooper()))
        Shizuku.addBinderDeadListener(binderDeadListener, Handler(Looper.getMainLooper()))
        registerNetworkCallback()
        ConfigServer.ensure(this)
        worker.post { relock("卫士启动") }
    }

    /** 无条件上锁（不结束应用），然后尽快检测。 */
    private fun relock(why: String) {
        Shell.probeRoot()
        synchronized(stateLock) {
            val pkgs = Prefs.packages(this)
            safeStreak = 0
            locked = true
            if (Firewall.lock(this, pkgs)) {
                Prefs.addTouched(this, pkgs)
                getSystemService(NotificationManager::class.java).cancel(NOTI_UNPROTECTED)
                setStatus("已锁定（$why），检测中")
            } else {
                setStatus(if (ClaudeBlocker.enabled()) "兜底模式（没有 root，Shizuku 未运行），检测中" else "无法上锁：没有 root，Shizuku 未运行，兜底也没开")
                warnUnprotected()
                // 断不了网就把它结束掉（开机时 Claude 可能已被推送拉起在后台）
                ClaudeBlocker.stopApps(pkgs)
            }
            ClaudeBlocker.kickIfForeground()
        }
        reschedule(500)
    }

    private fun reschedule(delay: Long) {
        worker.removeCallbacks(tickRunnable)
        worker.postDelayed(tickRunnable, delay)
    }

    private fun tick() {
        if (!running) return
        Shell.probeRoot()
        if (Subs.stale(this)) Subs.refreshAsync(this)
        val r = Checker.check(this)
        lastCheckAt = System.currentTimeMillis()
        synchronized(stateLock) {
            val pkgs = Prefs.packages(this)
            if (r.safe) {
                if (r.reason.contains("个别探测出错")) addLog(r.reason)
                safeStreak++
                exit = r.exit
                if (locked && safeStreak >= SAFE_STREAK && release(this, pkgs)) {
                    locked = false
                    addLog("连续 $SAFE_STREAK 次安全，已放行：" + pkgs.joinToString())
                }
                setStatus(if (locked) "检测通过 $safeStreak/$SAFE_STREAK，仍锁定" else "安全 · 出口 ${r.exit}")
            } else {
                safeStreak = 0
                exit = null
                if (!locked) {
                    protect(r.reason)
                } else {
                    // 拒绝位可能被清掉（重启、其他程序改动），补锁
                    if (pkgs.any { Firewall.state(this, it) != "deny" }) Firewall.lock(this, pkgs)
                    setStatus("锁定中：" + r.reason)
                }
            }
        }
        reschedule(if (locked) INTERVAL_LOCKED else INTERVAL_SAFE)
    }

    /** 先锁定后结束，与桌面端一致。调用方持有 stateLock。 */
    private fun protect(reason: String) {
        val pkgs = Prefs.packages(this)
        val ok = Firewall.lock(this, pkgs)
        Prefs.addTouched(this, pkgs)
        locked = true
        Prefs.setLastProtect(this, reason)
        if (Shell.permitted()) Firewall.forceStop(this, pkgs) else ClaudeBlocker.stopApps(pkgs)
        ClaudeBlocker.kickIfForeground()
        setStatus("已保护性断网：$reason")
        alert(
            when {
                ok -> "已为 ${pkgs.joinToString()} 断网并关闭：$reason"
                ClaudeBlocker.enabled() -> "没有 root、Shizuku 不可用，没法断网，已结束 Claude（含后台），恢复前打不开：$reason"
                else -> "没有 root、Shizuku 不可用、兜底也没开，Claude 没有保护，请不要使用：$reason"
            }
        )
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) = onNetChange("VPN 网络断开")
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = onNetChange("VPN 网络变化")
        }
        val req = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(req, cb)
        callback = cb
    }

    private fun onNetChange(why: String) {
        worker.post {
            if (!running) return@post
            if (!Checker.hasVpnNetwork(this)) {
                synchronized(stateLock) {
                    safeStreak = 0
                    if (!locked) protect(why)
                }
            }
            reschedule(300)
        }
    }

    private fun unregister() {
        callback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        callback = null
        Shizuku.removeBinderReceivedListener(binderListener)
        Shizuku.removeBinderDeadListener(binderDeadListener)
    }

    private fun shutdown() {
        running = false
        worker.removeCallbacks(tickRunnable)
        unregister()
        synchronized(stateLock) {
            val pkgs = Prefs.touched(this) + Prefs.packages(this)
            val ok = Firewall.restore(this, pkgs)
            if (ok) Prefs.clearTouched(this)
            Prefs.setEnabled(this, false)
            getSystemService(NotificationManager::class.java).cancel(NOTI_UNPROTECTED)
            locked = false
            exit = null
            setStatus(if (ok) "已停止，网络已还原" else "已停止，但还原失败：请启动 Shizuku 后再点一次「停止卫士并还原」")
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        running = false
        unregister()
        thread.quitSafely()
        super.onDestroy()
    }

    private fun setStatus(s: String) {
        if (s != status) addLog(s)
        status = s
        if (running) getSystemService(NotificationManager::class.java).notify(NOTI_STATUS, buildStatus())
        onChange?.invoke()
    }

    private fun openApp() = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
    )

    private fun buildStatus(): Notification = Notification.Builder(this, CH_STATUS)
        .setSmallIcon(R.drawable.ic_guard)
        .setContentTitle(if (locked) "网关卫士 · 已锁定" else "网关卫士 · 安全")
        .setContentText(status)
        .setOngoing(true)
        .setContentIntent(openApp())
        .build()

    /** 开机后 Shizuku 没起来时：常驻提醒，点一下打开 Shizuku；上锁成功后自动消失。 */
    private fun warnUnprotected() {
        val shizuku = packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api")
        val tap = if (shizuku != null) PendingIntent.getActivity(this, 1, shizuku, PendingIntent.FLAG_IMMUTABLE) else openApp()
        val fallback = ClaudeBlocker.enabled()
        val text = if (fallback) "Shizuku 没有运行，卫士已切到兜底模式：出口检测通过前 Claude 打不开。连上 Wi-Fi 后点这里启动 Shizuku，恢复断网级保护。"
        else "Shizuku 没有运行，兜底模式也没开，卫士无法保护 Claude。请先启动 Shizuku，再打开 Claude。"
        getSystemService(NotificationManager::class.java).notify(
            NOTI_UNPROTECTED,
            Notification.Builder(this, CH_ALERT)
                .setSmallIcon(R.drawable.ic_guard)
                .setContentTitle(if (fallback) "网关卫士 · 兜底模式" else "Claude 未受保护")
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setOngoing(true)
                .setContentIntent(tap)
                .build()
        )
    }

    private fun alert(text: String) {
        getSystemService(NotificationManager::class.java).notify(
            NOTI_ALERT,
            Notification.Builder(this, CH_ALERT)
                .setSmallIcon(R.drawable.ic_guard)
                .setContentTitle("网关卫士：保护性断网")
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setAutoCancel(true)
                .setContentIntent(openApp())
                .build()
        )
    }
}
