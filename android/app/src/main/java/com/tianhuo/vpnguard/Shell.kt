package com.tianhuo.vpnguard

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import rikka.shizuku.Shizuku
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * 拿 shell 权限执行命令：有 root（su）就用 root，开机即可用、不依赖 Wi-Fi；没有 root 再走 Shizuku。
 * 除 permitted()/rooted 外都是阻塞的，只能在工作线程调用。
 */
object Shell {
    data class Result(val code: Int, val out: String) {
        val ok get() = code == 0
    }

    @Volatile private var svc: IShell? = null
    @Volatile private var latch = CountDownLatch(1)

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder?) {
            if (binder != null && binder.pingBinder()) {
                svc = IShell.Stub.asInterface(binder)
                latch.countDown()
            }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            svc = null
        }
    }

    fun shizukuRunning(): Boolean = try {
        Shizuku.pingBinder()
    } catch (_: Throwable) {
        false
    }

    /** su 已确认可用（缓存值，不阻塞）。 */
    @Volatile var rooted = false
        private set
    @Volatile private var lastProbe = 0L

    /** 探测 su，最多每 60 秒真正执行一次（没装 su 时立即失败；Magisk 首次会弹授权框）。 */
    fun probeRoot(): Boolean {
        if (rooted) return true
        val now = System.currentTimeMillis()
        if (now - lastProbe < 60_000) return false
        lastProbe = now
        rooted = su("id")?.let { it.ok && it.out.contains("uid=0") } == true
        return rooted
    }

    fun shizukuPermitted(): Boolean = shizukuRunning() && !Shizuku.isPreV11() &&
        Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED

    /** 能执行特权命令（root 或 Shizuku）。 */
    fun permitted(): Boolean = rooted || shizukuPermitted()

    private fun su(cmd: String): Result? = try {
        val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        if (!p.waitFor(15, TimeUnit.SECONDS)) {
            p.destroyForcibly()
            Result(124, out.trim())
        } else {
            Result(p.exitValue(), out.trim())
        }
    } catch (_: Exception) {
        null
    }

    private fun args(ctx: Context) = Shizuku.UserServiceArgs(
        ComponentName(ctx.packageName, ShellService::class.java.name)
    ).daemon(false).processNameSuffix("shell").debuggable(BuildConfig.DEBUG).version(BuildConfig.VERSION_CODE)

    private fun ensure(ctx: Context): IShell? {
        svc?.let { if (it.asBinder().pingBinder()) return it }
        svc = null
        if (!shizukuPermitted()) return null
        val l = CountDownLatch(1)
        latch = l
        Handler(Looper.getMainLooper()).post {
            try {
                Shizuku.bindUserService(args(ctx), conn)
            } catch (_: Throwable) {
            }
        }
        l.await(10, TimeUnit.SECONDS)
        return svc
    }

    /** 执行命令；拿不到 shell 时返回 null。 */
    fun run(ctx: Context, cmd: String): Result? {
        if (rooted) {
            su(cmd)?.let { return it }
            rooted = false // su 失效（被收回授权等），退回 Shizuku
        }
        val s = ensure(ctx) ?: return null
        return try {
            val raw = s.exec(cmd)
            val nl = raw.indexOf('\n')
            Result(raw.substring(0, nl).toIntOrNull() ?: -1, raw.substring(nl + 1).trim())
        } catch (_: Exception) {
            svc = null
            null
        }
    }
}
