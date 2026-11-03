package com.tianhuo.vpnguard

import android.content.Context
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

/** Shizuku UserService：运行在 shell（uid 2000）进程，执行 cmd connectivity / am 等命令。 */
class ShellService : IShell.Stub {
    constructor()
    constructor(@Suppress("UNUSED_PARAMETER") context: Context)

    override fun destroy() {
        exitProcess(0)
    }

    /** 返回 "退出码\n输出"。 */
    override fun exec(cmd: String): String {
        return try {
            val p = ProcessBuilder("sh", "-c", cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            if (!p.waitFor(15, TimeUnit.SECONDS)) {
                p.destroyForcibly()
                "124\n$out"
            } else {
                "${p.exitValue()}\n$out"
            }
        } catch (e: Exception) {
            "-1\n${e.javaClass.simpleName}: ${e.message}"
        }
    }
}
