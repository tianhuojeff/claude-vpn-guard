package com.tianhuo.vpnguard

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

/**
 * 出口检测，对齐桌面端：Claude 域名的 cloudflare trace 必须是 loc=JP。
 * 两条路径都要过：① 经 FlClash 的 127.0.0.1:端口 代理（Claude App 实际走这条）；② 经默认网络（TUN）。
 */
object Checker {
    val HOSTS = listOf("claude.ai", "api.anthropic.com")

    data class Trace(val path: String, val host: String, val ip: String?, val loc: String?, val error: String?) {
        val ok get() = loc == "JP"
        override fun toString() = "$path $host → " + (error ?: "${loc ?: "?"} ${ip ?: ""}")
    }

    data class Report(val safe: Boolean, val reason: String, val traces: List<Trace>) {
        val exit get() = traces.firstOrNull { it.ok }?.let { "${it.loc} ${it.ip}" }
    }

    fun hasVpnNetwork(ctx: Context): Boolean {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        @Suppress("DEPRECATION")
        return cm.allNetworks.any { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
    }

    fun trace(path: String, host: String, proxy: Proxy): Trace = try {
        val c = URL("https://$host/cdn-cgi/trace").openConnection(proxy) as HttpURLConnection
        c.connectTimeout = 8000
        c.readTimeout = 8000
        c.useCaches = false
        c.setRequestProperty("Cache-Control", "no-cache")
        val body = c.inputStream.bufferedReader().use { it.readText() }
        c.disconnect()
        val kv = body.lines().mapNotNull { l -> l.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] } }.toMap()
        Trace(path, host, kv["ip"], kv["loc"], if (kv["loc"] == null) "无 loc 字段" else null)
    } catch (e: Exception) {
        Trace(path, host, null, null, e.javaClass.simpleName + (e.message?.let { ": " + it.take(60) } ?: ""))
    }

    fun check(ctx: Context): Report {
        if (!hasVpnNetwork(ctx)) return Report(false, "VPN 未连接", emptyList())
        // 兜底模式（root 和 Shizuku 都不在）读不到 VPN 归属，只靠下面的出口检测
        val fallback = !Shell.permitted()
        if (!fallback) {
            val owner = Firewall.vpnOwner(ctx) ?: return Report(false, "读不到 VPN 归属", emptyList())
            val want = Prefs.vpnPackage(ctx)
            if (owner != want) return Report(false, "VPN 不是 $want（当前 $owner）", emptyList())
        }

        val port = Prefs.proxyPort(ctx)
        val viaProxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port))
        val paths = listOf("代理:$port" to viaProxy, "TUN" to Proxy.NO_PROXY)
        var traces = paths.flatMap { (name, proxy) -> HOSTS.map { trace(name, it, proxy) } }
        // 超时、握手被断这类网络错误先重试一次（手机网络偶发抖动），查到的出口国家不重试
        if (traces.any { it.error != null }) {
            Thread.sleep(2000)
            traces = traces.map { t -> if (t.error == null) t else trace(t.path, t.host, paths.first { it.first == t.path }.second) }
        }
        // 判不安全：任何一条查到非日本出口（真泄漏）；或某条路径全部失败（这条路走不通，不能确认出口）。
        // 只是个别探测出错、同路径另一个域名已确认日本，不算异常：出错的连接本身没有流量出去。
        val leaks = traces.filter { it.error == null && !it.ok }
        val deadPaths = paths.map { it.first }.filter { p -> traces.none { it.path == p && it.ok } }
        val errs = traces.filter { it.error != null }
        val note = if (errs.isEmpty()) "" else "（个别探测出错已忽略：" + errs.joinToString("；") + "）"
        return when {
            leaks.isNotEmpty() -> Report(false, "出口不是日本：" + leaks.joinToString("；"), traces)
            deadPaths.isNotEmpty() -> Report(false, "出口异常：" + traces.filter { !it.ok }.joinToString("；"), traces)
            else -> Report(true, (if (fallback) "出口全部为日本（兜底模式，未核对 VPN 归属）" else "出口全部为日本") + note, traces)
        }
    }
}
