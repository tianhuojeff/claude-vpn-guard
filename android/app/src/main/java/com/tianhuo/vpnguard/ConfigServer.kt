package com.tianhuo.vpnguard

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.net.URLEncoder

/**
 * 只监听 127.0.0.1 的小 HTTP 服务，给 FlClash 订阅卫士生成的总配置。
 * 地址带随机令牌；令牌不对一律 404。
 */
object ConfigServer {
    @Volatile private var server: ServerSocket? = null

    fun ensure(ctx: Context) = synchronized(this) {
        if (server?.isClosed == false) return@synchronized
        val app = ctx.applicationContext
        try {
            val s = ServerSocket()
            s.reuseAddress = true
            s.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), Prefs.servePort(app)))
            server = s
            Thread({
                while (!s.isClosed) {
                    val c = try { s.accept() } catch (e: Exception) { break }
                    Thread({ handle(app, c) }, "serve").start()
                }
            }, "config-server").apply { isDaemon = true }.start()
        } catch (e: Exception) {
            GuardService.addLog("本机配置服务启动失败：" + e.message)
        }
    }

    private fun handle(ctx: Context, c: Socket) = c.use {
        c.soTimeout = 10000
        val r = c.getInputStream().bufferedReader()
        val path = r.readLine()?.split(' ')?.getOrNull(1) ?: return@use
        while (!r.readLine().isNullOrEmpty()) { /* 跳过请求头 */ }
        val token = Prefs.token(ctx)
        val out = c.getOutputStream()
        fun send(code: String, body: ByteArray, type: String, extra: String = "") {
            out.write(("HTTP/1.1 $code\r\nContent-Type: $type\r\nContent-Length: ${body.size}\r\n$extra" + "Connection: close\r\n\r\n").toByteArray())
            out.write(body)
            out.flush()
        }
        when (path) {
            "/guard/$token.yaml" -> {
                val f = Subs.configFile(ctx)
                if (!f.exists() && Subs.list(ctx).isNotEmpty()) Subs.refreshAll(ctx)
                if (!f.exists()) {
                    send("503 Service Unavailable", "还没有生成配置".toByteArray(), "text/plain; charset=utf-8")
                } else {
                    Prefs.setLastServed(ctx, System.currentTimeMillis())
                    GuardService.addLog("FlClash 拉取了卫士配置")
                    val name = URLEncoder.encode("网关卫士", "UTF-8").replace("+", "%20")
                    send("200 OK", f.readBytes(), "text/yaml; charset=utf-8", "Content-Disposition: attachment; filename*=UTF-8''$name\r\n")
                }
            }
            "/ping/$token" -> send("200 OK", "ok".toByteArray(), "text/plain")
            else -> send("404 Not Found", ByteArray(0), "text/plain")
        }
    }

    /**
     * FlClash 是否正在用卫士配置：经 FlClash 代理访问探针域名，
     * 只有卫士配置里这个域名才解析到本机（hosts + DIRECT 规则）。在工作线程调用。
     */
    fun flclashUsingGuard(ctx: Context): Boolean = try {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", Prefs.proxyPort(ctx)))
        val u = URL("http://${Subs.CHECK_HOST}:${Prefs.servePort(ctx)}/ping/${Prefs.token(ctx)}")
        val c = u.openConnection(proxy) as HttpURLConnection
        c.connectTimeout = 3000
        c.readTimeout = 3000
        val ok = c.responseCode == 200 && c.inputStream.bufferedReader().use { it.readText() } == "ok"
        c.disconnect()
        ok
    } catch (e: Exception) {
        false
    }

    /** FlClash 外部控制器（工具 → 常规 → 外部控制器，9090）里 Japan Auto 当前选中的节点；没开返回 null。 */
    fun currentNode(): String? = try {
        val c = URL("http://127.0.0.1:9090/proxies/" + URLEncoder.encode(Subs.GROUP, "UTF-8").replace("+", "%20")).openConnection(Proxy.NO_PROXY) as HttpURLConnection
        c.connectTimeout = 1500
        c.readTimeout = 1500
        val now = if (c.responseCode == 200) JSONObject(c.inputStream.bufferedReader().use { it.readText() }).optString("now").ifEmpty { null } else null
        c.disconnect()
        now
    } catch (e: Exception) {
        null
    }
}
