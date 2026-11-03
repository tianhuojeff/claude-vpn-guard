package com.tianhuo.vpnguard

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.snakeyaml.engine.v2.api.Dump
import org.snakeyaml.engine.v2.api.DumpSettings
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import org.snakeyaml.engine.v2.common.FlowStyle
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * 订阅与总配置（B 方案）：
 * - 订阅链接只存在本机（应用私有存储），不写日志；
 * - 卫士自己下载各订阅，以第一个订阅（主订阅）为底，其他订阅只取日本节点并入；
 * - 生成 Japan Auto（url-test，只含日本节点）：日本节点全挂时连接失败，绝不回退其他国家或直连；
 * - Claude 的域名和包名规则排在最前面，全部走 Japan Auto；其他应用沿用主订阅的分组和规则。
 * FlClash 不拉取 proxy-providers（真机实测），所以节点直接写进配置。
 */
object Subs {
    const val GROUP = "Japan Auto"
    const val CHECK_HOST = "guard-check.vpnguard"
    val CLAUDE_DOMAINS = listOf("claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com")
    private const val TEST_URL = "https://www.gstatic.com/generate_204"
    private const val STALE_MS = 6 * 3600_000L
    private val JP = Regex("(?i)日本|JP|Japan|东京|大阪|Tokyo|Osaka|🇯🇵")
    private val EXCLUDE = Regex("(?i)剩余|流量|到期|过期|官网|重置|套餐")

    fun isJp(name: String) = JP.containsMatchIn(name) && !EXCLUDE.containsMatchIn(name)

    data class Sub(
        val id: String,
        var name: String,
        var url: String,
        var updated: Long = 0,
        var error: String? = null,
        var info: String? = null,
        var total: Int = 0,
        var jp: Int = 0,
    )

    @Volatile var busy = false

    private fun sp(ctx: Context) = ctx.getSharedPreferences("subs", Context.MODE_PRIVATE)

    fun list(ctx: Context): MutableList<Sub> {
        val arr = JSONArray(sp(ctx).getString("list", "[]"))
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Sub(
                o.getString("id"), o.getString("name"), o.getString("url"), o.optLong("updated"),
                o.optString("error").ifEmpty { null }, o.optString("info").ifEmpty { null }, o.optInt("total"), o.optInt("jp"),
            )
        }.toMutableList()
    }

    private fun save(ctx: Context, subs: List<Sub>) {
        val arr = JSONArray()
        subs.forEach {
            arr.put(
                JSONObject().put("id", it.id).put("name", it.name).put("url", it.url).put("updated", it.updated)
                    .put("error", it.error ?: "").put("info", it.info ?: "").put("total", it.total).put("jp", it.jp)
            )
        }
        sp(ctx).edit().putString("list", arr.toString()).apply()
    }

    fun add(ctx: Context, name: String, url: String) = synchronized(this) {
        save(ctx, list(ctx) + Sub(UUID.randomUUID().toString().take(8), name.ifBlank { "订阅" + (list(ctx).size + 1) }, url.trim()))
    }

    fun remove(ctx: Context, id: String) = synchronized(this) {
        save(ctx, list(ctx).filter { it.id != id })
        cache(ctx, id).delete()
    }

    /** 设为主订阅：其他应用沿用它的分组和规则。 */
    fun makeMain(ctx: Context, id: String) = synchronized(this) {
        val l = list(ctx)
        save(ctx, l.filter { it.id == id } + l.filter { it.id != id })
    }

    private fun cache(ctx: Context, id: String) = File(ctx.filesDir, "subs/$id.yaml")
    fun configFile(ctx: Context) = File(ctx.filesDir, "guard.yaml")
    fun lastBuild(ctx: Context) = sp(ctx).getLong("built", 0)
    fun localUrl(ctx: Context) = "http://127.0.0.1:${Prefs.servePort(ctx)}/guard/${Prefs.token(ctx)}.yaml"

    /** 上次生成时的节点归属：节点名 → 订阅名（看板用来显示当前节点属于哪个订阅）。 */
    fun owners(ctx: Context): Map<String, String> {
        val o = JSONObject(sp(ctx).getString("owners", "{}"))
        return o.keys().asSequence().associateWith { o.getString(it) }
    }

    fun stale(ctx: Context) = list(ctx).isNotEmpty() && System.currentTimeMillis() - lastBuild(ctx) > STALE_MS

    /** 下载全部订阅并重新生成总配置。在工作线程调用。返回一句结果。 */
    fun refreshAll(ctx: Context): String = synchronized(this) {
        busy = true
        try {
            val subs = list(ctx)
            if (subs.isEmpty()) return "还没有订阅"
            for (s in subs) {
                try {
                    val (body, info) = download(s.url)
                    parse(body) // 先确认是 Clash 配置再落盘
                    cache(ctx, s.id).apply { parentFile?.mkdirs() }.writeText(body)
                    s.info = info
                    s.error = null
                    s.updated = System.currentTimeMillis()
                } catch (e: Exception) {
                    s.error = e.javaClass.simpleName + (e.message?.let { ": " + it.take(80) } ?: "")
                }
            }
            save(ctx, subs)
            val r = build(ctx, subs)
            GuardService.addLog("订阅更新：$r")
            r
        } finally {
            busy = false
        }
    }

    fun refreshAsync(ctx: Context, done: ((String) -> Unit)? = null) {
        if (busy) return
        Thread({ val r = try { refreshAll(ctx) } catch (e: Exception) { "失败：" + e.message }; done?.invoke(r) }, "subs").start()
    }

    private fun download(url: String): Pair<String, String?> {
        var u = URL(url)
        repeat(5) {
            val c = u.openConnection() as HttpURLConnection
            c.connectTimeout = 15000
            c.readTimeout = 30000
            c.instanceFollowRedirects = false
            // 机场按 UA 返回 Clash 格式
            c.setRequestProperty("User-Agent", "clash.meta FlClash")
            val code = c.responseCode
            if (code in 300..399) {
                u = URL(u, c.getHeaderField("Location"))
                c.disconnect()
                return@repeat
            }
            if (code != 200) throw IllegalStateException("HTTP $code")
            val body = c.inputStream.bufferedReader().use { it.readText() }
            val info = c.getHeaderField("subscription-userinfo")?.let(::formatInfo)
            c.disconnect()
            return body to info
        }
        throw IllegalStateException("重定向过多")
    }

    private fun formatInfo(h: String): String? {
        val kv = h.split(';').mapNotNull { p -> p.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0].trim() to it[1].trim().toDoubleOrNull() } }.toMap()
        val used = (kv["upload"] ?: 0.0) + (kv["download"] ?: 0.0)
        val total = kv["total"] ?: return null
        val exp = kv["expire"]?.takeIf { it > 0 }?.let { SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date((it * 1000).toLong())) }
        return "${size(used)} / ${size(total)}" + (exp?.let { "，到期 $it" } ?: "")
    }

    private fun size(b: Double): String {
        val units = listOf("B", "KB", "MB", "GB", "TB")
        var v = b
        var i = 0
        while (v >= 1024 && i < units.size - 1) { v /= 1024; i++ }
        return "%.1f%s".format(v, units[i])
    }

    @Suppress("UNCHECKED_CAST")
    private fun parse(text: String): MutableMap<String, Any?> {
        val doc = Load(LoadSettings.builder().setCodePointLimit(64 * 1024 * 1024).build()).loadFromString(text)
        val m = doc as? MutableMap<String, Any?> ?: throw IllegalStateException("不是 Clash 配置")
        if (m["proxies"] !is List<*>) throw IllegalStateException("配置里没有 proxies")
        return m
    }

    @Suppress("UNCHECKED_CAST")
    private fun build(ctx: Context, subs: List<Sub>): String {
        val ready = subs.filter { cache(ctx, it.id).exists() }
        if (ready.isEmpty()) return "没有可用的订阅：" + subs.joinToString("；") { "${it.name} ${it.error ?: "未下载"}" }

        val owners = LinkedHashMap<String, String>()
        val jp = mutableListOf<String>()
        var base: MutableMap<String, Any?>? = null
        lateinit var proxies: MutableList<Any?>
        for (s in ready) {
            val m = try { parse(cache(ctx, s.id).readText()) } catch (e: Exception) { s.error = "缓存解析失败"; continue }
            val ps = (m["proxies"] as List<Any?>).filterIsInstance<MutableMap<String, Any?>>()
            s.total = ps.size
            s.jp = ps.count { isJp(it["name"].toString()) }
            if (base == null) {
                base = m
                proxies = (m["proxies"] as List<Any?>).toMutableList()
                ps.forEach { val n = it["name"].toString(); owners[n] = s.name; if (isJp(n)) jp += n }
            } else {
                // 其他订阅只并入日本节点；改名带上订阅名，避免与主订阅重名
                for (p in ps.filter { isJp(it["name"].toString()) }) {
                    var n = "${p["name"]}｜${s.name}"
                    while (owners.containsKey(n)) n += "'"
                    p["name"] = n
                    proxies += p
                    owners[n] = s.name
                    jp += n
                }
            }
        }
        val cfg = base ?: return "订阅都解析失败"
        cfg["proxies"] = proxies

        val groups = ((cfg["proxy-groups"] as? List<Any?>) ?: emptyList()).filterIsInstance<Map<String, Any?>>()
            .filter { it["name"] != GROUP }.toMutableList()
        groups.add(
            0, linkedMapOf(
                "name" to GROUP,
                "type" to "url-test",
                // 组里只有日本节点：全挂时连接直接失败，不会退到其他国家或直连。
                // 不把 REJECT 放进组：真机实测内核测速前先选第一个，REJECT 打头会把正常的 Claude 也拒掉。
                // 一个日本节点都没有时只放 REJECT。
                "proxies" to jp.ifEmpty { listOf("REJECT") },
                "url" to TEST_URL,
                "interval" to 300,
                "tolerance" to 50,
                "lazy" to false,
            )
        )
        cfg["proxy-groups"] = groups

        val rules = mutableListOf<Any?>("DOMAIN,$CHECK_HOST,DIRECT")
        CLAUDE_DOMAINS.forEach { rules += "DOMAIN-SUFFIX,$it,$GROUP" }
        rules += "PROCESS-NAME,${Prefs.CLAUDE},$GROUP"
        rules.addAll((cfg["rules"] as? List<Any?>) ?: listOf("MATCH,DIRECT"))
        cfg["rules"] = rules

        // 「FlClash 是否在用卫士配置」的探针：这个域名只在卫士配置里解析到本机
        val hosts = ((cfg["hosts"] as? Map<String, Any?>) ?: emptyMap()).toMutableMap()
        hosts[CHECK_HOST] = "127.0.0.1"
        cfg["hosts"] = hosts

        val text = "# 网关卫士生成，勿手改。主订阅：${ready.first().name}\n" +
            Dump(DumpSettings.builder().setDefaultFlowStyle(FlowStyle.BLOCK).setWidth(4096).setSplitLines(false).build()).dumpToString(cfg)
        val f = configFile(ctx)
        File(f.path + ".tmp").apply { writeText(text) }.renameTo(f)
        save(ctx, subs)
        sp(ctx).edit().putLong("built", System.currentTimeMillis()).putString("owners", JSONObject(owners as Map<*, *>).toString()).apply()
        return "已生成：${ready.size} 个订阅，日本节点 ${jp.size} 个" + if (jp.isEmpty()) "（没有日本节点，Claude 会被拒绝）" else ""
    }
}
