package com.tianhuo.vpnguard

import android.content.Context

object Prefs {
    const val CLAUDE = "com.anthropic.claude"
    const val FLCLASH = "com.follow.clash"

    private fun sp(ctx: Context) = ctx.getSharedPreferences("guard", Context.MODE_PRIVATE)

    /** 卫士是否处于开启状态（开机自启依据）。 */
    fun enabled(ctx: Context) = sp(ctx).getBoolean("enabled", false)
    fun setEnabled(ctx: Context, v: Boolean) = sp(ctx).edit().putBoolean("enabled", v).apply()

    /** 受保护包名：默认只有 Claude。 */
    fun packages(ctx: Context): List<String> =
        sp(ctx).getString("packages", CLAUDE)!!.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }.distinct()
    fun setPackages(ctx: Context, v: String) = sp(ctx).edit().putString("packages", v).apply()

    /** 期望的 VPN 应用包名。 */
    fun vpnPackage(ctx: Context) = sp(ctx).getString("vpn", FLCLASH)!!

    fun proxyPort(ctx: Context) = sp(ctx).getInt("port", 7890)
    fun setProxyPort(ctx: Context, v: Int) = sp(ctx).edit().putInt("port", v).apply()

    /** 首次设置向导是否走完（没走完时打开 App 先进向导）。 */
    fun setupDone(ctx: Context) = sp(ctx).getBoolean("setup_done", false)
    fun setSetupDone(ctx: Context, v: Boolean) = sp(ctx).edit().putBoolean("setup_done", v).apply()

    /** 本机配置服务端口（只监听 127.0.0.1）。 */
    fun servePort(ctx: Context) = sp(ctx).getInt("serve_port", 17891)

    /** 本机配置地址里的随机令牌，防止本机其他应用猜到地址读走订阅节点。 */
    fun token(ctx: Context): String = sp(ctx).getString("token", null) ?: java.security.SecureRandom().let { r ->
        ByteArray(12).also { r.nextBytes(it) }.joinToString("") { "%02x".format(it) }
    }.also { sp(ctx).edit().putString("token", it).apply() }

    /** FlClash 最近一次拉取卫士配置的时间。 */
    fun lastServed(ctx: Context) = sp(ctx).getLong("last_served", 0)
    fun setLastServed(ctx: Context, v: Long) = sp(ctx).edit().putLong("last_served", v).apply()

    /** 最近一次保护性关闭（时间 + 原因），给看板显示。 */
    fun lastProtect(ctx: Context): Pair<Long, String>? =
        sp(ctx).getLong("protect_at", 0).takeIf { it > 0 }?.let { it to sp(ctx).getString("protect_why", "")!! }
    fun setLastProtect(ctx: Context, why: String) =
        sp(ctx).edit().putLong("protect_at", System.currentTimeMillis()).putString("protect_why", why).apply()

    /** 曾经被卫士加过拒绝位的包，停用时一并还原。 */
    fun touched(ctx: Context): Set<String> = sp(ctx).getStringSet("touched", emptySet())!!
    fun addTouched(ctx: Context, pkgs: Collection<String>) =
        sp(ctx).edit().putStringSet("touched", touched(ctx) + pkgs).apply()
    fun clearTouched(ctx: Context) = sp(ctx).edit().remove("touched").apply()
}
