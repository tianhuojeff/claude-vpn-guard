package com.tianhuo.vpnguard

import android.content.Context
import android.os.Build

/**
 * 按应用断网：Android 13+ 用 eBPF 防火墙链 FIREWALL_CHAIN_OEM_DENY_3。
 * 只有被打上拒绝位的包会断网（连 127.0.0.1 回环也断），其他应用不受影响。
 *
 * Android 12 及以下（例如鸿蒙 4 平板）没有这条链，改用「暂停应用」：结束进程并 pm suspend，
 * 暂停期间应用打不开、不能在后台运行，也就没有流量；解除时 pm unsuspend。
 * 暂停状态重启后仍保留（重启默认锁定，等卫士确认安全再解除）。
 */
object Firewall {
    private fun q(p: String) = p.filter { it.isLetterOrDigit() || it == '.' || it == '_' }

    /** 系统没有按应用断网的防火墙链，只能用暂停应用。 */
    val suspendMode get() = Build.VERSION.SDK_INT < 33

    /** 给这些包断网。返回是否全部确认为 deny。 */
    fun lock(ctx: Context, pkgs: Collection<String>): Boolean {
        if (suspendMode) {
            Shell.run(ctx, pkgs.joinToString("; ") { "am force-stop ${q(it)}; pm suspend ${q(it)}" }) ?: return false
            return pkgs.all { state(ctx, it) == "deny" }
        }
        val cmd = buildString {
            append("cmd connectivity set-chain3-enabled true")
            for (p in pkgs) append("; cmd connectivity set-package-networking-enabled false ").append(q(p))
        }
        Shell.run(ctx, cmd) ?: return false
        return pkgs.all { state(ctx, it) == "deny" } && chainEnabled(ctx) == true
    }

    fun forceStop(ctx: Context, pkgs: Collection<String>) {
        Shell.run(ctx, pkgs.joinToString("; ") { "am force-stop " + q(it) })
    }

    /** 解除这些包的拒绝位（链保持开启，其他包没有拒绝位，不受影响）。 */
    fun unlock(ctx: Context, pkgs: Collection<String>): Boolean {
        if (suspendMode) {
            Shell.run(ctx, pkgs.joinToString("; ") { "pm unsuspend " + q(it) }) ?: return false
            return pkgs.all { state(ctx, it) == "allow" }
        }
        Shell.run(ctx, pkgs.joinToString("; ") { "cmd connectivity set-package-networking-enabled true " + q(it) })
            ?: return false
        return pkgs.all { state(ctx, it) == "allow" }
    }

    /** 停用卫士：解除拒绝位并把链还原为关闭（与初始状态一致）。 */
    fun restore(ctx: Context, pkgs: Collection<String>): Boolean {
        val ok = unlock(ctx, pkgs)
        if (suspendMode) return ok
        Shell.run(ctx, "cmd connectivity set-chain3-enabled false")
        return ok && chainEnabled(ctx) == false
    }

    /** "allow" / "deny" / null（拿不到 shell）。 */
    fun state(ctx: Context, pkg: String): String? {
        if (suspendMode) {
            val d = Shell.run(ctx, "dumpsys package ${q(pkg)} | grep -m1 ' suspended='") ?: return null
            return when {
                d.out.contains("suspended=true") -> "deny"
                d.out.contains("suspended=false") -> "allow"
                else -> null
            }
        }
        val r = Shell.run(ctx, "cmd connectivity get-package-networking-enabled " + q(pkg)) ?: return null
        return r.out.substringAfterLast(':').trim().takeIf { it == "allow" || it == "deny" }
    }

    fun chainEnabled(ctx: Context): Boolean? {
        val r = Shell.run(ctx, "cmd connectivity get-chain3-enabled") ?: return null
        val o = r.out.lowercase()
        return when {
            o.contains("true") || o.endsWith("enabled") && !o.contains("disabled") -> true
            o.contains("false") || o.contains("disabled") -> false
            else -> null
        }
    }

    /** 当前 VPN 的所属包名（dumpsys vpn_management），没有 VPN 时为 null。 */
    fun vpnOwner(ctx: Context): String? {
        val r = Shell.run(ctx, "dumpsys vpn_management") ?: return null
        val lines = r.out.lines()
        for ((i, line) in lines.withIndex()) {
            val t = line.trim()
            if (!t.startsWith("Active package name:")) continue
            val pkg = t.substringAfter(':').trim()
            if (pkg.startsWith("[")) continue
            // 后面几行里的 NetworkCapabilities 带 INTERNET，说明这个 VPN 正在承载流量
            val caps = lines.subList(i + 1, minOf(i + 5, lines.size)).map { it.trim() }
                .firstOrNull { it.startsWith("NetworkCapabilities:") }.orEmpty()
            if (caps.contains("Transports: VPN") && caps.contains("INTERNET")) return pkg
        }
        // Android 12 的格式只有「用户号: 包名」，没 VPN 时是 [Legacy VPN]
        for (line in lines) {
            val m = Regex("""^\s*\d+: (\S+)$""").find(line) ?: continue
            val pkg = m.groupValues[1]
            if (!pkg.startsWith("[")) return pkg
        }
        return null
    }
}
