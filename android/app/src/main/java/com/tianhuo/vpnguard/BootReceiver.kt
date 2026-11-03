package com.tianhuo.vpnguard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** 开机或升级后：卫士开着就重新上锁（重启后内核拒绝位会被清空）。 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (Prefs.enabled(ctx)) GuardService.start(ctx)
    }
}
