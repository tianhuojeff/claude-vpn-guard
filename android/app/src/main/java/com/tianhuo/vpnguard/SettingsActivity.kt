package com.tianhuo.vpnguard

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.widget.EditText
import android.widget.TextView

/** 设置：重走向导、受保护应用、端口、启停卫士、日志。 */
class SettingsActivity : Activity() {
    private lateinit var logView: TextView
    private lateinit var pkgEdit: EditText
    private lateinit var portEdit: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val ui = Ui(this)
        ui.text(22f, true).text = "设置"
        ui.button("重走设置向导") { startActivity(Intent(this, SetupActivity::class.java)) }

        val c = ui.card("参数")
        ui.text(13f, parent = c).text = "受保护应用包名（逗号分隔）"
        pkgEdit = EditText(this).apply { setText(Prefs.packages(this@SettingsActivity).joinToString(",")) }
        c.addView(pkgEdit)
        ui.text(13f, parent = c).text = "FlClash 混合代理端口"
        portEdit = EditText(this).apply {
            setText(Prefs.proxyPort(this@SettingsActivity).toString())
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        c.addView(portEdit)
        ui.button("保存", c) {
            Prefs.setPackages(this, pkgEdit.text.toString())
            portEdit.text.toString().toIntOrNull()?.takeIf { it in 1..65535 }?.let { Prefs.setProxyPort(this, it) }
            Actions.toast(this, "已保存")
        }

        ui.button("启动卫士") { Actions.startGuard(this) }
        ui.button("停止卫士并还原网络") { GuardService.stop(this) }

        ui.text(15f, true).text = "日志"
        logView = ui.text(12f).apply { setTextColor(Color.DKGRAY); typeface = Typeface.MONOSPACE }
        ui.show()
    }

    override fun onResume() {
        super.onResume()
        GuardService.onChange = { runOnUiThread { refresh() } }
        refresh()
    }

    override fun onPause() {
        GuardService.onChange = null
        super.onPause()
    }

    private fun refresh() {
        logView.text = synchronized(GuardService.log) { GuardService.log.joinToString("\n") }
    }
}
