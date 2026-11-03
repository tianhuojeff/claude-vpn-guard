package com.tianhuo.vpnguard

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout

/** 订阅与节点：导入/删除/设为主订阅、全部更新、按订阅列出日本节点。链接只显示域名。 */
class SubsActivity : Activity() {
    private lateinit var ui: Ui
    private lateinit var listBox: LinearLayout
    private lateinit var nodeBox: LinearLayout
    @Volatile private var node: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ui = Ui(this)
        ui.text(22f, true).text = "订阅与节点"
        ui.text(13f).text = "第一个（★）是主订阅：其他应用沿用它的分组和规则。其余订阅只并入日本节点给 Claude 用。"

        val add = ui.card("添加订阅")
        val nameEdit = EditText(this).apply { hint = "名称（如 Kitty）"; isSingleLine = true }
        val urlEdit = EditText(this).apply {
            hint = "订阅链接（只存本机）"
            isSingleLine = true
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        }
        add.addView(nameEdit)
        add.addView(urlEdit)
        ui.button("添加并更新", add) {
            val url = urlEdit.text.toString().trim()
            if (!url.startsWith("http://") && !url.startsWith("https://")) return@button Actions.toast(this, "链接要以 http(s):// 开头")
            Subs.add(this, nameEdit.text.toString().trim(), url)
            nameEdit.setText("")
            urlEdit.setText("")
            update()
        }

        listBox = ui.card("已导入")
        ui.button("全部更新并重新生成配置") { update() }
        ui.button("导入到 FlClash") { Actions.importToFlClash(this) }
        nodeBox = ui.card("Claude 可用的日本节点（Japan Auto）")
        ui.show()
    }

    override fun onResume() {
        super.onResume()
        render()
        Thread { node = ConfigServer.currentNode(); runOnUiThread { render() } }.start()
    }

    private fun update() {
        Actions.toast(this, "更新中…")
        Subs.refreshAsync(this) { r -> Actions.toast(this, r); runOnUiThread { render() } }
    }

    private fun host(url: String) = Uri.parse(url).host ?: "?"

    private fun render() {
        listBox.removeViews(1, listBox.childCount - 1)
        val subs = Subs.list(this)
        if (subs.isEmpty()) ui.text(13f, parent = listBox).text = "还没有订阅"
        subs.forEachIndexed { i, s ->
            ui.text(14f, true, listBox).text = (if (i == 0) "★ " else "· ") + s.name
            ui.text(12f, parent = listBox).text = listOfNotNull(
                "来源：" + host(s.url),
                "节点 ${s.total}，日本 ${s.jp}",
                s.info,
                "更新：" + Actions.time(s.updated),
                s.error?.let { "更新失败：$it" },
            ).joinToString("\n")
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            listBox.addView(row)
            if (i > 0) ui.button("设为主订阅", row) { Subs.makeMain(this, s.id); update() }
            ui.button("删除", row) {
                AlertDialog.Builder(this).setMessage("删除订阅「${s.name}」？").setNegativeButton("取消", null)
                    .setPositiveButton("删除") { _, _ -> Subs.remove(this, s.id); update() }.show()
            }
        }

        nodeBox.removeViews(1, nodeBox.childCount - 1)
        val jp = Subs.owners(this).filterKeys { Subs.isJp(it) }
        if (jp.isEmpty()) ui.text(13f, parent = nodeBox).text = "没有日本节点：Claude 会被拒绝连接"
        jp.entries.groupBy({ it.value }, { it.key }).forEach { (sub, nodes) ->
            ui.text(13f, true, nodeBox).text = "$sub（${nodes.size}）"
            for (n in nodes) ui.text(12f, parent = nodeBox).apply {
                text = (if (n == node) "▶ " else "　") + n
                if (n == node) { setTextColor(Actions.GREEN); setTypeface(typeface, Typeface.BOLD) }
            }
        }
        node?.let { ui.text(12f, parent = nodeBox).text = "当前：" + (if (it == "REJECT") "REJECT（没有日本节点）" else it) }
    }
}
