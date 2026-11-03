package com.tianhuo.vpnguard;

// 在 Shizuku 的 shell（uid 2000）进程中执行命令
interface IShell {
    void destroy() = 16777114;
    String exec(String cmd) = 1;
}
