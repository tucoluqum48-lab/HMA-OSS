package org.frknkrc44.hma_oss.zygote.hook

import android.content.pm.PackageManager
import android.os.Binder
import icu.nullptr.hidemyapplist.common.Constants
import org.frknkrc44.hma_oss.zygote.util.Logcat.logD
import org.frknkrc44.hma_oss.zygote.util.ZLUtils.getArgument
import java.lang.reflect.Method
import java.util.concurrent.atomic.AtomicLong

/**
 * 权限查询隔离（v3）：
 * 被隐藏的包，checkPermission(perm, pid, uid) 也应返回 DENIED，
 * 否则「包名查不到 / 权限却有」就是一条可枚举的泄漏。
 *
 * 与 v2 的区别：不再依赖调用方包名解析，只看被查询 uid 是否在隐藏表里。
 * 唯一例外是「自己查自己」（hidden app 自查权限必须正常）。
 */
class PermissionHook : IFrameworkHook {
    override val TAG = "PermissionHook"

    private val uidToPkg = HashMap<Int, String>()
    private val lastBuild = AtomicLong(0L)
    private val denyCount = AtomicLong(0L)

    override fun load() {
        dumpCheckPermissionMethods()

        hooker.apply {
            hookBefore(
                "android.permission.PermissionManager",
                "checkPermission",
                3,
            ) { methodName, frame, returnValue ->
                val targetUid = frame.getArgument(2) as? Int ?: return@hookBefore
                if (targetUid < 10000) return@hookBefore

                ensureMap()

                val targetApp = synchronized(uidToPkg) { uidToPkg[targetUid] } ?: return@hookBefore

                val callingUid = Binder.getCallingUid()
                if (callingUid == targetUid) return@hookBefore          // 自查放行
                if (callingUid == Constants.UID_SYSTEM) {
                    // system_server 内部调用（clearCallingIdentity 之后）：同样拦截
                }

                returnValue.result = PackageManager.PERMISSION_DENIED
                val n = denyCount.incrementAndGet()
                if (n <= 5 || n % 50L == 0L) {
                    logD(TAG) { "@$methodName DENY #$n target=$targetApp($targetUid) caller=$callingUid" }
                }
            }
        }
        logD(TAG) { "checkPermission hook installed" }
    }

    /** 把类里所有 checkPermission 方法打出来，确认签名是否匹配 */
    private fun dumpCheckPermissionMethods() {
        try {
            val cls = Class.forName("android.permission.PermissionManager")
            val ms: Array<Method> = cls.declaredMethods
            val found = ms.filter { it.name.contains("checkPermission") }
            if (found.isEmpty()) {
                logD(TAG) { "NO checkPermission method on PermissionManager!" }
            } else {
                found.forEach { m ->
                    logD(TAG) { "candidate: ${m.parameterTypes.joinToString(",")} -> ${m.returnType}" }
                }
            }
        } catch (t: Throwable) {
            logD(TAG, t) { "dump methods failed" }
        }
    }

    /** 每 60 秒最多重建一次（配置可能被改） */
    private fun ensureMap() {
        val now = System.currentTimeMillis()
        val last = lastBuild.get()
        if (now - last < 60_000L) return
        if (!lastBuild.compareAndSet(last, now)) return

        try {
            val names = HashSet<String>()
            config.templates.values.forEach { names.addAll(it.appList) }
            config.scope.values.forEach {
                names.addAll(it.extraAppList)
                names.addAll(it.extraOppositeAppList)
            }

            val fresh = HashMap<Int, String>(names.size)
            names.forEach { p ->
                try {
                    val u = pms.getPackageUid(p, 0L, 0)
                    if (u >= 10000) fresh[u] = p
                } catch (ignored: Throwable) {
                }
            }
            synchronized(uidToPkg) {
                uidToPkg.clear()
                uidToPkg.putAll(fresh)
            }
            logD(TAG) { "uid map: ${fresh.size} entries from ${names.size} names" }
        } catch (t: Throwable) {
            logD(TAG, t) { "uid map rebuild failed" }
        }
    }
}
