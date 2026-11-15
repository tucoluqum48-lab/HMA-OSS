package org.frknkrc44.hma_oss.zygote.hook

import android.content.pm.PackageManager
import android.os.Binder
import android.util.Log
import org.frknkrc44.hma_oss.zygote.util.ZLUtils.getArgument
import java.util.concurrent.atomic.AtomicLong

/**
 * 权限查询隔离（v7，带诊断日志）
 *
 * 判断：目标 uid 在隐藏表里且不是自查 → 返回 DENIED
 * 日志：uid>=10000 的调用逐条记录（限 400 条），用于定位检测方查询了什么
 */
class PermissionHook : IFrameworkHook {
    override val TAG = "PermissionHook"

    private val uidToPkg = HashMap<Int, String>()
    private val lastBuild = AtomicLong(0L)
    private val denyCount = AtomicLong(0L)
    private val logCount = AtomicLong(0L)

    private fun flog(msg: String) {
        try {
            java.io.File("/data/misc/permhook_v8.log")
                .appendText(System.currentTimeMillis().toString() + " " + msg + "\n")
        } catch (t: Throwable) {
        }
    }

    override fun load() {
        try {
            java.io.File("/data/misc/permhook_v8.log").writeText("loaded\n")
        } catch (t: Throwable) {
        }

        hook3("com.android.server.pm.permission.PermissionManagerService")
        hook2("com.android.server.pm.permission.PermissionManagerService")
        hook3("com.android.server.am.ActivityManagerService")
        hook3("android.permission.PermissionManager")
        flog("v8 install done")
    }

    private fun hook3(clazz: String) {
        try {
            hooker.apply {
                hookBefore(clazz, "checkPermission", 3) { methodName, frame, returnValue ->
                    val uid = frame.getArgument(2) as? Int ?: return@hookBefore
                    if (uid >= 10000) {
                        ensureMap()
                        val app = synchronized(uidToPkg) { uidToPkg[uid] }
                        val caller = try { Binder.getCallingUid() } catch (t: Throwable) { -1 }
                        val n = logCount.incrementAndGet()
                        if (n <= 400) {
                            flog("@$methodName uid=$uid inMap=${app != null} caller=$caller app=$app")
                        }
                        if (app != null && caller != uid) {
                            returnValue.result = PackageManager.PERMISSION_DENIED
                            val d = denyCount.incrementAndGet()
                            if (d <= 10 || d % 100L == 0L) flog("DENY #$d $app($uid)")
                        }
                    }
                }
            }
            flog("hooked3 $clazz")
        } catch (t: Throwable) {
            flog("hook3 $clazz FAILED: $t")
        }
    }

    private fun hook2(clazz: String) {
        try {
            hooker.apply {
                hookBefore(clazz, "checkUidPermission", 2) { methodName, frame, returnValue ->
                    val uid = frame.getArgument(1) as? Int ?: return@hookBefore
                    if (uid >= 10000) {
                        ensureMap()
                        val app = synchronized(uidToPkg) { uidToPkg[uid] }
                        val caller = try { Binder.getCallingUid() } catch (t: Throwable) { -1 }
                        val n = logCount.incrementAndGet()
                        if (n <= 400) {
                            flog("@$methodName uid=$uid inMap=${app != null} caller=$caller app=$app")
                        }
                        if (app != null && caller != uid) {
                            returnValue.result = PackageManager.PERMISSION_DENIED
                            val d = denyCount.incrementAndGet()
                            if (d <= 10 || d % 100L == 0L) flog("DENY #$d $app($uid)")
                        }
                    }
                }
            }
            flog("hooked2 $clazz")
        } catch (t: Throwable) {
            flog("hook2 $clazz FAILED: $t")
        }
    }

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
            flog("uid map: ${fresh.size} entries")
        } catch (t: Throwable) {
            flog("uid map failed: $t")
        }
    }
}
