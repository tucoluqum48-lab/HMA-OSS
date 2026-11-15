package org.frknkrc44.hma_oss.zygote.hook

import android.content.pm.PackageManager
import android.os.Binder
import org.frknkrc44.hma_oss.zygote.util.ZLUtils.getArgument
import java.io.File
import java.util.concurrent.atomic.AtomicLong

/**
 * 权限查询隔离（v9）
 *
 * 变更：
 *  · 只在 load() 建一次 uid 表，不再定期重建（v8 重建时拿到 0 条）
 *  · uid 解析改为直接读 /data/system/packages.list（system_server 可读，
 *    不经过任何 PMS 查询，避免被 HMA 自己的过滤影响）
 *  · 诊断全部写 /data/misc/permhook_v9.log
 */
class PermissionHook : IFrameworkHook {
    override val TAG = "PermissionHook"

    private val uidToPkg = HashMap<Int, String>()
    private val denyCount = AtomicLong(0L)
    private val logCount = AtomicLong(0L)

    private fun flog(msg: String) {
        try {
            File("/data/misc/permhook_v9.log")
                .appendText(System.currentTimeMillis().toString() + " " + msg + "\n")
        } catch (t: Throwable) {
        }
    }

    override fun load() {
        try {
            File("/data/misc/permhook_v9.log").writeText("loaded\n")
        } catch (t: Throwable) {
        }

        buildMapOnce()

        hook3("com.android.server.pm.permission.PermissionManagerService")
        hook2("com.android.server.pm.permission.PermissionManagerService")
        hook3("com.android.server.am.ActivityManagerService")
        hook3("android.permission.PermissionManager")
        flog("v9 install done, map=" + uidToPkg.size)
    }

    /** 从 HMA 配置取包名，用 packages.list 解析 uid */
    private fun buildMapOnce() {
        try {
            val names = HashSet<String>()
            config.templates.values.forEach { names.addAll(it.appList) }
            config.scope.values.forEach {
                names.addAll(it.extraAppList)
                names.addAll(it.extraOppositeAppList)
            }
            flog("names from config = ${names.size}")

            val pkgUid = HashMap<String, Int>()
            val f = File("/data/system/packages.list")
            if (f.canRead()) {
                f.forEachLine { line ->
                    val p = line.split(' ')
                    if (p.size >= 2) {
                        val u = p[1].toIntOrNull()
                        if (u != null) pkgUid[p[0]] = u
                    }
                }
                flog("packages.list parsed = ${pkgUid.size}")
            } else {
                flog("packages.list NOT readable")
            }

            var ok = 0
            var miss = 0
            names.forEach { n ->
                val u = pkgUid[n]
                if (u != null && u >= 10000) {
                    synchronized(uidToPkg) { uidToPkg[u] = n }
                    ok++
                } else {
                    miss++
                    if (miss <= 5) flog("unresolved: $n")
                }
            }
            flog("map built: ok=$ok miss=$miss")
        } catch (t: Throwable) {
            flog("buildMapOnce failed: $t")
        }
    }

    private fun hook3(clazz: String) {
        try {
            hooker.apply {
                hookBefore(clazz, "checkPermission", 3) { methodName, frame, returnValue ->
                    val uid = frame.getArgument(2) as? Int ?: return@hookBefore
                    if (uid >= 10000) {
                        val app = synchronized(uidToPkg) { uidToPkg[uid] }
                        val caller = try { Binder.getCallingUid() } catch (t: Throwable) { -1 }
                        val n = logCount.incrementAndGet()
                        if (n <= 400) flog("@$methodName uid=$uid inMap=${app != null} caller=$caller app=$app")
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
                        val app = synchronized(uidToPkg) { uidToPkg[uid] }
                        val caller = try { Binder.getCallingUid() } catch (t: Throwable) { -1 }
                        val n = logCount.incrementAndGet()
                        if (n <= 400) flog("@$methodName uid=$uid inMap=${app != null} caller=$caller app=$app")
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
}
