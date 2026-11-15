package org.frknkrc44.hma_oss.zygote.hook

import android.content.pm.PackageManager
import android.os.Binder
import android.util.Log
import icu.nullptr.hidemyapplist.common.Constants
import org.frknkrc44.hma_oss.zygote.util.ZLUtils.getArgument
import java.lang.reflect.Method
import java.util.concurrent.atomic.AtomicLong

/**
 * 权限查询隔离（v5）
 *
 * android.permission.PermissionManager.checkPermission 是客户端静态方法（跑在调用方进程），
 * 真正判定在 system_server 的 com.android.server.pm.permission.PermissionManagerService#checkPermission。
 * 本 hook 注册在 system_server，因此挂服务端方法。
 */
class PermissionHook : IFrameworkHook {
    override val TAG = "PermissionHook"

    private val uidToPkg = HashMap<Int, String>()
    private val lastBuild = AtomicLong(0L)
    private val denyCount = AtomicLong(0L)

    override fun load() {
        dumpCandidates("com.android.server.pm.permission.PermissionManagerService")
        dumpCandidates("com.android.server.am.ActivityManagerService")
        dumpCandidates("android.permission.PermissionManager")

        hookOne("com.android.server.pm.permission.PermissionManagerService")
        hookOne("com.android.server.am.ActivityManagerService")
        Log.i(TAG, "hook install finished")
    }

    private fun hookOne(clazz: String) {
        try {
            hooker.apply {
                hookBefore(clazz, "checkPermission", 3) { methodName, frame, returnValue ->
                    val targetUid = frame.getArgument(2) as? Int ?: return@hookBefore
                    if (targetUid < 10000) return@hookBefore

                    ensureMap()
                    val targetApp = synchronized(uidToPkg) { uidToPkg[targetUid] }
                        ?: return@hookBefore

                    val callingUid = Binder.getCallingUid()
                    if (callingUid == targetUid) return@hookBefore

                    returnValue.result = PackageManager.PERMISSION_DENIED
                    val n = denyCount.incrementAndGet()
                    if (n <= 5 || n % 100L == 0L) {
                        Log.i(TAG, "@$methodName DENY #$n target=$targetApp($targetUid) caller=$callingUid")
                    }
                }
            }
            Log.i(TAG, "hooked $clazz")
        } catch (t: Throwable) {
            Log.i(TAG, "hook $clazz failed: $t")
        }
    }

    private fun dumpCandidates(clazz: String) {
        try {
            val cls = Class.forName(clazz)
            val found: List<Method> = cls.declaredMethods.filter { it.name.contains("checkPermission") }
            if (found.isEmpty()) {
                Log.i(TAG, "$clazz: no checkPermission")
            } else {
                found.forEach { m -> Log.i(TAG, "$clazz -> (${m.parameterTypes.joinToString(",")})") }
            }
        } catch (t: Throwable) {
            Log.i(TAG, "$clazz: load failed")
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
            Log.i(TAG, "uid map: ${fresh.size} entries from ${names.size} names")
        } catch (t: Throwable) {
            Log.i(TAG, "uid map rebuild failed: $t")
        }
    }
}
