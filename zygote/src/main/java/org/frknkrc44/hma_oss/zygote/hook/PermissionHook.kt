package org.frknkrc44.hma_oss.zygote.hook

import android.content.pm.PackageManager
import android.os.Binder
import icu.nullptr.hidemyapplist.common.Constants
import org.frknkrc44.hma_oss.zygote.util.Logcat.logD
import java.util.concurrent.atomic.AtomicLong

/**
 * 权限查询隔离：
 * 被隐藏的包，checkPermission(perm, pid, uid) 也应返回 DENIED，
 * 否则「包名查不到 / 权限却有」就是一条可枚举的泄漏（Duck、HMA Detector 都在用）。
 *
 * 注意：getPackagesForUid 正是 HMA 自己过滤的方法，对被隐藏 uid 返回 null，
 * 所以这里反向建「uid -> 包名」映射：包名来自 HMA 配置，uid 通过 getPackageUid 获取。
 */
class PermissionHook : IFrameworkHook {
    override val TAG = "PermissionHook"

    private val uidToPkg = HashMap<Int, String>()
    private val lastBuild = AtomicLong(0L)

    override fun load() {
        hooker.apply {
            hookBefore(
                "android.permission.PermissionManager",
                "checkPermission",
                3,
            ) { methodName, frame, returnValue ->
                val targetUid = frame.getArgument(2) as? Int ?: return@hookBefore
                if (targetUid < 10000) return@hookBefore

                val callingUid = Binder.getCallingUid()
                if (callingUid == Constants.UID_SYSTEM || callingUid < 10000) return@hookBefore

                ensureMap()

                val targetApp = uidToPkg[targetUid] ?: return@hookBefore

                val callerApps = try {
                    pms.getPackagesForUid(callingUid)
                } catch (t: Throwable) {
                    null
                } ?: return@hookBefore

                val hit = callerApps.firstOrNull { service.shouldHide(it, targetApp) } ?: return@hookBefore

                returnValue.result = PackageManager.PERMISSION_DENIED
                service.increasePMFilterCount(callingUid)
                logD(TAG) { "@$methodName denied $targetApp (uid=$targetUid) for $hit" }
            }
        }
        logD(TAG) { "checkPermission hook installed" }
    }

    /** 每 60 秒最多重建一次映射（配置可能被改） */
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
            logD(TAG) { "uid map rebuilt: ${fresh.size} entries" }
        } catch (t: Throwable) {
            logD(TAG, t) { "uid map rebuild failed" }
        }
    }
}
