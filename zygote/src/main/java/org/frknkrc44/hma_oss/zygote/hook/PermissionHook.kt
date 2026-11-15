package org.frknkrc44.hma_oss.zygote.hook

import android.content.pm.PackageManager
import icu.nullptr.hidemyapplist.common.Constants
import org.frknkrc44.hma_oss.zygote.util.Logcat.logD
import org.frknkrc44.hma_oss.zygote.util.ServiceUtils

/**
 * 权限查询隔离：
 * 把「被隐藏的包」的 checkPermission(perm, pid, uid) 结果改成 DENIED，
 * 避免出现「包名查不到 / 权限却有」的不一致（Duck、HMA Detector 都用这条）。
 */
class PermissionHook : IFrameworkHook {
    override val TAG = "PermissionHook"

    override fun load() {
        hooker.apply {
            hookBefore(
                "android.permission.PermissionManager",
                "checkPermission",
                3,
            ) { methodName, frame, returnValue ->
                val targetUid = frame.getArgument(2) as? Int ?: return@hookBefore
                if (targetUid < 10000) return@hookBefore

                val callingUid = android.os.Binder.getCallingUid()
                if (callingUid == Constants.UID_SYSTEM || callingUid < 10000) return@hookBefore

                val targetApp = try {
                    pms.getPackagesForUid(targetUid)?.firstOrNull()
                } catch (t: Throwable) {
                    null
                } ?: return@hookBefore

                val cached = dataHolder.shouldHideFromUid(callingUid, targetApp) == true
                val direct = if (cached) true else {
                    ServiceUtils.getPackagesForUidLocal(pms, callingUid)
                        .firstOrNull { service.shouldHide(it, targetApp) } != null
                }

                if (direct) {
                    returnValue.result = PackageManager.PERMISSION_DENIED
                    service.increasePMFilterCount(callingUid)
                    logD(TAG) { "@$methodName denied $targetApp (uid=$targetUid) for caller $callingUid" }
                }
            }
        }

        logD(TAG) { "checkPermission hook installed" }
    }
}
