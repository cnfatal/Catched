package cn.fatalc.catched.engine

import android.content.Context
import android.util.Log
import cn.fatalc.catched.detector.*
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class DetectorEngine(context: Context) {

    val checks: List<Check> = buildList {
        addAll(rootChecks(context))
        addAll(xposedChecks(context))
        addAll(fridaChecks())
        addAll(npatchChecks(context))
        addAll(nativeHookChecks())
        addAll(deviceIntegrityChecks(context))
        addAll(emulatorChecks(context))
        addAll(debugChecks(context))
        addAll(sslPinningChecks(context))
    }

    val groups: List<String> get() = checks.map { it.group }.distinct()

    fun checksForGroup(group: String): List<Check> = checks.filter { it.group == group }

    interface ScanCallback {
        fun onCheckComplete(check: Check, result: CheckResult)
        fun onProgress(progress: Float)
    }

    suspend fun scan(
        ids: Set<String>? = null,
        callback: ScanCallback? = null
    ): Map<String, CheckResult> = withContext(Dispatchers.IO) {
        val targets = if (ids == null) checks else checks.filter { it.id in ids }
        val results = mutableMapOf<String, CheckResult>()

        targets.forEachIndexed { index, check ->
            val result = check.run()
            results[check.id] = result
            Log.d("Catched", "[${check.id}] detected=${result.detected}" +
                    (if (result.actual != null) " actual=${result.actual}" else "") +
                    (if (result.evidence != null) " evidence=${result.evidence}" else ""))
            callback?.onCheckComplete(check, result)
            callback?.onProgress((index + 1).toFloat() / targets.size)
        }

        results
    }
}
