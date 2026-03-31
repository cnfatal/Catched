package cn.fatalc.catched

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import cn.fatalc.catched.engine.DetectorEngine
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ScanUiState(
    val isScanning: Boolean = false,
    val progress: Float = 0f,
    val results: Map<String, CheckResult> = emptyMap(),
    val scanTimeMs: Long = 0
)

class MainViewModel(context: Context) : ViewModel() {

    private val engine = DetectorEngine(context)

    val checks: List<Check> = engine.checks
    val groups: List<String> = engine.groups
    fun checksForGroup(group: String) = engine.checksForGroup(group)

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    fun startScan(ids: Set<String>? = null) {
        if (_uiState.value.isScanning) return

        viewModelScope.launch {
            val startTime = System.currentTimeMillis()
            _uiState.update { ScanUiState(isScanning = true) }

            val callback = object : DetectorEngine.ScanCallback {
                override fun onCheckComplete(check: Check, result: CheckResult) {
                    _uiState.update { it.copy(results = it.results + (check.id to result)) }
                }

                override fun onProgress(progress: Float) {
                    _uiState.update { it.copy(progress = progress) }
                }
            }

            engine.scan(ids, callback)

            _uiState.update {
                it.copy(
                    isScanning = false, progress = 1f,
                    scanTimeMs = System.currentTimeMillis() - startTime
                )
            }
        }
    }

    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T = MainViewModel(context) as T
    }
}
