package cn.fatalc.catched

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.*
import androidx.lifecycle.viewmodel.compose.viewModel
import cn.fatalc.catched.ui.ReportScreen
import cn.fatalc.catched.ui.theme.CatchedTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            CatchedTheme {
                val vm: MainViewModel = viewModel(factory = MainViewModel.Factory(applicationContext))
                val uiState by vm.uiState.collectAsState()

                ReportScreen(
                    groups = vm.groups,
                    checksForGroup = { vm.checksForGroup(it) },
                    uiState = uiState,
                    onStartScan = { vm.startScan() }
                )
            }
        }
    }
}
