package com.usehashmap.keyinspector

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.intellij.openapi.fileChooser.FileChooserDescriptor
import com.intellij.openapi.fileChooser.FileChooserFactory
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.usehashmap.keyinspector.actions.ImportCertAction
import com.usehashmap.keyinspector.actions.ImportCertActionHelper
import com.usehashmap.keyinspector.service.ExtensionMapper
import com.usehashmap.keyinspector.ui.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import androidx.compose.runtime.collectAsState
import org.jetbrains.jewel.bridge.addComposeTab
import org.jetbrains.jewel.ui.component.OutlinedButton
import org.jetbrains.jewel.ui.component.Text
import java.io.File

class KeyInspectorToolWindowFactory : ToolWindowFactory {

    override fun shouldBeAvailable(project: Project) = true

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val state = KeyInspectorState(scope)

        toolWindow.addComposeTab("Key Inspector", focusOnClickInside = true) {
            KeyInspectorContent(
                state   = state,
                project = project
            )
        }
    }
}

@Composable
private fun KeyInspectorContent(state: KeyInspectorState, project: Project) {
    val uiState by state.uiState.collectAsState()

    Column(modifier = Modifier.fillMaxSize()) {
        // ── Toolbar ──────────────────────────────────────────────────────────
        Toolbar(
            uiState    = uiState,
            onOpenFile = { file -> state.openFile(File(file.path)) },
            onRefresh  = { state.refresh() },
            onImport   = {
                ImportCertActionHelper.performImport(
                    project          = project,
                    keystoreFile     = state.currentKeystoreFile,
                    keystorePassword = state.currentKeystorePassword,
                    onSuccess        = { state.refresh() }
                )
            },
            project    = project
        )

        // ── Body ──────────────────────────────────────────────────────────────
        Box(modifier = Modifier.fillMaxSize().weight(1f)) {
            when (val s = uiState) {
                is InspectorUiState.Empty -> EmptyState()

                is InspectorUiState.Loading -> LoadingState()

                is InspectorUiState.PasswordRequired -> {
                    PasswordPromptPanel(
                        onSubmit = { pwd -> state.retryWithPassword(pwd) },
                        onCancel = { state.reset() },
                        modifier = Modifier.align(Alignment.Center).widthIn(max = 420.dp)
                    )
                }

                is InspectorUiState.Error -> ErrorState(s.title, s.message)

                is InspectorUiState.Loaded -> LoadedState(
                    loadedState   = s,
                    onSelectEntry = { state.selectEntry(it) }
                )
            }
        }
    }
}

@Composable
private fun Toolbar(
    uiState: InspectorUiState,
    onOpenFile: (VirtualFile) -> Unit,
    onRefresh: () -> Unit,
    onImport: () -> Unit,
    project: Project
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        OutlinedButton(onClick = {
            val descriptor = FileChooserDescriptor(
                /* chooseFiles = */ true,
                /* chooseFolders = */ false,
                /* chooseJars = */ false,
                /* chooseJarsAsFiles = */ false,
                /* chooseJarContents = */ false,
                /* chooseMultiple = */ false
            ).apply {
                title = "Open Keystore or Certificate File"
                description = "JKS, JCEKS, BKS, P12, PFX, UBER, BCFKS, PEM, CER, CRT, P7B, CRL, P10, PUB, KEY, PKCS8…"
                withFileFilter { vf ->
                    vf.isDirectory || SUPPORTED_EXTENSIONS.contains(vf.extension?.lowercase())
                }
            }
            val chooser = FileChooserFactory.getInstance()
                .createFileChooser(descriptor, project, null)
            val files = chooser.choose(project)
            files.firstOrNull()?.let { onOpenFile(it) }
        }) {
            Text("Open File…")
        }

        if (uiState is InspectorUiState.Loaded) {
            OutlinedButton(onClick = onRefresh) { Text("Refresh") }

            // "Import…" button – only makes sense for keystores, not bare cert files
            val loadedExt = File(uiState.loadedFile.filePath).extension.lowercase()
            if (ExtensionMapper.isKeystore(loadedExt)) {
                OutlinedButton(onClick = onImport) { Text("Import…") }
            }

            // Show the filename
            val name = File(uiState.loadedFile.filePath).name
            Text(
                text = name,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.weight(1f)
            )
            Text(
                text = uiState.loadedFile.keystoreType,
                fontSize = 11.sp,
                modifier = Modifier.padding(end = 4.dp)
            )
        }
    }
}

@Composable
private fun LoadedState(
    loadedState: InspectorUiState.Loaded,
    onSelectEntry: (com.usehashmap.keyinspector.model.KeyEntry) -> Unit
) {
    val loadedFile = loadedState.loadedFile
    val selected   = loadedState.selectedEntry

    Row(modifier = Modifier.fillMaxSize()) {
        // ── Entry list (master) ───────────────────────────────────────────
        Column(
            modifier = Modifier
                .width(260.dp)
                .fillMaxHeight()
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Entries", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Text(
                    "${loadedFile.entries.size}",
                    fontSize = 11.sp
                )
            }
            EntryListPanel(
                entries  = loadedFile.entries,
                selected = selected,
                onSelect = onSelectEntry,
                modifier = Modifier.fillMaxSize()
            )
        }

        // ── Detail panel ──────────────────────────────────────────────────
        Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
            if (selected == null) {
                Text(
                    text = "Select an entry from the list to view its details.",
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.align(Alignment.Center).padding(24.dp)
                )
            } else {
                EntryDetailPanel(
                    entry    = selected,
                    modifier = Modifier.fillMaxSize()
                )
            }
        }
    }
}

@Composable
private fun EmptyState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(32.dp)
        ) {
            Text("No file loaded", fontWeight = FontWeight.Bold, fontSize = 14.sp)
            Text(
                "Click \"Open File…\" to inspect a keystore or certificate file.",
                fontSize = 12.sp,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun LoadingState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text("Loading…", fontSize = 13.sp)
    }
}

@Composable
private fun ErrorState(title: String, message: String) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(32.dp)
        ) {
            Text(title, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            Text(message, fontSize = 12.sp, textAlign = TextAlign.Center)
        }
    }
}

private val SUPPORTED_EXTENSIONS = setOf(
    "jks", "jceks", "bks", "p12", "pfx", "uber", "bcfks",
    "pub", "key", "pem", "cer", "crt",
    "p7", "p7b", "pkipath", "spc",
    "p10", "spkac", "pkcs8", "pvk", "crl"
)
