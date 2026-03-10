package com.usehashmap.keyinspector.filetype

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.intellij.openapi.fileEditor.FileEditor
import com.intellij.openapi.fileEditor.FileEditorState
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.UserDataHolderBase
import com.intellij.openapi.vfs.VirtualFile
import com.usehashmap.keyinspector.ui.EntryDetailPanel
import com.usehashmap.keyinspector.ui.EntryListPanel
import com.usehashmap.keyinspector.ui.InspectorUiState
import com.usehashmap.keyinspector.ui.KeyInspectorState
import com.usehashmap.keyinspector.ui.PasswordPromptPanel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.jetbrains.jewel.bridge.JewelComposePanel
import java.beans.PropertyChangeListener
import java.io.File
import javax.swing.JComponent

/**
 * A [FileEditor] that renders the Key Inspector Compose UI for keystore /
 * certificate files opened directly from the project tree.
 */
class KeyInspectorFileEditor(
    @Suppress("UnusedPrivateProperty")
    private val project: Project,  // reserved for future project-scoped services
    private val virtualFile: VirtualFile
) : UserDataHolderBase(), FileEditor {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val state = KeyInspectorState(scope)

    private val rootComponent: JComponent = JewelComposePanel(focusOnClickInside = true) {
        val uiState by state.uiState.collectAsState()
        FileInspectorContent(uiState = uiState, state = state)
    }.also {
        // Kick off loading immediately when the editor is created
        state.openFile(File(virtualFile.path))
    }

    override fun getComponent(): JComponent = rootComponent
    override fun getPreferredFocusedComponent(): JComponent = rootComponent
    override fun getName(): String = "Key Inspector"
    override fun getFile(): VirtualFile = virtualFile

    override fun setState(state: FileEditorState) { /* no persistent state */ }
    override fun isModified(): Boolean = false
    override fun isValid(): Boolean = virtualFile.isValid

    override fun addPropertyChangeListener(listener: PropertyChangeListener) { /* not needed */ }
    override fun removePropertyChangeListener(listener: PropertyChangeListener) { /* not needed */ }

    override fun dispose() {
        // CoroutineScope is cancelled when the SupervisorJob is garbage-collected;
        // nothing else to tear down explicitly.
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Composables (mirror of KeyInspectorToolWindowFactory, but no toolbar needed
// because the file is already determined by the editor context)
// ──────────────────────────────────────────────────────────────────────────────

@Composable
private fun FileInspectorContent(uiState: InspectorUiState, state: KeyInspectorState) {
    Box(modifier = Modifier.fillMaxSize()) {
        when (val s = uiState) {
            is InspectorUiState.Empty -> FileEmptyState()
            is InspectorUiState.Loading -> FileLoadingState()
            is InspectorUiState.PasswordRequired -> {
                PasswordPromptPanel(
                    onSubmit = { pwd -> state.retryWithPassword(pwd) },
                    onCancel = { state.reset() },
                    modifier = Modifier.align(Alignment.Center).widthIn(max = 420.dp)
                )
            }
            is InspectorUiState.Error -> FileErrorState(s.title, s.message, onRetry = { state.refresh() })
            is InspectorUiState.Loaded -> {
                Row(modifier = Modifier.fillMaxSize()) {
                    // ── Entry list ────────────────────────────────────────
                    Column(modifier = Modifier.width(260.dp).fillMaxHeight()) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            org.jetbrains.jewel.ui.component.Text(
                                "Entries",
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                            org.jetbrains.jewel.ui.component.Text(
                                "${s.loadedFile.entries.size}",
                                fontSize = 11.sp
                            )
                        }
                        EntryListPanel(
                            entries = s.loadedFile.entries,
                            selected = s.selectedEntry,
                            onSelect = { state.selectEntry(it) },
                            modifier = Modifier.fillMaxSize()
                        )
                    }

                    // ── Detail panel ──────────────────────────────────────
                    Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
                        if (s.selectedEntry == null) {
                            org.jetbrains.jewel.ui.component.Text(
                                text = "Select an entry from the list to view its details.",
                                fontSize = 13.sp,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.align(Alignment.Center).padding(24.dp)
                            )
                        } else {
                            EntryDetailPanel(
                                entry = s.selectedEntry,
                                modifier = Modifier.fillMaxSize()
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun FileEmptyState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        org.jetbrains.jewel.ui.component.Text("Preparing…", fontSize = 13.sp)
    }
}

@Composable
private fun FileLoadingState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        org.jetbrains.jewel.ui.component.Text("Loading…", fontSize = 13.sp)
    }
}

@Composable
private fun FileErrorState(title: String, message: String, onRetry: () -> Unit) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(32.dp)
        ) {
            org.jetbrains.jewel.ui.component.Text(title, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            org.jetbrains.jewel.ui.component.Text(message, fontSize = 12.sp, textAlign = TextAlign.Center)
            org.jetbrains.jewel.ui.component.OutlinedButton(onClick = onRetry) {
                org.jetbrains.jewel.ui.component.Text("Retry")
            }
        }
    }
}
