package com.usehashmap.keyinspector.filetype

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileEditor.FileEditor
import com.intellij.openapi.fileEditor.FileEditorState
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.util.UserDataHolderBase
import com.intellij.openapi.vfs.VirtualFile
import com.usehashmap.keyinspector.actions.ChangeKeystorePasswordDialog
import com.usehashmap.keyinspector.actions.GenerateSelfSignedCertHelper
import com.usehashmap.keyinspector.actions.ImportCertActionHelper
import com.usehashmap.keyinspector.service.ChangeKeystorePasswordService
import com.usehashmap.keyinspector.service.ChangePasswordResult
import com.usehashmap.keyinspector.service.EntryOperationResult
import com.usehashmap.keyinspector.service.ExtensionMapper
import com.usehashmap.keyinspector.ui.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.jetbrains.jewel.bridge.JewelComposePanel
import org.jetbrains.jewel.ui.component.OutlinedButton
import org.jetbrains.jewel.ui.component.Text
import java.beans.PropertyChangeListener
import java.io.File
import javax.swing.JComponent

/**
 * [FileEditor] that renders the Key Inspector UI when a keystore / certificate
 * file is opened directly from the project tree.
 */
class KeyInspectorFileEditor(
    private val project:     Project,
    private val virtualFile: VirtualFile
) : UserDataHolderBase(), FileEditor {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val state = KeyInspectorState(scope)

    private val rootComponent: JComponent = JewelComposePanel(focusOnClickInside = true) {
        val uiState by state.uiState.collectAsState()
        FileInspectorContent(uiState = uiState, state = state, project = project)
    }.also {
        state.openFile(File(virtualFile.path))
    }

    override fun getComponent(): JComponent                              = rootComponent
    override fun getPreferredFocusedComponent(): JComponent             = rootComponent
    override fun getName(): String                                       = "Key Inspector"
    override fun getFile(): VirtualFile                                  = virtualFile
    override fun setState(state: FileEditorState)                       { /* no persistent state */ }
    override fun isModified(): Boolean                                   = false
    override fun isValid(): Boolean                                      = virtualFile.isValid
    override fun addPropertyChangeListener(l: PropertyChangeListener)   { }
    override fun removePropertyChangeListener(l: PropertyChangeListener){ }
    override fun dispose()                                               { }
}

// ─── Root composable ──────────────────────────────────────────────────────────

@Composable
private fun FileInspectorContent(
    uiState: InspectorUiState,
    state:   KeyInspectorState,
    project: Project
) {
    Column(modifier = Modifier.fillMaxSize()) {

        // ── Viewer action bar (always visible at the top of the editor) ───
        FileEditorActionBar(uiState = uiState, state = state, project = project)

        // ── Body ──────────────────────────────────────────────────────────
        Box(modifier = Modifier.fillMaxSize().weight(1f)) {
            when (val s = uiState) {
                is InspectorUiState.Empty   -> EmptyState()
                is InspectorUiState.Loading -> LoadingState()
                is InspectorUiState.PasswordRequired -> PasswordPromptPanel(
                    onSubmit = { pwd -> state.retryWithPassword(pwd) },
                    onCancel = { state.reset() },
                    modifier = Modifier.align(Alignment.Center).widthIn(max = 420.dp)
                )
                is InspectorUiState.Error  -> ErrorState(s.title, s.message, onRetry = { state.refresh() })
                is InspectorUiState.Loaded -> LoadedContent(s, state, project)
            }
        }
    }
}

// ─── Action bar ───────────────────────────────────────────────────────────────

/**
 * Top action bar for the file editor view.
 * Shows Refresh, Import, Generate and – for keystores – Change / Remove Password.
 */
@Composable
private fun FileEditorActionBar(
    uiState: InspectorUiState,
    state:   KeyInspectorState,
    project: Project
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier              = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment     = Alignment.CenterVertically
        ) {
            // Generate is always available

            if (uiState is InspectorUiState.Loaded) {
                OutlinedButton(onClick = { state.refresh() }) { Text("Refresh") }

                val ext = File(uiState.loadedFile.filePath).extension.lowercase()
                val isKeystore = ExtensionMapper.isKeystore(ext)

                if (isKeystore) {
                    OutlinedButton(onClick = {
                        ImportCertActionHelper.performImport(
                            project          = project,
                            keystoreFile     = state.currentKeystoreFile,
                            keystorePassword = state.currentKeystorePassword,
                            onSuccess        = { state.refresh() }
                        )
                    }) { Text("Import…") }

                    OutlinedButton(onClick = {
                        ApplicationManager.getApplication().invokeLater {
                            GenerateSelfSignedCertHelper.performGenerate(
                                project       = project,
                                preselectedKs = state.currentKeystoreFile,
                                onSuccess     = { state.refresh() }
                            )
                        }
                    }) { Text("Generate Self-Signed Cert…") }

                    OutlinedButton(onClick = {
                        ApplicationManager.getApplication().invokeLater {
                            performChangePassword(project, state)
                        }
                    }) { Text("Change / Remove Password…") }
                }

                Text(
                    text       = File(uiState.loadedFile.filePath).name,
                    fontSize   = 11.sp,
                    fontWeight = FontWeight.Medium,
                    modifier   = Modifier.weight(1f).padding(start = 4.dp)
                )
                Text(
                    text     = uiState.loadedFile.keystoreType,
                    fontSize = 10.sp,
                    modifier = Modifier.padding(end = 4.dp)
                )
            }
        }
        // Hairline divider
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(Color.Gray.copy(alpha = 0.20f))
        )
    }
}

// ─── Loaded master/detail ─────────────────────────────────────────────────────

@Composable
private fun LoadedContent(
    s:       InspectorUiState.Loaded,
    state:   KeyInspectorState,
    project: Project
) {
    Row(modifier = Modifier.fillMaxSize()) {
        // Entry list
        Column(modifier = Modifier.width(260.dp).fillMaxHeight()) {
            Row(
                modifier              = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment     = Alignment.CenterVertically
            ) {
                Text("Entries", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Text("${s.loadedFile.entries.size}", fontSize = 11.sp)
            }
            EntryListPanel(
                entries  = s.loadedFile.entries,
                selected = s.selectedEntry,
                onSelect = { state.selectEntry(it) },
                onDelete = { entry ->
                    ApplicationManager.getApplication().invokeLater {
                        performDeleteEntry(project, state, entry, state.scope)
                    }
                },
                onRename = { entry ->
                    ApplicationManager.getApplication().invokeLater {
                        performRenameEntry(project, state, entry, state.scope)
                    }
                },
                modifier = Modifier.fillMaxSize()
            )
        }
        // Detail panel
        Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
            if (s.selectedEntry == null) {
                Text(
                    text      = "Select an entry from the list to view its details.",
                    fontSize  = 13.sp,
                    textAlign = TextAlign.Center,
                    modifier  = Modifier.align(Alignment.Center).padding(24.dp)
                )
            } else {
                EntryDetailPanel(entry = s.selectedEntry, modifier = Modifier.fillMaxSize())
            }
        }
    }
}

// ─── Placeholder states ───────────────────────────────────────────────────────

@Composable
private fun EmptyState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text("Preparing…", fontSize = 13.sp)
    }
}

@Composable
private fun LoadingState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text("Loading…", fontSize = 13.sp)
    }
}

@Composable
private fun ErrorState(title: String, message: String, onRetry: () -> Unit) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(32.dp)
        ) {
            Text(title, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            Text(message, fontSize = 12.sp, textAlign = TextAlign.Center)
            OutlinedButton(onClick = onRetry) { Text("Retry") }
        }
    }
}

// ─── Change-password helper (same logic as in tool-window factory) ────────────

private fun performChangePassword(project: Project, state: KeyInspectorState) {
    val ksFile = state.currentKeystoreFile ?: return

    val dialog = ChangeKeystorePasswordDialog(project)
    if (!dialog.showAndGet()) return

    val result = ChangeKeystorePasswordService.changePassword(
        keystoreFile    = ksFile,
        currentPassword = dialog.currentPassword,
        newPassword     = dialog.newPassword
    )

    when (result) {
        is ChangePasswordResult.Success -> {
            state.updatePassword(dialog.newPassword)
            val verb = if (dialog.isRemovePassword) "removed" else "changed"
            NotificationGroupManager.getInstance()
                .getNotificationGroup("Key Inspector")
                .createNotification(
                    "Password $verb",
                    "The keystore password for <b>${ksFile.name}</b> was $verb successfully.",
                    NotificationType.INFORMATION
                )
                .notify(project)
        }
        is ChangePasswordResult.WrongCurrentPassword ->
            Messages.showErrorDialog(
                project,
                "The current password is incorrect.\n\nDetails: ${result.reason}",
                "Change Password — Wrong Password"
            )
        is ChangePasswordResult.WriteError ->
            Messages.showErrorDialog(
                project,
                "Could not save the keystore.\n\nDetails: ${result.reason}",
                "Change Password — Write Error"
            )
    }
}

// ─── Delete / Rename helpers ──────────────────────────────────────────────────

private fun performDeleteEntry(
    project: Project,
    state: KeyInspectorState,
    entry: com.usehashmap.keyinspector.model.KeyEntry,
    scope: CoroutineScope
) {
    val confirm = Messages.showYesNoDialog(
        project,
        "Are you sure you want to permanently delete the entry '${entry.alias}'?\n\nThis action cannot be undone.",
        "Delete Entry",
        "Delete",
        "Cancel",
        Messages.getWarningIcon()
    )
    if (confirm != Messages.YES) return

    scope.launch {
        val result = state.deleteEntry(entry.alias)
        ApplicationManager.getApplication().invokeLater {
            when (result) {
                is EntryOperationResult.Success          -> state.refresh()
                is EntryOperationResult.WrongPassword    ->
                    Messages.showErrorDialog(project, result.reason, "Delete Entry — Error")
                is EntryOperationResult.WriteError       ->
                    Messages.showErrorDialog(project, result.reason, "Delete Entry — Error")
                is EntryOperationResult.AliasNotFound    ->
                    Messages.showErrorDialog(project, "Alias '${result.alias}' not found.", "Delete Entry — Error")
                is EntryOperationResult.AliasAlreadyExists -> { /* can't happen on delete */ }
            }
        }
    }
}

private fun performRenameEntry(
    project: Project,
    state: KeyInspectorState,
    entry: com.usehashmap.keyinspector.model.KeyEntry,
    scope: CoroutineScope
) {
    val newAlias = Messages.showInputDialog(
        project,
        "Enter a new alias for '${entry.alias}':",
        "Rename Entry",
        Messages.getQuestionIcon(),
        entry.alias,
        null
    )?.trim() ?: return

    if (newAlias.isBlank()) {
        Messages.showErrorDialog(project, "Alias must not be empty.", "Rename Entry — Validation")
        return
    }
    if (newAlias == entry.alias) return

    scope.launch {
        val result = state.renameEntry(entry.alias, newAlias)
        ApplicationManager.getApplication().invokeLater {
            when (result) {
                is EntryOperationResult.Success          -> state.refresh()
                is EntryOperationResult.AliasAlreadyExists ->
                    Messages.showErrorDialog(
                        project,
                        "An entry with alias '${result.alias}' already exists.",
                        "Rename Entry — Conflict"
                    )
                is EntryOperationResult.WrongPassword    ->
                    Messages.showErrorDialog(project, result.reason, "Rename Entry — Error")
                is EntryOperationResult.WriteError       ->
                    Messages.showErrorDialog(project, result.reason, "Rename Entry — Error")
                is EntryOperationResult.AliasNotFound    ->
                    Messages.showErrorDialog(project, "Alias '${result.alias}' not found.", "Rename Entry — Error")
            }
        }
    }
}

