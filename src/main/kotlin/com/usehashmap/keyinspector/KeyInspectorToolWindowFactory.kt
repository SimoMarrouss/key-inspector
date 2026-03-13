package com.usehashmap.keyinspector

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
import com.intellij.openapi.fileChooser.FileChooserDescriptor
import com.intellij.openapi.fileChooser.FileChooserFactory
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.usehashmap.keyinspector.actions.ChangeKeystorePasswordDialog
import com.usehashmap.keyinspector.actions.GenerateSelfSignedCertHelper
import com.usehashmap.keyinspector.actions.ImportCertActionHelper
import com.usehashmap.keyinspector.model.KeyEntry
import com.usehashmap.keyinspector.service.ChangeKeystorePasswordService
import com.usehashmap.keyinspector.service.ChangePasswordResult
import com.usehashmap.keyinspector.service.EntryOperationResult
import com.usehashmap.keyinspector.service.ExtensionMapper
import com.usehashmap.keyinspector.ui.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.jetbrains.jewel.bridge.addComposeTab
import org.jetbrains.jewel.ui.component.OutlinedButton
import org.jetbrains.jewel.ui.component.Text
import java.io.File

// ─── Factory ──────────────────────────────────────────────────────────────────

class KeyInspectorToolWindowFactory : ToolWindowFactory {

    override fun shouldBeAvailable(project: Project) = true

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val state = KeyInspectorState(scope)

        toolWindow.addComposeTab("Key Inspector", focusOnClickInside = true) {
            KeyInspectorContent(state = state, project = project, scope = scope)
        }
    }
}

// ─── Root composable ──────────────────────────────────────────────────────────

@Composable
private fun KeyInspectorContent(state: KeyInspectorState, project: Project, scope: CoroutineScope) {
    val uiState by state.uiState.collectAsState()

    Column(modifier = Modifier.fillMaxSize()) {

        // ── Top file-picker / navigation toolbar ─────────────────────────
        FilePickerToolbar(
            uiState    = uiState,
            onOpenFile = { vf -> state.openFile(File(vf.path)) },
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
                is InspectorUiState.Error  -> ErrorState(s.title, s.message)
                is InspectorUiState.Loaded -> LoadedState(
                    loadedState      = s,
                    onSelectEntry    = { state.selectEntry(it) },
                    onChangePassword = {
                        ApplicationManager.getApplication().invokeLater {
                            performChangePassword(project, state)
                        }
                    },
                    onGenerate = {
                        ApplicationManager.getApplication().invokeLater {
                            GenerateSelfSignedCertHelper.performGenerate(
                                project       = project,
                                preselectedKs = state.currentKeystoreFile,
                                onSuccess     = { state.refresh() }
                            )
                        }
                    },
                    onDeleteEntry = { entry ->
                        ApplicationManager.getApplication().invokeLater {
                            performDeleteEntry(project, state, entry, scope)
                        }
                    },
                    onRenameEntry = { entry ->
                        ApplicationManager.getApplication().invokeLater {
                            performRenameEntry(project, state, entry, scope)
                        }
                    }
                )
            }
        }
    }
}

// ─── File-picker toolbar (always visible) ────────────────────────────────────

@Composable
private fun FilePickerToolbar(
    uiState:    InspectorUiState,
    onOpenFile: (VirtualFile) -> Unit,
    onRefresh:  () -> Unit,
    onImport:   () -> Unit,
    project:    Project
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment     = Alignment.CenterVertically
    ) {
        OutlinedButton(onClick = {
            val descriptor = FileChooserDescriptor(true, false, false, false, false, false).apply {
                title       = "Open Keystore or Certificate File"
                description = "JKS, JCEKS, BKS, P12, PFX, UBER, BCFKS, PEM, CER, CRT, P7B, CRL, P10, PUB, KEY, PKCS8…"
                withFileFilter { vf ->
                    vf.isDirectory || SUPPORTED_EXTENSIONS.contains(vf.extension?.lowercase())
                }
            }
            val files = FileChooserFactory.getInstance()
                .createFileChooser(descriptor, project, null)
                .choose(project)
            files.firstOrNull()?.let { onOpenFile(it) }
        }) { Text("Open File…") }


        if (uiState is InspectorUiState.Loaded) {
            OutlinedButton(onClick = onRefresh) { Text("Refresh") }

            val loadedExt = File(uiState.loadedFile.filePath).extension.lowercase()
            if (ExtensionMapper.isKeystore(loadedExt)) {
                OutlinedButton(onClick = onImport) { Text("Import…") }
            }

            Text(
                text       = File(uiState.loadedFile.filePath).name,
                fontSize   = 12.sp,
                fontWeight = FontWeight.Medium,
                modifier   = Modifier.weight(1f)
            )
            Text(
                text     = uiState.loadedFile.keystoreType,
                fontSize = 11.sp,
                modifier = Modifier.padding(end = 4.dp)
            )
        }
    }
}

// ─── Loaded state (master-detail + viewer toolbar) ────────────────────────────

@Composable
private fun LoadedState(
    loadedState:      InspectorUiState.Loaded,
    onSelectEntry:    (KeyEntry) -> Unit,
    onChangePassword: () -> Unit,
    onGenerate:       () -> Unit,
    onDeleteEntry:    (KeyEntry) -> Unit,
    onRenameEntry:    (KeyEntry) -> Unit
) {
    val loadedFile = loadedState.loadedFile
    val selected   = loadedState.selectedEntry
    val isKeystore = ExtensionMapper.isKeystore(File(loadedFile.filePath).extension.lowercase())

    Column(modifier = Modifier.fillMaxSize()) {

        // ── Viewer toolbar – keystore-level actions ───────────────────────
        if (isKeystore) {
            ViewerToolbar(
                onChangePassword = onChangePassword,
                onGenerate       = onGenerate
            )
        }

        // ── Master / detail row ───────────────────────────────────────────
        Row(modifier = Modifier.fillMaxSize().weight(1f)) {

            // Entry list (left panel)
            Column(modifier = Modifier.width(260.dp).fillMaxHeight()) {
                Row(
                    modifier              = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment     = Alignment.CenterVertically
                ) {
                    Text("Entries", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    Text("${loadedFile.entries.size}", fontSize = 11.sp)
                }
                EntryListPanel(
                    entries   = loadedFile.entries,
                    selected  = selected,
                    onSelect  = onSelectEntry,
                    onDelete  = onDeleteEntry,
                    onRename  = onRenameEntry,
                    modifier  = Modifier.fillMaxSize()
                )
            }

            // Detail panel (right)
            Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
                if (selected == null) {
                    Text(
                        text      = "Select an entry from the list to view its details.",
                        fontSize  = 13.sp,
                        textAlign = TextAlign.Center,
                        modifier  = Modifier.align(Alignment.Center).padding(24.dp)
                    )
                } else {
                    EntryDetailPanel(entry = selected, modifier = Modifier.fillMaxSize())
                }
            }
        }
    }
}

// ─── Viewer toolbar ───────────────────────────────────────────────────────────

/**
 * Thin action bar shown at the top of the keystore viewer (below the file-picker
 * toolbar). Only displayed when a keystore container is loaded (not for bare
 * certificate / key files). Contains operations that act on the keystore as a whole.
 */
@Composable
private fun ViewerToolbar(
    onChangePassword: () -> Unit,
    onGenerate:       () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier              = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment     = Alignment.CenterVertically
        ) {
            OutlinedButton(onClick = onChangePassword) {
                Text("Change / Remove Password…")
            }
            OutlinedButton(onClick = onGenerate) {
                Text("Generate Self-Signed Cert…")
            }
        }
        // Hairline separator between viewer toolbar and the entry list
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .padding(horizontal = 0.dp)
                .then(Modifier.background(Color.Gray.copy(alpha = 0.20f)))
        )
    }
}

// ─── Placeholder states ───────────────────────────────────────────────────────

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
                fontSize  = 12.sp,
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

// ─── Constants ────────────────────────────────────────────────────────────────

private val SUPPORTED_EXTENSIONS = setOf(
    "jks", "jceks", "bks", "p12", "pfx", "uber", "bcfks",
    "pub", "key", "pem", "cer", "crt",
    "p7", "p7b", "pkipath", "spc",
    "p10", "spkac", "pkcs8", "pvk", "crl"
)

// ─── Entry-level helpers (delete / rename) ────────────────────────────────────

/**
 * Shows a confirmation dialog then deletes the entry on a background thread.
 * Must be called on the EDT.
 */
private fun performDeleteEntry(
    project: Project,
    state: KeyInspectorState,
    entry: KeyEntry,
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
                is EntryOperationResult.Success ->
                    state.refresh()
                is EntryOperationResult.WrongPassword ->
                    Messages.showErrorDialog(project, result.reason, "Delete Entry — Error")
                is EntryOperationResult.WriteError ->
                    Messages.showErrorDialog(project, result.reason, "Delete Entry — Error")
                is EntryOperationResult.AliasNotFound ->
                    Messages.showErrorDialog(project, "Alias '${result.alias}' not found.", "Delete Entry — Error")
                is EntryOperationResult.AliasAlreadyExists -> { /* can't happen on delete */ }
            }
        }
    }
}

/**
 * Shows an input dialog for the new alias then renames the entry on a background thread.
 * Must be called on the EDT.
 */
private fun performRenameEntry(
    project: Project,
    state: KeyInspectorState,
    entry: KeyEntry,
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
                is EntryOperationResult.Success ->
                    state.refresh()
                is EntryOperationResult.AliasAlreadyExists ->
                    Messages.showErrorDialog(
                        project,
                        "An entry with alias '${result.alias}' already exists in this keystore.",
                        "Rename Entry — Conflict"
                    )
                is EntryOperationResult.WrongPassword ->
                    Messages.showErrorDialog(project, result.reason, "Rename Entry — Error")
                is EntryOperationResult.WriteError ->
                    Messages.showErrorDialog(project, result.reason, "Rename Entry — Error")
                is EntryOperationResult.AliasNotFound ->
                    Messages.showErrorDialog(project, "Alias '${result.alias}' not found.", "Rename Entry — Error")
            }
        }
    }
}

// ─── Change-password helper ───────────────────────────────────────────────────

/**
 * Shows the [ChangeKeystorePasswordDialog], calls [ChangeKeystorePasswordService],
 * then either notifies success (and reloads) or shows a specific error dialog.
 *
 * Must be called on the EDT (use ApplicationManager.invokeLater from Compose).
 */
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
