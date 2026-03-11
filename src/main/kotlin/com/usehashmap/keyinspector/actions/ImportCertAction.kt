@file:Suppress("NOTHING_TO_INLINE")
package com.usehashmap.keyinspector.actions

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.LocalFileSystem
import com.usehashmap.keyinspector.service.ExtensionMapper
import com.usehashmap.keyinspector.service.ImportResult
import com.usehashmap.keyinspector.service.ImportService
import java.io.File

/**
 * "Import Certificate / Key Pair…" action.
 *
 * Surfaced in three places:
 *   1. Right-click on a keystore file in the Project tool window.
 *   2. Tools → Key Inspector → Import Certificate / Key Pair…
 *   3. The "Import…" button in the Key Inspector tool-window toolbar
 *      (via [ImportCertActionHelper.performImport]).
 */
class ImportCertAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        val vf = e.getData(CommonDataKeys.VIRTUAL_FILE)
        val isKeystore = vf != null &&
            !vf.isDirectory &&
            ExtensionMapper.isKeystore(vf.extension?.lowercase() ?: "")
        e.presentation.isEnabledAndVisible = isKeystore || vf == null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val vf = e.getData(CommonDataKeys.VIRTUAL_FILE)
        val preSelected = if (vf != null && !vf.isDirectory &&
                               ExtensionMapper.isKeystore(vf.extension?.lowercase() ?: ""))
            File(vf.path) else null

        ImportCertActionHelper.performImport(
            project          = project,
            keystoreFile     = preSelected,
            keystorePassword = null,
            onSuccess        = {
                preSelected?.let { LocalFileSystem.getInstance().refreshAndFindFileByIoFile(it) }
            }
        )
    }

    companion object {
        const val NOTIFICATION_GROUP = "Key Inspector"
    }
}

// ─── Shared logic (action + toolbar button) ───────────────────────────────────

object ImportCertActionHelper {

    fun performImport(
        project: Project,
        keystoreFile: File?,
        keystorePassword: CharArray?,
        onSuccess: () -> Unit
    ) {
        val dialog = ImportCertDialog(project, keystoreFile, keystorePassword)
        if (!dialog.showAndGet()) return

        val ksFile  = dialog.selectedKeystoreFile
        val ksPwd   = dialog.keystorePasswordChars
        val srcFile = dialog.selectedSourceFile
        val srcPwd  = dialog.sourcePasswordChars
        val alias   = dialog.entryAlias
        val keyPwd  = dialog.keyPasswordChars

        ProgressManager.getInstance().run(object : Task.Backgroundable(
            project, "Importing '${srcFile.name}' into '${ksFile.name}'…", false
        ) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                val result = ImportService.import(
                    keystoreFile     = ksFile,
                    keystorePassword = ksPwd,
                    sourceFile       = srcFile,
                    alias            = alias,
                    keyPassword      = keyPwd,
                    sourcePassword   = srcPwd
                )
                ApplicationManager.getApplication().invokeLater {
                    handleResult(result, alias, ksFile, project, onSuccess)
                }
            }
        })
    }

    private fun handleResult(
        result: ImportResult,
        alias: String,
        ksFile: File,
        project: Project,
        onSuccess: () -> Unit
    ) {
        when (result) {
            is ImportResult.Success -> {
                onSuccess()
                NotificationGroupManager.getInstance()
                    .getNotificationGroup(ImportCertAction.NOTIFICATION_GROUP)
                    .createNotification(
                        "Import successful",
                        "Entry <b>$alias</b> was added to <b>${ksFile.name}</b>.",
                        NotificationType.INFORMATION
                    )
                    .notify(project)
            }
            is ImportResult.AliasExists ->
                Messages.showErrorDialog(
                    project,
                    "Alias '${result.alias}' already exists in the keystore.\n" +
                    "Choose a different alias and try again.",
                    "Import Failed — Duplicate Alias"
                )
            is ImportResult.WrongKeystorePassword ->
                Messages.showErrorDialog(
                    project,
                    "The keystore password is incorrect.\n\nDetails: ${result.reason}",
                    "Import Failed — Wrong Password"
                )
            is ImportResult.ParseError ->
                Messages.showErrorDialog(
                    project,
                    "The source file could not be parsed.\n\nDetails: ${result.reason}",
                    "Import Failed — Parse Error"
                )
            is ImportResult.WriteError ->
                Messages.showErrorDialog(
                    project,
                    "The keystore could not be updated.\n\nDetails: ${result.reason}",
                    "Import Failed — Write Error"
                )
        }
    }
}
