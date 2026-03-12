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
import com.usehashmap.keyinspector.service.GenerateCertResult
import com.usehashmap.keyinspector.service.GenerateCertService
import java.io.File

/**
 * "Generate Self-Signed Certificate…" action.
 *
 * Surfaced in:
 *  1. Tools → Key Inspector → Generate Self-Signed Certificate…
 *  2. Right-click on a keystore file in the Project view.
 *  3. The viewer toolbar button (called via [GenerateSelfSignedCertHelper.performGenerate]).
 */
class GenerateSelfSignedCertAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        val vf = e.getData(CommonDataKeys.VIRTUAL_FILE)
        val isKeystore = vf != null && !vf.isDirectory &&
            ExtensionMapper.isKeystore(vf.extension?.lowercase() ?: "")
        e.presentation.isEnabledAndVisible = isKeystore || vf == null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val vf      = e.getData(CommonDataKeys.VIRTUAL_FILE)
        val preselected = if (vf != null && !vf.isDirectory &&
                              ExtensionMapper.isKeystore(vf.extension?.lowercase() ?: ""))
            File(vf.path) else null

        GenerateSelfSignedCertHelper.performGenerate(project, preselected) {
            preselected?.let {
                LocalFileSystem.getInstance().refreshAndFindFileByIoFile(it)
            }
        }
    }
}

// ─── Shared helper (action + toolbar button) ──────────────────────────────────

object GenerateSelfSignedCertHelper {

    /**
     * Opens the [GenerateSelfSignedCertWizard], then runs certificate generation
     * on a background thread.
     *
     * @param project        current IDE project
     * @param preselectedKs  optional keystore to pre-fill Step 4
     * @param onSuccess      EDT callback after successful generation
     */
    fun performGenerate(
        project: Project,
        preselectedKs: File?,
        onSuccess: (outputPath: String) -> Unit
    ) {
        val wizard = GenerateSelfSignedCertWizard(project, preselectedKs)
        if (!wizard.showAndGet()) return

        val params = wizard.buildParams()

        ProgressManager.getInstance().run(object : Task.Backgroundable(
            project,
            "Generating self-signed certificate '${params.alias}'…",
            false
        ) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                val result = GenerateCertService.generate(params)

                ApplicationManager.getApplication().invokeLater {
                    when (result) {
                        is GenerateCertResult.Success -> {
                            val lines = result.summaryLines.joinToString("\n")
                            NotificationGroupManager.getInstance()
                                .getNotificationGroup("Key Inspector")
                                .createNotification(
                                    "Certificate '${result.alias}' generated",
                                    "<html><pre>$lines</pre></html>",
                                    NotificationType.INFORMATION
                                )
                                .notify(project)

                            onSuccess(result.outputPath)
                        }
                        is GenerateCertResult.Failure ->
                            Messages.showErrorDialog(
                                project,
                                "Certificate generation failed:\n\n${result.reason}",
                                "Generate Self-Signed Certificate — Error"
                            )
                    }
                }
            }
        })
    }
}
