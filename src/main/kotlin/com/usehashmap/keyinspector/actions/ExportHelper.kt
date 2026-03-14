package com.usehashmap.keyinspector.actions

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileChooser.FileSaverDescriptor
import com.intellij.openapi.fileChooser.FileChooserFactory
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.LocalFileSystem
import com.usehashmap.keyinspector.model.EntryType
import com.usehashmap.keyinspector.model.KeyEntry
import com.usehashmap.keyinspector.service.ExportFormat
import com.usehashmap.keyinspector.service.ExportResult
import com.usehashmap.keyinspector.service.ExportService
import java.io.File

/**
 * Shared helper that drives the full export flow:
 *  1. Prompt for a save location (FileSaverDialog)
 *  2. For PKCS12: prompt for an export password
 *  3. Run the export on a background thread
 *  4. Show a success balloon with a clickable "Open in IDE" link, or an error dialog
 *
 * Must be called on the EDT.
 */
object ExportHelper {

    /**
     * Entry point.
     *
     * @param project          current project
     * @param entry            the keystore entry to export
     * @param format           the desired output format
     * @param keystoreFile     the source keystore file
     * @param keystorePassword the keystore password
     */
    fun performExport(
        project:          Project,
        entry:            KeyEntry,
        format:           ExportFormat,
        keystoreFile:     File,
        keystorePassword: CharArray
    ) {
        // ── 1. Determine output filename + extension ───────────────────────
        val suggestedName = ExportService.suggestedFileName(entry.alias, format)
        val extension     = suggestedName.substringAfterLast('.', "")

        // ── 2. FileSaverDialog ────────────────────────────────────────────
        val descriptor = FileSaverDescriptor(
            exportDialogTitle(format),
            exportDialogDescription(format),
            extension
        )

        val wrapper = FileChooserFactory.getInstance()
            .createSaveFileDialog(descriptor, project)
            .save(suggestedName)
            ?: return  // user cancelled

        val destinationFile = wrapper.file.let { f ->
            // FileSaver may not add the extension when the user doesn't type it
            if (f.name.contains('.')) f else File(f.parentFile, "${f.name}.$extension")
        }

        // ── 3. For PKCS12: prompt for export password ─────────────────────
        val exportPassword: CharArray? = if (format == ExportFormat.PKCS12) {
            val dialog = ExportPasswordDialog(project, destinationFile.name)
            if (!dialog.showAndGet()) return
            dialog.exportPassword
        } else {
            null
        }

        // ── 4. Run export in background ───────────────────────────────────
        ProgressManager.getInstance().run(object : Task.Backgroundable(
            project,
            "Exporting '${entry.alias}' to '${destinationFile.name}'…",
            false
        ) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true

                val result = ExportService.export(
                    keystoreFile     = keystoreFile,
                    keystorePassword = keystorePassword,
                    alias            = entry.alias,
                    format           = format,
                    destination      = destinationFile,
                    exportPassword   = exportPassword
                )

                ApplicationManager.getApplication().invokeLater {
                    handleResult(result, entry.alias, project)
                }
            }
        })
    }

    // ─── Result handler ───────────────────────────────────────────────────────

    private fun handleResult(result: ExportResult, alias: String, project: Project) {
        when (result) {
            is ExportResult.Success -> {
                // Refresh VFS so the file is immediately visible in the project tree
                val vf = LocalFileSystem.getInstance()
                    .refreshAndFindFileByIoFile(result.exportedFile)

                val fileLink = if (vf != null)
                    "<a href='open:${result.exportedFile.absolutePath}'>${result.exportedFile.name}</a>"
                else
                    result.exportedFile.name

                val notification = NotificationGroupManager.getInstance()
                    .getNotificationGroup("Key Inspector")
                    .createNotification(
                        "Export successful",
                        "Entry <b>$alias</b> exported to $fileLink.",
                        NotificationType.INFORMATION
                    )

                // Clickable link: open the file in the IDE editor
                if (vf != null) {
                    notification.addAction(
                        com.intellij.notification.NotificationAction.createSimple("Open file") {
                            com.intellij.openapi.fileEditor.FileEditorManager
                                .getInstance(project)
                                .openFile(vf, true)
                        }
                    )
                }

                notification.notify(project)
            }

            is ExportResult.Error ->
                Messages.showErrorDialog(
                    project,
                    result.reason,
                    "Export Failed — $alias"
                )
        }
    }

    // ─── Dialog strings ───────────────────────────────────────────────────────

    private fun exportDialogTitle(format: ExportFormat) = when (format) {
        ExportFormat.CERT_PEM  -> "Export Certificate as PEM"
        ExportFormat.CERT_DER  -> "Export Certificate as DER"
        ExportFormat.CHAIN_PEM -> "Export Certificate Chain as PEM"
        ExportFormat.PKCS12    -> "Export Entry as PKCS#12"
    }

    private fun exportDialogDescription(format: ExportFormat) = when (format) {
        ExportFormat.CERT_PEM  -> "Save the end-entity certificate in PEM format (.pem)"
        ExportFormat.CERT_DER  -> "Save the end-entity certificate in DER binary format (.der)"
        ExportFormat.CHAIN_PEM -> "Save the full certificate chain in PEM format (.pem)"
        ExportFormat.PKCS12    -> "Save the private key and certificate chain in a PKCS#12 bundle (.p12)"
    }
}
