package com.usehashmap.keyinspector.actions

import com.intellij.openapi.fileChooser.FileChooserDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.ui.TextFieldWithBrowseButton
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import com.usehashmap.keyinspector.service.ImportService
import java.awt.Dimension
import java.io.File
import javax.swing.JComponent

/**
 * Dialog that collects everything needed to import a certificate or key pair
 * into an existing keystore.
 *
 * @param project          current IDE project (used for the file chooser)
 * @param keystoreFile     the target keystore; if null the user fills in the path
 * @param keystorePassword pre-filled keystore password (e.g. from the current view)
 */
class ImportCertDialog(
    project: Project,
    keystoreFile: File? = null,
    keystorePassword: CharArray? = null
) : DialogWrapper(project, /* canBeParent = */ true) {

    // ─── Widgets ──────────────────────────────────────────────────────────────

    private val keystorePathField = TextFieldWithBrowseButton().apply {
        addBrowseFolderListener(
            project,
            FileChooserDescriptor(true, false, false, false, false, false).apply {
                withFileFilter { vf ->
                    vf.isDirectory || vf.extension?.lowercase() in KEYSTORE_EXTENSIONS
                }
                title       = "Select Target Keystore"
                description = "JKS, JCEKS, PKCS#12 (p12/pfx), BKS, UBER, BCFKS"
            }
        )
        isEnabled = keystoreFile == null
        text      = keystoreFile?.absolutePath ?: ""
    }

    private val keystorePwdField = JBPasswordField().apply {
        keystorePassword?.let { text = String(it) }
        preferredSize = Dimension(300, preferredSize.height)
    }

    private val sourcePathField = TextFieldWithBrowseButton().apply {
        addBrowseFolderListener(
            project,
            FileChooserDescriptor(true, false, false, false, false, false).apply {
                withFileFilter { vf ->
                    vf.isDirectory || vf.extension?.lowercase() in SOURCE_EXTENSIONS
                }
                title       = "Select Certificate or Key Pair File"
                description = "PEM, CER, CRT, P12, PFX"
            }
        )
    }

    private val sourcePwdField = JBPasswordField().apply {
        preferredSize = Dimension(300, preferredSize.height)
        toolTipText   = "Required only if the source is encrypted (PKCS#12 or encrypted PEM)"
    }

    private val aliasField = JBTextField().apply {
        preferredSize = Dimension(300, preferredSize.height)
    }

    private val keyPwdField = JBPasswordField().apply {
        preferredSize = Dimension(300, preferredSize.height)
        toolTipText   = "Password that will protect the private key entry inside the keystore"
    }

    private val keyPwdConfirmField = JBPasswordField().apply {
        preferredSize = Dimension(300, preferredSize.height)
    }

    private val hintLabel = JBLabel(
        "<html><small style='color:gray'>" +
        "For a certificate-only import, leave the key-password fields blank." +
        "</small></html>"
    )

    // ─── Init ─────────────────────────────────────────────────────────────────

    init {
        title = "Import Certificate / Key Pair"
        setOKButtonText("Import")
        init()
    }

    // ─── DialogWrapper overrides ──────────────────────────────────────────────

    override fun createCenterPanel(): JComponent {
        val form = FormBuilder.createFormBuilder()
            // ── Target keystore ──────────────────────────────────────────────
            .addLabeledComponent(JBLabel("Keystore file:"),     keystorePathField, true)
            .addLabeledComponent(JBLabel("Keystore password:"), keystorePwdField,  true)
            .addSeparator()
            // ── Source file ──────────────────────────────────────────────────
            .addLabeledComponent(JBLabel("Source file (PEM / DER / P12):"),  sourcePathField, true)
            .addLabeledComponent(JBLabel("Source password (if encrypted):"), sourcePwdField,  true)
            .addSeparator()
            // ── Entry settings ───────────────────────────────────────────────
            .addLabeledComponent(JBLabel("Alias:"),                aliasField,         true)
            .addLabeledComponent(JBLabel("Key password:"),         keyPwdField,        true)
            .addLabeledComponent(JBLabel("Confirm key password:"), keyPwdConfirmField, true)
            .addComponent(hintLabel)
            .panel

        form.border = JBUI.Borders.empty(8)
        return form
    }

    override fun doValidate(): ValidationInfo? {
        // Target keystore
        if (keystorePathField.text.isBlank())
            return ValidationInfo("Please select a target keystore file.", keystorePathField)
        val ksFile = File(keystorePathField.text)
        if (!ksFile.isFile)
            return ValidationInfo("Keystore file does not exist.", keystorePathField)

        // Source file
        if (sourcePathField.text.isBlank())
            return ValidationInfo("Please select a source file.", sourcePathField)
        val srcFile = File(sourcePathField.text)
        if (!srcFile.isFile)
            return ValidationInfo("Source file does not exist.", sourcePathField)

        // Alias
        val alias = aliasField.text.trim()
        if (alias.isBlank())
            return ValidationInfo("Alias must not be empty.", aliasField)

        // Alias uniqueness (best-effort, using the password the user has typed)
        val existingAliases = ImportService.existingAliases(ksFile, keystorePwdField.password)
        if (existingAliases.isNotEmpty() && alias in existingAliases)
            return ValidationInfo("Alias '$alias' already exists in the keystore.", aliasField)

        // Key password match
        val pwd1 = keyPwdField.password
        val pwd2 = keyPwdConfirmField.password
        if ((pwd1.isNotEmpty() || pwd2.isNotEmpty()) && !pwd1.contentEquals(pwd2))
            return ValidationInfo("Key passwords do not match.", keyPwdConfirmField)

        return null   // all good
    }

    // ─── Result accessors ─────────────────────────────────────────────────────

    val selectedKeystoreFile: File      get() = File(keystorePathField.text)
    val keystorePasswordChars: CharArray get() = keystorePwdField.password
    val selectedSourceFile: File        get() = File(sourcePathField.text)
    val sourcePasswordChars: CharArray? get() = sourcePwdField.password.takeIf { it.isNotEmpty() }
    val entryAlias: String              get() = aliasField.text.trim()
    val keyPasswordChars: CharArray     get() = keyPwdField.password.let {
        if (it.isEmpty()) keystorePwdField.password else it
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    companion object {
        private val KEYSTORE_EXTENSIONS = setOf("jks", "jceks", "bks", "p12", "pfx", "uber", "bcfks")
        private val SOURCE_EXTENSIONS   = setOf("pem", "cer", "crt", "p12", "pfx", "key", "pub")
    }
}

