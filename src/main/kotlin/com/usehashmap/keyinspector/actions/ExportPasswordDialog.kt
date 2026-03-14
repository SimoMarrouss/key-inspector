package com.usehashmap.keyinspector.actions

import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import java.awt.Dimension
import javax.swing.JComponent

/**
 * Minimal password dialog used when exporting a PKCS#12 file.
 * Prompts for a new password + confirmation.
 */
class ExportPasswordDialog(
    project: Project,
    private val exportFileName: String
) : DialogWrapper(project, true) {

    private val pwdField = JBPasswordField().apply {
        preferredSize = Dimension(320, preferredSize.height)
        toolTipText   = "Password to protect the exported PKCS#12 file"
    }

    private val confirmField = JBPasswordField().apply {
        preferredSize = Dimension(320, preferredSize.height)
    }

    init {
        title = "Set Export Password — $exportFileName"
        setOKButtonText("Export")
        init()
    }

    override fun createCenterPanel(): JComponent {
        val hint = JBLabel(
            "<html><small style='color:gray'>" +
            "The exported PKCS#12 file will be protected with this password." +
            "</small></html>"
        )
        val form = FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Export password:"), pwdField,      true)
            .addLabeledComponent(JBLabel("Confirm password:"), confirmField, true)
            .addComponent(hint)
            .addComponentFillVertically(javax.swing.JPanel(), 0)
            .panel
        form.border = JBUI.Borders.empty(8)
        return form
    }

    override fun doValidate(): ValidationInfo? {
        val pwd     = pwdField.password
        val confirm = confirmField.password
        return when {
            pwd.isEmpty()              -> ValidationInfo("Export password must not be empty.", pwdField)
            !pwd.contentEquals(confirm) -> ValidationInfo("Passwords do not match.", confirmField)
            else                       -> null
        }
    }

    override fun getPreferredFocusedComponent(): JComponent = pwdField

    /** Returns the entered password. Only valid after [showAndGet] returns true. */
    val exportPassword: CharArray get() = pwdField.password
}
