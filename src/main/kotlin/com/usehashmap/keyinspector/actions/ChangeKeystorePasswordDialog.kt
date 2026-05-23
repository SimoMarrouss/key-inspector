package com.usehashmap.keyinspector.actions

import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import java.awt.Dimension
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.event.ChangeEvent

/**
 * Dialog that collects the credentials needed to change or remove a keystore password.
 *
 * When "Remove password (set empty)" is checked the new-password fields are disabled
 * and the operation will write the keystore with an empty password.
 */
class ChangeKeystorePasswordDialog(project: Project) : DialogWrapper(project, true) {

    // ─── Widgets ──────────────────────────────────────────────────────────────

    private val currentPwdField = JBPasswordField().apply {
        preferredSize = Dimension(320, preferredSize.height)
        toolTipText   = "Leave blank if the keystore has no password"
    }

    private val newPwdField = JBPasswordField().apply {
        preferredSize = Dimension(320, preferredSize.height)
        toolTipText   = "Leave blank to set an empty password"
    }

    private val confirmPwdField = JBPasswordField().apply {
        preferredSize = Dimension(320, preferredSize.height)
    }

    private val showPasswordsCheckBox = createShowPasswordsCheckBox(
        "Show passwords",
        currentPwdField,
        newPwdField,
        confirmPwdField
    )

    private val removePasswordCheckBox = JCheckBox("Remove password (set empty keystore password)").apply {
        addChangeListener { _: ChangeEvent ->
            val remove = isSelected
            newPwdField.isEnabled     = !remove
            confirmPwdField.isEnabled = !remove
        }
    }

    // ─── Init ─────────────────────────────────────────────────────────────────

    init {
        title = "Change / Remove Keystore Password"
        setOKButtonText("Apply")
        init()
    }

    // ─── DialogWrapper ────────────────────────────────────────────────────────

    override fun createCenterPanel(): JComponent {
        val currentPwdHint = JBLabel(
            "<html><small style='color:gray'>Leave blank if the keystore is not password-protected.</small></html>"
        )

        val form = FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Current password:"),     currentPwdField,        true)
            .addComponent(currentPwdHint)
            .addSeparator()
            .addComponent(removePasswordCheckBox)
            .addLabeledComponent(JBLabel("New password:"),         newPwdField,            true)
            .addLabeledComponent(JBLabel("Confirm new password:"), confirmPwdField,        true)
            .addComponent(showPasswordsCheckBox)
            .addComponentFillVertically(javax.swing.JPanel(), 0)
            .panel

        form.border = JBUI.Borders.empty(8)
        return form
    }

    override fun doValidate(): ValidationInfo? {
        // Current password may be empty — that is valid for unprotected keystores.
        // The service will return WrongCurrentPassword if it turns out to be wrong.

        if (!removePasswordCheckBox.isSelected) {
            val p1 = newPwdField.password
            val p2 = confirmPwdField.password
            if (!p1.contentEquals(p2))
                return ValidationInfo("New passwords do not match.", confirmPwdField)
        }
        return null
    }

    // ─── Result accessors ─────────────────────────────────────────────────────

    /** Password currently protecting the keystore. */
    val currentPassword: CharArray get() = currentPwdField.password

    /**
     * The new password to apply.  Returns an empty array when
     * "Remove password" is checked (meaning: store with no password).
     */
    val newPassword: CharArray
        get() = if (removePasswordCheckBox.isSelected) CharArray(0) else newPwdField.password

    val isRemovePassword: Boolean get() = removePasswordCheckBox.isSelected
}
