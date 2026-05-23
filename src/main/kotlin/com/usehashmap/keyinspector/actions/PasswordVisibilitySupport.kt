package com.usehashmap.keyinspector.actions

import javax.swing.JCheckBox
import javax.swing.JPasswordField

/**
 * Creates a checkbox that toggles visibility for one or more password fields.
 */
internal fun createShowPasswordsCheckBox(
    label: String = "Show passwords",
    vararg fields: JPasswordField
): JCheckBox {
    val originalEchoChars = fields.associateWith { it.echoChar }
    return JCheckBox(label).apply {
        addActionListener {
            val showPasswords = isSelected
            fields.forEach { field ->
                field.echoChar = if (showPasswords) 0.toChar() else originalEchoChars.getValue(field)
            }
        }
    }
}
