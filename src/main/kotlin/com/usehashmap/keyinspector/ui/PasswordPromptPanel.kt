package com.usehashmap.keyinspector.ui

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.intellij.openapi.ui.Messages
import org.jetbrains.jewel.ui.component.OutlinedButton
import org.jetbrains.jewel.ui.component.Text

/**
 * Shows a prompt telling the user the keystore is locked, with an "Unlock" button
 * that triggers IntelliJ's native password dialog (no Compose text input needed).
 */
@Composable
fun PasswordPromptPanel(
    onSubmit: (CharArray) -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Password Required",
            fontWeight = FontWeight.Bold,
            fontSize = 15.sp
        )
        Text(
            text = "This keystore is password-protected.",
            fontSize = 13.sp
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onCancel) { Text("Cancel") }
            OutlinedButton(onClick = {
                // Use IntelliJ's native password dialog — runs on the EDT
                val pwd = Messages.showPasswordDialog(
                    "Enter keystore password:",
                    "Unlock Keystore"
                )
                if (pwd != null) onSubmit(pwd.toCharArray())
            }) { Text("Enter Password…") }
        }
    }
}
