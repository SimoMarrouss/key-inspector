package com.usehashmap.keyinspector.ui

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.jetbrains.jewel.ui.component.Checkbox
import org.jetbrains.jewel.ui.component.DefaultButton
import org.jetbrains.jewel.ui.component.OutlinedButton
import org.jetbrains.jewel.ui.component.Text
import org.jetbrains.jewel.ui.component.TextField

/**
 * Shows an inline password input with a "Show password" checkbox.
 */
@Composable
fun PasswordPromptPanel(
    onSubmit: (CharArray) -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier
) {
    var password by remember { mutableStateOf(TextFieldValue("")) }
    var showPassword by remember { mutableStateOf(false) }

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

        TextField(
            value = password,
            onValueChange = { password = it },
            visualTransformation = if (showPassword) VisualTransformation.None
                                   else PasswordVisualTransformation(),
            modifier = Modifier.width(280.dp)
        )

        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Checkbox(
                checked = showPassword,
                onCheckedChange = { showPassword = it }
            )
            Text("Show password")
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onCancel) { Text("Cancel") }
            DefaultButton(
                onClick = { onSubmit(password.text.toCharArray()) },
                enabled = password.text.isNotEmpty()
            ) { Text("Unlock") }
        }
    }
}
