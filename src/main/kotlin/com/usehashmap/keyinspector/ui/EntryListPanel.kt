package com.usehashmap.keyinspector.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.usehashmap.keyinspector.model.*
import org.jetbrains.jewel.ui.component.Icon
import org.jetbrains.jewel.ui.component.Text
import org.jetbrains.jewel.ui.icon.IntelliJIconKey
import org.jetbrains.jewel.ui.icons.AllIconsKeys

@Composable
fun EntryListPanel(
    entries: List<KeyEntry>,
    selected: KeyEntry?,
    onSelect: (KeyEntry) -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(modifier = modifier) {
        items(entries, key = { it.alias }) { entry ->
            EntryRow(
                entry      = entry,
                isSelected = entry == selected,
                onClick    = { onSelect(entry) }
            )
        }
    }
}

@Composable
private fun EntryRow(entry: KeyEntry, isSelected: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        EntryTypeIcon(entry.entryType)
        Column {
            Text(
                text       = entry.alias,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                fontSize   = 13.sp
            )
            Text(
                text     = entry.entryType.displayName,
                fontSize = 11.sp
            )
        }
    }
}

@Composable
private fun EntryTypeIcon(type: EntryType) {
    val iconKey: IntelliJIconKey = when (type) {
        EntryType.PRIVATE_KEY       -> AllIconsKeys.Nodes.KeymapOther
        EntryType.TRUSTED_CERT      -> AllIconsKeys.Nodes.Padlock
        EntryType.SECRET_KEY        -> AllIconsKeys.Nodes.KeymapOther
        EntryType.CERTIFICATE       -> AllIconsKeys.Nodes.Padlock
        EntryType.CRL               -> AllIconsKeys.Nodes.ExceptionClass
        EntryType.CSR               -> AllIconsKeys.Nodes.NewParameter
        EntryType.PUBLIC_KEY        -> AllIconsKeys.Nodes.KeymapOther
        EntryType.PRIVATE_KEY_BARE  -> AllIconsKeys.Nodes.Locked
        EntryType.UNKNOWN           -> AllIconsKeys.Nodes.Unknown
    }
    Icon(
        key                = iconKey,
        contentDescription = type.displayName,
        modifier           = Modifier.size(16.dp)
    )
}


