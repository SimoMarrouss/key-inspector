package com.usehashmap.keyinspector.ui

import androidx.compose.foundation.ContextMenuArea
import androidx.compose.foundation.ContextMenuItem
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.usehashmap.keyinspector.model.*
import com.usehashmap.keyinspector.service.ExportFormat
import org.jetbrains.jewel.ui.component.Icon
import org.jetbrains.jewel.ui.component.Text
import org.jetbrains.jewel.ui.icon.IntelliJIconKey
import org.jetbrains.jewel.ui.icons.AllIconsKeys

@Composable
fun EntryListPanel(
    entries: List<KeyEntry>,
    selected: KeyEntry?,
    onSelect: (KeyEntry) -> Unit,
    onDelete: (KeyEntry) -> Unit,
    onRename: (KeyEntry) -> Unit,
    onExport: (KeyEntry, ExportFormat) -> Unit = { _, _ -> },
    modifier: Modifier = Modifier
) {
    LazyColumn(modifier = modifier) {
        items(entries, key = { it.alias }) { entry ->
            EntryRow(
                entry      = entry,
                isSelected = entry == selected,
                onClick    = { onSelect(entry) },
                onDelete   = { onDelete(entry) },
                onRename   = { onRename(entry) },
                onExport   = { fmt -> onExport(entry, fmt) }
            )
        }
    }
}

@Composable
private fun EntryRow(
    entry: KeyEntry,
    isSelected: Boolean,
    onClick: () -> Unit,
    onDelete: () -> Unit,
    onRename: () -> Unit,
    onExport: (ExportFormat) -> Unit
) {
    // Determine which export items apply to this entry type
    val exportItems: List<ContextMenuItem> = buildList {
        val hasChain = entry.entryType == EntryType.PRIVATE_KEY ||
                       entry.entryType == EntryType.TRUSTED_CERT ||
                       entry.entryType == EntryType.CERTIFICATE
        if (hasChain) {
            add(ContextMenuItem("Export Certificate as PEM")       { onExport(ExportFormat.CERT_PEM) })
            add(ContextMenuItem("Export Certificate as DER")       { onExport(ExportFormat.CERT_DER) })
        }
        if (entry.entryType == EntryType.PRIVATE_KEY) {
            add(ContextMenuItem("Export Certificate Chain as PEM") { onExport(ExportFormat.CHAIN_PEM) })
            add(ContextMenuItem("Export as PKCS#12…")              { onExport(ExportFormat.PKCS12) })
        }
    }

    ContextMenuArea(items = {
        buildList {
            add(ContextMenuItem("Rename '${entry.alias}'…") { onRename() })
            add(ContextMenuItem("Delete '${entry.alias}'")  { onDelete() })
            if (exportItems.isNotEmpty()) {
                // ContextMenuItem doesn't support separators directly; add a disabled label as a visual cue
                addAll(exportItems)
            }
        }
    }) {
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
