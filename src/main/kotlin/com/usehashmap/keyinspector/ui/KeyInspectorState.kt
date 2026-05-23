package com.usehashmap.keyinspector.ui

import com.usehashmap.keyinspector.model.KeyEntry
import com.usehashmap.keyinspector.model.LoadedFile
import com.usehashmap.keyinspector.service.KeystoreEntryService
import com.usehashmap.keyinspector.service.EntryOperationResult
import com.usehashmap.keyinspector.service.ExportFormat
import com.usehashmap.keyinspector.service.ExportResult
import com.usehashmap.keyinspector.service.ExportService
import com.usehashmap.keyinspector.service.KeystoreService
import com.usehashmap.keyinspector.service.LoadResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Models the current state of the Key Inspector tool window. */
sealed class InspectorUiState {
    object Empty : InspectorUiState()
    object Loading : InspectorUiState()
    data class Loaded(
        val loadedFile: LoadedFile,
        val rawView: RawViewContent,
        val viewMode: ViewMode = ViewMode.INSPECTOR,
        val selectedEntry: KeyEntry? = null
    ) : InspectorUiState()
    object PasswordRequired : InspectorUiState()
    data class Error(val title: String, val message: String) : InspectorUiState()
}

enum class ViewMode { INSPECTOR, RAW }

data class RawViewContent(
    val formatLabel: String,
    val description: String,
    val content: String,
    val truncated: Boolean
)

/**
 * Reactive state holder for the Key Inspector tool window.
 * All state mutations happen on a background dispatcher; Compose collects from the main thread.
 */
class KeyInspectorState(val scope: CoroutineScope) {

    private val _uiState = MutableStateFlow<InspectorUiState>(InspectorUiState.Empty)
    val uiState: StateFlow<InspectorUiState> = _uiState

    /** The file currently being inspected (needed to retry with password and for import). */
    private var currentFile: File? = null

    /** The last password that opened the current keystore successfully (used to pre-fill import). */
    private var lastPassword: CharArray? = null

    /** Public read-only view of the current keystore file path. */
    val currentKeystoreFile: File? get() = currentFile

    /** Public read-only view of the last successful keystore password. */
    val currentKeystorePassword: CharArray? get() = lastPassword?.copyOf()

    fun openFile(file: File, password: CharArray? = null) {
        val previousLoaded = _uiState.value as? InspectorUiState.Loaded
        val sameFileAsCurrent = currentFile?.absolutePath == file.absolutePath
        val previousMode = previousLoaded
            ?.takeIf { it.loadedFile.filePath == file.absolutePath }
            ?.viewMode
            ?: ViewMode.INSPECTOR
        val previousSelectedAlias = previousLoaded
            ?.takeIf { it.loadedFile.filePath == file.absolutePath }
            ?.selectedEntry
            ?.alias

        if (!sameFileAsCurrent) {
            lastPassword = null
        }

        currentFile = file
        _uiState.value = InspectorUiState.Loading
        scope.launch(Dispatchers.IO) {
            val result = KeystoreService.load(file, password)
            _uiState.value = when (result) {
                is LoadResult.Success -> {
                    lastPassword = password?.copyOf()
                    InspectorUiState.Loaded(
                        loadedFile = result.file,
                        rawView = buildRawView(file),
                        viewMode = previousMode,
                        selectedEntry = previousSelectedAlias?.let { alias ->
                            result.file.entries.firstOrNull { it.alias == alias }
                        }
                    )
                }
                is LoadResult.Failure.PasswordRequired ->
                    InspectorUiState.PasswordRequired
                is LoadResult.Failure.WrongPassword ->
                    InspectorUiState.Error("Wrong Password", result.message)
                is LoadResult.Failure.Unsupported ->
                    InspectorUiState.Error("Unsupported Format", result.message)
                is LoadResult.Failure.GenericError ->
                    InspectorUiState.Error("Load Error", result.message)
            }
        }
    }

    fun retryWithPassword(password: CharArray) {
        currentFile?.let { openFile(it, password) }
    }

    fun selectEntry(entry: KeyEntry) {
        val current = _uiState.value
        if (current is InspectorUiState.Loaded) {
            _uiState.value = current.copy(selectedEntry = entry)
        }
    }

    fun setViewMode(viewMode: ViewMode) {
        val current = _uiState.value
        if (current is InspectorUiState.Loaded) {
            _uiState.value = current.copy(viewMode = viewMode)
        }
    }

    /**
     * Deletes [alias] from the current keystore on a background thread.
     * Returns the [EntryOperationResult] on the calling coroutine (caller decides how to show errors).
     */
    suspend fun deleteEntry(alias: String): EntryOperationResult {
        val file = currentFile ?: return EntryOperationResult.WriteError("No file loaded.")
        val pwd  = lastPassword ?: CharArray(0)
        return kotlinx.coroutines.withContext(Dispatchers.IO) {
            KeystoreEntryService.deleteEntry(file, pwd, alias)
        }
    }

    /**
     * Renames [oldAlias] to [newAlias] in the current keystore on a background thread.
     */
    suspend fun renameEntry(oldAlias: String, newAlias: String): EntryOperationResult {
        val file = currentFile ?: return EntryOperationResult.WriteError("No file loaded.")
        val pwd  = lastPassword ?: CharArray(0)
        return kotlinx.coroutines.withContext(Dispatchers.IO) {
            KeystoreEntryService.renameEntry(file, pwd, oldAlias, newAlias)
        }
    }

    /**
     * Exports the entry with [alias] to [destination] using [format].
     * Must be called on a background thread (already handled by callers via ProgressManager).
     */
    fun exportEntry(
        alias:          String,
        format: ExportFormat,
        destination:    java.io.File,
        exportPassword: CharArray? = null
    ): ExportResult {
        val file = currentFile ?: return ExportResult.Error("No keystore file is currently loaded.")
        val pwd  = lastPassword ?: CharArray(0)
        return ExportService.export(
            keystoreFile     = file,
            keystorePassword = pwd,
            alias            = alias,
            format           = format,
            destination      = destination,
            exportPassword   = exportPassword
        )
    }

    fun refresh() {
        currentFile?.let { openFile(it, lastPassword) }
    }

    fun reset() {
        currentFile = null
        lastPassword = null
        _uiState.value = InspectorUiState.Empty
    }

    /**
     * Called after a successful password change so the state tracks the new credential
     * and the viewer reloads cleanly with the updated password.
     */
    fun updatePassword(newPassword: CharArray) {
        lastPassword = newPassword.copyOf()
        currentFile?.let { openFile(it, newPassword) }
    }

    private fun buildRawView(file: File): RawViewContent {
        val maxBytes = 64 * 1024
        val bytes = file.inputStream().use { input ->
            input.readNBytes(maxBytes + 1)
        }
        val truncated = bytes.size > maxBytes
        val visibleBytes = if (truncated) bytes.copyOf(maxBytes) else bytes
        val text = decodeUtf8OrNull(visibleBytes)

        return if (text != null && looksTextual(text)) {
            RawViewContent(
                formatLabel = "Raw Text",
                description = "Original file content as stored on disk.",
                content = text,
                truncated = truncated
            )
        } else {
            val base64 = Base64.getMimeEncoder(64, "\n".toByteArray())
                .encodeToString(visibleBytes)
            val hex = visibleBytes.toHexDump()
            RawViewContent(
                formatLabel = "Raw Binary",
                description = "Binary preview shown as hex dump and Base64.",
                content = buildString {
                    appendLine("HEX")
                    appendLine(hex)
                    appendLine()
                    appendLine("BASE64")
                    append(base64)
                },
                truncated = truncated
            )
        }
    }

    private fun decodeUtf8OrNull(bytes: ByteArray): String? {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            null
        }
    }

    private fun looksTextual(text: String): Boolean {
        if (text.isEmpty()) return true
        val printable = text.count { it == '\n' || it == '\r' || it == '\t' || !it.isISOControl() }
        return printable.toDouble() / text.length >= 0.90
    }

    private fun ByteArray.toHexDump(): String = buildString {
        for (offset in indices step 16) {
            append("%08x  ".format(offset))
            val end = minOf(offset + 16, size)
            append((offset until end).joinToString(" ") { index ->
                "%02x".format(this@toHexDump[index].toInt() and 0xff)
            })
            appendLine()
        }
    }
}
