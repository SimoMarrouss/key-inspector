package com.usehashmap.keyinspector.ui

import com.usehashmap.keyinspector.model.KeyEntry
import com.usehashmap.keyinspector.model.LoadedFile
import com.usehashmap.keyinspector.service.KeystoreService
import com.usehashmap.keyinspector.service.LoadResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.File

/** Models the current state of the Key Inspector tool window. */
sealed class InspectorUiState {
    object Empty : InspectorUiState()
    object Loading : InspectorUiState()
    data class Loaded(val loadedFile: LoadedFile, val selectedEntry: KeyEntry? = null) : InspectorUiState()
    object PasswordRequired : InspectorUiState()
    data class Error(val title: String, val message: String) : InspectorUiState()
}

/**
 * Reactive state holder for the Key Inspector tool window.
 * All state mutations happen on a background dispatcher; Compose collects from the main thread.
 */
class KeyInspectorState(private val scope: CoroutineScope) {

    private val _uiState = MutableStateFlow<InspectorUiState>(InspectorUiState.Empty)
    val uiState: StateFlow<InspectorUiState> = _uiState

    /** The file currently being inspected (needed to retry with password and for import). */
    private var currentFile: File? = null

    /** The last password that opened the current keystore successfully (used to pre-fill import). */
    private var lastPassword: CharArray? = null

    /** Public read-only view of the current keystore file path. */
    val currentKeystoreFile: File? get() = currentFile

    /** Public read-only view of the last successful keystore password. */
    val currentKeystorePassword: CharArray? get() = lastPassword

    fun openFile(file: File, password: CharArray? = null) {
        currentFile = file
        _uiState.value = InspectorUiState.Loading
        scope.launch(Dispatchers.IO) {
            val result = KeystoreService.load(file, password)
            _uiState.value = when (result) {
                is LoadResult.Success -> {
                    lastPassword = password
                    InspectorUiState.Loaded(result.file)
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

    fun refresh() {
        currentFile?.let { openFile(it) }
    }

    fun reset() {
        currentFile = null
        _uiState.value = InspectorUiState.Empty
    }

    /**
     * Called after a successful password change so the state tracks the new credential
     * and the viewer reloads cleanly with the updated password.
     */
    fun updatePassword(newPassword: CharArray) {
        lastPassword = newPassword
        currentFile?.let { openFile(it, newPassword) }
    }
}
