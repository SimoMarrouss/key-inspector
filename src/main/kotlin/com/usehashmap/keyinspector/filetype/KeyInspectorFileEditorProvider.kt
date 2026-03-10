package com.usehashmap.keyinspector.filetype

import com.intellij.openapi.fileEditor.FileEditor
import com.intellij.openapi.fileEditor.FileEditorPolicy
import com.intellij.openapi.fileEditor.FileEditorProvider
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

/**
 * Provides a [KeyInspectorFileEditor] for every keystore / certificate file
 * opened from the project tree (or anywhere else in the IDE).
 *
 * [FileEditorPolicy.HIDE_DEFAULT_EDITOR] ensures that the binary/text default
 * editor is replaced by our inspector view.
 */
class KeyInspectorFileEditorProvider : FileEditorProvider, DumbAware {

    override fun getEditorTypeId(): String = "key-inspector-editor"

    override fun accept(project: Project, file: VirtualFile): Boolean =
        KeyInspectorFileType.accepts(file)

    override fun createEditor(project: Project, file: VirtualFile): FileEditor =
        KeyInspectorFileEditor(project, file)

    override fun getPolicy(): FileEditorPolicy = FileEditorPolicy.HIDE_DEFAULT_EDITOR
}
