package com.usehashmap.keyinspector.filetype

import com.intellij.openapi.fileTypes.FileType
import com.intellij.openapi.vfs.VirtualFile
import javax.swing.Icon

/**
 * Represents all keystore / certificate / key file types handled by Key Inspector.
 * Files are associated by extension; no binary sniffing is done here – that is
 * left to the service layer which already handles detection gracefully.
 */
object KeyInspectorFileType : FileType {

    val SUPPORTED_EXTENSIONS = setOf(
        // Keystores
        "jks", "jceks", "bks", "p12", "pfx", "uber", "bcfks",
        // Certificates / chains
        "pem", "cer", "crt", "p7", "p7b", "pkipath", "spc",
        // Keys
        "pub", "key", "pkcs8", "pvk",
        // Misc
        "p10", "spkac", "crl"
    )

    override fun getName(): String = "Keystore / Certificate"
    override fun getDescription(): String =
        "Keystore, certificate, key or CRL file inspectable by Key Inspector"
    override fun getDefaultExtension(): String = "pem"
    override fun getIcon(): Icon? = null
    override fun isBinary(): Boolean = false
    override fun isReadOnly(): Boolean = true

    fun accepts(file: VirtualFile): Boolean =
        file.extension?.lowercase() in SUPPORTED_EXTENSIONS
}
