package com.usehashmap.keyinspector.service

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore

// ─── Result types ──────────────────────────────────────────────────────────────

sealed class EntryOperationResult {
    object Success : EntryOperationResult()
    data class AliasNotFound(val alias: String) : EntryOperationResult()
    data class AliasAlreadyExists(val alias: String) : EntryOperationResult()
    data class WrongPassword(val reason: String) : EntryOperationResult()
    data class WriteError(val reason: String) : EntryOperationResult()
}

// ─── Service ──────────────────────────────────────────────────────────────────

object KeystoreEntryService {

    private val BC_TYPES = setOf("BKS", "UBER", "BCFKS")

    /**
     * Deletes the entry with [alias] from [keystoreFile] and writes the result back to disk.
     */
    fun deleteEntry(
        keystoreFile: File,
        password: CharArray,
        alias: String
    ): EntryOperationResult {
        val ks = openKeystore(keystoreFile, password)
            ?: return EntryOperationResult.WrongPassword("Could not open keystore — check password.")

        if (!ks.containsAlias(alias))
            return EntryOperationResult.AliasNotFound(alias)

        ks.deleteEntry(alias)
        return saveKeystore(ks, keystoreFile, password)
    }

    /**
     * Renames the entry with [oldAlias] to [newAlias] inside [keystoreFile].
     * All key material and certificate chains are preserved exactly.
     *
     * Note: JKS/PKCS12 have no native "rename" — we copy under the new alias then delete the old one.
     * For private-key entries the key password must be supplied; if [entryPassword] is null the
     * keystore password is tried as a fallback.
     */
    fun renameEntry(
        keystoreFile: File,
        password: CharArray,
        oldAlias: String,
        newAlias: String,
        entryPassword: CharArray? = null
    ): EntryOperationResult {
        if (oldAlias == newAlias) return EntryOperationResult.Success

        val ks = openKeystore(keystoreFile, password)
            ?: return EntryOperationResult.WrongPassword("Could not open keystore — check password.")

        if (!ks.containsAlias(oldAlias))
            return EntryOperationResult.AliasNotFound(oldAlias)

        if (ks.containsAlias(newAlias))
            return EntryOperationResult.AliasAlreadyExists(newAlias)

        val keyPwd = entryPassword ?: password

        when {
            ks.isKeyEntry(oldAlias) -> {
                // Retrieve private key — try supplied entry password, then keystore password
                val key = try {
                    ks.getKey(oldAlias, keyPwd)
                } catch (_: Exception) {
                    try { ks.getKey(oldAlias, password) }
                    catch (e: Exception) {
                        return EntryOperationResult.WriteError(
                            "Could not retrieve key for '$oldAlias': ${e.message}"
                        )
                    }
                }
                val chain = ks.getCertificateChain(oldAlias)
                ks.setKeyEntry(newAlias, key, keyPwd, chain)
                ks.deleteEntry(oldAlias)
            }
            ks.isCertificateEntry(oldAlias) -> {
                val cert = ks.getCertificate(oldAlias)
                ks.setCertificateEntry(newAlias, cert)
                ks.deleteEntry(oldAlias)
            }
            else -> return EntryOperationResult.WriteError("Unknown entry type for alias '$oldAlias'.")
        }

        return saveKeystore(ks, keystoreFile, password)
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private fun openKeystore(file: File, password: CharArray): KeyStore? {
        val type = ExtensionMapper.keystoreType(file.extension.lowercase()) ?: "JKS"
        return try {
            val ks = if (type.uppercase() in BC_TYPES)
                KeyStore.getInstance(type, BouncyCastleProvider())
            else
                KeyStore.getInstance(type)
            FileInputStream(file).use { ks.load(it, password) }
            ks
        } catch (_: Exception) { null }
    }

    private fun saveKeystore(
        ks: KeyStore,
        file: File,
        password: CharArray
    ): EntryOperationResult = try {
        FileOutputStream(file).use { ks.store(it, password) }
        EntryOperationResult.Success
    } catch (e: Exception) {
        EntryOperationResult.WriteError("Could not save keystore: ${e.message}")
    }
}
