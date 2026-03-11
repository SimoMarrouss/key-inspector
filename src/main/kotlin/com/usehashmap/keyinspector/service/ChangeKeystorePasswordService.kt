package com.usehashmap.keyinspector.service

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.UnrecoverableKeyException

/** Outcome of a keystore password-change operation. */
sealed class ChangePasswordResult {
    object Success : ChangePasswordResult()
    data class WrongCurrentPassword(val reason: String) : ChangePasswordResult()
    data class WriteError(val reason: String) : ChangePasswordResult()
}

/**
 * Re-saves [keystoreFile] using [newPassword] after verifying [currentPassword].
 *
 * The keystore type is inferred from the file extension, exactly as in [KeystoreService].
 * All existing entries (private keys, trusted certs, secret keys) are re-protected
 * with [newPassword].  Pass an empty [newPassword] to remove the password entirely.
 *
 * Note: entry-level key passwords (inside the keystore) are NOT changed here —
 * only the outer keystore-store password is updated.
 */
object ChangeKeystorePasswordService {

    fun changePassword(
        keystoreFile: File,
        currentPassword: CharArray,
        newPassword: CharArray
    ): ChangePasswordResult {
        val type = ExtensionMapper.keystoreType(keystoreFile.extension.lowercase()) ?: "JKS"

        // 1. Open with the current password ───────────────────────────────────
        val ks = try {
            val store = KeyStore.getInstance(type)
            FileInputStream(keystoreFile).use { store.load(it, currentPassword) }
            store
        } catch (e: UnrecoverableKeyException) {
            return ChangePasswordResult.WrongCurrentPassword(e.message ?: "Wrong password")
        } catch (e: java.io.IOException) {
            val msg = e.message ?: ""
            return if (msg.contains("password", ignoreCase = true) ||
                       msg.contains("MAC",      ignoreCase = false) ||
                       msg.contains("failed to decrypt", ignoreCase = true))
                ChangePasswordResult.WrongCurrentPassword(msg)
            else
                ChangePasswordResult.WriteError("Cannot open keystore: $msg")
        } catch (e: Exception) {
            return ChangePasswordResult.WriteError("Cannot open keystore: ${e.message}")
        }

        // 2. Re-save with the new password ─────────────────────────────────────
        return try {
            FileOutputStream(keystoreFile).use { ks.store(it, newPassword) }
            ChangePasswordResult.Success
        } catch (e: Exception) {
            ChangePasswordResult.WriteError("Could not save keystore: ${e.message}")
        }
    }
}
