package com.usehashmap.keyinspector.service

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.StringWriter
import java.security.KeyStore
import java.security.cert.X509Certificate

// ─── Result ────────────────────────────────────────────────────────────────────

sealed class ExportResult {
    data class Success(val exportedFile: File) : ExportResult()
    data class Error(val reason: String) : ExportResult()
}

// ─── Export format ─────────────────────────────────────────────────────────────

enum class ExportFormat { CERT_PEM, CERT_DER, CHAIN_PEM, PKCS12 }

// ─── Service ──────────────────────────────────────────────────────────────────

object ExportService {

    /**
     * Export an entry from [keystoreFile] identified by [alias].
     *
     * @param keystoreFile     the source keystore
     * @param keystorePassword password to open it
     * @param alias            the entry alias to export
     * @param format           which export format to produce
     * @param destination      the output file to write
     * @param exportPassword   required for [ExportFormat.PKCS12]; ignored otherwise
     */
    fun export(
        keystoreFile:     File,
        keystorePassword: CharArray,
        alias:            String,
        format:           ExportFormat,
        destination:      File,
        exportPassword:   CharArray? = null
    ): ExportResult {
        val ks = try {
            openKeystore(keystoreFile, keystorePassword)
        } catch (e: Exception) {
            return ExportResult.Error("Cannot open keystore: ${e.message}")
        }

        return when (format) {
            ExportFormat.CERT_PEM   -> exportCertPem(ks, alias, destination)
            ExportFormat.CERT_DER   -> exportCertDer(ks, alias, destination)
            ExportFormat.CHAIN_PEM  -> exportChainPem(ks, alias, destination)
            ExportFormat.PKCS12     -> exportPkcs12(ks, alias, keystorePassword, destination, exportPassword)
        }
    }

    // ─── Format-specific writers ──────────────────────────────────────────────

    private fun exportCertPem(ks: KeyStore, alias: String, dest: File): ExportResult {
        val cert = ks.getCertificate(alias) as? X509Certificate
            ?: return ExportResult.Error("No certificate found for alias '$alias'.")
        return try {
            writePemObjects(dest, listOf(JcaX509CertificateHolder(cert)))
            ExportResult.Success(dest)
        } catch (e: Exception) {
            ExportResult.Error("PEM write failed: ${e.message}")
        }
    }

    private fun exportCertDer(ks: KeyStore, alias: String, dest: File): ExportResult {
        val cert = ks.getCertificate(alias) as? X509Certificate
            ?: return ExportResult.Error("No certificate found for alias '$alias'.")
        return try {
            FileOutputStream(dest).use { it.write(cert.encoded) }
            ExportResult.Success(dest)
        } catch (e: Exception) {
            ExportResult.Error("DER write failed: ${e.message}")
        }
    }

    private fun exportChainPem(ks: KeyStore, alias: String, dest: File): ExportResult {
        val chain = ks.getCertificateChain(alias)
            ?: return ExportResult.Error(
                "No certificate chain found for alias '$alias'. " +
                "Only private-key entries have a chain — for a trusted certificate use 'Export Certificate as PEM'."
            )
        if (chain.isEmpty()) return ExportResult.Error("Certificate chain is empty for alias '$alias'.")
        return try {
            val holders = chain.map { JcaX509CertificateHolder(it as X509Certificate) }
            writePemObjects(dest, holders)
            ExportResult.Success(dest)
        } catch (e: Exception) {
            ExportResult.Error("PEM chain write failed: ${e.message}")
        }
    }

    /**
     * Exports a private-key entry as a PKCS#12 file protected by [exportPassword].
     * The full certificate chain is included.
     */
    private fun exportPkcs12(
        ks:             KeyStore,
        alias:          String,
        keystorePwd:    CharArray,
        dest:           File,
        exportPassword: CharArray?
    ): ExportResult {
        if (!ks.isKeyEntry(alias))
            return ExportResult.Error(
                "Alias '$alias' is not a private-key entry. " +
                "PKCS#12 export is only available for private-key entries."
            )

        val pwd = exportPassword
            ?: return ExportResult.Error("An export password is required for PKCS#12 export.")

        val privateKey = try {
            // Try the keystore password as the entry password (standard for JKS/PKCS12)
            ks.getKey(alias, keystorePwd)
        } catch (_: Exception) {
            return ExportResult.Error("Could not retrieve private key for '$alias' — wrong entry password?")
        } ?: return ExportResult.Error("No private key found for alias '$alias'.")

        val chain = ks.getCertificateChain(alias)
            ?: return ExportResult.Error("No certificate chain found for alias '$alias'.")

        return try {
            val p12 = KeyStore.getInstance("PKCS12")
            p12.load(null, pwd)
            p12.setKeyEntry(alias, privateKey, pwd, chain)
            FileOutputStream(dest).use { p12.store(it, pwd) }
            ExportResult.Success(dest)
        } catch (e: Exception) {
            ExportResult.Error("PKCS#12 write failed: ${e.message}")
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private fun openKeystore(file: File, password: CharArray): KeyStore {
        val type = ExtensionMapper.keystoreType(file.extension.lowercase()) ?: "JKS"
        val ks = KeyStore.getInstance(type)
        FileInputStream(file).use { ks.load(it, password) }
        return ks
    }

    /** Writes any list of BouncyCastle PEM-encodable objects to [dest] in one PEM file. */
    private fun writePemObjects(dest: File, objects: List<Any>) {
        val sw = StringWriter()
        JcaPEMWriter(sw).use { writer ->
            for (obj in objects) writer.writeObject(obj)
        }
        dest.writeText(sw.toString())
    }

    /**
     * Returns the suggested file name for a given alias and format.
     * The alias is sanitised so it can be used safely as a filename.
     */
    fun suggestedFileName(alias: String, format: ExportFormat): String {
        val safe = alias.replace(Regex("[^A-Za-z0-9._\\-]"), "_")
        return when (format) {
            ExportFormat.CERT_PEM  -> "$safe.pem"
            ExportFormat.CERT_DER  -> "$safe.der"
            ExportFormat.CHAIN_PEM -> "${safe}_chain.pem"
            ExportFormat.PKCS12    -> "$safe.p12"
        }
    }
}
