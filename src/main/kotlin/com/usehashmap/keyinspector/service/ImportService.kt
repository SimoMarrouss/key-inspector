package com.usehashmap.keyinspector.service

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec

// ─── Domain types ──────────────────────────────────────────────────────────────

/** Everything that can be parsed from a source file to import. */
sealed class ImportSource {
    /** A single trusted certificate (no private key). */
    data class TrustedCert(val cert: X509Certificate) : ImportSource()

    /** A private key plus its certificate chain (end-entity first). */
    data class KeyPair(val privateKey: PrivateKey, val chain: Array<X509Certificate>) : ImportSource() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is KeyPair) return false
            return privateKey == other.privateKey && chain.contentEquals(other.chain)
        }
        override fun hashCode(): Int = 31 * privateKey.hashCode() + chain.contentHashCode()
    }

    /** A full PKCS#12 bundle – we merge all entries from it. */
    data class Pkcs12Bundle(val entries: List<ImportSource>) : ImportSource()
}

/** Outcome of an import operation. */
sealed class ImportResult {
    object Success : ImportResult()
    data class AliasExists(val alias: String) : ImportResult()
    data class ParseError(val reason: String) : ImportResult()
    data class WrongKeystorePassword(val reason: String) : ImportResult()
    data class WriteError(val reason: String) : ImportResult()
}

// ─── Service ───────────────────────────────────────────────────────────────────

object ImportService {

    /**
     * Parse [sourceFile] (PEM / DER cert / DER key / PKCS#12) and import the result
     * into [keystoreFile] under [alias].
     *
     * @param keystoreFile    the target keystore (JKS / JCEKS / PKCS12 / BKS …)
     * @param keystorePassword password to open & save the keystore
     * @param sourceFile      PEM, DER certificate, PKCS#12, or DER private key
     * @param alias           the alias to use inside the keystore
     * @param keyPassword     password to protect the imported private key entry
     *                        (ignored for certificate-only imports)
     * @param sourcePassword  password to decrypt the source (used for PKCS#12 / encrypted PEM)
     */
    fun import(
        keystoreFile: File,
        keystorePassword: CharArray,
        sourceFile: File,
        alias: String,
        keyPassword: CharArray,
        sourcePassword: CharArray?
    ): ImportResult {

        // 1. Open the target keystore ─────────────────────────────────────────
        val ks = try {
            openKeystore(keystoreFile, keystorePassword)
        } catch (e: Exception) {
            val msg = e.message ?: e.javaClass.simpleName
            return if (msg.contains("password", ignoreCase = true) ||
                       msg.contains("MAC", ignoreCase = false))
                ImportResult.WrongKeystorePassword(msg)
            else
                ImportResult.WriteError("Cannot open keystore: $msg")
        }

        // 2. Validate alias uniqueness ─────────────────────────────────────────
        if (ks.containsAlias(alias)) return ImportResult.AliasExists(alias)

        // 3. Parse the source file ─────────────────────────────────────────────
        val source = try {
            parseSource(sourceFile, sourcePassword)
        } catch (e: Exception) {
            return ImportResult.ParseError(e.message ?: "Could not parse source file")
        }

        // 4. Write entries into keystore ───────────────────────────────────────
        try {
            writeEntry(ks, source, alias, keyPassword)
        } catch (e: Exception) {
            return ImportResult.WriteError("Import failed: ${e.message}")
        }

        // 5. Persist keystore to disk ──────────────────────────────────────────
        return try {
            FileOutputStream(keystoreFile).use { ks.store(it, keystorePassword) }
            ImportResult.Success
        } catch (e: Exception) {
            ImportResult.WriteError("Could not save keystore: ${e.message}")
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private fun openKeystore(file: File, password: CharArray): KeyStore {
        // Infer the keystore type from extension
        val type = ExtensionMapper.keystoreType(file.extension.lowercase()) ?: "JKS"
        val ks = KeyStore.getInstance(type)
        FileInputStream(file).use { ks.load(it, password) }
        return ks
    }

    /**
     * Returns an [ImportSource] for [file], trying in order:
     * PKCS#12 container → PEM → DER certificate → DER PKCS#8 private key.
     */
    private fun parseSource(file: File, password: CharArray?): ImportSource {
        val ext = file.extension.lowercase()

        // PKCS#12 ─────────────────────────────────────────────────────────────
        if (ext == "p12" || ext == "pfx") {
            return parsePkcs12(file, password ?: CharArray(0))
        }

        // PEM (try first for .pem / .key / .cer / .crt etc.) ──────────────────
        tryParsePem(file, password)?.let { return it }

        // DER certificate ─────────────────────────────────────────────────────
        tryParseDerCert(file)?.let { return it }

        // DER PKCS#8 private key (without cert — import as bare key via trusted cert trick)
        tryParseDerPrivateKey(file)?.let { return it }

        throw IllegalArgumentException(
            "Could not parse '${file.name}' as PEM, DER certificate, or PKCS#12."
        )
    }

    private fun parsePkcs12(file: File, password: CharArray): ImportSource {
        val p12 = KeyStore.getInstance("PKCS12")
        FileInputStream(file).use { p12.load(it, password) }

        val entries = mutableListOf<ImportSource>()
        p12.aliases().toList().forEach { a ->
            when {
                p12.isKeyEntry(a) -> {
                    val privKey = p12.getKey(a, password) as? PrivateKey
                        ?: return@forEach
                    val chain = p12.getCertificateChain(a)
                        ?.filterIsInstance<X509Certificate>()
                        ?.toTypedArray()
                        ?: return@forEach
                    entries += ImportSource.KeyPair(privKey, chain)
                }
                p12.isCertificateEntry(a) -> {
                    val cert = p12.getCertificate(a) as? X509Certificate ?: return@forEach
                    entries += ImportSource.TrustedCert(cert)
                }
            }
        }
        require(entries.isNotEmpty()) { "PKCS#12 file contains no importable entries" }
        return if (entries.size == 1) entries[0] else ImportSource.Pkcs12Bundle(entries)
    }

    private fun tryParsePem(file: File, password: CharArray?): ImportSource? {
        return try {
            val converter    = JcaX509CertificateConverter().setProvider("BC")
            val keyConverter = JcaPEMKeyConverter().setProvider("BC")
            val certs        = mutableListOf<X509Certificate>()
            var privateKey: PrivateKey? = null

            InputStreamReader(FileInputStream(file)).use { reader ->
                val parser = PEMParser(reader)
                var obj: Any?
                while (true) {
                    obj = parser.readObject() ?: break
                    when (obj) {
                        is X509CertificateHolder -> certs += converter.getCertificate(obj)
                        is PEMKeyPair -> {
                            val kp = keyConverter.getKeyPair(obj)
                            privateKey = kp.private
                        }
                        is PEMEncryptedKeyPair -> {
                            val pwd = password ?: throw IllegalArgumentException(
                                "The PEM key is encrypted – provide a source password."
                            )
                            val decryptor = JcePEMDecryptorProviderBuilder().build(pwd)
                            val kp = keyConverter.getKeyPair(obj.decryptKeyPair(decryptor))
                            privateKey = kp.private
                        }
                        is PKCS8EncryptedPrivateKeyInfo -> {
                            val pwd = password ?: throw IllegalArgumentException(
                                "The PKCS#8 key is encrypted – provide a source password."
                            )
                            val decryptor = JcePKCSPBEInputDecryptorProviderBuilder()
                                .setProvider("BC").build(pwd)
                            val info = obj.decryptPrivateKeyInfo(decryptor)
                            val kf = KeyFactory.getInstance(info.privateKeyAlgorithm.algorithm.id, "BC")
                            privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(info.encoded))
                        }
                        is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> {
                            privateKey = keyConverter.getPrivateKey(obj)
                        }
                        is CMSSignedData -> {
                            val holders = obj.certificates.getMatches(null)
                            holders.forEach { h ->
                                certs += converter.getCertificate(h as X509CertificateHolder)
                            }
                        }
                    }
                }
            }

            when {
                certs.isEmpty() && privateKey == null -> null
                privateKey != null && certs.isNotEmpty() ->
                    ImportSource.KeyPair(privateKey, certs.toTypedArray())
                privateKey != null ->
                    throw IllegalArgumentException("PEM contains a private key but no certificate chain")
                else -> ImportSource.TrustedCert(certs.first())
            }
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (_: Exception) {
            null
        }
    }

    private fun tryParseDerCert(file: File): ImportSource? {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val cert = FileInputStream(file).use { cf.generateCertificate(it) } as X509Certificate
            ImportSource.TrustedCert(cert)
        } catch (_: Exception) {
            null
        }
    }

    private fun tryParseDerPrivateKey(file: File): ImportSource? {
        val bytes = file.readBytes()
        for (alg in listOf("RSA", "EC", "DSA")) {
            try {
                val kf = KeyFactory.getInstance(alg)
                    kf.generatePrivate(PKCS8EncodedKeySpec(bytes))  // probe only; succeeds → it's a PKCS8 key
                    throw IllegalArgumentException(
                    "The source file contains only a bare private key with no certificate. " +
                    "Please use a PEM file that includes both the key and certificate, " +
                    "or a PKCS#12 file."
                )
            } catch (e: IllegalArgumentException) {
                throw e
            } catch (_: Exception) {
                continue
            }
        }
        return null
    }

    private fun writeEntry(
        ks: KeyStore,
        source: ImportSource,
        alias: String,
        keyPassword: CharArray
    ) {
        when (source) {
            is ImportSource.TrustedCert ->
                ks.setCertificateEntry(alias, source.cert)

            is ImportSource.KeyPair ->
                ks.setKeyEntry(alias, source.privateKey, keyPassword, source.chain)

            is ImportSource.Pkcs12Bundle -> {
                // Import the first key-pair entry (if any) under the requested alias;
                // additional entries get auto-suffixed to keep aliases unique.
                var keyEntryCount = 0
                var certEntryCount = 0
                source.entries.forEach { entry ->
                    when (entry) {
                        is ImportSource.KeyPair -> {
                            val a = if (keyEntryCount == 0) alias else "$alias-key-${keyEntryCount + 1}"
                            if (!ks.containsAlias(a))
                                ks.setKeyEntry(a, entry.privateKey, keyPassword, entry.chain)
                            keyEntryCount++
                        }
                        is ImportSource.TrustedCert -> {
                            val a = if (certEntryCount == 0 && keyEntryCount > 0) "$alias-cert"
                                    else if (certEntryCount == 0) alias
                                    else "$alias-cert-${certEntryCount + 1}"
                            if (!ks.containsAlias(a))
                                ks.setCertificateEntry(a, entry.cert)
                            certEntryCount++
                        }
                        else -> { /* nested bundle – skip */ }
                    }
                }
            }
        }
    }

    /**
     * Returns all alias names currently in [keystoreFile].
     * Used by the dialog to validate uniqueness.
     */
    fun existingAliases(keystoreFile: File, password: CharArray): Set<String> {
        return try {
            val ks = openKeystore(keystoreFile, password)
            ks.aliases().toList().toSet()
        } catch (_: Exception) {
            emptySet()
        }
    }
}
