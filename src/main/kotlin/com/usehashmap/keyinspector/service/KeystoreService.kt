package com.usehashmap.keyinspector.service

import com.usehashmap.keyinspector.model.*
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.security.interfaces.DSAKey
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.SecretKey

/** Maps file extensions to their canonical keystore/file type */
object ExtensionMapper {

    /** Returns true if the extension belongs to a keystore container format. */
    fun isKeystore(ext: String): Boolean = ext.lowercase() in KEYSTORE_EXTENSIONS

    /** Returns true if the extension belongs to a single-object certificate/key/CRL file. */
    fun isCertOrKey(ext: String): Boolean = ext.lowercase() in CERT_KEY_EXTENSIONS

    fun keystoreType(ext: String): String? = KEYSTORE_EXTENSIONS[ext.lowercase()]

    private val KEYSTORE_EXTENSIONS = mapOf(
        "jks"   to "JKS",
        "jceks" to "JCEKS",
        "bks"   to "BKS",
        "p12"   to "PKCS12",
        "pfx"   to "PKCS12",
        "uber"  to "UBER",
        "bcfks" to "BCFKS"
    )

    private val CERT_KEY_EXTENSIONS = setOf(
        "pub", "key", "pem", "cer", "crt",
        "p7", "p7b", "pkipath", "spc",
        "p10", "spkac", "pkcs8", "pvk", "crl"
    )
}

/**
 * Result wrapper for file loading operations.
 * Either a [Success] or a typed [Failure].
 */
sealed class LoadResult {
    data class Success(val file: LoadedFile) : LoadResult()
    sealed class Failure : LoadResult() {
        data class WrongPassword(val message: String) : Failure()
        data class Unsupported(val message: String) : Failure()
        data class GenericError(val message: String, val cause: Throwable? = null) : Failure()
        object PasswordRequired : Failure()
    }
}

/** The main service responsible for parsing keystores and certificate files. */
object KeystoreService {

    /**
     * Attempt to load [file] using [password] (nullable = try empty/null password).
     */
    fun load(file: File, password: CharArray? = null): LoadResult {
        if (!file.exists() || !file.isFile) {
            return LoadResult.Failure.GenericError("File not found: ${file.absolutePath}")
        }

        val ext = file.extension.lowercase()

        return when {
            ExtensionMapper.isKeystore(ext) -> loadKeystore(file, ext, password)
            ExtensionMapper.isCertOrKey(ext) -> loadCertOrKey(file, ext, password)
            else -> LoadResult.Failure.Unsupported("Unsupported file extension: .$ext")
        }
    }

    // ─── Keystore loading ─────────────────────────────────────────────────────

    private fun loadKeystore(file: File, ext: String, password: CharArray?): LoadResult {
        val type = ExtensionMapper.keystoreType(ext)
            ?: return LoadResult.Failure.Unsupported("Unknown keystore type for .$ext")

        val pwd = password ?: CharArray(0)

        return try {
            val ks = KeyStore.getInstance(type)
            FileInputStream(file).use { ks.load(it, pwd) }

            val entries = ks.aliases().toList().map { alias ->
                parseKeystoreAlias(ks, alias)
            }

            LoadResult.Success(
                LoadedFile(
                    filePath      = file.absolutePath,
                    keystoreType  = type,
                    entries       = entries,
                    fileSizeBytes = file.length()
                )
            )
        } catch (e: java.security.UnrecoverableKeyException) {
            LoadResult.Failure.WrongPassword(e.message ?: "Wrong password")
        } catch (e: java.io.IOException) {
            val msg = e.message ?: ""
            when {
                msg.contains("password", ignoreCase = true) ||
                msg.contains("MAC", ignoreCase = false) ||
                msg.contains("failed to decrypt", ignoreCase = true) ->
                    if (password == null) LoadResult.Failure.PasswordRequired
                    else LoadResult.Failure.WrongPassword(msg)
                else -> LoadResult.Failure.GenericError(msg, e)
            }
        } catch (e: Exception) {
            LoadResult.Failure.GenericError(e.message ?: e.javaClass.simpleName, e)
        }
    }

    private fun parseKeystoreAlias(ks: KeyStore, alias: String): KeyEntry {
        return when {
            ks.isKeyEntry(alias) -> {
                val cert = ks.getCertificate(alias) as? X509Certificate
                val chain = ks.getCertificateChain(alias)
                    ?.filterIsInstance<X509Certificate>()
                    ?: emptyList()
                val creationDate = try { ks.getCreationDate(alias) } catch (_: Exception) { null }

                if (cert != null && chain.isNotEmpty()) {
                    val pubKey = cert.publicKey
                    PrivateKeyEntry(
                        alias            = alias,
                        algorithm        = pubKey.algorithm,
                        keySize          = keySize(pubKey),
                        certificateChain = chain.map { toCertificateInfo(it) },
                        creationDate     = creationDate
                    )
                } else {
                    // Secret key entry
                    try {
                        val secretKey = ks.getKey(alias, CharArray(0)) as? SecretKey
                        SecretKeyEntry(
                            alias        = alias,
                            algorithm    = secretKey?.algorithm ?: "Unknown",
                            keySize      = (secretKey?.encoded?.size ?: 0) * 8,
                            creationDate = creationDate
                        )
                    } catch (_: Exception) {
                        UnknownEntry(alias, "Could not retrieve key")
                    }
                }
            }
            ks.isCertificateEntry(alias) -> {
                val cert = ks.getCertificate(alias) as? X509Certificate
                val creationDate = try { ks.getCreationDate(alias) } catch (_: Exception) { null }
                if (cert != null) {
                    TrustedCertEntry(
                        alias        = alias,
                        certificate  = toCertificateInfo(cert),
                        creationDate = creationDate
                    )
                } else {
                    UnknownEntry(alias, "Null certificate")
                }
            }
            else -> UnknownEntry(alias, "Unknown entry type")
        }
    }

    // ─── Certificate / key / CRL file loading ─────────────────────────────────

    private fun loadCertOrKey(file: File, @Suppress("UNUSED_PARAMETER") ext: String, password: CharArray?): LoadResult {
        // 1. Try PEM first (handles most text formats)
        val pemResult = tryPem(file, password)
        if (pemResult != null) return pemResult

        // 2. Try DER-encoded X.509 certificate
        val derCertResult = tryDerCertificate(file)
        if (derCertResult != null) return derCertResult

        // 3. Try DER-encoded CRL
        val derCrlResult = tryDerCrl(file)
        if (derCrlResult != null) return derCrlResult

        // 4. Try PKCS#7 / CMS SignedData (p7b / spc / pkipath)
        val p7Result = tryPkcs7(file)
        if (p7Result != null) return p7Result

        // 5. Try DER PKCS#10 CSR
        val csrResult = tryDerCsr(file)
        if (csrResult != null) return csrResult

        // 6. Try DER public key (SubjectPublicKeyInfo)
        val pubResult = tryDerPublicKey(file)
        if (pubResult != null) return pubResult

        // 7. Try DER PKCS#8 private key
        val pkcs8Result = tryDerPrivateKey(file)
        if (pkcs8Result != null) return pkcs8Result

        return LoadResult.Failure.Unsupported("Could not parse the file as any supported format.")
    }

    private fun tryPem(file: File, password: CharArray?): LoadResult? {
        val entries = mutableListOf<KeyEntry>()
        return try {
            InputStreamReader(FileInputStream(file)).use { reader ->
                val parser = PEMParser(reader)
                val converter = JcaX509CertificateConverter().setProvider("BC")
                val keyConverter = JcaPEMKeyConverter().setProvider("BC")
                var obj: Any?
                var idx = 0
                while (true) {
                    obj = parser.readObject() ?: break
                    idx++
                    val alias = "entry-$idx"
                    when (obj) {
                        is X509CertificateHolder -> {
                            val cert = converter.getCertificate(obj)
                            entries += StandaloneCertEntry(alias, toCertificateInfo(cert))
                        }
                        is org.bouncycastle.cert.X509CRLHolder -> {
                            val crl = CertificateFactory.getInstance("X.509", "BC")
                                .generateCRL(obj.encoded.inputStream()) as X509CRL
                            entries += StandaloneCRLEntry(alias, toCrlInfo(crl))
                        }
                        is PKCS10CertificationRequest -> {
                            entries += csrToEntry(alias, obj)
                        }
                        is PEMEncryptedKeyPair -> {
                            val pwd = password ?: return@use
                            val decryptor = JcePEMDecryptorProviderBuilder().build(pwd)
                            val kp = keyConverter.getKeyPair(obj.decryptKeyPair(decryptor))
                            val pub = kp.public
                            entries += StandalonePublicKeyEntry(alias, pub.algorithm, keySize(pub), pub.format ?: "")
                        }
                        is PEMKeyPair -> {
                            val kp = keyConverter.getKeyPair(obj)
                            val priv = kp.private
                            entries += StandalonePrivateKeyEntry(alias, priv.algorithm, keySize(kp.public), priv.format ?: "")
                        }
                        is PKCS8EncryptedPrivateKeyInfo -> {
                            if (password != null) {
                                val decryptor = JcePKCSPBEInputDecryptorProviderBuilder()
                                    .setProvider("BC").build(password)
                                val privInfo = obj.decryptPrivateKeyInfo(decryptor)
                                val kf = KeyFactory.getInstance(privInfo.privateKeyAlgorithm.algorithm.id, "BC")
                                val priv = kf.generatePrivate(PKCS8EncodedKeySpec(privInfo.encoded))
                                entries += StandalonePrivateKeyEntry(alias, priv.algorithm, 0, priv.format ?: "")
                            }
                        }
                        is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> {
                            val priv = keyConverter.getPrivateKey(obj)
                            entries += StandalonePrivateKeyEntry(alias, priv.algorithm, 0, priv.format ?: "")
                        }
                        is org.bouncycastle.asn1.x509.SubjectPublicKeyInfo -> {
                            val pub = keyConverter.getPublicKey(obj)
                            entries += StandalonePublicKeyEntry(alias, pub.algorithm, keySize(pub), pub.format ?: "")
                        }
                        else -> {
                            // unknown PEM block — skip
                        }
                    }
                }
            }
            if (entries.isEmpty()) null
            else LoadResult.Success(
                LoadedFile(
                    filePath      = file.absolutePath,
                    keystoreType  = "PEM",
                    entries       = entries,
                    fileSizeBytes = file.length()
                )
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun tryDerCertificate(file: File): LoadResult? {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val cert = FileInputStream(file).use { cf.generateCertificate(it) } as X509Certificate
            LoadResult.Success(
                LoadedFile(
                    filePath      = file.absolutePath,
                    keystoreType  = "DER Certificate",
                    entries       = listOf(StandaloneCertEntry("certificate", toCertificateInfo(cert))),
                    fileSizeBytes = file.length()
                )
            )
        } catch (_: Exception) { null }
    }

    private fun tryDerCrl(file: File): LoadResult? {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val crl = FileInputStream(file).use { cf.generateCRL(it) } as X509CRL
            LoadResult.Success(
                LoadedFile(
                    filePath      = file.absolutePath,
                    keystoreType  = "Certificate Revocation List",
                    entries       = listOf(StandaloneCRLEntry("crl", toCrlInfo(crl))),
                    fileSizeBytes = file.length()
                )
            )
        } catch (_: Exception) { null }
    }

    private fun tryPkcs7(file: File): LoadResult? {
        return try {
            val bytes = file.readBytes()
            val cms = CMSSignedData(bytes)
            val certs = cms.certificates.getMatches(null).toList()
            val converter = JcaX509CertificateConverter().setProvider("BC")
            val entries = certs.mapIndexed { i, holder ->
                val cert = converter.getCertificate(holder as X509CertificateHolder)
                StandaloneCertEntry("cert-${i + 1}", toCertificateInfo(cert))
            }
            if (entries.isEmpty()) return null
            LoadResult.Success(
                LoadedFile(
                    filePath      = file.absolutePath,
                    keystoreType  = "PKCS#7 / CMS",
                    entries       = entries,
                    fileSizeBytes = file.length()
                )
            )
        } catch (_: Exception) { null }
    }

    private fun tryDerCsr(file: File): LoadResult? {
        return try {
            val bytes = file.readBytes()
            val csr = PKCS10CertificationRequest(bytes)
            LoadResult.Success(
                LoadedFile(
                    filePath      = file.absolutePath,
                    keystoreType  = "PKCS#10 CSR",
                    entries       = listOf(csrToEntry("csr", csr)),
                    fileSizeBytes = file.length()
                )
            )
        } catch (_: Exception) { null }
    }

    private fun tryDerPublicKey(file: File): LoadResult? {
        return try {
            val bytes = file.readBytes()
            // Try RSA first, then EC, then DSA
            for (alg in listOf("RSA", "EC", "DSA")) {
                try {
                    val kf = KeyFactory.getInstance(alg)
                    val pub = kf.generatePublic(X509EncodedKeySpec(bytes))
                    return LoadResult.Success(
                        LoadedFile(
                            filePath      = file.absolutePath,
                            keystoreType  = "Public Key",
                            entries       = listOf(StandalonePublicKeyEntry("public-key", pub.algorithm, keySize(pub), pub.format ?: "")),
                            fileSizeBytes = file.length()
                        )
                    )
                } catch (_: Exception) { continue }
            }
            null
        } catch (_: Exception) { null }
    }

    private fun tryDerPrivateKey(file: File): LoadResult? {
        return try {
            val bytes = file.readBytes()
            for (alg in listOf("RSA", "EC", "DSA")) {
                try {
                    val kf = KeyFactory.getInstance(alg)
                    val priv = kf.generatePrivate(PKCS8EncodedKeySpec(bytes))
                    return LoadResult.Success(
                        LoadedFile(
                            filePath      = file.absolutePath,
                            keystoreType  = "Private Key (PKCS#8)",
                            entries       = listOf(StandalonePrivateKeyEntry("private-key", priv.algorithm, 0, priv.format ?: "")),
                            fileSizeBytes = file.length()
                        )
                    )
                } catch (_: Exception) { continue }
            }
            null
        } catch (_: Exception) { null }
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────

    fun toCertificateInfo(cert: X509Certificate): CertificateInfo {
        val sha1   = fingerprint(cert.encoded, "SHA-1")
        val sha256 = fingerprint(cert.encoded, "SHA-256")

        val san = try {
            cert.subjectAlternativeNames?.map { sanEntry ->
                val type = sanEntry[0] as Int
                val value = sanEntry[1]
                when (type) {
                    0  -> "otherName: $value"
                    1  -> "email: $value"
                    2  -> "DNS: $value"
                    4  -> "dirName: $value"
                    6  -> "URI: $value"
                    7  -> "IP: $value"
                    8  -> "OID: $value"
                    else -> "[$type]: $value"
                }
            } ?: emptyList()
        } catch (_: Exception) { emptyList() }

        val keyUsageNames = listOf(
            "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
            "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
        )
        val keyUsage: List<String> = try {
            val usage: BooleanArray? = cert.keyUsage
            if (usage != null) {
                usage.toList().mapIndexedNotNull { i: Int, b: Boolean ->
                    if (b) keyUsageNames.getOrNull(i) else null
                }
            } else emptyList()
        } catch (_: Exception) { emptyList() }

        val extKeyUsage = try {
            cert.extendedKeyUsage?.map { oid ->
                EKU_MAP[oid] ?: oid
            } ?: emptyList()
        } catch (_: Exception) { emptyList() }

        val basicConstraints = when (val bc = cert.basicConstraints) {
            -1   -> "End-Entity"
            Int.MAX_VALUE -> "CA (path length: unlimited)"
            else -> "CA (path length: $bc)"
        }

        val isSelfSigned = try {
            cert.verify(cert.publicKey)
            true
        } catch (_: Exception) { false }

        return CertificateInfo(
            subject           = cert.subjectX500Principal.name,
            issuer            = cert.issuerX500Principal.name,
            serialNumber      = cert.serialNumber.toString(16).uppercase(),
            validFrom         = cert.notBefore,
            validUntil        = cert.notAfter,
            algorithm         = cert.publicKey.algorithm,
            signatureAlgorithm = cert.sigAlgName,
            keySize           = keySize(cert.publicKey),
            version           = cert.version,
            fingerprintSha1   = sha1,
            fingerprintSha256 = sha256,
            subjectAltNames   = san,
            keyUsage          = keyUsage,
            extendedKeyUsage  = extKeyUsage,
            basicConstraints  = basicConstraints,
            isSelfSigned      = isSelfSigned,
            raw               = cert
        )
    }

    private fun toCrlInfo(crl: X509CRL): CRLInfo = CRLInfo(
        issuer           = crl.issuerX500Principal.name,
        thisUpdate       = crl.thisUpdate,
        nextUpdate       = crl.nextUpdate,
        revokedEntries   = crl.revokedCertificates?.size ?: 0,
        signatureAlgorithm = crl.sigAlgName,
        raw              = crl
    )

    private fun csrToEntry(alias: String, csr: PKCS10CertificationRequest): StandaloneCSREntry {
        val subjectPubKeyInfo = csr.subjectPublicKeyInfo
        val alg = subjectPubKeyInfo.algorithm.algorithm.id
        // Convert to JCA public key for key size
        val pubKey = try {
            val converter = JcaPEMKeyConverter().setProvider("BC")
            converter.getPublicKey(subjectPubKeyInfo)
        } catch (_: Exception) { null }
        return StandaloneCSREntry(
            alias              = alias,
            subject            = csr.subject.toString(),
            algorithm          = pubKey?.algorithm ?: alg,
            keySize            = if (pubKey != null) keySize(pubKey) else 0,
            signatureAlgorithm = csr.signatureAlgorithm.algorithm.id
        )
    }

    private fun fingerprint(bytes: ByteArray, algorithm: String): String {
        val md = MessageDigest.getInstance(algorithm)
        return md.digest(bytes).joinToString(":") { "%02X".format(it) }
    }

    fun keySize(key: java.security.Key): Int = when (key) {
        is RSAKey  -> key.modulus.bitLength()
        is ECKey   -> key.params.order.bitLength()
        is DSAKey  -> key.params?.p?.bitLength() ?: 0
        else       -> 0
    }

    private val EKU_MAP = mapOf(
        "1.3.6.1.5.5.7.3.1"  to "TLS Web Server Authentication",
        "1.3.6.1.5.5.7.3.2"  to "TLS Web Client Authentication",
        "1.3.6.1.5.5.7.3.3"  to "Code Signing",
        "1.3.6.1.5.5.7.3.4"  to "Email Protection",
        "1.3.6.1.5.5.7.3.8"  to "Time Stamping",
        "1.3.6.1.5.5.7.3.9"  to "OCSP Signing",
        "1.3.6.1.4.1.311.10.3.3" to "Microsoft SGC",
        "2.16.840.1.113730.4.1"  to "Netscape SGC"
    )
}
