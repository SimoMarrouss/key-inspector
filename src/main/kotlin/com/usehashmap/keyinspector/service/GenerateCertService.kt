package com.usehashmap.keyinspector.service

import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.*
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter

// ─── Domain ────────────────────────────────────────────────────────────────────

/** Certificate generation parameters collected from the wizard. */
data class CertGenParams(
    val commonName:    String,
    val organization:  String,
    val country:       String,
    val validityDays:  Int,
    val keyAlgorithm:  KeyAlgorithmChoice,
    val sanDnsNames:   List<String>,
    val sanIpAddresses: List<String>,
    val outputFormat:  OutputFormatChoice,
    // used when outputFormat == ADD_TO_EXISTING or the keystore options
    val keystoreFile:     File?,
    val keystorePassword: CharArray,
    val keystoreType:     String,   // "JKS" / "PKCS12"
    val alias:            String,
    val keyPassword:      CharArray
)

enum class KeyAlgorithmChoice(val label: String, val jcaAlgorithm: String, val keySize: Int) {
    RSA_2048  ("RSA 2048",  "RSA", 2048),
    RSA_4096  ("RSA 4096",  "RSA", 4096),
    EC_P256   ("EC P-256",  "EC",  256),
    EC_P384   ("EC P-384",  "EC",  384);

    override fun toString() = label
}

enum class OutputFormatChoice(val label: String) {
    ADD_TO_EXISTING ("Add to existing keystore"),
    NEW_JKS         ("Create new JKS keystore"),
    NEW_PKCS12      ("Create new PKCS#12 keystore"),
    EXPORT_PEM      ("Export as PEM files");

    override fun toString() = label
}

/** Result of certificate generation. */
sealed class GenerateCertResult {
    /** Successfully generated; [summaryLines] contains human-readable details. */
    data class Success(
        val alias: String,
        val outputPath: String,
        val summaryLines: List<String>
    ) : GenerateCertResult()

    data class Failure(val reason: String) : GenerateCertResult()
}

// ─── Service ──────────────────────────────────────────────────────────────────

object GenerateCertService {

    fun generate(params: CertGenParams): GenerateCertResult = try {
        val keyPair = generateKeyPair(params.keyAlgorithm)
        val cert    = buildCertificate(keyPair, params)

        when (params.outputFormat) {
            OutputFormatChoice.ADD_TO_EXISTING -> addToKeystore(
                ksFile   = params.keystoreFile!!,
                ksType   = null,                  // infer from extension
                ksPwd    = params.keystorePassword,
                alias    = params.alias,
                keyPwd   = params.keyPassword,
                keyPair  = keyPair,
                cert     = cert,
                create   = false
            )
            OutputFormatChoice.NEW_JKS -> addToKeystore(
                ksFile   = params.keystoreFile!!,
                ksType   = "JKS",
                ksPwd    = params.keystorePassword,
                alias    = params.alias,
                keyPwd   = params.keyPassword,
                keyPair  = keyPair,
                cert     = cert,
                create   = true
            )
            OutputFormatChoice.NEW_PKCS12 -> addToKeystore(
                ksFile   = params.keystoreFile!!,
                ksType   = "PKCS12",
                ksPwd    = params.keystorePassword,
                alias    = params.alias,
                keyPwd   = params.keyPassword,
                keyPair  = keyPair,
                cert     = cert,
                create   = true
            )
            OutputFormatChoice.EXPORT_PEM -> exportPem(
                dir     = params.keystoreFile!!,
                alias   = params.alias,
                keyPair = keyPair,
                cert    = cert
            )
        }

        val outputPath = params.keystoreFile!!.absolutePath
        GenerateCertResult.Success(
            alias       = params.alias,
            outputPath  = outputPath,
            summaryLines = buildSummary(params, cert)
        )
    } catch (e: Exception) {
        GenerateCertResult.Failure(e.message ?: e.javaClass.simpleName)
    }

    // ─── Key generation ───────────────────────────────────────────────────────

    private fun generateKeyPair(choice: KeyAlgorithmChoice): KeyPair {
        val provider = BouncyCastleProvider()
        return when (choice.jcaAlgorithm) {
            "RSA" -> {
                val kg = KeyPairGenerator.getInstance("RSA", provider)
                kg.initialize(choice.keySize)
                kg.generateKeyPair()
            }
            "EC"  -> {
                val kg  = KeyPairGenerator.getInstance("EC", provider)
                val curveName = if (choice.keySize == 256) "P-256" else "P-384"
                val spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(curveName)
                kg.initialize(spec, SecureRandom())
                kg.generateKeyPair()
            }
            else  -> throw IllegalArgumentException("Unsupported algorithm: ${choice.jcaAlgorithm}")
        }
    }

    // ─── Certificate building ─────────────────────────────────────────────────

    private fun buildCertificate(keyPair: KeyPair, params: CertGenParams): X509Certificate {
        val subject = X500NameBuilder(BCStyle.INSTANCE).apply {
            addRDN(BCStyle.CN, params.commonName)
            if (params.organization.isNotBlank()) addRDN(BCStyle.O, params.organization)
            if (params.country.isNotBlank())      addRDN(BCStyle.C, params.country)
        }.build()

        val now        = Date()
        val notBefore  = now
        val notAfter   = Date(now.time + params.validityDays.toLong() * 86_400_000L)
        val serial     = BigInteger.valueOf(System.currentTimeMillis())
        val provider   = BouncyCastleProvider()

        val sigAlg = when (params.keyAlgorithm.jcaAlgorithm) {
            "RSA" -> "SHA256withRSA"
            "EC"  -> "SHA256withECDSA"
            else  -> "SHA256withRSA"
        }

        val builder = JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, keyPair.public
        )

        // Basic Constraints – mark as CA (self-signed = root)
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))

        // Key Usage
        val ku = KeyUsage(
            KeyUsage.digitalSignature or KeyUsage.keyEncipherment or
            KeyUsage.keyCertSign      or KeyUsage.cRLSign
        )
        builder.addExtension(Extension.keyUsage, true, ku)

        // SANs
        val sanList = mutableListOf<GeneralName>()
        params.sanDnsNames.filter { it.isNotBlank() }.forEach {
            sanList += GeneralName(GeneralName.dNSName, it.trim())
        }
        params.sanIpAddresses.filter { it.isNotBlank() }.forEach {
            sanList += GeneralName(GeneralName.iPAddress, it.trim())
        }
        if (sanList.isNotEmpty()) {
            builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                GeneralNames(sanList.toTypedArray())
            )
        }

        val signer = JcaContentSignerBuilder(sigAlg).setProvider(provider).build(keyPair.private)
        return JcaX509CertificateConverter()
            .setProvider(provider)
            .getCertificate(builder.build(signer))
    }

    // ─── Output writers ───────────────────────────────────────────────────────

    /** Keystore types that must be loaded via the Bouncy Castle provider. */
    private val BC_TYPES = setOf("BKS", "UBER", "BCFKS")

    private fun addToKeystore(
        ksFile:  File,
        ksType:  String?,
        ksPwd:   CharArray,
        alias:   String,
        keyPwd:  CharArray,
        keyPair: KeyPair,
        cert:    X509Certificate,
        create:  Boolean
    ) {
        val type = ksType
            ?: ExtensionMapper.keystoreType(ksFile.extension.lowercase())
            ?: "JKS"
        // JKS, JCEKS, PKCS12 are provided by the JDK; BKS/UBER/BCFKS need Bouncy Castle
        val ks = if (type.uppercase() in BC_TYPES)
            KeyStore.getInstance(type, BouncyCastleProvider())
        else
            KeyStore.getInstance(type)
        if (create || !ksFile.exists()) {
            ks.load(null, ksPwd)
        } else {
            java.io.FileInputStream(ksFile).use { ks.load(it, ksPwd) }
        }
        ks.setKeyEntry(alias, keyPair.private, keyPwd, arrayOf(cert))
        ksFile.parentFile?.mkdirs()
        FileOutputStream(ksFile).use { ks.store(it, ksPwd) }
    }

    private fun exportPem(dir: File, alias: String, keyPair: KeyPair, cert: X509Certificate) {
        // dir is actually the output directory in this case
        val safeAlias = alias.replace(Regex("[^A-Za-z0-9_\\-]"), "_")
        val certFile = File(dir, "$safeAlias.crt")
        val keyFile  = File(dir, "$safeAlias.key")

        dir.mkdirs()

        PemWriter(OutputStreamWriter(FileOutputStream(certFile))).use { pw ->
            pw.writeObject(PemObject("CERTIFICATE", cert.encoded))
        }
        PemWriter(OutputStreamWriter(FileOutputStream(keyFile))).use { pw ->
            pw.writeObject(PemObject("PRIVATE KEY", keyPair.private.encoded))
        }
    }

    // ─── Summary ─────────────────────────────────────────────────────────────

    private fun buildSummary(params: CertGenParams, cert: X509Certificate): List<String> {
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd")
        return listOf(
            "Alias:        ${params.alias}",
            "Subject DN:   ${cert.subjectX500Principal.name}",
            "Algorithm:    ${params.keyAlgorithm.label}",
            "Serial:       ${cert.serialNumber}",
            "Not Before:   ${fmt.format(cert.notBefore)}",
            "Not After:    ${fmt.format(cert.notAfter)}",
            "Output:       ${params.outputFormat.label}",
            "File:         ${params.keystoreFile?.absolutePath}"
        )
    }
}
