package com.usehashmap.keyinspector.model

import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.Date

/** Top-level sealed hierarchy for every entry the plugin can display. */
sealed class KeyEntry {
    abstract val alias: String
    abstract val entryType: EntryType
}

enum class EntryType(val displayName: String) {
    PRIVATE_KEY("Private Key + Certificate Chain"),
    TRUSTED_CERT("Trusted Certificate"),
    SECRET_KEY("Secret Key"),
    CERTIFICATE("Certificate"),
    CRL("Certificate Revocation List"),
    CSR("Certificate Signing Request"),
    PUBLIC_KEY("Public Key"),
    PRIVATE_KEY_BARE("Private Key"),
    UNKNOWN("Unknown")
}

// ─── Chain validation ──────────────────────────────────────────────────────────

enum class CertChainStatus {
    VALID,          // Complete chain, all signatures valid, no expired certs
    EXPIRING_SOON,  // All valid but ≥1 cert expires within 30 days
    INCOMPLETE,     // Chain does not terminate in a self-signed root CA
    EXPIRED,        // ≥1 cert in the chain is past notAfter
    BROKEN,         // Issuer/subject mismatch or signature verification failure
}

data class ChainValidationResult(
    val status: CertChainStatus,
    val details: String,
    val affectedCertIndex: Int? = null  // 0-based index of the offending cert, if any
)

// ─── Keystore entries ─────────────────────────────────────────────────────────

data class PrivateKeyEntry(
    override val alias: String,
    val algorithm: String,
    val keySize: Int,
    val certificateChain: List<CertificateInfo>,
    val creationDate: Date?,
    val chainValidation: ChainValidationResult
) : KeyEntry() {
    override val entryType = EntryType.PRIVATE_KEY
}

data class TrustedCertEntry(
    override val alias: String,
    val certificate: CertificateInfo,
    val creationDate: Date?
) : KeyEntry() {
    override val entryType = EntryType.TRUSTED_CERT
}

data class SecretKeyEntry(
    override val alias: String,
    val algorithm: String,
    val keySize: Int,
    val creationDate: Date?
) : KeyEntry() {
    override val entryType = EntryType.SECRET_KEY
}

// ─── Standalone file entries ───────────────────────────────────────────────────

data class StandaloneCertEntry(
    override val alias: String,
    val certificate: CertificateInfo
) : KeyEntry() {
    override val entryType = EntryType.CERTIFICATE
}

data class StandaloneCRLEntry(
    override val alias: String,
    val crl: CRLInfo
) : KeyEntry() {
    override val entryType = EntryType.CRL
}

data class StandaloneCSREntry(
    override val alias: String,
    val subject: String,
    val algorithm: String,
    val keySize: Int,
    val signatureAlgorithm: String,
    /** SAN values requested in the CSR attributes (may be empty). */
    val requestedSANs: List<String> = emptyList(),
    /** Key Usage OIDs/names requested in the CSR attributes (may be empty). */
    val requestedKeyUsage: List<String> = emptyList(),
    /** Extended Key Usage OIDs/names requested in the CSR attributes (may be empty). */
    val requestedExtendedKeyUsage: List<String> = emptyList(),
    /** Challenge password attribute, if present. */
    val challengePassword: String? = null
) : KeyEntry() {
    override val entryType = EntryType.CSR
}

data class StandalonePublicKeyEntry(
    override val alias: String,
    val algorithm: String,
    val keySize: Int,
    val format: String
) : KeyEntry() {
    override val entryType = EntryType.PUBLIC_KEY
}

data class StandalonePrivateKeyEntry(
    override val alias: String,
    val algorithm: String,
    val keySize: Int,
    val format: String
) : KeyEntry() {
    override val entryType = EntryType.PRIVATE_KEY_BARE
}

data class UnknownEntry(
    override val alias: String,
    val reason: String
) : KeyEntry() {
    override val entryType = EntryType.UNKNOWN
}

// ─── Value objects ─────────────────────────────────────────────────────────────

data class CertificateInfo(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val validFrom: Date,
    val validUntil: Date,
    val algorithm: String,
    val signatureAlgorithm: String,
    val keySize: Int,
    val version: Int,
    val fingerprintSha1: String,
    val fingerprintSha256: String,
    val subjectAltNames: List<String>,
    val keyUsage: List<String>,
    val extendedKeyUsage: List<String>,
    val basicConstraints: String,
    val isSelfSigned: Boolean,
    val raw: X509Certificate
)

data class CRLInfo(
    val issuer: String,
    val thisUpdate: Date,
    val nextUpdate: Date?,
    val revokedEntries: Int,
    val signatureAlgorithm: String,
    val raw: X509CRL
)

// ─── Loaded keystore metadata ──────────────────────────────────────────────────

data class LoadedFile(
    val filePath: String,
    val keystoreType: String,       // e.g. "JKS", "PKCS12", "PEM Certificate", …
    val entries: List<KeyEntry>,
    val fileSizeBytes: Long
)
