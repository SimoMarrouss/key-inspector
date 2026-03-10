package com.usehashmap.keyinspector.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.usehashmap.keyinspector.model.*
import org.jetbrains.jewel.ui.component.Text
import java.text.SimpleDateFormat

private val DATE_FORMAT = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z")

private const val LABEL_KEY_SIZE = "Key Size"
private const val LABEL_SIG_ALG = "Signature Algorithm"

@Composable
fun EntryDetailPanel(entry: KeyEntry, modifier: Modifier = Modifier) {
    LazyColumn(modifier = modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        item { SectionHeader(entry.entryType.displayName) }
        item { Spacer(Modifier.height(4.dp)) }

        when (entry) {
            is PrivateKeyEntry    -> privateKeyItems(entry)
            is TrustedCertEntry   -> trustedCertItems(entry)
            is SecretKeyEntry     -> secretKeyItems(entry)
            is StandaloneCertEntry -> standaloneCertItems(entry)
            is StandaloneCRLEntry  -> crlItems(entry)
            is StandaloneCSREntry  -> csrItems(entry)
            is StandalonePublicKeyEntry -> pubKeyItems(entry)
            is StandalonePrivateKeyEntry -> barePrivKeyItems(entry)
            is UnknownEntry        -> item { DetailRow("Reason", entry.reason) }
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.privateKeyItems(e: PrivateKeyEntry) {
    item { DetailRow("Alias", e.alias) }
    item { DetailRow("Algorithm", e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, if (e.keySize > 0) "${e.keySize} bits" else "—") }
    e.creationDate?.let { item { DetailRow("Created", DATE_FORMAT.format(it)) } }

    if (e.certificateChain.isNotEmpty()) {
        item { Spacer(Modifier.height(8.dp)) }
        item { SectionHeader("Certificate Chain (${e.certificateChain.size})") }
        e.certificateChain.forEachIndexed { i, cert ->
            item { Spacer(Modifier.height(6.dp)) }
            item { SubSectionHeader("Certificate [${i + 1}]${if (i == 0) " — End-Entity" else ""}") }
            certInfoItems(cert)
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.trustedCertItems(e: TrustedCertEntry) {
    item { DetailRow("Alias", e.alias) }
    e.creationDate?.let { item { DetailRow("Created", DATE_FORMAT.format(it)) } }
    item { Spacer(Modifier.height(8.dp)) }
    certInfoItems(e.certificate)
}

private fun androidx.compose.foundation.lazy.LazyListScope.secretKeyItems(e: SecretKeyEntry) {
    item { DetailRow("Alias", e.alias) }
    item { DetailRow("Algorithm", e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, if (e.keySize > 0) "${e.keySize} bits" else "—") }
    e.creationDate?.let { item { DetailRow("Created", DATE_FORMAT.format(it)) } }
}

private fun androidx.compose.foundation.lazy.LazyListScope.standaloneCertItems(e: StandaloneCertEntry) {
    certInfoItems(e.certificate)
}

private fun androidx.compose.foundation.lazy.LazyListScope.crlItems(e: StandaloneCRLEntry) {
    val crl = e.crl
    item { DetailRow("Issuer", crl.issuer) }
    item { DetailRow("This Update", DATE_FORMAT.format(crl.thisUpdate)) }
    item { DetailRow("Next Update", crl.nextUpdate?.let { DATE_FORMAT.format(it) } ?: "—") }
    item { DetailRow("Revoked Entries", crl.revokedEntries.toString()) }
    item { DetailRow(LABEL_SIG_ALG, crl.signatureAlgorithm) }
}

private fun androidx.compose.foundation.lazy.LazyListScope.csrItems(e: StandaloneCSREntry) {
    item { DetailRow("Subject (Requested)", e.subject) }
    item { DetailRow("Algorithm", e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, if (e.keySize > 0) "${e.keySize} bits" else "—") }
    item { DetailRow(LABEL_SIG_ALG, e.signatureAlgorithm) }
}

private fun androidx.compose.foundation.lazy.LazyListScope.pubKeyItems(e: StandalonePublicKeyEntry) {
    item { DetailRow("Algorithm", e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, if (e.keySize > 0) "${e.keySize} bits" else "—") }
    item { DetailRow("Format", e.format) }
}

private fun androidx.compose.foundation.lazy.LazyListScope.barePrivKeyItems(e: StandalonePrivateKeyEntry) {
    item { DetailRow("Algorithm", e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, if (e.keySize > 0) "${e.keySize} bits" else "—") }
    item { DetailRow("Format", e.format) }
}

private fun androidx.compose.foundation.lazy.LazyListScope.certInfoItems(cert: CertificateInfo) {
    item { DetailRow("Subject", cert.subject) }
    item { DetailRow("Issuer", cert.issuer) }
    item { DetailRow("Serial Number", cert.serialNumber) }
    item { DetailRow("Valid From", DATE_FORMAT.format(cert.validFrom)) }
    item { DetailRow("Valid Until", DATE_FORMAT.format(cert.validUntil)) }
    item { DetailRow("Algorithm", cert.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, if (cert.keySize > 0) "${cert.keySize} bits" else "—") }
    item { DetailRow(LABEL_SIG_ALG, cert.signatureAlgorithm) }
    item { DetailRow("Version", "v${cert.version}") }
    item { DetailRow("Self-Signed", if (cert.isSelfSigned) "Yes" else "No") }
    item { DetailRow("Basic Constraints", cert.basicConstraints) }
    if (cert.keyUsage.isNotEmpty()) {
        item { DetailRow("Key Usage", cert.keyUsage.joinToString(", ")) }
    }
    if (cert.extendedKeyUsage.isNotEmpty()) {
        item { DetailRow("Extended Key Usage", cert.extendedKeyUsage.joinToString(", ")) }
    }
    if (cert.subjectAltNames.isNotEmpty()) {
        item { DetailRow("Subject Alt Names", cert.subjectAltNames.joinToString("\n")) }
    }
    item { Spacer(Modifier.height(6.dp)) }
    item { SubSectionHeader("Fingerprints") }
    item { DetailRow("SHA-1", cert.fingerprintSha1, monospace = true) }
    item { DetailRow("SHA-256", cert.fingerprintSha256, monospace = true) }
}

// ─── Reusable composables ──────────────────────────────────────────────────────

@Composable
fun SectionHeader(text: String) {
    Text(
        text = text,
        fontSize = 13.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(bottom = 2.dp)
    )
}

@Composable
fun SubSectionHeader(text: String) {
    Text(
        text = text,
        fontSize = 12.sp,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(bottom = 2.dp)
    )
}

@Composable
fun DetailRow(label: String, value: String, monospace: Boolean = false) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = label,
            fontWeight = FontWeight.Medium,
            fontSize = 12.sp,
            modifier = Modifier.width(180.dp)
        )
        Text(
            text = value,
            fontSize = 12.sp,
            fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            modifier = Modifier.weight(1f)
        )
    }
}
