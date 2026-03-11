package com.usehashmap.keyinspector.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.usehashmap.keyinspector.model.*
import org.jetbrains.jewel.ui.component.Text
import java.text.SimpleDateFormat
import java.util.Date
import java.util.concurrent.TimeUnit

// ─── Formatting ────────────────────────────────────────────────────────────────

private val DATE_FMT = SimpleDateFormat("yyyy-MM-dd  HH:mm:ss  z")

private const val LABEL_KEY_SIZE = "Key Size"
private const val LABEL_SIG_ALG  = "Signature Algorithm"

/** Fixed width of the label column in dp. */
private const val LABEL_W = 192

// ─── Validity colour-coding ────────────────────────────────────────────────────

private val COLOR_EXPIRED  = Color(0xFFD32F2F)   // red   – already expired
private val COLOR_WARN     = Color(0xFFE65100)   // deep-orange – expiring within 30 days
private val COLOR_OK       = Color(0xFF2E7D32)   // green – more than 30 days left

private fun validityColor(notAfter: Date): Color {
    val msLeft = notAfter.time - System.currentTimeMillis()
    return when {
        msLeft <= 0                                      -> COLOR_EXPIRED
        msLeft <= TimeUnit.DAYS.toMillis(30)             -> COLOR_WARN
        else                                             -> COLOR_OK
    }
}

private fun validityBadge(notAfter: Date): String {
    val msLeft = notAfter.time - System.currentTimeMillis()
    return when {
        msLeft <= 0                                      -> "EXPIRED"
        msLeft <= TimeUnit.DAYS.toMillis(30)             ->
            "EXPIRING IN ${TimeUnit.MILLISECONDS.toDays(msLeft)}d"
        else                                             -> "VALID"
    }
}

// ─── Top-level dispatcher ─────────────────────────────────────────────────────

@Composable
fun EntryDetailPanel(entry: KeyEntry, modifier: Modifier = Modifier) {
    LazyColumn(
        modifier            = modifier.padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp)
    ) {
        item { SectionHeader(entry.entryType.displayName) }
        item { Spacer(Modifier.height(8.dp)) }

        when (entry) {
            is PrivateKeyEntry           -> privateKeyItems(entry)
            is TrustedCertEntry          -> trustedCertItems(entry)
            is SecretKeyEntry            -> secretKeyItems(entry)
            is StandaloneCertEntry       -> standaloneCertItems(entry)
            is StandaloneCRLEntry        -> crlItems(entry)
            is StandaloneCSREntry        -> csrItems(entry)
            is StandalonePublicKeyEntry  -> pubKeyItems(entry)
            is StandalonePrivateKeyEntry -> barePrivKeyItems(entry)
            is UnknownEntry              -> item { DetailRow("Reason", entry.reason) }
        }
    }
}

// ─── Per-entry-type lazy sections ────────────────────────────────────────────

private fun LazyListScope.privateKeyItems(e: PrivateKeyEntry) {
    item { GroupHeader("Key Entry") }
    item { DetailRow("Alias",       e.alias) }
    item { DetailRow("Algorithm",   e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, keySizeStr(e.keySize)) }
    e.creationDate?.let { item { DetailRow("Created", DATE_FMT.format(it)) } }

    if (e.certificateChain.isNotEmpty()) {
        item { Spacer(Modifier.height(12.dp)) }
        item { SectionHeader("Certificate Chain  (${e.certificateChain.size})") }
        e.certificateChain.forEachIndexed { i, cert ->
            val chainLabel = when (i) {
                0                         -> "End-Entity Certificate"
                e.certificateChain.lastIndex -> if (cert.isSelfSigned) "Root CA" else "Intermediate CA"
                else                      -> "Intermediate CA"
            }
            item { Spacer(Modifier.height(10.dp)) }
            item { SubSectionHeader("[${ i + 1}]  $chainLabel") }
            item { SectionDivider() }
            item { Spacer(Modifier.height(4.dp)) }
            certInfoItems(cert)
        }
    }
}

private fun LazyListScope.trustedCertItems(e: TrustedCertEntry) {
    item { GroupHeader("Keystore Entry") }
    item { DetailRow("Alias", e.alias) }
    e.creationDate?.let { item { DetailRow("Created", DATE_FMT.format(it)) } }
    item { Spacer(Modifier.height(10.dp)) }
    item { SectionDivider() }
    item { Spacer(Modifier.height(6.dp)) }
    certInfoItems(e.certificate)
}

private fun LazyListScope.secretKeyItems(e: SecretKeyEntry) {
    item { GroupHeader("Secret Key") }
    item { DetailRow("Alias",       e.alias) }
    item { DetailRow("Algorithm",   e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, keySizeStr(e.keySize)) }
    e.creationDate?.let { item { DetailRow("Created", DATE_FMT.format(it)) } }
}

private fun LazyListScope.standaloneCertItems(e: StandaloneCertEntry) {
    certInfoItems(e.certificate)
}

private fun LazyListScope.crlItems(e: StandaloneCRLEntry) {
    val crl = e.crl
    item { GroupHeader("Revocation List") }
    item { DetailRow("Issuer",          crl.issuer) }
    item { DetailRow("This Update",     DATE_FMT.format(crl.thisUpdate)) }
    item { DetailRow("Next Update",     crl.nextUpdate?.let { DATE_FMT.format(it) } ?: "—") }
    item { DetailRow("Revoked Entries", crl.revokedEntries.toString()) }
    item { DetailRow(LABEL_SIG_ALG,     crl.signatureAlgorithm) }
}

private fun LazyListScope.csrItems(e: StandaloneCSREntry) {
    item { GroupHeader("Certificate Signing Request") }
    item { DetailRow("Subject (Requested)", e.subject) }
    item { DetailRow("Algorithm",           e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE,        keySizeStr(e.keySize)) }
    item { DetailRow(LABEL_SIG_ALG,         e.signatureAlgorithm) }
}

private fun LazyListScope.pubKeyItems(e: StandalonePublicKeyEntry) {
    item { GroupHeader("Public Key") }
    item { DetailRow("Algorithm",   e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, keySizeStr(e.keySize)) }
    item { DetailRow("Format",      e.format) }
}

private fun LazyListScope.barePrivKeyItems(e: StandalonePrivateKeyEntry) {
    item { GroupHeader("Private Key") }
    item { DetailRow("Algorithm",   e.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE, keySizeStr(e.keySize)) }
    item { DetailRow("Format",      e.format) }
}

// ─── Full X.509 certificate detail block ─────────────────────────────────────

private fun LazyListScope.certInfoItems(cert: CertificateInfo) {

    // ── 1. Identity ────────────────────────────────────────────────────────
    item { GroupHeader("Identity") }
    item { DetailRow("Subject DN",     cert.subject) }
    item { DetailRow("Issuer DN",      cert.issuer) }
    item { DetailRow("Serial Number",  cert.serialNumber, monospace = true) }
    item { DetailRow("Version",        "v${cert.version}") }
    item { DetailRow("Self-Signed",    if (cert.isSelfSigned) "Yes" else "No") }

    // ── 2. Validity ────────────────────────────────────────────────────────
    item { Spacer(Modifier.height(8.dp)) }
    item { GroupHeader("Validity Period") }
    item { ValidityDateRow("Not Before", cert.validFrom,  colored = false) }
    item { ValidityDateRow("Not After",  cert.validUntil, colored = true) }

    // ── 3. Key & Signature ─────────────────────────────────────────────────
    item { Spacer(Modifier.height(8.dp)) }
    item { GroupHeader("Public Key & Signature") }
    item { DetailRow("Key Algorithm",  cert.algorithm) }
    item { DetailRow(LABEL_KEY_SIZE,   keySizeStr(cert.keySize)) }
    item { DetailRow(LABEL_SIG_ALG,    cert.signatureAlgorithm) }

    // ── 4. Constraints & Usage ─────────────────────────────────────────────
    item { Spacer(Modifier.height(8.dp)) }
    item { GroupHeader("Constraints & Usage") }
    item { BasicConstraintsRow(cert.basicConstraints) }
    if (cert.keyUsage.isNotEmpty()) {
        item { BadgeListRow("Key Usage", cert.keyUsage, badgeColor = Color(0xFF1565C0)) }
    }
    if (cert.extendedKeyUsage.isNotEmpty()) {
        item { BadgeListRow("Extended Key Usage", cert.extendedKeyUsage, badgeColor = Color(0xFF6A1B9A)) }
    }

    // ── 5. Subject Alternative Names ──────────────────────────────────────
    if (cert.subjectAltNames.isNotEmpty()) {
        item { Spacer(Modifier.height(8.dp)) }
        item { GroupHeader("Subject Alternative Names  (${cert.subjectAltNames.size})") }
        cert.subjectAltNames.forEach { san ->
            item { SanRow(san) }
        }
    }

    // ── 6. Fingerprints ────────────────────────────────────────────────────
    item { Spacer(Modifier.height(8.dp)) }
    item { GroupHeader("Fingerprints") }
    item { FingerprintRow("SHA-256", cert.fingerprintSha256) }
    item { FingerprintRow("SHA-1",   cert.fingerprintSha1) }

    item { Spacer(Modifier.height(12.dp)) }
}

// ─── Certificate-specific composables ────────────────────────────────────────

/**
 * Renders a single date row.  When [colored] is true the date and a status
 * badge use the validity colour (red / orange / green).
 */
@Composable
private fun ValidityDateRow(label: String, date: Date, colored: Boolean) {
    val color = if (colored) validityColor(date) else Color.Unspecified
    val badge = if (colored) validityBadge(date) else null

    Row(
        modifier          = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text       = label,
            fontWeight = FontWeight.Medium,
            fontSize   = 12.sp,
            modifier   = Modifier.width(LABEL_W.dp)
        )
        Text(
            text     = DATE_FMT.format(date),
            fontSize = 12.sp,
            color    = color,
            modifier = Modifier.weight(1f)
        )
        if (badge != null) {
            Spacer(Modifier.width(8.dp))
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(4.dp))
                    .background(color.copy(alpha = 0.13f))
                    .padding(horizontal = 7.dp, vertical = 2.dp)
            ) {
                Text(
                    text       = badge,
                    fontSize   = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color      = color
                )
            }
        }
    }
}

/**
 * Renders the Basic Constraints field with a small "CA" or "End-Entity" badge.
 */
@Composable
private fun BasicConstraintsRow(value: String) {
    val isCA    = value.startsWith("CA")
    val bgColor = if (isCA) Color(0xFF1B5E20) else Color(0xFF37474F)

    Row(
        modifier          = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text       = "Basic Constraints",
            fontWeight = FontWeight.Medium,
            fontSize   = 12.sp,
            modifier   = Modifier.width(LABEL_W.dp)
        )
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(4.dp))
                .background(bgColor.copy(alpha = 0.12f))
                .padding(horizontal = 7.dp, vertical = 2.dp)
        ) {
            Text(
                text       = if (isCA) "CA" else "End-Entity",
                fontSize   = 11.sp,
                fontWeight = FontWeight.SemiBold,
                color      = bgColor
            )
        }
        Spacer(Modifier.width(8.dp))
        Text(text = value, fontSize = 12.sp)
    }
}

/**
 * Renders a label followed by coloured pill chips for each usage string.
 */
@Composable
private fun BadgeListRow(label: String, items: List<String>, badgeColor: Color) {
    Row(
        modifier          = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text       = label,
            fontWeight = FontWeight.Medium,
            fontSize   = 12.sp,
            modifier   = Modifier.width(LABEL_W.dp).padding(top = 3.dp)
        )
        FlowRow(
            modifier             = Modifier.weight(1f),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalArrangement  = Arrangement.spacedBy(4.dp)
        ) {
            items.forEach { usage ->
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(10.dp))
                        .background(badgeColor.copy(alpha = 0.10f))
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Text(text = usage, fontSize = 11.sp, color = badgeColor)
                }
            }
        }
    }
}

/**
 * Renders a single SAN value indented to the value column.
 */
@Composable
private fun SanRow(san: String) {
    Row(
        modifier          = Modifier.fillMaxWidth().padding(vertical = 1.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(Modifier.width(LABEL_W.dp))
        Text(
            text       = san,
            fontSize   = 12.sp,
            fontFamily = FontFamily.Monospace,
            modifier   = Modifier.weight(1f)
        )
    }
}

/**
 * Renders a fingerprint value (colon-separated hex) in monospace, broken into
 * two visual lines if the hash is long (SHA-256).
 */
@Composable
private fun FingerprintRow(label: String, fingerprint: String) {
    // Split SHA-256 (32 pairs) at the midpoint for readability
    val parts = fingerprint.split(":")
    val line1 = parts.take(parts.size / 2 + parts.size % 2).joinToString(":")
    val line2 = parts.drop(parts.size / 2 + parts.size % 2).joinToString(":")

    Row(
        modifier          = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text       = label,
            fontWeight = FontWeight.Medium,
            fontSize   = 12.sp,
            modifier   = Modifier.width(LABEL_W.dp).padding(top = 1.dp)
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(text = line1, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            if (line2.isNotEmpty()) {
                Text(text = line2, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }
        }
    }
}

// ─── Structural composables ───────────────────────────────────────────────────

/** Thin horizontal rule between logical blocks. */
@Composable
fun SectionDivider() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(Color.Gray.copy(alpha = 0.22f))
    )
}

/** Uppercase grey label used as a group header inside the certificate block. */
@Composable
private fun GroupHeader(text: String) {
    Text(
        text       = text.uppercase(),
        fontSize   = 10.sp,
        fontWeight = FontWeight.Bold,
        color      = Color.Gray,
        modifier   = Modifier.padding(top = 4.dp, bottom = 4.dp)
    )
}

// ─── Reusable public composables (also used by FileEditor) ───────────────────

@Composable
fun SectionHeader(text: String) {
    Text(
        text       = text,
        fontSize   = 13.sp,
        fontWeight = FontWeight.Bold,
        modifier   = Modifier.padding(bottom = 2.dp)
    )
}

@Composable
fun SubSectionHeader(text: String) {
    Text(
        text       = text,
        fontSize   = 12.sp,
        fontWeight = FontWeight.SemiBold,
        modifier   = Modifier.padding(bottom = 2.dp)
    )
}

/**
 * A standard label + value row used throughout the panel.
 *
 * Pass an empty [label] to render a value-only row aligned with the value column
 * (used for SANs, continuation lines, etc.).
 */
@Composable
fun DetailRow(label: String, value: String, monospace: Boolean = false) {
    Row(
        modifier          = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.Top
    ) {
        if (label.isNotEmpty()) {
            Text(
                text       = label,
                fontWeight = FontWeight.Medium,
                fontSize   = 12.sp,
                modifier   = Modifier.width(LABEL_W.dp)
            )
        } else {
            Spacer(Modifier.width(LABEL_W.dp))
        }
        Text(
            text       = value,
            fontSize   = 12.sp,
            fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            modifier   = Modifier.weight(1f)
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

private fun keySizeStr(bits: Int) = if (bits > 0) "$bits bits" else "—"

