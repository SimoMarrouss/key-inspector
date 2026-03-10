package com.usehashmap.keyinspector

import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import java.security.Security

/**
 * Registers BouncyCastle providers once at IDE startup so that BKS, UBER, BCFKS
 * and all other BC-specific key/cert operations work correctly.
 */
class BouncyCastleStartupActivity : ProjectActivity {
    override suspend fun execute(project: Project) {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastlePQCProvider())
        }
    }
}
