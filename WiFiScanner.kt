package com.peagents.wifihacker.engine

import android.content.Context
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import com.peagents.wifihacker.model.NetworkInfo
import com.peagents.wifihacker.model.SecurityType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class WiFiScanner(private val context: Context, private val shell: RootShell) {

    suspend fun scan(): List<NetworkInfo> = withContext(Dispatchers.IO) {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        // Trigger a fresh scan
        wifiManager.startScan()
        Thread.sleep(3000) // Wait for scan to complete

        val results: List<ScanResult> = wifiManager.scanResults ?: emptyList()
        results.map { result ->
            NetworkInfo(
                bssid = result.BSSID,
                ssid = result.SSID.ifEmpty { "(Hidden)" },
                channel = result.frequency.toChannel(),
                frequencyMhz = result.frequency,
                signalDbm = result.level,
                security = parseSecurity(result),
                encryption = result.capabilities ?: "",
                isHidden = result.SSID.isEmpty()
            )
        }
        .sortedByDescending { it.signalDbm }
    }

    suspend fun deepScan(bssid: String): NetworkInfo? = withContext(Dispatchers.IO) {
        // Use iw to get detailed info including PMKID availability, WPS, etc.
        val iface = shell.getWiFiInterface()
        val result = shell.exec("iw", listOf("dev", iface, "scan"))
        val lines = result.stdout.lines()
        val idx = lines.indexOfFirst { it.contains(bssid) }
        if (idx == -1) return@withContext null

        val block = lines.subList(idx, minOf(idx + 30, lines.size))
        val pmkid = block.any { it.contains("PMKID") || it.contains("pmkid") }
        val wps = block.any { it.contains("WPS") || it.contains("wps") }

        // Re-scan and merge
        scan().firstOrNull { it.bssid == bssid }?.let { existing ->
            existing.copy(pmkidAvailable = pmkid, wpsEnabled = wps)
        } ?: NetworkInfo(
            bssid = bssid, ssid = "Unknown", channel = 1,
            frequencyMhz = 2400, signalDbm = -50,
            security = SecurityType.WPA2, encryption = "",
            pmkidAvailable = pmkid, wpsEnabled = wps
        )
    }

    private fun Int.toChannel(): Int = when {
        this in 2401..2483 -> (this - 2401) / 5 + 1
        this in 5170..5835 -> (this - 5180) / 5 + 3
        else -> 1
    }

    private fun parseSecurity(result: ScanResult): SecurityType {
        val caps = result.capabilities.lowercase()
        return when {
            caps.contains("sae") || caps.contains("wpa3") -> SecurityType.WPA3
            caps.contains("wpa2") && caps.contains("wpa-psk") -> SecurityType.WPA2
            caps.contains("wpa") && caps.contains("wpa-psk") -> SecurityType.WPA
            caps.contains("wep") -> SecurityType.WEP
            else -> SecurityType.OPEN
        }
    }
}
