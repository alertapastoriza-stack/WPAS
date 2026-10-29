package com.peagents.wifihacker.model

data class NetworkInfo(
    val bssid: String,
    val ssid: String,
    val channel: Int,
    val frequencyMhz: Int,
    val signalDbm: Int,
    val security: SecurityType,
    val encryption: String,
    val isHidden: Boolean = false,
    val pmkidAvailable: Boolean = false,
    val wpsEnabled: Boolean = false
) {
    val isTargetable: Boolean
        get() = security != OPEN && !isHidden

    override fun toString(): String =
        "$ssid [$security] CH:$channel ${signalDbm}dBm $bssid"
}
