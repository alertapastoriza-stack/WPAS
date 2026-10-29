package com.peagents.wifihacker.model

enum class SecurityType(val label: String, val hexValue: Int) {
    OPEN("Open", 0),
    WEP("WEP", 1),
    WPA("WPA (PSK)", 2),
    WPA2("WPA2 (PSK)", 4),
    WPA3("WPA3-SAE", 8),
    WPA_WPA2("WPA + WPA2", 6),
    WPA2_WPA3("WPA2 + WPA3", 12);

    companion object {
        fun fromHex(hex: Int): SecurityType =
            entries.find { it.hexValue == hex } ?: OPEN
    }
}
