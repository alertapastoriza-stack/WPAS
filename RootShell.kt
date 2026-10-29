package com.peagents.wifihacker.engine

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

/**
 * Capa de abstracción sobre el shell root del dispositivo.
 * Ejecuta comandos nativos (aircrack-ng, wpa_supplicant, hostapd, iw)
 * con timeout, captura de stdout/stderr y manejo de errores.
 */
class RootShell(private val context: Context) {

    data class ShellResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val success: Boolean = exitCode == 0
    )

    private var rootAvailable: Boolean? = null

    suspend fun checkRoot(): Boolean = withContext(Dispatchers.IO) {
        if (rootAvailable != null) return@withContext rootAvailable!!
        try {
            val result = exec("id", timeoutSec = 5)
            rootAvailable = result.stdout.contains("uid=0")
        } catch (_: Exception) {
            rootAvailable = false
        }
        rootAvailable!!
    }

    suspend fun exec(
        command: String,
        args: List<String> = emptyList(),
        timeoutSec: Long = 30,
        workingDir: String? = null
    ): ShellResult = withContext(Dispatchers.IO) {
        val fullCmd = listOf("su", "-c", buildString {
            append(command)
            args.forEach { append(" ").append(it) }
        })

        try {
            val process = ProcessBuilder(*fullCmd.toTypedArray())
                .redirectError(ProcessBuilder.Redirect.PIPE)
                .redirectOutput(ProcessBuilder.Redirect.PIPE)
                .apply { workingDir?.let { directory = java.io.File(it) } }
                .start()

            val stdout = BufferedReader(InputStreamReader(process.inputStream)).use { it.readText() }
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).use { it.readText() }

            val finished = process.waitFor(timeoutSec, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                return@withContext ShellResult(-1, stdout, "TIMEOUT: $command", false)
            }

            ShellResult(process.exitValue(), stdout, stderr)
        } catch (e: Exception) {
            ShellResult(-1, "", e.message ?: "Unknown error", false)
        }
    }

    suspend fun execRaw(cmd: String, timeoutSec: Long = 30): ShellResult = withContext(Dispatchers.IO) {
        try {
            val process = ProcessBuilder("su", "-c", cmd).start()
            val stdout = BufferedReader(InputStreamReader(process.inputStream)).use { it.readText() }
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).use { it.readText() }
            val finished = process.waitFor(timeoutSec, TimeUnit.SECONDS)
            if (!finished) { process.destroyForcibly(); return@withContext ShellResult(-1, stdout, "TIMEOUT", false) }
            ShellResult(process.exitValue(), stdout, stderr)
        } catch (e: Exception) {
            ShellResult(-1, "", e.message ?: "", false)
        }
    }

    suspend fun getWiFiInterface(): String = withContext(Dispatchers.IO) {
        val result = exec("iw", listOf("dev"))
        // Parse "wlan0" or "wlan1" from output
        result.stdout.lines()
            .firstOrNull { it.trim().startsWith("Device") }
            ?.substringAfter("Device")
            ?.trim()
            ?: "wlan0"
    }

    suspend fun setMonitorMode(iface: String): Boolean = withContext(Dispatchers.IO) {
        exec("ip", listOf("link", "set", iface, "down")).success &&
        exec("iw", listOf(iface, "set", "type", "monitor")).success &&
        exec("ip", listOf("link", "set", iface, "up")).success
    }

    suspend fun setManagedMode(iface: String): Boolean = withContext(Dispatchers.IO) {
        exec("ip", listOf("link", "set", iface, "down")).success &&
        exec("iw", listOf(iface, "set", "type", "managed")).success &&
        exec("ip", listOf("link", "set", iface, "up")).success
    }

    suspend fun getChannel(iface: String): Int = withContext(Dispatchers.IO) {
        val result = exec("iw", listOf("dev", iface, "info"))
        result.stdout
            .lines()
            .firstOrNull { it.contains("channel") }
            ?.substringAfter("channel")
            ?.trim()
            ?.toIntOrNull()
            ?: 1
    }

    suspend fun setChannel(iface: String, channel: Int): Boolean = withContext(Dispatchers.IO) {
        exec("iw", listOf(iface, "set", "channel", channel.toString())).success
    }
}
