package com.peagents.wifihacker.engine

import android.content.Context
import java.io.File

class DictionaryManager(private val context: Context) {

    private val dictDir = File(context.filesDir, "dictionaries")

    init {
        if (!dictDir.exists()) dictDir.mkdirs()
        // Copy bundled dictionaries from assets on first run
        copyAssets()
    }

    fun getAvailableDictionaries(): List<File> {
        return dictDir.listFiles()?.filter { it.extension == "txt" }?.sortedBy { it.name } ?: emptyList()
    }

    fun getDefaultDictionary(): File? {
        return listOf("wifipass-2024.txt", "rockyou-top10k.txt")
            .map { File(dictDir, it) }
            .firstOrNull { it.exists() }
    }

    fun importDictionary(sourceFile: File): File {
        val dest = File(dictDir, sourceFile.name)
        sourceFile.copyTo(dest, overwrite = true)
        return dest
    }

    fun getDictionarySize(file: File): Long {
        return file.inputStream().use { stream ->
            var count = 0L
            val buffer = ByteArray(8192)
            var read: Int
            while (stream.read(buffer).also { read = it } != -1) {
                for (i in 0 until read) if (buffer[i] == '\n'.code.toByte()) count++
            }
            count
        }
    }

    private fun copyAssets() {
        val assets = context.assets
        val bundled = listOf("rockyou-top10k.txt", "wifipass-2024.txt", "custom-patterns.txt")
        for (name in bundled) {
            val dest = File(dictDir, name)
            if (!dest.exists()) {
                try {
                    assets.open(name).use { input ->
                        dest.outputStream().use { output -> input.copyTo(output) }
                    }
                } catch (_: Exception) { /* asset not bundled */ }
            }
        }
    }
}
