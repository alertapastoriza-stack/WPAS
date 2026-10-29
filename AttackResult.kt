package com.peagents.wifihacker.model

data class AttackResult(
    val targetBSSID: String,
    val targetSSID: String,
    val securityType: SecurityType,
    val success: Boolean,
    val password: String?,
    val methodUsed: String,
    val durationMs: Long,
    val attemptsMade: Long,
    val timestamp: Long = System.currentTimeMillis()
)
