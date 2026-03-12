package com.security.ransomwaredefense.security

import android.content.Context
import android.os.Environment
import com.security.ransomwaredefense.data.FileEvent
import java.io.File

class HoneypotManager(private val context: Context) {

    private val honeypotFiles = mutableListOf<File>()

    private val decoyFileNames = listOf(
        "bank_details.txt",
        "salary_records.txt",
        "personal_photos.txt",
        "passwords.txt",
        "credit_card_info.txt",
        "private_documents.txt"
    )

    fun createHoneypotFiles(): List<File> {
        val baseDir = Environment.getExternalStoragePublicDirectory(
            Environment.DIRECTORY_DOCUMENTS
        )
        if (!baseDir.exists()) baseDir.mkdirs()

        honeypotFiles.clear()

        decoyFileNames.forEach { fileName ->
            try {
                val file = File(baseDir, ".$fileName")
                if (!file.exists()) {
                    file.writeText(generateDecoyContent(fileName))
                }
                honeypotFiles.add(file)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
        return honeypotFiles
    }

    fun isHoneypotFile(filePath: String): Boolean {
        return honeypotFiles.any { it.absolutePath == filePath } ||
                decoyFileNames.any { filePath.contains(it) }
    }

    fun getHoneypotPaths(): List<String> {
        return honeypotFiles.map { it.absolutePath }
    }

    fun checkHoneypotIntegrity(): List<FileEvent> {
        val violations = mutableListOf<FileEvent>()
        honeypotFiles.forEach { file ->
            if (!file.exists()) {
                violations.add(
                    FileEvent(
                        filePath = file.absolutePath,
                        eventType = "HONEYPOT_DELETED",
                        timestamp = System.currentTimeMillis(),
                        isHoneypot = true
                    )
                )
            }
        }
        return violations
    }

    private fun generateDecoyContent(fileName: String): String {
        return when {
            fileName.contains("bank") ->
                "Account: XXXX-XXXX-XXXX-1234\nBalance: \$45,230.00\nRouting: 021000021"
            fileName.contains("salary") ->
                "Employee Salary Records 2024\nJohn Doe: \$85,000\nJane Smith: \$92,000"
            fileName.contains("password") ->
                "gmail: mypassword123\nfacebook: securepass456\nbank: pincode789"
            fileName.contains("credit") ->
                "Visa: 4532-XXXX-XXXX-9876\nExp: 12/26\nCVV: 123"
            else ->
                "Confidential Document\nCreated: ${System.currentTimeMillis()}\nDo not share."
        }
    }
}