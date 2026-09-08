package com.yair.hackerbar

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.provider.MediaStore
import java.io.PrintWriter
import java.io.StringWriter

object CrashReporter {
    fun install(context: Context) {
        val app = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            runCatching { writeReport(app, thread, error) }
            previous?.uncaughtException(thread, error)
        }
    }

    private fun writeReport(context: Context, thread: Thread, error: Throwable) {
        val sw = StringWriter()
        error.printStackTrace(PrintWriter(sw))
        val report = buildString {
            appendLine("DH HackerBar crash report")
            appendLine("time=${System.currentTimeMillis()}")
            appendLine("thread=${thread.name}")
            appendLine("sdk=${Build.VERSION.SDK_INT}")
            appendLine("device=${Build.MANUFACTURER} ${Build.MODEL}")
            appendLine()
            append(sw.toString())
        }
        context.getFileStreamPath("last_crash.txt").writeText(report)
        saveToDownloads(context, report)
    }

private fun saveToDownloads(context: Context, report: String) {
    if (Build.VERSION.SDK_INT < 29) return
    val values = ContentValues().apply {
        put(MediaStore.Downloads.DISPLAY_NAME, "HackerBar-crash-${System.currentTimeMillis()}.txt")
        put(MediaStore.Downloads.MIME_TYPE, "text/plain")
        put(MediaStore.Downloads.RELATIVE_PATH, "Download/HackerBar")
        put(MediaStore.Downloads.IS_PENDING, 1)
    }
    val resolver = context.contentResolver
    val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return
    resolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(report) }
    values.clear()
    values.put(MediaStore.Downloads.IS_PENDING, 0)
    resolver.update(uri, values, null, null)
}
