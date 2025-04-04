package org.example.app

import kotlin.test.Test
import kotlin.test.assertEquals
import java.io.ByteArrayOutputStream
import java.io.PrintStream

class AppTest {

    @Test
    fun testVersionFlag() {
        val outContent = ByteArrayOutputStream()
        val originalOut = System.out

        try {
            System.setOut(PrintStream(outContent))
            main(arrayOf("-version"))
            assertEquals("Version: $APP_VERSION\n", outContent.toString())
        } finally {
            System.setOut(originalOut)
        }
    }

    @Test
    fun testHelpFlag() {
        val outContent = ByteArrayOutputStream()
        val originalOut = System.out

        try {
            System.setOut(PrintStream(outContent))
            main(arrayOf("-help"))
            val expected = """
                Usage: app [-version] [-help]
                Options:
                  -version    Displays the application version
                  -help       Displays this help message

            """.trimIndent()
            assertEquals(expected, outContent.toString())
        } finally {
            System.setOut(originalOut)
        }
    }
}
