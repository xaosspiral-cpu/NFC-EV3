package com.example.ntag424sdm

/**
 * SunVerifierTest — pure JVM tests (no Android context needed).
 *
 * These tests use the known-good test vectors from AN12196 to validate
 * that SunVerifier's crypto implementation is correct.
 *
 * Run with: ./gradlew :app:test
 *
 * ─────────────────────────────────────────────────────────────────────────
 * How to run without Gradle:
 *   javac -cp bcprov-jdk15on-1.70.jar SunVerifierTest.kt
 *   java  -cp .:bcprov-jdk15on-1.70.jar com.example.ntag424sdm.SunVerifierTestKt
 * ─────────────────────────────────────────────────────────────────────────
 */
object SunVerifierTest {

    // -----------------------------------------------------------------------
    // AN12196 §3.4.2.2 — Decryption of PICCData test vector
    // -----------------------------------------------------------------------
    private fun testDecryptPiccData() {
        val kSdmMetaRead = ByteArray(16) { 0x00 }  // all-zero key (App.Key0 = default)
        val encPiccData  = SunVerifier.hexToBytes("EF963FF7828658A599F3041510671E88")

        val piccData = SunVerifier.aesDecryptCbc(kSdmMetaRead, encPiccData)
        val piccHex  = SunVerifier.bytesToHex(piccData)

        // Expected per AN12196 Table 2, step 3: C704DE5F1EACC0403D0000DA5CF60941
        val expected = "C704DE5F1EACC0403D0000DA5CF60941"
        assert(piccHex.uppercase() == expected) {
            "PICCData mismatch: got $piccHex expected $expected"
        }

        val uid = piccData.copyOfRange(1, 8)
        val ctr = piccData.copyOfRange(8, 11)
        assert(SunVerifier.bytesToHex(uid) == "04DE5F1EACC040") { "UID mismatch" }
        assert(SunVerifier.bytesToHex(ctr) == "3D0000")        { "CTR mismatch" }

        println("✓ testDecryptPiccData PASSED")
    }

    // -----------------------------------------------------------------------
    // AN12196 §3.3 — SDM Session Key Generation test vector
    // -----------------------------------------------------------------------
    private fun testSessionKeyDerivation() {
        val kSdmFileRead = SunVerifier.hexToBytes("5ACE7E50AB65D5D51FD5BF5A16B8205B")
        val uid          = SunVerifier.hexToBytes("04C767F2066180")
        val ctr          = SunVerifier.hexToBytes("010000")  // LSB-first = 1

        val kSesMAC = SunVerifier.deriveSesKey(kSdmFileRead, uid, ctr, forMac = true)
        val kSesENC = SunVerifier.deriveSesKey(kSdmFileRead, uid, ctr, forMac = false)

        // Expected per AN12196 Table 1:
        val expectedMAC = "3A3E8110E05311F7A3FCF0D969BF2B48"
        val expectedENC = "66DA61797E23DECA5D8ECA13BBADF7A9"

        assert(SunVerifier.bytesToHex(kSesMAC).uppercase() == expectedMAC) {
            "KSesSDMFileReadMAC mismatch: got ${SunVerifier.bytesToHex(kSesMAC)} expected $expectedMAC"
        }
        assert(SunVerifier.bytesToHex(kSesENC).uppercase() == expectedENC) {
            "KSesSDMFileReadENC mismatch: got ${SunVerifier.bytesToHex(kSesENC)} expected $expectedENC"
        }

        println("✓ testSessionKeyDerivation PASSED")
    }

    // -----------------------------------------------------------------------
    // AN12196 §3.4.4.2.1 — SDMMAC calculation (CMACInputOffset == CMACOffset)
    // Test vector from Table 4
    // -----------------------------------------------------------------------
    private fun testSdmMacZeroInput() {
        // From AN12196 Table 4 step 13:
        val kSesMAC = SunVerifier.hexToBytes("3FB5F6E3A807A03D5E3570ACE393776F")

        val mact = SunVerifier.computeMact(kSesMAC, ByteArray(0))
        val expected = "94EED9EE65337086"

        assert(SunVerifier.bytesToHex(mact).uppercase() == expected) {
            "MACt mismatch: got ${SunVerifier.bytesToHex(mact)} expected $expected"
        }
        println("✓ testSdmMacZeroInput PASSED")
    }

    // -----------------------------------------------------------------------
    // AN12196 §3.4.4.2.1 — Full SUN verification round-trip
    // Using the example URL from §3.4.2 + §3.4.4.2.1
    // -----------------------------------------------------------------------
    private fun testFullSunVerification() {
        // From AN12196 Figure 2 + Table 4
        val sunUrl = "http://shrt.url.com/e=EF963FF7828658A599F3041510671E88&integCheck_cmac=94EED9EE65337086"

        val result = SunVerifier.verify(
            sunUrl       = sunUrl,
            kSdmMetaRead = ByteArray(16) { 0x00 },  // App.Key0 = all zeros
            kSdmFileRead = ByteArray(16) { 0x00 },  // App.Key0 = all zeros (test vector uses same)
            encParamName = "e",
            macParamName = "integCheck_cmac"
        )

        assert(result.macValid) { "SUN MAC verification failed for AN12196 test vector" }
        assert(SunVerifier.bytesToHex(result.uid) == "04DE5F1EACC040") {
            "UID mismatch in full verification: ${SunVerifier.bytesToHex(result.uid)}"
        }
        assert(result.sdmReadCtrInt == 0x3D) {
            "Counter mismatch: expected 0x3D = 61, got ${result.sdmReadCtrInt}"
        }
        println("✓ testFullSunVerification PASSED")
    }

    // -----------------------------------------------------------------------
    // NdefHelper offset calculation test
    // -----------------------------------------------------------------------
    private fun testNdefOffsets() {
        val url = "https://verify.example.com/ntag424?e=00000000000000000000000000000000&c=0000000000000000"
        val (encOffset, macOffset) = NdefHelper.calculateOffsets(url)

        println("NDEF offset debug:\n${NdefHelper.debugOffsets(url)}")

        // Update SdmConfig constants if these differ:
        println("  ENCPICCDataOffset = 0x${Integer.toHexString(encOffset)} ($encOffset)")
        println("  SDMMACOffset      = 0x${Integer.toHexString(macOffset)} ($macOffset)")

        // Basic sanity: MAC offset must be > ENC offset
        assert(macOffset > encOffset) { "MAC offset must come after ENC offset" }
        println("✓ testNdefOffsets PASSED")
    }

    // -----------------------------------------------------------------------
    // Run all tests
    // -----------------------------------------------------------------------
    fun runAll() {
        println("\n═══════════════════════════════════════")
        println("  SunVerifier Test Suite — AN12196")
        println("═══════════════════════════════════════\n")
        try {
            testDecryptPiccData()
            testSessionKeyDerivation()
            testSdmMacZeroInput()
            testFullSunVerification()
            testNdefOffsets()
            println("\n✅ All tests PASSED")
        } catch (e: AssertionError) {
            println("\n❌ Test FAILED: ${e.message}")
            throw e
        }
    }
}

// Allow running directly from JVM (not Android)
fun main() = SunVerifierTest.runAll()
