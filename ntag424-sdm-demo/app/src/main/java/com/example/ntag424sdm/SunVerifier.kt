package com.example.ntag424sdm

import android.net.Uri
import android.util.Log
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * SunVerifier implements the backend-side SUN (Secure Unique NFC) message verification
 * as specified in NXP AN12196 §3.4.
 *
 * This class does NOT use the TapLinX SDK — it is pure Kotlin + BouncyCastle so it
 * can also run on a server/backend.  On-device, you can alternatively call:
 *   ntag424DNA.verifySecureDynamicMessagingMacWithAESMode(...)
 *
 * Flow (AN12196 §3.4.4.2.1 — CMACInputOffset == CMACOffset):
 *  1. Parse URL parameters: e= (ENCPICCData) and c= (SDMMAC)
 *  2. Decrypt ENCPICCData with KSDMMetaRead → PICCDataTag | UID | SDMReadCtr | padding
 *  3. Derive KSesSDMFileReadMAC from KSDMFileRead using SV2
 *  4. Compute MACt over zero-length input (when CMACInputOffset == CMACOffset)
 *     OR over DynamicFileData[CMACInputOffset..CMACOffset-1] if they differ
 *  5. Compare computed MACt with received SDMMAC
 */
object SunVerifier {

    private const val TAG = "SunVerifier"

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    data class SunParseResult(
        val uid: ByteArray,
        val sdmReadCtr: ByteArray,    // 3 bytes LSB-first
        val sdmReadCtrInt: Int,
        val macValid: Boolean
    )

    /**
     * Verifies a SUN URL that uses encrypted PICCData + CMAC.
     *
     * @param sunUrl          Full URL received from the NFC tap (e.g. via Intent data)
     * @param kSdmMetaRead    16-byte KSDMMetaRead key (decrypts ENCPICCData)
     * @param kSdmFileRead    16-byte KSDMFileRead key (derives KSesSDMFileReadMAC)
     * @param encParamName    URL query param name for ENCPICCData (default "e")
     * @param macParamName    URL query param name for SDMMAC (default "c")
     * @return SunParseResult with uid, counter, and macValid flag
     * @throws IllegalArgumentException if URL params are missing or malformed
     */
    fun verify(
        sunUrl: String,
        kSdmMetaRead: ByteArray,
        kSdmFileRead: ByteArray,
        encParamName: String = "e",
        macParamName: String = "c"
    ): SunParseResult {
        val uri = Uri.parse(sunUrl)

        val encPiccHex = uri.getQueryParameter(encParamName)
            ?: throw IllegalArgumentException("Missing '$encParamName' parameter in URL")
        val sdmMacHex = uri.getQueryParameter(macParamName)
            ?: throw IllegalArgumentException("Missing '$macParamName' parameter in URL")

        log("ENCPICCData  : $encPiccHex")
        log("SDMMAC (rcvd): $sdmMacHex")

        // Step 1 — Decrypt ENCPICCData → PICCData (AN12196 §3.4.2.2)
        val encPiccData = hexToBytes(encPiccHex)
        val piccData = aesDecryptCbc(kSdmMetaRead, encPiccData)

        val piccDataTag = piccData[0].toInt() and 0xFF
        log("PICCDataTag  : ${String.format("%02X", piccDataTag)}")

        val uidPresent   = (piccDataTag shr 7) and 0x01 == 1
        val ctrPresent   = (piccDataTag shr 6) and 0x01 == 1
        val uidLength    = piccDataTag and 0x0F  // should be 7 for standard UID

        var offset = 1
        val uid = if (uidPresent) piccData.copyOfRange(offset, offset + uidLength).also { offset += uidLength }
                  else ByteArray(0)
        val ctr = if (ctrPresent) piccData.copyOfRange(offset, offset + 3)
                  else ByteArray(0)

        val ctrInt = if (ctr.size == 3) {
            (ctr[0].toInt() and 0xFF) or
            ((ctr[1].toInt() and 0xFF) shl 8) or
            ((ctr[2].toInt() and 0xFF) shl 16)
        } else 0

        log("UID          : ${bytesToHex(uid)}")
        log("SDMReadCtr   : ${bytesToHex(ctr)} (= $ctrInt decimal)")

        // Step 2 — Derive KSesSDMFileReadMAC from KSDMFileRead (AN12196 §3.3)
        val kSesMAC = deriveSesKey(kSdmFileRead, uid, ctr, forMac = true)
        log("KSesFileReadMAC: ${bytesToHex(kSesMAC)}")

        // Step 3 — Compute MACt
        // When CMACInputOffset == CMACOffset the MAC input is zero-length (AN12196 §3.4.4.2.1)
        val computedMact = computeMact(kSesMAC, ByteArray(0))
        log("SDMMAC (calc): ${bytesToHex(computedMact)}")

        val macValid = computedMact.contentEquals(hexToBytes(sdmMacHex))
        log("MAC valid    : $macValid")

        return SunParseResult(uid, ctr, ctrInt, macValid)
    }

    /**
     * Verifies a SUN URL where CMACInputOffset != CMACOffset (AN12196 §3.4.4.2.2).
     * In this case the CMAC covers the file data between CMACInputOffset and CMACOffset.
     *
     * @param sunUrl          Full URL
     * @param dynamicFileData The ASCII file data slice: DynamicFileData[CMACInputOffset..CMACOffset-1]
     *                        (the portion of the URL between the enc param value and "&c=")
     */
    fun verifyWithFileData(
        sunUrl: String,
        dynamicFileData: ByteArray,
        kSdmMetaRead: ByteArray,
        kSdmFileRead: ByteArray,
        encParamName: String = "picc_data",
        macParamName: String = "cmac"
    ): SunParseResult {
        val uri = Uri.parse(sunUrl)

        val encPiccHex = uri.getQueryParameter(encParamName)
            ?: throw IllegalArgumentException("Missing '$encParamName' parameter")
        val sdmMacHex  = uri.getQueryParameter(macParamName)
            ?: throw IllegalArgumentException("Missing '$macParamName' parameter")

        val piccData = aesDecryptCbc(kSdmMetaRead, hexToBytes(encPiccHex))

        val piccDataTag = piccData[0].toInt() and 0xFF
        val uidLen      = piccDataTag and 0x0F
        val uid         = piccData.copyOfRange(1, 1 + uidLen)
        val ctr         = piccData.copyOfRange(1 + uidLen, 1 + uidLen + 3)
        val ctrInt      = (ctr[0].toInt() and 0xFF) or
                          ((ctr[1].toInt() and 0xFF) shl 8) or
                          ((ctr[2].toInt() and 0xFF) shl 16)

        val kSesMAC     = deriveSesKey(kSdmFileRead, uid, ctr, forMac = true)
        val computedMact = computeMact(kSesMAC, dynamicFileData)

        val macValid = computedMact.contentEquals(hexToBytes(sdmMacHex))
        return SunParseResult(uid, ctr, ctrInt, macValid)
    }

    // -----------------------------------------------------------------------
    // Crypto helpers (all per AN12196 spec)
    // -----------------------------------------------------------------------

    /**
     * Derives KSesSDMFileReadENC (forMac=false) or KSesSDMFileReadMAC (forMac=true).
     *
     * SV construction (AN12196 §3.3):
     *   SV1 = C33C 0001 0080 [UID] [SDMReadCtr] [ZeroPadding to 16 bytes]
     *   SV2 = 3CC3 0001 0080 [UID] [SDMReadCtr] [ZeroPadding to 16 bytes]
     *
     * KSesSDMFileReadENC = CMAC(KSDMFileRead, SV1)
     * KSesSDMFileReadMAC = CMAC(KSDMFileRead, SV2)
     */
    fun deriveSesKey(kSdmFileRead: ByteArray, uid: ByteArray, ctr: ByteArray, forMac: Boolean): ByteArray {
        val prefix = if (forMac)
            byteArrayOf(0x3C, 0xC3.toByte(), 0x00, 0x01, 0x00, 0x80.toByte())
        else
            byteArrayOf(0xC3.toByte(), 0x3C, 0x00, 0x01, 0x00, 0x80.toByte())

        // Build SV: prefix (6) + UID (7) + CTR (3) = 16 bytes total
        val sv = ByteArray(16)
        System.arraycopy(prefix, 0, sv, 0, 6)
        System.arraycopy(uid, 0, sv, 6, uid.size.coerceAtMost(7))
        System.arraycopy(ctr, 0, sv, 6 + uid.size.coerceAtMost(7), ctr.size.coerceAtMost(3))
        // remaining bytes stay 0x00 (zero padding)

        return cmacAes128(kSdmFileRead, sv)
    }

    /**
     * Computes MACt (truncated CMAC) as defined in AN12196 §2:
     *   Full CMAC → retain even-indexed bytes (S14,S12,...S0) → 8 bytes result
     */
    fun computeMact(key: ByteArray, message: ByteArray): ByteArray {
        val fullCmac = cmacAes128(key, message)
        // Truncate: keep odd bytes (1,3,5,...15) → 8 bytes in MSB-first order
        return ByteArray(8) { i -> fullCmac[2 * i + 1] }
    }

    /**
     * AES-128 CBC decrypt with IV = 0x00…00 (16 zero bytes), as used in NTAG 424 DNA spec.
     */
    fun aesDecryptCbc(key: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(ByteArray(16)))
        return cipher.doFinal(data)
    }

    /**
     * AES-128 CBC encrypt with IV = 0x00…00 (16 zero bytes).
     */
    fun aesEncryptCbc(key: ByteArray, iv: ByteArray = ByteArray(16), data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    /**
     * Full AES-128 CMAC per NIST SP 800-38B, using BouncyCastle.
     */
    fun cmacAes128(key: ByteArray, message: ByteArray): ByteArray {
        val mac = CMac(AESEngine())
        mac.init(KeyParameter(key))
        mac.update(message, 0, message.size)
        val result = ByteArray(16)
        mac.doFinal(result, 0)
        return result
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Odd hex string length: ${hex.length}" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { String.format("%02X", it) }

    private fun log(msg: String) = Log.d(TAG, msg)
}
