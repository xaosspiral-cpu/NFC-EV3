package com.example.ntag424sdm

/**
 * NdefHelper provides utilities to:
 *  1. Build the raw NDEF binary for a URI record (matching what writeNDEF() puts on the tag)
 *  2. Calculate the exact byte offsets of SDM placeholders within that binary
 *
 * This is critical because the offsets passed to ChangeFileSettings MUST match
 * the actual byte positions of the placeholder characters in the NDEF binary.
 *
 * NDEF binary layout for a single URI Well-Known record:
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ Offset │ Size │ Field                                                │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │ 0      │ 2    │ NDEF File Length (0x00, Lc)                         │
 * │ 2      │ 1    │ TNF + flags byte (0xD1 = MB|ME|SR|TNF_WELL_KNOWN)   │
 * │ 3      │ 1    │ Type length (0x01 = 1 byte)                         │
 * │ 4      │ 1    │ Payload length (variable)                           │
 * │ 5      │ 1    │ Type ("U" = 0x55)                                   │
 * │ 6      │ 1    │ URI identifier code (0x04 = "https://")             │
 * │ 7      │ N    │ URL without scheme prefix (ASCII)                   │
 * └──────────────────────────────────────────────────────────────────────┘
 *
 * Total NDEF file content = 2 (len) + 1 + 1 + 1 + 1 + 1 + N = 7 + N bytes
 * where N = len(URL without "https://")
 *
 * The SDM placeholder search scans the binary for the query parameter markers
 * ("?e=" for ENCPICCData, "&c=" for SDMMAC) to derive the correct offsets.
 */
object NdefHelper {

    /**
     * Builds the raw NDEF binary that the NTAG 424 DNA NDEF file will contain.
     *
     * @param url  Full URL including "https://" prefix
     * @return     ByteArray representing the complete NDEF file content
     *
     * Example for url = "https://verify.example.com/ntag424?e=00...00&c=00...00":
     *   bytes[0..1]  = NDEF file length (big-endian)
     *   bytes[2]     = 0xD1 (TNF Well-Known | Short Record | Message Begin | Message End)
     *   bytes[3]     = 0x01 (type length)
     *   bytes[4]     = payload length (1 + url_without_scheme length)
     *   bytes[5]     = 0x55 ('U')
     *   bytes[6]     = 0x04 (https:// identifier)
     *   bytes[7..]   = url without "https://"
     */
    fun buildNdefBinary(url: String): ByteArray {
        require(url.startsWith("https://")) { "URL must start with https://" }

        val urlBody = url.removePrefix("https://").toByteArray(Charsets.US_ASCII)
        val payloadLength = 1 + urlBody.size  // URI code byte + url body

        // Short Record (SR bit set) → payload length fits in 1 byte
        require(payloadLength <= 255) { "URL too long for Short Record NDEF" }

        val recordBytes = ByteArray(3 + 1 + payloadLength)  // flags + typeLen + payloadLen + type + payload
        recordBytes[0] = 0xD1.toByte()       // MB | ME | SR | TNF=0x01
        recordBytes[1] = 0x01                // type length = 1
        recordBytes[2] = payloadLength.toByte()
        recordBytes[3] = 0x55                // type = 'U'
        recordBytes[4] = 0x04                // URI identifier: https://
        urlBody.copyInto(recordBytes, 5)

        // NDEF File content = 2-byte NDEF Length + record bytes
        val totalRecordLength = recordBytes.size
        val ndefFile = ByteArray(2 + totalRecordLength)
        ndefFile[0] = (totalRecordLength shr 8 and 0xFF).toByte()
        ndefFile[1] = (totalRecordLength and 0xFF).toByte()
        recordBytes.copyInto(ndefFile, 2)

        return ndefFile
    }

    /**
     * Calculates the SDM mirror offsets within the NDEF binary produced by [buildNdefBinary].
     *
     * @param url  Full URL template with placeholder characters
     * @param encParamMarker  The marker string whose VALUE starts ENCPICCData (e.g. "?e=")
     * @param macParamMarker  The marker string whose VALUE starts SDMMAC (e.g. "&c=")
     * @return Pair(encPiccDataOffset, sdmMacOffset) in bytes from start of NDEF file
     */
    fun calculateOffsets(
        url: String,
        encParamMarker: String = "?e=",
        macParamMarker: String = "&c="
    ): Pair<Int, Int> {
        val ndefBinary = buildNdefBinary(url)
        val ndefStr = String(ndefBinary, Charsets.ISO_8859_1)

        val encStart = ndefStr.indexOf(encParamMarker)
        require(encStart != -1) { "ENC param marker '$encParamMarker' not found in NDEF" }
        val encOffset = encStart + encParamMarker.length  // offset of first placeholder char

        val macStart = ndefStr.indexOf(macParamMarker)
        require(macStart != -1) { "MAC param marker '$macParamMarker' not found in NDEF" }
        val macOffset = macStart + macParamMarker.length  // offset of first placeholder char

        return Pair(encOffset, macOffset)
    }

    /**
     * Convenience: prints the NDEF binary layout and calculated offsets.
     * Useful for debugging when setting up a new URL template.
     */
    fun debugOffsets(url: String): String {
        val (encOffset, macOffset) = calculateOffsets(url)
        val binary = buildNdefBinary(url)
        return buildString {
            appendLine("URL: $url")
            appendLine("NDEF binary (${binary.size} bytes):")
            appendLine("  [0-1]  NDEF Length: ${String.format("%02X %02X", binary[0], binary[1])}")
            appendLine("  [2]    TNF+flags  : ${String.format("%02X", binary[2])}")
            appendLine("  [3]    Type len   : ${String.format("%02X", binary[3])}")
            appendLine("  [4]    Payload len: ${binary[4].toInt() and 0xFF}")
            appendLine("  [5]    Type ('U') : ${String.format("%02X", binary[5])}")
            appendLine("  [6]    URI code   : ${String.format("%02X", binary[6])} (https://)")
            appendLine("  [7..] URL body")
            appendLine()
            appendLine("ENCPICCDataOffset = 0x${Integer.toHexString(encOffset)} ($encOffset dec)")
            appendLine("SDMMACOffset      = 0x${Integer.toHexString(macOffset)} ($macOffset dec)")
        }
    }
}
