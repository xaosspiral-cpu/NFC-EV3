package com.example.ntag424sdm

import android.util.Log
import com.nxp.nfclib.CustomModules
import com.nxp.nfclib.desfire.INTAG424DNA
import com.nxp.nfclib.desfire.SUNMessageUtility

/**
 * SunMessageVerifier — las DOS rutas de verificación SUN confirmadas en bytecode.
 *
 * ─── Firmas confirmadas ────────────────────────────────────────────────────
 *
 * RUTA 1 — Vía instancia del tag (requiere tag activo):
 *   INTAG424DNA.verifySecureDynamicMessagingMacWithAESMode(
 *       piccEncData:  ByteArray,
 *       encFileData:  ByteArray,   // ByteArray(0) si SDMENCFileData no está activo
 *       sdmMac:       ByteArray,
 *       sdmMetaReadKey: ByteArray,
 *       sdmFileReadKey: ByteArray
 *   ): Boolean
 *   (firma: ([B [B [B [B [B): Z — 5 ByteArrays, sin CustomModules)
 *
 * RUTA 2 — Vía SUNMessageUtility (sin tag activo, para procesar URLs recibidas):
 *   SUNMessageUtility().verifySecureDynamicMessagingMacAESMode(
 *       customModules: CustomModules,
 *       piccEncData:   ByteArray,
 *       encFileData:   ByteArray,   // ByteArray(0) si no hay ENCFileData
 *       sdmMac:        ByteArray,
 *       sdmMetaReadKey: ByteArray,
 *       sdmFileReadKey: ByteArray
 *   ): Boolean
 *   (firma: (CustomModules [B [B [B [B [B): Z)
 *
 * ─── Parámetro encFileData ─────────────────────────────────────────────────
 *   Cuando no hay SDMENCFileData (caso CMACInputOffset == CMACOffset del §3.4.4.2.1)
 *   pasar ByteArray(0) — el SDK interpreta esto como MAC sobre input vacío.
 *
 * ─── Alternativa sin SDK ───────────────────────────────────────────────────
 *   SunVerifier.verify() implementa la misma lógica en Kotlin puro + BouncyCastle.
 *   Úsala cuando no tengas CustomModules disponibles (backend, tests JVM).
 * ─────────────────────────────────────────────────────────────────────────────
 */
object SunMessageVerifier {

    private const val TAG = "SunMessageVerifier"

    // ─────────────────────────────────────────────────────────────────────────
    // RUTA 1: verificación on-device vía instancia del tag
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifica el SDMMAC de un SUN usando la instancia activa del tag.
     *
     * La firma del método SDK es:
     *   verifySecureDynamicMessagingMacWithAESMode([B [B [B [B [B): Z
     *
     * Orden de parámetros confirmado:
     *   1. piccEncData     — ENCPICCData (del param "e=" en la URL)
     *   2. encFileData     — SDMENCFileData (ByteArray(0) si no hay ENCFileData)
     *   3. sdmMac          — SDMMAC recibido (del param "c=" en la URL)
     *   4. sdmMetaReadKey  — KSDMMetaRead en bruto (ByteArray)
     *   5. sdmFileReadKey  — KSDMFileRead en bruto (ByteArray)
     *
     * @param tag           Instancia activa (tag ya detectado, SSM opcional — este método
     *                      puede no necesitar SSM dependiendo de la implementación TapLinX)
     * @param piccEncDataHex  Hexstring del ENCPICCData (32 hex chars = 16 bytes)
     * @param sdmMacHex       Hexstring del SDMMAC (16 hex chars = 8 bytes)
     * @param encFileData     ByteArray(0) si CMACInputOffset == CMACOffset
     */
    fun verifyViaTag(
        tag:            INTAG424DNA,
        piccEncDataHex: String,
        sdmMacHex:      String,
        kSdmMetaRead:   ByteArray = Ntag424SDMConfig.KEY_SDM_META_READ,
        kSdmFileRead:   ByteArray = Ntag424SDMConfig.KEY_SDM_FILE_READ,
        encFileData:    ByteArray = ByteArray(0)   // vacío = sin SDMENCFileData
    ): Boolean {
        val piccEncData = SunVerifier.hexToBytes(piccEncDataHex)
        val sdmMac      = SunVerifier.hexToBytes(sdmMacHex)

        Log.d(TAG, "verifyViaTag: ENCPICCData=${piccEncDataHex.uppercase()}")
        Log.d(TAG, "verifyViaTag: SDMMAC=${sdmMacHex.uppercase()}")

        return tag.verifySecureDynamicMessagingMacWithAESMode(
            piccEncData,   // [B param 1
            encFileData,   // [B param 2 — ByteArray(0) si no hay ENCFileData
            sdmMac,        // [B param 3
            kSdmMetaRead,  // [B param 4
            kSdmFileRead   // [B param 5
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RUTA 2: verificación offline vía SUNMessageUtility (sin tag activo)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifica el SDMMAC de un SUN usando SUNMessageUtility.
     * No requiere tag activo — procesa directamente los parámetros de la URL.
     *
     * La firma del método SDK es:
     *   SUNMessageUtility().verifySecureDynamicMessagingMacAESMode(
     *       customModules, [B piccEncData, [B encFileData, [B sdmMac,
     *       [B metaReadKey, [B fileReadKey): Z
     *
     * @param customModules  Obtenido de NxpNfcLib.getInstance().getCustomModules()
     * @param piccEncDataHex Hexstring del parámetro "e=" de la URL
     * @param sdmMacHex      Hexstring del parámetro "c=" de la URL
     * @param encFileData    ByteArray(0) si CMACInputOffset == CMACOffset (caso más común)
     */
    fun verifyViaSUNMessageUtility(
        customModules:  CustomModules,
        piccEncDataHex: String,
        sdmMacHex:      String,
        kSdmMetaRead:   ByteArray = Ntag424SDMConfig.KEY_SDM_META_READ,
        kSdmFileRead:   ByteArray = Ntag424SDMConfig.KEY_SDM_FILE_READ,
        encFileData:    ByteArray = ByteArray(0)
    ): Boolean {
        val piccEncData = SunVerifier.hexToBytes(piccEncDataHex)
        val sdmMac      = SunVerifier.hexToBytes(sdmMacHex)

        Log.d(TAG, "verifyViaSUNUtil: ENCPICCData=${piccEncDataHex.uppercase()}")
        Log.d(TAG, "verifyViaSUNUtil: SDMMAC=${sdmMacHex.uppercase()}")

        return SUNMessageUtility().verifySecureDynamicMessagingMacAESMode(
            customModules,  // CustomModules param 1
            piccEncData,    // [B param 2
            encFileData,    // [B param 3 — ByteArray(0) si no hay ENCFileData
            sdmMac,         // [B param 4
            kSdmMetaRead,   // [B param 5
            kSdmFileRead    // [B param 6
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RUTA 3: verificación pura Kotlin (sin SDK, válida en backend)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Wrapper de SunVerifier.verify() para tener las tres rutas en un solo lugar.
     *
     * No requiere ni tag ni CustomModules.
     * Implementa AN12196 §3.4.2.2 + §3.3 + §3.4.4.2.1 con vectores verificados.
     */
    fun verifyPureKotlin(
        sunUrl:      String,
        kSdmMetaRead: ByteArray = Ntag424SDMConfig.KEY_SDM_META_READ,
        kSdmFileRead: ByteArray = Ntag424SDMConfig.KEY_SDM_FILE_READ,
        encParamName: String = "e",
        macParamName: String = "c"
    ): SunVerifier.SunParseResult {
        return SunVerifier.verify(sunUrl, kSdmMetaRead, kSdmFileRead, encParamName, macParamName)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper: extrae los parámetros SUN de una URL y elige la ruta de verificación
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Decide automáticamente qué ruta usar según disponibilidad:
     *   - Si tiene customModules → Ruta 2 (SUNMessageUtility)
     *   - Si no → Ruta 3 (puro Kotlin)
     *
     * La Ruta 1 (vía tag) no se incluye aquí porque requiere tag activo,
     * que normalmente ya no está disponible cuando se procesa la URL.
     */
    fun verifyBestEffort(
        sunUrl:        String,
        customModules: CustomModules?,
        kSdmMetaRead:  ByteArray = Ntag424SDMConfig.KEY_SDM_META_READ,
        kSdmFileRead:  ByteArray = Ntag424SDMConfig.KEY_SDM_FILE_READ,
        encParamName:  String = "e",
        macParamName:  String = "c"
    ): Pair<Boolean, String> {
        // Extraer parámetros de la URL
        val uri   = android.net.Uri.parse(sunUrl)
        val encHex = uri.getQueryParameter(encParamName) ?: return Pair(false, "Missing '$encParamName'")
        val macHex = uri.getQueryParameter(macParamName) ?: return Pair(false, "Missing '$macParamName'")

        return if (customModules != null) {
            Log.d(TAG, "Using SUNMessageUtility (Ruta 2)")
            val valid = verifyViaSUNMessageUtility(customModules, encHex, macHex, kSdmMetaRead, kSdmFileRead)
            Pair(valid, "SUNMessageUtility")
        } else {
            Log.d(TAG, "Using pure Kotlin SunVerifier (Ruta 3)")
            val result = SunVerifier.verify(sunUrl, kSdmMetaRead, kSdmFileRead, encParamName, macParamName)
            Pair(result.macValid, "SunVerifier (Kotlin)")
        }
    }
}
