package com.example.ntag424sdm

/**
 * Ntag424SDMConfig — todas las constantes y helpers de configuración SDM.
 *
 * CORRECCIÓN vs versión anterior:
 *   Todos los setters de offset en NTAG424DNAFileSettings reciben ByteArray (3 bytes, LSB first),
 *   NO Int. Firma confirmada en bytecode: ([B)V
 *
 * Ejemplo:
 *   ❌  settings.setPiccDataOffset(0x20)
 *   ✅  settings.setPiccDataOffset(byteArrayOf(0x20, 0x00, 0x00))
 *   ✅  settings.setPiccDataOffset(Ntag424SDMConfig.offsetBytes(0x20))
 */
object Ntag424SDMConfig {

    // -------------------------------------------------------------------------
    // Keys — sustituir antes de producción; nunca usar factory-default (all-zero)
    // -------------------------------------------------------------------------

    /** AppKey 0x00 — Master key (autenticación + ChangeFileSettings) */
    val KEY_MASTER: ByteArray = ByteArray(16) { 0x00 }

    /** AppKey 0x01 — SDMFileReadKey → deriva KSesSDMFileReadMAC para el CMAC */
    val KEY_SDM_FILE_READ: ByteArray = ByteArray(16) { 0x00 }

    /** AppKey 0x02 — SDMMetaReadKey → cifra PICCData (UID+CTR) → ENCPICCData */
    val KEY_SDM_META_READ: ByteArray = ByteArray(16) { 0x00 }

    // -------------------------------------------------------------------------
    // NFC Forum NDEF Application DF Name (fijo para NTAG 424 DNA)
    // -------------------------------------------------------------------------
    val APP_DFNAME: ByteArray =
        byteArrayOf(0xD2.toByte(), 0x76, 0x00, 0x00, 0x85.toByte(), 0x01, 0x01)

    /** Número de fichero NDEF */
    const val FILE_NO_NDEF = 0x02

    // -------------------------------------------------------------------------
    // URL template — los placeholders serán sobreescritos por el tag en cada tap
    //
    // ENCPICCData: 32 chars ASCII-hex (16 bytes cifrados)
    // SDMMAC:      16 chars ASCII-hex ( 8 bytes MACt)
    //
    // IMPORTANTE: los offsets calculados abajo DEBEN coincidir con las posiciones
    // reales dentro del binario NDEF. Usa NdefHelper.debugOffsets(URL_TEMPLATE)
    // para verificarlos antes de personalizar.
    // -------------------------------------------------------------------------
    const val URL_TEMPLATE =
        "https://verify.example.com/ntag424?e=00000000000000000000000000000000&c=0000000000000000"

    // Offsets calculados para URL_TEMPLATE con NdefHelper.calculateOffsets()
    // Verificar siempre al cambiar la URL.
    private const val _OFFSET_ENC_PICC = 0x20   // 32 dec
    private const val _OFFSET_SDM_MAC  = 0x43   // 67 dec

    // -------------------------------------------------------------------------
    // Conversión de offsets: Int → ByteArray(3) LSB-first
    // (firma real de los setters: ([B)V — confirmado en bytecode)
    // -------------------------------------------------------------------------

    /**
     * Convierte un offset entero a ByteArray de 3 bytes en formato LSB-first,
     * tal como requieren todos los setters de offset de NTAG424DNAFileSettings.
     */
    fun offsetBytes(offset: Int): ByteArray = byteArrayOf(
        (offset and 0xFF).toByte(),
        ((offset shr 8) and 0xFF).toByte(),
        ((offset shr 16) and 0xFF).toByte()
    )

    // Offsets pre-calculados para la URL_TEMPLATE
    val OFFSET_ENC_PICC_DATA: ByteArray = offsetBytes(_OFFSET_ENC_PICC)
    val OFFSET_SDM_MAC:       ByteArray = offsetBytes(_OFFSET_SDM_MAC)

    // -------------------------------------------------------------------------
    // SDMAccessRights (2 bytes, MSB-first según AN12196)
    //
    //   byte[0] = 0xF0 | sdmCtrRetKeyNo
    //   byte[1] = (sdmMetaReadKeyNo shl 4) | sdmFileReadKeyNo
    //
    // Ejemplo AN12196 §5.9: CtrRet=0x1, MetaRead=0x2, FileRead=0x1 → 0xF1 0x21
    // -------------------------------------------------------------------------

    fun buildSdmAccessRights(
        sdmFileReadKeyNo:  Int = 0x01,   // Key que genera el CMAC
        sdmMetaReadKeyNo:  Int = 0x02,   // Key que cifra PICCData
        sdmCtrRetKeyNo:    Int = 0x01    // Key que puede leer el contador
    ): ByteArray {
        require(sdmFileReadKeyNo  in 0..0xF) { "sdmFileReadKeyNo out of range" }
        require(sdmMetaReadKeyNo  in 0..0xF) { "sdmMetaReadKeyNo out of range" }
        require(sdmCtrRetKeyNo    in 0..0xF) { "sdmCtrRetKeyNo out of range" }
        return byteArrayOf(
            (0xF0 or sdmCtrRetKeyNo).toByte(),
            ((sdmMetaReadKeyNo shl 4) or sdmFileReadKeyNo).toByte()
        )
    }

    /** SDMAccessRights por defecto para el ejemplo AN12196: 0xF1 0x21 */
    val SDM_ACCESS_RIGHTS_DEFAULT: ByteArray = buildSdmAccessRights()

    // -------------------------------------------------------------------------
    // Constante cero para offsets deshabilitados
    // -------------------------------------------------------------------------
    val OFFSET_ZERO: ByteArray = offsetBytes(0)
}
