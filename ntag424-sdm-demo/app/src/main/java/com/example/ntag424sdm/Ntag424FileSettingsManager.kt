package com.example.ntag424sdm

import android.util.Log
import com.nxp.nfclib.desfire.INTAG424DNA
import com.nxp.nfclib.desfire.NTAG424DNAFileSettings

/**
 * Ntag424FileSettingsManager — lectura y modificación de FileSettings.
 *
 * ─── BUG CORREGIDO ───────────────────────────────────────────────────────────
 * El patrón `getTag().getFileSettings(...)` seguido de `getTag().changeFileSettings(...)`
 * crea DOS instancias distintas. La segunda NO tiene la sesión SSM activa → falla.
 *
 * Corrección: capturar `val tag = getTag()` UNA SOLA VEZ y reutilizarlo.
 * Aquí el constructor recibe directamente el INTAG424DNA — no hay getTag().
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * La clase asume que ya se ha llamado a:
 *   1. isoSelectApplicationByDFName(APP_DFNAME)
 *   2. authenticateEV2First(keyNo, keyData, null)
 *
 * antes de llamar a cualquier método de esta clase.
 */
class Ntag424FileSettingsManager(private val tag: INTAG424DNA) {

    private val TAG = "FileSettingsManager"

    // -------------------------------------------------------------------------
    // Lectura de FileSettings
    // -------------------------------------------------------------------------

    /**
     * Lee y devuelve los FileSettings del fichero indicado.
     * Confirmado en bytecode: getFileSettings(Int): NTAG424DNAFileSettings
     *
     * El helper interno NTAG424DNAFileSettingsHelper.parse() rellena los campos en este orden:
     *   setUIDMirroringEnabled → setSdmReadCounterEnabled → setSdmReadCounterLimitEnabled
     *   → setSdmEncryptFileDataEnabled → setSdmAccessRights → setUidOffset
     *   → setSdmReadCounterOffset → setPiccDataOffset → setSdmMacInputOffset
     *   → setSdmEncryptionOffset → setSdmEncryptionLength → setSdmMacOffset
     *   → setSdmReadCounterLimit
     *
     * Todos los getters de offset devuelven ByteArray (confirmado en bytecode).
     */
    fun readFileSettings(fileNo: Int = Ntag424SDMConfig.FILE_NO_NDEF): Ntag424FileSettingsSnapshot {
        Log.d(TAG, "getFileSettings(fileNo=0x${Integer.toHexString(fileNo)})")
        val settings = tag.getFileSettings(fileNo) as NTAG424DNAFileSettings
        return Ntag424FileSettingsSnapshot.from(settings)
    }

    /**
     * Vuelca los FileSettings a String legible para logs/UI.
     */
    fun readFileSettingsForDisplay(fileNo: Int = Ntag424SDMConfig.FILE_NO_NDEF): String =
        readFileSettings(fileNo).toDisplayString()

    // -------------------------------------------------------------------------
    // Modificación de FileSettings — ChangeFileSettings
    // -------------------------------------------------------------------------

    /**
     * Modifica SOLO el SDMReadCounterLimit manteniendo el resto de settings intactos.
     *
     * ─── BUG CORREGIDO ───────────────────────────────────────────────────────
     * Versión anterior llamaba getTag() dos veces:
     *   getTag().getFileSettings(...)   ← instancia 1, tiene SSM
     *   getTag().changeFileSettings(...)← instancia 2, NO tiene SSM → falla
     *
     * Corrección: `tag` es la misma instancia inyectada en el constructor.
     * ─────────────────────────────────────────────────────────────────────────
     *
     * @param limit  0xFFFFFF = deshabilitado; cualquier otro valor = límite activo
     */
    fun setReadCounterLimit(limit: Int, fileNo: Int = Ntag424SDMConfig.FILE_NO_NDEF): String {
        Log.d(TAG, "setReadCounterLimit(limit=0x${Integer.toHexString(limit)})")

        // Leer settings actuales con la MISMA instancia
        val settings = tag.getFileSettings(fileNo) as NTAG424DNAFileSettings

        val limitEnabled = limit != 0xFFFFFF
        settings.setSDMReadCounterLimitEnabled(limitEnabled)

        // setSdmReadCounterLimit recibe ByteArray (3 bytes, LSB-first) — confirmado en bytecode
        settings.setSdmReadCounterLimit(Ntag424SDMConfig.offsetBytes(limit))

        // changeFileSettings con la MISMA instancia que tiene SSM activa
        tag.changeFileSettings(fileNo, settings)

        return "SDMReadCtrLimit → ${if (limitEnabled) "0x${Integer.toHexString(limit)}" else "DISABLED"}"
    }

    /**
     * Aplica un objeto NTAG424DNAFileSettings ya construido.
     * Útil cuando se necesita cambiar múltiples campos a la vez.
     *
     * Precondición: `settings` debe construirse con buildSdmSettings() o similar,
     * con todos los ByteArray offsets correctamente formateados.
     */
    fun applyFileSettings(settings: NTAG424DNAFileSettings, fileNo: Int = Ntag424SDMConfig.FILE_NO_NDEF) {
        Log.d(TAG, "changeFileSettings(fileNo=0x${Integer.toHexString(fileNo)})")
        tag.changeFileSettings(fileNo, settings)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot — representación legible de NTAG424DNAFileSettings
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Ntag424FileSettingsSnapshot — datos extraídos de NTAG424DNAFileSettings.
 *
 * Todos los campos de offset son ByteArray (getters devuelven [B — confirmado bytecode).
 * Los convertimos a Int para facilitar comparaciones y display.
 */
data class Ntag424FileSettingsSnapshot(
    val communicationMode:          String,
    val sdmEnabled:                 Boolean,
    val uidMirroringEnabled:        Boolean,
    val sdmReadCounterEnabled:      Boolean,
    val sdmReadCounterLimitEnabled: Boolean,
    val sdmEncFileDataEnabled:      Boolean,
    val sdmAccessRights:            ByteArray,
    val uidOffset:                  Int,
    val piccDataOffset:             Int,
    val sdmReadCounterOffset:       Int,
    val sdmMacInputOffset:          Int,
    val sdmEncryptionOffset:        Int,
    val sdmEncryptionLength:        Int,
    val sdmMacOffset:               Int,
    val sdmReadCounterLimit:        Int
) {
    companion object {
        fun from(s: NTAG424DNAFileSettings) = Ntag424FileSettingsSnapshot(
            communicationMode          = s.communicationMode?.name ?: "UNKNOWN",
            sdmEnabled                 = s.isSDMEnabled,
            uidMirroringEnabled        = s.isUIDMirroringEnabled,
            sdmReadCounterEnabled      = s.isSDMReadCounterEnabled,
            sdmReadCounterLimitEnabled = s.isSDMReadCounterLimitEnabled,
            sdmEncFileDataEnabled      = s.isSDMEncryptFileDataEnabled,
            // sdmAccessRights() getter devuelve ByteArray
            sdmAccessRights            = s.sdmAccessRights ?: ByteArray(2),
            // Todos los getters de offset devuelven ByteArray (LSB-first) → convertir a Int
            uidOffset                  = bytesToInt(s.uidOffset),
            piccDataOffset             = bytesToInt(s.piccDataOffset),
            sdmReadCounterOffset       = bytesToInt(s.sdmReadCounterOffset),
            sdmMacInputOffset          = bytesToInt(s.sdmMacInputOffset),
            sdmEncryptionOffset        = bytesToInt(s.sdmEncryptionOffset),
            sdmEncryptionLength        = bytesToInt(s.sdmEncryptionLength),
            sdmMacOffset               = bytesToInt(s.sdmMacOffset),
            sdmReadCounterLimit        = bytesToInt(s.sdmReadCounterLimit)
        )

        /** ByteArray LSB-first (3 bytes) → Int */
        private fun bytesToInt(b: ByteArray?): Int {
            if (b == null || b.isEmpty()) return 0
            var result = 0
            for (i in b.indices.reversed()) {
                result = (result shl 8) or (b[i].toInt() and 0xFF)
            }
            return result
        }
    }

    fun toDisplayString(): String = buildString {
        appendLine("─── NTAG424DNA File Settings ───────────────")
        appendLine("CommMode             : $communicationMode")
        appendLine("SDM enabled          : $sdmEnabled")
        appendLine("UID mirroring        : $uidMirroringEnabled")
        appendLine("SDMReadCtr mirror    : $sdmReadCounterEnabled")
        appendLine("SDMReadCtrLimit ena  : $sdmReadCounterLimitEnabled")
        appendLine("SDMENCFileData ena   : $sdmEncFileDataEnabled")
        appendLine("SDMAccessRights      : ${hex(sdmAccessRights)}")
        appendLine("UIDOffset            : 0x${Integer.toHexString(uidOffset)} ($uidOffset)")
        appendLine("PiccDataOffset       : 0x${Integer.toHexString(piccDataOffset)} ($piccDataOffset)")
        appendLine("SDMReadCtrOffset     : 0x${Integer.toHexString(sdmReadCounterOffset)}")
        appendLine("SDMMACInputOffset    : 0x${Integer.toHexString(sdmMacInputOffset)}")
        appendLine("SDMENCOffset         : 0x${Integer.toHexString(sdmEncryptionOffset)}")
        appendLine("SDMENCLength         : 0x${Integer.toHexString(sdmEncryptionLength)}")
        appendLine("SDMMACOffset         : 0x${Integer.toHexString(sdmMacOffset)}")
        if (sdmReadCounterLimitEnabled)
            appendLine("SDMReadCtrLimit      : $sdmReadCounterLimit")
        appendLine("────────────────────────────────────────────")
    }

    private fun hex(b: ByteArray) = b.joinToString("") { String.format("%02X", it) }

    override fun equals(other: Any?) = other is Ntag424FileSettingsSnapshot &&
            communicationMode == other.communicationMode &&
            sdmEnabled == other.sdmEnabled &&
            sdmMacOffset == other.sdmMacOffset &&
            piccDataOffset == other.piccDataOffset

    override fun hashCode() = sdmMacOffset * 31 + piccDataOffset
}
