package com.example.ntag424sdm

import android.util.Log
import com.nxp.nfclib.defaultimpl.KeyData
import com.nxp.nfclib.desfire.INTAG424DNA
import com.nxp.nfclib.desfire.MFPCard
import com.nxp.nfclib.desfire.NTAG424DNAFileSettings
import com.nxp.nfclib.ndef.NdefMessageWrapper
import com.nxp.nfclib.ndef.NdefRecordWrapper
import java.security.Key
import javax.crypto.spec.SecretKeySpec

/**
 * Ntag424DnaSDMConfigurator — personalización completa de NTAG 424 DNA con SDM.
 *
 * ─── CORRECCIONES vs versión anterior ────────────────────────────────────────
 *
 * 1. Todos los setters de offset reciben ByteArray(3) LSB-first, no Int:
 *      ❌  settings.setPiccDataOffset(0x20)
 *      ✅  settings.setPiccDataOffset(Ntag424SDMConfig.offsetBytes(0x20))
 *    Afecta: setPiccDataOffset, setSdmMacOffset, setSdmMacInputOffset,
 *            setUidOffset, setSdmEncryptionOffset, setSdmEncryptionLength,
 *            setSdmReadCounterLimit, setSdmReadCounterOffset
 *    (firma bytecode: ([B)V en todos ellos)
 *
 * 2. changeKey() firma confirmada: (Int, ByteArray, ByteArray, Byte)
 *    El SDK gestiona internamente el XOR para Case 1 y Case 2 del §5.16.
 *
 * 3. Una sola instancia de INTAG424DNA por sesión — no hay getTag() doble.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Precondición para todos los métodos:
 *   El objeto `tag` debe ser una instancia activa obtenida de:
 *     DESFireFactory.getInstance().getNTAG424DNA(libInstance.getCustomModules())
 *   justo después de detectar el tag en onNewIntent / handleIntent.
 */
class Ntag424DnaSDMConfigurator(private val tag: INTAG424DNA) {

    private val TAG = "SDMConfigurator"
    private val log = StringBuilder()

    // ─────────────────────────────────────────────────────────────────────────
    // Secuencia completa de personalización (AN12196 §5)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Personaliza el tag con SDM en modo SUN (URL con ENCPICCData + CMAC).
     *
     * Secuencia:
     *   1. isoSelectApplicationByDFName
     *   2. authenticateEV2First(0x00, masterKey)
     *   3. writeNDEF (URL template con placeholders)
     *   4. changeFileSettings (activa SDM)
     *   5. Opcional: changeKey(0x00) para cambiar la master key
     *
     * @param masterKey     Clave actual del AppKey 0x00 (factory: all-zero)
     * @param newMasterKey  Nueva master key (null = no cambiar)
     */
    fun configureSDMForSUNMirroring(
        masterKey:    ByteArray = Ntag424SDMConfig.KEY_MASTER,
        newMasterKey: ByteArray? = null
    ): String {
        log.clear()
        try {
            step("SELECT NDEF Application (DF Name)")
            tag.isoSelectApplicationByDFName(Ntag424SDMConfig.APP_DFNAME)
            ok("Application selected")

            step("AuthenticateEV2First — Key 0x00")
            tag.authenticateEV2First(0x00, keyData(masterKey), null)
            ok("Authenticated with Key 0x00")

            step("Write NDEF template (AN12196 §5.8)")
            writeNdefTemplate()

            step("ChangeFileSettings — enable SDM (AN12196 §5.9)")
            val settings = buildSdmSettings()
            // Una sola instancia: `tag` ya tiene SSM activa
            tag.changeFileSettings(Ntag424SDMConfig.FILE_NO_NDEF, settings)
            ok("SDM FileSettings applied")
            logSdmOffsets()

            if (newMasterKey != null) {
                step("ChangeKey 0x00 → new master key (AN12196 §5.16.2)")
                // Firma confirmada: changeKey(keyNo: Int, oldKey: ByteArray, newKey: ByteArray, version: Byte)
                tag.changeKey(0x00, masterKey, newMasterKey, 0x01.toByte())
                ok("Master key changed")
            }

            ok("=== Personalization complete ===")

        } catch (e: Exception) {
            err("Personalization FAILED: ${e.javaClass.simpleName}: ${e.message}")
            Log.e(TAG, "configureSDMForSUNMirroring", e)
        }
        return log.toString()
    }

    /**
     * Variante con SDMENCFileData activado (AN12196 §3.4.3).
     * Útil cuando además de cifrar el PICCData se quiere cifrar un trozo de los datos del fichero.
     *
     * Los offsets encOffset y cmacOffset deben calcularse externamente con NdefHelper
     * para la URL concreta que se use.
     *
     * @param encOffset    Offset del inicio del bloque ENCFileData en el binario NDEF
     * @param encLength    Longitud del bloque ENCFileData (múltiplo de 16)
     * @param cmacOffset   Offset del CMAC placeholder
     */
    fun configureSDMWithEncFileData(
        masterKey:  ByteArray = Ntag424SDMConfig.KEY_MASTER,
        encOffset:  Int,
        encLength:  Int,
        cmacOffset: Int
    ): String {
        log.clear()
        try {
            step("SELECT + Authenticate")
            tag.isoSelectApplicationByDFName(Ntag424SDMConfig.APP_DFNAME)
            tag.authenticateEV2First(0x00, keyData(masterKey), null)
            ok("Authenticated")

            step("Write NDEF template")
            writeNdefTemplate()

            step("ChangeFileSettings — SDM + ENCFileData")
            val settings = buildSdmSettingsWithEncFileData(encOffset, encLength, cmacOffset)
            tag.changeFileSettings(Ntag424SDMConfig.FILE_NO_NDEF, settings)
            ok("SDM + ENCFileData settings applied")

        } catch (e: Exception) {
            err("configureSDMWithEncFileData FAILED: ${e.message}")
            Log.e(TAG, "configureSDMWithEncFileData", e)
        }
        return log.toString()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Construcción de NTAG424DNAFileSettings
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Construye NTAG424DNAFileSettings para el caso SUN estándar:
     *   - ENCPICCData (UID + CTR cifrado) en URL
     *   - SDMMAC al final
     *   - Sin SDMENCFileData
     *
     * CORRECCIÓN: todos los setters de offset reciben ByteArray(3) LSB-first.
     *
     * Constructor NTAG424DNAFileSettings (firma confirmada en bytecode):
     *   (CommunicationMode, readAccess: Byte, writeAccess: Byte, readWriteAccess: Byte, changeAccess: Byte)
     *
     * Access rights (AN12196 §5.9 Table 18):
     *   Read      = 0xE (libre, sin clave)
     *   Write     = 0x0 (Key 0)
     *   ReadWrite = 0x0 (Key 0)
     *   Change    = 0x0 (Key 0)
     */
    fun buildSdmSettings(
        piccDataOffset: Int = offsetToInt(Ntag424SDMConfig.OFFSET_ENC_PICC_DATA),
        sdmMacOffset:   Int = offsetToInt(Ntag424SDMConfig.OFFSET_SDM_MAC),
        accessRights:   ByteArray = Ntag424SDMConfig.SDM_ACCESS_RIGHTS_DEFAULT
    ): NTAG424DNAFileSettings {

        val settings = NTAG424DNAFileSettings(
            MFPCard.CommunicationMode.Plain,
            0x0E.toByte(),  // read: libre
            0x00.toByte(),  // write: Key 0
            0x00.toByte(),  // readWrite: Key 0
            0x00.toByte()   // change: Key 0
        )

        // Opciones SDM
        settings.setSDMEnabled(true)
        settings.setUIDMirroringEnabled(true)
        settings.setSDMReadCounterEnabled(true)
        settings.setSDMReadCounterLimitEnabled(false)
        settings.setSDMEncryptFileDataEnabled(false)

        // SDMAccessRights — ByteArray (2 bytes)
        settings.setSdmAccessRights(accessRights)

        // ── Offsets — todos ByteArray(3) LSB-first ──
        settings.setPiccDataOffset(Ntag424SDMConfig.offsetBytes(piccDataOffset))

        // CMACInputOffset == CMACOffset → MAC sobre input de longitud cero (AN12196 §3.4.4.2.1)
        settings.setSdmMacOffset(Ntag424SDMConfig.offsetBytes(sdmMacOffset))
        settings.setSdmMacInputOffset(Ntag424SDMConfig.offsetBytes(sdmMacOffset))

        // ENC file data: no usado en este modo
        settings.setSdmEncryptionOffset(Ntag424SDMConfig.OFFSET_ZERO)
        settings.setSdmEncryptionLength(Ntag424SDMConfig.OFFSET_ZERO)

        // UID mirror offset (puede ser el mismo que piccDataOffset, ambos apuntan al ENCPICCData)
        settings.setUidOffset(Ntag424SDMConfig.offsetBytes(piccDataOffset))

        // SDMReadCtr offset (posición del contador dentro del NDEF; normalmente dentro de ENCPICCData)
        settings.setSdmReadCounterOffset(Ntag424SDMConfig.offsetBytes(piccDataOffset))

        // Sin límite de contador
        settings.setSdmReadCounterLimit(Ntag424SDMConfig.offsetBytes(0xFFFFFF))

        return settings
    }

    /**
     * Construye NTAG424DNAFileSettings con SDMENCFileData habilitado (AN12196 §3.4.3).
     * SDMMACInputOffset apunta al inicio del bloque ENCFileData (≠ SDMMACOffset).
     */
    fun buildSdmSettingsWithEncFileData(
        encOffset:      Int,
        encLength:      Int,
        cmacOffset:     Int,
        piccDataOffset: Int = offsetToInt(Ntag424SDMConfig.OFFSET_ENC_PICC_DATA),
        accessRights:   ByteArray = Ntag424SDMConfig.SDM_ACCESS_RIGHTS_DEFAULT
    ): NTAG424DNAFileSettings {

        val settings = NTAG424DNAFileSettings(
            MFPCard.CommunicationMode.Plain,
            0x0E.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte()
        )

        settings.setSDMEnabled(true)
        settings.setUIDMirroringEnabled(true)
        settings.setSDMReadCounterEnabled(true)
        settings.setSDMReadCounterLimitEnabled(false)
        settings.setSDMEncryptFileDataEnabled(true)   // ENCFileData activado

        settings.setSdmAccessRights(accessRights)
        settings.setPiccDataOffset(Ntag424SDMConfig.offsetBytes(piccDataOffset))
        settings.setUidOffset(Ntag424SDMConfig.offsetBytes(piccDataOffset))
        settings.setSdmReadCounterOffset(Ntag424SDMConfig.offsetBytes(piccDataOffset))

        // ENCFileData block
        settings.setSdmEncryptionOffset(Ntag424SDMConfig.offsetBytes(encOffset))
        settings.setSdmEncryptionLength(Ntag424SDMConfig.offsetBytes(encLength))

        // CMACInputOffset = inicio del bloque ENCFileData (AN12196 §3.4.4.2.2)
        settings.setSdmMacInputOffset(Ntag424SDMConfig.offsetBytes(encOffset))
        settings.setSdmMacOffset(Ntag424SDMConfig.offsetBytes(cmacOffset))

        settings.setSdmReadCounterLimit(Ntag424SDMConfig.offsetBytes(0xFFFFFF))

        return settings
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Escritura NDEF
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Escribe el URL template en el fichero NDEF usando CommMode.PLAIN.
     * Después de esto el NDEF tiene los placeholders '00...' que el tag
     * sobreescribirá con los valores dinámicos una vez activado el SDM.
     */
    private fun writeNdefTemplate() {
        val url = Ntag424SDMConfig.URL_TEMPLATE
        require(url.startsWith("https://")) { "URL must start with https://" }

        // Payload: URI identifier 0x04 ("https://") + URL sin el scheme
        val urlBody = url.removePrefix("https://").toByteArray(Charsets.US_ASCII)
        val payload = ByteArray(1 + urlBody.size)
        payload[0] = 0x04   // URI identifier code: https://
        urlBody.copyInto(payload, 1)

        val record = NdefRecordWrapper(
            NdefRecordWrapper.TNF_WELL_KNOWN,  // 0x01
            byteArrayOf(0x55),                 // type = "U"
            ByteArray(0),                      // ID
            payload
        )
        val msg = NdefMessageWrapper(record)
        tag.writeNDEF(msg)
        ok("NDEF written — ${msg.toByteArray().size} bytes")
        log("  URL: $url")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private fun keyData(keyBytes: ByteArray): KeyData {
        val kd = KeyData()
        kd.setKey(SecretKeySpec(keyBytes, "AES") as Key)
        return kd
    }

    private fun logSdmOffsets() {
        val enc = offsetToInt(Ntag424SDMConfig.OFFSET_ENC_PICC_DATA)
        val mac = offsetToInt(Ntag424SDMConfig.OFFSET_SDM_MAC)
        log("  ENCPICCDataOffset : 0x${Integer.toHexString(enc)} ($enc dec)")
        log("  SDMMACOffset      : 0x${Integer.toHexString(mac)} ($mac dec)")
        log("  SDMMACInputOffset : 0x${Integer.toHexString(mac)} (= SDMMACOffset → zero-len input)")
    }

    private fun step(msg: String) { log.append("\n→ $msg\n"); Log.d(TAG, "STEP: $msg") }
    private fun ok(msg: String)   { log.append("  ✓ $msg\n");  Log.d(TAG, "OK: $msg") }
    private fun err(msg: String)  { log.append("  ✗ $msg\n");  Log.e(TAG, "ERR: $msg") }
    private fun log(msg: String)  { log.append("    $msg\n");   Log.d(TAG, msg) }

    companion object {
        /** ByteArray(3) LSB-first → Int */
        fun offsetToInt(b: ByteArray): Int {
            if (b.isEmpty()) return 0
            return (b[0].toInt() and 0xFF) or
                   ((if (b.size > 1) b[1].toInt() and 0xFF else 0) shl 8) or
                   ((if (b.size > 2) b[2].toInt() and 0xFF else 0) shl 16)
        }
    }
}
