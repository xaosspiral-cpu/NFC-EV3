package com.example.ntag424sdm

import android.app.Activity
import android.content.Intent
import android.nfc.NfcAdapter
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import com.nxp.nfclib.CardType
import com.nxp.nfclib.NxpNfcLib
import com.nxp.nfclib.defaultimpl.KeyData
import com.nxp.nfclib.desfire.DESFireFactory
import com.nxp.nfclib.exceptions.NxpNfcLibException
import javax.crypto.spec.SecretKeySpec

/**
 * MainActivity — ciclo de vida TapLinX + despacho NFC en primer plano.
 *
 * ─── Obtener Package Key ──────────────────────────────────────────────────
 * TapLinX exige una package key por app, emitida por NXP.
 * Regístrala en https://www.mifare.net/support/mifare-sdk/ y pega la clave
 * en TAPLINX_PACKAGE_KEY.
 * ─────────────────────────────────────────────────────────────────────────
 */
class MainActivity : Activity() {

    companion object {
        private const val TAG = "MainActivity"
        private const val TAPLINX_PACKAGE_KEY = "db3feae1d9d97444abfaa38aa57c2196"
    }

    private lateinit var nfcLib: NxpNfcLib
    private lateinit var tvLog: TextView
    private lateinit var tvInstruction: TextView
    private lateinit var btnPersonalize: Button
    private lateinit var btnVerifySun: Button
    private lateinit var btnReadSettings: Button
    private lateinit var btnClear: Button

    private enum class Operation { PERSONALIZE, VERIFY_SUN, READ_SETTINGS }
    private var pendingOperation: Operation = Operation.READ_SETTINGS

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvLog           = findViewById(R.id.tvLog)
        tvInstruction   = findViewById(R.id.tvInstruction)
        btnPersonalize  = findViewById(R.id.btnPersonalize)
        btnVerifySun    = findViewById(R.id.btnVerifySun)
        btnReadSettings = findViewById(R.id.btnReadSettings)
        btnClear        = findViewById(R.id.btnClear)

        nfcLib = NxpNfcLib.getInstance()
        try {
            nfcLib.registerActivity(this, TAPLINX_PACKAGE_KEY)
        } catch (e: NxpNfcLibException) {
            appendLog("⚠ TapLinX init failed: ${e.message}")
        }

        btnPersonalize.setOnClickListener {
            pendingOperation = Operation.PERSONALIZE
            setInstruction("Acerca el NTAG 424 DNA para personalizarlo…")
        }
        btnVerifySun.setOnClickListener {
            pendingOperation = Operation.VERIFY_SUN
            setInstruction("Acerca el tag para verificar el SUN URL…")
        }
        btnReadSettings.setOnClickListener {
            pendingOperation = Operation.READ_SETTINGS
            setInstruction("Acerca el tag para leer FileSettings…")
        }
        btnClear.setOnClickListener { tvLog.text = "" }
    }

    override fun onResume()  { super.onResume();  nfcLib.startForeGroundDispatch() }
    override fun onPause()   { super.onPause();   nfcLib.stopForeGroundDispatch()  }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); handleNfcIntent(intent) }

    // ─────────────────────────────────────────────────────────────────────
    // Gestión del intent NFC
    // ─────────────────────────────────────────────────────────────────────

    private fun handleNfcIntent(intent: Intent) {
        if (intent.action !in listOf(
                NfcAdapter.ACTION_NDEF_DISCOVERED,
                NfcAdapter.ACTION_TECH_DISCOVERED,
                NfcAdapter.ACTION_TAG_DISCOVERED)) return

        val cardType = try {
            nfcLib.getCardType(intent)
        } catch (e: NxpNfcLibException) {
            appendLog("Error detectando tipo de card: ${e.message}"); return
        }

        if (cardType != CardType.NTAG424DNA && cardType != CardType.NTAG424DNATT) {
            appendLog("Tag no soportado: $cardType"); return
        }
        appendLog("\n─── Tag detectado: $cardType ───")

        // ── Instancia del tag UNA SOLA VEZ ───────────────────────────────────
        val tag = try {
            if (cardType == CardType.NTAG424DNATT)
                DESFireFactory.getInstance().getNTAG424DNATT(nfcLib.getCustomModules())
            else
                DESFireFactory.getInstance().getNTAG424DNA(nfcLib.getCustomModules())
        } catch (e: Exception) {
            appendLog("Error creando instancia del tag: ${e.message}"); return
        }

        Thread {
            val result = try {
                when (pendingOperation) {

                    Operation.PERSONALIZE -> {
                        Ntag424DnaSDMConfigurator(tag)
                            .configureSDMForSUNMirroring(Ntag424SDMConfig.KEY_MASTER)
                    }

                    Operation.READ_SETTINGS -> {
                        tag.isoSelectApplicationByDFName(Ntag424SDMConfig.APP_DFNAME)
                        val kd = KeyData()
                        kd.setKey(SecretKeySpec(Ntag424SDMConfig.KEY_MASTER, "AES"))
                        tag.authenticateEV2First(0x00, kd, null)
                        Ntag424FileSettingsManager(tag).readFileSettingsForDisplay()
                    }

                    Operation.VERIFY_SUN -> verifySunFlow(intent)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Operation failed", e)
                "Error: ${e.javaClass.simpleName}: ${e.message}"
            }
            runOnUiThread { appendLog(result) }
        }.start()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Verificación SUN (Ruta 3 — Kotlin puro, sin tag activo)
    // Para Ruta 2 usar: SunMessageVerifier.verifyViaSUNMessageUtility(...)
    // ─────────────────────────────────────────────────────────────────────

    private fun verifySunFlow(intent: Intent): String {
        val sunUrl = intent.data?.toString()
            ?: return "No URL en el intent. Acerca el tag personalizado."

        val sb = StringBuilder("SUN URL: $sunUrl\n\n")
        val result = SunVerifier.verify(sunUrl, Ntag424SDMConfig.KEY_SDM_META_READ, Ntag424SDMConfig.KEY_SDM_FILE_READ)
        sb.appendLine("UID        : ${SunVerifier.bytesToHex(result.uid)}")
        sb.appendLine("SDMReadCtr : ${result.sdmReadCtrInt}")
        sb.appendLine(if (result.macValid) "✅ MAC VÁLIDO" else "❌ MAC INVÁLIDO")
        return sb.toString()
    }

    private fun appendLog(text: String) = runOnUiThread { tvLog.append("$text\n") }
    private fun setInstruction(msg: String) {
        tvInstruction.text = msg
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }
}
