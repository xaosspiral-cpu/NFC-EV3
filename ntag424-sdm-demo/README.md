# NTAG 424 DNA — SDM Demo (Android / Kotlin + TapLinX)

Demo app completa que implementa **Secure Dynamic Messaging (SDM)** sobre NTAG 424 DNA
usando el SDK TapLinX de NXP, siguiendo exactamente las especificaciones de **AN12196 Rev. 2.0**.

---

## Funcionalidades implementadas

| Módulo | Descripción |
|--------|-------------|
| `Ntag424Operations.personalize()` | Escribe NDEF con URL template + activa SDM via `changeFileSettings()` |
| `Ntag424Operations.readFileSettings()` | Lee y muestra todos los campos de `NTAG424DNAFileSettings` |
| `Ntag424Operations.setReadCounterLimit()` | Modifica `SDMReadCtrLimit` sobre settings existentes |
| `Ntag424Operations.verifySunOnDevice()` | Verifica SUN MAC usando el método SDK del tag |
| `SunVerifier.verify()` | Verificación SUN **pura Kotlin + BouncyCastle** (sin tag, válida en backend) |
| `NdefHelper.calculateOffsets()` | Calcula los offsets correctos para cualquier URL template |

---

## Estructura del proyecto

```
app/
├── libs/
│   └── NxpNfcAndroidLib-release.aar     ← TapLinX SDK (colócalo tú)
└── src/main/java/com/example/ntag424sdm/
    ├── MainActivity.kt         ← UI + NFC dispatch + TapLinX lifecycle
    ├── SdmConfig.kt            ← Constantes: keys, offsets, URL template
    ├── Ntag424Operations.kt    ← Todas las operaciones SDK sobre el tag
    ├── SunVerifier.kt          ← Crypto SUN pura: decrypt + CMAC + verify
    ├── NdefHelper.kt           ← Construcción NDEF binary + cálculo de offsets
    └── SunVerifierTest.kt      ← Tests con vectores AN12196
```

---

## Setup

### 1. TapLinX AAR

Copia el fichero `NxpNfcAndroidLib-release.aar` (descargado de [mifare.net](https://www.mifare.net/en/products/mifare-sdk/taplinx/))
en `app/libs/`.

### 2. Package Key

TapLinX requiere una clave de paquete vinculada a tu certificado de firma.
Regístrala en https://www.mifare.net/support/mifare-sdk/ y pégala en:

```kotlin
// MainActivity.kt
private const val TAPLINX_PACKAGE_KEY = "TU_CLAVE_AQUI"
```

> Para pruebas rápidas con el certificado debug por defecto de NXP usa `" "` (espacio).

### 3. Claves SDM

Edita `SdmConfig.kt` para configurar tus claves antes de personalizar:

```kotlin
val KEY_APP_MASTER   = byteArrayOf(...)   // AppKey 0x00
val KEY_SDM_FILE_READ = byteArrayOf(...)  // AppKey 0x01 → CMAC
val KEY_SDM_META_READ = byteArrayOf(...)  // AppKey 0x02 → encrypt PICCData
```

> ⚠️ **No dejes las claves de fábrica (todo-ceros) en producción.**

### 4. URL template y offsets

El offset del placeholder `e=` y `c=` dentro del binario NDEF **debe coincidir exactamente**
con lo que configure `changeFileSettings`. Usa `NdefHelper` para calcularlos:

```kotlin
val (encOffset, macOffset) = NdefHelper.calculateOffsets(
    url = "https://tu.dominio.com/verify?e=0000000000000000000000000000000000000000&c=0000000000000000"
)
// Actualiza SdmConfig.OFFSET_ENC_PICC_DATA y OFFSET_SDM_MAC con estos valores
println(NdefHelper.debugOffsets(url))
```

---

## Operaciones disponibles en la app

### 1. Personalize
Escribe el NDEF template y activa SDM. Requiere tag de fábrica (claves all-zero) o
autenticación con la clave master actual.

**Secuencia equivalente en AN12196:**
- §5.6 AuthenticateEV2First Key 0x00
- §5.8 Write NDEF File
- §5.9 Change NDEF File Settings (activa SDM)

### 2. Verify SUN
Lee la URL del NDEF tras un tap y verifica el MAC SUN con `SunVerifier.verify()`.

**Verificación implementada:** AN12196 §3.4.4.2.1 (CMACInputOffset == CMACOffset)

### 3. File Settings
Lee y muestra todos los campos de FileSettings del fichero NDEF (0x02).

---

## SDM Flow (resumen AN12196)

```
Tag tap
  └─ NTAG genera SUN:
       1. KSesSDMFileReadENC = CMAC(KSDMFileRead, SV1)   §3.3
       2. KSesSDMFileReadMAC = CMAC(KSDMFileRead, SV2)   §3.3
       3. ENCPICCData = AES-CBC(KSDMMetaRead, PICCDataTag|UID|CTR|Pad)  §3.4.2
       4. SDMMAC = MACt(KSesSDMFileReadMAC, input)        §3.4.4

Backend recibe URL:
  └─ SunVerifier.verify():
       1. D(KSDMMetaRead, ENCPICCData) → UID, CTR         §3.4.2.2
       2. Derivar KSesSDMFileReadMAC desde KSDMFileRead   §3.3
       3. Calcular MACt esperado                          §3.4.4.2.1
       4. Comparar con SDMMAC recibido
```

---

## Vectores de test (AN12196)

`SunVerifierTest.kt` verifica todos los cálculos contra los vectores de prueba del documento:

| Test | Sección AN12196 | Vector |
|------|----------------|--------|
| `testDecryptPiccData` | §3.4.2.2 Table 2 | ENCPICCData → UID + CTR |
| `testSessionKeyDerivation` | §3.3 Table 1 | KSesSDMFileReadMAC derivation |
| `testSdmMacZeroInput` | §3.4.4.2.1 Table 4 | MACt = `94EED9EE65337086` |
| `testFullSunVerification` | §3.4 Fig.2 | Round-trip URL verify |

---

## Ambigüedades del SDK documentadas

### `NTAG424DNAFileSettings` constructor
Firma inferida del bytecode del AAR:
```kotlin
NTAG424DNAFileSettings(
    communicationMode: MFPCard.CommunicationMode,
    readAccess: Byte,      // nibble 0xE = free
    writeAccess: Byte,
    readWriteAccess: Byte,
    changeAccess: Byte
)
```
Si tu versión del SDK tiene un constructor diferente (p.ej. acepta un `byte[]` de access rights),
ajusta `configureSdmFileSettings()` en `Ntag424Operations.kt`.

### `verifySecureDynamicMessagingMacWithAESMode`
Firma inferida del bytecode:
```kotlin
fun verifySecureDynamicMessagingMacWithAESMode(
    fileNo: Int,
    encPiccData: ByteArray,
    sdmMac: ByteArray,
    kSdmMetaRead: KeyData,
    kSdmFileRead: KeyData
): Boolean
```
Si el orden de parámetros es diferente en tu versión, el método SDK lanzará una excepción
con un mensaje descriptivo. **`SunVerifier.verify()` es la alternativa siempre segura.**

---

## Dependencias

```
TapLinX:       NxpNfcAndroidLib-release.aar   (NXP, requiere registro)
BouncyCastle:  org.bouncycastle:bcprov-jdk15on:1.70  (CMAC/AES)
AndroidX:      appcompat, material, constraintlayout
```

---

## Licencia

Código propio bajo MIT. El SDK TapLinX y AN12196 son propiedad de NXP Semiconductors.
