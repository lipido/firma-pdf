# Firma de PDF con certificado PKCS#12

Herramienta para firmar archivos PDF con un certificado personal en formato
`.p12`/`.pfx`, usando [pyHanko](https://github.com/MatthiasValvekens/pyHanko).
Genera firmas **PAdES** (subfiltro `ETSI.CAdES.detached`), con opción de sello
visible y soporte de **múltiples firmas** sobre el mismo documento.

## Requisitos

- `conda` (Miniconda/Anaconda).
- Un certificado en formato `.p12`/`.pfx` y su contraseña.

## Crear el entorno conda

### Opción A: desde `environment.yml` (recomendado)

```bash
conda env create -f environment.yml
conda activate firma-electronica-pdf
```

### Opción B: crearlo a mano

```bash
conda create -y -n firma-electronica-pdf python=3.12
conda activate firma-electronica-pdf
pip install "pyhanko[opentype,image-support]"
```

> El extra `opentype` (aportan `fonttools` y `uharfbuzz`) es necesario para
> dibujar el texto del sello visible. Sin él solo funciona la firma invisible.
> El extra `image-support` (aporta `Pillow`) es necesario para usar una **imagen
> propia** como sello (`--stamp-image`).

## Uso

```bash
conda activate firma-electronica-pdf
cd /ruta/a/esta/carpeta

python firmar.py \
  --p12 mi_certificado.p12 \
  --in presentacion.pdf \
  --out presentacion_firmado.pdf
```

Al ejecutarlo pedirá la contraseña del `.p12` de forma **oculta**
(`getpass`). También se puede pasar por la variable de entorno `P12_PASS`:

```bash
P12_PASS='mi-contrasena' python firmar.py --p12 mi_certificado.p12
```

> La contraseña no se guarda ni se muestra en ningún caso.

### Opciones

| Opción | Descripción | Por defecto |
| --- | --- | --- |
| `--p12` | Ruta al certificado `.p12` (**obligatorio**) | — |
| `--in` | PDF de entrada | `presentacion.pdf` |
| `--out` | PDF firmado de salida | `presentacion_firmado.pdf` |
| `--field` | Nombre del campo de firma | automático |
| `--reason` | Motivo de la firma | `Firma del documento` |
| `--location` | Ubicación de la firma | vacío |
| `--tsa` | URL de autoridad de sellado de tiempo (TSA) | sin sello de tiempo |
| `--lt` | PAdES B-LT: embeber info de revocación (DSS) | desactivado |
| `--lta` | PAdES B-LTA: `--lt` + sello de tiempo del documento (requiere `--tsa`) | desactivado |
| `--trust-pem` | Certificado PEM/DER extra para confiar (repetible) | — |
| `--invisible` | No dibujar sello visible | sello visible |
| `--page` | Página del sello (1-based) | `1` |
| `--box` | Recuadro `x1,y1,x2,y2` en puntos | `650,30,940,120` |
| `--stamp-image` | Imagen PNG/JPG como fondo del sello (requiere `image-support`) | — |
| `--stamp-no-text` | Sello solo con la imagen (sin firmante/fecha) | con texto |
| `--stamp-text` | Plantilla de texto del sello (params: `signer`, `ts`) | plantilla por defecto |
| `--stamp-no-border` | Quitar el borde del sello | con borde |
| `--stamp-opacity` | Opacidad del fondo del sello (`0`–`1`) | `1.0` con imagen |

### Sello visible personalizado

El sello visible por defecto usa un icono vectorial que trae pyHanko (un "sello"
morado). Puedes usar tu propia **imagen** y/o personalizar el **texto**:

```bash
# Imagen + texto (firmante/fecha) con borde
python firmar.py --p12 mi_certificado.p12 --stamp-image sello.png

# Solo la imagen, sin texto ni borde
python firmar.py --p12 mi_certificado.p12 --stamp-image sello.png \
  --stamp-no-text --stamp-no-border

# Atenuar la imagen (se multiplica por el alfa del PNG)
python firmar.py --p12 mi_certificado.p12 --stamp-image sello.png \
  --stamp-opacity 0.3

# Texto personalizado (funciona también sin imagen)
python firmar.py --p12 mi_certificado.p12 --stamp-image sello.png \
  --stamp-text "Firmado por %(signer)s el %(ts)s"
```

- Se aceptan **PNG/JPG**. Si el PNG tiene **canal alfa**, se respeta (se incrusta
  como máscara `SMask`); `--stamp-opacity` se aplica **encima** de ese alfa.
- La imagen se escala/centra dentro del recuadro `--box`.
- `--stamp-text` usa formato printf con los parámetros `%(signer)s` (firmante) y
  `%(ts)s` (fecha ya formateada); un `%` literal se escribe `%%`.
- Requiere el extra `image-support` (Pillow) para `--stamp-image`.

### Ejemplos

Firma visible en la última página, abajo a la izquierda:

```bash
python firmar.py --p12 mi_certificado.p12 --page 6 --box 30,30,320,120
```

Firma invisible (oculta):

```bash
python firmar.py --p12 mi_certificado.p12 --invisible
```

Con sellado de tiempo (TSA):

```bash
python firmar.py --p12 mi_certificado.p12 --tsa http://tss.accv.es:8318/tsa
```

> **TSA cualificada (recomendado en España/EU).** Si el documento va a
> validarse ante la administración, o el validador exige un sello *cualificado*
> (eIDAS), usa una TSA de la Lista de Confianza (TSL). Verificada y sin
> autenticación:
>
> - **ACCV** (Agencia de Tecnología y Certificación Electrónica, Generalitat
>   Valenciana): `http://tss.accv.es:8318/tsa`
>
> Otras TSAs (públicas, **no** cualificadas): `http://timestamp.digicert.com`,
> `http://timestamp.globalsign.com/tsa/r6advanced1`,
> `http://timestamp.sectigo.com`. El endpoint de DigiCert es HTTP; si tu red
> bloquea el puerto 443/HTTPS hacia ese host verás un *timeout*.
>
> El sello de tiempo **no cambia lo que ves en visores básicos** como Okular:
> allí solo aparece la *hora declarada* por quien firma. La TSA añade un token
> RFC3161 firmado por ella (atributo CMS sin firmar + su certificado), que es lo
> que da autoridad a la fecha/hora. Para verlo usa `verificar.py` o Adobe Acrobat.

## Perfiles PAdES (validez a largo plazo)

| Perfil | Cómo | Qué aporta |
| --- | --- | --- |
| B-B | por defecto | firma básica |
| B-T | `--tsa URL` | sello de tiempo de la firma (RFC3161) |
| B-LT | `--lt --tsa URL` | + información de revocación (OCSP/CRL) en el DSS |
| B-LTA | `--lta --tsa URL` | + sello de tiempo del documento (*DocTimeStamp*) |

`--lt` y `--lta` descargan OCSP/CRL de la cadena del firmante (y de la TSA) y las
incrustan en el DSS, por lo que **requieren red**. `--lta` añade además un
*document timestamp*; es lo que Adobe muestra como "LTV habilitado".

```bash
python firmar.py --p12 mi_certificado.p12 --out firmado_lta.pdf \
  --lta --tsa http://tss.accv.es:8318/tsa
```

> `--trust-pem cacert.pem` añade anclas de confianza extra (útil, por ejemplo,
> para probar con certificados propios).

## Múltiples firmas

El script permite firmar un PDF ya firmado:

- Si existe un **campo de firma vacío**, lo reutiliza.
- Si no, crea un campo nuevo (`Signature1`, `Signature2`, `...`).
- El **sello visible se desplaza** automáticamente (sube de fila y luego salta a
  la izquierda) para no solapar firmas anteriores.
- Si la firma previa es una **firma de certificación** con `DocMDP = NO_CHANGES`,
  la operación se aborta con un mensaje claro.

Puedes forzar el nombre del campo con `--field`:

```bash
python firmar.py --p12 mi_certificado.p12 --in doble.pdf --out triple.pdf --field Firma3
```

Para firmar un documento con varias firmas, encadena la salida de una como
entrada de la siguiente:

```bash
python firmar.py --p12 a.p12 --in original.pdf   --out paso1.pdf
python firmar.py --p12 b.p12 --in paso1.pdf       --out paso2.pdf
```

## Verificar una firma

Inspección rápida con Poppler:

```bash
pdfsig presentacion_firmado.pdf
```

> `pdfsig` y visores como Okular muestran la **hora declarada** (`/M`), no el
> sello RFC3161 de la TSA.

Inspección detallada (firmante, hora declarada, **hora real de la TSA**,
política, cadena de la TSA y si hay revocación embebida):

```bash
python verificar.py presentacion_firmado.pdf
```

Validación criptográfica con informe de **qué se comprobó y qué no**:

```bash
python verificar.py presentacion_firmado.pdf --validate
```

Opciones de validación:

| Opción | Descripción | Por defecto |
| --- | --- | --- |
| `--revocation {off,soft,hard}` | política de revocación: `off` no la mira; `soft` la intenta y no falla si no puede; `hard` la exige | `soft` |
| `--offline` | usa solo la revocación embebida en el `/DSS` (sin red) | online |
| `--trust-pem CERT` | certificado PEM/DER extra para confiar (repetible) | — |
| `--details` | añade el informe detallado de pyHanko | — |

### Qué se comprueba

| Aspecto | Por defecto | `--offline` (B-LT/LTA) | `--revocation off` |
| --- | --- | --- | --- |
| Integridad (hash + firma) | Sí | Sí | Sí |
| Cadena de confianza | Sí | Sí (con certs del DSS) | Sí |
| Revocación del firmante | Sí (online) | Sí (datos DSS) | No |
| Sello de tiempo / TSA | Sí | Sí | Sí (sin revocación) |
| Revocación de la TSA | Sí (online) | Sí (datos DSS) | No |
| Cobertura / modificaciones | Sí | Sí | Sí |
| Cualificación eIDAS | No (no implementado) | No | No |

> Nota: la **cualificación eIDAS** (contraste con la Lista de Confianza / TSL) **no
> está implementada**; ese punto sale siempre `NO COMPROBADA (no implementado)`.
> La firma puede ser válida y confiable aunque la cualificación no se evalúe.

> Importante: **firmar no consulta la revocación**. Un `B-B` firmado sin conexión
> podría hacerse con un certificado revocado. Solo la validación la comprueba, y
> solo si tiene datos: online (`--revocation soft|hard`) o embebidos en el DSS
> de un `B-LT`/`B-LTA` (`--offline`). Si no hay datos, el informe dirá
> `NO COMPROBADA` (nunca lo dará por bueno).

Salida de ejemplo (recorte):

```
Archivo: firmado_lta.pdf
DSS (revocacion embebida): Certs=8 OCSPs=4 CRLs=0
Validacion: revocation=soft offline=False fetch=True

=== Firma #1 (campo Signature1) tipo=/Sig ===
Firmante          : NOMBRE APELLIDOS - 00000000X
Hora declarada    : 2026-10-02 23:43:58+02:00 (no verificable por si sola)
Sello de tiempo   : TSA TSA1 ACCV 2016 ...
COMPROBACIONES:
  Integridad (hash + firma)....... COMPROBADA: OK
  Cadena de confianza............. COMPROBADA: OK (ancla: ...)
  Revocacion del firmante......... COMPROBADA (online): no consta revocacion
  Sello de tiempo................. COMPROBADA: OK; TSA: TSA1 ACCV 2016 ...
    Revocacion de la TSA.......... COMPROBADA (online): no consta revocacion
  Cobertura / modificaciones...... COMPROBADA: ENTIRE_REVISION + LTA_UPDATES
  Cualificacion eIDAS............. NO COMPROBADA (no implementado)
RESUMEN: firma OK; sello OK; revocacion OK (online)
```

Códigos de salida: `0` todo correcto; `1` firma no íntegra/válida; `2` certificado
**revocado**; `3` `--revocation hard` sin poder determinar el estado.

> Nota: sin `--tsa`/`--lt`/`--lta` las firmas son **PAdES B-B**; con `--tsa` son
> **B-T**. Para validez a largo plazo y poder comprobar la revocación **offline**
> usa `--lt` (B-LT) o `--lta` (B-LTA), que embeben la información en el DSS.

## Archivos ignorados por git

El repositorio no versiona datos sensibles ni artefactos generados: ver
`.gitignore` (`.p12`, `*.pdf`, `__pycache__/`, `.vscode/`, `.mypy_cache/`).
