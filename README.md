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
pip install "pyhanko[opentype]"
```

> El extra `opentype` (aportan `fonttools` y `uharfbuzz`) es necesario para
> dibujar el texto del sello visible. Sin él solo funciona la firma invisible.

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
python firmar.py --p12 mi_certificado.p12 --tsa http://timestamp.digicert.com
```

> Usa `http://timestamp.digicert.com`. El endpoint RFC3161 de DigiCert es HTTP;
> si tu red bloquea el puerto 443/HTTPS hacia ese host verás un *timeout*. Otros
> servidores gratuitos: `http://timestamp.globalsign.com/tsa/r6advanced1`.
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
  --lta --tsa http://timestamp.digicert.com
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

Validación criptográfica (integridad, validez, confianza y token TSA; puede
requerir red):

```bash
python verificar.py presentacion_firmado.pdf --validate
```

Salida de ejemplo:

```
DSS (revocacion embebida): no hay

=== Firma #1 ===
campo          : Signature1
firmante       : NOMBRE APELLIDOS - 00000000X
hora declarada : 2026-10-02 21:59:31+02:00  (no verificable por si sola)
SELLO DE TIEMPO TSA (RFC3161):
  hora TSA     : 2026-10-02 19:59:31+00:00
  politica     : 2.16.840.1.114412.7.1
  cert TSA     : DigiCert SHA256 RSA4096 Timestamp Responder 2026 1
  cert TSA     : DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
  cert TSA     : DigiCert Trusted Root G4
```

> Nota: sin `--tsa`/`--lt`/`--lta` las firmas son **PAdES B-B**; con `--tsa` son
> **B-T**. Para validez a largo plazo usa `--lt` (B-LT) o `--lta` (B-LTA), que
> embeben la información de revocación en el DSS.

## Archivos ignorados por git

El repositorio no versiona datos sensibles ni artefactos generados: ver
`.gitignore` (`.p12`, PDFs firmados, `__pycache__/`, `.vscode/`).
