#!/usr/bin/env python3
"""Firma un PDF con un certificado PKCS#12 (.p12/.pfx).

La contrasena se pide de forma interactiva y oculta, o se puede pasar por la
variable de entorno P12_PASS. Nunca se guarda ni se muestra.

Por defecto crea una firma PAdES VISIBLE en la pagina 1, abajo a la derecha. El
recuadro por defecto se calcula a partir del tamano real de la pagina, de modo
que siempre cabe. Con --box puedes fijarlo: cada coordenada admite un valor en
puntos (p. ej. 30) o una fraccion de 0 a 1 de la dimension de la pagina (p. ej.
0.75 = 75% del ancho para x, del alto para y). Si el recuadro resultante se sale
de la pagina, se avisa por stderr pero se continua.

Soporta multi-firma: si el PDF ya tiene firmas, usa/reutiliza un campo libre o
crea uno nuevo (Signature2, Signature3, ...) y desplaza el sello para no
solaparlo. Usa --invisible para una firma sin sello visible.

Perfiles PAdES:
  (por defecto) B-B, con --tsa B-T, con --lt B-LT, con --lta B-LTA.
"""
import argparse
import getpass
import io
import os
import sys
from dataclasses import replace

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import (
    MDPPerm,
    SigFieldSpec,
    SigSeedSubFilter,
    enumerate_sig_fields,
)
from pyhanko.sign.general import SigningError, load_cert_from_pemder
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko.sign.signers.constants import DEFAULT_SIGNING_STAMP_STYLE
from pyhanko.sign.signers.pdf_signer import PdfSigner
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.sign.validation import ValidationContext, read_certification_data

STAMP_WIDTH = 290.0
STAMP_HEIGHT = 90.0
STAMP_MARGIN = 20.0
GAP = 10
DEFAULT_PAGE_WIDTH = 595.0
DEFAULT_PAGE_HEIGHT = 842.0
DEFAULT_TSA = "http://tss.accv.es:8318/tsa"


def parse_box(valor: str) -> tuple[float, float, float, float]:
    try:
        partes = [float(p.strip()) for p in valor.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "El box debe ser x1,y1,x2,y2 (numeros en puntos o fracciones 0-1)"
        )
    if len(partes) != 4:
        raise argparse.ArgumentTypeError("El box debe ser x1,y1,x2,y2")
    return tuple(partes)  # type: ignore[return-value]


def _resolve_box(raw_box, page_w: float, page_h: float):
    """Convierte cada coordenada: 0<=v<=1 es fraccion de la dimension de pagina."""
    dims = (page_w, page_h, page_w, page_h)
    return tuple(
        v * dim if 0.0 <= v <= 1.0 else v
        for v, dim in zip(raw_box, dims)
    )


def _default_box(page_w: float, page_h: float):
    """Sello abajo a la derecha, encogido si la pagina es pequena."""
    w = min(STAMP_WIDTH, max(0.0, page_w - 2 * STAMP_MARGIN))
    h = min(STAMP_HEIGHT, max(0.0, page_h - 2 * STAMP_MARGIN))
    x2 = page_w - STAMP_MARGIN
    x1 = x2 - w
    y1 = STAMP_MARGIN
    return (x1, y1, x1 + w, y1 + h)


def _box_warnings(box, page_w: float, page_h: float):
    x1, y1, x2, y2 = box
    avisos = []
    if x1 >= x2 or y1 >= y2:
        avisos.append(
            f"el recuadro del sello no tiene dimensiones validas: "
            f"x1={x1}, y1={y1}, x2={x2}, y2={y2}."
        )
        return avisos
    fuera = x1 < 0 or y1 < 0 or x2 > page_w or y2 > page_h
    if fuera:
        avisos.append(
            f"el recuadro del sello ({x1:g}, {y1:g}, {x2:g}, {y2:g}) se sale de "
            f"la pagina ({page_w:g}x{page_h:g}); la firma seguira pero puede no "
            f"verse completa. Ajusta --box."
        )
    return avisos


def _resolve(obj):
    try:
        return obj.get_object()
    except AttributeError:
        return obj


def _page_size(handler, page_ix: int) -> tuple[float, float]:
    fallback = (DEFAULT_PAGE_WIDTH, DEFAULT_PAGE_HEIGHT)
    try:
        page_ref, _ = handler.find_page_for_modification(page_ix)
        page = _resolve(page_ref)
        mb = page.get("/MediaBox")
        while mb is None:
            parent = page.get("/Parent")
            if parent is None:
                return fallback
            page = _resolve(parent)
            mb = page.get("/MediaBox")
        mb = _resolve(mb)
        return (float(mb[2]) - float(mb[0]), float(mb[3]) - float(mb[1]))
    except Exception:
        return fallback


def _box_for_signature(base_box, page_h: float, index: int):
    if index <= 0:
        return base_box
    x1, y1, x2, y2 = base_box
    w, h = x2 - x1, y2 - y1
    rows = max(1, int((page_h - 2 * y1) // (h + GAP)))
    col, row = divmod(index, rows)
    ny1 = y1 + row * (h + GAP)
    nx1 = x1 - col * (w + GAP)
    return (nx1, ny1, nx1 + w, ny1 + h)


def _field_lists(reader):
    all_names, filled, empties = [], [], []
    try:
        for name, value, _ref in enumerate_sig_fields(reader):
            all_names.append(name)
            (filled if value else empties).append(name)
    except Exception:
        pass
    return all_names, filled, empties


def _next_field_name(existing):
    i = 1
    while f"Signature{i}" in existing:
        i += 1
    return f"Signature{i}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Firmar un PDF con un .p12")
    ap.add_argument("--p12", required=True,
                    help="ruta al archivo .p12")
    ap.add_argument("--in", dest="entrada", default="presentacion.pdf",
                    help="PDF de entrada")
    ap.add_argument("--out", dest="salida", default="presentacion_firmado.pdf",
                    help="PDF firmado de salida")
    ap.add_argument("--field", default=None,
                    help="nombre del campo de firma (por defecto: automatico)")
    ap.add_argument("--reason", default="Firma del documento", help="motivo")
    ap.add_argument("--location", default="", help="ubicacion")
    ap.add_argument("--tsa", nargs="?", const=DEFAULT_TSA, default=None,
                    metavar="URL",
                    help="URL de autoridad de sellado de tiempo (opcional). "
                         f"Si se pone --tsa sin URL usa ACCV ({DEFAULT_TSA})")
    ap.add_argument("--lt", action="store_true",
                    help="PAdES B-LT: embeber informacion de revocacion (DSS)")
    ap.add_argument("--lta", action="store_true",
                    help="PAdES B-LTA: --lt + sellado de tiempo del documento "
                         "(requiere --tsa)")
    ap.add_argument("--trust-pem", action="append", default=[], metavar="FILE",
                    help="certificado PEM/DER extra para confiar (repetible)")
    ap.add_argument("--invisible", action="store_true",
                    help="no dibujar sello visible")
    ap.add_argument("--page", type=int, default=1,
                    help="pagina del sello visible (1-based, por defecto 1)")
    ap.add_argument("--box", type=parse_box, default=None, metavar="x1,y1,x2,y2",
                    help="recuadro del sello; cada valor en puntos (p. ej. 30) o "
                         "fraccion 0-1 de la dimension de la pagina (p. ej. 0.75). "
                         "Por defecto: abajo a la derecha, calculado segun la pagina")
    ap.add_argument("--stamp-image", default=None, metavar="FILE",
                    help="imagen PNG/JPG de fondo del sello visible")
    ap.add_argument("--stamp-no-text", action="store_true",
                    help="sello solo con la imagen (sin firmante/fecha)")
    ap.add_argument("--stamp-text", default=None, metavar="PLANTILLA",
                    help="plantilla de texto del sello (params: signer, ts)")
    ap.add_argument("--stamp-no-border", action="store_true",
                    help="quitar el borde del sello")
    ap.add_argument("--stamp-opacity", type=float, default=None, metavar="0-1",
                    help="opacidad del fondo del sello (por defecto 1.0 con imagen)")
    args = ap.parse_args()

    if args.lta and not args.tsa:
        print("ERROR: --lta requiere --tsa (hace falta una TSA para el sello "
              "de tiempo del documento).", file=sys.stderr)
        return 6
    if args.stamp_no_text and not args.stamp_image:
        print("ERROR: --stamp-no-text requiere --stamp-image.",
              file=sys.stderr)
        return 7
    if args.stamp_no_text and args.stamp_text is not None:
        print("ERROR: --stamp-text no tiene sentido con --stamp-no-text.",
              file=sys.stderr)
        return 7
    if args.stamp_opacity is not None and not 0.0 <= args.stamp_opacity <= 1.0:
        print("ERROR: --stamp-opacity debe estar entre 0 y 1.", file=sys.stderr)
        return 7

    with open(args.entrada, "rb") as f:
        data = f.read()

    reader = PdfFileReader(io.BytesIO(data), strict=False)
    all_names, filled, empties = _field_lists(reader)
    n_sigs = len(filled)

    try:
        cd = read_certification_data(reader)
    except Exception:
        cd = None
    if cd is not None and cd.permission == MDPPerm.NO_CHANGES:
        print("ERROR: la firma de certificacion existente prohibe cualquier "
              "cambio (DocMDP NO_CHANGES). No se puede anadir otra firma.",
              file=sys.stderr)
        return 3

    if args.field:
        field_name = args.field
        if field_name in empties:
            reuse = True
        elif field_name in all_names:
            print(f"ERROR: el campo '{field_name}' ya existe y esta firmado. "
                  "Usa otro --field o dejalo automatico.", file=sys.stderr)
            return 4
        else:
            reuse = False
    elif empties:
        field_name = empties[0]
        reuse = True
    else:
        field_name = _next_field_name(all_names)
        reuse = False

    if n_sigs:
        print(f"Documento con {n_sigs} firma(s) previa(s). "
              f"Anadiendo firma en el campo '{field_name}'"
              f"{' (campo vacio reutilizado)' if reuse else ' (campo nuevo)'}.")

    pw = os.environ.get("P12_PASS")
    if pw is None:
        pw = getpass.getpass("Contrasena del .p12: ")

    signer = signers.SimpleSigner.load_pkcs12(args.p12, passphrase=pw.encode("utf-8"))
    if signer is None:
        print("ERROR: no se pudo cargar el .p12 (contrasena incorrecta?).", file=sys.stderr)
        return 2

    vc = None
    if args.lt or args.lta:
        extra_roots = [load_cert_from_pemder(p) for p in args.trust_pem] or None
        vc = ValidationContext(
            allow_fetching=True,
            extra_trust_roots=extra_roots,
        )

    meta = PdfSignatureMetadata(
        field_name=field_name,
        reason=args.reason,
        location=args.location or None,
        subfilter=SigSeedSubFilter.PADES,
        embed_validation_info=(args.lt or args.lta),
        use_pades_lta=args.lta,
        validation_context=vc,
    )

    spec = None
    if not args.invisible and not reuse:
        page_w, page_h = _page_size(reader, args.page - 1)
        if args.box is None:
            base_box = _default_box(page_w, page_h)
        else:
            base_box = _resolve_box(args.box, page_w, page_h)
        box = _box_for_signature(base_box, page_h, n_sigs)
        for aviso in _box_warnings(box, page_w, page_h):
            print(f"AVISO: {aviso}", file=sys.stderr)
        spec = SigFieldSpec(
            sig_field_name=field_name,
            on_page=args.page - 1,
            box=box,
        )

    stamp_style = None
    if not args.invisible:
        bg = None
        if args.stamp_image:
            try:
                from pyhanko.pdf_utils.images import PdfImage
                from pyhanko.stamp import StaticStampStyle
            except ImportError:
                print('ERROR: --stamp-image requiere Pillow; instala con '
                      'pip install "pyhanko[image-support]"', file=sys.stderr)
                return 8
            try:
                bg = PdfImage(args.stamp_image)
            except Exception as e:
                print(f"ERROR: no se pudo cargar la imagen "
                      f"{args.stamp_image}: {e}", file=sys.stderr)
                return 8

        opacity = args.stamp_opacity
        if args.stamp_no_text:
            if opacity is None:
                opacity = 1.0
            stamp_style = StaticStampStyle(
                background=bg,
                border_width=0 if args.stamp_no_border else 3,
                background_opacity=opacity,
            )
        else:
            kwargs = {}
            if bg is not None:
                kwargs["background"] = bg
                kwargs["background_opacity"] = (
                    opacity if opacity is not None else 1.0
                )
            elif opacity is not None:
                kwargs["background_opacity"] = opacity
            if args.stamp_no_border:
                kwargs["border_width"] = 0
            if args.stamp_text is not None:
                kwargs["stamp_text"] = args.stamp_text
            if kwargs:
                stamp_style = replace(DEFAULT_SIGNING_STAMP_STYLE, **kwargs)

    timestamper = HTTPTimeStamper(args.tsa) if args.tsa else None
    pdf_signer = PdfSigner(meta, signer, timestamper=timestamper,
                           new_field_spec=spec, stamp_style=stamp_style)

    writer = IncrementalPdfFileWriter(io.BytesIO(data))
    tmp_out = args.salida + ".part"
    try:
        with open(tmp_out, "wb") as out:
            pdf_signer.sign_pdf(writer, output=out)
        os.replace(tmp_out, args.salida)
    except Exception as e:
        try:
            os.remove(tmp_out)
        except OSError:
            pass
        if isinstance(e, SigningError):
            print(f"ERROR al firmar: {e}", file=sys.stderr)
        else:
            print(f"ERROR al firmar ({type(e).__name__}): {e}", file=sys.stderr)
        return 5

    print("Firmado correctamente:", args.salida)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
