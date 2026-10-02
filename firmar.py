#!/usr/bin/env python3
"""Firma un PDF con un certificado PKCS#12 (.p12/.pfx).

La contrasena se pide de forma interactiva y oculta, o se puede pasar por la
variable de entorno P12_PASS. Nunca se guarda ni se muestra.

Por defecto crea una firma PAdES VISIBLE en la pagina 1, abajo a la derecha.
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
from pyhanko.sign.signers.pdf_signer import PdfSigner
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.sign.validation import ValidationContext, read_certification_data

DEFAULT_BOX = (650, 30, 940, 120)
GAP = 10
DEFAULT_PAGE_HEIGHT = 842.0


def parse_box(valor: str) -> tuple[int, int, int, int]:
    partes = [int(p.strip()) for p in valor.split(",")]
    if len(partes) != 4:
        raise argparse.ArgumentTypeError("El box debe ser x1,y1,x2,y2")
    return tuple(partes)  # type: ignore[return-value]


def _resolve(obj):
    try:
        return obj.get_object()
    except AttributeError:
        return obj


def _page_height(handler, page_ix: int) -> float:
    try:
        page_ref, _ = handler.find_page_for_modification(page_ix)
        page = _resolve(page_ref)
        mb = page.get("/MediaBox")
        while mb is None:
            parent = page.get("/Parent")
            if parent is None:
                return DEFAULT_PAGE_HEIGHT
            page = _resolve(parent)
            mb = page.get("/MediaBox")
        mb = _resolve(mb)
        return float(mb[3]) - float(mb[1])
    except Exception:
        return DEFAULT_PAGE_HEIGHT


def _box_for_signature(base_box, page_h: float, index: int):
    if index <= 0:
        return base_box
    x1, y1, x2, y2 = base_box
    w, h = x2 - x1, y2 - y1
    rows = max(1, int((page_h - 2 * y1) // (h + GAP)))
    col, row = divmod(index, rows)
    ny1 = y1 + row * (h + GAP)
    nx1 = x1 - col * (w + GAP)
    return (nx1, int(ny1), nx1 + w, int(ny1) + h)


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
    ap.add_argument("--tsa", default=None,
                    help="URL de autoridad de sellado de tiempo (opcional)")
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
    ap.add_argument("--box", type=parse_box, default=DEFAULT_BOX,
                    help="recuadro x1,y1,x2,y2 en puntos (por defecto 650,30,940,120)")
    args = ap.parse_args()

    if args.lta and not args.tsa:
        print("ERROR: --lta requiere --tsa (hace falta una TSA para el sello "
              "de tiempo del documento).", file=sys.stderr)
        return 6

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
        page_h = _page_height(reader, args.page - 1)
        box = _box_for_signature(args.box, page_h, n_sigs)
        spec = SigFieldSpec(
            sig_field_name=field_name,
            on_page=args.page - 1,
            box=box,
        )

    timestamper = HTTPTimeStamper(args.tsa) if args.tsa else None
    pdf_signer = PdfSigner(meta, signer, timestamper=timestamper, new_field_spec=spec)

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
