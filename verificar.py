#!/usr/bin/env python3
"""Inspecciona (y opcionalmente valida) las firmas de un PDF.

Para cada firma muestra:
  - el firmante;
  - la hora DECLARADA por quien firma (/M y atributo signing-time);
  - el sello de tiempo RFC3161 de la TSA (hora real, politica y cadena), si
    existe;
  - si hay informacion de revocacion (DSS/OCSP/CRL) embebida.

Con --validate anade un bloque COMPROBACIONES que indica explicitamente que se
comprobo y que no (integridad, cadena, revocacion, sello de tiempo, cobertura),
teniendo en cuenta lo que el contexto de validacion permite comprobar.

Uso:
    python verificar.py [pdf] [--validate] [--revocation {off,soft,hard}]
                        [--offline] [--trust-pem CERT] [--details]
"""
import argparse
import sys

from asn1crypto import cms, crl, ocsp, x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko.sign.validation import (
    ValidationContext,
    validate_pdf_signature,
    validate_pdf_timestamp,
)

SIGNING_TIME_OID = "1.2.840.113549.1.9.5"
TS_TOKEN_OID = "1.2.840.113549.1.9.16.2.14"

REVOCATION_INDICATORS = {
    "REVOKED",
    "REVOKED_NO_POE",
    "REVOKED_CA_NO_POE",
    "REVOCATION_OUT_OF_BOUNDS_NO_POE",
    "OUT_OF_BOUNDS_NO_POE",
    "OUT_OF_BOUNDS_NOT_REVOKED",
    "TRY_LATER",
}


def _cn(cert) -> str:
    try:
        return cert.subject.native.get("common_name", cert.subject.human_friendly)
    except Exception:
        return "?"


def _extract_timestamp(attrs):
    for a in attrs or []:
        if a["type"].dotted != TS_TOKEN_OID:
            continue
        ci = cms.ContentInfo.load(a["values"][0].dump())
        sd = ci["content"]
        tst = sd["encap_content_info"]["content"].parsed
        certs = [c.chosen for c in sd["certificates"] if c.name == "certificate"]
        return {
            "gen_time": tst["gen_time"].native,
            "policy": tst["policy"].native,
            "serial": tst["serial_number"].native,
            "certs": certs,
        }
    return None


def _signing_time_attr(attrs):
    for a in attrs or []:
        if a["type"].dotted == SIGNING_TIME_OID:
            try:
                return a["values"][0].native
            except Exception:
                return None
    return None


def _load_dss(reader):
    try:
        dss = reader.root["/DSS"]
    except KeyError:
        return None

    def raw(ref):
        return ref.get_object().data

    return {
        "certs": [x509.Certificate.load(raw(r)) for r in dss.get("/Certs", [])],
        "ocsps": [ocsp.OCSPResponse.load(raw(r)) for r in dss.get("/OCSPs", [])],
        "crls": [crl.CertificateList.load(raw(r)) for r in dss.get("/CRLs", [])],
    }


def _dss_summary(dss):
    if not dss:
        return "no hay"
    return (
        f"Certs={len(dss['certs'])} OCSPs={len(dss['ocsps'])} "
        f"CRLs={len(dss['crls'])}"
    )


def _build_vc(args, dss):
    extra = [load_cert_from_pemder(p) for p in args.trust_pem] or None
    hard = args.revocation == "hard"
    kwargs = {"extra_trust_roots": extra}
    if args.revocation == "off":
        kwargs.update(allow_fetching=False, revocation_mode="soft-fail")
    elif args.offline:
        kwargs.update(
            allow_fetching=False,
            revocation_mode="hard-fail" if hard else "soft-fail",
            ocsps=(dss["ocsps"] if dss else []) or [],
            crls=(dss["crls"] if dss else []) or [],
            other_certs=(dss["certs"] if dss else []) or [],
        )
    else:
        kwargs.update(
            allow_fetching=True,
            revocation_mode="hard-fail" if hard else "soft-fail",
        )
    return ValidationContext(**kwargs)


def _revocation_context(args, dss):
    """Devuelve (comprometida, metodo, aviso)."""
    if args.revocation == "off":
        return False, None, "modo --revocation off"
    if args.offline:
        has_dss = bool(dss and (dss["ocsps"] or dss["crls"]))
        if has_dss:
            return True, "DSS", None
        return (
            False,
            None,
            "el PDF no lleva datos de revocacion (B-B); "
            "re-firma con --lt/--lta o usa modo online",
        )
    return True, "online", None


def _revocation_status(attempted, method, status):
    """Devuelve (texto, nivel) donde nivel: ok|unknown|revoked|skipped."""
    if not attempted:
        return "NO COMPROBADA", "skipped"
    if status.revoked:
        det = status.revocation_details
        when = det.revocation_date.isoformat() if det.revocation_date else "?"
        reason = det.revocation_reason.human_friendly if det.revocation_reason else "?"
        return f"REVOCADO ({when}, {reason})", "revoked"
    tpi = status.trust_problem_indic
    name = tpi.standard_name if tpi is not None else None
    if name in REVOCATION_INDICATORS:
        return f"NO COMPROBADA (estado desconocido: {name})", "unknown"
    return "no consta revocacion", "ok"


def _fmt(label, value, width=32):
    return f"  {label.ljust(width, '.')} {value}"


def _anchor(status):
    try:
        return status.validation_path[0].subject.human_friendly
    except Exception:
        return "?"


def _chain_line(status):
    if status.validation_path is not None:
        return f"COMPROBADA: OK (ancla: {_anchor(status)})"
    tpi = status.trust_problem_indic
    name = tpi.standard_name if tpi is not None else "sin cadena de confianza"
    return f"FALLO ({name})"


def _coverage_line(status):
    cov = getattr(status, "coverage", None)
    mod = getattr(status, "modification_level", None)
    if cov is None:
        return "NO COMPROBADA"
    text = cov.name
    if mod is not None and mod.name not in ("NONE",):
        text += f" + {mod.name}"
    return f"COMPROBADA: {text}"


def _qualification_line(status):
    qr = getattr(status, "qualification_result", None)
    if qr is None:
        return "NO COMPROBADA (requiere TSL eIDAS)"
    return "COMPROBADA: " + ("cualificado" if qr.status.qualified else "no cualificado")


def _report_timestamp(vc_status):
    ts = getattr(vc_status, "timestamp_validity", None)
    if ts is None:
        return None
    return ts


def _comprobaciones(status, is_doc_ts, attempted, method, warn):
    lines = []
    lines.append(_fmt("Integridad (hash + firma)",
                      "COMPROBADA: OK" if status.intact and status.valid else "FALLO"))
    lines.append(_fmt("Cadena de confianza", _chain_line(status)))

    rev_text, rev_level = _revocation_status(attempted, method, status)
    if rev_level == "ok":
        rev_text = f"COMPROBADA ({method}): {rev_text}"
    elif rev_level == "skipped" and warn:
        rev_text = f"{rev_text} ({warn})"
    rev_label = "Revocacion de la TSA" if is_doc_ts else "Revocacion del firmante"
    lines.append(_fmt(rev_label, rev_text))

    if is_doc_ts:
        lines.append(_fmt("Sello del documento",
                          "COMPROBADA: DocTimeStamp RFC3161"))
    else:
        ts = _report_timestamp(status)
        if ts is None:
            lines.append(_fmt("Sello de tiempo", "AUSENTE"))
        else:
            ok = ts.intact and ts.valid and ts.trusted
            lines.append(_fmt("Sello de tiempo",
                              f"COMPROBADA: {'OK' if ok else 'FALLO'}; "
                              f"TSA: {_cn(ts.signing_cert)}"))
            lines.append(_fmt("  Revocacion de la TSA",
                              _prefix_rev(attempted, method, ts, warn)))

    lines.append(_fmt("Cobertura / modificaciones", _coverage_line(status)))
    lines.append(_fmt("Cualificacion eIDAS", _qualification_line(status)))
    return lines, rev_level


def _prefix_rev(attempted, method, ts, warn):
    text, level = _revocation_status(attempted, method, ts)
    if level == "ok":
        return f"COMPROBADA ({method}): {text}"
    if level == "skipped" and warn:
        return f"{text} ({warn})"
    return text


def inspect(args) -> int:
    reader = PdfFileReader(open(args.pdf, "rb"), strict=False)
    sigs = list(reader.embedded_signatures)
    if not sigs:
        print("No se encontraron firmas en", args.pdf)
        return 0

    dss = _load_dss(reader)
    print("Archivo:", args.pdf)
    print("DSS (revocacion embebida):", _dss_summary(dss))

    vc = None
    attempted = method = warn = None
    if args.validate:
        vc = _build_vc(args, dss)
        attempted, method, warn = _revocation_context(args, dss)
        print(f"Validacion: revocation={args.revocation} "
              f"offline={args.offline} fetch={vc.fetching_allowed}")

    exit_code = 0
    for i, s in enumerate(sigs, 1):
        is_doc_ts = getattr(s, "sig_object_type", None) == "/DocTimeStamp"
        print(f"\n=== Firma #{i} (campo {getattr(s, 'fq_name', '?')}) "
              f"tipo={getattr(s, 'sig_object_type', '?')} ===")
        try:
            print("Firmante          :", _cn(s.signer_cert))
        except Exception:
            print("Firmante          : ?")

        si = s.signer_info
        if is_doc_ts:
            print("Hora TSA          :", s.self_reported_timestamp,
                  "(sello de tiempo del documento)")
        else:
            claimed = _signing_time_attr(si["signed_attrs"]) or s.self_reported_timestamp
            print("Hora declarada    :", claimed, "(no verificable por si sola)")
            ts = _extract_timestamp(si["unsigned_attrs"])
            if ts:
                print("Sello de tiempo   : TSA", _cn(ts["certs"][0]) if ts["certs"] else "?")
                print("                    hora:", ts["gen_time"])
                print("                    politica:", ts["policy"])
                for cert in ts["certs"]:
                    print("                    cadena:", _cn(cert))
            else:
                print("Sello de tiempo   : AUSENTE")

        if not args.validate:
            continue

        try:
            if is_doc_ts:
                status = validate_pdf_timestamp(s, validation_context=vc)
            else:
                status = validate_pdf_signature(
                    s, signer_validation_context=vc, ts_validation_context=vc
                )
        except Exception as e:
            print("COMPROBACIONES: ERROR",
                  f"{type(e).__name__}: {e}")
            exit_code = max(exit_code, 1)
            continue

        print("COMPROBACIONES:")
        lines, rev_level = _comprobaciones(
            status, is_doc_ts, attempted, method, warn
        )
        for line in lines:
            print(line)

        bottom = []
        bottom.append("firma " + ("OK" if status.intact and status.valid else "FALLO"))
        if getattr(status, "timestamp_validity", None):
            ts_ok = (
                status.timestamp_validity.intact
                and status.timestamp_validity.valid
                and status.timestamp_validity.trusted
            )
            bottom.append("sello " + ("OK" if ts_ok else "FALLO"))
        if rev_level == "ok":
            bottom.append(f"revocacion OK ({method})")
        elif rev_level == "revoked":
            bottom.append("REVOCADO")
        else:
            bottom.append("revocacion NO verificada")
        print("RESUMEN:", "; ".join(bottom))

        if args.details and hasattr(status, "pretty_print_details"):
            print()
            print(status.pretty_print_details())

        if rev_level == "revoked":
            exit_code = max(exit_code, 2)
        elif rev_level == "unknown" and args.revocation == "hard":
            exit_code = max(exit_code, 3)

    return exit_code


def main() -> int:
    ap = argparse.ArgumentParser(description="Inspeccionar validar firmas de un PDF")
    ap.add_argument("pdf", nargs="?", default="presentacion_firmado.pdf",
                    help="PDF a inspeccionar")
    ap.add_argument("--validate", action="store_true",
                    help="validar criptograficamente (incluye revocacion segun opciones)")
    ap.add_argument("--revocation", choices=("off", "soft", "hard"), default="soft",
                    help="politica de revocacion (por defecto soft)")
    ap.add_argument("--offline", action="store_true",
                    help="usar solo la revocacion embebida en el /DSS (sin red)")
    ap.add_argument("--trust-pem", action="append", default=[], metavar="FILE",
                    help="certificado PEM/DER extra para confiar (repetible)")
    ap.add_argument("--details", action="store_true",
                    help="mostrar tambien el informe detallado de pyHanko")
    args = ap.parse_args()
    try:
        return inspect(args)
    except FileNotFoundError:
        print(f"ERROR: no existe el archivo {args.pdf}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
