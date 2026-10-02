#!/usr/bin/env python3
"""Inspecciona (y opcionalmente valida) las firmas de un PDF.

Para cada firma muestra:
  - el firmante;
  - la hora DECLARADA por quien firma (/M y atributo signing-time);
  - el sello de tiempo RFC3161 de la TSA (hora real, politica y cadena), si
    existe;
  - si hay informacion de revocacion (DSS/OCSP/CRL) embebida.

Uso:
    python verificar.py [pdf] [--validate]
"""
import argparse
import sys

from asn1crypto import cms
from pyhanko.pdf_utils.reader import PdfFileReader

SIGNING_TIME_OID = "1.2.840.113549.1.9.5"
TS_TOKEN_OID = "1.2.840.113549.1.9.16.2.14"


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
        certs = [
            c.chosen for c in sd["certificates"] if c.name == "certificate"
        ]
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


def _dss_info(reader):
    try:
        dss = reader.root["/DSS"]
    except KeyError:
        return None
    info = {}
    for key in ("/Certs", "/OCSPs", "/CRLs"):
        try:
            info[key] = len(dss[key])
        except KeyError:
            info[key] = 0
    return info


def inspect(path: str, validate: bool) -> int:
    reader = PdfFileReader(open(path, "rb"), strict=False)
    sigs = list(reader.embedded_signatures)
    if not sigs:
        print("No se encontraron firmas en", path)
        return 0

    dss = _dss_info(reader)
    if dss is not None:
        print(f"DSS (revocacion embebida): {dss}")
    else:
        print("DSS (revocacion embebida): no hay")

    for i, s in enumerate(sigs, 1):
        print(f"\n=== Firma #{i} ===")
        try:
            print("campo          :", s.fq_name)
        except Exception:
            print("campo          : ?")
        print("tipo           :", getattr(s, "sig_object_type", "?"))
        try:
            print("firmante       :", _cn(s.signer_cert))
        except Exception:
            print("firmante       : ?")

        si = s.signer_info
        is_doc_ts = getattr(s, "sig_object_type", None) == "/DocTimeStamp"
        if is_doc_ts:
            print("hora TSA       :", s.self_reported_timestamp,
                  " (sello de tiempo del documento)")
            print("SELLO DE TIEMPO DEL DOCUMENTO (DocTimeStamp, RFC3161)")
        else:
            claimed = _signing_time_attr(si["signed_attrs"]) or s.self_reported_timestamp
            print("hora declarada :", claimed, " (no verificable por si sola)")

            ts = _extract_timestamp(si["unsigned_attrs"])
            if ts:
                print("SELLO DE TIEMPO TSA (RFC3161):")
                print("  hora TSA     :", ts["gen_time"])
                print("  politica     :", ts["policy"])
                print("  serie        :", ts["serial"])
                for cert in ts["certs"]:
                    print("  cert TSA     :", _cn(cert))
            else:
                print("SELLO DE TIEMPO TSA: no hay (firma sin --tsa)")

        if validate:
            from pyhanko.sign.validation import validate_pdf_signature

            try:
                st = validate_pdf_signature(s)
                print("validacion     :", st.summary())
                print(
                    f"  intacto={st.intact} valido={st.valid} "
                    f"confiable={st.trusted}"
                )
                tsv = getattr(st, "timestamp_validity", None)
                if tsv is not None:
                    print(
                        f"  sello TSA: intacto={tsv.intact} valido={tsv.valid} "
                        f"confiable={tsv.trusted} hora={tsv.timestamp}"
                    )
            except Exception as e:
                print("validacion     : ERROR:", e)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Inspeccionar firmas de un PDF")
    ap.add_argument("pdf", nargs="?", default="presentacion_firmado.pdf",
                    help="PDF a inspeccionar")
    ap.add_argument("--validate", action="store_true",
                    help="validar criptograficamente (puede requerir red)")
    args = ap.parse_args()
    try:
        return inspect(args.pdf, args.validate)
    except FileNotFoundError:
        print(f"ERROR: no existe el archivo {args.pdf}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
