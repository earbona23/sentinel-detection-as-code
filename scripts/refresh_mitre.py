#!/usr/bin/env python3
"""Destila el catalogo oficial de MITRE ATT&CK a un indice pequeno y versionado.

POR QUE UN SNAPSHOT Y NO UNA LLAMADA EN VIVO
El bundle STIX de ATT&CK pesa ~54 MB. Meterlo al repo es inaceptable, y consultarlo por red
en cada corrida de CI ata la validacion a que un servicio de terceros este arriba. Un pipeline
que falla porque MITRE tuvo un mal dia no esta validando nada: esta generando ruido.

Con un snapshot destilado el CI es reproducible y funciona sin red. La contrapartida honesta
es que el catalogo envejece — por eso se versiona, se registra la fecha, y actualizarlo es un
PR explicito que se revisa como cualquier otro cambio.

POR QUE SE GUARDA EL SHA-256 DEL ORIGEN
Para que cualquiera pueda comprobar que este indice salio del bundle oficial y no de una
edicion a mano. Sin eso, "verificado contra MITRE" es una afirmacion sin respaldo — que es
justo lo que este repo no quiere ser.

USO:  python scripts/refresh_mitre.py [--offline <ruta-al-bundle.json>]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import sys
import urllib.request

FUENTE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
SALIDA = pathlib.Path(__file__).resolve().parent.parent / "data" / "mitre-techniques.json"


def descargar(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=300) as r:
        return r.read()


def destilar(crudo: bytes) -> dict:
    bundle = json.loads(crudo)
    tecnicas: dict[str, dict] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        tid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                break
        if not tid:
            continue

        # Las tacticas viven en kill_chain_phases con kill_chain_name = mitre-attack.
        tacticas = [
            f["phase_name"]
            for f in obj.get("kill_chain_phases", [])
            if f.get("kill_chain_name") == "mitre-attack"
        ]

        tecnicas[tid] = {
            "name": obj.get("name"),
            "tactics": sorted(set(tacticas)),
            # Se conservan a proposito en vez de filtrarlas: el validador tiene que poder
            # decir "esa tecnica EXISTE pero esta deprecada", que es un mensaje distinto —
            # y mas util — que "no existe".
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "revoked": bool(obj.get("revoked", False)),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
        }

    return {
        "source": FUENTE,
        "retrieved_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha256_of_source": hashlib.sha256(crudo).hexdigest(),
        "spec_version": bundle.get("spec_version"),
        "count": len(tecnicas),
        "techniques": dict(sorted(tecnicas.items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--offline", help="usar un bundle ya descargado en vez de bajarlo")
    args = ap.parse_args()

    if args.offline:
        crudo = pathlib.Path(args.offline).read_bytes()
        origen = f"archivo local: {args.offline}"
    else:
        crudo = descargar(FUENTE)
        origen = FUENTE

    indice = destilar(crudo)
    if indice["count"] < 500:
        # Fail-closed: un bundle truncado produciria un indice que rechaza tecnicas validas,
        # y eso se veria como "el repo tiene mapeos malos" cuando el roto es el indice.
        print(f"ABORTA: solo {indice['count']} tecnicas; el bundle parece incompleto", file=sys.stderr)
        return 1

    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    SALIDA.write_text(json.dumps(indice, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    kb = SALIDA.stat().st_size / 1024
    print(f"origen        : {origen}")
    print(f"sha256 origen : {indice['sha256_of_source'][:32]}…")
    print(f"tecnicas      : {indice['count']}")
    print(f"escrito       : {SALIDA}  ({kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
