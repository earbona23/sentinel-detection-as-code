"""CLI del validador: recorre las detecciones y las valida en tres frentes.

  1. ESTRUCTURA  — schema_check  (JSON Schema + reglas semanticas propias)
  2. MITRE       — mitre_check   (contra el catalogo ATT&CK real, no una lista escrita a mano)
  3. KQL         — tools/kql-lint (el parser de Microsoft, no expresiones regulares)

PRINCIPIO DE DISENO: FALLAR CERRADO
Si alguna de las tres validaciones NO SE PUDO EJECUTAR —falta el indice MITRE, no esta
compilado el linter, el YAML no se puede leer— el resultado es FALLO, nunca "sin problemas".
Un chequeo que no corrio no es un chequeo que paso, y confundir las dos cosas es como un
pipeline verde termina certificando codigo que nadie miro.

USO:
  python -m validator.cli                    # valida todo detections/
  python -m validator.cli ruta/a/regla.yaml  # valida una sola
  python -m validator.cli --json             # salida para maquinas
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

import yaml

from validator.mitre_check import IndiceMitre
from validator.schema_check import ValidadorEsquema

RAIZ = pathlib.Path(__file__).resolve().parent.parent
DIR_DETECCIONES = RAIZ / "detections"
KQL_LINT_DLL = RAIZ / "tools" / "kql-lint" / "bin" / "Release" / "net6.0" / "kql-lint.dll"


@dataclass
class Informe:
    archivo: str
    errores: list[str] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errores


def validar_kql(consulta: str) -> tuple[list[str], list[str]]:
    """Devuelve (errores, avisos). Si el linter no se puede ejecutar, eso ES un error."""
    if not KQL_LINT_DLL.exists():
        return (
            [
                "no encuentro el linter de KQL compilado. Compilalo con: "
                "dotnet build -c Release tools/kql-lint  "
                "(sin el, la sintaxis KQL NO se valida y este resultado no vale)"
            ],
            [],
        )

    with tempfile.NamedTemporaryFile("w", suffix=".kql", delete=False, encoding="utf-8") as f:
        f.write(consulta)
        temporal = f.name

    try:
        proc = subprocess.run(
            ["dotnet", str(KQL_LINT_DLL), temporal],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return (["no encuentro `dotnet`; hace falta el runtime .NET para validar KQL"], [])
    except subprocess.TimeoutExpired:
        return (["el linter de KQL no respondio en 120s"], [])
    finally:
        pathlib.Path(temporal).unlink(missing_ok=True)

    # 0 = todo bien · 1 = hay diagnosticos · 2 = el linter fallo (y eso NO es "sin problemas")
    if proc.returncode == 2:
        return ([f"el linter de KQL fallo: {proc.stderr.strip()[:200]}"], [])

    try:
        salida = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return ([f"el linter devolvio algo que no es JSON: {proc.stdout[:150]}"], [])

    errores: list[str] = []
    for res in salida.get("results", []):
        for d in res.get("diagnostics", []):
            errores.append(
                f"KQL linea {d['line']}, columna {d['column']}: {d['message']}"
            )
    return errores, []


def validar_archivo(
    ruta: pathlib.Path, esquema: ValidadorEsquema, mitre: IndiceMitre
) -> Informe:
    rel = str(ruta.relative_to(RAIZ))
    inf = Informe(archivo=rel)

    try:
        doc = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        inf.errores.append(f"YAML invalido: {str(e)[:200]}")
        return inf
    if not isinstance(doc, dict):
        inf.errores.append("el archivo no contiene un mapa YAML en la raiz")
        return inf

    r1 = esquema.validar(doc)
    inf.errores += r1.errores
    inf.avisos += r1.avisos

    # MITRE y KQL solo si los campos existen; si faltan, el error ya lo reporto el esquema y
    # repetirlo seria ruido.
    tecnicas = doc.get("relevantTechniques")
    tacticas = doc.get("tactics")
    if isinstance(tecnicas, list) and isinstance(tacticas, list):
        r2 = mitre.validar(tecnicas, tacticas)
        inf.errores += r2.errores
        inf.avisos += r2.avisos

    consulta = doc.get("query")
    if isinstance(consulta, str) and consulta.strip():
        e, a = validar_kql(consulta)
        inf.errores += e
        inf.avisos += a

    return inf


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("rutas", nargs="*", help="archivos a validar (por defecto: detections/)")
    ap.add_argument("--json", action="store_true", help="salida JSON")
    args = ap.parse_args()

    # Si el validador no se puede inicializar, se aborta con codigo 2 — distinto de "hay
    # reglas mal" (1). Confundir "no pude validar" con "valide y esta mal" hace que se
    # arreglen las reglas equivocadas.
    try:
        esquema = ValidadorEsquema()
        mitre = IndiceMitre()
    except Exception as e:
        print(f"NO PUDE INICIALIZAR EL VALIDADOR: {e}", file=sys.stderr)
        return 2

    if args.rutas:
        archivos = [pathlib.Path(p).resolve() for p in args.rutas]
    else:
        archivos = sorted(DIR_DETECCIONES.rglob("*.yaml")) + sorted(DIR_DETECCIONES.rglob("*.yml"))

    if not archivos:
        print("NO ENCONTRE DETECCIONES QUE VALIDAR.", file=sys.stderr)
        print("Esto NO es un exito: es un directorio vacio.", file=sys.stderr)
        return 2

    informes = [validar_archivo(a, esquema, mitre) for a in archivos]

    if args.json:
        print(json.dumps(
            {
                "mitre_index": {"retrieved_utc": mitre.obtenido, "techniques": len(mitre.tecnicas)},
                "files": [
                    {"file": i.archivo, "ok": i.ok, "errors": i.errores, "warnings": i.avisos}
                    for i in informes
                ],
            },
            indent=2, ensure_ascii=False,
        ))
    else:
        for i in informes:
            marca = "OK  " if i.ok else "FAIL"
            print(f"[{marca}] {i.archivo}")
            for e in i.errores:
                print(f"       error: {e}")
            for a in i.avisos:
                print(f"       aviso: {a}")

        malos = sum(1 for i in informes if not i.ok)
        avisos = sum(len(i.avisos) for i in informes)
        print()
        print(f"  {len(informes)} deteccion(es) · {malos} con errores · {avisos} aviso(s)")
        print(f"  catalogo ATT&CK: {len(mitre.tecnicas)} tecnicas (snapshot {mitre.obtenido})")

    return 1 if any(not i.ok for i in informes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
