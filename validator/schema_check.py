"""Valida una deteccion contra el contrato del repo (schema/detection.schema.json).

DOS NIVELES, Y LA DIFERENCIA IMPORTA
1. ESTRUCTURA — la hace JSON Schema: campos requeridos, tipos, enums, formatos.
2. SEMANTICA  — la hace este modulo a mano, porque JSON Schema no puede expresarla.

El caso que motiva el nivel 2 es `queryPeriod >= queryFrequency`. Los dos campos son strings
con formato ISO 8601 validos por separado; ningun esquema puede decir que uno tiene que ser
mayor que el otro. Y si no se cumple, la regla corre cada hora mirando 30 minutos:
**la mitad de los eventos nunca se evalua** y el panel de Sentinel se ve perfecto.
Es un agujero silencioso — exactamente la clase de fallo que este repo existe para no tener.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
from dataclasses import dataclass, field

import jsonschema

RUTA_ESQUEMA = pathlib.Path(__file__).resolve().parent.parent / "schema" / "detection.schema.json"

# ISO 8601 de duracion, acotado a lo que Sentinel acepta en estos campos: dias, horas,
# minutos y segundos. No se soportan anios ni meses a proposito — no tienen duracion fija
# (un mes son 28, 30 o 31 dias) y compararlos exigiria inventar una convencion.
_PATRON = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")


def duracion_a_segundos(valor: str) -> int | None:
    """Convierte PT1H / P1D / PT30M a segundos. Devuelve None si no se puede interpretar."""
    m = _PATRON.match(valor or "")
    if not m or valor in ("P", "PT"):
        return None
    dias, horas, minutos, segundos = (int(g) if g else 0 for g in m.groups())
    if dias == horas == minutos == segundos == 0:
        return None
    return int(
        dt.timedelta(days=dias, hours=horas, minutes=minutos, seconds=segundos).total_seconds()
    )


@dataclass
class Resultado:
    errores: list[str] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errores


class ValidadorEsquema:
    def __init__(self, ruta: pathlib.Path | None = None) -> None:
        self.ruta = ruta or RUTA_ESQUEMA
        if not self.ruta.exists():
            raise FileNotFoundError(f"falta el esquema en {self.ruta}")
        esquema = json.loads(self.ruta.read_text(encoding="utf-8"))
        # check_schema falla si el esquema mismo esta mal formado. Sin esto, un esquema roto
        # aceptaria cualquier cosa en silencio — el validador diria "todo bien" sin validar.
        jsonschema.Draft202012Validator.check_schema(esquema)
        self._v = jsonschema.Draft202012Validator(esquema)

    def validar(self, doc: dict) -> Resultado:
        r = Resultado()

        # ── Nivel 1: estructura ──
        for err in sorted(self._v.iter_errors(doc), key=lambda e: list(e.path)):
            donde = ".".join(str(p) for p in err.path) or "(raiz)"
            r.errores.append(f"{donde}: {err.message}")

        # ── Nivel 2: semantica que el esquema no puede expresar ──
        # Se corre aunque el nivel 1 haya fallado, para dar el diagnostico completo de una vez
        # en lugar de obligar a arreglar-reintentar-arreglar.
        freq = doc.get("queryFrequency")
        per = doc.get("queryPeriod")
        if isinstance(freq, str) and isinstance(per, str):
            sf, sp = duracion_a_segundos(freq), duracion_a_segundos(per)
            if sf is None:
                r.errores.append(f"queryFrequency: no pude interpretar la duracion '{freq}'")
            if sp is None:
                r.errores.append(f"queryPeriod: no pude interpretar la duracion '{per}'")
            if sf and sp and sp < sf:
                r.errores.append(
                    f"queryPeriod ({per}) es MENOR que queryFrequency ({freq}): la regla "
                    f"correria cada {freq} mirando solo {per}, y los eventos de la diferencia "
                    "no se evaluarian nunca. El panel se veria bien igual."
                )
            # Un periodo mucho mas largo que la frecuencia no es un error, pero duplica
            # alertas sobre los mismos eventos.
            if sf and sp and sp > sf * 24:
                r.avisos.append(
                    f"queryPeriod ({per}) es mas de 24 veces queryFrequency ({freq}): "
                    "los mismos eventos se van a evaluar muchas veces y a alertar repetido."
                )

        # El playbook declarado tiene que existir de verdad.
        pb = doc.get("playbook")
        if pb:
            destino = self.ruta.parent.parent / pb
            if not destino.exists():
                r.errores.append(f"playbook: '{pb}' no existe en el repo")

        # Una regla marcada como no ejecutada NO puede tener severidad alta sin decir por que:
        # afirmar gravedad sobre algo que nunca corrio es la clase de promesa que este repo
        # se propuso no hacer.
        estado = (doc.get("validationStatus") or {}).get("state")
        if estado == "syntax-only-not-executed" and doc.get("severity") == "High":
            if not (doc.get("validationStatus") or {}).get("notes"):
                r.avisos.append(
                    "severidad High en una regla que nunca se ejecuto: agrega "
                    "validationStatus.notes explicando en que basas esa severidad."
                )

        return r
