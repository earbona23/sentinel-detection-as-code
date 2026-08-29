"""Verifica que los mapeos MITRE de una deteccion existan de verdad.

POR QUE ESTE MODULO EXISTE
Un ID de tecnica inventado es el error mas caro de un repo de detecciones, porque es invisible:
`T1136.004` se ve exactamente igual de legitimo que `T1136.001`, la regla despliega igual, y la
tabla de cobertura del README queda mintiendo. Nadie lo nota hasta que alguien la audita.

Se valida contra el indice destilado en `data/mitre-techniques.json`, generado por
`scripts/refresh_mitre.py` desde el bundle STIX oficial (con el sha256 del origen guardado,
para que cualquiera pueda comprobar que no se edito a mano).

LA DIVERGENCIA DE TAXONOMIAS — el detalle que hace falta entender
ATT&CK y Sentinel NO usan el mismo vocabulario de tacticas, y en esta version se separaron mas:
ATT&CK dividio `defense-evasion` en `stealth` y `defense-impairment`, mientras que Sentinel
sigue esperando `DefenseEvasion` en su campo `tactics`.

Por eso hay DOS validaciones distintas y no una:
  · `relevantTechniques` se valida contra ATT&CK  -> es la verdad sobre el adversario.
  · `tactics`            se valida contra Sentinel -> es el contrato de la plataforma.
Y la coherencia entre ambas es un AVISO, no un error: exigir que coincidan obligaria a elegir
una taxonomia y romper la otra.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

RUTA_INDICE = pathlib.Path(__file__).resolve().parent.parent / "data" / "mitre-techniques.json"

# Traduccion entre el vocabulario de Sentinel y el de ATT&CK.
# Se mantiene explicita —y no derivada por algoritmo— porque la divergencia NO es mecanica:
# un `DefenseEvasion` de Sentinel corresponde hoy a DOS tacticas de ATT&CK. Un `.lower()` con
# guiones daria la ilusion de que traduce y fallaria justo en el caso interesante.
SENTINEL_A_ATTACK: dict[str, tuple[str, ...]] = {
    "Reconnaissance": ("reconnaissance",),
    "ResourceDevelopment": ("resource-development",),
    "InitialAccess": ("initial-access",),
    "Execution": ("execution",),
    "Persistence": ("persistence",),
    "PrivilegeEscalation": ("privilege-escalation",),
    "DefenseEvasion": ("stealth", "defense-impairment"),
    "CredentialAccess": ("credential-access",),
    "Discovery": ("discovery",),
    "LateralMovement": ("lateral-movement",),
    "Collection": ("collection",),
    "CommandAndControl": ("command-and-control",),
    "Exfiltration": ("exfiltration",),
    "Impact": ("impact",),
}


@dataclass
class Resultado:
    errores: list[str] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errores


class IndiceMitre:
    """El catalogo ATT&CK cargado en memoria. Falla CERRADO si no se puede leer."""

    def __init__(self, ruta: pathlib.Path | None = None) -> None:
        self.ruta = ruta or RUTA_INDICE
        if not self.ruta.exists():
            # No se degrada a "no valido MITRE y sigo": eso convertiria la ausencia del indice
            # en una validacion que pasa siempre. Un chequeo que no puede correr tiene que
            # detener el pipeline, no aprobarlo.
            raise FileNotFoundError(
                f"falta el indice MITRE en {self.ruta}. "
                "Generalo con: python scripts/refresh_mitre.py"
            )
        datos = json.loads(self.ruta.read_text(encoding="utf-8"))
        self.tecnicas: dict[str, dict] = datos["techniques"]
        self.obtenido: str = datos.get("retrieved_utc", "?")
        self.sha_origen: str = datos.get("sha256_of_source", "?")
        if len(self.tecnicas) < 500:
            raise ValueError(
                f"el indice MITRE solo tiene {len(self.tecnicas)} tecnicas; parece truncado"
            )

    def validar(self, tecnicas: list[str], tacticas_sentinel: list[str]) -> Resultado:
        r = Resultado()

        for tid in tecnicas:
            info = self.tecnicas.get(tid)
            if info is None:
                # El mensaje distingue el caso mas frecuente: haber escrito una subtecnica que
                # no existe bajo una tecnica que si.
                padre = tid.split(".")[0]
                pista = ""
                if "." in tid and padre in self.tecnicas:
                    subs = sorted(k for k in self.tecnicas if k.startswith(padre + "."))
                    pista = f" (la tecnica padre {padre} existe; subtecnicas validas: {', '.join(subs)})"
                r.errores.append(f"la tecnica {tid} NO existe en ATT&CK{pista}")
                continue

            if info.get("revoked"):
                r.errores.append(
                    f"la tecnica {tid} ({info['name']}) fue REVOCADA por MITRE; "
                    "usar la que la reemplaza"
                )
            elif info.get("deprecated"):
                r.errores.append(
                    f"la tecnica {tid} ({info['name']}) esta DEPRECADA en ATT&CK"
                )

        # Coherencia entre lo declarado y lo que dice ATT&CK. AVISO, no error: ver la nota
        # sobre divergencia de taxonomias arriba.
        esperadas: set[str] = set()
        for t in tacticas_sentinel:
            esperadas.update(SENTINEL_A_ATTACK.get(t, ()))

        if esperadas:
            for tid in tecnicas:
                info = self.tecnicas.get(tid)
                if not info:
                    continue
                suyas = set(info.get("tactics", []))
                if suyas and not (suyas & esperadas):
                    r.avisos.append(
                        f"{tid} ({info['name']}) pertenece a [{', '.join(sorted(suyas))}] "
                        f"pero la regla declara [{', '.join(tacticas_sentinel)}]. "
                        "Puede ser correcto —una tecnica sirve a varias tacticas— pero conviene "
                        "revisar que la clasificacion sea la que queres defender."
                    )

        return r
