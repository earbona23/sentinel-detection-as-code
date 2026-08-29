"""Tests del validador MITRE.

Lo que se prueba aca no es "sabe leer un JSON": es que RECHACE lo que tiene que rechazar.
Un ID de tecnica inventado es el error mas caro de este repo porque es invisible — `T1136.999`
se ve igual de legitimo que `T1136.001` — asi que la mayoria de estos tests son negativos.
"""
from __future__ import annotations

import json

import pytest

from validator.mitre_check import SENTINEL_A_ATTACK, IndiceMitre


@pytest.fixture(scope="module")
def m() -> IndiceMitre:
    return IndiceMitre()


# ── El indice se cargo de verdad ───────────────────────────────────────────
def test_el_indice_tiene_el_catalogo_completo(m):
    assert len(m.tecnicas) > 500, "un indice truncado rechazaria tecnicas validas"


def test_el_indice_registra_su_procedencia(m):
    # Sin el sha del origen, "verificado contra MITRE" es una afirmacion sin respaldo.
    assert m.sha_origen and m.sha_origen != "?"
    assert m.obtenido and m.obtenido != "?"


# ── Lo valido pasa ─────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "tecnica,tactica",
    [
        ("T1110.003", "CredentialAccess"),
        ("T1078.004", "InitialAccess"),
        ("T1098.001", "Persistence"),
        ("T1021.001", "LateralMovement"),
        ("T1048", "Exfiltration"),
    ],
)
def test_las_tecnicas_que_usamos_existen(m, tecnica, tactica):
    assert m.validar([tecnica], [tactica]).ok


# ── Lo inventado se rechaza ────────────────────────────────────────────────
@pytest.mark.parametrize("inventada", ["T9999", "T0000", "T1110.999", "T1136.999"])
def test_una_tecnica_inventada_se_rechaza(m, inventada):
    r = m.validar([inventada], ["Persistence"])
    assert not r.ok, f"{inventada} no existe y deberia rechazarse"
    assert any("NO existe" in e for e in r.errores)


def test_una_subtecnica_inventada_sugiere_las_validas(m):
    # El error mas frecuente: inventar una subtecnica bajo una tecnica que SI existe.
    # Decir solo "esta mal" obliga a ir a buscar; decir cuales valen resuelve el problema.
    r = m.validar(["T1136.999"], ["Persistence"])
    assert not r.ok
    mensaje = " ".join(r.errores)
    assert "T1136" in mensaje and "subtecnicas validas" in mensaje
    assert "T1136.001" in mensaje


# ── Existe pero no se puede usar ───────────────────────────────────────────
def test_una_tecnica_revocada_se_rechaza(m):
    revocadas = [t for t, v in m.tecnicas.items() if v.get("revoked")]
    assert revocadas, "el indice deberia conservar las revocadas para poder rechazarlas"
    r = m.validar([revocadas[0]], ["Impact"])
    assert not r.ok, "una tecnica revocada existe en el archivo pero no debe usarse"
    assert any("REVOCADA" in e for e in r.errores)


def test_una_tecnica_deprecada_se_rechaza(m):
    deprecadas = [
        t for t, v in m.tecnicas.items() if v.get("deprecated") and not v.get("revoked")
    ]
    if not deprecadas:
        pytest.skip("esta version de ATT&CK no trae tecnicas deprecadas sin revocar")
    r = m.validar([deprecadas[0]], ["Impact"])
    assert not r.ok
    assert any("DEPRECADA" in e for e in r.errores)


# ── Coherencia entre taxonomias ────────────────────────────────────────────
def test_una_tactica_incoherente_avisa_pero_no_falla(m):
    # T1486 es Impact. Declararla como InitialAccess es raro, pero no imposible:
    # una tecnica puede servir a varias tacticas segun el contexto del ataque.
    r = m.validar(["T1486"], ["InitialAccess"])
    assert r.ok, "no debe bloquear: la clasificacion es criterio del autor"
    assert r.avisos, "pero tiene que obligar a defenderla"


def test_la_tabla_de_traduccion_cubre_todo_el_vocabulario_de_sentinel():
    # Si el esquema acepta una tactica que la tabla no traduce, la coherencia se dejaria de
    # chequear para esa tactica EN SILENCIO — el aviso simplemente no saldria nunca.
    esquema = json.loads(
        (IndiceMitre().ruta.parent.parent / "schema" / "detection.schema.json").read_text(
            encoding="utf-8"
        )
    )
    del_esquema = set(esquema["properties"]["tactics"]["items"]["enum"])
    de_la_tabla = set(SENTINEL_A_ATTACK)
    assert del_esquema == de_la_tabla, (
        f"desincronizadas. Solo en el esquema: {del_esquema - de_la_tabla}. "
        f"Solo en la tabla: {de_la_tabla - del_esquema}"
    )


def test_defense_evasion_mapea_a_las_dos_tacticas_de_attack():
    # ATT&CK partio defense-evasion en stealth y defense-impairment; Sentinel sigue con
    # DefenseEvasion. Si alguien "simplifica" esta entrada a una sola, se rompe el chequeo.
    assert set(SENTINEL_A_ATTACK["DefenseEvasion"]) == {"stealth", "defense-impairment"}


def test_las_tacticas_de_la_tabla_existen_en_attack(m):
    reales = {t for v in m.tecnicas.values() for t in v.get("tactics", [])}
    for sentinel, attack in SENTINEL_A_ATTACK.items():
        for a in attack:
            assert a in reales, f"'{a}' (mapeado desde {sentinel}) no existe en ATT&CK"


# ── Fallar cerrado ─────────────────────────────────────────────────────────
def test_sin_indice_no_valida_en_silencio(tmp_path):
    with pytest.raises(FileNotFoundError):
        IndiceMitre(tmp_path / "no-existe.json")


def test_un_indice_truncado_se_rechaza(tmp_path):
    falso = tmp_path / "chico.json"
    falso.write_text(json.dumps({"techniques": {"T1110": {"name": "x"}}}), encoding="utf-8")
    with pytest.raises(ValueError, match="truncado"):
        IndiceMitre(falso)
