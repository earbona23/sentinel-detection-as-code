"""Tests del validador de esquema.

REGLA DE ESTE ARCHIVO: cada test rompe UNA cosa y comprueba que el validador la CAZA.
Un test que solo verifica que lo valido pasa no prueba nada — pasaria igual con el validador
desconectado. Por eso la mayoria son casos negativos.
"""
from __future__ import annotations

import pytest

from validator.schema_check import ValidadorEsquema, duracion_a_segundos


@pytest.fixture(scope="module")
def v() -> ValidadorEsquema:
    return ValidadorEsquema()


# ── Lo valido pasa (un solo test: es la premisa, no la prueba) ──────────────
def test_una_deteccion_valida_pasa(v, deteccion_valida):
    r = v.validar(deteccion_valida)
    assert r.ok, f"la deteccion valida fue rechazada: {r.errores}"


# ── Campos obligatorios ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "campo",
    [
        "id", "name", "description", "severity", "severityJustification",
        "requiredDataConnectors", "queryFrequency", "queryPeriod",
        "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
        "query", "entityMappings", "falsePositives", "responseSteps",
        "validationStatus", "version", "kind",
    ],
)
def test_falta_un_campo_obligatorio(v, deteccion_valida, romper, campo):
    r = v.validar(romper(deteccion_valida, campo))
    assert not r.ok, f"quitar '{campo}' deberia fallar y no fallo"


# ── Los cuatro campos que NO son de Sentinel ───────────────────────────────
# Van aparte a proposito: son la decision de diseno de este repo, y un refactor que los
# volviera opcionales tiene que romper un test con nombre explicito.
def test_una_deteccion_sin_falsos_positivos_se_rechaza(v, deteccion_valida, romper):
    r = v.validar(romper(deteccion_valida, "falsePositives", []))
    assert not r.ok, "una regla sin falsos positivos documentados no deberia entrar al repo"


def test_una_deteccion_sin_pasos_de_respuesta_se_rechaza(v, deteccion_valida, romper):
    r = v.validar(romper(deteccion_valida, "responseSteps", ["uno solo no alcanza"]))
    assert not r.ok, "se exigen al menos dos pasos de respuesta"


def test_severidad_sin_justificar_se_rechaza(v, deteccion_valida, romper):
    r = v.validar(romper(deteccion_valida, "severityJustification", "porque si"))
    assert not r.ok, "una justificacion trivial no deberia alcanzar el minimo"


def test_estado_de_validacion_inventado_se_rechaza(v, deteccion_valida, romper):
    r = v.validar(romper(deteccion_valida, "validationStatus", {"state": "probadisimo"}))
    assert not r.ok, "solo se aceptan los tres estados declarados"


# ── Formatos ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("malo", ["no-es-un-guid", "8f3b1c94", "", "8f3b1c94-2d5e-4a71-9c8f"])
def test_un_id_que_no_es_guid_se_rechaza(v, deteccion_valida, romper, malo):
    assert not v.validar(romper(deteccion_valida, "id", malo)).ok


@pytest.mark.parametrize("malo", ["Critica", "high", "MEDIUM", ""])
def test_una_severidad_fuera_del_enum_se_rechaza(v, deteccion_valida, romper, malo):
    assert not v.validar(romper(deteccion_valida, "severity", malo)).ok


def test_una_tactica_inventada_se_rechaza(v, deteccion_valida, romper):
    assert not v.validar(romper(deteccion_valida, "tactics", ["MovimientoLateral"])).ok


def test_un_id_de_tecnica_con_formato_invalido_se_rechaza(v, deteccion_valida, romper):
    assert not v.validar(romper(deteccion_valida, "relevantTechniques", ["1110.003"])).ok


def test_un_campo_de_mas_se_rechaza(v, deteccion_valida, romper):
    # additionalProperties:false. Un campo con el nombre mal escrito se ignoraria en silencio
    # si no se rechazara, y la regla desplegaria sin el.
    assert not v.validar(romper(deteccion_valida, "severidad", "High")).ok


# ── La regla semantica que JSON Schema no puede expresar ───────────────────
def test_periodo_menor_que_frecuencia_se_rechaza(v, deteccion_valida):
    d = dict(deteccion_valida, queryFrequency="PT1H", queryPeriod="PT30M")
    r = v.validar(d)
    assert not r.ok
    assert any("no se evaluarian nunca" in e for e in r.errores), (
        "el error tiene que explicar la CONSECUENCIA, no solo decir que el valor esta mal"
    )


def test_periodo_igual_a_frecuencia_es_valido(v, deteccion_valida):
    assert v.validar(dict(deteccion_valida, queryFrequency="PT1H", queryPeriod="PT1H")).ok


def test_periodo_mucho_mayor_avisa_pero_no_falla(v, deteccion_valida):
    r = v.validar(dict(deteccion_valida, queryFrequency="PT1H", queryPeriod="P7D"))
    assert r.ok, "un periodo largo es subóptimo, no invalido"
    assert r.avisos, "pero tiene que avisar, porque duplica alertas"


def test_playbook_que_no_existe_se_rechaza(v, deteccion_valida):
    r = v.validar(dict(deteccion_valida, playbook="playbooks/no-existe/README.md"))
    assert not r.ok, "declarar un playbook inexistente es una promesa sin respaldo"


def test_severidad_alta_sin_ejecutar_y_sin_notas_avisa(v, deteccion_valida):
    d = dict(
        deteccion_valida,
        severity="High",
        validationStatus={"state": "syntax-only-not-executed"},
    )
    r = v.validar(d)
    assert r.avisos, "afirmar gravedad alta sobre algo que nunca corrio merece al menos un aviso"


# ── El parser de duraciones ────────────────────────────────────────────────
@pytest.mark.parametrize(
    "texto,segundos",
    [("PT1H", 3600), ("PT30M", 1800), ("P1D", 86400), ("PT2H30M", 9000), ("PT45S", 45)],
)
def test_duraciones_validas(texto, segundos):
    assert duracion_a_segundos(texto) == segundos


@pytest.mark.parametrize("texto", ["", "1H", "P", "PT", "PT1X", "hora", "P1Y"])
def test_duraciones_invalidas_devuelven_none(texto):
    # P1Y (un anio) se rechaza a proposito: no tiene duracion fija y compararlo exigiria
    # inventar una convencion.
    assert duracion_a_segundos(texto) is None


# ── Fallar cerrado ─────────────────────────────────────────────────────────
def test_sin_esquema_no_valida_en_silencio(tmp_path):
    with pytest.raises(FileNotFoundError):
        ValidadorEsquema(tmp_path / "no-existe.json")
