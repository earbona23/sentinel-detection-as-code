"""Fixtures compartidas.

`deteccion_valida` es una deteccion minima que PASA todo. Cada test parte de ella y rompe
UNA sola cosa. Asi, cuando un test falla, el motivo es inequivoco: lo unico que cambio fue
lo que ese test estaba probando.
"""
from __future__ import annotations

import copy

import pytest


@pytest.fixture
def deteccion_valida() -> dict:
    return {
        "id": "8f3b1c94-2d5e-4a71-9c8f-6b0e5d2a7143",
        "name": "Deteccion de prueba con nombre suficientemente largo",
        "description": (
            "Descripcion de prueba lo bastante larga como para superar el minimo que exige "
            "el esquema, porque una descripcion corta no le sirve a nadie."
        ),
        "severity": "Medium",
        "severityJustification": (
            "Medium porque es una deteccion de prueba y no representa riesgo real alguno."
        ),
        "requiredDataConnectors": [
            {"connectorId": "AzureActiveDirectory", "dataTypes": ["SigninLogs"]}
        ],
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "gt",
        "triggerThreshold": 0,
        "tactics": ["CredentialAccess"],
        "relevantTechniques": ["T1110.003"],
        "query": "SigninLogs | where ResultType != 0 | count",
        "entityMappings": [
            {
                "entityType": "IP",
                "fieldMappings": [{"identifier": "Address", "columnName": "IPAddress"}],
            }
        ],
        "falsePositives": [
            {
                "scenario": "Un proxy corporativo concentra el trafico de la oficina.",
                "howToDistinguish": "Comparar contra la linea base de esa direccion IP.",
            }
        ],
        "responseSteps": [
            "Confirmar si la direccion pertenece a un rango corporativo conocido.",
            "Revisar si hubo algun inicio de sesion exitoso desde esa direccion.",
        ],
        "validationStatus": {"state": "syntax-only-not-executed"},
        "version": "1.0.0",
        "kind": "Scheduled",
    }


@pytest.fixture
def romper():
    """Devuelve una copia de la deteccion con UNA clave cambiada o eliminada."""

    def _romper(base: dict, clave: str, valor=...) -> dict:
        d = copy.deepcopy(base)
        if valor is ...:
            d.pop(clave, None)
        else:
            d[clave] = valor
        return d

    return _romper
