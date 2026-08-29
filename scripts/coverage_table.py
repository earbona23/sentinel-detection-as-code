#!/usr/bin/env python3
"""Genera la tabla de cobertura MITRE desde las detecciones REALES.

Escrita a mano, una tabla de cobertura se desincroniza en el primer PR y queda afirmando algo
falso — que es el peor defecto posible en un repo cuyo argumento es la honestidad.
Se regenera con: python scripts/coverage_table.py
"""
import json, pathlib, sys
import yaml

RAIZ = pathlib.Path(__file__).resolve().parent.parent
mitre = json.loads((RAIZ / "data" / "mitre-techniques.json").read_text())["techniques"]

filas = []
for f in sorted((RAIZ / "detections").rglob("*.yaml")):
    d = yaml.safe_load(f.read_text(encoding="utf-8"))
    for t in d.get("relevantTechniques", []):
        filas.append({
            "tactica": ", ".join(d.get("tactics", [])),
            "tecnica": t,
            "nombre": mitre.get(t, {}).get("name", "?"),
            "regla": d.get("name", "?"),
            "archivo": str(f.relative_to(RAIZ)),
            "severidad": d.get("severity"),
            "estado": (d.get("validationStatus") or {}).get("state", "?"),
            "tabla": ", ".join(dt for c in d.get("requiredDataConnectors", []) for dt in c.get("dataTypes", [])),
        })

ORDEN = ["InitialAccess", "Persistence", "PrivilegeEscalation", "LateralMovement", "Exfiltration"]
filas.sort(key=lambda r: (next((i for i, o in enumerate(ORDEN) if o in r["tactica"]), 99), r["tecnica"]))

print("| Táctica | Técnica | Nombre en ATT&CK | Regla | Severidad | Tabla | Estado |")
print("|---|---|---|---|---|---|---|")
for r in filas:
    est = {"tested-with-real-data": "probada", "tested-with-synthetic-data": "sintética",
           "syntax-only-not-executed": "solo sintaxis"}.get(r["estado"], r["estado"])
    print(f"| {r['tactica']} | `{r['tecnica']}` | {r['nombre']} | {r['regla']} | {r['severidad']} | `{r['tabla']}` | {est} |")
print()
print(f"**{len(filas)} técnicas cubiertas por {len(set(r['archivo'] for r in filas))} reglas.**")
