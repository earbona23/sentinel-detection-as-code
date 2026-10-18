# Detection-as-Code para Microsoft Sentinel

Librería de detecciones para Microsoft Sentinel escritas como código, con un pipeline que las
valida en cada cambio: **estructura, mapeo MITRE ATT&CK real y sintaxis KQL con el parser de
Microsoft**.

> **Status: snapshot.** Feature-complete for what it does and its tests pass; last
> substantive change September 2026. I am not adding features here, and issues are welcome
> and read. Under active maintenance instead: [revtriage](https://github.com/earbona23/revtriage),
> [entra-tripwire](https://github.com/earbona23/entra-tripwire),
> [entraform](https://github.com/earbona23/entraform) and
> [vantage](https://github.com/earbona23/vantage).

12 reglas · 73 tests · validación automática en cada PR.

---

## El problema que resuelve

En la mayoría de las organizaciones las reglas de detección se escriben a mano en el portal de
Sentinel. Eso trae cuatro problemas que solo se ven cuando ya es tarde:

**No hay historial.** Nadie sabe quién cambió el umbral de una regla, cuándo, ni por qué. Cuando
una detección deja de disparar, no hay contra qué comparar.

**No hay revisión.** Un ID de técnica MITRE inventado —`T1136.999` se ve igual de legítimo que
`T1136.001`— se despliega sin que nadie lo note, y la tabla de cobertura del informe queda
afirmando algo falso.

**No hay pruebas.** Una consulta con un error de sintaxis se guarda igual y devuelve cero
resultados. **Cero resultados se lee exactamente igual que "no hay ataques".**

**No hay contexto operativo.** Una regla sin falsos positivos documentados y sin pasos de
respuesta genera una alerta que el analista de guardia no sabe qué hacer con ella. La silencia.
Y una regla silenciada es peor que ninguna, porque **parece cobertura**.

Este repositorio trata las detecciones como código: viven en Git, se revisan en PRs, y un
pipeline las valida antes de que se puedan mergear.

---

## Qué valida el pipeline

| Frente | Cómo | Qué atrapa |
|---|---|---|
| **Estructura** | JSON Schema draft 2020-12 | Campos faltantes, tipos mal, severidades inventadas, campos con el nombre mal escrito |
| **Semántica** | Reglas propias en Python | `queryPeriod` menor que `queryFrequency`, playbooks declarados que no existen |
| **MITRE** | Catálogo ATT&CK real (858 técnicas) | Técnicas inventadas, **deprecadas** y **revocadas**; coherencia entre táctica y técnica |
| **KQL** | `Microsoft.Azure.Kusto.Language` | Errores de sintaxis reales, con línea y columna |

### Sobre la validación de KQL

Se usa **el parser de Microsoft**, la misma librería con la que Azure Data Explorer analiza las
consultas. No es una heurística con expresiones regulares.

La diferencia no es académica. Una regex aceptaría `SigninLogs | wher ResultType == 0` —tiene
forma de consulta, tiene pipes, tiene un nombre de tabla— y esa regla desplegaría devolviendo
cero resultados para siempre. El parser lo rechaza en la columna exacta.

**Límite honesto:** valida **sintaxis, no semántica**. Sin el esquema de tablas de un tenant, el
parser no puede saber si `SigninLogs` tiene una columna `ResultTye` mal escrita. Detecta que la
consulta está bien formada, no que vaya a devolver algo. Prometer más sería el mismo problema
que las regex, con mejor disfraz.

---

## Lo que este esquema exige y Sentinel no

Sentinel acepta una regla sin nada de esto. Acá son obligatorios:

- **`falsePositives`** — escenarios benignos conocidos, cada uno con **cómo distinguirlo**.
  Listarlos no alcanza: si el analista no sabe diferenciarlos, silencia la regla.
- **`responseSteps`** — mínimo dos pasos de triaje. Una alerta sin siguiente paso le delega el
  razonamiento a quien esté de guardia a las 3 de la mañana.
- **`severityJustification`** — por qué *esta* severidad y no la de al lado.
- **`validationStatus`** — si la regla corrió contra datos reales, contra datos sintéticos, o
  solo se validó su sintaxis.

Ese último campo es deliberado: **este repositorio prefiere declarar una laguna a insinuar una
prueba que no existe.**

---

## Cobertura MITRE ATT&CK

Esta tabla se genera desde las detecciones reales con `python scripts/coverage_table.py`.
No se escribe a mano: una tabla escrita a mano se desincroniza en el primer PR.

| Táctica | Técnica | Nombre en ATT&CK | Regla | Severidad | Tabla | Estado |
|---|---|---|---|---|---|---|
| InitialAccess | `T1078.004` | Cloud Accounts | Inicio de sesión exitoso tras una ráfaga de MFA denegados | High | `SigninLogs` | solo sintaxis |
| InitialAccess | `T1528` | Steal Application Access Token | Consentimiento otorgado a una aplicación OAuth sospechosa | High | `AuditLogs` | solo sintaxis |
| CredentialAccess | `T1110.003` | Password Spraying | Password spraying contra Entra ID desde una sola IP | Medium | `SigninLogs` | solo sintaxis |
| Persistence | `T1098.001` | Additional Cloud Credentials | Credencial nueva añadida a una aplicación o service principal | High | `AuditLogs` | solo sintaxis |
| PrivilegeEscalation, DefenseEvasion | `T1484.002` | Trust Modification | Dominio federado o relación de confianza nueva en el tenant | High | `AuditLogs` | solo sintaxis |
| Collection | `T1114.003` | Email Forwarding Rule | Regla de bandeja que reenvía correo fuera de la organización | Medium | `OfficeActivity` | solo sintaxis |
| PrivilegeEscalation | `T1098.003` | Additional Cloud Roles | Usuario añadido a un rol privilegiado de directorio | High | `AuditLogs` | solo sintaxis |
| PrivilegeEscalation | `T1098.003` | Additional Cloud Roles | Rol Owner o Contributor asignado a nivel de suscripción | High | `AzureActivity` | solo sintaxis |
| LateralMovement | `T1021.001` | Remote Desktop Protocol | Un mismo origen abre RDP contra muchos destinos | Medium | `SecurityEvent` | solo sintaxis |
| LateralMovement | `T1550.001` | Application Access Token | Mismo token de sesión usado desde direcciones IP distintas | High | `SigninLogs` | solo sintaxis |
| Exfiltration | `T1567` | Exfiltration Over Web Service | Descarga masiva de archivos desde SharePoint u OneDrive | Medium | `OfficeActivity` | solo sintaxis |
| Exfiltration | `T1048` | Exfiltration Over Alternative Protocol | Volumen de salida anómalo desde un recurso de Azure | Medium | `AzureActivity` | solo sintaxis |

**12 técnicas · 12 reglas · 5 tácticas.**

> **Ninguna regla se ha ejecutado todavía contra datos reales.** Están escritas y validadas
> sintácticamente. Lo dice cada archivo en su campo `validationStatus` y lo dice esta tabla,
> porque un repositorio que afirma "probado" sobre algo que nunca corrió enseña algo peor que
> una laguna de cobertura.

### Las dos reglas de escalada usan la misma técnica, a propósito

`T1098.003` aparece dos veces: una para roles de **Entra ID** y otra para roles de **Azure
Resource Manager**. Son **planos de control distintos** —directorio contra infraestructura— y
tratarlos como uno es un error frecuente. Un atacante con Global Administrator no controla
automáticamente las suscripciones, y viceversa.

---

## Arquitectura

```
detections/            reglas en YAML, una carpeta por táctica MITRE
  ├── initial-access/
  ├── persistence/
  ├── privilege-escalation/
  ├── lateral-movement/
  └── exfiltration/

schema/                el contrato: qué es una detección válida acá
validator/             schema_check · mitre_check · orquestador
tools/kql-lint/        programa .NET que usa el parser real de Kusto
data/                  snapshot de ATT&CK con el sha256 de su origen
playbooks/             respuesta automatizada, con su propia documentación
tests/                 73 tests, casi todos negativos
docs/adr/              decisiones de arquitectura y su porqué
```

**Las carpetas están organizadas por táctica y no por fuente de datos** porque la primera
pregunta que se le hace a una librería de detecciones es *"¿qué cubre?"*. La estructura la
responde antes de abrir un archivo.

### El principio que atraviesa todo: fallar cerrado

Si una validación **no se pudo ejecutar** —falta el índice MITRE, no está compilado el linter,
el YAML no se puede leer— el resultado es **fallo**, nunca "sin problemas".

Un chequeo que no corrió no es un chequeo que pasó, y confundirlos es exactamente cómo un
pipeline en verde termina certificando código que nadie miró. El CI incluso **se autoverifica**:
antes de confiar en el linter de KQL, le da una consulta rota y exige que la rechace.

---

## Cómo desplegarlo en tu propio tenant

### Requisitos

- Microsoft Sentinel sobre un workspace de Log Analytics
- Los conectores de datos que use cada regla (ver la columna *Tabla*)
- Python 3.12+ y .NET 8 para correr las validaciones en local

### Validar en local

```bash
pip install -r requirements.txt
dotnet build -c Release tools/kql-lint
python -m validator.cli          # valida todas
python -m pytest                 # tests del validador
```

### Desplegar una regla

Las reglas siguen el formato de Sentinel, así que se pueden desplegar con la API de
`Microsoft.SecurityInsights/alertRules` o con el conector de repositorios de Sentinel apuntando
a este repositorio.

**Antes de desplegar nada, calibrá los umbrales.** Los valores de este repo —10 usuarios
distintos para el spraying, 100 archivos para la descarga masiva, 5 destinos para el RDP— son
puntos de partida razonables, **no valores universales**. Una organización de 50 personas y una
de 5.000 necesitan umbrales distintos, y desplegarlos sin calibrar produce alertas que nadie
va a leer.

### Actualizar el catálogo ATT&CK

```bash
python scripts/refresh_mitre.py
```

Baja el bundle STIX oficial, lo destila a un índice de 170 KB y guarda el **sha256 del
original**, para que cualquiera pueda comprobar que el índice salió de la fuente y no de una
edición a mano.

---

## Estado y límites

**Lo que está hecho y verificado:**
12 reglas que pasan las cuatro validaciones · 73 tests, cada guard comprobado eliminándolo para
confirmar que un test muere · CI simulado de extremo a extremo · playbook desplegable.

**Lo que no:**
Ninguna regla ejecutada contra un tenant productivo · el playbook no probado de punta a punta ·
los umbrales sin calibrar contra una línea base real.

Está escrito acá y en cada archivo. La alternativa —insinuar que fue probado— haría que todo lo
demás de este repositorio dejara de ser creíble.

---

## Documentación

- [ADR 0001 — Por qué detection-as-code y no reglas en el portal](docs/adr/0001-detection-as-code.md)
- [Playbook: revocar sesiones ante fatiga de MFA](playbooks/revoke-sessions-on-mfa-fatigue/README.md)

## Licencia

MIT. Ver [LICENSE](LICENSE).

---

*Construido por Eduard Arbona con asistencia de IA. Las decisiones de arquitectura, la selección
de detecciones y los criterios de validación son propios; el código se escribió en colaboración.*
