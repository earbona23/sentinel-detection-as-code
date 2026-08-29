# ADR 0001 — Detection-as-code en lugar de reglas escritas en el portal

**Fecha:** 2026-08-29
**Estado:** aceptada
**Autor:** Eduard Arbona

---

## Contexto

Microsoft Sentinel permite crear reglas de análisis directamente desde el portal: se escribe la
consulta KQL en un formulario, se eligen severidad y tácticas, y se guarda. Es el camino que
sigue la mayoría de las organizaciones porque no requiere herramientas ni proceso.

Ese camino tiene cuatro consecuencias que no se ven hasta que ya pasó algo:

**No queda historial de por qué.** Sentinel registra que la regla cambió, pero no el motivo. Seis
meses después, cuando una detección deja de disparar, no hay forma de saber si alguien subió el
umbral por una razón válida o para silenciar ruido.

**Nadie revisa antes de que esté en producción.** El formulario guarda lo que le pongas. Un ID de
técnica MITRE inventado se guarda igual, y aparece en el informe de cobertura como si fuera real.

**Los errores son silenciosos.** Una consulta KQL con un error de sintaxis se guarda y devuelve
cero resultados. **Cero resultados es indistinguible de "no hay ataques"**, y ese es el modo de
fallo más peligroso de todo el dominio: el panel se ve perfecto mientras no se está detectando
nada.

**No hay lugar donde poner el contexto operativo.** El esquema de Sentinel no tiene campos para
falsos positivos conocidos ni pasos de respuesta. Ese conocimiento termina en la cabeza de quien
escribió la regla, o en un documento aparte que se desactualiza.

---

## Decisión

Las detecciones viven en Git como archivos YAML, se revisan en pull requests, y un pipeline de
CI las valida automáticamente antes de que se puedan mergear.

El esquema del repositorio es un **superconjunto** del de Sentinel: acepta todo lo que Sentinel
acepta y además **exige** falsos positivos documentados, pasos de respuesta, justificación de la
severidad y una declaración explícita de si la regla se ejecutó alguna vez.

La distinción que ordena todo:

> **El esquema de Sentinel define qué acepta la plataforma. El de este repositorio define qué
> merece llegar a un analista.**

---

## Alternativas consideradas

### A. Seguir con el portal

Cero fricción, cero herramientas. Es lo que ya hace la mayoría.

Se descarta porque no resuelve ninguno de los cuatro problemas. En particular no resuelve el
tercero, que es el que importa: **una regla rota se ve exactamente igual que una que no encontró
nada**, y nadie la revisa nunca porque no hay nada que la señale.

### B. Detection-as-code con validación por expresiones regulares

Lo mismo que se eligió, pero validando el KQL con patrones en vez de un parser.

Se descarta por una razón concreta: **no valida sintaxis, la aparenta**. Aceptaría
`SigninLogs | wher ResultType == 0` y rechazaría consultas válidas que usen algo que quien
escribió la regex no previó. Un repositorio que dice "valido KQL" mientras hace coincidencia de
texto está mintiendo en su propio README — y este repositorio se apoya justamente en ser creíble.

### C. Validar contra un cluster real de Azure Data Explorer

La más fiel de todas: valida sintaxis **y** semántica, porque conoce el esquema de las tablas.

Se descarta por dos motivos. Necesita credenciales en el CI, y un pipeline de seguridad con
credenciales de producción es una superficie de ataque nueva —cualquiera que abra un PR ejecuta
código en ese contexto—. Y ata la validación a que un servicio externo esté disponible: un CI que
falla porque Azure tuvo un mal día no está validando, está generando ruido.

**Vale reconsiderarla** el día que el repositorio se use contra un tenant productivo y la
validación semántica justifique el costo.

### D. Detection-as-code con el parser real de Microsoft *(elegida)*

Se usa `Microsoft.Azure.Kusto.Language`, la misma librería con la que Azure Data Explorer analiza
las consultas. Corre sin red, sin credenciales y sin cluster.

**El costo que asume:** una dependencia de .NET en el CI, y validación de sintaxis únicamente.

Ese límite está escrito en el código, en el README y acá. Es una decisión, no un descuido.

---

## Consecuencias

### A favor

Toda detección tiene historial, autor y motivo. Los errores que antes eran silenciosos ahora
frenan un PR. El conocimiento operativo —qué falso positivo esperar, qué hacer con la alerta—
vive **en el mismo archivo que la regla**, así que no se desactualiza por separado. Y la tabla
de cobertura MITRE se genera desde las reglas reales, así que no puede mentir.

### En contra

Hay fricción: escribir una detección ahora exige documentar falsos positivos y pasos de
respuesta. **Esa fricción es intencional** — es exactamente el trabajo que el portal permitía
saltear y que después aparece como una alerta que nadie sabe atender.

El CI depende de dos ecosistemas, Python y .NET. Y el catálogo ATT&CK es un snapshot: envejece,
y actualizarlo requiere un PR explícito. Se aceptó a cambio de que la validación sea
reproducible y funcione sin red.

### El principio que quedó

Todo el repositorio falla cerrado. Si una validación **no se pudo ejecutar**, el resultado es
fallo, nunca "sin problemas". El CI incluso se autoverifica: antes de confiar en el linter de
KQL, le da una consulta rota y exige que la rechace.

La razón es la misma que motivó todo lo demás: **un chequeo que no corrió no es un chequeo que
pasó**, y confundir las dos cosas es cómo un pipeline en verde termina certificando algo que
nadie miró.

---

## Notas

Esta decisión no aplica a las reglas gestionadas por Microsoft (las *Analytics rule templates*),
que se activan desde el portal y no se versionan acá. Este repositorio cubre las detecciones
propias.
