# Playbook: revocar sesiones ante fatiga de MFA

Respuesta automatizada conectada a la detección
[`entra-mfa-fatigue-then-success`](../../detections/initial-access/entra-mfa-fatigue-then-success.yaml).

Cuando esa regla dispara, **la contraseña del usuario ya está comprometida y hubo un acceso
exitoso**. La contención urgente no es cambiar la contraseña —el atacante ya tiene una sesión
activa— sino **invalidar esa sesión**.

---

## Lo que hace, en orden

| # | Acción | Por qué |
|---|---|---|
| 1 | Toma la entidad `Account` del incidente | Si no hay cuenta, no hay nada que revocar |
| 2 | **Consulta si la cuenta tiene roles de directorio** | Guard anti-arma, ver abajo |
| 3 | Si **no** es privilegiada → revoca las sesiones | Reversible, no necesita aprobación |
| 4 | Si **sí** es privilegiada → **no actúa**, escala | Decisión humana |
| 5 | Anota el resultado en el incidente, salga bien o mal | Un playbook mudo se lee como uno que funcionó |

---

## Las cuatro decisiones que hay que poder defender

### 1. Revoca sesiones, pero NO deshabilita la cuenta

Deshabilitar automáticamente es tentador y es un error.

**Revocar es reversible**: el atacante pierde la sesión robada y el usuario legítimo simplemente
vuelve a iniciar sesión. Si la detección fue un falso positivo, el costo es un login extra.

**Deshabilitar no es reversible sin intervención**: un falso positivo deja a una persona real
sin poder trabajar hasta que alguien la habilite a mano. En una empresa sin turno nocturno, eso
puede ser toda la noche.

La regla que se sigue acá: **automatizar lo reversible, escalar lo destructivo.**

### 2. El guard anti-arma

Si la cuenta tiene roles de directorio asignados, **el playbook no actúa**.

El motivo no es prudencia genérica: es que un atacante puede **usar nuestra propia automatización
como arma**. Si sabe que existe esta regla, puede disparar deliberadamente el patrón de fatiga de
MFA contra un administrador para que el playbook le revoque las sesiones — y así **cortar la
capacidad de responder al incidente** justo cuando hace falta.

Es la misma idea que hay detrás de no permitir que un sistema de bloqueo automático se aplique a
las cuentas que lo administran.

### 3. Falla ruidosamente

Si la llamada a Graph falla, el incidente recibe un comentario que dice **"la contención NO se
hizo, hay que revocar manualmente"**.

Sin eso, el analista ve que el playbook corrió, asume que la sesión está cerrada y cierra el
incidente — mientras el atacante sigue adentro. **Un playbook que falla en silencio es peor que
no tener playbook**, porque produce una falsa sensación de contención.

Por el mismo motivo, cuando el incidente no trae una entidad `Account` utilizable el playbook
también lo anota, en vez de terminar sin hacer nada y sin decirlo.

### 4. Identidad administrada, no credenciales guardadas

El Logic App se autentica con su identidad administrada del sistema. **No hay secretos en el
repositorio ni en la configuración del playbook.**

Permiso necesario: `User.ReadWrite.All` de Microsoft Graph, como permiso de aplicación, otorgado
por un administrador. Es el mínimo que permite `revokeSignInSessions`.

---

## Despliegue

```bash
az deployment group create \
  --resource-group <tu-grupo> \
  --template-file azuredeploy.json \
  --parameters PlaybookName=revoke-sessions-on-mfa-fatigue
```

Después, **y es imprescindible**, otorgar el permiso de Graph a la identidad administrada que
creó el despliegue. Sin ese paso el playbook se despliega bien y falla en cada ejecución —
que es exactamente el escenario que cubre el paso 5.

---

## Lo que este playbook NO hace, a propósito

- **No fuerza el cambio de contraseña.** Requiere decidir si se notifica al usuario y por qué
  canal; en un compromiso activo, avisar por el canal comprometido es avisarle al atacante.
- **No bloquea la IP.** Bloquear en el borde afecta a todos los usuarios detrás de esa dirección.
- **No cierra el incidente.** La contención no es la investigación. Cerrar automáticamente haría
  que nadie revise qué hizo la sesión antes de revocarla, que es la parte que importa.

## Estado de validación

**No ejecutado contra un tenant real.** La plantilla es válida y desplegable, pero no se probó
la ejecución de extremo a extremo porque requiere un tenant con Sentinel y permisos de Graph
otorgados por un administrador.

Se dice acá por lo mismo que las detecciones declaran su `validationStatus`: afirmar que algo
funciona sin haberlo corrido es la clase de promesa que este repositorio existe para no hacer.
