# RustVault (SQLite + cifrado autenticado)

Proyecto CLI educativo en Rust con persistencia SQLite, Argon2id y XChaCha20-Poly1305.

## Uso

```bash
cargo run
cargo test
cargo check
```

Se crea `rustvault.db` en el **directorio de trabajo actual**. En el primer inicio se solicita definir la contraseña maestra (dos veces); en los siguientes, desbloquear con ella. La contraseña se captura sin eco mediante `rpassword`.

## Qué se cifra

Solo el campo de contraseña de cada credencial, con un nonce aleatorio nuevo y autenticación de `service` y `username` como datos asociados. El servicio, el usuario, el ID y la fecha **no están cifrados**. Los listados no descifran contraseñas. La opción 7 permite mostrar una contraseña bajo advertencia.

La clave se deriva mediante Argon2id con parámetros persistidos en `vault_config` (19 MiB, 2 iteraciones, 1 carril) y salt aleatorio de 16 bytes. Se verifica la contraseña maestra con un mensaje cifrado y autenticado. El salt, el nonce y los parámetros no son secretos; **no se guarda la contraseña maestra ni la clave**.

## IMPORTANTE: bases de datos anteriores

Las versiones anteriores usaban `password TEXT` en claro. Esta versión **rechaza** la base antigua y **no la migra ni elimina automáticamente**. Si tienes solo datos ficticios: cierra el programa, haz copia si la necesitas y elimina o renombra `rustvault.db` antes de ejecutar esta versión. Nunca borres una base de datos con datos importantes sin una copia.

## Limitaciones de seguridad

- Proyecto educativo sin auditoría; **no lo uses aún con credenciales reales**.
- La contraseña maestra no se puede recuperar si se pierde.
- Solo la contraseña está cifrada: los metadatos siguen visibles en SQLite.
- Los secretos descifrados siguen existiendo temporalmente en memoria; `zeroize` reduce exposición pero no garantiza limpieza de todas las copias.
- Al revelar una contraseña, queda visible en pantalla y podría ser capturada por otras aplicaciones.
- No hay cambio de contraseña maestra, migraciones de datos, copias de seguridad verificadas, bloqueo automático ni protección ante manipulación/eliminación de filas completas.
- Ejecuta `cargo test` y revisa dependencias; no se ha validado con una auditoría de seguridad.

## Estructura

- `main.rs`: arranque y desbloqueo.
- `security.rs`: derivación y cifrado autenticado.
- `database.rs`: SQL, configuración de la clave y repositorio.
- `vault.rs`: interfaz de operaciones del dominio.
- `credential.rs`: datos de entrada, registros recuperados y resúmenes.
- `cli.rs`, `terminal.rs`: interfaz de terminal.
- `error.rs`: errores compartidos.
