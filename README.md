# ztftp

Transferencia de archivos y carpetas liviana por CLI entre los nodos de una red [ZeroTier One](https://www.zerotier.com/).
Un solo archivo de Python 3, sin dependencias.

```
ztftp cp master:./colportores zephy:C:/repos
```

Cada nodo corre un demonio (`ztftp serve`). Desde cualquier nodo y desde cualquier carpeta se copia de un lado a
otro indicando **nodo + ruta de origen** y **nodo + ruta de destino**. Cuando ambos son remotos, el nodo de origen
envía directo al de destino, sin pasar por la máquina donde ejecutaste el comando.

## Requisitos

- Python 3.8+ en cada nodo
- ZeroTier One instalado y unido a la red (`zerotier-cli` en el PATH para detectar la IP automáticamente)

## Instalación en Windows (un solo script)

Clonar el repo en cada nodo y, en PowerShell **como administrador**, correr `instalar.ps1`. En un solo paso:
instala el comando `ztftp`, escribe la config, abre el firewall, registra el demonio como tarea programada
(arranca con Windows, sin sesión abierta, y se reinicia si falla) y activa el Tab en PowerShell.

```powershell
# Primer nodo: genera el token y lo muestra al final
.\instalar.ps1 -Nodo master=10.147.17.5,zephy=10.147.17.8 -Root C:\repos

# Resto de los nodos: mismo token
.\instalar.ps1 -Token <token> -Nodo master=10.147.17.5,zephy=10.147.17.8 -Root C:\repos
```

| Parámetro | Descripción |
|---|---|
| `-Token` | Secreto compartido de la red. Sin él se genera uno nuevo. |
| `-Nodo` | Alias `NOMBRE=IP` de los nodos. |
| `-Root` | Directorio que expone este nodo (default: el home). |
| `-Port` | Puerto TCP (default 9777). |
| `-RemoteAddress` | Orígenes permitidos en el firewall (default: las subredes ZeroTier de este nodo). |
| `-Quitar` | Desinstala todo; conserva `~/.ztftp.json`. |

Es repetible: volver a correrlo actualiza la config y reinstala la tarea. Si las IPs de ZeroTier del nodo cambian,
volvelo a correr. Al terminar, abrí una terminal nueva. El log del demonio queda en `%USERPROFILE%\.ztftp.log`.

> La IP donde escucha el demonio se guarda en la config (`bind`) porque `zerotier-cli` solo funciona con
> permisos de administrador y la tarea corre sin elevar.

## Instalación manual (Linux/macOS u otros)

```
pip install -e .                      # comando `ztftp`
ztftp init --node master=10.147.17.5 --node zephy=10.147.17.8 --root ~/repos [--token <token>]
ztftp serve                           # abrí el puerto 9777 en tu firewall; usá systemd/launchd para dejarlo fijo
```

## Configuración (`~/.ztftp.json`)

Lo escribe `ztftp init` (que también actualiza una config existente). Todos los nodos deben compartir el `token`.

```json
{
  "token": "…",
  "port": 9777,
  "root": "C:\\repos",
  "bind": ["10.147.17.5"],
  "nodes": { "master": "10.147.17.5", "zephy": "10.147.17.8" }
}
```

- `nodes`: alias → IP de ZeroTier.
- `root` (opcional, puede ser distinto en cada nodo): directorio que expone el demonio. Por defecto, el home.
- `bind` (opcional): IPs donde escucha el demonio. Por defecto las autodetecta con `zerotier-cli`.

> El `.ztftp.json` contiene el secreto compartido: no lo subas a ningún repositorio.

## Uso

Levantar el demonio en cada nodo:

```
ztftp serve [--root DIR] [--bind IP] [--port N]
```

Escucha solo en las IPs de ZeroTier (autodetectadas) o en las de `--bind`.

Copiar y listar:

```
ztftp cp master:./colportores zephy:C:/repos     # nodo -> nodo (carpeta completa)
ztftp cp master:docs/a.pdf zephy:backup/         # un archivo
ztftp cp C:\datos\foto.jpg master:fotos/         # local -> nodo
ztftp cp zephy:backup/foto.jpg .\                # nodo -> local
ztftp ls master:.                                # listar un directorio remoto
```

- Cada lado es una ruta local o `nodo:ruta`, donde `nodo` es un alias de `nodes` o una IP.
- Las rutas remotas **relativas** (`./colportores`, `docs/a.pdf`) se resuelven desde la `root` de ese nodo; las
  absolutas (`C:/repos`) deben quedar dentro de ella.
- Si el origen es una carpeta se copia completa, con subcarpetas y carpetas vacías (como `cp -r`). Si el destino
  ya existe como carpeta, o termina en `/`, la copia queda **dentro** (`.../repos/colportores`); si no existe,
  pasa a llamarse como el destino.

## Autocompletado (Tab)

En PowerShell, `ztftp-completion.ps1` completa subcomandos, alias y **rutas remotas** consultando al nodo (como
al hacer `cd`):

```
ztftp cp master:./co<Tab>        ->  master:./colportores/
ztftp cp master:./colportores zephy:re<Tab>  ->  zephy:repos/
```

`instalar.ps1` lo agrega a tu `$PROFILE`; a mano basta con
`. "C:\ruta\al\repo\ztftp-completion.ps1"`. Los nodos tienen que tener el demonio corriendo para completar sus rutas.

## Seguridad y diseño

- ZeroTier ya cifra el tráfico entre nodos; ztftp agrega **autenticación mutua** por secreto compartido
  (desafío-respuesta HMAC-SHA256, el token nunca viaja) e **integridad** con SHA-256 por archivo.
- Cada archivo se escribe como `.ztftp-part` y se renombra solo si el hash coincide.
- Quien tenga el token puede leer y escribir **dentro de la raíz** del demonio; las rutas con `..` o enlaces
  simbólicos que escapen de la raíz se rechazan. Usá `root` para acotar lo que expone cada nodo.
- Limita el acceso de red con el firewall y con las reglas de flujo de tu red en ZeroTier Central.

## Limitaciones

Sin reanudación de transferencias cortadas, no conserva fechas ni permisos, autocompletado solo para PowerShell
y solo IPv4.
