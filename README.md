# ztftp

Transferencia de archivos liviana por CLI entre los nodos de una red [ZeroTier One](https://www.zerotier.com/).
Un solo archivo de Python 3, sin dependencias.

```
python ztftp.py cp pc1:docs/informe.pdf pc2:backup/
```

Cada nodo corre un demonio (`ztftp serve`). Desde cualquier nodo se copia de un lado a otro indicando
**nodo + ruta de origen** y **nodo + ruta de destino**. Cuando ambos son remotos, el nodo de origen envía el
archivo directo al de destino, sin pasar por la máquina donde ejecutaste el comando.

## Requisitos

- Python 3.8+ en cada nodo
- ZeroTier One instalado y unido a la red (`zerotier-cli` en el PATH para detectar la IP automáticamente)

## Configuración

En **un** nodo:

```
python ztftp.py init
```

Crea `~/.ztftp.json` con un token aleatorio. Copiá ese archivo al home de **todos** los nodos (el token debe ser
el mismo) y completá los alias:

```json
{
  "token": "…generado por init…",
  "port": 9777,
  "nodes": { "pc1": "10.147.17.5", "pc2": "10.147.17.8" }
}
```

> El `.ztftp.json` contiene el secreto compartido: no lo subas a ningún repositorio.

## Uso

Levantar el demonio en cada nodo:

```
python ztftp.py serve [--root DIR] [--bind IP] [--port N]
```

Escucha solo en las IPs de ZeroTier (autodetectadas) o en las de `--bind`. La raíz expuesta por defecto es el
home del usuario.

Copiar y listar:

```
python ztftp.py cp pc1:docs/a.pdf pc2:backup/       # nodo -> nodo
python ztftp.py cp C:\datos\foto.jpg pc1:fotos/     # local -> nodo
python ztftp.py cp pc2:backup/foto.jpg .\           # nodo -> local
python ztftp.py ls pc1:docs                         # listar un directorio remoto
```

Cada lado es una ruta local o `nodo:ruta`, donde `nodo` es un alias de `nodes` o una IP. Si el destino termina en
`/` o ya es un directorio, se conserva el nombre del archivo.

## Windows

Ambos scripts se ejecutan en PowerShell **como administrador**.

**Firewall** — abre el puerto TCP entrante (por defecto 9777):

```powershell
.\habilitar-firewall.ps1 -RemoteAddress 10.147.17.0/24   # solo desde tu subred ZeroTier
.\habilitar-firewall.ps1 -Quitar
```

**Arranque automático** — registra `serve` como tarea programada (inicia con Windows, sin sesión abierta, y se
reinicia si falla). Log en `%USERPROFILE%\.ztftp.log`:

```powershell
.\instalar-servicio.ps1 [-Root D:\datos]
.\instalar-servicio.ps1 -Quitar
```

## Seguridad y diseño

- ZeroTier ya cifra el tráfico entre nodos; ztftp agrega **autenticación mutua** por secreto compartido
  (desafío-respuesta HMAC-SHA256, el token nunca viaja) e **integridad** con SHA-256 por archivo.
- Cada archivo se escribe como `.ztftp-part` y se renombra solo si el hash coincide.
- Quien tenga el token puede leer y escribir **dentro de la raíz** del demonio; las rutas con `..` o enlaces
  simbólicos que escapen de la raíz se rechazan. Usá `--root` para acotar lo que expone cada nodo.
- Limita el acceso de red con el firewall y con las reglas de flujo de tu red en ZeroTier Central.

## Limitaciones

Solo archivos (sin directorios recursivos), sin reanudación de transferencias cortadas y solo IPv4.
