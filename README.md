# Automatización de Políticas de Seguridad con API REST y ACLs (Cisco IOS)

**Instituto Politécnico Nacional (IPN) — ESCOM**

**Materia:** Redes de Computadoras / Administración de Servicios en Red

**Alumno:** Juan Carlos Negrete Pérez

**Entorno:** GNS3 (Cisco c7200, VPCS, Ubuntu Linux) | Python 3, Flask, Paramiko, OSPFv2

## 1. De qué trata la práctica

En esta práctica armamos una red en GNS3 con routers Cisco c7200 y nodos VPCS, y levantamos una API REST en Python (usando Flask y Paramiko) desde Ubuntu para automatizar las reglas de seguridad sin tener que entrar router por router.

La idea es poder activar, cambiar o quitar tres escenarios distintos de ACLs (estándar, extendida numerada y extendida nombrada) mediante peticiones HTTP (`POST` y `DELETE`), asegurando que nunca queden dos escenarios encimados al mismo tiempo (exclusión mutua).

## 2. Topología y Direccionamiento IP

### Equipos de la red

| Dispositivo | Tipo | Función en la topología | 
| ----- | ----- | ----- | 
| **`Edge`** | Cisco c7200 | Router de frontera. Conecta la red interna (OSPF) con el proveedor externo (`ISP`). | 
| **`TOR-1`** | Cisco c7200 | Router de acceso para la red de usuarios (`192.168.10.0/24`). | 
| **`Tor-2`** | Cisco c7200 | Router de acceso que protege la red de servidores y administración (`192.168.20.0/24`). | 
| **`ISP`** | Cisco c7200 | Router externo que simula Internet con rutas estáticas hacia nuestra red. | 
| **`PCUsuarios`** | VPCS | Equipo de usuario final (`192.168.10.10/24`). | 
| **`PCServInt`** | VPCS | Servidor interno de aplicaciones (`192.168.20.20/24`). | 
| **`HostExterno`** | VPCS | Equipo externo hostil (`200.20.30.10/24`). | 
| **`API-Rest`** | Ubuntu Linux | Nodo `SistemasDistribuidos-1` (`192.168.20.10/24`). Corre la API REST (`:5000`), el servidor HTTP de prueba (`:80`) y los comandos `curl`/SSH. | 

### Direccionamiento IP

| Segmento | Subred | Interfaces y Hosts | 
| ----- | ----- | ----- | 
| **Red de Usuarios** | `192.168.10.0/24` | `TOR-1 f0/0`: `192.168.10.1` \| `PCUsuarios`: `192.168.10.10` | 
| **Servidores y Admin** | `192.168.20.0/24` | `Tor-2 f1/1`: `192.168.20.1` \| `API-Rest`: `192.168.20.10` \| `PCServInt`: `192.168.20.20` | 
| **Enlaces Internos** | `10.0.0.0/24` (`/30`) | `Edge-TOR1`: `10.0.0.1` - `10.0.0.2` \| `Edge-Tor2`: `10.0.0.5` - `10.0.0.6` | 
| **Loopbacks Admin** | `10.0.1.0/24` (`/32`) | `TOR-1 Lo0`: `10.0.1.1` \| `Tor-2 Lo0`: `10.0.1.2` \| `Edge Lo0`: `10.0.1.3` | 
| **Enlace Edge - ISP** | `200.20.20.0/30` | `Edge f0/0`: `200.20.20.1` - `ISP f0/0`: `200.20.20.2` | 
| **Red Externa** | `200.20.30.0/24` | `ISP f1/0`: `200.20.30.1` \| `HostExterno`: `200.20.30.10` | 

## 3. Los 3 Escenarios (Configuración ACL: Activar y Desactivar)

### Escenario 1: Protección del plano de administración

* **Tipo y ubicación:** ACL estándar numerada (`access-list 10`) en `line vty 0 4` (`access-class 10 in`) en **`Edge`**, **`TOR-1`** y **`Tor-2`**.
* **Qué hace:** Deja entrar por SSH únicamente a los equipos autorizados (`192.168.20.10`, `192.168.20.25` y `200.20.30.10`) y rechaza los intentos desde `PCUsuarios` (`192.168.10.10`).

```cisco
! --- ACTIVAR ESCENARIO 1 (Edge, TOR-1 y Tor-2) ---
configure terminal
access-list 10 permit host 192.168.20.10
access-list 10 permit host 192.168.20.25
access-list 10 permit host 200.20.30.10
access-list 10 deny any
line vty 0 4
 access-class 10 in
exit
end

! --- DESACTIVAR ESCENARIO 1 ---
configure terminal
line vty 0 4
 no access-class 10 in
exit
no access-list 10
end
```

### Escenario 2: Contención de un equipo externo hostil

* **Tipo y ubicación:** ACL extendida numerada (`access-list 100`) en **`Edge`**, interfaz **`FastEthernet0/0` (`in`)**.
* **Por qué ACL extendida y por qué en `Edge f0/0 in`:** Usamos una ACL extendida porque necesitamos filtrar por puerto (`eq 22`) y protocolo, algo que una estándar no permite. Se coloca en la entrada de `Edge f0/0` (lo más cerca posible del origen hostil) para tirar el tráfico malicioso desde la frontera antes de que consuma ancho de banda en los enlaces internos.

```cisco
! --- ACTIVAR ESCENARIO 2 (Edge) ---
configure terminal
access-list 100 permit tcp any any established
access-list 100 permit icmp any any echo-reply
access-list 100 deny tcp host 200.20.30.10 any eq 22
access-list 100 deny ip host 200.20.30.10 192.168.20.0 0.0.0.255
access-list 100 deny ip host 200.20.30.10 10.0.1.0 0.0.0.255
access-list 100 permit ip host 200.20.30.10 192.168.10.0 0.0.0.255
access-list 100 permit ip any any
interface FastEthernet0/0
 ip access-group 100 in
exit
end

! --- DESACTIVAR ESCENARIO 2 ---
configure terminal
interface FastEthernet0/0
 no ip access-group 100 in
exit
no access-list 100
end
```

### Escenario 3: Contención de movimiento lateral dentro de la red

* **Tipo y ubicación:** ACL extendida nombrada (`USERS_TO_SERVERS`) en **`TOR-1`**, interfaz **`FastEthernet0/0` (`in`)**.
* **Qué hace:** Filtra el tráfico de los usuarios (`192.168.10.0/24`) desde el primer salto, permitiendo solo HTTP (`TCP/80`) hacia `PCServInt` (`192.168.20.20`) y bloqueando SSH o HTTP hacia `API-Rest` (`192.168.20.10`) y las loopbacks administrativas.

```cisco
! --- ACTIVAR ESCENARIO 3 (TOR-1) ---
configure terminal
ip access-list extended USERS_TO_SERVERS
 permit tcp 192.168.10.0 0.0.0.255 host 192.168.20.20 eq 80
 deny tcp 192.168.10.0 0.0.0.255 host 192.168.20.10 eq 22
 deny tcp 192.168.10.0 0.0.0.255 host 192.168.20.10 eq 80
 deny ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255
 deny ip 192.168.10.0 0.0.0.255 10.0.1.0 0.0.0.255
 permit ip any any
exit
interface FastEthernet0/0
 ip access-group USERS_TO_SERVERS in
exit
end

! --- DESACTIVAR ESCENARIO 3 ---
configure terminal
interface FastEthernet0/0
 no ip access-group USERS_TO_SERVERS in
exit
no ip access-list extended USERS_TO_SERVERS
end
```

## 4. Código Pertinente de la API REST (`app.py`)

Aquí se muestran únicamente las estructuras donde definimos los comandos para activar (`apply`) y desactivar (`remove`) cada escenario, junto con los endpoints `POST` y `DELETE` encargados de aplicar las políticas y mantener la exclusión mutua.

### Definición de comandos por escenario (`CONFIG_ESCENARIOS`)

```python
CONFIG_ESCENARIOS = {
    1: {
        "apply": {
            "Edge": [
                "access-list 10 permit host 192.168.20.10",
                "access-list 10 permit host 192.168.20.25",
                "access-list 10 permit host 200.20.30.10",
                "access-list 10 deny any",
                "line vty 0 4",
                "access-class 10 in",
                "exit"
            ],
            "TOR-1": [
                "access-list 10 permit host 192.168.20.10",
                "access-list 10 permit host 192.168.20.25",
                "access-list 10 permit host 200.20.30.10",
                "access-list 10 deny any",
                "line vty 0 4",
                "access-class 10 in",
                "exit"
            ],
            "TOR-2": [
                "access-list 10 permit host 192.168.20.10",
                "access-list 10 permit host 192.168.20.25",
                "access-list 10 permit host 200.20.30.10",
                "access-list 10 deny any",
                "line vty 0 4",
                "access-class 10 in",
                "exit"
            ]
        },
        "remove": {
            "Edge": ["line vty 0 4", "no access-class 10 in", "exit", "no access-list 10"],
            "TOR-1": ["line vty 0 4", "no access-class 10 in", "exit", "no access-list 10"],
            "TOR-2": ["line vty 0 4", "no access-class 10 in", "exit", "no access-list 10"],
        }
    },
    2: {
        "apply": {
            "Edge": [
                "access-list 100 permit tcp any any established",
                "access-list 100 permit icmp any any echo-reply",
                "access-list 100 deny tcp host 200.20.30.10 any eq 22",
                "access-list 100 deny ip host 200.20.30.10 192.168.20.0 0.0.0.255",
                "access-list 100 deny ip host 200.20.30.10 10.0.1.0 0.0.0.255",
                "access-list 100 permit ip host 200.20.30.10 192.168.10.0 0.0.0.255",
                "access-list 100 permit ip any any",
                "interface FastEthernet0/0",
                "ip access-group 100 in",
                "exit"
            ]
        },
        "remove": {
            "Edge": ["interface FastEthernet0/0", "no ip access-group 100 in", "exit", "no access-list 100"]
        }
    },
    3: {
        "apply": {
            "TOR-1": [
                "ip access-list extended USERS_TO_SERVERS",
                "permit tcp 192.168.10.0 0.0.0.255 host 192.168.20.20 eq 80",
                "deny tcp 192.168.10.0 0.0.0.255 host 192.168.20.10 eq 22",
                "deny tcp 192.168.10.0 0.0.0.255 host 192.168.20.10 eq 80",
                "deny ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255",
                "deny ip 192.168.10.0 0.0.0.255 10.0.1.0 0.0.0.255",
                "permit ip any any",
                "exit",
                "interface FastEthernet0/0",
                "ip access-group USERS_TO_SERVERS in",
                "exit"
            ]
        },
        "remove": {
            "TOR-1": ["interface FastEthernet0/0", "no ip access-group USERS_TO_SERVERS in", "exit", "no ip access-list extended USERS_TO_SERVERS"]
        }
    }
}
```

### Rutas para activar (`POST`), desactivar (`DELETE`) y limpiar (`0`)

```python
@app.route("/api/v1/escenarios/<escenario_id>", methods=["POST"])
def activar_escenario(escenario_id):
    if not escenario_id.isdigit() or int(escenario_id) not in ESCENARIOS_INFO:
        return jsonify({"status": "error", "message": f"Escenario '{escenario_id}' inválido."}), 400

    target_id = int(escenario_id)
    body = request.get_json(silent=True) or {}
    reason = body.get("reason", "Activación solicitada vía API REST")

    with api_lock:
        previo_id = None
        try:
            # 1. Revisamos si hay algún escenario activo y lo retiramos primero
            _, detectados = inspeccionar_routers()
            if len(detectados) == 1:
                previo_id = detectados[0]

            for sc in detectados:
                retirar_escenario_interno(sc)

            # 2. Aplicamos el escenario nuevo y verificamos en los routers
            aplicar_escenario_interno(target_id)
            ok, msg = verificar_escenario(target_id)
            if not ok:
                raise RuntimeError(msg)

            guardar_estado(target_id, f"Activado escenario {target_id}. Motivo: {reason}")
            return jsonify({
                "active_scenario": target_id,
                "status": "active",
                "message": f"Escenario {target_id} aplicado y verificado"
            }), 200

        except Exception as e:
            # Si falla a medias, hacemos rollback al escenario previo
            retirar_escenario_interno(target_id)
            if previo_id is not None:
                aplicar_escenario_interno(previo_id)
            return jsonify({
                "active_scenario": previo_id,
                "status": "rollback_completed",
                "message": f"Fallo al aplicar escenario {target_id}: {str(e)}. Se restauró el estado previo."
            }), 502


@app.route("/api/v1/escenarios/<escenario_id>", methods=["DELETE"])
def desactivar_escenario(escenario_id):
    if not escenario_id.isdigit() or int(escenario_id) not in ESCENARIOS_INFO:
        return jsonify({"status": "error", "message": f"Escenario '{escenario_id}' inválido."}), 400

    target_id = int(escenario_id)

    with api_lock:
        _, detectados = inspeccionar_routers()
        if target_id not in detectados:
            activo_actual = detectados[0] if len(detectados) == 1 else None
            return jsonify({
                "active_scenario": activo_actual,
                "status": "unchanged",
                "message": f"El escenario {target_id} no está activo; no se modificó la red"
            }), 200

        retirar_escenario_interno(target_id)
        ok, msg = verificar_escenario(None)
        if not ok:
            return jsonify({"status": "partial_error", "message": msg}), 500

        guardar_estado(None, f"Desactivado escenario {target_id} vía DELETE")
        return jsonify({
            "active_scenario": None,
            "status": "inactive",
            "message": f"Escenario {target_id} retirado"
        }), 200


@app.route("/api/v1/escenarios/0", methods=["POST", "DELETE"])
def desactivar_todos():
    with api_lock:
        _, detectados = inspeccionar_routers()
        for sc in detectados:
            retirar_escenario_interno(sc)

        ok, msg = verificar_escenario(None)
        if not ok:
            return jsonify({"status": "partial_error", "message": msg}), 500

        guardar_estado(None, "Desactivación global mediante escenario 0")
        return jsonify({
            "active_scenario": None,
            "status": "inactive",
            "message": "Todos los escenarios fueron desactivados; política base restaurada"
        }), 200
```

## 5. Comandos para Activar, Desactivar y Probar en Vivo

### Arrancar la API en Ubuntu (Terminal 1)

```bash
sudo python3 -m http.server 80 > /dev/null 2>&1 &
cd ~/Desktop/ACL && python3 app.py


sudo -v
sudo python3 -m http.server 80 > /dev/null 2>&1 &
cd ~/Desktop/ACL
python3 app.py
```

### Consultar escenarios y estado actual (Terminal 2)

```bash
curl -s http://192.168.20.10:5000/api/v1/escenarios | python3 -m json.tool
curl -s http://192.168.20.10:5000/api/v1/escenarios/estado | python3 -m json.tool
```

### Activar y desactivar Escenario 1

```bash
# Activar
curl -s -X POST http://192.168.20.10:5000/api/v1/escenarios/1 -H "Content-Type: application/json" -d '{"reason":"Prueba escenario 1"}' | python3 -m json.tool

# Desactivar
curl -s -X DELETE http://192.168.20.10:5000/api/v1/escenarios/1 | python3 -m json.tool
```

### Cambiar entre escenarios (Exclusión mutua: 1 -> 2 -> 3)

```bash
# Activar 1 y pasar directo al 2 (retira ACL 10 de todos y pone ACL 100 en Edge)
curl -s -X POST http://192.168.20.10:5000/api/v1/escenarios/1 | python3 -m json.tool
curl -s -X POST http://192.168.20.10:5000/api/v1/escenarios/2 | python3 -m json.tool
curl -s http://192.168.20.10:5000/api/v1/escenarios/estado | python3 -m json.tool

# Pasar directo del 2 al 3 (limpia Edge y pone USERS_TO_SERVERS en TOR-1)
curl -s -X POST http://192.168.20.10:5000/api/v1/escenarios/3 | python3 -m json.tool
curl -s http://192.168.20.10:5000/api/v1/escenarios/estado | python3 -m json.tool
```

### Pruebas de validación y limpieza global (Escenario 0)

```bash
# DELETE sobre un escenario que no está activo (responde status: "unchanged")
curl -s -X DELETE http://192.168.20.10:5000/api/v1/escenarios/1 | python3 -m json.tool

# POST repetido sobre el escenario ya activo
curl -s -X POST http://192.168.20.10:5000/api/v1/escenarios/3 | python3 -m json.tool

# Desactivar todo y volver a la política base
curl -s -X POST http://192.168.20.10:5000/api/v1/escenarios/0 | python3 -m json.tool
```

### Pruebas rápidas desde las consolas VPCS

Como los nodos VPCS en GNS3 no traen instalados clientes `ssh` ni `curl`, usamos los parámetros extra del comando `ping` de VPCS para simular tráfico TCP hacia puertos específicos:

* **`-P 6`**: Cambia el protocolo del paquete de ICMP (por defecto) a **TCP** (número de protocolo IP `6`), que es lo que filtran nuestras ACLs para SSH y HTTP.
* **`-p 22` / `-p 80`**: Indica el **puerto destino** al que intenta conectarse (`22` para simular una sesión SSH y `80` para simular una petición web HTTP).
* **`-c 3`**: Limita el envío a **3 paquetes** en lugar de los 5 por defecto, para que las pruebas en vivo sean más rápidas (este último es opcional).

```text
# Durante Escenario 1:
PCUsuarios>  ping 10.0.1.2 -P 6 -p 22 -c 3   # Denegado (RST)
HostExterno> ping 10.0.1.2 -P 6 -p 22 -c 3   # Permitido

# Durante Escenario 2:
HostExterno> ping 10.0.1.2 -P 6 -p 22 -c 3       # Denegado
HostExterno> ping 192.168.20.10 -c 3             # Denegado (ICMP normal)
HostExterno> ping 192.168.10.10 -c 3             # Permitido (ICMP normal)

# Durante Escenario 3:
PCUsuarios> ping 192.168.20.20 -P 6 -p 80 -c 3   # Permitido (HTTP a PCServInt)
PCUsuarios> ping 192.168.20.10 -P 6 -p 80 -c 3   # Denegado (HTTP a API-Rest)
PCUsuarios> ping 192.168.20.10 -P 6 -p 22 -c 3   # Denegado (SSH a API-Rest)
```
