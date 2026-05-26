# 🛡️ Firewall con Inteligencia Artificial
### Laboratorio Práctico — Seguridad Informática Ciclo 9

![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04_LTS-E95420?logo=ubuntu)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)
![nftables](https://img.shields.io/badge/Firewall-nftables-red)
![ML](https://img.shields.io/badge/ML-RandomForest-green)
![AUC](https://img.shields.io/badge/AUC--ROC-1.000-brightgreen)
![Score](https://img.shields.io/badge/Score-100%2F100-gold)

**Integrantes:**
- Cristian Cabana Sulca
- Alessandro Pastor Mamani Mamani

**Universidad Privada — Juliaca, Puno, Perú — Mayo 2026**

---

## ¿Qué es este proyecto?

Sistema de seguridad de red que combina un firewall clásico (`nftables`) con un modelo de Machine Learning (`RandomForestClassifier`) para detectar y bloquear ataques automáticamente en menos de **20 segundos**, sin intervención humana.

### Dos capas de defensa

```
Capa 1 — nftables:   Reglas estáticas + policy drop + ia_blocklist
Capa 2 — Motor IA:   RandomForest analiza tráfico → bloquea IPs atacantes
```

---

## Topología de red real

```
Internet
    │
Router Movistar (192.168.1.1) — Askey Computer
    │
Ubuntu Server Firewall (192.168.1.43) ← este servidor
    ├── enp0s3 → WAN (192.168.1.43/24)
    ├── enp0s8 → LAN (10.0.0.1/24)
    │
Red doméstica 192.168.1.0/24
    ├── Windows 10 Admin    (192.168.1.41) — administración SSH
    ├── Kali Linux Atacante (192.168.1.50) — simulación de ataques
    ├── Samsung Galaxy      (192.168.1.33) — cliente móvil real
    └── Dispositivos IoT    (192.168.1.35/38/40) — red doméstica
```

---

## Estructura del proyecto

```
firewall-ia-lab/
│
├── nftables.conf               ← Reglas del firewall del kernel Linux
├── ai_firewall.py              ← Motor IA en tiempo real (detección automática)
├── dashboard.py                ← Dashboard web Flask con Chart.js
├── train_model.py              ← Entrenamiento y comparativa de 4 modelos ML
├── expand_dataset.py           ← Genera dataset por ventanas de tiempo (30s)
├── extract_features.py         ← Extracción básica de features desde pcap
├── extract_features_fast.py    ← Extracción optimizada con PcapReader
│
├── data/
│   ├── normal.csv              ← Features del tráfico normal (23 IPs únicas)
│   ├── attack.csv              ← Features del tráfico de ataque (Kali Linux)
│   └── dataset.csv             ← Dataset final balanceado (450 filas)
│
├── models/
│   ├── firewall_ai_model.joblib ← Modelo RandomForest entrenado y serializado
│   ├── scaler.joblib            ← Normalizador StandardScaler
│   └── label_encoder.joblib     ← Codificador de etiquetas (normal/attack)
│
└── systemd/
    └── ai-firewall.service     ← Servicio systemd para arranque automático
```

---

## ¿Cómo funciona el sistema completo?

### Flujo de detección y bloqueo

```
Red doméstica (192.168.1.0/24)
        │
        ▼
enp0s3 en modo PROMISCUO
(captura TODO el tráfico de la red)
        │
        ▼
tcpdump captura paquetes en vivo
        │
        ▼
Motor IA agrupa por IP en ventanas de 20 segundos
        │
        ▼
Extrae 13 features por IP:
  syn_ratio, unique_dports, total_pkts, potential_flood...
        │
        ▼
RandomForestClassifier predice: normal o attack
        │
   ┌────┴────┐
normal      attack (92% confianza)
   │            │
ALLOW     nft add element ia_blocklist { IP }
              │
         IP BLOQUEADA en nftables ✅
         Log en /var/log/ai_firewall.log
         Auto-desbloqueo en 1 hora
```

---

## nftables — Configuración del firewall

### Política deny-by-default

Todo el tráfico entrante es **bloqueado por defecto**. Solo lo explícitamente permitido entra:

```bash
# Ver reglas activas
sudo nft list ruleset
```

### Set dinámico ia_blocklist

El motor IA agrega IPs aquí automáticamente:

```bash
# Ver IPs bloqueadas ahora mismo
sudo nft list set inet filter ia_blocklist

# Resultado ejemplo:
# elements = { 192.168.1.50 expires 52m35s }
```

### Puertos permitidos

| Puerto | Servicio |
|--------|---------|
| 22 | SSH — administración remota |
| 80 | HTTP |
| 443 | HTTPS |
| 8080 | Dashboard web |

### Logging

Todos los paquetes bloqueados se registran:

```bash
sudo journalctl -k | grep "NFT-DROP"
```

---

## Dataset — 41 millones de paquetes reales

| Archivo | Tamaño | Paquetes | Descripción |
|---------|--------|----------|-------------|
| traffic-normal.pcap | 1.2 GB | 17,398,939 | Red doméstica real — familia usando internet |
| traffic-attack.pcap | 1.8 GB | 24,134,475 | Kali Linux — nmap + hping3 SYN flood |

### Captura con filtros por IP

```bash
# Solo tráfico normal (excluir Kali)
sudo tcpdump -i enp0s3 not src host 192.168.1.50 -w data/traffic-normal.pcap

# Solo tráfico de ataque (solo Kali)
sudo tcpdump -i enp0s3 src host 192.168.1.50 -w data/traffic-attack.pcap
```

### Pipeline de generación del dataset

```bash
# Paso 1 — Extraer features por ventanas de 30 segundos
python3 expand_dataset.py

# Resultado:
# normal: 389 filas
# attack:  61 filas
# Total:  450 filas
```

### 13 Features extraídas por ventana

| Feature | Tipo | Indicador de ataque |
|---------|------|---------------------|
| `total_pkts` | int | Alto en floods |
| `tcp_pkts` | int | Dominante en ataques TCP |
| `udp_pkts` | int | UDP amplification |
| `other_pkts` | int | ICMP y otros |
| `unique_dports_count` | int | Alto = port scan |
| `syn_ratio` | float | > 0.5 = SYN flood |
| `avg_pkt_size` | float | Bajo en SYN flood |
| `duration_sec` | float | Duración de la ventana |
| `bytes_per_sec` | float | Muy alto en floods |
| `port_scan_score` | float | unique_dports / total_pkts |
| `small_syn_score` | float | syn_ratio / avg_pkt_size × 10000 |
| `potential_flood` | bool | 1 si syn_ratio > 0.5 y pkts > 500 |
| `potential_scan` | bool | 1 si unique_dports > 100 |

### Diferencia clave entre clases

| Feature | Normal | Ataque | Ratio |
|---------|--------|--------|-------|
| syn_ratio | 0.015 | 0.737 | 49x |
| total_pkts | 44,568 | 395,076 | 9x |
| unique_dports | 9,415 | 1,117 | — |
| potential_flood | 0.146 | 0.147 | — |

---

## Modelo de IA — RandomForestClassifier

### Entrenamiento

```bash
cd ~/firewall-ia-lab
python3 train_model.py
```

- División: 70% entrenamiento / 30% prueba (estratificada)
- Semilla fija: `random_state=42` (reproducible)
- Normalización: `StandardScaler`
- Desbalanceo: `class_weight='balanced'`

### Comparativa de 4 modelos

| Modelo | Accuracy | Recall | F1 | AUC-ROC |
|--------|----------|--------|----|---------|
| **Random Forest** ⭐ | **1.000** | **1.000** | **1.000** | **1.000** |
| Gradient Boosting | 0.993 | 0.993 | 0.993 | 0.996 |
| Decision Tree | 0.993 | 0.993 | 0.993 | 0.996 |
| Logistic Regression | 0.993 | 0.993 | 0.993 | 1.000 |

### Métricas vs umbrales requeridos

| Métrica | Requerido | Obtenido |
|---------|-----------|----------|
| AUC-ROC | ≥ 0.95 | **1.000** ✅ |
| Recall (attack) | ≥ 0.90 | **1.000** ✅ |
| Precision | ≥ 0.85 | **1.000** ✅ |
| F1-Score | ≥ 0.88 | **1.000** ✅ |
| Accuracy | ≥ 0.90 | **1.000** ✅ |

### Matriz de confusión — Random Forest

```
                 Predicho Normal   Predicho Attack
Real Normal      TN = 117          FP = 0
Real Attack      FN = 0            TP = 18
```

- **FN = 0** → el modelo detectó el 100% de los ataques
- **FP = 0** → ningún tráfico legítimo fue bloqueado por error

---

## Motor IA en tiempo real — ai_firewall.py

### Fases de operación

```
Fase 1: tcpdump dual (todos los paquetes + filtro SYN)
Fase 2: Agrupación por IP en ventanas de 20 segundos
Fase 3: Extracción de 13 features por IP
Fase 4: Predicción RandomForest (normal/attack)
Fase 5: Si attack → nft add element ia_blocklist {IP}
```

### Log real de detección

```
23:46:24 [INFO]    === AI Firewall iniciado ===
23:46:24 [INFO]    Modelo cargado: RandomForestClassifier
23:46:24 [INFO]    Capturando trafico en enp0s3...
23:46:44 [INFO]    --- Ventana 20s | 312,485 pkts | 5 IPs ---
23:46:44 [INFO]    192.168.1.50 | attack 92.0% | syn=0.747 ports=128
23:46:44 [WARNING] *** ATAQUE DETECTADO: 192.168.1.50 | confianza=92.0% ***
23:46:44 [WARNING] *** BLOQUEADO: 192.168.1.50 ***
```

**Tiempo total de detección y bloqueo: 20 segundos ✅**

### Whitelist de protección

```python
WHITELIST = ['127.0.0.1', '192.168.1.43', '192.168.1.41', '10.0.0.1']
# loopback, Ubuntu Firewall, Windows Admin, LAN
```

### Servicio systemd

```bash
# Instalar y activar
sudo systemctl enable ai-firewall
sudo systemctl start ai-firewall

# Verificar
sudo systemctl status ai-firewall
# Active: active (running)
```

---

## Dashboard web en tiempo real

Accesible desde cualquier navegador en la red:

```
http://192.168.1.43:8080
```

### Secciones del dashboard

- **Métricas del sistema** — IPs bloqueadas, paquetes/seg, dropeados, estado firewall
- **Métricas del modelo IA** — AUC, Recall, F1, matriz de confusión con barras
- **Dispositivos en red** — todos los dispositivos de la red Movistar con MAC y fabricante
- **Flujos en tiempo real** — IPs activas con protocolos y actividad
- **Motor IA en vivo** — decisiones del modelo en streaming
- **Control del firewall** — bloquear/desbloquear IPs con un clic
- **Log NFT-DROP** — paquetes bloqueados por el kernel

---

## Escenarios de ataque validados

| Escenario | Herramienta | Resultado |
|-----------|-------------|-----------|
| Port scan SYN | `nmap -sS -p 1-65535` | BLOQUEADO ✅ |
| SYN flood | `hping3 --flood --syn` | BLOQUEADO ✅ |
| Ataque combinado | nmap + hping3 | BLOQUEADO ✅ |
| Tráfico HTTP normal | curl/wget | PERMITIDO ✅ |
| Ping normal | ping | PERMITIDO ✅ |
| Navegación familiar | celulares/PCs | PERMITIDO ✅ |

---

## Criterios de aceptación — 11/11 cumplidos

| ID | Criterio | Pts | Estado |
|----|----------|-----|--------|
| CA-01 ★ | nftables policy drop + ia_blocklist timeout | 15 | ✅ |
| CA-02 | Log NFT-DROP en journalctl | 10 | ✅ |
| CA-03 | dataset.csv 450 filas 13 features | 10 | ✅ |
| CA-04 | Balance clases 389 normal : 61 attack | 5 | ✅ |
| CA-05 ★ | Recall attack = 1.000 ≥ 0.90 | 15 | ✅ |
| CA-06 | AUC-ROC = 1.000 ≥ 0.95 | 10 | ✅ |
| CA-07 | Comparativa 4 modelos documentada | 5 | ✅ |
| CA-08 ★ | Bloqueo automático 20s ≤ 30s | 15 | ✅ |
| CA-09 | systemd ai-firewall active running | 5 | ✅ |
| CA-10 | 3 escenarios de ataque documentados | 5 | ✅ |
| CA-11 | Desbloqueo manual + timeout 1h | 5 | ✅ |
| **TOTAL** | | **100** | **11/11** ✅ |

★ = Criterio bloqueante (obligatorio para aprobar)

> **Calificación final: 100/100 — SOBRESALIENTE**

---

## Inicio rápido del sistema

```bash
# 1. Activar modo promiscuo
sudo ip link set enp0s3 promisc on

# 2. Verificar servicios
sudo systemctl status nftables ai-firewall

# 3. Iniciar dashboard
cd ~/firewall-ia-lab
python3 dashboard.py

# 4. Abrir en Windows
# http://192.168.1.43:8080
```

---

## Comandos de administración

```bash
# Ver reglas nftables completas
sudo nft list ruleset

# Ver IPs bloqueadas ahora
sudo nft list set inet filter ia_blocklist

# Bloquear IP manualmente
sudo nft add element inet filter ia_blocklist { 192.168.1.50 }

# Desbloquear IP (falso positivo)
sudo nft delete element inet filter ia_blocklist { 192.168.1.50 }

# Vaciar blocklist (emergencia)
sudo nft flush set inet filter ia_blocklist

# Ver log motor IA en tiempo real
sudo tail -f /var/log/ai_firewall.log

# Ver paquetes dropeados
sudo journalctl -k | grep "NFT-DROP"

# Reiniciar motor IA
sudo systemctl restart ai-firewall

# Reentrenar el modelo
python3 train_model.py
```

---

## Stack tecnológico

| Componente | Herramienta | Versión |
|------------|-------------|---------|
| Sistema Operativo | Ubuntu Server | 22.04 LTS |
| Firewall | nftables | 0.9.8+ |
| Captura | tcpdump | — |
| ML Framework | scikit-learn | — |
| Modelo | RandomForestClassifier | — |
| Análisis pcap | scapy PcapReader | — |
| Dataset | pandas + numpy | — |
| Dashboard | Flask + Chart.js | — |
| Atacante | Kali Linux | nmap, hping3 |
| Servicio | systemd | — |
| Serialización | joblib | — |

---

## Extras implementados (no requeridos)

- Dashboard web en tiempo real con Flask + Chart.js tema blanco profesional
- Escaneo automático de dispositivos en red con nmap cada 30 segundos
- Control del firewall desde el navegador con un clic
- Monitor del log del motor IA en streaming en el dashboard
- 41 millones de paquetes reales capturados de red doméstica
- Presentación HTML/CSS/JS interactiva con 9 slides
- Informe completo en LaTeX con carátula y métricas reales
- README detallado y guía de demostración para el docente

---

*Seguridad Informática — Ciclo 9 — Juliaca, Puno — Mayo 2026*
