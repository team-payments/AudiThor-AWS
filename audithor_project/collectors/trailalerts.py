# collectors/trailalerts.py
import json
import yaml
import requests
import os
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import pytz
from botocore.exceptions import ClientError

# Configuración de paths
SIGMA_RULES_DIR = "sigma_rules"
PARSED_RULES_FILE = os.path.join(SIGMA_RULES_DIR, "parsed_rules.json")
METADATA_FILE = os.path.join(SIGMA_RULES_DIR, "metadata.json")

# URL del repositorio TrailAlerts
TRAILALERTS_REPO_URL = "https://api.github.com/repos/adanalvarez/TrailAlerts/contents/rules/sigma_rules"
TRAILALERTS_RAW_URL = "https://raw.githubusercontent.com/adanalvarez/TrailAlerts/main/rules/sigma_rules"

def ensure_sigma_rules_directory():
    """Crea el directorio sigma_rules si no existe."""
    if not os.path.exists(SIGMA_RULES_DIR):
        os.makedirs(SIGMA_RULES_DIR)

def download_sigma_rules_from_github():
    """
    Descarga las reglas Sigma desde el repositorio TrailAlerts de GitHub.
    
    Returns:
        dict: Resultado de la operación con status y mensaje
    """
    try:
        ensure_sigma_rules_directory()
        
        # Obtener la lista de archivos del repositorio
        response = requests.get(TRAILALERTS_REPO_URL, timeout=30)
        response.raise_for_status()
        
        files_data = response.json()
        downloaded_rules = []
        
        for file_info in files_data:
            if file_info['name'].endswith('.yml') or file_info['name'].endswith('.yaml'):
                # Descargar el contenido del archivo
                file_url = f"{TRAILALERTS_RAW_URL}/{file_info['name']}"
                file_response = requests.get(file_url, timeout=30)
                file_response.raise_for_status()
                
                try:
                    # Parsear el YAML
                    rule_content = yaml.safe_load(file_response.text)
                    if rule_content:  # Verificar que no esté vacío
                        rule_content['_filename'] = file_info['name']
                        downloaded_rules.append(rule_content)
                except yaml.YAMLError as e:
                    print(f"Error parsing YAML file {file_info['name']}: {e}")
                    continue
        
        # Guardar metadata de la descarga
        metadata = {
            "last_update": datetime.now(pytz.utc).isoformat(),
            "total_rules_downloaded": len(downloaded_rules),
            "source": "TrailAlerts GitHub Repository"
        }
        
        with open(METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Parsear y guardar las reglas
        parsed_rules = parse_sigma_rules_to_json(downloaded_rules)
        
        return {
            "status": "success",
            "message": f"Successfully downloaded and parsed {len(parsed_rules)} Sigma rules",
            "rules_count": len(parsed_rules)
        }
        
    except requests.RequestException as e:
        return {
            "status": "error",
            "message": f"Network error downloading rules: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error", 
            "message": f"Unexpected error downloading rules: {str(e)}"
        }

def parse_sigma_rules_to_json(raw_rules: List[Dict]) -> List[Dict]:
    """
    Convierte reglas Sigma en formato YAML a formato JSON ejecutable.
    
    Args:
        raw_rules: Lista de reglas en formato YAML parseado
        
    Returns:
        List[Dict]: Reglas parseadas en formato JSON
    """
    parsed_rules = []
    
    for rule in raw_rules:
        try:
            parsed_rule = {
                "rule_id": rule.get('id', rule.get('_filename', 'unknown')),
                "title": rule.get('title', 'Unknown Rule'),
                "description": rule.get('description', ''),
                "severity": rule.get('level', 'medium'),
                "author": rule.get('author', ''),
                "mitre_tags": [tag for tag in rule.get('tags', []) if tag.startswith('attack.')],
                "logsource": rule.get('logsource', {}),
                "detection": rule.get('detection', {}),
                "false_positives": rule.get('falsepositives', []),
                "references": rule.get('references', []),
                "_filename": rule.get('_filename', ''),
                "_parsed_conditions": parse_detection_logic(rule.get('detection', {}))
            }
            
            # Solo añadir reglas que tengan lógica de detección válida
            if parsed_rule["_parsed_conditions"]:
                parsed_rules.append(parsed_rule)
                
        except Exception as e:
            print(f"Error parsing rule {rule.get('title', 'unknown')}: {e}")
            continue
    
    # Guardar reglas parseadas
    with open(PARSED_RULES_FILE, 'w') as f:
        json.dump(parsed_rules, f, indent=2)
    
    return parsed_rules

def parse_detection_logic(detection: Dict) -> Optional[Dict]:
    """
    Convierte la lógica de detección Sigma a formato ejecutable.
    
    Args:
        detection: Sección detection de una regla Sigma
        
    Returns:
        Dict: Condiciones parseadas o None si no se puede parsear
    """
    if not detection:
        return None
    
    try:
        parsed_conditions = {}
        
        # Extraer todas las secciones de selección
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and not key.startswith('filter'):
                selections[key] = value
        
        # Parsear la condición principal
        condition = detection.get('condition', '')
        
        # Para simplificar, empezamos con condiciones básicas
        # Esto se puede expandir para lógica más compleja
        if 'selection' in selections:
            parsed_conditions = parse_selection_conditions(selections['selection'])
        elif len(selections) == 1:
            # Si solo hay una selección, usarla directamente
            selection_name = list(selections.keys())[0]
            parsed_conditions = parse_selection_conditions(selections[selection_name])
        
        return parsed_conditions if parsed_conditions else None
        
    except Exception as e:
        print(f"Error parsing detection logic: {e}")
        return None

def parse_selection_conditions(selection: Dict) -> Dict:
    """
    Parsea las condiciones de una selección específica.
    
    Args:
        selection: Diccionario con condiciones de selección
        
    Returns:
        Dict: Condiciones parseadas
    """
    parsed = {}
    
    for field, values in selection.items():
        if isinstance(values, str):
            # Valor único
            parsed[field] = {"type": "exact", "value": values}
        elif isinstance(values, list):
            # Lista de valores (OR lógico)
            parsed[field] = {"type": "list", "values": values}
        elif isinstance(values, dict):
            # Condiciones especiales (contains, startswith, etc.)
            for operator, value in values.items():
                if operator == "contains":
                    parsed[field] = {"type": "contains", "value": value}
                elif operator == "startswith":
                    parsed[field] = {"type": "startswith", "value": value}
                elif operator == "endswith":
                    parsed[field] = {"type": "endswith", "value": value}
    
    return parsed

def load_parsed_rules() -> List[Dict]:
    """
    Carga las reglas parseadas desde el archivo local.
    
    Returns:
        List[Dict]: Lista de reglas parseadas
    """
    try:
        if not os.path.exists(PARSED_RULES_FILE):
            return []
        
        with open(PARSED_RULES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading parsed rules: {e}")
        return []

def get_rules_metadata() -> Dict:
    """
    Obtiene metadata sobre las reglas descargadas.
    
    Returns:
        Dict: Metadata de las reglas
    """
    try:
        if not os.path.exists(METADATA_FILE):
            return {"last_update": None, "total_rules_downloaded": 0}
        
        with open(METADATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading metadata: {e}")
        return {"last_update": None, "total_rules_downloaded": 0}

def analyze_events_against_rules(events: List[Dict], start_date: Optional[str] = None, end_date: Optional[str] = None) -> Dict:
    """
    Analiza eventos de CloudTrail contra las reglas Sigma cargadas.
    
    Args:
        events: Lista de eventos de CloudTrail
        start_date: Fecha de inicio opcional (formato ISO)
        end_date: Fecha de fin opcional (formato ISO)
        
    Returns:
        Dict: Resultados del análisis con alertas encontradas
    """
    try:
        # Cargar reglas parseadas
        rules = load_parsed_rules()
        if not rules:
            return {
                "status": "error",
                "message": "No Sigma rules found. Please update rules database first.",
                "alerts": [],
                "events_analyzed": 0,
                "rules_loaded": 0
            }
        
        # Filtrar eventos por fecha si se especifica
        filtered_events = filter_events_by_date(events, start_date, end_date)
        
        alerts = []
        
        for event in filtered_events:
            for rule in rules:
                if evaluate_event_against_rule(event, rule):
                    alert = {
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "mitre_tags": rule["mitre_tags"],
                        "matched_event": {
                            "EventName": event.get("EventName"),
                            "EventTime": event.get("EventTime"),
                            "Username": event.get("Username"),
                            "SourceIPAddress": event.get("SourceIPAddress"),
                            "EventRegion": event.get("EventRegion")
                        },
                        "timestamp": datetime.now(pytz.utc).isoformat(),
                        "risk_score": calculate_risk_score(rule["severity"], rule["mitre_tags"])
                    }
                    alerts.append(alert)
        
        # Ordenar alertas por risk score descendente
        alerts.sort(key=lambda x: x["risk_score"], reverse=True)
        
        # Calcular resumen de alertas por severidad
        severity_counts = {}
        for alert in alerts:
            severity = alert["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary = {
            "total_alerts": len(alerts),
            "critical_alerts": severity_counts.get("critical", 0),
            "high_alerts": severity_counts.get("high", 0),
            "medium_alerts": severity_counts.get("medium", 0),
            "low_alerts": severity_counts.get("low", 0),
            "info_alerts": severity_counts.get("info", 0)
        }
        
        return {
            "status": "success",
            "alerts": alerts,
            "summary": summary,
            "events_analyzed": len(filtered_events),
            "rules_loaded": len(rules),
            "analysis_timeframe": {
                "start_date": start_date,
                "end_date": end_date
            }
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error analyzing events: {str(e)}",
            "alerts": [],
            "events_analyzed": 0,
            "rules_loaded": 0
        }


def filter_events_by_date(events: List[Dict], start_date: Optional[str], end_date: Optional[str]) -> List[Dict]:
    """
    Filtra eventos por rango de fechas.
    
    Args:
        events: Lista de eventos
        start_date: Fecha de inicio (ISO format)
        end_date: Fecha de fin (ISO format)
        
    Returns:
        List[Dict]: Eventos filtrados
    """
    if not start_date and not end_date:
        return events
    
    filtered = []
    
    try:
        start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00')) if start_date else None
        end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00')) if end_date else None
        
        print(f"DEBUG: Filtering events. Start: {start_dt}, End: {end_dt}")
        print(f"DEBUG: Total events to filter: {len(events)}")
        
        for event in events:
            event_time_str = event.get("EventTime", "")
            if not event_time_str:
                continue
                
            try:
                # Usar fromisoformat que maneja mejor los timezones
                if event_time_str.endswith('Z'):
                    # Formato ISO con Z
                    event_dt = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                elif '+' in event_time_str or '-' in event_time_str[-6:]:
                    # Formato con timezone como +02:00
                    event_dt = datetime.fromisoformat(event_time_str)
                else:
                    # Formato sin timezone
                    event_dt = datetime.fromisoformat(event_time_str)
                    event_dt = event_dt.replace(tzinfo=pytz.utc)
                
                # Asegurar que todas las fechas tengan timezone para comparación
                if event_dt.tzinfo is None:
                    event_dt = event_dt.replace(tzinfo=pytz.utc)
                if start_dt and start_dt.tzinfo is None:
                    start_dt = start_dt.replace(tzinfo=pytz.utc)
                if end_dt and end_dt.tzinfo is None:
                    end_dt = end_dt.replace(tzinfo=pytz.utc)
                
                # Comparar fechas
                include_event = True
                if start_dt and event_dt < start_dt:
                    include_event = False
                if end_dt and event_dt > end_dt:
                    include_event = False
                
                if include_event:
                    filtered.append(event)
                    
            except (ValueError, TypeError) as e:
                print(f"DEBUG: Error parsing event date '{event_time_str}': {e}")
                # Si no se puede parsear, incluir por defecto
                filtered.append(event)
                
    except Exception as e:
        print(f"Error filtering events by date: {e}")
        return events
    
    print(f"DEBUG: Filtered events count: {len(filtered)}")
    return filtered

def evaluate_event_against_rule(event: Dict, rule: Dict) -> bool:
    """
    Evalúa si un evento coincide con una regla específica.
    
    Args:
        event: Evento de CloudTrail
        rule: Regla Sigma parseada
        
    Returns:
        bool: True si el evento coincide con la regla
    """
    try:
        conditions = rule.get("_parsed_conditions", {})
        if not conditions:
            return False
        
        # Evaluar cada condición
        for field, condition in conditions.items():
            event_value = get_nested_field_value(event, field)
            if event_value is None:
                return False
            
            if not evaluate_condition(event_value, condition):
                return False
        
        return True
        
    except Exception as e:
        print(f"Error evaluating event against rule {rule.get('rule_id', 'unknown')}: {e}")
        return False


def get_nested_field_value(event: Dict, field_path: str) -> Any:
    """
    Obtiene el valor de un campo anidado en el evento.
    """
    try:
        # Parsear el CloudTrailEvent JSON si está disponible
        cloudtrail_data = None
        if 'CloudTrailEvent' in event:
            try:
                import json
                cloudtrail_data = json.loads(event['CloudTrailEvent'])
            except (json.JSONDecodeError, TypeError):
                cloudtrail_data = None
        
        # Para eventos de CloudTrail, buscar primero en CloudTrailEvent JSON
        if field_path == "eventSource":
            # Primero intentar desde CloudTrailEvent JSON
            if cloudtrail_data:
                value = cloudtrail_data.get("eventSource")
                if value:
                    return value
            
            # Fallback a los métodos anteriores
            value = event.get("RequestParameters", {}).get("eventSource") or event.get("EventSource")
            return value
            
        elif field_path == "eventName":
            # Primero CloudTrailEvent, luego fallback
            if cloudtrail_data:
                value = cloudtrail_data.get("eventName")
                if value:
                    return value
            return event.get("EventName")
            
        elif field_path == "sourceIPAddress":
            # Primero CloudTrailEvent, luego fallback
            if cloudtrail_data:
                value = cloudtrail_data.get("sourceIPAddress")
                if value:
                    return value
            return event.get("SourceIPAddress")
            
        elif field_path == "userIdentity.type":
            # Buscar en CloudTrailEvent JSON
            if cloudtrail_data:
                value = cloudtrail_data.get("userIdentity", {}).get("type")
                if value:
                    return value
            
            # Fallback
            return event.get("RequestParameters", {}).get("userIdentity", {}).get("type")
            
        elif field_path == "Username":
            # Primero intentar desde CloudTrailEvent
            if cloudtrail_data:
                # Para eventos de signin, el userName está en userIdentity
                user_identity = cloudtrail_data.get("userIdentity", {})
                if isinstance(user_identity, dict):
                    cloudtrail_username = user_identity.get("userName")
                    if cloudtrail_username:
                        return cloudtrail_username
                
                # También intentar directamente
                direct_username = cloudtrail_data.get("userName")
                if direct_username:
                    return direct_username
            
            # Probar diferentes campos donde podría estar el username en el evento plano
            possible_fields = [
                event.get("Username"),
                event.get("UserName"), 
                event.get("userName"),
                event.get("userIdentity", {}).get("userName") if isinstance(event.get("userIdentity"), dict) else None,
                event.get("RequestParameters", {}).get("userName") if isinstance(event.get("RequestParameters"), dict) else None,
                event.get("ResponseElements", {}).get("userName") if isinstance(event.get("ResponseElements"), dict) else None
            ]
            
            # Devolver el primer valor no None
            for field_value in possible_fields:
                if field_value is not None:
                    return field_value
            
            return None
        
        # Para campos anidados, navegar por la estructura
        if '.' in field_path:
            parts = field_path.split('.')
            
            # Primero intentar en CloudTrailEvent
            if cloudtrail_data:
                value = cloudtrail_data
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
                if value is not None:
                    return value
            
            # Fallback al evento plano
            value = event
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return None
            return value
        else:
            # Primero CloudTrailEvent, luego evento plano
            if cloudtrail_data and field_path in cloudtrail_data:
                return cloudtrail_data.get(field_path)
            return event.get(field_path)
            
    except Exception:
        return None

def evaluate_condition(event_value: Any, condition: Dict) -> bool:
    """
    Evalúa una condición específica contra un valor del evento.
    
    Args:
        event_value: Valor del campo del evento
        condition: Condición a evaluar
        
    Returns:
        bool: True si la condición se cumple
    """
    try:
        condition_type = condition.get("type")
        
        if condition_type == "exact":
            return str(event_value) == str(condition.get("value", ""))
        
        elif condition_type == "list":
            return str(event_value) in [str(v) for v in condition.get("values", [])]
        
        elif condition_type == "contains":
            return str(condition.get("value", "")) in str(event_value)
        
        elif condition_type == "startswith":
            return str(event_value).startswith(str(condition.get("value", "")))
        
        elif condition_type == "endswith":
            return str(event_value).endswith(str(condition.get("value", "")))
        
        return False
        
    except Exception:
        return False

def calculate_risk_score(severity: str, mitre_tags: List[str]) -> int:
    """
    Calcula un score de riesgo basado en la severidad y tags MITRE.
    
    Args:
        severity: Nivel de severidad
        mitre_tags: Tags MITRE ATT&CK
        
    Returns:
        int: Score de riesgo (0-100)
    """
    base_scores = {
        "critical": 90,
        "high": 70,
        "medium": 50,
        "low": 30,
        "info": 10
    }
    
    score = base_scores.get(severity.lower(), 50)
    
    # Incrementar score basado en técnicas MITRE críticas
    critical_techniques = ["t1078", "t1190", "t1133", "t1566"]  # Ejemplos de técnicas críticas
    for tag in mitre_tags:
        technique = tag.replace("attack.", "").lower()
        if technique in critical_techniques:
            score += 10
    
    return min(score, 100)  # Máximo 100