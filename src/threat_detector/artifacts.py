"""Reglas para leer la salida de un modelo, compartidas por ml/ y app/."""

import numpy as np

from threat_detector.config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM


def is_alert(attack_probability, threshold):
    """Indica si la probabilidad de ataque es alerta: mayor o igual que el umbral del modelo.

    Con un solo flujo (un número) devuelve un bool de Python, que se puede poner directamente en
    un JSON; con muchos (una lista o un arreglo) devuelve un arreglo con un valor por flujo.
    """
    alerts = np.asarray(attack_probability) >= threshold
    return bool(alerts) if alerts.ndim == 0 else alerts


def severity(attack_probability, threshold):
    """Severidad de un flujo: "critical", "high", "medium", "low" o "normal" (contrato, sección 3)."""
    if not is_alert(attack_probability, threshold):
        return "normal"
    if attack_probability >= SEVERITY_CRITICAL:
        return "critical"
    if attack_probability >= SEVERITY_HIGH:
        return "high"
    if attack_probability >= SEVERITY_MEDIUM:
        return "medium"
    return "low"


def detection_rate(y_true, alerts):
    """De los ataques reales (label = 1), la parte que es alerta; None si no hay ataques reales."""
    attacks = np.asarray(y_true) == 1
    return float(np.asarray(alerts)[attacks].mean()) if attacks.any() else None


def false_alarm_rate(y_true, alerts):
    """De los flujos normales reales (label = 0), la parte que es alerta; None si no hay normales."""
    normals = np.asarray(y_true) == 0
    return float(np.asarray(alerts)[normals].mean()) if normals.any() else None
