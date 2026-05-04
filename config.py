import os
from pathlib import Path

# 1. Racine du projet (deux niveaux au-dessus de ce fichier si besoin, ou juste le parent)
# Path(__file__).resolve().parent désigne le dossier Projet-Sentinel-Dashboard/
BASE_DIR = Path(__file__).resolve().parent

# 2. Définition des dossiers clés
DATA_DIR = BASE_DIR / "data"
CORE_DIR = BASE_DIR / "core"
IMAGES_DIR = BASE_DIR / "images"

# Chemins spécifiques vers les logs
# -- HIDS OUTPUT DATA & LOG ------------------------------------------------------------------------
LOGS_EVENTS_DIR = DATA_DIR / "logs_hids/logs_event"
DATA_HIDS_DIR = DATA_DIR / "logs_hids/data_hids/data_ip.json"

# -- SCAN & SYSTEM LOG OUTPUT ----------------------------------------------------------------------
LOGS_SCANS_DIR = DATA_DIR / "logs_scans"
LOGS_SYSTEM = DATA_DIR / "logs_system"

# -- DATA INTPUT - WITHLIST HIDS & PORT SCAN & SYSTEM MONITOR PATH ---------------------------------
DATA_HIDS_WITHLIST_DIR = DATA_DIR / "data_input/hids_whitlist.json"
DATA_SCAN_PORT_DIR =  DATA_DIR / "data_input/scan_data_port.json"
DATA_SYSTEM_MONITOR_DIR = DATA_DIR / "data_input/system_security_baseline.csv"

