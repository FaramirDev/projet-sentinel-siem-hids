import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
import json
import time
import subprocess
from datetime import datetime
from numpy.random import default_rng as rng
import plotly.express as px
import sys
from pathlib import Path
from dotenv import load_dotenv

# ====== CONFIG DE LA RACCINE =========================================================
# Depuis pages/, le parent est dashboard/, et le parent du parent est la racine
BASE_DIR = Path(__file__).resolve().parent.parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# *************************************************************************************
# ====== 1er PARTIE CONFIGURATION ENV & PATH PARENT ===================================
from config import BASE_DIR, LOGS_EVENTS_DIR, DATA_HIDS_DIR, LOGS_SYSTEM, LOGS_SCANS_DIR
import streamlit as st
load_dotenv(BASE_DIR / ".env")


# --- 1.1 PATH & DIR ------------------------------------------------------------------
PATH_DIR_LOGS_HIDS = LOGS_EVENTS_DIR
LOG_HEALTH_DIR = LOGS_SYSTEM
PATH_DIR_DATA_HIDS = DATA_HIDS_DIR
PATH_LOG_SCAN = LOGS_SCANS_DIR

# --- 2. Couleurs du thème ------------------------------------------------------------
ST_BG_COLOR = "#1e2130"
COLOR_FLASH = "#BF6BFF"  # Violet néon

# --- 1.2 FONCTION  -------------------------------------------------------------------
def load_latest_audit(path):
    files = [f for f in os.listdir(path) if f.startswith("AUDIT_")]
    if not files: return None
    files.sort(reverse=True)
    with open(os.path.join(path, files[0]), 'r') as f:
        files_last = files[0]
        return json.load(f), files_last

def load_audit(path):
    with open(os.path.join(path), 'r') as f:
        return json.load(f)

def get_banned_count_from_dict(data_ip):
    banned_count = 0
    
    # data_ip ressemble à {"1.1.1.1": {"status": "BANNED", ...}, "2.2.2.2": {...}}
    for ip, details in data_ip.items():
        if details.get("status") == "BANNED":
            banned_count += 1
            
    return banned_count

def recup_hote_scan(data):
    recup_machine_detecte = 0
    for ip in data:
        recup_machine_detecte += 1
    return recup_machine_detecte

def check_status_service(data_service):
    status_global_service = 0
    for serv in service:
            if service[serv] == "inactive":
                status_global_service += 1
    return status_global_service

def render_top_metric(title, value, status_text, color, icon):
    html = (
        f"<div style='background-color: {ST_BG_COLOR}; padding: 15px 20px; border-radius: 12px; "
        f"border-top: 4px solid {color}; border-left: 1px solid #2d3142; border-right: 1px solid #2d3142; "
        f"border-bottom: 1px solid #2d3142; box-shadow: 0px 4px 12px rgba(0,0,0,0.4);'>"
        f"<div style='display: flex; justify-content: space-between; align-items: center;'>"
        f"<span style='color: #8a8f9e; font-size: 13px; font-weight: bold; letter-spacing: 1px;'>{title.upper()}</span>"
        f"<span class='material-symbols-outlined' style='color: {color}; font-size: 24px;'>{icon}</span>"
        f"</div>"
        f"<div style='font-size: 28px; font-weight: 900; color: white; margin: 10px 0; font-family: monospace;'>{value}</div>"
        f"<div style='color: {color}; font-size: 12px; font-weight: bold;'>● {status_text}</div>"
        f"</div>"
    )
    st.markdown(html, unsafe_allow_html=True)

def render_cyber_progress(title, value, color_hex):
    bar_color = "#ff4b4b" if value > 85 else color_hex
    neon_style = f"box-shadow: 0px 0px 6px {bar_color}, 0px 0px 18px {bar_color}cc;"
    html = (
        f"<div style='background-color: {ST_BG_COLOR}; padding: 18px; border-radius: 12px; border: 1px solid #2d3142; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.3); margin-bottom: 15px;'>"
        f"<div style='display: flex; justify-content: space-between; margin-bottom: 12px; align-items: center;'>"
        f"<span style='color: #8a8f9e; font-size: 13px; font-weight: bold; letter-spacing: 1px;'>{title.upper()}</span>"
        f"<span style='color: white; font-size: 18px; font-weight: bold; font-family: monospace;'>{value}%</span>"
        f"</div>"
        f"<div style='background-color: #12141d; width: 100%; height: 8px; border-radius: 4px; display: flex; align-items: center;'>"
        f"<div style='background-color: {bar_color}; width: {value}%; height: 100%; border-radius: 4px; transition: width 0.5s ease-in-out; {neon_style}'></div>"
        f"</div>"
        f"</div>"
    )
    st.markdown(html, unsafe_allow_html=True)

def render_compact_log(event_type, ip, time_str, color, icon):
    html = (
        f"<div style='background-color: {ST_BG_COLOR}; padding: 12px 18px; border-radius: 8px; "
        f"border-left: 4px solid {color}; border-top: 1px solid #2d3142; border-right: 1px solid #2d3142; "
        f"border-bottom: 1px solid #2d3142; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;'>"
        f"<div style='display: flex; align-items: center; gap: 12px;'>"
        f"<span class='material-symbols-outlined' style='color: {color}; font-size: 22px;'>{icon}</span>"
        f"<div>"
        f"<strong style='color: white; font-size: 13px;'>{event_type.upper()}</strong><br>"
        f"<span style='color: #8a8f9e; font-size: 11px; font-family: monospace;'>Provenance : {ip}</span>"
        f"</div>"
        f"</div>"
        f"<span style='color: #646a78; font-size: 12px; font-family: monospace; display: flex; align-items: center; gap: 4px;'>"
        f"<span class='material-symbols-outlined' style='font-size: 14px;'>schedule</span>{time_str}</span>"
        f"</div>"
    )
    st.markdown(html, unsafe_allow_html=True)

# --- 1.3 CHARGEMENT DE LA DATA -------------------------------------------------------
## 1. LOAD data System HEALTH
data_health, health_files_last = load_latest_audit(LOG_HEALTH_DIR)  

## 2. LOAD data_scan
data_scan = load_latest_audit(PATH_LOG_SCAN)

## 3. Load data ip HIDS
data_ip_recup = load_audit(PATH_DIR_DATA_HIDS)

# *************************************************************************************
# ====== 2e PARTIE EXTRATION & EXPLOITATION DATA ======================================

# --- EXTRATION DATA ------------------------------------------------------------------
total_banned = get_banned_count_from_dict(data_ip_recup)

## RECUP Hote scan
rec_nb_hote = recup_hote_scan(data_scan)

## Extraction des variables HEALTH pour plus de clarté
sys_info = data_health["data_systeme"]["data_sys"]
disk = data_health["data_systeme"]["data_disk"]
mem = data_health["data_systeme"]["data_memory"]
procs = data_health["data_systeme"]["data_memory_high"]
service = data_health["data_systeme"]["data_service"]
cpu_load = data_health["data_systeme"]["data_cpu"]

## Memoire
rec_memoire = mem['memory_percent']
rec_disk = disk['stockage_percent']

status_global_serv = check_status_service(service)


# Chargement du CDN Google pour les icônes
st.markdown("<link href='https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined' rel='stylesheet' />", unsafe_allow_html=True)

# ***************************************************************************************************
# ====== 3e PARTIE INTERFACE DESIGN PAGE ============================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°

# --- 3.1 HEADER DE LA PAGE -------------------------------------------------------------------------

# En-tête de la page en HTML/CSS pour intégrer une icone de Google 
header_html = (
    f"<div style='display: flex; align-items: center; gap: 10px; margin-bottom: 5px;'>"
    f"<span class='material-symbols-outlined' style='font-size: 32px; color: {COLOR_FLASH};'>dashboard</span>"
    f"<h1 style='margin: 0; font-size: 32px; color: white;'>Terminal Sentinel SIEM</h1>"
    f"</div>"
    f"<div style='color: #8a8f9e; font-size: 14px; margin-bottom: 20px;'>Console de supervision de sécurité</div>"
)
st.markdown(header_html, unsafe_allow_html=True)
st.markdown("---")

# ==================================================================================================
# ZONE 1 : LE BANDEAU (Cartes Métriques)
# ==================================================================================================

m_col1, m_col2, m_col3 = st.columns(3)

with m_col1:
    if status_global_serv == 0:
        render_top_metric("Santé Système", "OPTIMAL", "Tous les services sont actifs", "#86E846", "check_circle")
    else:
        render_top_metric("Santé Système", "WARNING", "Tous les services sont actifs", "#ED5151", "check_circle")

with m_col2:
    render_top_metric("Menaces HIDS", total_banned, "Activité suspecte détectée", "#ED5151", "gpp_maybe")
with m_col3:
    render_top_metric("Scan Réseau", rec_nb_hote, "Hote(s) Decouvert(s)", "#5178ED", "lan")

st.markdown("<br>", unsafe_allow_html=True)

# ===================================================================================================
# ZONE 2 : LE COEUR DES OPÉRATIONS (2 Colonnes)
# ===================================================================================================

col_g, col_r = st.columns([1, 1])

with col_g:
    st.markdown(
        f"<div style='display: flex; align-items: center; gap: 8px; margin-bottom: 15px;'>"
        f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 22px;'>monitoring</span>"
        f"<span style='color: white; font-size: 18px; font-weight: bold;'>Constantes Systemes</span>"
        f"</div>", 
        unsafe_allow_html=True
    )
    render_cyber_progress("Charge CPU", cpu_load["charge_cpu"], "#BF6BFF")
    render_cyber_progress("Usage RAM", rec_memoire, "#00cc96")
    render_cyber_progress("Espace Disque", rec_disk, "#2450E0")

with col_r:
    st.markdown(
        f"<div style='display: flex; align-items: center; gap: 8px; margin-bottom: 15px;'>"
        f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 22px;'>public</span>"
        f"<span style='color: white; font-size: 18px; font-weight: bold;'>Localisation des Attaques</span>"
        f"</div>", 
        unsafe_allow_html=True
    )
    
    df_mini_map = pd.DataFrame({
        "lat": [48.8566, 37.7749],
        "lon": [2.3522, -122.4194],
        "ip": ["192.168.1.50", "45.33.22.11"]
    })
    
    fig = px.scatter_mapbox(
        df_mini_map, lat="lat", lon="lon", hover_name="ip", zoom=0.5
    )
    fig.update_layout(
        mapbox_style="carto-darkmatter",
        margin={"r": 0, "t": 0, "l": 0, "b": 0},
        height=225,
        showlegend=False
    )
    st.plotly_chart(fig, use_container_width=True)

# ================================================================================================
# ZONE 3 : LE JOURNAL D'ACTIVITÉ FLASH
# ================================================================================================

# --- 3.1. En-tête de la section -----------------------------------------------------------------
st.markdown("<br>", unsafe_allow_html=True)
st.markdown(
    f"<div style='display: flex; align-items: center; gap: 8px; margin-bottom: 15px;'>"
    f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 22px;'>format_list_bulleted</span>"
    f"<span style='color: white; font-size: 18px; font-weight: bold;'>Derniers Événements Détectés</span>"
    f"</div>", 
    unsafe_allow_html=True
)

# --- 3.2. Lecture, parsing et tri chronologique -------------------------------------------------
if os.path.exists(PATH_DIR_LOGS_HIDS):
    log_files = [f for f in os.listdir(PATH_DIR_LOGS_HIDS) if f.endswith(".json")]
    
    if log_files:
        all_events = []
        
        # On lit d'abord TOUS les fichiers JSON pour charger leurs données en mémoire -------------
        for file in log_files:
            with open(os.path.join(PATH_DIR_LOGS_HIDS, file), 'r') as f:
                try:
                    event_data = json.load(f)
                    all_events.append(event_data)
                except:
                    continue
        
        # Tri de la liste complète basé sur le champ 'full_timestamp'  ----------------------------
        all_events.sort(key=lambda x: x.get("full_timestamp", ""), reverse=True)
        
        # On extrait uniquement les 4 événements les plus récents  --------------------------------
        recent_events = all_events[:4]
        
        for event in recent_events:
            evt_type = event.get("event_type", "unknown").lower()
            ip = event.get("ip_source", "0.0.0.0")
            time_str = event.get("full_timestamp", "N/A")
            
            # Gestion des couleurs et icones  -----------------------------------------------------
            if "ban" in evt_type:
                color = "#ff4b4b"
                icon = "gpp_maybe"
                label = "Ip Bannie"
            elif "echec" in evt_type or "failed" in evt_type:
                color = "#ffaa00"
                icon = "warning"
                label = "Échec Connexion"
            elif "succes" in evt_type or "accepted" in evt_type:
                color = "#00cc96"
                icon = "check_circle"
                label = "Connexion Réussie"
            else:
                color = "#2450E0"
                icon = "info"
                label = evt_type.capitalize()
                
            render_compact_log(label, ip, time_str, color, icon)
    else:
        st.info("Aucun événement détecté pour le moment.")
else:
    st.warning("⚠️ Dossier logs d'événements introuvable.")