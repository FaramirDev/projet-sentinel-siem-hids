import pandas as pd
import plotly.graph_objects as go
import os
import json
import time
import requests
import subprocess
import psutil
from datetime import datetime
from numpy.random import default_rng as rng
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv
import sys
from pathlib import Path

# ====== CONFIG DE LA RACCINE =========================================================
# Depuis pages/, le parent est dashboard/, et le parent du parent est la racine
BASE_DIR = Path(__file__).resolve().parent.parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# *************************************************************************************
# ====== 1er PARTIE CONFIGURATION =====================================================
from config import BASE_DIR, CORE_DIR, LOGS_EVENTS_DIR, DATA_HIDS_DIR
import streamlit as st

load_dotenv(BASE_DIR / ".env")


# --- 1.1 PATH & DIR & VARIABLE--------------------------------------------------------
DATA_DIR = DATA_HIDS_DIR
LOG_DIR = LOGS_EVENTS_DIR
SCRIPT_DIR = CORE_DIR / "daemon_sentinel_hids.py"

# --- VAR COULEUR THEME ---------------------------------------------------------------
ST_BG_COLOR = "#1e2130"
COLOR_FLASH = "#BF6BFF"

## --- LIST PALETTE DE COULEURS NÉON ( MAP ) ------------------------------------------
CYBER_COLORS = ["#BF6BFF", "#00ff41", "#2450E0", "#FF007F", "#00F0FF", "#FFB000", "#FF4B4B"]

# --- 1.2 FONCTION  -------------------------------------------------------------------
def load_audit(path):
    with open(os.path.join(path), 'r') as f:
        return json.load(f),

def run_script(script_path):
    """Exécute un script python externe."""
    try:
        subprocess.run(["python3", script_path], check=True)
        return True
    except Exception as e:
        st.error(f"Erreur d'exécution : {e}")
        return False

def info_card(conteneur="st", title="", text="", color="#BF6BFF", border="left", bg_color="#1e2130"):
    conteneur.markdown(f"""
        <div style="
            background-color: {bg_color}; 
            padding: 20px; 
            border-radius: 10px; 
            border-{border}: 5px solid {color};
            margin-bottom: 10px;
        ">
            <span style="font-size: 20px; font-weight: bold; color: white;">{title}</span><br>
            <span style="font-size: 14px; color: #a3a8b4;">{text}</span>
        </div>
        """, unsafe_allow_html=True)

def render_attacker_card(list_ip, color):
    # Extraction des données liste_ip
    ip = list_ip[0]
    tentatives = list_ip[1]
    first_seean = list_ip[2]
    status = list_ip[3]
    last_attempt = list_ip[4]
    last_user_targeted = list_ip[5]

    # Gestion dynamique du statut (Badge d'alerte)
    if status == "BANNED":
        status_color = "#ff4b4b"
        status_label = "gpp_maybe"
        status_text = "Banni"
    else:
        status_color = "#ffaa00"
        status_label = "visibility"
        status_text = "En surveillance"

    google_icons_link = "<link href='https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200' rel='stylesheet' />"

    # Le HTML pour les CARDS
    html_content = (
        f"{google_icons_link}"
        f"<div style='background-color: {ST_BG_COLOR}; padding: 20px; border-radius: 10px; "
        f"border-left: 5px solid {color}; border-top: 1px solid #2d3142; "
        f"border-right: 1px solid #2d3142; border-bottom: 1px solid #2d3142; margin-bottom: 15px; "
        f"box-shadow: 0px 0px 8px {color}cc; font-family: sans-serif;'>"
        
        # En-tête de la Card
        f"<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;'>"
        f"<span style='font-size: 20px; font-weight: bold; color: white; display: flex; align-items: center; gap: 8px;'>"
        f"<span class='material-symbols-outlined' style='color: #a3a8b4;'>computer</span> {ip}</span>"
        f"<span style='background-color: {status_color}22; color: {status_color}; border: 1px solid {status_color}; "
        f"padding: 4px 12px; border-radius: 15px; font-size: 13px; font-weight: bold; display: flex; align-items: center; gap: 5px;'>"
        f"<span class='material-symbols-outlined' style='font-size: 16px;'>{status_label}</span>{status_text}</span>"
        f"</div>"
        
        # Informations de la Card
        f"<div style='display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 14px;'>"
        f"<div style='display: flex; align-items: center; gap: 6px;'>"
        f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 18px;'>person</span>"
        f"<span style='color: #8a8f9e;'>Cible :</span> <strong style='color: {COLOR_FLASH}; font-family: monospace;'>{last_user_targeted}</strong>"
        f"</div>"
        f"<div style='display: flex; align-items: center; gap: 6px;'>"
        f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 18px;'>local_fire_department</span>"
        f"<span style='color: #8a8f9e;'>Essais :</span> <strong style='color: white;'>{tentatives} / 3</strong>"
        f"</div>"
        f"<div style='display: flex; align-items: center; gap: 6px;'>"
        f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 18px;'>event_upcoming</span>"
        f"<span style='color: #8a8f9e;'>1ère détection :</span> <span style='color: white;'>{first_seean}</span>"
        f"</div>"
        f"<div style='display: flex; align-items: center; gap: 6px;'>"
        f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 18px;'>schedule</span>"
        f"<span style='color: #8a8f9e;'>Dernier essai :</span> <span style='color: white;'>{last_attempt}</span>"
        f"</div>"
        f"</div>"
        f"</div>"
    )

    st.markdown(html_content, unsafe_allow_html=True)

def render_log_card(event_data):
    """Génère une carte d'événement."""
    evt_type = event_data.get("event_type", "unknown").lower()
    
    # Couleurs et icones Google dynamiques selon le statut
    if "ban" in evt_type:
        color = "#ff4b4b"
        icon = "gpp_maybe" # Icone de bouclier alerte
        label = "BANNI"
    elif "echec" in evt_type or "failed" in evt_type:
        color = "#ffaa00"
        icon = "warning"   # Icone de triangle attention
        label = "ÉCHEC"
    elif "succes" in evt_type or "accepted" in evt_type:
        color = "#00cc96"
        icon = "check_circle" # Icone de validation verte
        label = "SUCCÈS"
    else:
        color = "#8a8f9e"
        icon = "info"
        label = evt_type.upper()

    google_icons_link = "<link href='https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined' rel='stylesheet' />"

    html_content = (
        f"{google_icons_link}"
        f"<div style='background-color: {ST_BG_COLOR}; padding: 15px; border-radius: 10px; "
        f"border-left: 5px solid {color}; border-top: 1px solid #2d3142; border-right: 1px solid #2d3142; "
        f"border-bottom: 1px solid #2d3142; margin-bottom: 10px; box-shadow: 0px 4px 6px rgba(0,0,0,0.1);'>"
        
        # En-tête : Type d'événement (Badge) + Heure
        f"<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>"
        f"<span style='background-color: {color}22; color: {color}; border: 1px solid {color}; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; display: flex; align-items: center; gap: 4px;'>"
        f"<span class='material-symbols-outlined' style='font-size: 14px;'>{icon}</span>{label}</span>"
        f"<span style='color: #8a8f9e; font-size: 12px; font-family: monospace; display: flex; align-items: center; gap: 4px;'>"
        f"<span class='material-symbols-outlined' style='font-size: 14px;'>schedule</span>{event_data.get('full_timestamp')}</span>"
        f"</div>"
        
        # Grid : Informations en 2 colonnes
        f"<div style='display: grid; grid-template-columns: 1fr 1.2fr; gap: 10px; font-size: 13px;'>"
        f"<div style='display: flex; align-items: center; gap: 5px;'>"
        f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 16px;'>terminal</span>"
        f"<span style='color: #8a8f9e;'>IP :</span> <strong style='color: white; font-family: monospace;'>{event_data.get('ip_source')}</strong>"
        f"</div>"
        
        f"<div style='display: flex; align-items: center; gap: 5px;'>"
        f"<span class='material-symbols-outlined' style='color: #8a8f9e; font-size: 16px;'>person</span>"
        f"<span style='color: #8a8f9e;'>Cible :</span> <strong style='color: #BF6BFF; font-family: monospace;'>{event_data.get('user_target')}</strong>"
        f"</div>"
        f"</div>"
        
        # Pied de carte : Source de log
        f"<div style='margin-top: 10px; padding-top: 6px; border-top: 1px solid #2d3142; font-size: 11px; color: #646a78; display: flex; align-items: center; gap: 4px;'>"
        f"<span class='material-symbols-outlined' style='font-size: 15px;'>description</span> Source : {event_data.get('system_log_source')}"
        f"</div>"
        
        f"</div>"
    )

    st.markdown(html_content, unsafe_allow_html=True)

def get_ip_location(ip):
    """Géolocalise une IP (Simulée pour le local)."""
    if ip == "127.0.0.1" or ip.startswith("192.168."):
        return 48.8566, 2.3522, "France (Local)"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response['status'] == 'success':
            return response['lat'], response['lon'], response['country']
    except: pass
    return None, None, "Inconnu"

def calculate_global_metrics(directory_path):
    # On initialise les compteurs à 0
    total_connexions = 0
    total_echecs = 0
    total_bans = 0
    
    if os.path.exists(directory_path):
        # Lister tous les fichiers JSON dans le dossier
        log_files = [f for f in os.listdir(directory_path) if f.endswith(".json")]
        
        for file in log_files:
            try:
                # Lecture de chaque fichier JSON
                with open(os.path.join(directory_path, file), 'r') as f:
                    event_data = json.load(f)
                    
                # Extraction du type d'événement
                evt_type = event_data.get("event_type", "unknown").lower()
                
                # Incrémentation des compteurs
                if "ban" in evt_type:
                    total_bans += 1
                elif "echec" in evt_type or "failed" in evt_type:
                    total_echecs += 1
                elif "succes" in evt_type or "accepted" in evt_type:
                    total_connexions += 1
            except:
                continue
                
    return total_echecs, total_connexions, total_bans

def metric_global(data_scan):
    ip_detecte = 0
    ip_banni = 0
    status_parfeu = "Actif"

    ## Recup DATA 
    for ip in data_scan:
        ip_detecte += 1
        for i in ip: 
            recup_int = ip[i]
            for recup in recup_int:   
                data_u = recup_int[recup]    
                if data_u == "BANNED":
                    ip_banni += 1
                else:
                    pass
    return ip_detecte, ip_banni, status_parfeu

def extration_clean_list_all_ip(data_scan):
    list_avec_all_list_clean = []

    for donne in data:
        list_clean = []
        for do in donne:
            list_clean.append(do)    
            recup_dico_ip = donne[do]
            for element in recup_dico_ip:
                if element == "tentatives":
                    list_clean.append(recup_dico_ip[element])
                elif element == "first_seen":
                    list_clean.append(recup_dico_ip[element])
                elif element == "status":
                    list_clean.append(recup_dico_ip[element])
                elif element == "last_attempt":
                    list_clean.append(recup_dico_ip[element])
                elif element == "last_user_targeted":
                    list_clean.append(recup_dico_ip[element])
                    list_avec_all_list_clean.append(list_clean)

    return list_avec_all_list_clean


# --- 1.3 CHARGEMENT DE LA DATA -------------------------------------------------------
data = load_audit(DATA_DIR)

if not data:
    st.error("Impossible de charger les données d'audit.")
    st.stop()


# ***************************************************************************************************
# ====== 2e PARTIE EXTRATION & EXPLOITATION DATA ====================================================

# --- EXTRATION Metric GLobal Metric 1 --------------------------------------------------------------
ip_detecte, ip_banni, status_parfeu = metric_global(data)

# --- EXTRATION List Clean ALL IP -------------------------------------------------------------------
list_avec_all_list_clean = extration_clean_list_all_ip(data)

## --- EXTRATION Metric GLobal Metric 2 -------------------------------------------------------------
ip_echec, ip_connexion, tentative_ban = calculate_global_metrics(LOG_DIR)


# ***************************************************************************************************
# ====== 3e PARTIE INTERFACE DESIGN PAGE ============================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°

# --- 3.1 HEADER DE LA PAGE -------------------------------------------------------------------------
st.title("Dashboard Sentinel HIDS")
st.caption(f"Detection HIDS Automatique")

st.markdown("---")

changes = list(rng(4).standard_normal(20))
data_metric = [sum(changes[:i]) for i in range(15)]
delta = round(data_metric[-1], 2)

# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- 3.2 METRIC  -----------------------------------------------------------------------------------
cont_metric = st.container(border=True, horizontal=True)

cont_metric.metric("IP Détecté", ip_detecte, delta=ip_detecte, chart_data=data_metric, chart_type="line", border=True)
cont_metric.metric("IP Banni", ip_banni, delta=ip_banni, delta_color="red",chart_data=data_metric, chart_type="line", border=True)
cont_metric.metric("Connexion Reussi", ip_connexion, delta=ip_connexion, chart_data=data_metric, chart_type="line", border=True)
cont_metric.metric("Echec Connexion", ip_echec, delta=ip_echec, delta_color="orange",chart_data=data_metric, chart_type="line", border=True)
cont_metric.metric("Status HIDS", status_parfeu, delta=status_parfeu, chart_data=data_metric, chart_type="line", border=True)


# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- 2. ASSIGNATION D'UNE COULEUR PAR IP -----------------------------------------------------------

color_mapping = {}
for i, list_ip in enumerate(list_avec_all_list_clean):
    recup_ip = list_ip[0]
    # On assigne une couleur de la liste à l'IP (avec un modulo pour ne pas dépasser la taille de la liste)
    color_mapping[recup_ip] = CYBER_COLORS[i % len(CYBER_COLORS)]

# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- 3.3 MISE EN PAGE ET AFFICHAGE -----------------------------------------------------------------

cont_analyse = st.container(border=True)
col_g, col_r = cont_analyse.columns(2)

# \\\\ Colonne de gauche : Cartes d'attaquants ---------------
with col_g:
    cont_ip_data = col_g.container(border=True)
    info_card(conteneur=cont_ip_data, title="IP Attaquant", text="Ensemble des IP initiant une connexion avec Assiociation de Couleur", color="#6B7FFF", border="top", bg_color="#1e2130")
    
    # Ajout d'une petite zone de scroll 
    st.markdown("<div style='max-height: 450px; overflow-y: auto;'>", unsafe_allow_html=True)
    
    for list_ip in list_avec_all_list_clean:
        recup_ip = list_ip[0]
        # On récupère la couleur unique de cette IP
        ip_color = color_mapping[recup_ip]
        # On affiche la card avec sa couleur
        render_attacker_card(list_ip, color=ip_color)
        
    st.markdown("</div>", unsafe_allow_html=True)
    
# \\\\ Colonne de droite : Carte géographique Mapbox ---------------
with col_r:
    cont_ip_data = col_r.container(border=True)
    info_card(conteneur=cont_ip_data, title="Carte des Attaquants", text="Les IP locales seront assignées à une valeur par défaut (Paris)", color="#B34040", border="top", bg_color="#1e2130")
    
    # PREPARATION des données pour la carte Plotly
    map_pts = []
    for list_ip in list_avec_all_list_clean:
        recup_ip = list_ip[0]
        lat, lon, _ = get_ip_location(recup_ip)
        if lat: 
            map_pts.append({
                "ip": recup_ip,
                "lat": lat,
                "lon": lon
            })
            
    if map_pts:
        df_map = pd.DataFrame(map_pts)
        
        # GENERATION de la carte avec Plotly Express pour avoir les couleurs dynamiques  ---------------
        fig = px.scatter_mapbox(
            df_map,
            lat="lat",
            lon="lon",
            color="ip",
            color_discrete_map=color_mapping, # On applique notre dictionnaire de couleurs  ---------------
            zoom=1,
            hover_name="ip"
        )
        
        # Style sombre pour Mapbox  ---------------
        fig.update_layout(
            mapbox_style="carto-darkmatter",
            margin={"r": 0, "t": 0, "l": 0, "b": 0},
            height=400,
            showlegend=False 
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Aucune coordonnée géographique à afficher pour le moment.")



# ***************************************************************************************************
# ====== 4. JOURNALISATION DES LOGS ==== ============================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°

st.markdown("---")
st.subheader("Journal des événements récents")

if os.path.exists(LOG_DIR):
    # RECUPERATION de tous les fichiers .json
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    
    if log_files:
        # °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
        # --- 1. FILTRES ET TRI --- -------------------------------------------------------------------------

        col_search, col_type, col_date, col_sort = st.columns([2, 1.2, 1.2, 1.2])
        
        with col_search:
            search_ip = st.text_input("Filtrer par IP", icon=":material/id_card:", placeholder="Ex: 127.0.0.1")
            
        with col_type:
            filter_type = st.selectbox("Type", ["Tous", "Banned", "Echec", "Succes"])
            
        with col_date:
            # On ajoute un sélecteur de date 
            selected_date = st.date_input("Date précise", value=None, format="YYYY-MM-DD")
            
        with col_sort:
            # On ajoute le choix du tri
            sort_order = st.selectbox("Ordre", ["Plus récent", "Plus ancien"])

        # °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
        # --- 2. LECTURE ET PARSING DES FICHIERS ------------------------------------------------------------

        all_events = []
        for file in log_files:
            with open(os.path.join(LOG_DIR, file), 'r') as f:
                try:
                    event_data = json.load(f)
                    
                    ## Stockage du Nom pour revenir
                    event_data["filename"] = file
                    all_events.append(event_data)
                except:
                    continue

        # °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
        # --- 3. APPLICATION DES FILTRES --------------------------------------------------------------------

        filtered_events = []
        for event in all_events:
            # Filtre IP
            if search_ip and search_ip not in event.get("ip_source", ""):
                continue
            
            # Filtre Type
            if filter_type != "Tous" and filter_type.lower() not in event.get("event_type", "").lower():
                continue
            
            # Filtre Date précise (YYYY-MM-DD)
            if selected_date:
                # On extrait la partie date (YYYY-MM-DD) du timestamp complet
                event_date_str = event.get("full_timestamp", "")[:10]
                if event_date_str != str(selected_date):
                    continue
                    
            filtered_events.append(event)

        # °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
        # --- 4. TRI DES RÉSULTATS --------------------------------------------------------------------------

        # On trie en fonction du timestamp complet
        if sort_order == "Plus récent":
            filtered_events.sort(key=lambda x: x.get("full_timestamp", ""), reverse=True)
        else:
            filtered_events.sort(key=lambda x: x.get("full_timestamp", ""), reverse=False)

        # °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
        # --- 5. AFFICHAGE DES CARTES -----------------------------------------------------------------------

        if filtered_events:
            col_left, col_right = st.columns(2)
            
            for index, event_data in enumerate(filtered_events):
                if index % 2 == 0:
                    with col_left:
                        render_log_card(event_data)
                else:
                    with col_right:
                        render_log_card(event_data)
        else:
            st.info("Aucun log ne correspond à vos critères de recherche.")
    else:
        st.info("Aucun fichier d'événement individuel trouvé.")
else:
    st.warning("⚠️ Dossier logs d'événements introuvable.")



