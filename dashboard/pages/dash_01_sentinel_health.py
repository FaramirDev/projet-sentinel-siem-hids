
import pandas as pd
import plotly.graph_objects as go
import os
import json
import time
import psutil
import subprocess
from datetime import datetime
from numpy.random import default_rng as rng
from dotenv import load_dotenv
from pathlib import Path
import sys

# ====== CONFIG DE LA RACCINE =========================================================
# Depuis pages/, le parent est dashboard/, et le parent du parent est la racine
BASE_DIR = Path(__file__).resolve().parent.parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# *************************************************************************************
# ====== 1er PARTIE CONFIGURATION =====================================================
from config import BASE_DIR, CORE_DIR, LOGS_SYSTEM
import streamlit as st

load_dotenv(BASE_DIR / ".env")

# --- 1.1 PATH & DIR ------------------------------------------------------------------
LOG_DIR = LOGS_SYSTEM
SCRIPT_DIR = CORE_DIR / "sentinel_monitor_system.py"

ST_BG_COLOR = "#1e2130"


# --- 1.2 FONCTION  -------------------------------------------------------------------
def load_latest_audit():
    files = [f for f in os.listdir(LOG_DIR) if f.startswith("AUDIT_")]
    if not files: return None
    files.sort(reverse=True)
    with open(os.path.join(LOG_DIR, files[0]), 'r') as f:
        files_last = files[0]
        return json.load(f), files_last

def run_script(script_path):
    """Exécute un script python externe."""
    try:
        subprocess.run(["python3", script_path], check=True)
        return True
    except Exception as e:
        st.error(f"Erreur d'exécution : {e}")
        return False

def render_cyber_progress(conteneur, title, value, color_hex):
    bar_color = "#ff4b4b" if value > 85 else color_hex
    
    # Effet néon 
    neon_style = f"box-shadow: 0px 0px 6px {bar_color}, 0px 0px 11px {bar_color}cc;"

    html_content = (
        f"<div style='background-color: #1e2130; padding: 18px; border-radius: 12px; border: 1px solid #2d3142; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.3); margin-bottom: 10px;'>"
        f"<div style='display: flex; justify-content: space-between; margin-bottom: 12px; align-items: center;'>"
        f"<span style='color: #8a8f9e; font-size: 13px; font-weight: bold; letter-spacing: 1px;'>{title.upper()}</span>"
        f"<span style='color: white; font-size: 18px; font-weight: bold; font-family: monospace;'>{value}%</span>"
        f"</div>"
        
        f"<div style='background-color: #12141d; width: 100%; height: 8px; border-radius: 4px; display: flex; align-items: center;'>"
        f"<div style='background-color: {bar_color}; width: {value}%; height: 100%; border-radius: 4px; transition: width 0.5s ease-in-out; {neon_style}'></div>"
        f"</div>"
        f"</div>"
    )
    
    conteneur.markdown(html_content, unsafe_allow_html=True)

def get_service_status(service_name):
    """Vérifie si un service est actif ou non."""
    try:
        # La commande 'is-active' renvoie 'active' ou 'inactive'
        result = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "error"

def manage_service(service_name, action):
    """Exécute start, stop ou restart."""
    # /!\ ATTENTION : Nécessite des droits sudo - Ajout de documentation dans la prochaine version
    try:
        subprocess.run(["sudo", "systemctl", action, service_name], check=True)
        return True
    except Exception as e:
        st.error(f"Erreur lors de l'action {action} : {e}")
        return False

def info_card(conteneur, title, text, color="#BF6BFF", border="left", bg_color="#1e2130"):
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

def extraction_list_service(data):
    list_service = []
    for serv in data:
        list_service.append(serv)

    return list_service

def list_path_detection_alerte(data):
    list_path = 0
    detection_alerte = 0

    for path in data:
        list_path += 1
        for status in path:
            if type(status)==str and "🔴" in status:
                detection_alerte += 1
            else:
                pass

    recup_description = data[path]["description"]
    recup_usage_normal = data[path]["usage_normal"]
    recup_risque_cyber = data[path]["risque_cyber"]

    return list_path, detection_alerte, recup_description, recup_usage_normal, recup_risque_cyber



# --- 1.3 CHARGEMENT DE LA DATA -------------------------------------------------------
data, files_last = load_latest_audit()

if not data:
    st.error("Impossible de charger les données d'audit.")
    st.stop()


# *************************************************************************************
# ====== 2e PARTIE EXTRATION & EXPLOITATION DATA ======================================

# --- EXTRATION DATA ------------------------------------------------------------------
## DATA pour la partie System & Service
sys_info = data["data_systeme"]["data_sys"] 
disk = data["data_systeme"]["data_disk"]
mem = data["data_systeme"]["data_memory"]
procs = data["data_systeme"]["data_memory_high"]
service = data["data_systeme"]["data_service"]
cpu_load = data["data_systeme"]["data_cpu"]



## EXTRACTION SERVICE
SERVICES_MONITOR = extraction_list_service(service)

## Extraction donnée audit security
data_security_path = data["data_audit_security"]

## Extration donnée PATH 
list_path, detection_alerte, recup_description, recup_usage_normal, recup_risque_cyber = list_path_detection_alerte(data_security_path)


# ***************************************************************************************************
# ====== 3e PARTIE INTERFACE DESIGN PAGE ============================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°

# --- 3.1 HEADER DE LA PAGE -------------------------------------------------------------------------
st.title("Diagnostic Vital du Système")

st.caption("L'Audit s'effectue Automatiquement toutes les heures.")
st.caption(f"📂 Dernière analyse effectuée le : {data['data_systeme']['date_actuel']}")

st.markdown("---")
if st.button("Relancer l'Analyse Manuellement", use_container_width=True, icon=":material/directory_sync:"):
    with st.spinner("Audit du systeme en cours..",show_time=True):
        if run_script(SCRIPT_DIR):
                st.toast("Audit terminé !", icon="✅")
                time.sleep(1); st.rerun()

        st.success("Données actualisées !")
        st.rerun()
        

# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- 3.2 LES JAUGES  --------------------------------------------------------------------------------

col_cpu, col_ram, col_disk = st.columns(3)

with col_cpu:
    c = col_cpu.container(border=True)
    render_cyber_progress(c,"Charge CPU", cpu_load["charge_cpu"], "#BF6BFF")

with col_ram:
    r = col_ram.container(border=True)
    render_cyber_progress(r,"Usage RAM", mem['memory_percent'], "#00cc96")

with col_disk:
    n = col_disk.container(border=True)
    render_cyber_progress(n,"Espace Disque", disk['stockage_percent'], "#2450E0")

st.markdown("---")


# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- 3.3 DETAILS ET PROCESSUS ----------------------------------------------------------------------

c_info, c_proc = st.columns([1, 2])

with c_info:
    c_infos = st.container(border=True)
    c_infos.subheader("Identité Machine")
    c_infos.success(f"**Hostname:** {sys_info['name_machine']}")
    c_infos.info(f"**OS:** {sys_info['systeme']}")
    c_infos.info(f"**Version:** {sys_info['version']}" )
    c_infos.info(f"**Release:** {sys_info['release']}")
    
    c_stock = st.container(border=True)
    c_stock.subheader("Stockage")

    total_sk, status_sk = st.columns([1, 2])
    with total_sk:
        st.info(f"**Total:** {disk['stockage_total']} Go")
        st.info(f"**Use:** {disk['stockage_used']} Go")

    with status_sk:
        if disk['stockage_percent'] > 75:
            st.info(f"**Status:** : Warning")  
        else:
            st.success(f"**Status:** : Ok ")  

        st.warning(f"**Libre:** {disk['stockage_free']} Go")

    c_stock.progress(disk['stockage_percent'] / 100, f"{disk['stockage_percent']} %" )

with c_proc:
    c_all_proc = st.container(border=True)
    c_all_proc.subheader("Top Processus Gourmands")
    df_procs = pd.DataFrame.from_dict(procs, orient='index')
    c_all_proc.dataframe(df_procs[['nom', 'memory_percent', 'pid']].head(6), use_container_width=True, hide_index=True)

    c_all_proc.subheader("Kill Process ")
    k = c_all_proc.container(border=True)
    k.markdown("Veuillez **Selectionner** un **Processus** puis Confirmer avant de le Kill.") 

    if not df_procs.empty:
            proc_options = [f"{row['nom']} (PID: {row['pid']})" for _, row in df_procs.iterrows()]
            selected = k.selectbox("Cible :", proc_options)
            confirm_kill = k.checkbox("⚠️ Confirmer Kill")
            if k.button("Kill Process", type="primary", disabled=not confirm_kill, use_container_width=True, icon=":material/cancel:"):
                pid = int(selected.split("PID: ")[1].split(")")[0])
                psutil.Process(pid).terminate()
                st.toast(f"PID {pid} tué"); time.sleep(1); st.rerun()


st.markdown("---")

# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- 3.4 DASHBOARD SERVICE -------------------------------------------------------------------------

c_service = st.container(border=True)
c_service.subheader("Dashboard Service")

row_1_service, row_2_stat = st.columns([1, 2])

row_c_1 = c_service.container(horizontal=True)
row_c_2 = c_service.container(horizontal=True)

changes = list(rng(4).standard_normal(20))
data_metric = [sum(changes[:i]) for i in range(20)]
delta = round(data_metric[-1], 2)

status_global_service = 0
nombre_service_global = 0
for serv in service: 
    nombre_service_global += 1

nombre_service_start = 0
nombre_service_sleep = 0

with c_service:
    with row_1_service:
        for serv in service:
            if serv == "sentinel-log.service":
                row_c_1.success(f"Sentinel HIDS ssh", icon=":material/check_circle:", width=200) 
                nombre_service_start += 1
            elif service[serv] == "active":
                row_c_1.success(f"{serv}", icon=":material/check_circle:", width=150) 
                nombre_service_start += 1
            else:
                row_c_1.error(f"{serv}", icon=":material/close:", width=150) 
                status_global_service += 1
                nombre_service_sleep += 1

    with row_2_stat:
        if status_global_service == 0:
            row_c_2.metric("Santé Service", "OPTIMAL",  delta="Normal", chart_data=data_metric, chart_type="line", border=True)
        else:
            row_c_2.metric("Santé Service", "Warning",  delta="Service non lancé", delta_color="orange", chart_data=data_metric, chart_type="line", border=True)

        row_c_2.metric("Demarré", nombre_service_start, delta=nombre_service_start, chart_data=data_metric, chart_type="line", border=True)
        row_c_2.metric("Arreté", nombre_service_sleep, delta=nombre_service_sleep, chart_data=data_metric, chart_type="line", border=True)
        row_c_2.metric("Total Service Suivi", nombre_service_global, delta="0", chart_data=data_metric, chart_type="line", border=True)



# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- LISTE DES SERVICES À SURVEILLER ---------------------------------------------------------------

cont_service = st.container(border=True)
cont_service.subheader("Contrôle des Services Système")

# CREATION DU TABLEAU POUR LISTER LES SERVICES
for svc in SERVICES_MONITOR:
    col_name, col_status, col_actions = cont_service.columns([2, 1, 3])
    
    status = get_service_status(svc)
    
    with col_name:
        st.info(f"**{svc}**",icon=":material/settings_heart:")
    
    with col_status:
        if status == "active":
            st.success("Actif",icon=":material/check_circle:")
        else:
            st.error("Arrêté",icon=":material/close:")
            
    with col_actions:
        # On aligne les boutons horizontalement
        btn_start, btn_stop, btn_restart = st.columns(3)
        
        if btn_start.button("Lancer le Service", icon=":material/keyboard_double_arrow_right:", key=f"start_{svc}", help=f"Lancer {svc}", disabled=(status=="active"),width=200):
            if manage_service(svc, "start"):
                st.toast(f"{svc} démarré !"); st.rerun()
                
        if btn_stop.button("Arreter le Service ", icon=":material/stop_circle:", key=f"stop_{svc}", help=f"Arrêter {svc}", disabled=(status!="active"),width=200):
            if manage_service(svc, "stop"):
                st.toast(f"{svc} arrêté !"); st.rerun()
                
        if btn_restart.button("Relancer le Service", icon=":material/restart_alt:", key=f"restart_{svc}", help=f"Redémarrer {svc}",width=200):
            if manage_service(svc, "restart"):
                st.toast(f"{svc} redémarré !"); st.rerun()

# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
## ---- DASHBOARD PARH ------------------------------------------------------------------------------

c_cont_path = st.container(border=True)
c_cont_path.subheader("Dashboard Path Critique")

## Status GLOBAL
if detection_alerte == 0:
    status_global = "NORMAL"
else:
    status_global = "CRITIQUE"

c_cont_global_status_path = c_cont_path.container(horizontal=True)

if status_global == "NORMAL":
    c_cont_global_status_path.metric("Statu Global", "NORMAL", delta="normal", chart_data=data_metric, chart_type="line", border=True)
else:
    c_cont_global_status_path.metric("Statu Global", "CRITIQUE", delta="critique", chart_data=data_metric, delta_color="red", chart_type="line", border=True)

c_cont_global_status_path.metric("Path Suivi", list_path, delta=list_path, chart_data=data_metric, chart_type="line", border=True)

if detection_alerte == 0:
    c_cont_global_status_path.metric("Critique Detecté", detection_alerte, delta=detection_alerte, chart_data=data_metric, chart_type="line", border=True)
else:
    c_cont_global_status_path.metric("Critique Detecté", detection_alerte, delta=detection_alerte, chart_data=data_metric, delta_color="red", chart_type="line", border=True)


# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
## ---- DETAIL PATH EXPLAIN -------------------------------------------------------------------------

# Lien CDN pour charger les ICONES Google
google_icons = "<link href='https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200' rel='stylesheet' />"

for path in data_security_path:
    path_data = data_security_path[path]
    
    # 1. Extraction des variables
    recup_perm = path_data.get("permission")
    recup_status_audit = path_data.get("statut_permission", "")
    recup_perm_user = path_data.get("perm_user")
    recup_status_user = path_data.get("statut_perm_user", "")
    recup_status_acces = path_data.get("Statut_audit_acces", "")
    recup_status_modif = path_data.get("Statut_audit_modif", "")
    
    recup_description = path_data.get("description", "Non documenté.")
    recup_usage_normal = path_data.get("usage_normal", "Non spécifié.")
    recup_risque_cyber = path_data.get("risque_cyber", "Non spécifié.")

    # 2. Calcul du statut global
    status_alerte_path = 0
    if "🟢" not in recup_status_audit: status_alerte_path += 1
    if "🟢" not in recup_status_user: status_alerte_path += 1
    if "🟢" not in recup_status_acces: status_alerte_path += 1
    if "🟢" not in recup_status_modif: status_alerte_path += 1

    # Attribution des couleurs
    if status_alerte_path == 0:
        header_color = "#29BA58"  # Vert néon
        badge_status = "🟢"

    else:
        header_color = "#ff4b4b"  # Rouge alerte
        badge_status = f"{status_alerte_path} 🔴 ALERTE(S)"
    
    # EN-TETE HEADER
    expander_title = f"{path}   {badge_status}"
    
    with c_cont_path.expander(expander_title, expanded=False):
        k_cont = st.container()
        
        # 3. Carte principale du chemin (Header)
        k_cont.markdown(
            f"{google_icons}"
            f"<div style='background-color: {ST_BG_COLOR}; padding: 16px; border-radius: 10px; "
            f"border-left: 5px solid {header_color}; border-top: 1px solid #2d3142; "
            f"border-right: 1px solid #2d3142; border-bottom: 1px solid #2d3142; "
            f"box-shadow: 0px 4px 10px rgba(0,0,0,0.3); margin-bottom: 20px;'>"
            f"<span style='color: #8a8f9e; font-size: 11px; font-weight: bold; letter-spacing: 1px; text-transform: uppercase;'>Point de Contrôle Système</span>"
            f"<h3 style='color: white; margin: 6px 0 0 0; font-family: monospace; font-size: 17px;'>{path}</h3>"
            f"</div>",
            unsafe_allow_html=True
        )

        # 4. Grille des badges de Statut
        col_perm, col_prop, col_acc, col_mod = k_cont.columns(4)

        couleur_vert_bg = "#31BD79"

        with col_perm:
            c, icon, lbl = (couleur_vert_bg, "check_circle", f"Perms OK ({recup_perm})") if "🟢" in recup_status_audit else ("#ff4b4b", "release_alert", f"Perms ({recup_perm})")
            st.markdown(f"{google_icons}<div style='background-color: {c}15; color: {c}; border: 1px solid {c}; padding: 10px; border-radius: 8px; font-size: 15px; font-weight: bold; display: flex; align-items: center; justify-content: center; gap: 8px;'><span class='material-symbols-outlined' style='font-size: 18px;'>{icon}</span>{lbl}</div>", unsafe_allow_html=True)

        with col_prop:
            c, icon, lbl = (couleur_vert_bg, "check_circle", f"Proprio OK ({recup_perm_user})") if "🟢" in recup_status_user else ("#ff4b4b", "release_alert", f"Proprio ({recup_perm_user})")
            st.markdown(f"{google_icons}<div style='background-color: {c}15; color: {c}; border: 1px solid {c}; padding: 10px; border-radius: 8px; font-size: 15px; font-weight: bold; display: flex; align-items: center; justify-content: center; gap: 8px;'><span class='material-symbols-outlined' style='font-size: 18px;'>{icon}</span>{lbl}</div>", unsafe_allow_html=True)

        with col_acc:
            c, icon, lbl = (couleur_vert_bg, "check_circle", "Accès OK") if "🟢" in recup_status_acces else ("#ffaa00", "warning", "Accès récent")
            st.markdown(f"{google_icons}<div style='background-color: {c}15; color: {c}; border: 1px solid {c}; padding: 10px; border-radius: 8px; font-size: 15px; font-weight: bold; display: flex; align-items: center; justify-content: center; gap: 8px;'><span class='material-symbols-outlined' style='font-size: 18px;'>{icon}</span>{lbl}</div>", unsafe_allow_html=True)

        with col_mod:
            c, icon, lbl = (couleur_vert_bg, "check_circle", "Modifs OK") if "🟢" in recup_status_modif else ("#ffaa00", "warning", "Modif récente")
            st.markdown(f"{google_icons}<div style='background-color: {c}15; color: {c}; border: 1px solid {c}; padding: 10px; border-radius: 8px; font-size: 15px; font-weight: bold; display: flex; align-items: center; justify-content: center; gap: 8px;'><span class='material-symbols-outlined' style='font-size: 18px;'>{icon}</span>{lbl}</div>", unsafe_allow_html=True)

        # AJUSTEMENT Espacement forcé manuellement entre la ligne supérieure et inférieure
        k_cont.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)
        
        # 5. Grille d'informations columns
        col_desc, col_usage, col_risk = k_cont.columns(3)

        def render_audit_info_card(col, title, text, color_hex, icon):
            col.markdown(
                f"{google_icons}"
                f"<div style='background-color: #12141d; padding: 14px; border-radius: 8px; "
                f"border-top: 3px solid {color_hex}; border-left: 1px solid #2d3142; "
                f"border-right: 1px solid #2d3142; border-bottom: 1px solid #2d3142; "
                f"height: 90px; box-sizing: border-box; display: flex; flex-direction: column; justify-content: flex-start;'>"
                f"<div style='display: flex; align-items: center; gap: 8px; margin-bottom: 8px;'>"
                f"<span class='material-symbols-outlined' style='color: {color_hex}; font-size: 18px;'>{icon}</span>"
                f"<span style='color: #8a8f9e; font-size: 15px; font-weight: bold; letter-spacing: 1px; text-transform: uppercase;'>{title}</span>"
                f"</div>"
                f"<div style='color: white; font-size: 14px; line-height: 1.4; overflow-y: auto; flex-grow: 1;'>{text}</div>"
                f"</div>",
                unsafe_allow_html=True
            )

        render_audit_info_card(col_desc, "Description", recup_description, "#2450E0", "description")
        render_audit_info_card(col_usage, "Usage Normal", recup_usage_normal, "#00cc96", "shield")
        render_audit_info_card(col_risk, "Risque Cyber", recup_risque_cyber, "#ff4b4b", "gpp_maybe")

        k_cont.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)


## END
