
import pandas as pd
import socket
import psutil
import plotly.graph_objects as go
import os
import json
import time
import subprocess
from datetime import datetime
from numpy.random import default_rng as rng
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv
import sys
from pathlib import Path
import ipaddress

# ====== CONFIG DE LA RACCINE =========================================================
# Depuis pages/, le parent est dashboard/, et le parent du parent est la racine
BASE_DIR = Path(__file__).resolve().parent.parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# *************************************************************************************
# ====== 1er PARTIE CONFIGURATION =====================================================
from config import BASE_DIR, CORE_DIR, LOGS_SCANS_DIR
import streamlit as st

load_dotenv(BASE_DIR / ".env")

# --- 1.1 PATH & DIR ------------------------------------------------------------------
LOG_DIR = LOGS_SCANS_DIR
SCRIPT_SCAN_RESEAU = CORE_DIR / "sentinel_scan_vulnerability.py"

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

def extration_data_reseau(data_scan_reseau):
    ## VAR setup
    recup_machine_detecte = 0
    port_ouvert_reperer = 0
    os_Linux = 0
    os_windows = 0
    banner_found = 0

    for ip in data_scan_reseau:
        recup_machine_detecte += 1
        recup_dic_ip = data_scan_reseau[ip]
        
        for all_data_ip in recup_dic_ip:
            recup_all_data = recup_dic_ip[all_data_ip]

            if recup_all_data == "Linux/Unix":
                os_Linux += 1
            elif recup_all_data == "Windows":
                os_windows += 1       
            try:
                for donne in recup_all_data:
                    recup_in_donne = recup_all_data[donne]
                    if donne == "Banner" and recup_in_donne != "erreur : timed out":
                        banner_found += 1

                    elif "🟢" in recup_in_donne:
                        port_ouvert_reperer += 1
            except:
                pass
            
    return recup_machine_detecte, port_ouvert_reperer, os_Linux, os_windows, banner_found

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    if_list = []
    for iface_name, iface_addresses in interfaces.items():
        for addr in iface_addresses:
            # On ne garde que les adresses IPv4 (famille AF_INET)
            if addr.family == socket.AF_INET:
                if_list.append({"interface": iface_name, "ip": addr.address, "netmask": addr.netmask})
    return if_list

def test_internet_connection():
    try:
        # On tente de se connecter au DNS de Google sur le port 53 en 2 secondes max
        socket.setdefaulttimeout(2)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True, "Connecté"
    except socket.error:
        return False, "Déconnecté"

def render_neon_title(title, subtitle="", color_hex="#BF6BFF", icon=""):
    """
    Génère un titre principal avec un effet néon et une icône Google Fonts.
    """
    # Construction du style d'effet néon
    neon_style = f"color: ##BF6BFF; text-shadow: 0 0 2px {color_hex}, 0 0 2px {color_hex}, 0 0 2px {color_hex};"
    
    html_content = (
        f"<div style='margin-bottom: 20px;'>"
        f"<div style='display: flex; align-items: center; gap: 0px;'>"
        f"<span class='material-symbols-outlined' style='font-size: 36px; color: {color_hex}; text-shadow: 0 0 10px {color_hex};'>{icon}</span>"
        f"<h1 style=\"margin: 0; font-family: 'Courier New', monospace; font-size: 36px; font-weight: 1000; {neon_style} letter-spacing: 2px;\">"
        f"{title.upper()}</h1>"
        f"</div>"
    )
    
    # Ajout du sous-titre si présent
    if subtitle:
        html_content += f"<div style='color: #8a8f9e; font-size: 14px; margin-top: 6px; margin-left: 12; font-family: sans-serif;'>{subtitle}</div>"
        
    html_content += "</div>"
    
    st.markdown(html_content, unsafe_allow_html=True)

def render_cyber_metric(title, value, delta, color_hex="#2450E0", icon="devices"):
    """
    Génère une carte de métrique avec effet néon et icône Google.
    """
    # Effet neon
    neon_glow = f"box-shadow: 0px 0px 5px {color_hex}, 0px 0px 15px {color_hex}33;"
    
    html_metric = (
        f"<div style='background-color: #1e2130; padding: 16px; border-radius: 12px; "
        f"border-top: 4px solid {color_hex}; border-left: 1px solid #2d3142; "
        f"border-right: 1px solid #2d3142; border-bottom: 1px solid #2d3142; {neon_glow} "
        f"display: flex; flex-direction: column; justify-content: space-between; height: 110px;'>"
        
        # En-tête : Titre + Icone Google
        f"<div style='display: flex; justify-content: space-between; align-items: center;'>"
        f"<span style='color: #8a8f9e; font-size: 11px; font-weight: bold; letter-spacing: 1px; text-transform: uppercase;'>{title}</span>"
        f"<span class='material-symbols-outlined' style='color: {color_hex}; font-size: 22px; text-shadow: 0 0 8px {color_hex};'>{icon}</span>"
        f"</div>"
        
        # Corps : Valeur + Delta (évolution)
        f"<div style='display: flex; justify-content: space-between; align-items: baseline; margin-top: auto;'>"
        f"<span style='color: white; font-size: 28px; font-weight: 800; font-family: monospace;'>{value}</span>"
        f"<span style='background-color: {color_hex}22; color: {color_hex}; border: 1px solid {color_hex}; "
        f"padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: bold; font-family: monospace;'>+{delta}</span>"
        f"</div>"
        
        f"</div>"
    )
    
    st.markdown(html_metric, unsafe_allow_html=True)


# --- 1.3 CHARGEMENT DE LA DATA -------------------------------------------------------
data, files_last = load_latest_audit()

if not data:
    st.error("Impossible de charger les données d'audit.")
    st.stop()

# *************************************************************************************
# ====== 2e PARTIE EXTRATION & EXPLOITATION DATA ======================================

# --- EXTRATION DATA ------------------------------------------------------------------
recup_machine_detecte, port_ouvert_reperer, os_Linux, os_windows, banner_found = extration_data_reseau(data)

is_connected, status_label = test_internet_connection()
color_status = "#00cc96" if is_connected else "#ff4b4b"
icon_status = "wifi" if is_connected else "wifi_off"

# --- POUR METRIC ---------------------------------------------------------------------

changes = list(rng(4).standard_normal(20))
data_metric = [sum(changes[:i]) for i in range(20)]
delta = round(data_metric[-1], 2)


# ***************************************************************************************************
# ====== 3e PARTIE INTERFACE DESIGN PAGE ============================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°

# --- 3.1 HEADER DE LA PAGE -------------------------------------------------------------------------


render_neon_title(
    title="Réseau & Scan Vulnérabilité", 
    color_hex="#2450E0", # Bleu
)

cont_header = st.container(horizontal=True)
col_header_1, col_header_2 = cont_header.columns(2)

with col_header_1:
    col_header_1.caption(f"📂 Dernier Scan effectuée : {files_last}")
    # Gestion dynamique de la couleur et de la lueur selon le statut
    if is_connected:
        color_status = "#00cc96"  # Vert néon
        icon_status = "Wifi"
        status_label = "Connecté"
        # Effet de lueur néon verte
        neon_glow = f"box-shadow: 0px 0px 5px {color_status}, 0px 0px 15px {color_status}66;"
    else:
        color_status = "#ff4b4b"  # Rouge néon
        icon_status = "wifi_off"
        status_label = "Déconnecté"
        # Effet de lueur néon rouge
        neon_glow = f"box-shadow: 0px 0px 5px {color_status}, 0px 0px 15px {color_status}66;"

    # Construction de la carte en une seule ligne continue
    html_internet_card = (
        f"<div style='background-color: #1e2130; padding: 16px; border-radius: 12px; "
        f"max-width: 450px; margin: -50 auto; "  
        f"border-left: 4px solid {color_status}; border-top: 1px solid #2d3142; border-right: 1px solid #2d3142; "
        f"border-bottom: 1px solid #2d3142; {neon_glow} display: flex; justify-content: space-between; align-items: center;'>"
        f"<div style='display: flex; align-items: center; gap: 12px;'>"
        f"<span class='material-symbols-outlined' style='color: {color_status}; font-size: 26px; text-shadow: 0 0 10px {color_status};'>{icon_status}</span>"
        f"<div>"
        f"<div style='color: #8a8f9e; font-size: 11px; font-weight: bold; letter-spacing: 1px; margin-left: 10px; text-transform: uppercase;'>Liaison WAN</div>"
        f"<div style='color: white; font-size: 15px; font-weight: bold; margin-top: 2px; margin-left: 10px'>Connexion Internet</div>"
        f"</div>"
        f"</div>"
        f"<span style='background-color: {color_status}22; color: {color_status}; border: 1px solid {color_status}; "
        f"padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; font-family: monospace;'>{status_label.upper()}</span>"
        f"</div>"
    )

    col_header_1.markdown(html_internet_card, unsafe_allow_html=True)

# --- 3.2 INTERFAC RESEAU DETECTEES ----------------------------------------------------------------

st.markdown("---")

st.subheader("Interfaces Réseau Détectées")
ifaces = get_network_interfaces()

col_if = st.columns(len(ifaces) if ifaces else 1)
for i, iface in enumerate(ifaces):
    with col_if[i]:
        # On définit la couleur néon 
        color_neon = "#2450E0"

        # AJUSTEMENT de L'effet néon: 0px horizontal, 0px vertical, 5px de flou intense, 15px de halo plus large
        neon_glow = f"box-shadow: 0px 0px 5px {color_neon}, 0px 0px 15px {color_neon}44;"

        st.markdown(
            f"<div style='background-color: #1e2130; padding: 14px; border-radius: 10px; "
            f"border-left: 3px solid {color_neon}; border-top: 1px solid #2d3142; "
            f"border-right: 1px solid #2d3142; border-bottom: 1px solid #2d3142; {neon_glow}'>"
            f"<div style='color: #8a8f9e; font-size: 11px; font-weight: bold; letter-spacing: 1px;'>{iface['interface'].upper()}</div>"
            f"<div style='color: white; font-size: 16px; font-family: monospace; font-weight: bold; margin-top: 6px; margin-bottom: 4px;'>{iface['ip']}</div>"
            f"<div style='color: #646a78; font-size: 11px;'>Masque : {iface['netmask']}</div>"
            f"</div>",
            unsafe_allow_html=True)


# # --- 3.2 LANCER UN SCAN  ----------------------------------------------------------------

st.markdown("---")

cont_relancer_scan = st.container(border=True)

cont_relancer_scan.subheader("Lancer un scan réseau")

# On extrait les réseaux disponibles à partir des interfaces pour proposer un choix
network_choices = [f"{iface['interface']} ({iface['ip']})" for iface in ifaces]
selected_iface = cont_relancer_scan.selectbox("Sélectionnez l'interface à scanner", network_choices)

# Champ libre si l'utilisateur veut entrer un CIDR manuellement (ex: 192.168.1.0/24)
custom_range = cont_relancer_scan.text_input("Ou entrez un sous-réseau spécifique (CIDR)", placeholder="Ex: 192.168.1.0/24")

if cont_relancer_scan.button("Exécuter le Scan",  icon=":material/not_started:"):
    # On détermine la cible du scan
    target_scan = custom_range.strip() if custom_range else ""
    
    with cont_relancer_scan.spinner(f"Scan en cours sur {target_scan}..."):
        try:
            if not target_scan:
                try:
                    # 1. On extrait l'IP de l'interface : "eth0 (192.168.1.50)" -> "192.168.1.50"
                    ip_extracted = selected_iface.split("(")[1].split(")")[0]
                    
                    # 2. On transforme le .X en .0/24
                    octets = ip_extracted.split(".")
                    target_scan = ".".join(octets[:3]) + ".0/24"
                    
                except IndexError:
                    st.error("Impossible d'extraire la cible de l'interface sélectionnée.")
                    target_scan = None

            # 3. Lancement du scan si la cible est valide
            if target_scan:
                st.info(f"Cible calculée pour le scan : **{target_scan}**")
                result = subprocess.run(
                    ["sudo", "/usr/bin/python3", SCRIPT_SCAN_RESEAU, target_scan],
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                st.success("✅ Scan exécuté avec succès !")
            
        except subprocess.CalledProcessError as e:
            # On affiche l'erreur exacte retournée par le script Python
            st.error("❌ Le script de scan a planté pendant son exécution.")
            
            with st.expander("🔍 Voir le détail technique de l'erreur (Traceback)"):
                if e.stderr:
                    st.code(e.stderr, language="python")
                elif e.stdout:
                    st.code(e.stdout, language="text")
                else:
                    st.write("Aucun message d'erreur n'a été capturé.")



# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- 3.2 DASHBOARD  ----------------------------------------------------------------------------------


# --- 3.2 SELECTION DU LOG & PATH  ----------------------------------------------------------------------------------
cont_global_selection_analyse = st.container(border=True)

cont_choice_paht = cont_global_selection_analyse.container(border=True)

cont_choice_paht.subheader("Historique des Scans Réseau")

if os.path.exists(LOG_DIR):
    # On liste tous les fichiers de scan enregistrés
    scan_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    
    if scan_files:
        # Tri inverse pour avoir les plus récents en premier
        scan_files.sort(reverse=True)
        
        selected_scan_file = cont_choice_paht.selectbox("Sélectionnez un scan à analyser", scan_files)
        
        # Lecture du fichier de scan sélectionné
        with open(os.path.join(LOG_DIR, selected_scan_file), "r") as f:
            try:
                # --- CHANGEMENT DE DATA par SELECTION ---------------------------------------------------------------------------------
                scan_data = json.load(f)

                # --- RECALCUL DES METRICS --------------------------------------------------------------------------------- 
                recup_machine_detecte, port_ouvert_reperer, os_Linux, os_windows, banner_found = extration_data_reseau(scan_data)

            except Exception as e:
                cont_choice_paht.error(f"Erreur de lecture du fichier : {e}")
    else:
        cont_choice_paht.info("Aucun historique de scan trouvé.")
else:
    cont_choice_paht.warning("⚠️ Dossier des logs de scan introuvable.")


cont_global = cont_global_selection_analyse.container(horizontal=True)

cont_global.metric("Machine Detecté", recup_machine_detecte, delta=recup_machine_detecte, chart_data=data_metric, chart_type="line", border=True)
cont_global.metric("Port Ouvert Repéré", port_ouvert_reperer, delta=port_ouvert_reperer, chart_data=data_metric, chart_type="line", border=True)
cont_global.metric("OS Linux Detecté", os_Linux, delta=os_Linux, chart_data=data_metric, chart_type="line", border=True)
cont_global.metric("OS Windows Detecté", os_windows, delta=os_windows, chart_data=data_metric, chart_type="line", border=True)
cont_global.metric("Banner Trouvé", banner_found, delta=banner_found, chart_data=data_metric, chart_type="line", border=True)

grah_cont = cont_global_selection_analyse.container(border=True)
grah_cont.subheader("Machines Decouvert")

# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
# --- 3.3 DETAILS -----------------------------------------------------------------------------------

nl, nr = grah_cont.columns([2, 1])
with nl:
    for ip, det in scan_data.items():  
        with grah_cont.expander(f"{ip} ({det.get('Name DNS', 'N/A')})"):
            recup_adresse_mac = f"{det.get('Addresse MAC')}"
            recup_os_detecte = f"{det.get('OS Detecte')}"

            ## METRIC
            col_g, col_r = st.columns(2)

            info_card(conteneur=col_g,title="Adresse Mac", text=recup_adresse_mac, color="#BF6BFF", border="left", bg_color="#1e2130")  
            info_card(conteneur=col_r,title="OS Détecé", text=recup_os_detecte, color="#4351BA", border="left", bg_color="#1e2130")  

            rows = [{"Port": k, "Svc": v["Service"], "Statut": v["statut"] , "Banner" : v.get("Banner", "N/A")} for k,v in det.items() if isinstance(v, dict) and "statut" in v]
            st.table(pd.DataFrame(rows))

