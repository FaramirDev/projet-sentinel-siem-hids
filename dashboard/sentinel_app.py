
import os
import sys
from dotenv import load_dotenv
from pathlib import Path
from PIL import Image

# *************************************************************************************
# ====== 1er PARTIE CONFIGURATION =====================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°

# RECUPERATION chemin de la racine (Projet-Sentinel-Dashboard)
# __file__ est dans dashboard/, son parent est la racine du projet.
BASE_DIR = Path(__file__).resolve().parent.parent

# FORCER Python à regarder à la racine du projet pour trouver config.py
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# *************************************************************************************
# ====== CONFIGURATION ENV & PATH PARENT ===================================
from config import BASE_DIR, IMAGES_DIR
import streamlit as st

load_dotenv(BASE_DIR / ".env")

st.set_page_config(page_title="Sentinel SIEM", page_icon="🛡️", layout="wide")


# *************************************************************************************
# ====== 2e PARTIE EXTRATION & EXPLOITATION DATA ======================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
dashboard   = st.Page("pages/dashboard.py", title="Accueil", icon=":material/home:", default=True)
dash_health = st.Page("pages/dash_01_sentinel_health.py", title="Santé Serveur", icon=":material/ecg:")
dash_reseau = st.Page("pages/dash_02_sentinel_reseau.py", title="Scan Réseau", icon=":material/globe:")
dash_hids   = st.Page("pages/dash_03_sentinel_hids.py", title="HIDS SSH", icon=":material/shield_with_heart:")

## --- Path image -----------------------------------------------------------------------
LOGO_1 = IMAGES_DIR / "sentinel-logo-v2.png"
LOGO_2 = IMAGES_DIR / "sentinel-logo-v3.png"
ICON = IMAGES_DIR / "sentinel-logo-96.png"

# ***************************************************************************************************
# ====== 3e PARTIE INTERFACE DESIGN PAGE ============================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
st.logo(LOGO_2, size="large", icon_image=ICON)

## -- SET-UP PAGE NAVIGATIOB  -----------------------------------------------------------------------
pg = st.navigation({
    "Général": [dashboard],
    "Analyses": [dash_health, dash_reseau, dash_hids]
})

## -- LANCEMENT PAGE NAVIGATION ---------------------------------------------------------------------
pg.run()


# ***************************************************************************************************
# ====== 4e PARTIE SIDE BARD =======================================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
with st.sidebar:
    ## AJOUTER UN ECART
    st.markdown("<br>" * 15, unsafe_allow_html=True) 
    st.divider()
    
    # -- Couleur néon principale ---------------------
    color_neon = "#BF6BFF"
    
    # -- LOGO EN LIGNE -------------------------------
    logo_html = (
        f"<div style='text-align: center; padding: 15px 10px; background-color: #12141d; "
        f"border-radius: 10px; border: 1px solid #2d3142; box-shadow: 0px 4px 12px rgba(0, 0, 0, 0.5); margin-bottom: 15px;'>"
        f"<span style=\"font-family: 'Courier New', monospace; font-size: 22px; font-weight: 900; color: #fff; "
        f"letter-spacing: 3px; text-shadow: 0 0 5px #fff, 0 0 10px {color_neon}, 0 0 20px {color_neon}, 0 0 35px {color_neon};\">"
        f"SENTINEL</span>"
        f"<div style='font-size: 10px; color: #646a78; text-transform: uppercase; letter-spacing: 2px; margin-top: 8px; font-family: sans-serif;'>"
        f"Security Lab</div>"
        f"</div>"
    )
    
    st.markdown(logo_html, unsafe_allow_html=True)
    
    # -- Informations de version et de copyright en ligne continue  -----------------------------
    footer_html = (
        f"<div style='text-align: center; font-size: 11px; color: #646a78; line-height: 1.6; font-family: sans-serif;'>"
        f"© 2026 Sentinel Security Lab • <b>v1.2.5</b><br>"
        f"<span style='color: #B2B5C2;'>Made by Alexis Rousseau</span>"
        f"</div>"
    )
    
    st.markdown(footer_html, unsafe_allow_html=True)