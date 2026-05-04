import shutil, subprocess, psutil, os, time, csv, pwd, stat, json, requests, sys
from datetime import date, datetime
from dotenv import load_dotenv
from pathlib import Path

# *************************************************************************************
# ====== CONFIGURATION  ENV & PATH =====================================================
# °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°

# RECUPERATION chemin de la racine (Projet-Sentinel-Dashboard)
# __file__ est dans core/, son parent est la racine du projet.
BASE_DIR = Path(__file__).resolve().parent.parent

# On force Python à regarder à la racine du projet pour trouver config.py
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# *************************************************************************************
# ====== CONFIGURATION ENV & PATH PARENT ===================================
from config import BASE_DIR, LOGS_SYSTEM, DATA_SYSTEM_MONITOR_DIR
load_dotenv(BASE_DIR / ".env")


# *************************************************************************************
# ====== Cartouche SENTINEL HEALTH ====================================================

# Autheur : Alexis Rousseau - Ingenieur | Admin Systeme Reseau et Cybersécurité
# mail : alexisrousseau.work@proton.me
# Date creation : 23/04/2026
# Date Mise A jours : 02/05/2026
# Vesion : v3.1 - Clean Code - Ajout Fonctionnalite Carte réseau & Check Connexion internet
# --
# Description : Sentinel Heath est un outil d'Audit de systeme, Analysant l'état actuel de la machine, DISK, Service, Memoire
# Audit des paths critiques Acces & Modification h-60 minutes pour une remonté d'alerte
# Execution de Sentinel-Health toutes les 60 minutes & remonté d'Alerte via Discord
# --
# Tracabilité via une DATA centralisé des LOGS 
# Script sous licence CC BY-NC 4.0


# *************************************************************************************
# ====== 1er PARTIE CONFIGURATION =====================================================

# --- 1.1 Load env & path(for cron) ---------------------------------------------------
load_dotenv()

# --- 1.2 LOADPATH & VAR SERVICE  -----------------------------------------------------
path="/"
path_write_log = LOGS_SYSTEM
os.makedirs(path_write_log, exist_ok=True)

# --- LIST SERVICE TO CHECK  ----------------------------------------------------------
list_service = ["ssh","ufw","docker","mysql","sentinel-log.service"]


## --- 1.3 DATA CYBER  ----------------------------------------------------------------
data_csv_security = DATA_SYSTEM_MONITOR_DIR
data_all_security = {}

## --- 1.4 WEBHOOB  -------------------------------------------------------------------
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL_SYSTEM")   

if not WEBHOOK_URL:
    print("ERROR de chargement de l'url Webook")


# *************************************************************************************
# ====== FONCTION TOOLS ===============================================================

def afficher_date():
    date_actuel = datetime.now().strftime("%Y-%m-%d-%H%M")
    print("\n=================")
    print("---- RAPPORT ----")
    print(f"Date Actuel : {date_actuel}")

    return date_actuel

def recup_etat_disk(path_env):
    ## recup all space disk
    recup_disk_all = shutil.disk_usage(path_env)

    ## recup All - Used - Free // Octer
    recup_all_space_path = recup_disk_all[0]
    recup_used_space_path = recup_disk_all[1]
    recup_free_space_path = recup_disk_all[2]

    ## Pourcentage Utilise 
    percent_used_total = round(recup_used_space_path / recup_all_space_path * 100,2)

    ## Conversion en gigaoctet 1024**3
    conv_octet = 1024**3
    convert_all = round(recup_all_space_path / conv_octet,2)
    convert_used = round(recup_used_space_path / conv_octet,2)
    convert_free = round(recup_free_space_path / conv_octet,2)

    ## Etabli Criticite 
    Seuil_critique_orange = 75
    Seuil_critique_rouge = 90

    value_critique = 0

    if percent_used_total >= Seuil_critique_rouge:
        value_critique = 100
    elif percent_used_total >= Seuil_critique_orange and percent_used_total < Seuil_critique_rouge:
        value_critique = 50
    else: 
        pass 

    ## Stock in Dictionnaire Disk 
    dic_stockage_disk = {}
    dic_stockage_disk["stockage_total"] = convert_all
    dic_stockage_disk["stockage_used"] = convert_used
    dic_stockage_disk["stockage_free"] = convert_free
    dic_stockage_disk["stockage_percent"] = percent_used_total

    if value_critique >= Seuil_critique_rouge:
        dic_stockage_disk["stockage_status"] = f"🔴 Stockage Status : {percent_used_total} > 90% Critique"
    elif percent_used_total >= Seuil_critique_orange and percent_used_total < Seuil_critique_rouge:
        dic_stockage_disk["stockage_status"] = f"🟠 Stockage Status : {percent_used_total} > 75% Warning"
    else: 
        dic_stockage_disk["stockage_status"] = f"🟢Stockage Status : {percent_used_total} < 75% Ok"

    
    ## RAPPORT 
    print("\n================================")
    print("----- RAPPORT Etat Disque ------")
    print(f"Espace Disque Full : {convert_all} Go")
    print(f"Espace Disque Utilisé : {convert_used} Go")
    print(f"Espace Disque Libre : {convert_free} Go\n")
    print(f"ETAT DISQUE remplie de : {percent_used_total} %")

    if value_critique == 100:
        print(f">> 🔴 ALERTE ROUGE ! Seuil Critique de {Seuil_critique_rouge} % atteind !")
    elif value_critique == 50:
        print(f">> 🟠 Attention Espace Disque bientot full, seuil {Seuil_critique_orange} % dépassé !")
    else:
        print(">> 🟢 Tout est ok ! ")

    return dic_stockage_disk
    
def check_service(service_list):
    list_etat = ["inactive", "active"]
    dic_etat_service = {}
    try:
        for service in service_list:
            commande = subprocess.run(["systemctl","is-active",service], capture_output=True, text=True)
            recupere_sortie = commande.stdout.strip()

            dic_etat_service[service] = recupere_sortie
        
        print("\n=======================================")
        print("----- Check Service Personnalisé ------")
        for service in dic_etat_service:
            if dic_etat_service[service] == list_etat[0]:
                print(f"Service : {service}")
                print(f">> Statut : 🔴 Pas Activé !\n")

            elif dic_etat_service[service] == list_etat[1]:
                print(f"Service : {service}")
                print(f">> Statut : 🟢 Activé !\n")
            else:
                print("Error, impossible d'afficher le statut !")

    except FileNotFoundError:
            print("Nous avons rencontrez une erreur.")

    return dic_etat_service
    
def check_memory_high():
    list_proc = []
    for proc in psutil.process_iter(['name', 'memory_percent', 'pid']):
        recup_infos_proc = proc.info
        list_proc.append(recup_infos_proc)
    
    ## Clean et Ranger Liste 
    list_clean_memory_proc = sorted(list_proc, key=lambda proc: proc["memory_percent"])
    list_clean_memory_proc.reverse()

    ## RAPPORT Proces
    print("\n===========================================")
    print("----- Check most HIGH Process Memory ------")
    start = 1
    max = 6
    
    ## Dic Data Process
    dic_data_process_high = {}

    for proces in list_clean_memory_proc:
        if start <= max:
            recup_memory_proces = round(proces["memory_percent"],2)
            recup_name_proces = proces["name"]
            recup_pid_proces = proces["pid"]

            ## DATA Dic 
            data_proces = {}
            data_proces["pid"] = recup_pid_proces
            data_proces["nom"] = recup_name_proces
            data_proces["memory_percent"] = recup_memory_proces   

            statut_memory_high = ""

            print(f"Name Process : {recup_name_proces}")
            print(f"PID : {recup_pid_proces}")
            if recup_memory_proces >= 35 and recup_memory_proces < 50:
                print(f"Percent Memory Process Actuel : {recup_memory_proces} % 🟠 - Attention Consommation Elevé\n")
                statut_memory_high = f"🟠 Memoire Process : {recup_memory_proces}% > 35% Seuil Warning | Pid : {recup_pid_proces} | Nom : {recup_name_proces}"
            elif recup_memory_proces >= 50:
                print(f"Percent Memory Process Actuel : {recup_memory_proces} % 🔴 - Consommation Critique !\n")
                statut_memory_high = f"🔴 Memoire Process : {recup_memory_proces}% > 50% Seuil Warning | Pid : {recup_pid_proces} | Nom : {recup_name_proces}"
            else: 
                print(f"Percent Memory Process Actuel : {recup_memory_proces} % 🟢 - Seuil Normale\n")
                statut_memory_high = f"🟢 Memoire Process : {recup_memory_proces}% - Seuil Ok"

            data_proces["statut"] = statut_memory_high   

            dic_data_process_high[recup_pid_proces] = data_proces 

            start += 1           
        else: pass

    return dic_data_process_high

def check_memory():
    mem = psutil.virtual_memory()
    total_memory = round(mem.total / (1024**3),2)
    free_memory = round(mem.free / (1024**3),2)
    used_memory = round(mem.used / (1024**3),2)
    percent_memory = mem.percent

    ## RAPORT
    print("\n============================")
    print("------- RAPPORT Memory -----")
    print(f"Memoire Total : {total_memory} Go")
    print(f"Memoire Libre : {free_memory} Go")
    print(f"Memoire Utilisé : {used_memory} Go")
    print(f"\nPourcentage Utilisé : {percent_memory} %")

    statut_mem = ""
    if percent_memory >= 60 and percent_memory <80: 
        print(">> Status : 🟠 Attention dépassement du Seuil de 60%")
        statut_mem = f"🟠 Memoire {percent_memory} > 60% Seuil Warning"
    elif percent_memory >= 80:
        print(">> Status : 🔴 Critique dépassement du Seuil de 80%")
        statut_mem = f"🔴 Memoire {percent_memory} > 80% Seuil Critique"
    else:
        print(">> Status : 🟢 Seuil Normale ")
        statut_mem = f"🟢 Memoire {percent_memory} < 60% Seuil Normale "

    ## Data memory
    dic_data_memory = {}
    dic_data_memory["memory_total"] = total_memory
    dic_data_memory["memory_used"] = used_memory
    dic_data_memory["memory_free"] = free_memory
    dic_data_memory["memory_percent"] = percent_memory
    dic_data_memory["memory_statut"] = statut_mem

    return dic_data_memory 

def afficher_systeme():
    dict_systeme = {}
    infos_all = os.uname()
    infos_sys = infos_all.sysname
    infos_name_machine = infos_all.nodename
    infos_release = infos_all.release
    infos_version = infos_all.version

    ## Ajout Dictionnaire Systeme
    dict_systeme["systeme"] = infos_sys
    dict_systeme["name_machine"] = infos_name_machine
    dict_systeme["version"] = infos_version
    dict_systeme["release"] = infos_release

    ## RAPPORT Terminal
    print("\n=========================")
    print("----- Infos Systeme -----")
    print(f"Nom Machine : {infos_name_machine}")
    print(f"Systeme : {infos_sys}")
    print(f"Release : {infos_release}")
    print(f"Version : {infos_version}")

    return dict_systeme

def check_cup_():
    data_cpu = {}

    cpu_load = psutil.cpu_percent(interval=1)
    data_cpu["charge_cpu"] = cpu_load

    return data_cpu

# *************************************************************************************
# ====== APPLY FONCTION n°1 - RECUP DATA ==============================================

actuel_date = afficher_date()
data_sys = afficher_systeme()
data_disk = recup_etat_disk(path)
data_service = check_service(list_service)
data_memory = check_memory()
data_memory_high = check_memory_high()
data_cpu = check_cup_()

## All Data -- AUDIT Machine Setup
data_check_machine = {}
data_check_machine["date_actuel"] = actuel_date
data_check_machine["data_sys"] = data_sys
data_check_machine["data_disk"] = data_disk
data_check_machine["data_service"] = data_service
data_check_machine["data_memory"] = data_memory
data_check_machine["data_memory_high"] = data_memory_high
data_check_machine["data_cpu"] = data_cpu

# *************************************************************************************
# ====== APPLY FONCTION n° 2 ==========================================================

## 1. Def Fonction Check Cyber
def convert_second_to_dhms(input_sec):
    days = input_sec // 86400
    input_sec %= 86400

    hours = input_sec // 3600
    input_sec %= 3600

    minutes = input_sec // 60
    input_sec %= 60

    return days, hours, minutes, input_sec

def check_path_time(data): 
    recup_data_path = data["path"] 
    ## 1. RECUP Temps actuel en seconde
    temps_actuel = time.time()

    ## 2. RECUP Temps Last Modif Fichier en seconde
    recup_time_last_modif = os.path.getmtime(recup_data_path) 

    ## 3. RECUP Temps Last Acces en seconde 
    recup_time_last_acces = os.path.getatime(recup_data_path)

    ## CALCUL DIFERENCE Actuel - Last modif
    calcul_seconde_dif_modif = temps_actuel - recup_time_last_modif 
    d2,h2,m2,s2 = convert_second_to_dhms(calcul_seconde_dif_modif)

    ## Cacul Dif Actuel - Last Acces
    calcul_seconde_dif_acces = temps_actuel - recup_time_last_modif 
    d3,h3,m3,s3 = convert_second_to_dhms(calcul_seconde_dif_acces)

    data["Date_Last_Acces"] = f"{int(d3)} day {int(h3)} hours {int(h3)} min {int(h3)} sec"
    data["Date_Last_Modif"] = f"{int(d2)} day {int(h2)} hours {int(h2)} min {int(h2)} sec"
    
    ## Etablir Status - LOG
    statut_audit = ""

    ## RAPPORT print
    print(f"\n-Pour le Path : {recup_data_path}")
    print(f"    .Derniers Modification : {d2} Jours {h2} Heurs {m2} min {round(s2,2)} sec")
    print(f"    .Derniers Acces : {d3} Jours {h3} Heurs {m3} min {round(s3,2)} sec")
    
    ## Gestion d'ALERTE
    if calcul_seconde_dif_modif < 3600 and calcul_seconde_dif_acces < 3600:
        print("🔴 Critique Modification et Acces il y a moins d'1heure ! ")
        statut_audit = f"🔴 Critique sur {recup_data_path} - Modification et Acces il y a moins d'1heure"
        data["Statut_audit_modif"] = statut_audit
        data["Statut_audit_acces"] = statut_audit
    elif calcul_seconde_dif_modif < 3600 and calcul_seconde_dif_acces > 3600:
        print("🔴 Critique Modification il y a moins d'1 heure - Verification !")
        statut_audit = f"🔴 Critique sur {recup_data_path} - Modification il y a moins d'1 heure - Verification"
        data["Statut_audit_modif"] = statut_audit
        data["Statut_audit_acces"] = "🟢 Pas d'acces dans la derniere Heure."
    elif calcul_seconde_dif_acces < 3600 and calcul_seconde_dif_acces > 3600:
        print("🔴 Critique Acces il y a moins d'1 heure - Verification !")
        statut_audit = f"🔴 Critique sur {recup_data_path} - d'acces il y a moins d'1 heure - Verification"
        data["Statut_audit_acces"] = statut_audit
        data["Statut_audit_modif"] = "🟢 Pas de modification dans la derniere Heure."
    else:
        statut_audit = "🟢 Pas de modification dans la derniere Heure."
        print(f"    .Statut : {statut_audit}")
        data["Statut_audit_acces"] = "🟢 Pas d'Acces dans la derniere Heure."
        data["Statut_audit_modif"] = statut_audit

    return data

def check_permission(data):
    recup_path = data["path"]
    recup_permission = data["permission"]
    recup_perm_user = data["perm_user"]
    
    ## RECUP Infos sur le PATH
    stat_path = os.stat(recup_path)

    ## RECUP Permission en format Octal
    actuel_perm = oct(stat.S_IMODE(stat_path.st_mode)).zfill(4)

    ## RECUP du Proprietaire
    actuel_user = pwd.getpwuid(stat_path.st_uid).pw_name

    ## Etablir Statut Permission LOG 
    statut_log_permission = ""
    statut_log_perm_user = ""
    
    ## Verification
    if actuel_perm > recup_permission:
        print("    --")
        print(f"    .🔴 Permission Critique - Trop Grande ! Actuel : {actuel_perm} | Attendu : {recup_permission} max")
        statut_log_permission = f"🔴 Permission Critique sur {recup_path} - Trop Grande ! Actuel : {actuel_perm} | Attendu : {recup_permission} max"
        data["statut_permission"] = statut_log_permission
    else:
        print("    --")
        print(f"    .🟢 Permission Ok : {actuel_perm}")
        statut_log_permission = f"🟢 Permission Ok pour {recup_path}"
        data["statut_permission"] = statut_log_permission

    if actuel_user != recup_perm_user:
        print(f"    .🔴 Critique ! Propriétaire Incorret ! Actuel : {actuel_user} | Attendu : {recup_perm_user}")
        statut_log_perm_user = f"🔴 Permission Critique sur {recup_path} - Propriétaire Incorret ! Actuel : {actuel_user} | Attendu : {recup_perm_user}"
        data["statut_perm_user"] = statut_log_perm_user
    else: 
        print(f"    .🟢 Proprietaire OK : {recup_perm_user}")
        statut_log_perm_user = f"🟢 Permission Ok pour {recup_path}"
        data["statut_perm_user"] = statut_log_perm_user

    return data
    
def start_audit_data(data_audit_csv, data_audit_all):
    with open(data_audit_csv, newline ='') as f:
        reader = csv.reader(f)
        print("\n=========================")
        print("======== AUDIT Path =====")
        try:
            for row in reader:
                if row[0] == "path":
                    pass
                else:
                    data_path_cyber = {}
                    ## RECUP DATA
                    path = row[0]
                    permission = row[1]
                    perm_user = row[2]
                    perm_group = row[3]
                    description = row[4]
                    usage_normal = row[5]
                    risque_cyber = row[6]

                    data_path_cyber["path"] = path
                    data_path_cyber["permission"] = permission
                    data_path_cyber["perm_user"] = perm_user
                    data_path_cyber["perm_group"] = perm_group
                    data_path_cyber["description"] = description
                    data_path_cyber["usage_normal"] = usage_normal
                    data_path_cyber["risque_cyber"] = risque_cyber

                    ## APPLICATION Data Check
                    data_path_cyber = check_path_time(data_path_cyber)
                    data_path_cyber = check_permission(data_path_cyber)
                    
                    ## EMPLIE DATA CYBER
                    data_audit_all[path]=data_path_cyber

                    ## AD WIP
                    print("    --")
                    print(f"    .Description : {description}")
                    print(f"    .Usage Normale : {usage_normal}")
                    print(f"    .Risque Cyber : {risque_cyber}")
                    print("----------------------")


        except csv.Error as e:
            sys.exit(f'file {data_path_security}, line {reader.line_num}: {e}')
        
    return data_audit_all

def send_discord_alerte(liste_alertes, name_machine, nombre_alerte, path_log_audit, color=15158332):
    # Transformation de la liste en chaîne de caractères pour l'embed
    alertes_texte = "\n".join(liste_alertes)
    
    # Si le texte est trop long (> 1024 caractères)
    if len(alertes_texte) > 800:
        alertes_texte = alertes_texte[:750] + "..."

    payload = {
        "embeds": [{
            "title": "🛡️ Sentinel-Health Alert",
            "color": color,
            "fields": [
                {
                    "name": "Machine:",
                    "value": f"`{name_machine}`",
                    "inline": True
                },
                {
                    "name": "NB Alerte :",
                    "value": f"**{str(nombre_alerte)}**",
                    "inline": True
                },
                {
                    "name": "📂  Fichier Log",
                    "value": f"`{path_log_audit}`",
                    "inline": False
                },
                {
                    "name": "Détails des alertes",
                    "value": alertes_texte,
                    "inline": False
                }
            ],
            "footer": {
                "text": "Audit Système Automatisé"
            }
        }]
    }
    
    try:
        response = requests.post(WEBHOOK_URL, json=payload)
        if response.status_code == 204:
            print("✅ Alerte Discord envoyée avec succès !")
        else:
            print(f"❌ Erreur Discord : {response.status_code}")
    except Exception as e:
        print(f"❌ Erreur de connexion : {e}")

def ecriture_fichier_log(nom_files, data_to_write):
    with open(nom_files, "w") as f:
        json.dump(data_to_write, f, indent=4)

def statut_to_send(all_data_audit):
    statut_to_send = []

    ## --- AUDIT recup Alerte pour remonte Alerte message sur discord  ---------------------
    for data in all_data_audit: 
        recup_dict_data = all_data_audit[data]
        for key in recup_dict_data:
            recup_donne = recup_dict_data[key]
            if type(recup_donne) == str:
                pass
            else:
                for donne in recup_donne:
                    recuperer_value = recup_donne[donne]
                    if type(recuperer_value) == str:
                        split_recuperer_value = recuperer_value.split(" ")
                        if "🟠" in split_recuperer_value or "🔴" in split_recuperer_value:
                            statut_to_send.append(recuperer_value)

    return statut_to_send

data_all_security = start_audit_data(data_csv_security,data_all_security)

# *************************************************************************************
# ====== PARTIE 3 - ECRITURE LOG ======================================================

## --- Setup Name File log  ------------------------------------------------------------
nom_machine_recup = data_check_machine["data_sys"]["name_machine"]
nom_fichier_log = f"{LOGS_SYSTEM}/AUDIT_{actuel_date}_{nom_machine_recup}.json"

## --- RECUP ALL DATA System & Audit Secu  ---------------------------------------------
data_all_audit = {}
data_all_audit["data_systeme"] = data_check_machine
data_all_audit["data_audit_security"] = data_all_security

# ---- STATUS TO SEND -----------------------------------------------
statut_to_send = statut_to_send(data_all_audit)

# --- ECRITURE DU FICHIER LOG ----------------------------------------
ecriture_fichier_log(nom_fichier_log, data_all_audit)

# --- RECUPERER Nb d'alerte ------------------------------------------
recupere_nb_alerte = len(statut_to_send)

# --- Setup Message to Send ALERTE  ---------------------------------------------------
alerte_message = f"Machine : {nom_machine_recup} | Nombre d'Alerte : {recupere_nb_alerte} \n>> {nom_fichier_log} \n{statut_to_send} " 

# --- TRANSFORMATION la liste en texte, une alerte par ligne  -------------------------
message_formate = "\n".join(statut_to_send) if statut_to_send else "Aucune alerte."


# *************************************************************************************
# ====== PARTIE - ENVOI ALERTE  =======================================================

if recupere_nb_alerte != 0:
    send_discord_alerte(statut_to_send, nom_machine_recup, recupere_nb_alerte, nom_fichier_log)
    