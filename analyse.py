import os
import subprocess
import gzip

os.system("clear")

# Fonction pour écrire les résultats dans le fichier rapport.txt
def write_results(file, title, data):
    file.write("=================================\n")
    file.write(title + ": " + str(len(data)) + "\n")
    for line in data:
        file.write(line + "\n")

# Fonction pour extraire les informations des blocs de logs
def extract_info(block):
    lines = block.strip().split('\n')
    date_line = lines[0]
    command_line = lines[1]
    requested_by_line = lines[2]
    install_lines = lines[3:-1]  # Exclude the last line "End-Date"
    
    # Extracting information from each line
    date = date_line.split(': ')[1]
    command = command_line.split(': ')[1]
    requested_by = requested_by_line.split(': ')[1]
    packages = [line.split(' ', 1)[1] for line in install_lines]
    
    return date, requested_by, command, packages

# Fonction pour lire les fichiers de logs d'installation d'applications
def read_history_log(file_path):
    if file_path.endswith('.gz'):
        with gzip.open(file_path, 'rt') as file:
            return file.read().split('\n\n')
    else:
        with open(file_path, 'r') as file:
            return file.read().split('\n\n')

# Fonction pour générer le rapport des applications installées
def generate_report(blocks):
    with open('apprapport3.txt', 'w') as report_file:  # Use 'w' to overwrite the file
        for block in blocks:
            date, requested_by, command, packages = extract_info(block)
            report_file.write(f"Date: {date}\n")
            report_file.write(f"Requested by: {requested_by}\n")
            report_file.write(f"Command: {command}\n")
            report_file.write("Installed packages:\n")
            for package in packages:
                report_file.write(f" - {package}\n")
            report_file.write("\n")

# Fonction pour réaliser une analyse de connexion
def analyze_connection_logs():
    print("Analyse des fichiers de logs disponibles pour les connexions...")

    # Vérification de la présence des fichiers auth.log et auth.log.1 jusqu'à auth.log.4
    auth_log_files = []
    for i in range(5):
        log_file = f'/var/log/auth.log.{i}'
        if os.path.exists(log_file):
            auth_log_files.append(log_file)

    # Vérification de la présence des fichiers auth.log."nombre".gz
    for i in range(5):
        log_file_gz = f'/var/log/auth.log.{i}.gz'
        if os.path.exists(log_file_gz):
            auth_log_files.append(log_file_gz)

    # Vérification de la présence des fichiers auth.log et auth.log.1
    log_file = '/var/log/auth.log'
    if os.path.exists(log_file):
        auth_log_files.insert(0, log_file)
    log_file_1 = '/var/log/auth.log.1'
    if os.path.exists(log_file_1):
        auth_log_files.insert(1, log_file_1)

    if len(auth_log_files) == 0:
        print("Aucun fichier de logs trouvé pour les connexions.")
    else:
        print(f"Il y a {len(auth_log_files)} fichier(s) de logs disponible(s) pour les connexions.")

        # Interaction utilisateur
        power = int(input(f"À quelle puissance voulez-vous le rapport entre 1 et {len(auth_log_files)} ? Entrez un nombre : "))

        # Vérification de l'entrée utilisateur
        if power < 1 or power > len(auth_log_files):
            print(f"La puissance doit être entre 1 et {len(auth_log_files)}.")
        else:
            # Sélection du bon fichier de log en fonction de l'entrée utilisateur
            log_file_path = auth_log_files[power - 1]
            if log_file_path.endswith('.gz'):
                # Si c'est un fichier compressé, décompresser temporairement pour l'analyse
                with subprocess.Popen(['gunzip', '-c', log_file_path], stdout=subprocess.PIPE) as proc:
                    log_content = proc.stdout.readlines()
                    log_content = [line.decode('utf-8') for line in log_content]
            else:
                # Si c'est un fichier non compressé, lire le contenu directement
                with open(log_file_path, 'r') as file:
                    log_content = file.readlines()

            # Exécuter les commandes de recherche de logs
            failed_su_auth = [line.strip() for line in log_content if "pam_unix(su:auth): authentication failure" in line]
            failed_sudo_auth = [line.strip() for line in log_content if "pam_unix(sudo:auth): authentication failure" in line]
            su_session_opened = [line.strip() for line in log_content if "pam_unix(su:session): session opened" in line]
            sudo_session_opened = [line.strip() for line in log_content if "pam_unix(sudo:session): session opened" in line]

            # Écriture des résultats dans le fichier rapport.txt
            with open('rapport.txt', 'w') as file:
                write_results(file, "Tentative d'authentification ratée avec su", failed_su_auth)
                write_results(file, "Tentative d'authentification ratée avec sudo", failed_sudo_auth)
                write_results(file, "Session ouverte avec su", su_session_opened)
                write_results(file, "Session ouverte avec sudo", sudo_session_opened)

            print("Le rapport a été généré avec succès.")

# Fonction pour réaliser une analyse d'installation d'applications
def analyze_application_logs():
    print("Analyse des fichiers de logs disponibles...")

    # Vérification de la présence des fichiers history.log et history.log.1.gz jusqu'à history.log.5.gz
    history_log_files = []
    for i in range(1, 6):
        log_file = f'/var/log/apt/history.log.{i}.gz'
        if os.path.exists(log_file):
            history_log_files.append(log_file)

    # Ajout du fichier history.log
    history_log_files.insert(0, '/var/log/apt/history.log')

    if len(history_log_files) == 0:
        print("Aucun fichier de logs trouvé.")
    else:
        print(f"Il y a {len(history_log_files)} fichier(s) de logs disponible(s).")

        # Interaction utilisateur
        power = int(input(f"À quelle puissance voulez-vous le rapport entre 1 et {len(history_log_files)} ? Entrez un nombre : "))

        # Vérification de l'entrée utilisateur
        if power < 1 or power > len(history_log_files):
            print(f"La puissance doit être entre 1 et {len(history_log_files)}.")
        else:
            for file_path in history_log_files[:power]:
                blocks = read_history_log(file_path)
                generate_report(blocks)

            print("Le rapport a été généré avec succès.")

# Menu pour choisir l'analyse à réaliser
while True:
    print("Menu :")
    print("1. Faire une analyse de connexion")
    print("2. Faire une analyse d'application")
    print("3. Quitter")
    choice = input("Entrez votre choix : ")

    if choice == '1':
        analyze_connection_logs()
    elif choice == '2':
        analyze_application_logs()
    elif choice == '3':
        print("Au revoir !")
        break
    else:
        print("Choix invalide. Veuillez entrer 1, 2 ou 3.")
