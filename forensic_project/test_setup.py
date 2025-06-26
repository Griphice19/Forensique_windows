# test_setup.py - Vérification de l'installation des bibliothèques

import sys
print("=== Test d'installation des bibliothèques forensiques ===\n")

# Liste des bibliothèques à tester
libraries = [
    ("psutil", "Informations système et processus"),
    ("win32evtlog", "Journaux d'événements Windows"),
    ("wmi", "Windows Management Instrumentation"),
    ("winreg", "Accès au registre Windows"),
    ("cryptography", "Chiffrement des données"),
    ("requests", "Requêtes HTTP"),
    ("pandas", "Manipulation de données"),
    ("yaml", "Configuration YAML"),
    ("json", "Traitement JSON"),
]

success_count = 0
total_count = len(libraries)

for lib_name, description in libraries:
    try:
        if lib_name == "win32evtlog":
            import win32evtlog
        elif lib_name == "winreg":
            import winreg
        elif lib_name == "cryptography":
            from cryptography.fernet import Fernet
        elif lib_name == "yaml":
            import yaml
        else:
            __import__(lib_name)
        
        print(f"✅ {lib_name:<15} - {description}")
        success_count += 1
        
    except ImportError as e:
        print(f"❌ {lib_name:<15} - ERREUR: {e}")
    except Exception as e:
        print(f"⚠️  {lib_name:<15} - ATTENTION: {e}")

print(f"\n=== Résultat: {success_count}/{total_count} bibliothèques installées ===")

# Test rapide de fonctionnalité
if success_count == total_count:
    print("\n🎉 Excellent! Toutes les bibliothèques sont prêtes!")
    print("Vous pouvez maintenant commencer le développement de l'agent.")
    
    # Test rapide de psutil
    try:
        import psutil
        print(f"\n📊 Test rapide - Processus actifs: {len(psutil.pids())}")
        print(f"📊 Utilisation CPU: {psutil.cpu_percent()}%")
        print(f"📊 Utilisation RAM: {psutil.virtual_memory().percent}%")
    except:
        pass
else:
    print(f"\n⚠️  {total_count - success_count} bibliothèque(s) manquante(s)")
    print("Vérifiez votre environnement virtuel et réinstallez si nécessaire.")

print(f"\n🐍 Version Python: {sys.version}")
print(f"📁 Environnement: {sys.executable}")