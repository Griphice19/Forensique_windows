# Créer un fichier test_registry.py
from registry import RegistryCollector

def test_registry():
    collector = RegistryCollector()
    try:
        data = collector.collect()
        print(f"✅ Registry: {len(data.get('entries', []))} entrées collectées")
        print(f"Erreurs: {len(data.get('errors', []))}")
        return True
    except Exception as e:
        print(f"❌ Registry Error: {e}")
        return False

if __name__ == "__main__":
    test_registry()