# Créer un fichier test_network.py
from network import NetworkCollector

def test_network():
    collector = NetworkCollector()
    try:
        data = collector.collect()
        print(f"✅ Network: {len(data.get('connections', []))} connexions")
        print(f"Ports ouverts: {len(data.get('listening_ports', []))}")
        return True
    except Exception as e:
        print(f"❌ Network Error: {e}")
        return False

if __name__ == "__main__":  # ← Correction ici : deux underscores de chaque côté
    test_network()