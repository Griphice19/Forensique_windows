#!/usr/bin/env python3
"""
Test du module EventLogCollector
"""
import sys
import os
import logging
import json
from datetime import datetime

# Suppression de la ligne problématique :
# sys.path.append('forensic_agent')

def setup_test_logging():
    """Configure le logging pour les tests"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def test_eventlog_collector():
    """Test du collecteur de journaux d'événements"""
    print("=== Test du module EventLogCollector ===\n")
   
    try:
        # Import corrigé :
        from forensic_agent.core.eventlogs import EventLogCollector
       
        # Création du collecteur
        collector = EventLogCollector()
        print("✅ EventLogCollector créé avec succès")
       
        # Test de collecte
        print("🔍 Début de la collecte des journaux d'événements...")
        data = collector.collect()
       
        # Affichage des résultats
        print(f"\n📊 Résultats de la collecte:")
        print(f"  - Journaux analysés: {len(data.get('logs', {}))}")
        print(f"  - Événements totaux: {data.get('statistics', {}).get('total_events', 0)}")
        print(f"  - Événements critiques: {len(data.get('critical_events', []))}")
       
        # Affichage des journaux collectés
        print(f"\n📝 Journaux collectés:")
        for log_name, log_data in data.get('logs', {}).items():
            if 'events' in log_data:
                print(f"  - {log_name}: {len(log_data['events'])} événements")
            else:
                print(f"  - {log_name}: Erreur - {log_data.get('error', 'Unknown')}")
       
        # Affichage des événements critiques récents (5 premiers)
        critical_events = data.get('critical_events', [])
        if critical_events:
            print(f"\n🚨 Événements critiques récents (5 premiers):")
            for i, event in enumerate(critical_events[:5]):
                print(f"  {i+1}. [{event.get('timestamp')}] ID {event.get('event_id')}: {event.get('description', 'Unknown')}")
       
        # Affichage des alertes de sécurité
        alerts = data.get('summary', {}).get('security_alerts', [])
        if alerts:
            print(f"\n⚠️ Alertes de sécurité:")
            for alert in alerts:
                print(f"  - {alert}")
       
        # Sauvegarde des résultats pour analyse
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"test_eventlogs_{timestamp}.json"
       
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
       
        print(f"\n💾 Résultats sauvegardés dans: {filename}")
        print("✅ Test du module EventLogCollector réussi!")
       
        return True
       
    except ImportError as e:
        print(f"❌ Erreur d'import: {e}")
        return False
    except Exception as e:
        print(f"❌ Erreur durant le test: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Point d'entrée du test"""
    setup_test_logging()
   
    print("🧪 Test du module EventLogCollector")
    print("=" * 50)
   
    success = test_eventlog_collector()
   
    if success:
        print("\n🎉 Tous les tests sont passés avec succès!")
    else:
        print("\n❌ Des erreurs ont été détectées lors des tests")
   
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
    