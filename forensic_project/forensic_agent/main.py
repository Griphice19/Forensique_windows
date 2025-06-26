#!/usr/bin/env python3
"""
Agent Forensique Windows - Point d'entrée principal
Collecte et analyse des artefacts système pour investigation forensique
"""

import sys
import os
import time
import logging
import argparse
from datetime import datetime
from pathlib import Path

# Configuration du logging
def setup_logging():
    """Configure le système de logging"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler('forensic_agent.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('ForensicAgent')

class ForensicAgent:
    """Agent principal de collecte forensique"""
    
    def __init__(self):
        self.logger = setup_logging()
        self.version = "1.0.0"
        self.start_time = datetime.now()
        self.data_collected = {}
        
        self.logger.info(f"🚀 Agent Forensique Windows v{self.version} - Démarrage")
        self.logger.info(f"📅 Session démarrée: {self.start_time}")
    
    def check_privileges(self):
        """Vérifie si l'agent s'exécute avec les privilèges administrateur"""
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                self.logger.info("✅ Privilèges administrateur détectés")
                return True
            else:
                self.logger.warning("⚠️  Privilèges administrateur requis pour certaines fonctions")
                return False
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de la vérification des privilèges: {e}")
            return False
    
    def initialize_collectors(self):
        """Initialise tous les modules de collecte"""
        self.logger.info("🔧 Initialisation des modules de collecte...")
        
        try:
            from core.collector import DataCollector
            from core.eventlogs import EventLogCollector
            from core.registry import RegistryCollector
            from core.network import NetworkCollector
            from core.browser import BrowserCollector
            from core.usb import USBCollector
            
            self.collectors = {
                'main': DataCollector(),
                'eventlogs': EventLogCollector(),
                'registry': RegistryCollector(),
                'network': NetworkCollector(),
                'browser': BrowserCollector(),
                'usb': USBCollector()
            }
            
            self.logger.info(f"✅ {len(self.collectors)} modules de collecte initialisés")
            return True
            
        except ImportError as e:
            self.logger.error(f"❌ Erreur d'import des modules: {e}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de l'initialisation: {e}")
            return False
    
    def collect_artifacts(self):
        """Lance la collecte de tous les artefacts"""
        self.logger.info("🔍 Début de la collecte des artefacts...")
        
        collection_results = {}
        
        for name, collector in self.collectors.items():
            try:
                self.logger.info(f"📊 Collecte {name}...")
                start_time = time.time()
                
                data = collector.collect()
                elapsed_time = time.time() - start_time
                
                collection_results[name] = {
                    'data': data,
                    'timestamp': datetime.now().isoformat(),
                    'duration': round(elapsed_time, 2),
                    'status': 'success',
                    'items_count': len(data) if isinstance(data, (list, dict)) else 1
                }
                
                self.logger.info(f"✅ {name}: {collection_results[name]['items_count']} éléments collectés en {elapsed_time:.2f}s")
                
            except Exception as e:
                self.logger.error(f"❌ Erreur lors de la collecte {name}: {e}")
                collection_results[name] = {
                    'data': None,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'error',
                    'error': str(e)
                }
        
        self.data_collected = collection_results
        return collection_results
    
    def generate_report(self):
        """Génère un rapport de collecte"""
        self.logger.info("📝 Génération du rapport de collecte...")
        
        total_items = sum(
            result.get('items_count', 0) 
            for result in self.data_collected.values() 
            if result.get('status') == 'success'
        )
        
        successful_collections = sum(
            1 for result in self.data_collected.values() 
            if result.get('status') == 'success'
        )
        
        end_time = datetime.now()
        total_duration = (end_time - self.start_time).total_seconds()
        
        report = {
            'session_info': {
                'version': self.version,
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'total_duration': round(total_duration, 2)
            },
            'collection_summary': {
                'total_modules': len(self.collectors),
                'successful_modules': successful_collections,
                'failed_modules': len(self.collectors) - successful_collections,
                'total_artifacts': total_items
            },
            'detailed_results': self.data_collected
        }
        
        self.logger.info(f"📊 Rapport généré: {total_items} artefacts collectés en {total_duration:.2f}s")
        return report
    
    def save_data(self, report):
        """Sauvegarde les données collectées"""
        try:
            import json
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"forensic_data_{timestamp}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            
            self.logger.info(f"💾 Données sauvegardées: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de la sauvegarde: {e}")
            return None
    
    def run(self):
        """Lance l'exécution complète de l'agent"""
        try:
            # Vérification des privilèges
            self.check_privileges()
            
            # Initialisation des collecteurs
            if not self.initialize_collectors():
                self.logger.error("❌ Impossible d'initialiser les modules de collecte")
                return False
            
            # Collecte des artefacts
            self.collect_artifacts()
            
            # Génération du rapport
            report = self.generate_report()
            
            # Sauvegarde
            filename = self.save_data(report)
            
            self.logger.info("🎉 Collecte forensique terminée avec succès!")
            if filename:
                self.logger.info(f"📁 Fichier de données: {filename}")
            
            return True
            
        except KeyboardInterrupt:
            self.logger.info("⏸️  Arrêt demandé par l'utilisateur")
            return False
        except Exception as e:
            self.logger.error(f"❌ Erreur critique: {e}")
            return False

def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(description='Agent Forensique Windows')
    parser.add_argument('--version', action='version', version='ForensicAgent 1.0.0')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Création et lancement de l'agent
    agent = ForensicAgent()
    success = agent.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()