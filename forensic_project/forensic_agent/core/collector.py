#!/usr/bin/env python3
"""
collector.py - Orchestrateur Principal de l'Agent Forensique Windows
Module central qui coordonne tous les collecteurs d'artefacts
"""

import os
import json
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Imports des modules forensiques
try:
    from .eventlogs import EventLogCollector
    from .registry import RegistryCollector  
    from .network import NetworkCollector
    from .browser import BrowserCollector
    from .usb import USBCollector
    # from .processes import ProcessCollector
    # from .filesystem import FilesystemCollector
except ImportError:
    # Pour les tests standalone
    import sys
    sys.path.append(os.path.dirname(__file__))
    try:
        from eventlogs import EventLogCollector
        from registry import RegistryCollector
        from network import NetworkCollector
        from browser import BrowserCollector
        from usb import USBCollector
    except ImportError as e:
        print(f"⚠️  Modules manquants: {e}")
        print("Certains collecteurs ne seront pas disponibles")

class ForensicCollector:
    """
    Orchestrateur principal pour la collecte d'artefacts forensiques
    Coordonne tous les modules de collecte et génère des rapports unifiés
    """
    
    def __init__(self, output_dir: str = "forensic_output"):
        """
        Initialise le collecteur principal
        
        Args:
            output_dir: Répertoire de sortie pour les artefacts
        """
        self.output_dir = output_dir
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = os.path.join(output_dir, f"collection_{self.session_id}")
        
        # Création des répertoires
        os.makedirs(self.session_dir, exist_ok=True)
        os.makedirs(os.path.join(self.session_dir, "raw_data"), exist_ok=True)
        os.makedirs(os.path.join(self.session_dir, "reports"), exist_ok=True)
        
        # Configuration du logging
        self.setup_logging()
        
        # Initialisation des collecteurs
        self.collectors = {}
        self.collection_results = {}
        self.collection_errors = {}
        
        # Statistiques de collecte
        self.start_time = None
        self.end_time = None
        self.total_artifacts = 0
        
        self.logger.info(f"🚀 Forensic Collector initialisé - Session: {self.session_id}")

    def setup_logging(self):
        """Configure le système de logging"""
        log_file = os.path.join(self.session_dir, "collection.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ForensicCollector')

    def initialize_collectors(self):
        """Initialise tous les collecteurs disponibles"""
        self.logger.info("🔧 Initialisation des collecteurs...")
        
        # EventLogs Collector
        try:
            self.collectors['eventlogs'] = EventLogCollector()
            self.logger.info("✅ EventLogCollector initialisé")
        except Exception as e:
            self.logger.error(f"❌ Erreur EventLogCollector: {e}")
            
        # Registry Collector
        try:
            self.collectors['registry'] = RegistryCollector()
            self.logger.info("✅ RegistryCollector initialisé")
        except Exception as e:
            self.logger.error(f"❌ Erreur RegistryCollector: {e}")
            
        # Network Collector
        try:
            self.collectors['network'] = NetworkCollector()
            self.logger.info("✅ NetworkCollector initialisé")
        except Exception as e:
            self.logger.error(f"❌ Erreur NetworkCollector: {e}")
            
        # Browser Collector
        try:
            self.collectors['browser'] = BrowserCollector()
            self.logger.info("✅ BrowserCollector initialisé")
        except Exception as e:
            self.logger.error(f"❌ Erreur BrowserCollector: {e}")
            
        # USB Collector
        try:
            self.collectors['usb'] = USBCollector()
            self.logger.info("✅ USBCollector initialisé")
        except Exception as e:
            self.logger.error(f"❌ Erreur USBCollector: {e}")
            
        # Futurs collecteurs
        # try:
        #     self.collectors['processes'] = ProcessCollector()
        #     self.logger.info("✅ ProcessCollector initialisé")
        # except Exception as e:
        #     self.logger.error(f"❌ Erreur ProcessCollector: {e}")
            
        self.logger.info(f"📊 {len(self.collectors)} collecteurs initialisés")

    def collect_single_module(self, name: str, collector) -> Dict[str, Any]:
        """
        Collecte les données d'un module spécifique
        
        Args:
            name: Nom du collecteur
            collector: Instance du collecteur
            
        Returns:
            Dictionnaire avec les résultats de la collecte
        """
        start_time = time.time()
        self.logger.info(f"🔍 Début collecte: {name}")
        
        try:
            # Collecte des données selon le type de collecteur
            if hasattr(collector, 'collect_all'):
                data = collector.collect_all()
            elif hasattr(collector, 'collect'):
                data = collector.collect()
            elif hasattr(collector, 'analyze_all') and name == 'browser':
                # Spécifique pour BrowserCollector
                data = collector.analyze_all()
            elif hasattr(collector, 'collect_usb_artifacts') and name == 'usb':
                # Spécifique pour USBCollector
                data = collector.collect_usb_artifacts()
            else:
                # Tentative avec les méthodes standards
                methods = ['collect_all', 'collect', 'analyze', 'get_data']
                data = None
                for method in methods:
                    if hasattr(collector, method):
                        data = getattr(collector, method)()
                        break
                
                if data is None:
                    raise AttributeError(f"Aucune méthode de collecte compatible trouvée pour {name}")
            
            # Calcul des statistiques
            artifacts_count = self._count_artifacts(data)
            duration = time.time() - start_time
            
            result = {
                'status': 'success',
                'data': data,
                'artifacts_count': artifacts_count,
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'collector_type': name
            }
            
            # Sauvegarde des données brutes
            self._save_raw_data(name, data)
            
            self.logger.info(f"✅ {name}: {artifacts_count} artefacts en {duration:.2f}s")
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"❌ Erreur {name}: {e}")
            
            return {
                'status': 'error',
                'error': str(e),
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'collector_type': name
            }

    def collect_all(self, parallel: bool = True, timeout: int = 300) -> Dict[str, Any]:
        """
        Lance la collecte complète de tous les artefacts
        
        Args:
            parallel: Exécution en parallèle des collecteurs
            timeout: Timeout en secondes pour chaque collecteur
            
        Returns:
            Résultats complets de la collecte
        """
        self.start_time = time.time()
        self.logger.info("🚀 Début de la collecte forensique complète")
        
        # Initialisation des collecteurs
        self.initialize_collectors()
        
        if not self.collectors:
            self.logger.error("❌ Aucun collecteur disponible")
            return {'status': 'error', 'message': 'Aucun collecteur disponible'}
        
        # Collecte des données
        if parallel:
            self._collect_parallel(timeout)
        else:
            self._collect_sequential()
        
        self.end_time = time.time()
        
        # Génération du rapport final
        return self._generate_final_report()

    def _collect_parallel(self, timeout: int):
        """Collecte en parallèle avec ThreadPoolExecutor"""
        self.logger.info("🔄 Collecte en parallèle...")
        
        with ThreadPoolExecutor(max_workers=len(self.collectors)) as executor:
            # Soumission des tâches
            future_to_collector = {
                executor.submit(self.collect_single_module, name, collector): name
                for name, collector in self.collectors.items()
            }
            
            # Récupération des résultats
            for future in as_completed(future_to_collector, timeout=timeout):
                collector_name = future_to_collector[future]
                try:
                    result = future.result()
                    self.collection_results[collector_name] = result
                except Exception as e:
                    self.logger.error(f"❌ Erreur dans le thread {collector_name}: {e}")
                    self.collection_errors[collector_name] = str(e)

    def _collect_sequential(self):
        """Collecte séquentielle"""
        self.logger.info("🔄 Collecte séquentielle...")
        
        for name, collector in self.collectors.items():
            result = self.collect_single_module(name, collector)
            self.collection_results[name] = result

    def _count_artifacts(self, data: Any) -> int:
        """Compte le nombre d'artefacts dans les données"""
        if isinstance(data, dict):
            count = 0
            for key, value in data.items():
                if isinstance(value, (list, tuple)):
                    count += len(value)
                elif isinstance(value, dict):
                    # Pour les structures complexes comme browser data
                    if key in ['browsers', 'profiles', 'history', 'bookmarks', 'downloads', 'usb_devices']:
                        count += self._count_artifacts(value)
                    else:
                        count += len(value) if value else 0
                else:
                    count += 1 if value is not None else 0
            return count
        elif isinstance(data, (list, tuple)):
            return len(data)
        else:
            return 1 if data is not None else 0

    def _save_raw_data(self, collector_name: str, data: Any):
        """Sauvegarde les données brutes"""
        filename = os.path.join(self.session_dir, "raw_data", f"{collector_name}.json")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            self.logger.error(f"❌ Erreur sauvegarde {collector_name}: {e}")

    def _generate_final_report(self) -> Dict[str, Any]:
        """Génère le rapport final de collecte"""
        total_duration = self.end_time - self.start_time
        
        # Statistiques globales
        successful_collectors = [name for name, result in self.collection_results.items() 
                               if result.get('status') == 'success']
        failed_collectors = [name for name, result in self.collection_results.items() 
                           if result.get('status') == 'error']
        
        self.total_artifacts = sum(
            result.get('artifacts_count', 0) 
            for result in self.collection_results.values()
            if result.get('status') == 'success'
        )
        
        # Rapport final
        final_report = {
            'session_info': {
                'session_id': self.session_id,
                'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
                'end_time': datetime.fromtimestamp(self.end_time).isoformat(),
                'total_duration': total_duration,
                'output_directory': self.session_dir
            },
            'collection_summary': {
                'total_collectors': len(self.collectors),
                'successful_collectors': len(successful_collectors),
                'failed_collectors': len(failed_collectors),
                'total_artifacts': self.total_artifacts,
                'success_rate': len(successful_collectors) / len(self.collectors) * 100 if self.collectors else 0
            },
            'collector_results': self.collection_results,
            'errors': self.collection_errors,
            'recommendations': self._generate_recommendations()
        }
        
        # Sauvegarde du rapport
        report_file = os.path.join(self.session_dir, "reports", "final_report.json")
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False, default=str)
        
        # Génération du rapport HTML
        self._generate_html_report(final_report)
        
        self.logger.info(f"🎉 Collecte terminée: {self.total_artifacts} artefacts en {total_duration:.2f}s")
        return final_report

    def _generate_recommendations(self) -> List[str]:
        """Génère des recommandations basées sur les résultats"""
        recommendations = []
        
        # Analyse des résultats pour recommandations
        for collector_name, result in self.collection_results.items():
            if result.get('status') == 'error':
                recommendations.append(f"⚠️  Réexécuter {collector_name} avec des privilèges élevés")
            elif result.get('artifacts_count', 0) == 0:
                recommendations.append(f"🔍 Vérifier la configuration de {collector_name}")
        
        # Recommandations spécifiques par type de collecteur
        if 'browser' in self.collection_results:
            browser_result = self.collection_results['browser']
            if browser_result.get('status') == 'success':
                browser_data = browser_result.get('data', {})
                if 'browsers' in browser_data and len(browser_data['browsers']) > 3:
                    recommendations.append("🌐 Multiples navigateurs détectés - analyser les corrélations")
                if any('private' in str(data).lower() for data in browser_data.values() if isinstance(data, (list, dict))):
                    recommendations.append("🔒 Navigation privée détectée - vérifier les artefacts temporaires")
        
        if 'usb' in self.collection_results:
            usb_result = self.collection_results['usb']
            if usb_result.get('status') == 'success':
                usb_data = usb_result.get('data', {})
                if usb_data.get('usb_devices') and len(usb_data['usb_devices']) > 5:
                    recommendations.append("🔌 Nombreux périphériques USB - analyser les accès récents")
        
        if 'network' in self.collection_results:
            network_result = self.collection_results['network']
            if network_result.get('status') == 'success':
                network_data = network_result.get('data', {})
                if network_data.get('suspicious_connections'):
                    recommendations.append("🚨 Connexions suspectes détectées - enquête approfondie requise")
        
        if 'eventlogs' in self.collection_results:
            eventlogs_result = self.collection_results['eventlogs']
            if eventlogs_result.get('status') == 'success':
                eventlogs_data = eventlogs_result.get('data', {})
                if eventlogs_data.get('security_events') and len(eventlogs_data['security_events']) > 1000:
                    recommendations.append("📊 Volume élevé d'événements de sécurité - filtrage recommandé")
        
        if 'registry' in self.collection_results:
            registry_result = self.collection_results['registry']
            if registry_result.get('status') == 'success':
                registry_data = registry_result.get('data', {})
                if registry_data.get('startup_programs') and len(registry_data['startup_programs']) > 10:
                    recommendations.append("🚀 Nombreux programmes au démarrage - vérifier la légitimité")
        
        # Recommandations générales
        if self.total_artifacts > 10000:
            recommendations.append("📊 Volume important d'artefacts - considérer une analyse automatisée")
        
        if len(self.collection_errors) > 0:
            recommendations.append("🛠️  Certains collecteurs ont échoué - vérifier les logs")
            
        if len(self.collection_results) >= 4:
            recommendations.append("🔗 Effectuer une analyse croisée entre les différents types d'artefacts")
            
        return recommendations

    def _generate_html_report(self, report_data: Dict[str, Any]):
        """Génère un rapport HTML lisible"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport Forensique - {self.session_id}</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .success {{ color: #27ae60; }}
                .error {{ color: #e74c3c; }}
                .collector {{ margin: 20px 0; padding: 15px; border: 1px solid #bdc3c7; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Rapport de Collecte Forensique</h1>
                <p>Session: {report_data['session_info']['session_id']}</p>
                <p>Durée: {report_data['session_info']['total_duration']:.2f} secondes</p>
            </div>
            
            <div class="summary">
                <h2>📊 Résumé</h2>
                <table>
                    <tr><td>Collecteurs lancés</td><td>{report_data['collection_summary']['total_collectors']}</td></tr>
                    <tr><td>Collecteurs réussis</td><td class="success">{report_data['collection_summary']['successful_collectors']}</td></tr>
                    <tr><td>Collecteurs échoués</td><td class="error">{report_data['collection_summary']['failed_collectors']}</td></tr>
                    <tr><td>Total artefacts</td><td><strong>{report_data['collection_summary']['total_artifacts']}</strong></td></tr>
                    <tr><td>Taux de réussite</td><td>{report_data['collection_summary']['success_rate']:.1f}%</td></tr>
                </table>
            </div>
            
            <h2>🔧 Détails des Collecteurs</h2>
        """
        
        # Ordre d'affichage des collecteurs pour la lisibilité
        collector_order = ['eventlogs', 'registry', 'network', 'browser', 'usb']
        displayed_collectors = []
        
        # Affichage dans l'ordre préféré
        for collector_name in collector_order:
            if collector_name in report_data['collector_results']:
                result = report_data['collector_results'][collector_name]
                status_class = "success" if result['status'] == 'success' else "error"
                
                # Icônes spécifiques par collecteur
                icons = {
                    'eventlogs': '📋',
                    'registry': '🗂️',
                    'network': '🌐',
                    'browser': '🌍',
                    'usb': '🔌'
                }
                
                icon = icons.get(collector_name, '📁')
                
                html_content += f"""
                <div class="collector">
                    <h3 class="{status_class}">{icon} {collector_name.upper()}</h3>
                    <p>Statut: <span class="{status_class}">{result['status']}</span></p>
                    <p>Durée: {result['duration']:.2f}s</p>
                    <p>Artefacts: {result.get('artifacts_count', 0)}</p>
                    <p>Timestamp: {result['timestamp']}</p>
                """
                
                # Informations spécifiques par type de collecteur
                if result['status'] == 'success' and 'data' in result:
                    data = result['data']
                    if collector_name == 'browser':
                        browsers_count = len(data.get('browsers', []))
                        if browsers_count > 0:
                            html_content += f"<p>Navigateurs détectés: {browsers_count}</p>"
                    elif collector_name == 'usb':
                        usb_count = len(data.get('usb_devices', []))
                        if usb_count > 0:
                            html_content += f"<p>Périphériques USB: {usb_count}</p>"
                    elif collector_name == 'network':
                        connections = len(data.get('active_connections', []))
                        if connections > 0:
                            html_content += f"<p>Connexions actives: {connections}</p>"
                
                html_content += "</div>"
                displayed_collectors.append(collector_name)
        
        # Affichage des collecteurs restants
        for collector_name, result in report_data['collector_results'].items():
            if collector_name not in displayed_collectors:
                status_class = "success" if result['status'] == 'success' else "error"
                html_content += f"""
                <div class="collector">
                    <h3 class="{status_class}">📁 {collector_name.upper()}</h3>
                    <p>Statut: <span class="{status_class}">{result['status']}</span></p>
                    <p>Durée: {result['duration']:.2f}s</p>
                    <p>Artefacts: {result.get('artifacts_count', 0)}</p>
                </div>
                """
        
        html_content += """
        </body>
        </html>
        """
        
        html_file = os.path.join(self.session_dir, "reports", "report.html")
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def get_session_summary(self) -> Dict[str, Any]:
        """Retourne un résumé de la session courante"""
        return {
            'session_id': self.session_id,
            'output_dir': self.session_dir,
            'collectors_available': list(self.collectors.keys()),
            'total_artifacts': self.total_artifacts,
            'status': 'completed' if self.end_time else 'running'
        }

def main():
    """Test du collecteur principal"""
    print("🚀 Test du Forensic Collector Complet")
    print("📋 Collecteurs supportés: EventLogs, Registry, Network, Browser, USB")
    
    # Création du collecteur
    collector = ForensicCollector("test_output")
    
    print(f"\n🔧 Session créée: {collector.session_id}")
    print(f"📂 Répertoire de sortie: {collector.session_dir}")
    
    # Lancement de la collecte
    print("\n🚀 Lancement de la collecte forensique...")
    results = collector.collect_all(parallel=True, timeout=120)
    
    # Affichage des résultats détaillés
    print(f"\n📊 Résultats de la collecte:")
    print(f"├── Session: {results['session_info']['session_id']}")
    print(f"├── Durée totale: {results['session_info']['total_duration']:.2f}s")
    print(f"├── Collecteurs lancés: {results['collection_summary']['total_collectors']}")
    print(f"├── Collecteurs réussis: {results['collection_summary']['successful_collectors']}")
    print(f"├── Collecteurs échoués: {results['collection_summary']['failed_collectors']}")
    print(f"├── Total artefacts: {results['collection_summary']['total_artifacts']}")
    print(f"├── Taux de réussite: {results['collection_summary']['success_rate']:.1f}%")
    print(f"└── Rapports: {collector.session_dir}")
    
    # Détails par collecteur
    print(f"\n🔍 Détails par collecteur:")
    for collector_name, result in results['collector_results'].items():
        status_icon = "✅" if result['status'] == 'success' else "❌"
        print(f"{status_icon} {collector_name.upper()}: {result.get('artifacts_count', 0)} artefacts en {result['duration']:.2f}s")
    
    # Recommandations
    if results.get('recommendations'):
        print(f"\n💡 Recommandations:")
        for rec in results['recommendations']:
            print(f"  {rec}")
    
    print(f"\n📋 Fichiers générés:")
    print(f"├── Logs: {collector.session_dir}/collection.log")
    print(f"├── Rapport JSON: {collector.session_dir}/reports/final_report.json")
    print(f"├── Rapport HTML: {collector.session_dir}/reports/report.html")
    print(f"└── Données brutes: {collector.session_dir}/raw_data/")

if __name__ == "__main__":
    main()