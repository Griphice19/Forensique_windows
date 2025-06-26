"""
EventLogs Collector - Module de collecte des journaux d'événements Windows
Agent Forensique - Module de collection d'artefacts forensiques
"""

import win32evtlog
import win32api
import win32con
import win32security
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json

class EventLogCollector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.events_data = []
        self.statistics = {}
        self.alerts = []
        
        # Types d'événements critiques à surveiller
        self.critical_events = {
            # Authentification et Sessions
            4624: "Connexion réussie",
            4625: "Échec de connexion",
            4634: "Déconnexion",
            4647: "Déconnexion initiée par l'utilisateur",
            4648: "Tentative de connexion avec identifiants explicites",
            4672: "Privilèges spéciaux assignés",
            4768: "Ticket Kerberos (TGT) demandé",
            4769: "Ticket de service Kerberos demandé",
            4771: "Échec de pré-authentification Kerberos",
            
            # Gestion des comptes
            4720: "Compte utilisateur créé",
            4722: "Compte utilisateur activé",
            4724: "Tentative de réinitialisation de mot de passe",
            4725: "Compte utilisateur désactivé",
            4726: "Compte utilisateur supprimé",
            4738: "Compte utilisateur modifié",
            4781: "Nom de compte modifié",
            
            # Groupes et privilèges
            4728: "Membre ajouté à un groupe de sécurité global",
            4732: "Membre ajouté à un groupe de sécurité local",
            4756: "Membre ajouté à un groupe de sécurité universel",
            
            # Services et processus
            7034: "Service arrêté de manière inattendue",
            7035: "Service contrôlé avec succès",
            7036: "Service entré dans l'état d'arrêt/démarrage",
            7040: "Paramètres de service modifiés",
            4697: "Service installé",
            
            # Processus
            4688: "Nouveau processus créé",
            4689: "Processus terminé",
            
            # Objets et fichiers
            4656: "Handle vers un objet demandé",
            4658: "Handle vers un objet fermé",
            4663: "Tentative d'accès à un objet",
            
            # PowerShell
            4103: "Exécution de pipeline PowerShell",
            4104: "Exécution de bloc de script PowerShell",
            
            # Nettoyage des logs
            1102: "Journal d'audit effacé",
            
            # RDP
            1149: "Connexion réseau réussie par le Bureau à distance",
            
            # Systémique
            6005: "Démarrage du service de journal d'événements",
            6006: "Arrêt du service de journal d'événements",
            1074: "Arrêt/redémarrage du système initié",
            1076: "Arrêt/redémarrage du système",
        }
        
        # Journaux à analyser
        self.logs_to_analyze = [
            'Security',
            'System', 
            'Application',
            'Microsoft-Windows-PowerShell/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        ]

    def collect(self, max_events=1000):
        """Collecte les événements des journaux Windows"""
        try:
            self.logger.info("🔍 Début de la collecte des journaux d'événements...")
            
            for log_name in self.logs_to_analyze:
                try:
                    self._collect_from_log(log_name, max_events)
                except Exception as e:
                    self.logger.warning(f"❌ Erreur lors de la collecte du journal {log_name}: {e}")
                    
            self._analyze_events()
            self._generate_statistics()
            self._detect_alerts()
            
            self.logger.info(f"✅ Collecte terminée: {len(self.events_data)} événements collectés")
            
            return {
                'events': self.events_data,
                'statistics': self.statistics,
                'alerts': self.alerts,
                'total_events': len(self.events_data)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de la collecte des événements: {e}")
            return None

    def _collect_from_log(self, log_name, max_events):
        """Collecte les événements d'un journal spécifique"""
        try:
            # Ouvrir le journal d'événements
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events_collected = 0
            
            while events_collected < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                    
                for event in events:
                    if events_collected >= max_events:
                        break
                        
                    event_data = self._parse_event(event, log_name)
                    if event_data:
                        self.events_data.append(event_data)
                        events_collected += 1
                        
            win32evtlog.CloseEventLog(hand)
            self.logger.info(f"📊 {log_name}: {events_collected} événements collectés")
            
        except Exception as e:
            self.logger.error(f"❌ Erreur collecte journal {log_name}: {e}")

    def _parse_event(self, event, log_name):
        """Parse un événement Windows en format standardisé"""
        try:
            # Conversion du timestamp
            timestamp = event.TimeGenerated.Format()
            
            # Récupération des informations de base
            event_id = event.EventID & 0xFFFF  # Masquer les bits de facilité
            event_type = event.EventType
            source = event.SourceName
            computer = event.ComputerName
            
            # Récupération du message et des données
            try:
                message = win32evtlogutil.SafeFormatMessage(event, log_name)
            except:
                message = "Message non disponible"
                
            # Informations utilisateur si disponibles
            username = None
            if event.Sid:
                try:
                    username = win32security.LookupAccountSid(None, event.Sid)[0]
                except:
                    username = str(event.Sid)
            
            # Déterminer si c'est un événement critique
            is_critical = event_id in self.critical_events
            event_description = self.critical_events.get(event_id, "Événement standard")
            
            return {
                'timestamp': timestamp,
                'log_name': log_name,
                'event_id': event_id,
                'event_type': event_type,
                'source': source,
                'computer': computer,
                'username': username,
                'message': message,
                'is_critical': is_critical,
                'description': event_description,
                'raw_data': list(event.StringInserts) if event.StringInserts else []
            }
            
        except Exception as e:
            self.logger.warning(f"⚠️ Erreur parsing événement: {e}")
            return None

    def _analyze_events(self):
        """Analyse les événements collectés pour identifier les patterns"""
        try:
            # Analyse temporelle - activité récente (24h)
            now = datetime.now()
            recent_threshold = now - timedelta(hours=24)
            
            recent_events = []
            for event in self.events_data:
                try:
                    event_time = datetime.strptime(event['timestamp'], '%m/%d/%y %H:%M:%S')
                    if event_time >= recent_threshold:
                        recent_events.append(event)
                except:
                    continue
                    
            # Timeline des événements critiques
            critical_timeline = []
            for event in self.events_data:
                if event['is_critical']:
                    critical_timeline.append({
                        'time': event['timestamp'],
                        'event_id': event['event_id'],
                        'description': event['description'],
                        'username': event['username'],
                        'source': event['source']
                    })
            
            # Tri par timestamp (plus récents en premier)
            critical_timeline.sort(key=lambda x: x['time'], reverse=True)
            
            self.analysis = {
                'recent_activity': {
                    'total_recent_events': len(recent_events),
                    'critical_recent_events': len([e for e in recent_events if e['is_critical']])
                },
                'critical_timeline': critical_timeline[:50]  # Top 50 événements critiques
            }
            
        except Exception as e:
            self.logger.error(f"❌ Erreur analyse événements: {e}")

    def _generate_statistics(self):
        """Génère des statistiques détaillées"""
        try:
            # Compteurs généraux
            total_events = len(self.events_data)
            critical_events = len([e for e in self.events_data if e['is_critical']])
            
            # Statistiques par journal
            log_stats = Counter([e['log_name'] for e in self.events_data])
            
            # Statistiques par type d'événement
            event_type_stats = Counter([e['event_type'] for e in self.events_data])
            
            # Top événements critiques
            critical_event_stats = Counter([
                f"{e['event_id']} - {e['description']}" 
                for e in self.events_data if e['is_critical']
            ])
            
            # Top utilisateurs actifs
            user_stats = Counter([
                e['username'] for e in self.events_data 
                if e['username'] and e['username'] != 'N/A'
            ])
            
            # Top sources d'événements
            source_stats = Counter([e['source'] for e in self.events_data])
            
            self.statistics = {
                'summary': {
                    'total_events': total_events,
                    'critical_events': critical_events,
                    'critical_percentage': round((critical_events/total_events)*100, 2) if total_events > 0 else 0
                },
                'by_log': dict(log_stats.most_common(10)),
                'by_event_type': dict(event_type_stats.most_common()),
                'top_critical_events': dict(critical_event_stats.most_common(15)),
                'top_users': dict(user_stats.most_common(10)),
                'top_sources': dict(source_stats.most_common(10))
            }
            
        except Exception as e:
            self.logger.error(f"❌ Erreur génération statistiques: {e}")

    def _detect_alerts(self):
        """Détecte les événements suspects et génère des alertes"""
        try:
            self.alerts = []
            
            # Détection de nettoyage de logs
            log_clearing_events = [e for e in self.events_data if e['event_id'] == 1102]
            if log_clearing_events:
                self.alerts.append({
                    'severity': 'HIGH',
                    'type': 'Log Clearing Detected',
                    'description': f"{len(log_clearing_events)} événement(s) de nettoyage de logs détecté(s)",
                    'events': log_clearing_events[:5]  # Top 5
                })
            
            # Multiple échecs de connexion
            failed_logins = [e for e in self.events_data if e['event_id'] == 4625]
            if len(failed_logins) > 10:
                self.alerts.append({
                    'severity': 'MEDIUM',
                    'type': 'Multiple Failed Logins',
                    'description': f"{len(failed_logins)} échecs de connexion détectés",
                    'count': len(failed_logins)
                })
            
            # Privilèges spéciaux fréquents
            privilege_events = [e for e in self.events_data if e['event_id'] == 4672]
            if len(privilege_events) > 5:
                self.alerts.append({
                    'severity': 'MEDIUM',
                    'type': 'Frequent Privilege Usage',
                    'description': f"{len(privilege_events)} utilisations de privilèges spéciaux",
                    'count': len(privilege_events)
                })
            
            # Services arrêtés de manière inattendue
            unexpected_service_stops = [e for e in self.events_data if e['event_id'] == 7034]
            if unexpected_service_stops:
                self.alerts.append({
                    'severity': 'MEDIUM',
                    'type': 'Unexpected Service Stops',
                    'description': f"{len(unexpected_service_stops)} arrêt(s) inattendu(s) de service",
                    'events': unexpected_service_stops[:3]
                })
            
            # Nouveaux comptes créés
            new_accounts = [e for e in self.events_data if e['event_id'] == 4720]
            if new_accounts:
                self.alerts.append({
                    'severity': 'LOW',
                    'type': 'New User Accounts',
                    'description': f"{len(new_accounts)} nouveau(x) compte(s) utilisateur créé(s)",
                    'events': new_accounts
                })
                
        except Exception as e:
            self.logger.error(f"❌ Erreur détection alertes: {e}")

    def get_forensic_summary(self):
        """Retourne un résumé forensique des découvertes"""
        try:
            summary = {
                'collection_timestamp': datetime.now().isoformat(),
                'total_events_analyzed': len(self.events_data),
                'critical_events_found': len([e for e in self.events_data if e['is_critical']]),
                'alerts_generated': len(self.alerts),
                'logs_analyzed': list(set([e['log_name'] for e in self.events_data])),
                'analysis_period': 'Last 1000 events per log',
                'key_findings': [],
                'recommendations': []
            }
            
            # Recommandations basées sur l'analyse
            if any(alert['type'] == 'Log Clearing Detected' for alert in self.alerts):
                summary['recommendations'].append("🚨 Nettoyage de logs détecté - Enquête approfondie recommandée")
                
            if len([e for e in self.events_data if e['event_id'] == 4625]) > 10:
                summary['recommendations'].append("🔐 Nombreux échecs de connexion - Vérifier les tentatives de brute force")
                
            if len([e for e in self.events_data if e['event_id'] == 4688]) > 100:
                summary['recommendations'].append("⚡ Activité processus élevée - Analyser les nouveaux processus")
                
            # Findings clés
            for alert in self.alerts[:5]:  # Top 5 alertes
                summary['key_findings'].append(f"{alert['severity']}: {alert['description']}")
            
            return summary
            
        except Exception as e:
            self.logger.error(f"❌ Erreur génération résumé: {e}")
            return None

# Import nécessaire pour le formatage des messages
try:
    import win32evtlogutil
except ImportError:
    # Fallback si win32evtlogutil n'est pas disponible
    class MockWin32EvtLogUtil:
        @staticmethod
        def SafeFormatMessage(event, log_name):
            return "Message formatting not available"
    
    win32evtlogutil = MockWin32EvtLogUtil()

if __name__ == "__main__":
    # Test du module
    collector = EventLogCollector()
    results = collector.collect(max_events=100)
    
    if results:
        print(f"✅ Collecte terminée: {results['total_events']} événements")
        print(f"🚨 Alertes générées: {len(results['alerts'])}")
        
        # Affichage des statistiques
        print("\n📊 STATISTIQUES:")
        for category, stats in results['statistics'].items():
            print(f"\n{category.upper()}:")
            if isinstance(stats, dict):
                for key, value in list(stats.items())[:5]:  # Top 5
                    print(f"  {key}: {value}")
    else:
        print("❌ Échec de la collecte")