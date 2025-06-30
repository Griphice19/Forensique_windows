"""
Registry Collector - Module de collecte du registre Windows
Agent Forensique - Module de collection d'artefacts forensiques
"""

import winreg
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os
import subprocess

class RegistryCollector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.registry_data = {}
        self.security_findings = []
        self.persistence_mechanisms = []
        self.user_activities = []
        
        # Clés de registre importantes pour l'analyse forensique
        self.important_keys = {
            # Démarrage automatique et persistance
            'autorun_currentuser': {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'description': 'Applications au démarrage (utilisateur courant)'
            },
            'autorun_localmachine': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'description': 'Applications au démarrage (machine)'
            },
            'autorun_runonce': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'description': 'Applications à exécuter une fois'
            },
            'services': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SYSTEM\CurrentControlSet\Services',
                'description': 'Services Windows installés'
            },
            
            # Activité utilisateur
            'userassist': {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist',
                'description': 'Programmes exécutés par l\'utilisateur'
            },
            'recent_docs': {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
                'description': 'Documents récents'
            },
            'typed_paths': {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
                'description': 'Chemins tapés dans l\'explorateur'
            },
            'mru_paths': {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU',
                'description': 'Fichiers récemment ouverts/sauvegardés'
            },
            
            # Informations système
            'current_version': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                'description': 'Informations version Windows'
            },
            'computer_name': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName',
                'description': 'Nom de l\'ordinateur'
            },
            'timezone': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SYSTEM\CurrentControlSet\Control\TimeZoneInformation',
                'description': 'Informations fuseau horaire'
            },
            
            # Sécurité et audit
            'audit_policy': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SECURITY\Policy\PolAdtEv',
                'description': 'Politique d\'audit'
            },
            'lsa_secrets': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SECURITY\Policy\Secrets',
                'description': 'Secrets LSA'
            },
            
            # Logiciels installés
            'installed_programs_32': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'description': 'Programmes installés (32-bit)'
            },
            'installed_programs_64': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                'description': 'Programmes installés (64-bit sur système 32-bit)'
            },
            
            # Réseau
            'network_profiles': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles',
                'description': 'Profils réseau'
            },
            'network_interfaces': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces',
                'description': 'Interfaces réseau'
            },
            
            # USB et périphériques
            'usb_storage': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SYSTEM\CurrentControlSet\Enum\USBSTOR',
                'description': 'Périphériques USB de stockage'
            },
            'mounted_devices': {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SYSTEM\MountedDevices',
                'description': 'Périphériques montés'
            },
            
            # Applications spécifiques
            'outlook_security': {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Office\Outlook\Security',
                'description': 'Paramètres sécurité Outlook'
            },
            'ie_typed_urls': {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Internet Explorer\TypedURLs',
                'description': 'URLs tapées dans Internet Explorer'
            }
        }
        
        # Patterns suspects à détecter
        self.suspicious_patterns = {
            'persistence_locations': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
            ],
            'suspicious_extensions': ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar'],
            'suspicious_paths': ['temp', 'appdata', 'downloads', 'desktop'],
            'remote_access_tools': ['teamviewer', 'vnc', 'rdp', 'logmein', 'anydesk']
        }

    def collect(self):
        """Collecte les données du registre Windows"""
        try:
            self.logger.info("🔍 Début de la collecte du registre Windows...")
            
            for key_name, key_info in self.important_keys.items():
                try:
                    self.logger.info(f"📊 Collecte de {key_name}...")
                    key_data = self._collect_registry_key(
                        key_info['hive'], 
                        key_info['path'], 
                        key_info['description']
                    )
                    if key_data:
                        self.registry_data[key_name] = key_data
                        self.logger.info(f"✅ {key_name}: {len(key_data.get('values', {}))} valeurs collectées")
                    
                except Exception as e:
                    self.logger.warning(f"⚠️ Erreur collecte {key_name}: {e}")
                    
            # Analyses spécialisées
            self._analyze_persistence_mechanisms()
            self._analyze_user_activity()
            self._analyze_security_settings()
            self._analyze_installed_software()
            self._analyze_network_activity()
            self._analyze_usb_devices()
            
            self.logger.info(f"✅ Collecte registre terminée: {len(self.registry_data)} sections analysées")
            
            return {
                'registry_data': self.registry_data,
                'security_findings': self.security_findings,
                'persistence_mechanisms': self.persistence_mechanisms,
                'user_activities': self.user_activities,
                'total_keys_analyzed': len(self.registry_data)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de la collecte du registre: {e}")
            return None

    def _collect_registry_key(self, hive, path, description, max_depth=2):
        """Collecte récursivement une clé de registre"""
        try:
            key_data = {
                'path': path,
                'description': description,
                'values': {},
                'subkeys': {},
                'last_modified': None,
                'error': None
            }
            
            # Ouvrir la clé
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                # Informations sur la clé
                num_subkeys, num_values, last_modified = winreg.QueryInfoKey(key)[:3]
                key_data['last_modified'] = datetime.fromtimestamp(last_modified/10000000 - 11644473600).isoformat()
                
                # Collecter les valeurs
                for i in range(num_values):
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        key_data['values'][name or '(Default)'] = {
                            'value': self._format_registry_value(value, reg_type),
                            'type': self._get_registry_type_name(reg_type),
                            'raw_type': reg_type
                        }
                    except Exception as e:
                        self.logger.debug(f"Erreur lecture valeur {i}: {e}")
                
                # Collecter les sous-clés (limitée en profondeur)
                if max_depth > 0:
                    for i in range(min(num_subkeys, 50)):  # Limiter à 50 sous-clés
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey_path = f"{path}\\{subkey_name}"
                            
                            # Collecter récursivement
                            subkey_data = self._collect_registry_key(
                                hive, subkey_path, f"Sous-clé de {description}", max_depth-1
                            )
                            if subkey_data:
                                key_data['subkeys'][subkey_name] = subkey_data
                                
                        except Exception as e:
                            self.logger.debug(f"Erreur lecture sous-clé {i}: {e}")
            
            return key_data
            
        except FileNotFoundError:
            self.logger.debug(f"Clé non trouvée: {path}")
            return None
        except PermissionError:
            self.logger.warning(f"Accès refusé: {path}")
            return {'error': 'Access Denied', 'path': path, 'description': description}
        except Exception as e:
            self.logger.warning(f"Erreur lecture clé {path}: {e}")
            return {'error': str(e), 'path': path, 'description': description}

    def _format_registry_value(self, value, reg_type):
        """Formate une valeur de registre selon son type"""
        try:
            if reg_type == winreg.REG_DWORD:
                return value
            elif reg_type == winreg.REG_QWORD:
                return value
            elif reg_type == winreg.REG_SZ or reg_type == winreg.REG_EXPAND_SZ:
                return str(value)
            elif reg_type == winreg.REG_MULTI_SZ:
                return list(value) if isinstance(value, (list, tuple)) else [str(value)]
            elif reg_type == winreg.REG_BINARY:
                return value.hex() if isinstance(value, bytes) else str(value)
            else:
                return str(value)
        except:
            return str(value)

    def _get_registry_type_name(self, reg_type):
        """Retourne le nom du type de registre"""
        type_names = {
            winreg.REG_BINARY: 'REG_BINARY',
            winreg.REG_DWORD: 'REG_DWORD',
            winreg.REG_DWORD_LITTLE_ENDIAN: 'REG_DWORD_LITTLE_ENDIAN',
            winreg.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
            winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
            winreg.REG_LINK: 'REG_LINK',
            winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
            winreg.REG_NONE: 'REG_NONE',
            winreg.REG_QWORD: 'REG_QWORD',
            winreg.REG_QWORD_LITTLE_ENDIAN: 'REG_QWORD_LITTLE_ENDIAN',
            winreg.REG_SZ: 'REG_SZ'
        }
        return type_names.get(reg_type, f'UNKNOWN_TYPE_{reg_type}')

    def _analyze_persistence_mechanisms(self):
        """Analyse les mécanismes de persistance"""
        try:
            self.logger.info("🔍 Analyse des mécanismes de persistance...")
            
            persistence_keys = ['autorun_currentuser', 'autorun_localmachine', 'autorun_runonce']
            
            for key_name in persistence_keys:
                if key_name in self.registry_data and 'values' in self.registry_data[key_name]:
                    values = self.registry_data[key_name]['values']
                    
                    for name, data in values.items():
                        if isinstance(data, dict) and 'value' in data:
                            value = str(data['value']).lower()
                            
                            # Détection de patterns suspects
                            is_suspicious = False
                            reasons = []
                            
                            # Vérifier les extensions suspectes
                            for ext in self.suspicious_patterns['suspicious_extensions']:
                                if ext in value:
                                    is_suspicious = True
                                    reasons.append(f"Extension suspecte: {ext}")
                            
                            # Vérifier les chemins suspects
                            for path in self.suspicious_patterns['suspicious_paths']:
                                if path in value:
                                    is_suspicious = True
                                    reasons.append(f"Chemin suspect: {path}")
                            
                            # Vérifier les outils d'accès distant
                            for tool in self.suspicious_patterns['remote_access_tools']:
                                if tool in value:
                                    reasons.append(f"Outil d'accès distant: {tool}")
                            
                            persistence_entry = {
                                'name': name,
                                'value': data['value'],
                                'location': self.registry_data[key_name]['path'],
                                'description': self.registry_data[key_name]['description'],
                                'is_suspicious': is_suspicious,
                                'reasons': reasons,
                                'last_modified': self.registry_data[key_name].get('last_modified')
                            }
                            
                            self.persistence_mechanisms.append(persistence_entry)
                            
                            if is_suspicious:
                                self.security_findings.append({
                                    'type': 'Suspicious Persistence',
                                    'severity': 'HIGH',
                                    'description': f"Entrée de persistance suspecte: {name}",
                                    'details': persistence_entry
                                })
                                
        except Exception as e:
            self.logger.error(f"❌ Erreur analyse persistance: {e}")

    def _analyze_user_activity(self):
        """Analyse l'activité utilisateur"""
        try:
            self.logger.info("🔍 Analyse de l'activité utilisateur...")
            
            # Analyser UserAssist (programmes exécutés)
            if 'userassist' in self.registry_data:
                self._analyze_userassist()
            
            # Analyser les documents récents
            if 'recent_docs' in self.registry_data:
                self._analyze_recent_documents()
            
            # Analyser les chemins tapés
            if 'typed_paths' in self.registry_data:
                self._analyze_typed_paths()
            
            # Analyser les URLs IE
            if 'ie_typed_urls' in self.registry_data:
                self._analyze_ie_urls()
                
        except Exception as e:
            self.logger.error(f"❌ Erreur analyse activité utilisateur: {e}")

    def _analyze_userassist(self):
        """Analyse les données UserAssist"""
        try:
            if 'subkeys' in self.registry_data['userassist']:
                for guid, guid_data in self.registry_data['userassist']['subkeys'].items():
                    if 'subkeys' in guid_data and 'Count' in guid_data['subkeys']:
                        count_data = guid_data['subkeys']['Count']
                        if 'values' in count_data:
                            for program, data in count_data['values'].items():
                                if isinstance(data, dict) and 'value' in data:
                                    # Décoder le nom du programme (ROT13)
                                    try:
                                        decoded_name = program.encode().decode('rot13')
                                    except:
                                        decoded_name = program
                                    
                                    self.user_activities.append({
                                        'type': 'Program Execution',
                                        'program': decoded_name,
                                        'raw_name': program,
                                        'run_count_data': data['value'],
                                        'source': 'UserAssist'
                                    })
        except Exception as e:
            self.logger.debug(f"Erreur analyse UserAssist: {e}")

    def _analyze_recent_documents(self):
        """Analyse les documents récents"""
        try:
            if 'values' in self.registry_data['recent_docs']:
                for name, data in self.registry_data['recent_docs']['values'].items():
                    if isinstance(data, dict) and 'value' in data and name != 'MRUListEx':
                        self.user_activities.append({
                            'type': 'Recent Document',
                            'document': data['value'],
                            'source': 'RecentDocs'
                        })
        except Exception as e:
            self.logger.debug(f"Erreur analyse documents récents: {e}")

    def _analyze_typed_paths(self):
        """Analyse les chemins tapés dans l'explorateur"""
        try:
            if 'values' in self.registry_data['typed_paths']:
                for name, data in self.registry_data['typed_paths']['values'].items():
                    if isinstance(data, dict) and 'value' in data:
                        self.user_activities.append({
                            'type': 'Typed Path',
                            'path': data['value'],
                            'source': 'TypedPaths'
                        })
        except Exception as e:
            self.logger.debug(f"Erreur analyse chemins tapés: {e}")

    def _analyze_ie_urls(self):
        """Analyse les URLs tapées dans Internet Explorer"""
        try:
            if 'values' in self.registry_data['ie_typed_urls']:
                for name, data in self.registry_data['ie_typed_urls']['values'].items():
                    if isinstance(data, dict) and 'value' in data:
                        self.user_activities.append({
                            'type': 'Typed URL',
                            'url': data['value'],
                            'source': 'IE TypedURLs'
                        })
        except Exception as e:
            self.logger.debug(f"Erreur analyse URLs IE: {e}")

    def _analyze_security_settings(self):
        """Analyse les paramètres de sécurité"""
        try:
            self.logger.info("🔍 Analyse des paramètres de sécurité...")
            
            # Vérifier les politiques d'audit (si accessible)
            if 'audit_policy' in self.registry_data:
                if self.registry_data['audit_policy'].get('error'):
                    self.security_findings.append({
                        'type': 'Security Access',
                        'severity': 'INFO',
                        'description': 'Impossible d\'accéder aux politiques d\'audit (normal sans privilèges admin)',
                        'details': 'Les politiques d\'audit nécessitent des privilèges élevés'
                    })
            
            # Vérifier les paramètres Outlook si présents
            if 'outlook_security' in self.registry_data and 'values' in self.registry_data['outlook_security']:
                outlook_values = self.registry_data['outlook_security']['values']
                for setting, data in outlook_values.items():
                    if 'security' in setting.lower() or 'macro' in setting.lower():
                        self.security_findings.append({
                            'type': 'Application Security',
                            'severity': 'INFO',
                            'description': f"Paramètre sécurité Outlook: {setting}",
                            'details': data
                        })
                        
        except Exception as e:
            self.logger.error(f"❌ Erreur analyse sécurité: {e}")

    def _analyze_installed_software(self):
        """Analyse les logiciels installés"""
        try:
            self.logger.info("🔍 Analyse des logiciels installés...")
            
            installed_software = []
            
            for key_name in ['installed_programs_32', 'installed_programs_64']:
                if key_name in self.registry_data and 'subkeys' in self.registry_data[key_name]:
                    for program_id, program_data in self.registry_data[key_name]['subkeys'].items():
                        if 'values' in program_data:
                            values = program_data['values']
                            
                            # Extraire les informations du programme
                            program_info = {
                                'id': program_id,
                                'name': values.get('DisplayName', {}).get('value', 'Unknown'),
                                'version': values.get('DisplayVersion', {}).get('value', 'Unknown'),
                                'publisher': values.get('Publisher', {}).get('value', 'Unknown'),
                                'install_date': values.get('InstallDate', {}).get('value', 'Unknown'),
                                'install_location': values.get('InstallLocation', {}).get('value', 'Unknown'),
                                'uninstall_string': values.get('UninstallString', {}).get('value', 'Unknown'),
                                'architecture': '64-bit' if key_name == 'installed_programs_64' else '32-bit'
                            }
                            
                            # Vérifier si c'est un logiciel potentiellement suspect
                            if self._is_suspicious_software(program_info):
                                self.security_findings.append({
                                    'type': 'Suspicious Software',
                                    'severity': 'MEDIUM',
                                    'description': f"Logiciel potentiellement suspect: {program_info['name']}",
                                    'details': program_info
                                })
                            
                            installed_software.append(program_info)
            
            # Stocker la liste des logiciels installés
            self.registry_data['software_analysis'] = {
                'total_programs': len(installed_software),
                'programs': installed_software[:50]  # Limiter à 50 pour éviter la surcharge
            }
            
        except Exception as e:
            self.logger.error(f"❌ Erreur analyse logiciels: {e}")

    def _is_suspicious_software(self, program_info):
        """Détermine si un logiciel est potentiellement suspect"""
        suspicious_keywords = [
            'remote', 'vnc', 'teamviewer', 'anydesk', 'logmein',
            'hack', 'crack', 'keygen', 'patch', 'loader',
            'rat', 'backdoor', 'trojan', 'keylogger'
        ]
        
        name_lower = program_info['name'].lower()
        publisher_lower = program_info['publisher'].lower()
        
        for keyword in suspicious_keywords:
            if keyword in name_lower or keyword in publisher_lower:
                return True
        
        # Vérifier les éditeurs non fiables
        if 'unknown' in publisher_lower or publisher_lower == '':
            return True
            
        return False

    def _analyze_network_activity(self):
        """Analyse l'activité réseau"""
        try:
            self.logger.info("🔍 Analyse de l'activité réseau...")
            
            # Analyser les profils réseau
            if 'network_profiles' in self.registry_data and 'subkeys' in self.registry_data['network_profiles']:
                network_profiles = []
                for profile_id, profile_data in self.registry_data['network_profiles']['subkeys'].items():
                    if 'values' in profile_data:
                        values = profile_data['values']
                        profile_info = {
                            'id': profile_id,
                            'name': values.get('ProfileName', {}).get('value', 'Unknown'),
                            'description': values.get('Description', {}).get('value', 'Unknown'),
                            'category': values.get('Category', {}).get('value', 'Unknown'),
                            'date_created': values.get('DateCreated', {}).get('value', 'Unknown')
                        }
                        network_profiles.append(profile_info)
                
                self.registry_data['network_analysis'] = {
                    'total_profiles': len(network_profiles),
                    'profiles': network_profiles
                }
                
        except Exception as e:
            self.logger.error(f"❌ Erreur analyse réseau: {e}")

    def _analyze_usb_devices(self):
        """Analyse les périphériques USB"""
        try:
            self.logger.info("🔍 Analyse des périphériques USB...")
            
            if 'usb_storage' in self.registry_data and 'subkeys' in self.registry_data['usb_storage']:
                usb_devices = []
                for device_id, device_data in self.registry_data['usb_storage']['subkeys'].items():
                    if 'subkeys' in device_data:
                        for instance_id, instance_data in device_data['subkeys'].items():
                            if 'values' in instance_data:
                                values = instance_data['values']
                                device_info = {
                                    'device_id': device_id,
                                    'instance_id': instance_id,
                                    'friendly_name': values.get('FriendlyName', {}).get('value', 'Unknown'),
                                    'device_desc': values.get('DeviceDesc', {}).get('value', 'Unknown'),
                                    'service': values.get('Service', {}).get('value', 'Unknown')
                                }
                                usb_devices.append(device_info)
                
                self.registry_data['usb_analysis'] = {
                    'total_devices': len(usb_devices),
                    'devices': usb_devices
                }
                
                # Alerter si beaucoup de périphériques USB
                if len(usb_devices) > 10:
                    self.security_findings.append({
                        'type': 'USB Activity',
                        'severity': 'INFO',
                        'description': f"Nombreux périphériques USB détectés: {len(usb_devices)}",
                        'details': f"{len(usb_devices)} périphériques USB ont été connectés"
                    })
                    
        except Exception as e:
            self.logger.error(f"❌ Erreur analyse USB: {e}")

    def get_forensic_summary(self):
        """Retourne un résumé forensique des découvertes du registre"""
        try:
            summary = {
                'collection_timestamp': datetime.now().isoformat(),
                'total_registry_keys_analyzed': len(self.registry_data),
                'security_findings_count': len(self.security_findings),
                'persistence_mechanisms_count': len(self.persistence_mechanisms),
                'user_activities_count': len(self.user_activities),
                'key_findings': [],
                'recommendations': []
            }
            
            # Findings clés
            high_severity_findings = [f for f in self.security_findings if f.get('severity') == 'HIGH']
            if high_severity_findings:
                summary['key_findings'].append(f"🚨 {len(high_severity_findings)} finding(s) de haute sévérité détecté(s)")
            
            suspicious_persistence = [p for p in self.persistence_mechanisms if p.get('is_suspicious')]
            if suspicious_persistence:
                summary['key_findings'].append(f"⚠️ {len(suspicious_persistence)} mécanisme(s) de persistance suspect(s)")
            
            if len(self.user_activities) > 0:
                summary['key_findings'].append(f"👤 {len(self.user_activities)} activité(s) utilisateur enregistrée(s)")
            
            # Recommandations
            if high_severity_findings:
                summary['recommendations'].append("🔍 Investiguer immédiatement les findings de haute sévérité")
            
            if suspicious_persistence:
                summary['recommendations'].append("🚨 Analyser les mécanismes de persistance suspects")
            
            if 'software_analysis' in self.registry_data:
                total_programs = self.registry_data['software_analysis']['total_programs']
                summary['recommendations'].append(f"📊 Auditer la liste des {total_programs} logiciels installés")
            
            summary['recommendations'].append("🔒 Vérifier les paramètres de sécurité système")
            summary['recommendations'].append("🌐 Analyser l'historique des connexions réseau")
            summary['recommendations'].append("💾 Examiner l'activité des périphériques USB")
            
            return summary
            
        except Exception as e:
            self.logger.error(f"❌ Erreur génération résumé: {e}")
            return None

    def export_to_json(self, filepath):
        """Exporte les données du registre vers un fichier JSON"""
        try:
            export_data = {
                'collection_info': {
                    'timestamp': datetime.now().isoformat(),
                    'collector': 'RegistryCollector',
                    'version': '1.0'
                },
                'registry_data': self.registry_data,
                'security_findings': self.security_findings,
                'persistence_mechanisms': self.persistence_mechanisms,
                'user_activities': self.user_activities,
                'forensic_summary': self.get_forensic_summary()
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
                
            self.logger.info(f"✅ Données exportées vers: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Erreur export JSON: {e}")
            return False

    def get_timeline_data(self):
        """Génère une timeline des activités basée sur le registre"""
        try:
            timeline = []
            
            # Ajouter les événements de persistance
            for persistence in self.persistence_mechanisms:
                if persistence.get('last_modified'):
                    timeline.append({
                        'timestamp': persistence['last_modified'],
                        'type': 'Persistence Mechanism',
                        'description': f"Mécanisme de persistance: {persistence['name']}",
                        'severity': 'HIGH' if persistence.get('is_suspicious') else 'LOW',
                        'details': persistence
                    })
            
            # Ajouter les activités utilisateur (approximatif)
            for activity in self.user_activities:
                timeline.append({
                    'timestamp': datetime.now().isoformat(),  # Approximatif
                    'type': activity['type'],
                    'description': f"{activity['type']}: {activity.get('program', activity.get('document', activity.get('path', activity.get('url', 'Unknown'))))}",
                    'severity': 'INFO',
                    'details': activity
                })
            
            # Trier par timestamp
            timeline.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return timeline[:100]  # Top 100 événements
            
        except Exception as e:
            self.logger.error(f"❌ Erreur génération timeline: {e}")
            return []

    def search_registry(self, search_term, case_sensitive=False):
        """Recherche un terme dans toutes les données du registre collectées"""
        try:
            results = []
            search_term_processed = search_term if case_sensitive else search_term.lower()
            
            def search_in_data(data, path=""):
                if isinstance(data, dict):
                    for key, value in data.items():
                        current_path = f"{path}.{key}" if path else key
                        
                        # Rechercher dans la clé
                        key_str = key if case_sensitive else str(key).lower()
                        if search_term_processed in key_str:
                            results.append({
                                'type': 'Registry Key',
                                'path': current_path,
                                'match': key,
                                'context': str(value)[:200] + "..." if len(str(value)) > 200 else str(value)
                            })
                        
                        # Recherche récursive
                        search_in_data(value, current_path)
                        
                elif isinstance(data, (list, tuple)):
                    for i, item in enumerate(data):
                        search_in_data(item, f"{path}[{i}]")
                        
                else:
                    # Rechercher dans la valeur
                    value_str = str(data) if case_sensitive else str(data).lower()
                    if search_term_processed in value_str:
                        results.append({
                            'type': 'Registry Value',
                            'path': path,
                            'match': str(data),
                            'context': str(data)
                        })
            
            # Rechercher dans toutes les données
            search_in_data(self.registry_data)
            search_in_data(self.security_findings, "security_findings")
            search_in_data(self.persistence_mechanisms, "persistence_mechanisms")
            search_in_data(self.user_activities, "user_activities")
            
            self.logger.info(f"🔍 Recherche '{search_term}': {len(results)} résultats trouvés")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Erreur recherche registre: {e}")
            return []

if __name__ == "__main__":
    # Test du module
    import sys
    
    print("🚀 Test du RegistryCollector...")
    collector = RegistryCollector()
    
    try:
        results = collector.collect()
        
        if results:
            print(f"\n✅ COLLECTE RÉUSSIE")
            print(f"📊 Clés analysées: {results['total_keys_analyzed']}")
            print(f"🚨 Findings sécurité: {len(results['security_findings'])}")
            print(f"🔄 Mécanismes persistance: {len(results['persistence_mechanisms'])}")
            print(f"👤 Activités utilisateur: {len(results['user_activities'])}")
            
            # Afficher les findings de haute sévérité
            high_severity = [f for f in results['security_findings'] if f.get('severity') == 'HIGH']
            if high_severity:
                print(f"\n🚨 FINDINGS HAUTE SÉVÉRITÉ:")
                for finding in high_severity[:5]:
                    print(f"  - {finding['description']}")
            
            # Afficher quelques mécanismes de persistance
            if results['persistence_mechanisms']:
                print(f"\n🔄 MÉCANISMES DE PERSISTANCE:")
                for mech in results['persistence_mechanisms'][:5]:
                    status = "⚠️ SUSPECT" if mech.get('is_suspicious') else "✅ Normal"
                    print(f"  - {mech['name']}: {mech['value']} [{status}]")
            
            # Afficher le résumé forensique
            summary = collector.get_forensic_summary()
            if summary and summary.get('recommendations'):
                print(f"\n💡 RECOMMANDATIONS:")
                for rec in summary['recommendations'][:3]:
                    print(f"  - {rec}")
            
            # Test d'export
            export_file = f"registry_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            if collector.export_to_json(export_file):
                print(f"\n💾 Données exportées: {export_file}")
            
            # Test de recherche
            if len(sys.argv) > 1:
                search_term = sys.argv[1]
                search_results = collector.search_registry(search_term)
                print(f"\n🔍 Recherche '{search_term}': {len(search_results)} résultats")
                for result in search_results[:3]:
                    print(f"  - {result['type']}: {result['path']} = {result['match']}")
        
        else:
            print("❌ ÉCHEC DE LA COLLECTE")
            
    except Exception as e:
        print(f"❌ ERREUR: {e}")
        import traceback
        traceback.print_exc()