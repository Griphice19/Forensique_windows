#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USB Forensic Collector - Module de collecte des artefacts USB
Collecte l'historique des périphériques USB, activité, métadonnées
Compatible avec votre système de collecte forensique
"""

import os
import sys
import json
import winreg
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging
import hashlib

class USBCollector:
    """Collecteur d'artefacts USB pour investigation forensique"""
    
    def __init__(self, output_dir: str = "usb_artifacts"):
        """
        Initialise le collecteur USB
        
        Args:
            output_dir: Répertoire de sortie pour les artefacts
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Configuration du logging
        self.logger = self._setup_logging()
        
        # Statistiques de collecte
        self.stats = {
            'devices_found': 0,
            'registry_entries': 0,
            'log_entries': 0,
            'mount_points': 0,
            'errors': 0,
            'start_time': datetime.now(timezone.utc),
            'end_time': None
        }
        
        # Clés de registre importantes pour USB
        self.registry_keys = {
            'USBSTOR': r'SYSTEM\CurrentControlSet\Enum\USBSTOR',
            'USB': r'SYSTEM\CurrentControlSet\Enum\USB',
            'MountedDevices': r'SYSTEM\MountedDevices',
            'MountPoints2': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2',
            'USBFlags': r'SYSTEM\CurrentControlSet\Control\UsbFlags',
            'DeviceClasses': r'SYSTEM\CurrentControlSet\Control\DeviceClasses'
        }
        
        self.logger.info("USBCollector initialisé")

    def _setup_logging(self) -> logging.Logger:
        """Configure le système de logging"""
        logger = logging.getLogger('USBCollector')
        logger.setLevel(logging.INFO)
        
        # Handler pour fichier
        file_handler = logging.FileHandler(
            self.output_dir / 'usb_collection.log',
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        if not logger.handlers:
            logger.addHandler(file_handler)
        
        return logger

    def collect_all(self) -> Dict[str, Any]:
        """
        Collecte tous les artefacts USB
        
        Returns:
            Dictionnaire avec tous les artefacts collectés
        """
        self.logger.info("Début de la collecte USB complète")
        
        artifacts = {
            'collection_info': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'collector': 'USBCollector',
                'version': '1.0.0',
                'system': self._get_system_info()
            },
            'usb_devices': [],
            'registry_artifacts': {},
            'mount_points': [],
            'event_logs': [],
            'physical_devices': [],
            'statistics': {}
        }
        
        try:
            # Collecte des périphériques USB
            artifacts['usb_devices'] = self._collect_usb_devices()
            
            # Collecte du registre
            artifacts['registry_artifacts'] = self._collect_registry_artifacts()
            
            # Collecte des points de montage
            artifacts['mount_points'] = self._collect_mount_points()
            
            # Collecte des logs d'événements
            artifacts['event_logs'] = self._collect_event_logs()
            
            # Collecte des périphériques physiques
            artifacts['physical_devices'] = self._collect_physical_devices()
            
            # Mise à jour des statistiques
            self._update_statistics()
            artifacts['statistics'] = self.stats
            
            # Sauvegarde des artefacts
            self._save_artifacts(artifacts)
            
            self.logger.info("Collecte USB terminée avec succès")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte USB: {e}")
            self.stats['errors'] += 1
            
        return artifacts

    def _collect_usb_devices(self) -> List[Dict[str, Any]]:
        """Collecte les informations des périphériques USB"""
        devices = []
        
        try:
            # Collecte via WMI
            wmi_devices = self._get_wmi_usb_devices()
            devices.extend(wmi_devices)
            
            # Collecte via registre USBSTOR
            registry_devices = self._get_registry_usb_devices()
            devices.extend(registry_devices)
            
            # Déduplication basée sur le VID/PID
            unique_devices = self._deduplicate_devices(devices)
            
            self.stats['devices_found'] = len(unique_devices)
            self.logger.info(f"Trouvé {len(unique_devices)} périphériques USB")
            
            return unique_devices
            
        except Exception as e:
            self.logger.error(f"Erreur collecte périphériques USB: {e}")
            self.stats['errors'] += 1
            return []

    def _get_wmi_usb_devices(self) -> List[Dict[str, Any]]:
        """Collecte via WMI (Windows Management Instrumentation)"""
        devices = []
        
        try:
            # Commande PowerShell pour obtenir les infos USB
            cmd = [
                'powershell', '-Command',
                '''
                Get-WmiObject -Class Win32_USBHub | ForEach-Object {
                    [PSCustomObject]@{
                        DeviceID = $_.DeviceID
                        Description = $_.Description
                        Name = $_.Name
                        Status = $_.Status
                        SystemName = $_.SystemName
                        Service = $_.Service
                    }
                } | ConvertTo-Json -Depth 3
                '''
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                wmi_data = json.loads(result.stdout)
                
                # Assurer que c'est une liste
                if not isinstance(wmi_data, list):
                    wmi_data = [wmi_data]
                
                for device in wmi_data:
                    device_info = {
                        'source': 'WMI',
                        'device_id': device.get('DeviceID', ''),
                        'description': device.get('Description', ''),
                        'name': device.get('Name', ''),
                        'status': device.get('Status', ''),
                        'system_name': device.get('SystemName', ''),
                        'service': device.get('Service', ''),
                        'collection_time': datetime.now(timezone.utc).isoformat(),
                        'vid_pid': self._extract_vid_pid(device.get('DeviceID', ''))
                    }
                    devices.append(device_info)
                    
        except Exception as e:
            self.logger.error(f"Erreur WMI USB: {e}")
            
        return devices

    def _get_registry_usb_devices(self) -> List[Dict[str, Any]]:
        """Collecte depuis le registre USBSTOR"""
        devices = []
        
        try:
            # Ouverture de la clé USBSTOR
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.registry_keys['USBSTOR']) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        
                        # Ouvrir la sous-clé
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            device_info = {
                                'source': 'Registry_USBSTOR',
                                'key_name': subkey_name,
                                'collection_time': datetime.now(timezone.utc).isoformat()
                            }
                            
                            # Extraction des informations du nom de clé
                            parts = subkey_name.split('&')
                            if len(parts) >= 2:
                                device_info['device_type'] = parts[0]
                                device_info['vendor_product'] = parts[1] if len(parts) > 1 else ''
                                device_info['revision'] = parts[2] if len(parts) > 2 else ''
                            
                            # Énumération des instances
                            device_info['instances'] = []
                            j = 0
                            while True:
                                try:
                                    instance_name = winreg.EnumKey(subkey, j)
                                    
                                    # Informations de l'instance
                                    with winreg.OpenKey(subkey, instance_name) as instance_key:
                                        instance_info = {
                                            'instance_id': instance_name,
                                            'properties': {}
                                        }
                                        
                                        # Lecture des propriétés
                                        k = 0
                                        while True:
                                            try:
                                                prop_name, prop_value, prop_type = winreg.EnumValue(instance_key, k)
                                                instance_info['properties'][prop_name] = {
                                                    'value': str(prop_value) if prop_value else '',
                                                    'type': prop_type
                                                }
                                                k += 1
                                            except OSError:
                                                break
                                        
                                        device_info['instances'].append(instance_info)
                                    
                                    j += 1
                                except OSError:
                                    break
                            
                            devices.append(device_info)
                        
                        i += 1
                    except OSError:
                        break
                        
        except Exception as e:
            self.logger.error(f"Erreur registre USBSTOR: {e}")
            
        return devices

    def _collect_registry_artifacts(self) -> Dict[str, Any]:
        """Collecte tous les artefacts du registre liés aux USB"""
        artifacts = {}
        
        for key_name, key_path in self.registry_keys.items():
            try:
                artifacts[key_name] = self._read_registry_key(key_path)
                self.stats['registry_entries'] += len(artifacts[key_name].get('values', []))
                
            except Exception as e:
                self.logger.error(f"Erreur lecture clé {key_name}: {e}")
                artifacts[key_name] = {'error': str(e)}
                
        return artifacts

    def _read_registry_key(self, key_path: str) -> Dict[str, Any]:
        """Lit une clé de registre complètement"""
        result = {
            'path': key_path,
            'values': [],
            'subkeys': [],
            'read_time': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                # Lecture des valeurs
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        result['values'].append({
                            'name': name,
                            'value': self._format_registry_value(value, reg_type),
                            'type': reg_type,
                            'type_name': self._get_registry_type_name(reg_type)
                        })
                        i += 1
                    except OSError:
                        break
                
                # Lecture des sous-clés (limitée en profondeur)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        result['subkeys'].append(subkey_name)
                        i += 1
                    except OSError:
                        break
                        
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def _collect_mount_points(self) -> List[Dict[str, Any]]:
        """Collecte les points de montage USB"""
        mount_points = []
        
        try:
            # Points de montage système
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.registry_keys['MountedDevices']) as key:
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        
                        if 'USBSTOR' in str(value) or name.startswith('\\DosDevices\\'):
                            mount_info = {
                                'name': name,
                                'value': self._format_binary_data(value),
                                'type': self._get_registry_type_name(reg_type),
                                'is_usb': 'USBSTOR' in str(value),
                                'collection_time': datetime.now(timezone.utc).isoformat()
                            }
                            mount_points.append(mount_info)
                        
                        i += 1
                    except OSError:
                        break
                        
            self.stats['mount_points'] = len(mount_points)
            
        except Exception as e:
            self.logger.error(f"Erreur collecte points de montage: {e}")
            
        return mount_points

    def _collect_event_logs(self) -> List[Dict[str, Any]]:
        """Collecte les logs d'événements liés aux USB"""
        events = []
        
        try:
            # Commande PowerShell pour les événements USB
            cmd = [
                'powershell', '-Command',
                '''
                Get-WinEvent -FilterHashtable @{LogName="System"; ID=20001,20003,10000,10001} -MaxEvents 100 -ErrorAction SilentlyContinue | 
                Where-Object {$_.Message -match "USB|Mass Storage"} |
                ForEach-Object {
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        Id = $_.Id
                        LevelDisplayName = $_.LevelDisplayName
                        Message = $_.Message
                        LogName = $_.LogName
                        ProviderName = $_.ProviderName
                    }
                } | ConvertTo-Json -Depth 3
                '''
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and result.stdout.strip():
                log_data = json.loads(result.stdout)
                
                if not isinstance(log_data, list):
                    log_data = [log_data]
                
                for event in log_data:
                    event_info = {
                        'time_created': event.get('TimeCreated', ''),
                        'event_id': event.get('Id', 0),
                        'level': event.get('LevelDisplayName', ''),
                        'message': event.get('Message', ''),
                        'log_name': event.get('LogName', ''),
                        'provider': event.get('ProviderName', ''),
                        'collection_time': datetime.now(timezone.utc).isoformat()
                    }
                    events.append(event_info)
                    
            self.stats['log_entries'] = len(events)
            
        except Exception as e:
            self.logger.error(f"Erreur collecte logs événements: {e}")
            
        return events

    def _collect_physical_devices(self) -> List[Dict[str, Any]]:
        """Collecte les informations des périphériques physiques"""
        devices = []
        
        try:
            # Commande PowerShell pour les périphériques physiques
            cmd = [
                'powershell', '-Command',
                '''
                Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2} |
                ForEach-Object {
                    [PSCustomObject]@{
                        DeviceID = $_.DeviceID
                        Description = $_.Description
                        FileSystem = $_.FileSystem
                        Size = $_.Size
                        FreeSpace = $_.FreeSpace
                        VolumeName = $_.VolumeName
                        VolumeSerialNumber = $_.VolumeSerialNumber
                        MediaType = $_.MediaType
                    }
                } | ConvertTo-Json -Depth 3
                '''
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                device_data = json.loads(result.stdout)
                
                if not isinstance(device_data, list):
                    device_data = [device_data]
                
                for device in device_data:
                    device_info = {
                        'device_id': device.get('DeviceID', ''),
                        'description': device.get('Description', ''),
                        'file_system': device.get('FileSystem', ''),
                        'size': device.get('Size', 0),
                        'free_space': device.get('FreeSpace', 0),
                        'volume_name': device.get('VolumeName', ''),
                        'volume_serial': device.get('VolumeSerialNumber', ''),
                        'media_type': device.get('MediaType', ''),
                        'collection_time': datetime.now(timezone.utc).isoformat()
                    }
                    
                    # Calcul de l'espace utilisé
                    if device_info['size'] and device_info['free_space']:
                        device_info['used_space'] = device_info['size'] - device_info['free_space']
                        device_info['usage_percent'] = (device_info['used_space'] / device_info['size']) * 100
                    
                    devices.append(device_info)
                    
        except Exception as e:
            self.logger.error(f"Erreur collecte périphériques physiques: {e}")
            
        return devices

    def _deduplicate_devices(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Supprime les doublons de périphériques"""
        seen_devices = set()
        unique_devices = []
        
        for device in devices:
            # Création d'une signature unique
            device_id = device.get('device_id', '')
            vid_pid = device.get('vid_pid', '')
            name = device.get('name', '')
            
            signature = f"{device_id}_{vid_pid}_{name}"
            
            if signature not in seen_devices:
                seen_devices.add(signature)
                unique_devices.append(device)
                
        return unique_devices

    def _extract_vid_pid(self, device_id: str) -> str:
        """Extrait VID/PID depuis un device ID"""
        try:
            if 'VID_' in device_id and 'PID_' in device_id:
                vid_start = device_id.find('VID_') + 4
                vid_end = device_id.find('&', vid_start)
                vid = device_id[vid_start:vid_end] if vid_end != -1 else device_id[vid_start:vid_start+4]
                
                pid_start = device_id.find('PID_') + 4
                pid_end = device_id.find('&', pid_start)
                pid = device_id[pid_start:pid_end] if pid_end != -1 else device_id[pid_start:pid_start+4]
                
                return f"VID_{vid}&PID_{pid}"
        except:
            pass
        return ''

    def _format_registry_value(self, value: Any, reg_type: int) -> str:
        """Formate une valeur de registre pour l'affichage"""
        try:
            if reg_type == winreg.REG_BINARY:
                return self._format_binary_data(value)
            elif reg_type == winreg.REG_DWORD:
                return f"0x{value:08X} ({value})"
            elif reg_type == winreg.REG_QWORD:
                return f"0x{value:016X} ({value})"
            else:
                return str(value) if value is not None else ""
        except:
            return str(value) if value is not None else ""

    def _format_binary_data(self, data: bytes) -> str:
        """Formate des données binaires"""
        try:
            if isinstance(data, bytes):
                # Tentative de décodage UTF-16 pour les chaînes Unicode
                if len(data) > 1 and data[1] == 0:
                    try:
                        decoded = data.decode('utf-16le').rstrip('\x00')
                        if decoded.isprintable():
                            return f'"{decoded}"'
                    except:
                        pass
                
                # Format hexadécimal
                hex_str = ' '.join(f'{b:02X}' for b in data[:50])
                if len(data) > 50:
                    hex_str += "..."
                return hex_str
        except:
            pass
        return str(data)

    def _get_registry_type_name(self, reg_type: int) -> str:
        """Retourne le nom du type de registre"""
        type_names = {
            winreg.REG_BINARY: "REG_BINARY",
            winreg.REG_DWORD: "REG_DWORD",
            winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
            winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
            winreg.REG_NONE: "REG_NONE",
            winreg.REG_QWORD: "REG_QWORD",
            winreg.REG_SZ: "REG_SZ"
        }
        return type_names.get(reg_type, f"UNKNOWN_{reg_type}")

    def _get_system_info(self) -> Dict[str, str]:
        """Récupère les informations système"""
        return {
            'platform': sys.platform,
            'hostname': os.environ.get('COMPUTERNAME', 'Unknown'),
            'username': os.environ.get('USERNAME', 'Unknown'),
            'python_version': sys.version.split()[0]
        }

    def _update_statistics(self):
        """Met à jour les statistiques de collecte"""
        self.stats['end_time'] = datetime.now(timezone.utc)
        duration = self.stats['end_time'] - self.stats['start_time']
        self.stats['duration_seconds'] = duration.total_seconds()

    def _save_artifacts(self, artifacts: Dict[str, Any]):
        """Sauvegarde les artefacts collectés"""
        try:
            # Sauvegarde JSON principale
            json_file = self.output_dir / f"usb_artifacts_{int(time.time())}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(artifacts, f, indent=2, ensure_ascii=False, default=str)
            
            # Sauvegarde CSV pour les périphériques
            self._save_devices_csv(artifacts.get('usb_devices', []))
            
            # Rapport de synthèse
            self._generate_summary_report(artifacts)
            
            self.logger.info(f"Artefacts sauvegardés dans {json_file}")
            
        except Exception as e:
            self.logger.error(f"Erreur sauvegarde artefacts: {e}")

    def _save_devices_csv(self, devices: List[Dict[str, Any]]):
        """Sauvegarde les périphériques en format CSV"""
        try:
            import csv
            
            csv_file = self.output_dir / f"usb_devices_{int(time.time())}.csv"
            
            if devices:
                fieldnames = set()
                for device in devices:
                    fieldnames.update(device.keys())
                
                with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    writer.writerows(devices)
                    
                self.logger.info(f"Périphériques sauvegardés en CSV: {csv_file}")
                
        except Exception as e:
            self.logger.error(f"Erreur sauvegarde CSV: {e}")

    def _generate_summary_report(self, artifacts: Dict[str, Any]):
        """Génère un rapport de synthèse"""
        try:
            report_file = self.output_dir / f"usb_summary_{int(time.time())}.txt"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("=== RAPPORT DE COLLECTE USB FORENSIQUE ===\n\n")
                f.write(f"Date de collecte: {artifacts['collection_info']['timestamp']}\n")
                f.write(f"Système: {artifacts['collection_info']['system']['hostname']}\n")
                f.write(f"Utilisateur: {artifacts['collection_info']['system']['username']}\n\n")
                
                f.write("=== STATISTIQUES ===\n")
                stats = artifacts.get('statistics', {})
                f.write(f"Périphériques trouvés: {stats.get('devices_found', 0)}\n")
                f.write(f"Entrées de registre: {stats.get('registry_entries', 0)}\n")
                f.write(f"Points de montage: {stats.get('mount_points', 0)}\n")
                f.write(f"Logs d'événements: {stats.get('log_entries', 0)}\n")
                f.write(f"Erreurs: {stats.get('errors', 0)}\n")
                f.write(f"Durée: {stats.get('duration_seconds', 0):.2f} secondes\n\n")
                
                f.write("=== PÉRIPHÉRIQUES USB DÉTECTÉS ===\n")
                for i, device in enumerate(artifacts.get('usb_devices', []), 1):
                    f.write(f"\n{i}. {device.get('name', 'Périphérique inconnu')}\n")
                    f.write(f"   ID: {device.get('device_id', 'N/A')}\n")
                    f.write(f"   Description: {device.get('description', 'N/A')}\n")
                    f.write(f"   Source: {device.get('source', 'N/A')}\n")
                    f.write(f"   VID/PID: {device.get('vid_pid', 'N/A')}\n")
                
            self.logger.info(f"Rapport de synthèse généré: {report_file}")
            
        except Exception as e:
            self.logger.error(f"Erreur génération rapport: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de collecte"""
        return self.stats.copy()

    def cleanup(self):
        """Nettoyage des ressources"""
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)


def main():
    """Fonction principale pour test"""
    print("🔌 USB Forensic Collector - Test")
    print("=" * 50)
    
    collector = USBCollector("test_usb_output")
    
    try:
        artifacts = collector.collect_all()
        stats = collector.get_stats()
        
        print(f"\n✅ Collecte terminée!")
        print(f"📊 Statistiques:")
        print(f"   - Périphériques: {stats['devices_found']}")
        print(f"   - Entrées registre: {stats['registry_entries']}")
        print(f"   - Points montage: {stats['mount_points']}")
        print(f"   - Logs: {stats['log_entries']}")
        print(f"   - Durée: {stats.get('duration_seconds', 0):.2f}s")
        print(f"   - Erreurs: {stats['errors']}")
        
    except KeyboardInterrupt:
        print("\n❌ Collecte interrompue par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
    finally:
        collector.cleanup()


if __name__ == "__main__":
    main()