#!/usr/bin/env python3
"""
Module de collecte d'informations réseau pour l'agent forensique Windows
Collecte les connexions actives, ports ouverts, historique DNS, ARP, etc.
"""

import subprocess
import json
import socket
import psutil
import re
from datetime import datetime, timedelta
import os
import logging

class NetworkCollector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.results = {
            'metadata': {
                'collector': 'NetworkCollector',
                'timestamp': datetime.now().isoformat(),
                'hostname': socket.gethostname()
            },
            'connections': [],
            'listening_ports': [],
            'network_interfaces': [],
            'arp_table': [],
            'dns_cache': [],
            'routing_table': [],
            'network_shares': [],
            'firewall_rules': [],
            'wifi_profiles': [],
            'statistics': {},
            'analysis': {
                'suspicious_connections': [],
                'unusual_ports': [],
                'external_connections': [],
                'timeline': [],
                'recommendations': []
            }
        }
        
        # Ports suspects connus
        self.suspicious_ports = {
            22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB',
            1433: 'SQL Server', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM HTTPS',
            4444: 'Metasploit', 4445: 'Metasploit', 31337: 'Back Orifice',
            12345: 'NetBus', 20034: 'NetBus', 1234: 'SubSeven'
        }

    def collect_all(self):
        """Collecte toutes les informations réseau"""
        self.logger.info("🌐 Début de la collecte des informations réseau...")
        
        try:
            self.collect_active_connections()
            self.collect_listening_ports()
            self.collect_network_interfaces()
            self.collect_arp_table()
            self.collect_dns_cache()
            self.collect_routing_table()
            self.collect_network_shares()
            self.collect_firewall_rules()
            self.collect_wifi_profiles()
            self.collect_network_statistics()
            self.analyze_network_data()
            
            self.logger.info("✅ Collecte réseau terminée avec succès")
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de la collecte réseau: {e}")
            return self.results

    def collect_active_connections(self):
        """Collecte les connexions réseau actives"""
        try:
            self.logger.info("📡 Collecte des connexions actives...")
            
            # Utilisation de psutil pour les connexions
            connections = psutil.net_connections(kind='all')
            
            for conn in connections:
                try:
                    process = None
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process = {
                                'pid': conn.pid,
                                'name': proc.name(),
                                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat()
                            }
                        except:
                            process = {'pid': conn.pid, 'name': 'Unknown'}
                    
                    connection_data = {
                        'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                        'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                        'status': conn.status,
                        'process': process
                    }
                    
                    self.results['connections'].append(connection_data)
                    
                    # Analyse des connexions suspectes
                    if conn.raddr and self.is_suspicious_connection(conn):
                        self.results['analysis']['suspicious_connections'].append({
                            'connection': connection_data,
                            'reason': self.get_suspicious_reason(conn)
                        })
                        
                except Exception as e:
                    self.logger.warning(f"Erreur traitement connexion: {e}")
                    
        except Exception as e:
            self.logger.error(f"Erreur collecte connexions: {e}")

    def collect_listening_ports(self):
        """Collecte les ports en écoute"""
        try:
            self.logger.info("🎯 Collecte des ports en écoute...")
            
            connections = psutil.net_connections(kind='inet')
            listening = [c for c in connections if c.status == 'LISTEN']
            
            for conn in listening:
                try:
                    process = None
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process = {
                                'pid': conn.pid,
                                'name': proc.name(),
                                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else ''
                            }
                        except:
                            pass
                    
                    port_info = {
                        'address': conn.laddr.ip if conn.laddr else 'N/A',
                        'port': conn.laddr.port if conn.laddr else 'N/A',
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'process': process,
                        'service': self.identify_service(conn.laddr.port if conn.laddr else 0)
                    }
                    
                    self.results['listening_ports'].append(port_info)
                    
                    # Vérification ports suspects
                    if conn.laddr and conn.laddr.port in self.suspicious_ports:
                        self.results['analysis']['unusual_ports'].append({
                            'port': conn.laddr.port,
                            'service': self.suspicious_ports[conn.laddr.port],
                            'process': process,
                            'risk': 'High'
                        })
                        
                except Exception as e:
                    self.logger.warning(f"Erreur traitement port: {e}")
                    
        except Exception as e:
            self.logger.error(f"Erreur collecte ports: {e}")

    def collect_network_interfaces(self):
        """Collecte les interfaces réseau"""
        try:
            self.logger.info("🔌 Collecte des interfaces réseau...")
            
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for interface, addresses in interfaces.items():
                interface_data = {
                    'name': interface,
                    'addresses': [],
                    'statistics': stats.get(interface)._asdict() if interface in stats else {}
                }
                
                for addr in addresses:
                    address_info = {
                        'family': addr.family.name if hasattr(addr.family, 'name') else str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_data['addresses'].append(address_info)
                
                self.results['network_interfaces'].append(interface_data)
                
        except Exception as e:
            self.logger.error(f"Erreur collecte interfaces: {e}")

    def collect_arp_table(self):
        """Collecte la table ARP"""
        try:
            self.logger.info("📋 Collecte de la table ARP...")
            
            result = subprocess.run(['arp', '-a'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    # Format: Interface: 192.168.1.1 --- 0x2
                    # ou: 192.168.1.1    00-11-22-33-44-55     dynamique
                    if '---' in line or 'Interface:' in line:
                        continue
                        
                    parts = line.split()
                    if len(parts) >= 3:
                        arp_entry = {
                            'ip_address': parts[0].strip('()'),
                            'mac_address': parts[1],
                            'type': parts[2] if len(parts) > 2 else 'unknown'
                        }
                        self.results['arp_table'].append(arp_entry)
                        
        except Exception as e:
            self.logger.error(f"Erreur collecte ARP: {e}")

    def collect_dns_cache(self):
        """Collecte le cache DNS"""
        try:
            self.logger.info("🌍 Collecte du cache DNS...")
            
            result = subprocess.run(['ipconfig', '/displaydns'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                current_record = {}
                lines = result.stdout.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        if current_record:
                            self.results['dns_cache'].append(current_record)
                            current_record = {}
                        continue
                        
                    if '-------' in line:
                        continue
                        
                    if ':' in line:
                        key, value = line.split(':', 1)
                        current_record[key.strip()] = value.strip()
                
                if current_record:
                    self.results['dns_cache'].append(current_record)
                    
        except Exception as e:
            self.logger.error(f"Erreur collecte DNS: {e}")

    def collect_routing_table(self):
        """Collecte la table de routage"""
        try:
            self.logger.info("🛣️ Collecte de la table de routage...")
            
            result = subprocess.run(['route', 'print'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                parsing_routes = False
                
                for line in lines:
                    line = line.strip()
                    if 'Destination réseau' in line or 'Network Destination' in line:
                        parsing_routes = True
                        continue
                    
                    if parsing_routes and line and not line.startswith('='):
                        parts = line.split()
                        if len(parts) >= 5:
                            route_entry = {
                                'destination': parts[0],
                                'netmask': parts[1],
                                'gateway': parts[2],
                                'interface': parts[3],
                                'metric': parts[4] if len(parts) > 4 else 'N/A'
                            }
                            self.results['routing_table'].append(route_entry)
                            
        except Exception as e:
            self.logger.error(f"Erreur collecte routage: {e}")

    def collect_network_shares(self):
        """Collecte les partages réseau"""
        try:
            self.logger.info("📂 Collecte des partages réseau...")
            
            result = subprocess.run(['net', 'share'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip() and not line.startswith('-'):
                        parts = line.split()
                        if len(parts) >= 2:
                            share_info = {
                                'name': parts[0],
                                'path': ' '.join(parts[1:]).split()[0] if len(parts) > 1 else 'N/A',
                                'description': ' '.join(parts[2:]) if len(parts) > 2 else ''
                            }
                            self.results['network_shares'].append(share_info)
                            
        except Exception as e:
            self.logger.error(f"Erreur collecte partages: {e}")

    def collect_firewall_rules(self):
        """Collecte les règles de pare-feu"""
        try:
            self.logger.info("🛡️ Collecte des règles de pare-feu...")
            
            result = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
            ], capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                current_rule = {}
                lines = result.stdout.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        if current_rule:
                            self.results['firewall_rules'].append(current_rule)
                            current_rule = {}
                        continue
                        
                    if ':' in line:
                        key, value = line.split(':', 1)
                        current_rule[key.strip()] = value.strip()
                
                if current_rule:
                    self.results['firewall_rules'].append(current_rule)
                    
        except Exception as e:
            self.logger.error(f"Erreur collecte firewall: {e}")

    def collect_wifi_profiles(self):
        """Collecte les profils WiFi"""
        try:
            self.logger.info("📶 Collecte des profils WiFi...")
            
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Profil Tous les utilisateurs' in line or 'All User Profile' in line:
                        profile_name = line.split(':')[1].strip()
                        
                        # Collecte des détails du profil
                        detail_result = subprocess.run([
                            'netsh', 'wlan', 'show', 'profile', profile_name, 'key=clear'
                        ], capture_output=True, text=True, shell=True)
                        
                        profile_info = {'name': profile_name, 'details': {}}
                        
                        if detail_result.returncode == 0:
                            detail_lines = detail_result.stdout.split('\n')
                            for detail_line in detail_lines:
                                if ':' in detail_line:
                                    key, value = detail_line.split(':', 1)
                                    profile_info['details'][key.strip()] = value.strip()
                        
                        self.results['wifi_profiles'].append(profile_info)
                        
        except Exception as e:
            self.logger.error(f"Erreur collecte WiFi: {e}")

    def collect_network_statistics(self):
        """Collecte les statistiques réseau"""
        try:
            self.logger.info("📊 Collecte des statistiques réseau...")
            
            net_io = psutil.net_io_counters()
            
            self.results['statistics'] = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_received': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_received': net_io.packets_recv,
                'errors_in': net_io.errin,
                'errors_out': net_io.errout,
                'drops_in': net_io.dropin,
                'drops_out': net_io.dropout,
                'total_connections': len(self.results['connections']),
                'listening_ports_count': len(self.results['listening_ports']),
                'active_interfaces': len([i for i in self.results['network_interfaces'] 
                                        if i.get('statistics', {}).get('isup', False)])
            }
            
        except Exception as e:
            self.logger.error(f"Erreur collecte statistiques: {e}")

    def analyze_network_data(self):
        """Analyse les données réseau collectées"""
        try:
            self.logger.info("🔍 Analyse des données réseau...")
            
            # Analyse des connexions externes
            for conn in self.results['connections']:
                if conn.get('remote_address') and conn['remote_address'] != 'N/A':
                    remote_ip = conn['remote_address'].split(':')[0]
                    if not self.is_local_ip(remote_ip):
                        self.results['analysis']['external_connections'].append({
                            'connection': conn,
                            'remote_ip': remote_ip,
                            'analysis': self.analyze_ip(remote_ip)
                        })
            
            # Timeline des événements
            now = datetime.now()
            self.results['analysis']['timeline'] = [
                {
                    'timestamp': now.isoformat(),
                    'event': 'Network scan completed',
                    'details': f"Found {len(self.results['connections'])} connections, "
                              f"{len(self.results['listening_ports'])} listening ports"
                }
            ]
            
            # Recommandations
            recommendations = []
            
            if len(self.results['analysis']['suspicious_connections']) > 0:
                recommendations.append({
                    'level': 'HIGH',
                    'title': 'Connexions suspectes détectées',
                    'description': f"{len(self.results['analysis']['suspicious_connections'])} connexions suspectes trouvées",
                    'action': 'Analyser immédiatement ces connexions'
                })
            
            if len(self.results['analysis']['unusual_ports']) > 0:
                recommendations.append({
                    'level': 'MEDIUM',
                    'title': 'Ports suspects en écoute',
                    'description': f"{len(self.results['analysis']['unusual_ports'])} ports suspects trouvés",
                    'action': 'Vérifier la légitimité de ces services'
                })
            
            if len(self.results['analysis']['external_connections']) > 10:
                recommendations.append({
                    'level': 'MEDIUM',
                    'title': 'Nombreuses connexions externes',
                    'description': f"{len(self.results['analysis']['external_connections'])} connexions externes",
                    'action': 'Examiner le trafic réseau sortant'
                })
            
            self.results['analysis']['recommendations'] = recommendations
            
        except Exception as e:
            self.logger.error(f"Erreur analyse réseau: {e}")

    def is_suspicious_connection(self, conn):
        """Détermine si une connexion est suspecte"""
        try:
            if not conn.raddr:
                return False
                
            # Ports suspects
            if conn.raddr.port in self.suspicious_ports:
                return True
                
            # Connexions vers des IPs privées externes
            remote_ip = conn.raddr.ip
            if remote_ip and not self.is_local_ip(remote_ip):
                # Vérification de ports non standards
                if conn.raddr.port > 49152:  # Ports dynamiques
                    return True
                    
            return False
            
        except:
            return False

    def get_suspicious_reason(self, conn):
        """Retourne la raison pour laquelle une connexion est suspecte"""
        reasons = []
        
        try:
            if conn.raddr and conn.raddr.port in self.suspicious_ports:
                reasons.append(f"Port suspect: {self.suspicious_ports[conn.raddr.port]}")
                
            if conn.raddr and conn.raddr.port > 49152:
                reasons.append("Port dynamique élevé")
                
            return ", ".join(reasons) if reasons else "Connexion inhabituelle"
            
        except:
            return "Connexion suspecte"

    def is_local_ip(self, ip):
        """Vérifie si une IP est locale"""
        try:
            if ip in ['127.0.0.1', '::1', 'localhost']:
                return True
                
            # Plages IP privées
            if (ip.startswith('192.168.') or 
                ip.startswith('10.') or 
                ip.startswith('172.16.') or
                ip.startswith('169.254.')):  # Link-local
                return True
                
            return False
            
        except:
            return False

    def analyze_ip(self, ip):
        """Analyse basique d'une IP"""
        try:
            analysis = {
                'ip': ip,
                'type': 'unknown',
                'risk_level': 'low'
            }
            
            # Classification basique
            if self.is_local_ip(ip):
                analysis['type'] = 'local'
            else:
                analysis['type'] = 'external'
                analysis['risk_level'] = 'medium'
            
            return analysis
            
        except:
            return {'ip': ip, 'type': 'unknown', 'risk_level': 'unknown'}

    def identify_service(self, port):
        """Identifie le service basé sur le port"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'SQL Server', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM HTTPS'
        }
        
        return common_ports.get(port, f'Port {port}')

    def export_results(self, output_file=None):
        """Exporte les résultats en JSON"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"network_forensics_{timestamp}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"📁 Résultats exportés vers: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Erreur export: {e}")
            return None

    def get_summary(self):
        """Retourne un résumé de l'analyse"""
        summary = {
            'total_connections': len(self.results['connections']),
            'listening_ports': len(self.results['listening_ports']),
            'network_interfaces': len(self.results['network_interfaces']),
            'suspicious_connections': len(self.results['analysis']['suspicious_connections']),
            'unusual_ports': len(self.results['analysis']['unusual_ports']),
            'external_connections': len(self.results['analysis']['external_connections']),
            'recommendations': len(self.results['analysis']['recommendations']),
            'risk_level': self.calculate_risk_level()
        }
        
        return summary

    def calculate_risk_level(self):
        """Calculate le niveau de risque global"""
        risk_score = 0
        
        risk_score += len(self.results['analysis']['suspicious_connections']) * 3
        risk_score += len(self.results['analysis']['unusual_ports']) * 2
        risk_score += min(len(self.results['analysis']['external_connections']), 20)
        
        if risk_score >= 15:
            return 'HIGH'
        elif risk_score >= 8:
            return 'MEDIUM'
        else:
            return 'LOW'

def main():
    """Fonction principale pour test du module"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🌐 Agent Forensique - Module Network")
    print("=" * 50)
    
    collector = NetworkCollector()
    results = collector.collect_all()
    
    # Affichage du résumé
    summary = collector.get_summary()
    print(f"\n📊 RÉSUMÉ DE L'ANALYSE RÉSEAU")
    print(f"{'='*40}")
    print(f"Connexions actives: {summary['total_connections']}")
    print(f"Ports en écoute: {summary['listening_ports']}")
    print(f"Interfaces réseau: {summary['network_interfaces']}")
    print(f"Connexions suspectes: {summary['suspicious_connections']}")
    print(f"Ports inhabituels: {summary['unusual_ports']}")
    print(f"Connexions externes: {summary['external_connections']}")
    print(f"Niveau de risque: {summary['risk_level']}")
    
    # Export des résultats
    output_file = collector.export_results()
    if output_file:
        print(f"\n📁 Résultats sauvegardés: {output_file}")
    
    # Affichage des recommandations
    recommendations = results['analysis']['recommendations']
    if recommendations:
        print(f"\n🚨 RECOMMANDATIONS ({len(recommendations)}):")
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. [{rec['level']}] {rec['title']}")
            print(f"   {rec['description']}")
            print(f"   Action: {rec['action']}\n")

if __name__ == "__main__":
    main()