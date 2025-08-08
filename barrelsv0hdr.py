import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import requests
import json
import os
import platform
import subprocess
import hashlib
import threading
import zipfile
import shutil
import uuid
import http.server
import socketserver
import webbrowser

# Define get_minecraft_dir function before using it
def get_minecraft_dir():
    if platform.system() == 'Windows':
        return os.path.join(os.environ['APPDATA'], '.minecraft')
    elif platform.system() == 'Darwin':
        return os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'minecraft')
    else:
        return os.path.join(os.path.expanduser('~'), '.minecraft')

VERSION_MANIFEST_URL = 'https://piston-meta.mojang.com/mc/game/version_manifest.json'
MINECRAFT_DIR = get_minecraft_dir()
VERSIONS_DIR = os.path.join(MINECRAFT_DIR, 'versions')
JAVA_DIR = os.path.join(MINECRAFT_DIR, 'java')
THEME = {'bg': '#181818', 'fg': 'white', 'accent': '#6A1B9A'}
# Replace with your Ely.by OAuth2 app credentials
CLIENT_ID = "your_client_id_here"
CLIENT_SECRET = "your_client_secret_here"
REDIRECT_URI = "http://localhost:8000/callback"

class OAuth2CallbackHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/callback?'):
            self.server.auth_code = self.path.split('code=')[1].split('&')[0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Login successful! You can close this window.</h1></body></html>")
            self.server.stop = True

class BarrelsClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BARRELSCLIENT")
        self.root.geometry("500x600")
        self.root.resizable(False, False)
        self.root.configure(bg=THEME['bg'])
        self.version_manifest = None
        self.selected_version = None
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.auth_tokens = {}  # Store Ely.by tokens
        self.skin_path = None
        self.init_ui()
        self.install_java_if_needed()
        self.load_version_manifest()

    def init_ui(self):
        header = tk.Label(self.root, text="BARRELSCLIENT", font=('Arial', 18, 'bold'), bg=THEME['bg'], fg=THEME['fg'])
        header.pack(pady=20)

        account_frame = tk.Frame(self.root, bg=THEME['bg'])
        account_frame.pack(pady=10)
        tk.Label(account_frame, text="Username (or email for Ely.by):", bg=THEME['bg'], fg=THEME['fg']).grid(row=0, column=0, padx=5)
        tk.Entry(account_frame, textvariable=self.username, bg='#333', fg=THEME['fg'], insertbackground=THEME['fg']).grid(row=0, column=1)
        tk.Label(account_frame, text="Password (Mojang/Ely.by):", bg=THEME['bg'], fg=THEME['fg']).grid(row=1, column=0, padx=5)
        tk.Entry(account_frame, textvariable=self.password, show="*", bg='#333', fg=THEME['fg'], insertbackground=THEME['fg']).grid(row=1, column=1)

        auth_label = tk.Label(self.root, text="Auth Mode:", font=('Arial', 12), bg=THEME['bg'], fg=THEME['fg'])
        auth_label.pack(pady=5)
        self.auth_mode_combobox = ttk.Combobox(self.root, values=["Mojang", "Ely.by (OAuth2)", "Ely.by (Direct)", "Offline"], state='readonly', width=30)
        self.auth_mode_combobox.pack(pady=5)
        self.auth_mode_combobox.current(0)

        version_label = tk.Label(self.root, text="Select Version:", font=('Arial', 12), bg=THEME['bg'], fg=THEME['fg'])
        version_label.pack(pady=10)
        self.version_combobox = ttk.Combobox(self.root, state='readonly', width=30)
        self.version_combobox.pack(pady=10)
        self.version_combobox.bind("<<ComboboxSelected>>", lambda e: self.update_account_fields())

        skin_button = tk.Button(self.root, text="Select Skin", command=self.select_skin, bg=THEME['accent'], fg=THEME['fg'], font=('Arial', 12))
        skin_button.pack(pady=10)

        launch_button = tk.Button(self.root, text="Launch", command=self.prepare_and_launch, bg=THEME['accent'], fg=THEME['fg'], font=('Arial', 12, 'bold'))
        launch_button.pack(pady=20)
        launch_button.bind("<Enter>", self.on_enter)
        launch_button.bind("<Leave>", self.on_leave)

        self.status = tk.Label(self.root, text="", font=('Arial', 10), bg=THEME['bg'], fg=THEME['fg'])
        self.status.pack(pady=10)

    def on_enter(self, event):
        event.widget['bg'] = '#8E24AA'

    def on_leave(self, event):
        event.widget['bg'] = THEME['accent']

    def _clear_placeholder(self, event):
        pass

    def _restore_placeholder(self, event):
        pass

    def update_account_fields(self):
        pass

    def update_version_list(self):
        if self.version_manifest:
            versions = [v['id'] for v in self.version_manifest['versions']]
            self.version_combobox['values'] = versions
            self.version_combobox.current(0)

    def load_version_manifest(self):
        try:
            response = requests.get(VERSION_MANIFEST_URL)
            self.version_manifest = response.json()
            self.update_version_list()
            self.status.config(text="Versions loaded.", fg='green')
        except Exception as e:
            self.status.config(text=f"Error loading manifest: {e}", fg='red')

    def is_java_installed(self):
        java_path = os.path.join(JAVA_DIR, 'bin', 'java.exe' if platform.system() == 'Windows' else 'java')
        return os.path.exists(java_path)

    def install_java(self):
        try:
            os.makedirs(JAVA_DIR, exist_ok=True)
            sys_os = platform.system().lower()
            if sys_os == 'darwin':
                sys_os = 'mac'
            jdk_url = f'https://api.adoptium.net/v3/binary/latest/21/ga/{sys_os}/x64/jdk/hotspot/normal/eclipse?project=jdk'
            response = requests.get(jdk_url, stream=True)
            zip_path = os.path.join(JAVA_DIR, 'jdk.zip')
            with open(zip_path, 'wb') as f:
                shutil.copyfileobj(response.raw, f)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(JAVA_DIR)
            os.remove(zip_path)
            self.status.config(text="Java installed.", fg='green')
        except Exception as e:
            self.status.config(text=f"Error installing Java: {e}", fg='red')

    def install_java_if_needed(self):
        if not self.is_java_installed():
            if messagebox.askyesno("Java Required", "Java not found. Install now?"):
                self.install_java()

    def select_skin(self):
        mode = self.auth_mode_combobox.get()
        self.skin_path = filedialog.askopenfilename(title="Select Skin", filetypes=[("PNG Files", "*.png")])
        if self.skin_path:
            skin_dest = os.path.join(MINECRAFT_DIR, 'skins', os.path.basename(self.skin_path))
            os.makedirs(os.path.dirname(skin_dest), exist_ok=True)
            shutil.copy(self.skin_path, skin_dest)
            if mode in ["Ely.by (OAuth2)", "Ely.by (Direct)"]:
                try:
                    with open(self.skin_path, 'rb') as f:
                        files = {'skin': (os.path.basename(self.skin_path), f, 'image/png')}
                        headers = {'Authorization': f'Bearer {self.auth_tokens.get("access_token")}'}
                        response = requests.post('https://account.ely.by/api/skins/v1/skin', files=files, headers=headers)
                        response.raise_for_status()
                        self.status.config(text="Skin uploaded to Ely.by.", fg='green')
                except Exception as e:
                    self.status.config(text=f"Error uploading skin: {e}", fg='red')
            else:
                self.status.config(text="Skin selected.", fg='green')

    def verify_file(self, path, expected_sha1):
        if not os.path.exists(path):
            return False
        with open(path, 'rb') as f:
            return hashlib.sha1(f.read()).hexdigest() == expected_sha1

    def download_version_files(self, version_data):
        version_id = version_data['id']
        version_folder = os.path.join(VERSIONS_DIR, version_id)
        os.makedirs(version_folder, exist_ok=True)

        jar_dl = version_data['downloads']['client']
        jar_path = os.path.join(version_folder, f"{version_id}.jar")
        if not self.verify_file(jar_path, jar_dl['sha1']):
            with requests.get(jar_dl['url'], stream=True) as r:
                with open(jar_path, 'wb') as f:
                    shutil.copyfileobj(r.raw, f)

        libs_dir = os.path.join(MINECRAFT_DIR, 'libraries')
        sys_os = platform.system().lower().replace('darwin', 'osx')
        natives_dir = os.path.join(version_folder, f'{version_id}-natives')
        os.makedirs(natives_dir, exist_ok=True)
        for lib in version_data['libraries']:
            if not self.is_library_allowed(lib):
                continue
            downloads = lib.get('downloads', {})
            if 'artifact' in downloads:
                art = downloads['artifact']
                lib_path = os.path.join(libs_dir, art['path'])
                os.makedirs(os.path.dirname(lib_path), exist_ok=True)
                if not self.verify_file(lib_path, art['sha1']):
                    with requests.get(art['url'], stream=True) as r:
                        with open(lib_path, 'wb') as f:
                            shutil.copyfileobj(r.raw, f)
            if 'natives' in lib:
                classifier = lib['natives'].get(sys_os)
                if classifier and 'classifiers' in downloads and classifier in downloads['classifiers']:
                    nat = downloads['classifiers'][classifier]
                    nat_path = os.path.join(libs_dir, nat['path'])
                    os.makedirs(os.path.dirname(nat_path), exist_ok=True)
                    if not self.verify_file(nat_path, nat['sha1']):
                        with requests.get(nat['url'], stream=True) as r:
                            with open(nat_path, 'wb') as f:
                                shutil.copyfileobj(r.raw, f)
                    with zipfile.ZipFile(nat_path, 'r') as zip_ref:
                        exclude = lib.get('extract', {}).get('exclude', [])
                        for file in zip_ref.namelist():
                            if file.startswith('META-INF/') or any(file.startswith(ex) for ex in exclude):
                                continue
                            zip_ref.extract(file, natives_dir)

        asset_index = version_data['assetIndex']
        assets_dir = os.path.join(MINECRAFT_DIR, 'assets')
        index_path = os.path.join(assets_dir, 'indexes', f"{version_data['assets']}.json")
        os.makedirs(os.path.dirname(index_path), exist_ok=True)
        if not self.verify_file(index_path, asset_index['sha1']):
            with requests.get(asset_index['url']) as r:
                with open(index_path, 'w') as f:
                    f.write(r.text)
        with open(index_path, 'r') as f:
            asset_data = json.load(f)
        objects_dir = os.path.join(assets_dir, 'objects')
        for obj in asset_data['objects'].values():
            hash_ = obj['hash']
            size = obj['size']
            first2 = hash_[:2]
            obj_path = os.path.join(objects_dir, first2, hash_)
            os.makedirs(os.path.dirname(obj_path), exist_ok=True)
            if os.path.exists(obj_path) and os.path.getsize(obj_path) == size and self.verify_file(obj_path, hash_):
                continue
            obj_url = f'https://resources.download.minecraft.net/{first2}/{hash_}'
            with requests.get(obj_url, stream=True) as r:
                with open(obj_path, 'wb') as f:
                    shutil.copyfileobj(r.raw, f)

        return natives_dir

    def modify_options_txt(self):
        options_path = os.path.join(MINECRAFT_DIR, 'options.txt')
        if not os.path.exists(options_path):
            with open(options_path, 'w') as f:
                f.write('')
        with open(options_path, 'a') as f:
            f.write('\nfullscreen:true\n')

    def is_library_allowed(self, lib):
        return self.evaluate_rules(lib.get('rules', []))

    def evaluate_rules(self, rules):
        if not rules:
            return True
        allow = False
        sys_os = platform.system().lower().replace('darwin', 'osx')
        for rule in rules:
            if 'os' in rule and rule['os'].get('name') != sys_os:
                continue
            if rule['action'] == 'allow':
                allow = True
            elif rule['action'] == 'disallow':
                allow = False
        return allow

    def generate_offline_uuid(self, username):
        return hashlib.md5(f"OfflinePlayer:{username}".encode()).hexdigest()

    def authenticate_elyby_oauth(self):
        auth_url = f"https://account.ely.by/oauth2/v1?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=minecraft_server_session account_info"
        webbrowser.open(auth_url)

        with socketserver.TCPServer(("localhost", 8000), OAuth2CallbackHandler) as httpd:
            httpd.auth_code = None
            httpd.stop = False
            while not httpd.stop:
                httpd.handle_request()
            auth_code = httpd.auth_code

        if not auth_code:
            raise Exception("OAuth2 login cancelled.")
        token_url = "https://account.ely.by/api/oauth2/v1/token"
        payload = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code': auth_code,
            'grant_type': 'authorization_code',
            'redirect_uri': REDIRECT_URI
        }
        try:
            response = requests.post(token_url, data=payload)
            response.raise_for_status()
            self.auth_tokens = response.json()
            user_info = requests.get('https://account.ely.by/api/account/v1/info', headers={
                'Authorization': f'Bearer {self.auth_tokens["access_token"]}'
            }).json()
            return {
                'uuid': user_info['uuid'],
                'accessToken': self.auth_tokens['accessToken'],
                'name': user_info['username']
            }
        except Exception as e:
            raise Exception(f"OAuth2 token exchange failed: {e}")

    def authenticate(self):
        mode = self.auth_mode_combobox.get()
        username = self.username.get()
        if mode == "Offline":
            if not username:
                raise Exception("Username required for offline mode.")
            return {'uuid': self.generate_offline_uuid(username), 'accessToken': '0', 'name': username}
        if mode == "Ely.by (OAuth2)":
            try:
                return self.authenticate_elyby_oauth()
            except Exception as e:
                messagebox.showerror("Auth Error", f"Ely.by OAuth2 failed: {e}. Falling back to offline mode.")
                return {'uuid': self.generate_offline_uuid(username), 'accessToken': '0', 'name': username}
        password = self.password.get()
        if not username or not password:
            raise Exception("Credentials required for online auth.")
        client_token = str(uuid.uuid4())
        payload = {
            "agent": {"name": "Minecraft", "version": 1},
            "username": username,
            "password": password,
            "clientToken": client_token,
            "requestUser": True
        }
        auth_url = 'https://authserver.mojang.com/authenticate' if mode == "Mojang" else 'https://authserver.ely.by/auth/authenticate'
        try:
            response = requests.post(auth_url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.auth_tokens = {'access_token': data['accessToken'], 'client_token': client_token}
                return {
                    'uuid': data['selectedProfile']['id'],
                    'accessToken': data['accessToken'],
                    'name': data['selectedProfile']['name']
                }
            elif mode == "Ely.by (Direct)" and response.status_code == 401 and "Account protected with two factor auth." in response.json().get('errorMessage', ''):
                totp = simpledialog.askstring("2FA Required", "Enter your 2FA code:")
                if not totp:
                    raise Exception("2FA cancelled.")
                payload['password'] = password + ":" + totp
                response = requests.post(auth_url, json=payload)
                response.raise_for_status()
                data = response.json()
                self.auth_tokens = {'access_token': data['accessToken'], 'client_token': client_token}
                return {
                    'uuid': data['selectedProfile']['id'],
                    'accessToken': data['accessToken'],
                    'name': data['selectedProfile']['name']
                }
            else:
                raise Exception(f"Auth failed: {response.text}")
        except Exception as e:
            messagebox.showerror("Auth Error", f"Authentication failed: {e}. Falling back to offline mode.")
            return {'uuid': self.generate_offline_uuid(username), 'accessToken': '0', 'name': username}

    def ensure_authlib_injector(self):
        path = os.path.join(MINECRAFT_DIR, 'authlib-injector.jar')
        if not os.path.exists(path):
            try:
                url = 'https://authlib-injector.yushi.moe/artifact/latest.jar'
                r = requests.get(url, stream=True)
                with open(path, 'wb') as f:
                    shutil.copyfileobj(r.raw, f)
                self.status.config(text="Downloaded authlib-injector for Ely.by support.", fg='green')
            except Exception as e:
                raise Exception(f"Failed to download authlib-injector: {e}")
        return path

    def build_launch_command(self, version_data, auth, natives_dir):
        java_path = os.path.join(JAVA_DIR, 'bin', 'java.exe' if platform.system() == 'Windows' else 'java')
        version_id = version_data['id']
        game_dir = MINECRAFT_DIR
        assets_dir = os.path.join(MINECRAFT_DIR, 'assets')
        asset_index = version_data['assets']
        main_class = version_data['mainClass']
        jvm_args = version_data.get('arguments', {}).get('jvm', []) + ['-Xmx2G', f'-Djava.library.path={natives_dir}']
        game_args = version_data.get('arguments', {}).get('game', []) + [
            '--version', version_id,
            '--gameDir', game_dir,
            '--assetsDir', assets_dir,
            '--assetIndex', asset_index,
            '--uuid', auth['uuid'],
            '--username', auth['name'],
            '--accessToken', auth['accessToken']
        ]

        if self.auth_mode_combobox.get() in ["Ely.by (OAuth2)", "Ely.by (Direct)"]:
            authlib_path = self.ensure_authlib_injector()
            jvm_args = [f'-javaagent:{authlib_path}=authserver.ely.by'] + jvm_args

        cp = [os.path.join(VERSIONS_DIR, version_id, f"{version_id}.jar")]
        for lib in version_data['libraries']:
            if self.is_library_allowed(lib) and 'downloads' in lib and 'artifact' in lib['downloads']:
                cp.append(os.path.join(MINECRAFT_DIR, 'libraries', lib['downloads']['artifact']['path']))
        classpath = os.pathsep.join(cp)

        cmd = [java_path] + jvm_args + ['-cp', classpath, main_class] + game_args
        return cmd

    def prepare_and_launch(self):
        selected = self.version_combobox.get()
        if not selected:
            self.status.config(text="Select a version.", fg='red')
            return
        try:
            version_url = next(v['url'] for v in self.version_manifest['versions'] if v['id'] == selected)
            version_data = requests.get(version_url).json()
            natives_dir = self.download_version_files(version_data)
            self.modify_options_txt()
            auth = self.authenticate()
            cmd = self.build_launch_command(version_data, auth, natives_dir)
            threading.Thread(target=self.launch_thread, args=(cmd,)).start()
            self.status.config(text="Launching...", fg='green')
        except Exception as e:
            self.status.config(text=f"Error: {e}", fg='red')

    def launch_thread(self, cmd):
        try:
            subprocess.run(cmd, cwd=MINECRAFT_DIR)
            self.status.config(text="Game closed.", fg='green')
        except Exception as e:
            self.status.config(text=f"Launch failed: {e}", fg='red')

if __name__ == "__main__":
    root = tk.Tk()
    app = BarrelsClientApp(root)
    root.mainloop()
