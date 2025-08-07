import os
import random
import time
import threading
import re
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template_string, request, redirect, url_for
import logging
import warnings
warnings.filterwarnings("ignore", message=".*Do not use it in a production deployment.*")

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) 
class UltimatePenTestSimulator:
    def __init__(self):
        # Initialize game state
        self._initialize_game_state()
        self._print_banner()
        self._start_background_threads()
        self._setup_web_interface()

    def _initialize_game_state(self):
        """Initialize all game state variables"""
        self.target_systems = self._create_target_systems()
        self.internet_hosts = self._generate_decoys()
        self.all_hosts = self._merge_and_shuffle_hosts()
        
        # Player state
        self.current_system = None
        self.current_path = "/"
        self.current_web_path = "/"
        self.score = 0
        self.discovered_ips = set()
        self.session_active = True
        self.web_session = False
        self.listening = False
        self.credentials = defaultdict(dict)  # Track found credentials
        self.email_access = defaultdict(dict)  # Track accessed email accounts
        
        # Game configuration
        self.SCORE_VALUES = {
            'credential_find': 10,
            'system_compromise': 25,
            'vulnerability_find': 5,
            'file_download': 5,
            'password_reset': 15,
            'payment_redirect': 20,
            'email_access': 15,
            'malicious_upload': 10
        }

    def _setup_web_interface(self):
        """Setup Flask web interface for realistic interactions"""
        self.web_app = Flask(__name__)
        self.web_app.config['SECRET_KEY'] = 'not-a-real-secret-key'
        self.web_app.config['DEBUG'] = False 
        @self.web_app.route('/')
        def home():
            if not self.web_session:
                return "No active web session. Use 'web <ip>' from the command interface first."
            
            host = next((h for h in self.all_hosts if h["ip"] == self.current_system)), None
            if not host or "web_admin" not in host:
                return "Invalid web session"
            
            return self._render_web_interface(host, "/")
        
        @self.web_app.route('/<path:subpath>')
        def catch_all(subpath):
            if not self.web_session:
                return "No active web session"
            
            host = next((h for h in self.all_hosts if h["ip"] == self.current_system), None)
            if not host or "web_admin" not in host:
                return "Invalid web session"
            
            return self._render_web_interface(host, f"/{subpath}")
        
        @self.web_app.route('/login', methods=['POST'])
        def handle_login():
            username = request.form.get('username')
            password = request.form.get('password')
            self.auth(username, password)
            return redirect(url_for('home'))
        
        @self.web_app.route('/reset_password', methods=['POST'])
        def handle_password_reset():
            username = request.form.get('username')
            email = request.form.get('email')
            return self._handle_password_reset(username, email)
        
        @self.web_app.route('/execute_sql', methods=['POST'])
        def handle_sql():
            query = request.form.get('query')
            return self._handle_sql_execution(query)
        
        @self.web_app.route('/upload', methods=['POST'])
        def handle_upload():
            filename = request.form.get('filename')
            content = request.form.get('content')
            return self._handle_file_upload(filename, content)
        
        @self.web_app.route('/redirect_payment', methods=['POST'])
        def handle_payment_redirect():
            original_account = request.form.get('original_account')
            target_account = request.form.get('target_account')
            amount = request.form.get('amount')
            return self._handle_payment_redirect(original_account, target_account, amount)
        
        @self.web_app.route('/access_email', methods=['POST'])
        def handle_email_access():
            email_account = request.form.get('email_account')
            return self._handle_email_access(email_account)
        
        # Run Flask in a separate thread
        self.flask_thread = threading.Thread(
            target=lambda: self.web_app.run(
                port=3021,  # ← updated port
                debug=False,
                use_reloader=False,
                host='127.0.0.1',
                passthrough_errors=True
            ),
            daemon=True
        )

        self.flask_thread.start()

    def _render_web_interface(self, host, path):
        """Render the appropriate web interface based on path"""
        template = ""
        
        if path == "/":
            # Login page
            template = """
            <h2>Bank Admin Portal</h2>
            <form action="/login" method="post">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
            <hr>
            <h3>Forgot Password?</h3>
            <form action="/reset_password" method="post">
                Username: <input type="text" name="username"><br>
                Email: <input type="text" name="email"><br>
                <input type="submit" value="Reset Password">
            </form>
            """
        elif path == "/admin/dashboard":
            # Admin dashboard
            template = """
            <h2>Admin Dashboard</h2>
            <p>Welcome to the bank administration portal</p>
            
            <h3>User Management</h3>
            <ul>
                <li>Admin Users: admin, backupadmin</li>
                <li>Total Customers: 12,487</li>
            </ul>
            
            <h3>Payment Redirection</h3>
            <form action="/redirect_payment" method="post">
                Original Account: <input type="text" name="original_account"><br>
                Target Account: <input type="text" name="target_account"><br>
                Amount: <input type="text" name="amount"><br>
                <input type="submit" value="Redirect Payment">
            </form>
            
            <h3>File Upload</h3>
            <form action="/upload" method="post">
                Filename: <input type="text" name="filename"><br>
                Content: <textarea name="content"></textarea><br>
                <input type="submit" value="Upload">
            </form>
            
            <h3>Email Access</h3>
            <form action="/access_email" method="post">
                Email Account: <input type="text" name="email_account"><br>
                <input type="submit" value="Access Emails">
            </form>
            """
        elif path == "/admin/users":
            # User management
            template = """
            <h2>User Management</h2>
            <table border="1">
                <tr><th>Username</th><th>Role</th><th>Last Login</th></tr>
                <tr><td>admin</td><td>Super Admin</td><td>Today</td></tr>
                <tr><td>backupadmin</td><td>Admin</td><td>Yesterday</td></tr>
            </table>
            """
        elif path == "/phpmyadmin" or path == "/phpmyadmin/sql":
            # phpMyAdmin interface
            template = """
            <h2>phpMyAdmin</h2>
            <form action="/execute_sql" method="post">
                <textarea name="query" rows="5" cols="80">SELECT * FROM users;</textarea><br>
                <input type="submit" value="Execute">
            </form>
            """
        else:
            # Generic page
            template = f"<h2>Page at {path}</h2><p>Standard content here</p>"
        
        # Wrap in basic HTML template
        return f"""
        <html>
        <head><title>Bank Admin Portal</title></head>
        <body>
            {template}
            <hr>
            <p>Simulated web interface - for educational purposes only</p>
        </body>
        </html>
        """

    def _handle_password_reset(self, username, email):
        """Handle password reset functionality"""
        if not self.web_session:
            return "No active session"
        
        host = next((h for h in self.all_hosts if h["ip"] == self.current_system), None)
        if not host or "web_admin" not in host:
            return "Invalid session"
        
        # Check if user exists
        if username in host["web_admin"]["credentials"]:
            # Check if email matches (in a real system this would be verified)
            print(f"\n[PASSWORD RESET] Attempt for {username} with email {email}")
            
            # Simple email pattern check
            if "@" in email and "." in email.split("@")[1]:
                # Generate a temporary password
                temp_password = f"Temp{random.randint(1000,9999)}!"
                host["web_admin"]["credentials"][username] = temp_password
                
                print(f"Password reset successful! New password: {temp_password}")
                self._add_score(self.SCORE_VALUES['password_reset'], "password reset")
                
                return f"""
                <h2>Password Reset Successful</h2>
                <p>A temporary password has been sent to {email}</p>
                <p>Your new temporary password is: {temp_password}</p>
                <p><a href="/">Return to login</a></p>
                """
            else:
                return "Invalid email address"
        else:
            return "Username not found"

    def _handle_sql_execution(self, query):
        """Handle SQL execution in web interface"""
        if not self.web_session:
            return "No active session"
        
        host = next((h for h in self.all_hosts if h["ip"] == self.current_system), None)
        if not host or "phpMyAdmin" not in host["services"]:
            return "SQL interface not available"
        
        self.query(query)
        return redirect(url_for('home'))

    def _handle_file_upload(self, filename, content):
        """Handle file uploads to the system"""
        if not self.web_session:
            return "No active session"
        
        host = next((h for h in self.all_hosts if h["ip"] == self.current_system), None)
        if not host:
            return "Invalid session"
        
        # Add file to the system
        if "/var/www/html" not in self.target_systems[self.current_system]["files"]:
            self.target_systems[self.current_system]["files"]["/var/www/html"] = {}
        
        self.target_systems[self.current_system]["files"]["/var/www/html"][filename] = content
        
        print(f"\nUploaded {filename} to web server")
        self._add_score(self.SCORE_VALUES['malicious_upload'], "uploading malicious file")
        
        # Check if this is a web shell
        if "<?php" in content or "<%" in content:
            print("Warning: This appears to be a web shell! Use with caution.")
        
        return f"""
        <h2>File Upload Successful</h2>
        <p>File {filename} has been uploaded to the server.</p>
        <p><a href="/admin/dashboard">Return to dashboard</a></p>
        """

    def _handle_payment_redirect(self, original_account, target_account, amount):
        """Handle payment redirection attempts"""
        if not self.web_session:
            return "No active session"
        
        host = next((h for h in self.all_hosts if h["ip"] == self.current_system), None)
        if not host:
            return "Invalid session"
        
        print(f"\n[PAYMENT REDIRECT] Attempt to redirect {amount} from {original_account} to {target_account}")
        
        # Simple validation
        if original_account and target_account and amount.isdigit():
            print(f"Successfully redirected ${amount} from account {original_account} to {target_account}")
            self._add_score(self.SCORE_VALUES['payment_redirect'], "redirecting payments")
            
            return f"""
            <h2>Payment Redirect Successful</h2>
            <p>Redirected ${amount} from account {original_account} to {target_account}</p>
            <p><a href="/admin/dashboard">Return to dashboard</a></p>
            """
        else:
            return "Invalid payment details"

    def _handle_email_access(self, email_account):
        """Handle email access attempts"""
        if not self.web_session:
            return "No active session"
        
        host = next((h for h in self.all_hosts if h["ip"] == self.current_system), None)
        if not host:
            return "Invalid session"
        
        print(f"\n[EMAIL ACCESS] Attempt to access emails for {email_account}")
        
        # Check if we have credentials for this email
        if email_account in self.email_access.get(self.current_system, {}):
            # Already accessed
            emails = self.email_access[self.current_system][email_account]
        else:
            # Generate some fake emails
            emails = [
                f"From: support@bank.com\nSubject: Password Reset\nWe received a request to reset your password.",
                f"From: no-reply@bank.com\nSubject: Security Alert\nNew login detected from your account.",
                f"From: admin@bank.com\nSubject: 2FA Code\nYour verification code is {random.randint(100000,999999)}"
            ]
            self.email_access[self.current_system][email_account] = emails
            self._add_score(self.SCORE_VALUES['email_access'], "accessing emails")
        
        # Display emails
        emails_html = "<hr>".join([f"<pre>{email}</pre>" for email in emails])
        
        return f"""
        <h2>Email Access: {email_account}</h2>
        {emails_html}
        <p><a href="/admin/dashboard">Return to dashboard</a></p>
        """

    def _create_target_systems(self):
        """Create the target systems with vulnerabilities"""
        return {
            "bank_web": self._create_bank_system(),
            "atm_database": self._create_database_system()
        }

    def _create_bank_system(self):
        """Create the bank web target system"""
        ip = self._generate_random_ip()
        return {
            "ip": ip,
            "hostname": f"web-bank-prod-{random.randint(1, 10)}",
            "services": ["HTTP", "HTTPS", "SSH", "Flask", "phpMyAdmin", "MySQL"],
            "vulnerabilities": ["SQLi", "XSS", "Weak_Credentials", "Debug_Mode"],
            "files": self._create_bank_files(),
            "web_admin": {
                "url": "/admin",
                "credentials": {
                    "admin": "TempP@ss123",
                    "backupadmin": "Backup@987"
                },
                "pages": {
                    "/dashboard": "Bank Admin Dashboard | Customer Accounts",
                    "/users": "User Management | Current admins: admin, backupadmin"
                }
            },
            "value": 75,
            "compromised": False
        }

    def _create_bank_files(self):
        """Create file structure for bank system"""
        return {
            "/": ["README.txt"],
            "/etc": {
                "passwd": "root:x:0:0:root:/root:/bin/bash\nwebadmin:x:1000:1000:Web Admin,,,:/home/webadmin:/bin/bash",
                "shadow": "root:$6$salt$hash:18580:0:99999:7:::\nwebadmin:$6$salt$hash:18580:0:99999:7:::",
                "hosts": "127.0.0.1 localhost"
            },
            "/var/www/html": {
                "index.php": "<?php\n// Bank portal\n$db_conn = mysqli_connect('localhost', 'webadmin', 's3cur3P@ss!2023', 'bankdb');",
                "config.php": "<?php\n// Database configuration\n$db_host = 'localhost';\n$db_user = 'admin';\n$db_pass = 'B@nkAdm1nP@ss';\n$db_name = 'customer_data';",
                ".env": "DEBUG=True\nSECRET_KEY=ThisIsNotSecure!\nDB_PASSWORD=Web@dm1nP@ss123",
                "login.php": "<?php\n// Admin login page\n// Default creds: admin:TempP@ss123",
                "admin/dashboard.php": "<!-- Admin dashboard -->\n<!-- Hidden backup creds: backupadmin:Backup@987 -->"
            },
            "/var/log": ["auth.log", "syslog"],
            "/home/webadmin": {
                ".bash_history": "mysql -u admin -p\nssh admin@192.168.1.100\nvim config.php",
                "notes.txt": "Emergency SSH: user=breakglass password=Fire!Drill123"
            }
        }

    def _create_database_system(self):
        """Create the database target system"""
        ip = self._generate_random_ip()
        return {
            "ip": ip,
            "hostname": f"db-financial-{random.randint(1, 5)}",
            "services": ["MySQL", "SSH", "Redis", "phpMyAdmin"],
            "vulnerabilities": ["Default_Creds", "Unpatched_DB", "Exposed_phpMyAdmin"],
            "files": {
                "/etc/mysql": {
                    "my.cnf": "[client]\nuser=root\npassword=R00t#DB!2023",
                    "debian.cnf": "[client]\nuser=debian-sys-maint\npassword=j8K7*2bnQw!p"
                },
                "/backups": {
                    "financial_records.sql": "-- MySQL dump\n-- User: dbadmin\n-- Password: D@t@b@s3#Secure!",
                },
                "/root/.ssh": {
                    "authorized_keys": "ssh-rsa AAAAB3Nza... admin@bank",
                    "id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
                }
            },
            "web_admin": {
                "url": "/phpmyadmin",
                "credentials": {
                    "root": "R00t#DB!2023",
                    "dbadmin": "D@t@b@s3#Secure!"
                },
                "pages": {
                    "/": "phpMyAdmin | MySQL Database Manager",
                    "/sql": "SQL Query Interface"
                }
            },
            "value": 100,
            "compromised": False
        }

    def _generate_decoys(self):
        """Generate decoy hosts with random configurations"""
        decoys = []
        for _ in range(random.randint(20, 30)):
            host = {
                "ip": self._generate_random_ip(),
                "hostname": f"host-{random.randint(100, 999)}",
                "services": random.sample(["HTTP", "FTP", "Telnet", "SMTP", "DNS"], random.randint(1, 3)),
                "files": {},
                "is_decoy": True,
                "compromised": False
            }
            
            if random.random() < 0.3:
                host["web_admin"] = {
                    "url": random.choice(["/admin", "/wp-admin", "/manager"]),
                    "credentials": {
                        "admin": "password" + str(random.randint(1, 100)),
                        "user": "welcome" + str(random.randint(1, 50))
                    },
                    "pages": {
                        "/": "Login Page",
                        "/dashboard": "Empty Dashboard"
                    }
                }
            
            decoys.append(host)
        return decoys

    def _merge_and_shuffle_hosts(self):
        """Combine and shuffle all hosts for the game"""
        all_hosts = list(self.target_systems.values()) + self.internet_hosts
        random.shuffle(all_hosts)
        return all_hosts

    def _generate_random_ip(self):
        """Generate a random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _print_banner(self):
        """Display the game banner"""
        print(r"""
  _   _ _____ _   _ _____ _____ _____ _____ _____ 
 | | | |_   _| \ | |_   _|_   _|  ___|_   _| ____|
 | | | | | | |  \| | | |   | | | |_    | | |  _|  
 | |_| | | | | |\  | | |   | | |  _|   | | | |___ 
  \___/  |_| |_| \_| |_|   |_| |_|     |_| |_____|
        """)
        print("Ultimate Penetration Testing Simulator v6.1")
        print("Discover credentials through multiple attack vectors!")
        print(f"Targets to find: {len(self.target_systems)} | Decoys: {len(self.internet_hosts)}")
        print("Type 'help' for commands\n")

    def _start_background_threads(self):
        """Start all background monitoring threads"""
        self._start_log_monitor()
        self._start_security_monitor()

    def _start_log_monitor(self):
        """Thread for generating random network events"""
        def monitor():
            while self.session_active:
                if random.randint(1, 100) <= 5:
                    log = self._generate_log_event()
                    print(f"\n[NETWORK EVENT] {log}")
                time.sleep(random.randint(5, 10))
        threading.Thread(target=monitor, daemon=True).start()

    def _start_security_monitor(self):
        """Thread for security responses"""
        def monitor():
            while self.session_active:
                if random.randint(1, 100) <= 3 and any(h.get('compromised') for h in self.all_hosts):
                    print("\n[SECURITY ALERT] Suspicious activity detected! Security team investigating...")
                time.sleep(random.randint(10, 20))
        threading.Thread(target=monitor, daemon=True).start()

    def _generate_log_event(self):
        """Generate random network events"""
        events = [
            f"Port scan detected from {self._generate_random_ip()}",
            f"Failed login attempt for user 'admin' on {random.choice(self.all_hosts)['ip']}",
            "Database backup in progress",
            "Security alert: possible SQL injection attempt",
            f"New admin login from {self._generate_random_ip()}"
        ]
        return random.choice(events)

    def _add_score(self, points, reason):
        """Helper to add points with feedback"""
        self.score += points
        print(f"+{points} points for {reason}! Total: {self.score}")

    def scan_network(self):
        """Scan the network for hosts"""
        print("\n[NETWORK SCAN RESULTS]")
        print("IP".ljust(16) + "HOSTNAME".ljust(20) + "SERVICES".ljust(25) + "WEB ADMIN".ljust(15) + "NOTES")
        print("-"*90)
        
        found_targets = 0
        for host in random.sample(self.all_hosts, min(15, len(self.all_hosts))):
            self.discovered_ips.add(host["ip"])
            services = ", ".join(host["services"])
            web_admin = "Yes" if "web_admin" in host else "No"
            note = ""
            
            is_target = any(t["ip"] == host["ip"] for t in self.target_systems.values())
            if is_target:
                found_targets += 1
                note = "INTERESTING"
            
            print(host["ip"].ljust(16) + 
                  host.get("hostname", "").ljust(20) + 
                  services.ljust(25) + 
                  web_admin.ljust(15) + 
                  note)
        
        print(f"\nFound {found_targets} potentially interesting systems among {min(15, len(self.all_hosts))} scanned hosts")
        print("Use 'investigate <ip>' for more details")

    def listen(self, ip):
        """Monitor network traffic on an IP"""
        if ip not in self.discovered_ips:
            print(f"IP {ip} not discovered yet. Use 'scan_network' first")
            return
        
        target = next((sys for sys in self.all_hosts if sys["ip"] == ip), None)
        if not target:
            print("Invalid IP address")
            return
        
        print(f"\nStarting packet capture on {ip}...")
        print("Monitoring network traffic (Ctrl+C to stop)")
        print("Looking for credentials in plaintext protocols...")
        
        self.listening = True
        try:
            while self.listening:
                time.sleep(random.randint(2, 5))
                
                # Chance to find credentials in traffic
                if random.randint(1, 4) == 1:
                    if any(t["ip"] == ip for t in self.target_systems.values()):
                        target_name = next(k for k,v in self.target_systems.items() if v["ip"] == ip)
                        creds = self.target_systems[target_name].get("web_admin", {}).get("credentials", {})
                        if creds:
                            user = random.choice(list(creds.keys()))
                            password = creds[user]
                            print(f"\n[TRAFFIC CAPTURE] Found in plaintext HTTP: {user}:{password}")
                            self.credentials[ip][user] = password
                            self._add_score(self.SCORE_VALUES['credential_find'], "finding credentials")
                    else:
                        protocols = ["FTP", "Telnet", "HTTP"]
                        print(f"\n[TRAFFIC CAPTURE] {random.choice(protocols)} credentials: user{random.randint(1,10)}:pass{random.randint(1000,9999)}")
                else:
                    events = [
                        f"HTTP GET /login.php",
                        f"FTP session opened",
                        f"MySQL query: SELECT * FROM users",
                        f"SSH connection attempt",
                        f"Redis command: AUTH {random.choice(['admin', 'root', 'user'])}",
                        f"Telnet login attempt for 'admin'",
                        f"SMTP AUTH LOGIN attempt"
                    ]
                    print(f"\n[TRAFFIC CAPTURE] {random.choice(events)}")
        except KeyboardInterrupt:
            self.listening = False
            print("\nStopped packet capture")

    def investigate(self, ip):
        """Investigate a specific host"""
        if ip not in self.discovered_ips:
            print(f"IP {ip} not discovered yet. Use 'scan_network' first")
            return
        
        host = next((h for h in self.all_hosts if h["ip"] == ip), None)
        if not host:
            print("Invalid IP address")
            return
        
        print(f"\n[INVESTIGATION: {ip}]")
        print(f"Hostname: {host.get('hostname', 'unknown')}")
        print("Services: " + ", ".join(host["services"]))
        
        if "web_admin" in host:
            print(f"\nWeb Admin Interface: http://{ip}{host['web_admin']['url']}")
            print("Discovered accounts: " + ", ".join(host["web_admin"]["credentials"].keys()))
        
        if "is_decoy" in host:
            print("\nThis appears to be a regular internet host")
            return
        
        target_name = next(k for k,v in self.target_systems.items() if v["ip"] == ip)
        print(f"\nThis is the {target_name.replace('_', ' ')} system!")
        print("Potential vulnerabilities:")
        print("- " + "\n- ".join(self.target_systems[target_name]["vulnerabilities"]))
        print("\nTry these commands:")
        print(f"  ssh admin@{ip}          # Attempt SSH login")
        if "web_admin" in host:
            print(f"  web {ip}               # Access web interface")
        print(f"  listen {ip}            # Monitor network traffic")
        print(f"  exploit <vulnerability> # Try an exploit")

    def web(self, ip, path="/"):
        """Access web interface of a host"""
        if ip not in self.discovered_ips:
            print(f"IP {ip} not discovered yet")
            return
        
        host = next((h for h in self.all_hosts if h["ip"] == ip), None)
        if not host:
            print("Invalid IP address")
            return
        
        if "web_admin" not in host:
            print("No web admin interface found on this host")
            return
        
        self.web_session = True
        self.current_system = ip
        self.current_web_path = path
        
        print(f"\nAccessing web interface at http://{ip}{host['web_admin']['url']}{path}")
        print("Running Dashboard at http://localhost:5000")
        
        if path == "/":
            print("\n[Login Page]")
            print("Enter credentials with: auth <username> <password>")
            print("Discovered accounts: " + ", ".join(host["web_admin"]["credentials"].keys()))
        else:
            page_content = host["web_admin"]["pages"].get(path, "404 Not Found")
            print(f"\n{page_content}")
            
            if path == "/sql" and "phpMyAdmin" in host["services"]:
                print("\nSQL Query Interface (try: query 'SELECT * FROM users')")

    def auth(self, username, password):
        """Authenticate to web interface"""
        if not self.web_session:
            print("Not in a web session. Use 'web <ip>' first")
            return
        
        host = next((h for h in self.all_hosts if h["ip"] == self.current_system), None)
        if not host or "web_admin" not in host:
            print("No web session active")
            return
        
        if username in host["web_admin"]["credentials"]:
            if password == host["web_admin"]["credentials"][username]:
                print(f"Authentication successful! Welcome {username}")
                
                # Mark system as compromised if this is a target
                if not host.get('is_decoy', False) and not host.get('compromised', False):
                    host['compromised'] = True
                    self._add_score(self.SCORE_VALUES['system_compromise'], "compromising system")
                else:
                    self._add_score(self.SCORE_VALUES['credential_find'], "successful authentication")
            else:
                print("Invalid password")
        else:
            print("Invalid username")

    def query(self, sql):
        """Execute SQL query in web interface"""
        if not self.web_session:
            print("Not in a web session")
            return
        
        host = next((h for h in self.all_hosts if h["ip"] == self.current_system), None)
        if not host or "phpMyAdmin" not in host["services"]:
            print("No SQL interface available")
            return
        
        print(f"\nExecuting: {sql}")
        
        if "SELECT" in sql.upper():
            if "users" in sql.lower():
                print("\nid | username | password           | email")
                print("---+----------+--------------------+-------------------")
                print(f"1  | admin    | {host['web_admin']['credentials']['admin']} | admin@bank.com")
                if "backupadmin" in host["web_admin"]["credentials"]:
                    print(f"2  | backup   | {host['web_admin']['credentials']['backupadmin']} | backup@bank.com")
            elif "database" in sql.lower():
                print("\nDatabase: bankdb")
                print("Tables: users, accounts, transactions")
            else:
                print("\nQuery returned 0 rows")
        else:
            print("\nQuery executed successfully")

    def ssh(self, target):
        """SSH into a host"""
        try:
            user, ip = target.split("@")
        except:
            print("Usage: ssh user@ip")
            return
        
        if ip not in self.discovered_ips:
            print(f"IP {ip} not discovered yet")
            return
        
        host = next((h for h in self.all_hosts if h["ip"] == ip), None)
        if not host:
            print("Invalid IP address")
            return
        
        print(f"\nAttempting SSH connection to {ip} as {user}...")
        
        if "is_decoy" in host:
            print("Connection refused - no SSH service running")
            return
        
        if "SSH" not in host["services"]:
            print("SSH service not available on this system")
            return
        
        # Check if we have credentials for this user
        if user in self.credentials.get(ip, {}):
            password = input(f"Password for {user}: ")
            if password == self.credentials[ip][user]:
                print(f"Access granted! Connected to system")
                self.current_system = next(k for k,v in self.target_systems.items() if v["ip"] == ip)
                self.current_path = "/"
                
                if not host.get('compromised', False):
                    host['compromised'] = True
                    self._add_score(self.SCORE_VALUES['system_compromise'], "compromising system via SSH")
                else:
                    self._add_score(self.SCORE_VALUES['credential_find'], "successful SSH login")
            else:
                print("Authentication failed")
        else:
            print("No known credentials for this user. Try finding credentials first.")

    def ls(self, path=None):
        """List directory contents"""
        if not self.current_system:
            print("Not connected to any system")
            return
        
        display_path = path if path else self.current_path
        abs_path = os.path.abspath(os.path.join(self.current_path, display_path)) if path else self.current_path
        
        print(f"\nContents of {abs_path}:")
        
        system_files = self.target_systems[self.current_system]["files"]
        dir_contents = []
        
        for dir_path in system_files:
            if dir_path == abs_path:
                if isinstance(system_files[dir_path], dict):
                    dir_contents.extend(system_files[dir_path].keys())
                else:
                    dir_contents.extend(system_files[dir_path])
            elif dir_path.startswith(abs_path + '/') and dir_path != abs_path:
                subdir = dir_path[len(abs_path)+1:].split('/')[0]
                if subdir and subdir + '/' not in dir_contents:
                    dir_contents.append(subdir + '/')
        
        if not dir_contents:
            print("(empty)")
        else:
            for item in sorted(dir_contents):
                if item.endswith('/'):
                    print(f"\033[94m{item.ljust(20)}\033[0m")  # Blue for directories
                else:
                    print(item.ljust(20))

    def cd(self, new_path):
        """Change directory"""
        if not self.current_system:
            print("Not connected to any system")
            return
        
        if new_path.startswith('/'):
            abs_path = new_path
        else:
            abs_path = os.path.normpath(os.path.join(self.current_path, new_path))
        
        system_files = self.target_systems[self.current_system]["files"]
        path_exists = any(
            dir_path == abs_path or 
            dir_path.startswith(abs_path + '/') 
            for dir_path in system_files
        )
        
        if path_exists:
            self.current_path = abs_path
            print(f"Changed directory to {abs_path}")
        else:
            print(f"Directory not found: {abs_path}")

    def cat(self, filename):
        """View file contents"""
        if not self.current_system:
            print("Not connected to any system")
            return
        
        full_path = os.path.join(self.current_path, filename)
        system_files = self.target_systems[self.current_system]["files"]
        
        file_content = None
        for dir_path in system_files:
            if isinstance(system_files[dir_path], dict):
                if filename in system_files[dir_path]:
                    file_content = system_files[dir_path][filename]
                    break
            elif filename in system_files[dir_path]:
                file_content = f"[Binary file: {filename}]"
                break
        
        if file_content is None:
            print("File not found")
            return
        
        print(f"\nContents of {full_path}:")
        print(file_content)
        
        # Search for credentials in file
        cred_patterns = [
            r"pass(word)?\s*=\s*['\"]([^'\"]+)['\"]",
            r"password\s*:\s*['\"]([^'\"]+)['\"]",
            r"DB_PASSWORD\s*=\s*['\"]([^'\"]+)['\"]"
        ]
        
        found_creds = []
        for pattern in cred_patterns:
            matches = re.finditer(pattern, file_content, re.IGNORECASE)
            for match in matches:
                cred = match.group(2) if len(match.groups()) > 1 else match.group(1)
                found_creds.append(cred)
        
        if found_creds:
            print("\n[!] Found potential credentials in file:")
            for cred in found_creds:
                print(f"- {cred}")
                # Store found credentials
                ip = self.target_systems[self.current_system]["ip"]
                self.credentials[ip]["file_found"] = cred
            self._add_score(self.SCORE_VALUES['credential_find'], "finding credentials in file")

    def steal(self, filename):
        """Download a file from the system"""
        if not self.current_system:
            print("Not connected to any system")
            return
        
        full_path = os.path.join(self.current_path, filename)
        system_files = self.target_systems[self.current_system]["files"]
        
        file_exists = any(
            (isinstance(dir_files, dict) and filename in dir_files) or 
            (isinstance(dir_files, list) and filename in dir_files)
            for dir_files in system_files.values()
        )
        
        if not file_exists:
            print("File not found")
            return
        
        print(f"\nDownloading {full_path}...")
        print("File successfully downloaded")
        self._add_score(self.SCORE_VALUES['file_download'], "downloading file")
        
        # If this is a target system and not already compromised
        host = next((h for h in self.all_hosts if h["ip"] == self.target_systems[self.current_system]["ip"]), None)
        if host and not host.get('is_decoy', True) and not host.get('compromised', False):
            host['compromised'] = True
            self._add_score(self.SCORE_VALUES['system_compromise'], "compromising system via file download")

    def exploit(self, vulnerability):
        """Attempt to exploit a vulnerability"""
        if not self.current_system:
            print("Not connected to any system")
            return
        
        host = self.target_systems[self.current_system]
        
        if vulnerability not in host["vulnerabilities"]:
            print(f"Vulnerability '{vulnerability}' not found on this system")
            return
        
        print(f"\nAttempting {vulnerability} exploit...")
        time.sleep(2)
        
        if random.random() < 0.7:  # 70% success rate
            print("Exploit successful!")
            
            if not host.get('compromised', False):
                host['compromised'] = True
                points = self.SCORE_VALUES['system_compromise'] + self.SCORE_VALUES['vulnerability_find']
                self._add_score(points, "successful exploit and system compromise")
            else:
                self._add_score(self.SCORE_VALUES['vulnerability_find'], "successful exploit")
            
            # Special outcomes for certain vulnerabilities
            if vulnerability == "SQLi":
                print("\nDumped database credentials:")
                print(f"admin:{host['web_admin']['credentials']['admin']}")
            elif vulnerability == "Weak_Credentials":
                print("\nFound default credentials in config files")
        else:
            print("Exploit failed")
            
            # 20% chance of detection
            if random.random() < 0.2:
                print("\n[WARNING] Exploit attempt detected! Security systems alerted")

    def run(self):
        """Main game loop"""
        while True:
            try:
                prompt = self._get_prompt()
                cmd = input(prompt).strip()
                
                if not cmd:
                    continue
                
                if self._handle_exit(cmd):
                    break
                
                if cmd.lower() == "help":
                    self._show_help()
                    continue
                
                parts = cmd.split()
                main_cmd = parts[0].lower()
                
                # Command routing
                commands = {
                    'scan_network': lambda: self.scan_network(),
                    'investigate': lambda: self.investigate(parts[1]) if len(parts) > 1 else print("Usage: investigate <ip>"),
                    'listen': lambda: self.listen(parts[1]) if len(parts) > 1 else print("Usage: listen <ip>"),
                    'web': lambda: self.web(parts[1], parts[2] if len(parts) > 2 else "/") if len(parts) > 1 else print("Usage: web <ip> [path]"),
                    'auth': lambda: self.auth(parts[1], parts[2]) if len(parts) > 2 else print("Usage: auth <user> <pass>"),
                    'query': lambda: self.query(' '.join(parts[1:])) if len(parts) > 1 else print("Usage: query 'SQL statement'"),
                    'ssh': lambda: self.ssh(parts[1]) if len(parts) > 1 else print("Usage: ssh user@ip"),
                    'ls': lambda: self.ls(parts[1] if len(parts) > 1 else None),
                    'cd': lambda: self.cd(parts[1]) if len(parts) > 1 else print("Usage: cd <path>"),
                    'cat': lambda: self.cat(parts[1]) if len(parts) > 1 else print("Usage: cat <file>"),
                    'steal': lambda: self.steal(parts[1]) if len(parts) > 1 else print("Usage: steal <file>"),
                    'exploit': lambda: self.exploit(parts[1]) if len(parts) > 1 else print("Usage: exploit <vulnerability>"),
                    'score': lambda: self._show_score(),
                }
                
                if main_cmd in commands:
                    commands[main_cmd]()
                else:
                    print("Command not recognized")
            
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except Exception as e:
                print(f"Error: {str(e)}")

    def _get_prompt(self):
        """Generate the appropriate command prompt"""
        if self.web_session:
            return f"web:{self.current_system}{self.current_web_path}> "
        elif self.current_system:
            return f"{self.current_system}:{self.current_path}$ "
        else:
            return "scan> "

    def _handle_exit(self, cmd):
        """Handle exit command"""
        if cmd.lower() == "exit":
            if self.web_session:
                self.web_session = False
                print("Exited web interface")
            elif self.listening:
                self.listening = False
                print("Stopped monitoring")
            else:
                print(f"\nSession ended. Final score: {self.score}")
                compromised = len([h for h in self.all_hosts if h.get('compromised') and not h.get('is_decoy')])
                print(f"Targets compromised: {compromised}/{len(self.target_systems)}")
                self.session_active = False
                return True
        return False

    def _show_help(self):
        """Display help information"""
        print("\nAvailable Commands:")
        print("scan_network      - Discover hosts")
        print("investigate ip    - Examine a host")
        print("listen ip         - Monitor network traffic")
        print("web ip [path]     - Access web interface")
        print("auth user pass    - Authenticate to web")
        print("query 'SQL'       - Execute SQL (in phpMyAdmin)")
        print("ssh user@ip       - SSH to host")
        print("ls [path]         - List files")
        print("cd path           - Change directory")
        print("cat file          - View file contents")
        print("steal file        - Download file")
        print("exploit vuln      - Try an exploit")
        print("score             - Show points")
        print("exit              - Exit current mode")
        print("help              - Show this help\n")

    def _show_score(self):
        """Display current score"""
        print(f"\nCurrent score: {self.score}")
        compromised = len([h for h in self.all_hosts if h.get('compromised') and not h.get('is_decoy')])
        print(f"Targets compromised: {compromised}/{len(self.target_systems)}")

if __name__ == "__main__":
    simulator = UltimatePenTestSimulator()
    simulator.run()
