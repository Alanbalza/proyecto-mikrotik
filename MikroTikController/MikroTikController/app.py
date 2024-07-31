from flask import Flask, request, render_template, redirect, url_for, session
import sys
import socket
import ssl
import binascii
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necesario para las sesiones

class ApiRos:
    "RouterOS API"
    def __init__(self, sk):
        self.sk = sk
        self.currenttag = 0

    def login(self, username, pwd):
        print(f"Attempting to login with username: {username}")
        for repl, attrs in self.talk(["/login", "=name=" + username, "=password=" + pwd]):
            if repl == '!trap':
                print("Login failed at initial step.")
                return False
            elif '=ret' in attrs.keys():
                chal = binascii.unhexlify((attrs['=ret']).encode(sys.stdout.encoding))
                md = hashlib.md5()
                md.update(b'\x00')
                md.update(pwd.encode(sys.stdout.encoding))
                md.update(chal)
                for repl2, attrs2 in self.talk(["/login", "=name=" + username, "=response=00"
                    + binascii.hexlify(md.digest()).decode(sys.stdout.encoding) ]):
                    if repl2 == '!trap':
                        print("Login failed at challenge step.")
                        return False
        print("Login successful.")
        return True

    def talk(self, words):
        if self.writeSentence(words) == 0: return
        r = []
        while 1:
            i = self.readSentence()
            if len(i) == 0: continue
            reply = i[0]
            attrs = {}
            for w in i[1:]:
                j = w.find('=', 1)
                if (j == -1):
                    attrs[w] = ''
                else:
                    attrs[w[:j]] = w[j+1:]
            r.append((reply, attrs))
            if reply == '!done': return r

    def writeSentence(self, words):
        ret = 0
        for w in words:
            self.writeWord(w)
            ret += 1
        self.writeWord('')
        return ret

    def readSentence(self):
        r = []
        while 1:
            w = self.readWord()
            if w == '': return r
            r.append(w)

    def writeWord(self, w):
        print(("<<< " + w))
        self.writeLen(len(w))
        self.writeStr(w)

    def readWord(self):
        ret = self.readStr(self.readLen())
        print((">>> " + ret))
        return ret

    def writeLen(self, l):
        if l < 0x80:
            self.writeByte((l).to_bytes(1, sys.byteorder))
        elif l < 0x4000:
            l |= 0x8000
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        elif l < 0x200000:
            l |= 0xC00000
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        elif l < 0x10000000:
            l |= 0xE0000000
            self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        else:
            self.writeByte((0xF0).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))

    def readLen(self):
        c = ord(self.readStr(1))
        if (c & 0x80) == 0x00:
            pass
        elif (c & 0xC0) == 0x80:
            c &= ~0xC0
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xE0) == 0xC0:
            c &= ~0xE0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF0) == 0xE0:
            c &= ~0xF0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF8) == 0xF0:
            c = ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        return c

    def writeStr(self, str):
        n = 0
        while n < len(str):
            r = self.sk.send(bytes(str[n:], 'UTF-8'))
            if r == 0: raise RuntimeError("connection closed by remote end")
            n += r

    def writeByte(self, str):
        n = 0
        while n < len(str):
            r = self.sk.send(str[n:])
            if r == 0: raise RuntimeError("connection closed by remote end")
            n += r

    def readStr(self, length):
        ret = ''
        while len(ret) < length:
            s = self.sk.recv(length - len(ret))
            if s == b'': raise RuntimeError("connection closed by remote end")
            if any(b >= 128 for b in s):
                return s
            ret += s.decode(sys.stdout.encoding, "replace")
        return ret

def open_socket(dst, port, secure=False):
    try:
        print(f"Opening socket to {dst}:{port}, secure={secure}")
        res = socket.getaddrinfo(dst, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        af, socktype, proto, canonname, sockaddr = res[0]
        skt = socket.socket(af, socktype, proto)
        if secure:
            s = ssl.wrap_socket(skt, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="ECDHE-RSA-AES256-GCM-SHA384")
        else:
            s = skt
        s.connect(sockaddr)
        print(f"Socket successfully opened to {dst}:{port}")
        return s
    except Exception as e:
        print(f"Error opening socket: {e}")
        return None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        dst = request.form['dst']
        user = request.form['user']
        passw = request.form['passw']
        port = request.form.get('port', 8728)

        print(f"Attempting to connect to {dst}:{port} with user {user}")

        s = open_socket(dst, int(port))
        if s is None:
            print("Could not open socket")
            return "Could not open socket", 500

        apiros = ApiRos(s)
        if not apiros.login(user, passw):
            print("Login failed")
            return "Login failed", 401

        session['dst'] = dst
        session['user'] = user
        session['passw'] = passw
        session['port'] = port

        return redirect(url_for('devices'))
    return render_template('login.html')

@app.route('/devices')
def devices():
    if 'dst' not in session:
        return redirect(url_for('login'))

    dst = session['dst']
    user = session['user']
    passw = session['passw']
    port = session['port']

    print(f"Fetching devices from {dst}:{port}")

    s = open_socket(dst, int(port))
    if s is None:
        print("Could not open socket")
        return "Could not open socket", 500

    apiros = ApiRos(s)
    if not apiros.login(user, passw):
        print("Login failed")
        return "Login failed", 401

    leases = []
    for repl, attrs in apiros.talk(["/ip/dhcp-server/lease/print"]):
        if repl == '!re':
            leases.append(attrs)

    active_users = []
    for repl, attrs in apiros.talk(["/ip/hotspot/active/print"]):
        if repl == '!re':
            active_users.append(attrs)

    return render_template('devices.html', leases=leases, active_users=active_users)

@app.route('/block', methods=['POST'])
def block_mac():
    if 'dst' not in session:
        return redirect(url_for('login'))

    dst = session['dst']
    user = session['user']
    passw = session['passw']
    port = session['port']
    mac_address = request.form['mac_address']

    print(f"Blocking MAC address {mac_address} on {dst}:{port}")

    s = open_socket(dst, int(port))
    if s is None:
        print("Could not open socket")
        return "Could not open socket", 500

    apiros = ApiRos(s)
    if not apiros.login(user, passw):
        print("Login failed")
        return "Login failed", 401

    for repl, attrs in apiros.talk(["/ip/hotspot/host/set", "=mac-address=" + mac_address, "=blocked=yes"]):
        if repl == '!trap':
            print("Failed to block MAC address")
            return "Failed to block MAC address", 500

    return redirect(url_for('devices'))

@app.route('/unblock', methods=['POST'])
def unblock_mac():
    if 'dst' not in session:
        return redirect(url_for('login'))

    dst = session['dst']
    user = session['user']
    passw = session['passw']
    port = session['port']
    mac_address = request.form['mac_address']

    print(f"Unblocking MAC address {mac_address} on {dst}:{port}")

    s = open_socket(dst, int(port))
    if s is None:
        print("Could not open socket")
        return "Could not open socket", 500

    apiros = ApiRos(s)
    if not apiros.login(user, passw):
        print("Login failed")
        return "Login failed", 401

    for repl, attrs in apiros.talk(["/ip/hotspot/host/set", "=mac-address=" + mac_address, "=blocked=no"]):
        if repl == '!trap':
            print("Failed to unblock MAC address")
            return "Failed to unblock MAC address", 500

    return redirect(url_for('devices'))

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Procesar los datos como necesites, aquí simplemente los imprimimos
        print(f"Username: {username}, Password: {password}")
        # Redirigir a alguna página o mostrar un mensaje de éxito
        return redirect(url_for('index'))
    return render_template('add_user.html')

if __name__ == "__main__":
    app.run(debug=True)
