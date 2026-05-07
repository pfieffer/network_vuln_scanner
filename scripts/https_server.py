from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

try:
    server_address = ("127.0.0.1", 4443)

    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    httpd.socket = context.wrap_socket(
        httpd.socket,
        server_side=True
    )

    print("Serving HTTPS on https://127.0.0.1:4443")

    httpd.serve_forever()

except Exception as e:
    print("HTTPS server failed:", e)