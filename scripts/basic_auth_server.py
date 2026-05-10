from http.server import HTTPServer, BaseHTTPRequestHandler
import base64

USERNAME = "admin"
PASSWORD = "admin"

class AuthHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        auth_header = self.headers.get("Authorization")

        expected = "Basic " + base64.b64encode(
            f"{USERNAME}:{PASSWORD}".encode()
        ).decode()

        if auth_header == expected:

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authenticated!")

        else:

            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                'Basic realm="Secure Area"'
            )
            self.end_headers()
            self.wfile.write(b"Authentication required")


server = HTTPServer(("localhost", 8081), AuthHandler)

print("Basic Auth server running on http://localhost:8081")
print("Username: admin")
print("Password: admin")

server.serve_forever()