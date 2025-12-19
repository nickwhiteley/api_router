from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime
from urllib.parse import urlparse

# Store requests in memory
requests_log = []

class RequestHandler(BaseHTTPRequestHandler):
    def log_request_data(self):
        """Log request details"""
        # Skip logging for monitoring page and favicon
        if self.path == '/monitor' or self.path == '/favicon.ico':
            return
        
        # Read request body if present
        body = ''
        content_length = self.headers.get('Content-Length')
        if content_length:
            body = self.rfile.read(int(content_length)).decode('utf-8', errors='replace')
        
        request_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'method': self.command,
            'path': self.path,
            'client': self.client_address[0],
            'headers': dict(self.headers),
            'body': body
        }
        requests_log.append(request_data)
        # Keep only last 100 requests
        if len(requests_log) > 100:
            requests_log.pop(0)
    
    def do_GET(self):
        if self.path == '/favicon.ico':
            self.send_response(200)
            self.send_header('Content-Type', 'image/x-icon')
            self.send_header('Content-Length', 0)
            self.end_headers()
        elif self.path == '/monitor':
            self.send_monitor_page()
        else:
            self.log_request_data()
            self.send_json_response()
    
    def do_POST(self):
        self.log_request_data()
        self.send_json_response()
    
    def do_PUT(self):
        self.log_request_data()
        self.send_json_response()
    
    def do_DELETE(self):
        self.log_request_data()
        self.send_json_response()
    
    def send_json_response(self):
        """Send basic JSON response"""
        response = {
            'status': 'success',
            'message': 'Request received',
            'path': self.path,
            'method': self.command,
            'timestamp': datetime.now().isoformat()
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())
    
    def send_monitor_page(self):
        """Send HTML monitoring page"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Request Monitor</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                h1 {{ color: #333; }}
                .request {{ background: white; padding: 15px; margin: 10px 0; 
                           border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .method {{ font-weight: bold; color: #0066cc; }}
                .path {{ color: #666; }}
                .timestamp {{ color: #999; font-size: 0.9em; }}
                .count {{ color: #0066cc; }}
                .headers {{ background: #f9f9f9; padding: 10px; margin: 10px 0; 
                           border-left: 3px solid #0066cc; font-size: 0.9em; }}
                .body {{ background: #f9f9f9; padding: 10px; margin: 10px 0; 
                         border-left: 3px solid #00cc66; font-family: monospace; 
                         white-space: pre-wrap; word-break: break-all; }}
                .section-title {{ font-weight: bold; margin-bottom: 5px; }}
            </style>
            <meta http-equiv="refresh" content="5">
        </head>
        <body>
            <h1>Request Monitor</h1>
            <p>Total requests: <span class="count">{len(requests_log)}</span></p>
            <p><em>Auto-refreshes every 5 seconds</em></p>
            <div id="requests">
        """
        
        for req in reversed(requests_log):
            headers_html = '<br>'.join([f'{k}: {v}' for k, v in req['headers'].items()])
            body_display = req['body'] if req['body'] else '<em>No body</em>'
            
            html += f"""
                <div class="request">
                    <div><span class="method">{req['method']}</span> <span class="path">{req['path']}</span></div>
                    <div class="timestamp">From: {req['client']} at {req['timestamp']}</div>
                    <div class="headers">
                        <div class="section-title">Headers:</div>
                        {headers_html}
                    </div>
                    <div class="body">
                        <div class="section-title">Body:</div>
                        {body_display}
                    </div>
                </div>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

def run_server(port=8081):
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f'Server running on http://localhost:{port}')
    print(f'Monitor page: http://localhost:{port}/monitor')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()