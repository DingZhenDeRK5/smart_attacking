"""
VAmPI Mock — 基于 VAmPI OpenAPI 规范的轻量级 Mock API
专为 SmartAttack 扫描演示设计，无需 Docker，无外部依赖。
"""
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = 5000
HOST = "127.0.0.1"

# 内置测试用户数据
USERS = [
    {"id": 1, "username": "admin", "password": "admin123", "email": "admin@vampi.local", "role": "admin"},
    {"id": 2, "username": "user1", "password": "password", "email": "user1@vampi.local", "role": "user"},
    {"id": 3, "username": "test", "password": "test123", "email": "test@vampi.local", "role": "user"},
]

BOOKS = [
    {"id": 1, "title": "The Art of API Hacking", "author": "Security Researcher", "secret_note": "internal_draft_v2"},
    {"id": 2, "title": "Microservices Security", "author": "Jane Doe", "secret_note": ""},
]
next_book_id = 3


class VampiMockHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def log_message(self, format, *args):
        print(f"[VAmPI Mock] {args[0]}")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        params = parse_qs(urlparse(self.path).query)
        token = self.headers.get("Authorization", "")

        # Swagger
        if path == "/api/swagger.json":
            swagger_path = os.path.join(os.path.dirname(__file__), "swagger.json")
            with open(swagger_path) as f:
                self._send_json(json.load(f))
            return

        # 创建数据库
        if path == "/createdb":
            self._send_json({"status": "success", "message": "Database initialized"})
            return

        # 用户列表（故意返回敏感信息）
        if path == "/users/v1":
            # 漏洞：不校验 token
            self._send_json({"users": USERS})  # 暴露密码！
            return

        # 单用户
        if path.startswith("/users/v1/"):
            username = path.split("/")[-1]
            user = next((u for u in USERS if u["username"] == username), None)
            if user:
                self._send_json(user)
            else:
                self._send_json({"error": "User not found"}, 404)
            return

        # 书籍列表
        if path == "/books/v1":
            self._send_json({"books": BOOKS})
            return

        # 单本书（越权漏洞）
        if path.startswith("/books/v1/"):
            book_id = int(path.split("/")[-1])
            book = next((b for b in BOOKS if b["id"] == book_id), None)
            if book:
                # 漏洞：secret_note 对任何人可见
                self._send_json(book)
            else:
                self._send_json({"error": "Book not found"}, 404)
            return

        # Debug 端点 — 故意暴露内部信息
        if path == "/debug":
            self._send_json({
                "debug_mode": True,
                "internal_config": {"db_host": "internal-db.vampi.local:5432", "admin_panel": "/admin"},
                "env_vars": {"SECRET_KEY": "vampi_super_secret_key_do_not_leak", "DB_PASSWORD": "p@ssw0rd123"},
            })
            return

        # 邮箱验证
        if path == "/mail/v1":
            self._send_json({"emails": [{"to": "admin@vampi.local", "subject": "Login alert", "body": "Someone logged in from IP 10.0.0.55"}]})
            return

        self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        # 登录（暴力破解漏洞）
        if path == "/users/v1/login":
            username = body.get("username", "")
            password = body.get("password", "")
            user = next((u for u in USERS if u["username"] == username), None)
            if not user:
                # 漏洞：明确区分用户不存在
                self._send_json({"error": "Username does not exist"}, 401)
                return
            if user["password"] != password:
                # 漏洞：明确区分密码错误
                self._send_json({"error": "Password incorrect"})
                return
            self._send_json({"auth_token": f"jwt_fake_{user['username']}_{user['role']}", "user": user})
            return

        # 注册（批量赋值漏洞）
        if path == "/users/v1/register":
            # 漏洞：允许客户端传入 role
            new_user = {
                "id": len(USERS) + 1,
                "username": body.get("username", "anonymous"),
                "password": body.get("password", ""),
                "email": body.get("email", ""),
                "role": body.get("role", "user"),  # 客户端可控制！
                "admin": body.get("admin", False),  # 甚至可注入 admin 字段
            }
            USERS.append(new_user)
            self._send_json({"success": True, "message": "User registered", "user": new_user})
            return

        # 添加书籍
        if path == "/books/v1":
            global next_book_id
            new_book = {
                "id": next_book_id,
                "title": body.get("title", "Untitled"),
                "author": body.get("author", "Unknown"),
                "secret_note": body.get("secret_note", ""),
            }
            BOOKS.append(new_book)
            next_book_id += 1
            self._send_json({"success": True, "book": new_book})
            return

        # 密码重置（逻辑绕过）
        if path == "/users/v1/reset-password":
            # 漏洞：不需要旧密码即可重置
            username = body.get("username", "")
            new_pass = body.get("new_password", "hacked")
            user = next((u for u in USERS if u["username"] == username), None)
            if user:
                user["password"] = new_pass
                self._send_json({"success": True, "message": f"Password for {username} has been reset"})
            else:
                self._send_json({"error": "User not found"}, 404)
            return

        self._send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        path = urlparse(self.path).path
        body = self._read_body()

        if path.startswith("/books/v1/"):
            book_id = int(path.split("/")[-1])
            book = next((b for b in BOOKS if b["id"] == book_id), None)
            if book:
                # 漏洞：不校验权限，任何人都能修改
                book["title"] = body.get("title", book["title"])
                book["author"] = body.get("author", book["author"])
                self._send_json({"success": True, "book": book})
            else:
                self._send_json({"error": "Book not found"}, 404)
            return

        if path.startswith("/users/v1/"):
            username = path.split("/")[-1]
            user = next((u for u in USERS if u["username"] == username), None)
            if user:
                # 漏洞：客户端可修改任何字段
                user["role"] = body.get("role", user["role"])
                user["email"] = body.get("email", user["email"])
                self._send_json({"success": True, "user": user})
            else:
                self._send_json({"error": "User not found"}, 404)
            return

        self._send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        path = urlparse(self.path).path

        if path.startswith("/books/v1/"):
            book_id = int(path.split("/")[-1])
            global BOOKS
            before = len(BOOKS)
            BOOKS = [b for b in BOOKS if b["id"] != book_id]
            if len(BOOKS) < before:
                self._send_json({"success": True, "message": f"Book {book_id} deleted"})
            else:
                self._send_json({"error": "Book not found"}, 404)
            return

        self._send_json({"error": "Not found"}, 404)


if __name__ == "__main__":
    print(f"[VAmPI Mock] 启动在 http://{HOST}:{PORT}")
    print(f"[VAmPI Mock] Swagger: http://{HOST}:{PORT}/api/swagger.json")
    print(f"[VAmPI Mock] 内置漏洞: 越权/批量赋值/信息泄露/暴力破解/逻辑绕过/debug端点")
    server = HTTPServer((HOST, PORT), VampiMockHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        print("\n[VAmPI Mock] 已停止")
