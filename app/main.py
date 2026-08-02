"""
BoB 15기 보안 실습용 애플리케이션
=====================================
이 파일에는 의도적으로 심어둔 보안 취약점이 있습니다.
CodeQL 스캔 결과를 확인하고, 최소 2개 이상을 수정하세요.

주의: 실제 서비스 코드로 사용하지 마세요.
"""

import sqlite3
import subprocess
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "app.db")


def get_connection():
    return sqlite3.connect(DB_PATH)


@app.route("/api/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT id, username, email FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "email": r[2]} for r in rows])


@app.route("/api/search")
def search_products():
    keyword = request.args.get("q", "")
    conn = get_connection()
    cursor = conn.cursor()

    query = f"SELECT name, price FROM products WHERE name LIKE '%{keyword}%'"
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()
    return jsonify([{"name": r[0], "price": r[1]} for r in rows])


@app.route("/api/ping")
def ping_host():
    host = request.args.get("host", "localhost")

    result = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
    )

    return jsonify({"output": result.stdout, "error": result.stderr})


@app.route("/api/logs")
def read_log():
    filename = request.args.get("file", "app.log")

    path = "/var/app/logs/" + filename
    with open(path, "r") as f:
        content = f.read()

    return jsonify({"content": content})


@app.route("/api/admin/exec", methods=["POST"])
def admin_exec():
    command = request.form.get("cmd", "")

    output = os.popen("/usr/local/bin/admin-tool " + command).read()

    return jsonify({"output": output})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
