# =============================================================================
# CodeQL 알림 2건 패치 — py/command-line-injection (CWE-78, Critical)
#
#   [#1] app/main.py:57  ping_host()   — subprocess.run(..., shell=True)
#   [#2] app/main.py:81  admin_exec()  — os.popen("... " + command)
#
# 아래 두 함수로 기존 함수를 그대로 교체하고, 상단 import/상수를 추가하십시오.
# =============================================================================

# ---- 파일 상단 import 영역에 추가 -------------------------------------------
import ipaddress
import logging
import re
import shutil
import subprocess

from flask import abort, jsonify, request

logger = logging.getLogger(__name__)

# os.popen 은 더 이상 사용하지 않으므로 관련 import 제거 가능
# (os 는 DB_PATH 에서 계속 쓰이므로 유지)


# ---- 상수 정의 (모듈 레벨) ---------------------------------------------------

# [#1] ping 허용 대상. 운영 환경에서는 설정 파일/환경변수로 분리 권장
ALLOWED_PING_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "10.0.0.10",
    "monitor.internal.example",
})

# [#2] admin-tool 에 허용할 하위 명령. 키만 외부에 노출되고,
#      실제 실행 인자는 서버가 소유한 고정 리스트에서만 선택된다.
ADMIN_COMMANDS = {
    "status":  ["status"],
    "version": ["--version"],
    "reload":  ["reload", "--safe"],
}

ADMIN_TOOL_PATH = "/usr/local/bin/admin-tool"


# =============================================================================
# [#1] app/main.py:57 — ping_host()
# =============================================================================
@app.route("/api/ping")
def ping_host():
    host = request.args.get("host", "localhost")

    # (1) 화이트리스트 검증: 상수 집합과의 비교가 CodeQL 의 sanitizer 로 인식되어
    #     taint 경로가 끊긴다. 블랙리스트(;, |, && 제거)는 우회 기법이 계속
    #     나오므로 사용하지 않는다.
    if host not in ALLOWED_PING_HOSTS:
        logger.warning("disallowed ping target: %r from %s", host, request.remote_addr)
        abort(400, description="허용되지 않은 호스트입니다.")

    # (2) shell=False + 인자 리스트 전달: 쉘을 거치지 않으므로
    #     메타문자(; | & $() ` 등) 주입 자체가 성립하지 않는다.
    # (3) "--" 로 옵션 파싱 종료 → 호스트명이 옵션으로 해석되는 것을 방지
    # (4) timeout 으로 자원 고갈(CWE-400) 방어
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "--", host],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504

    # (5) 명령 원문 출력(stdout/stderr)을 그대로 반환하지 않는다.
    #     내부 네트워크 구조·에러 메시지 노출(CWE-209) 차단
    return jsonify({"host": host, "reachable": result.returncode == 0})


# =============================================================================
# [#2] app/main.py:81 — admin_exec()
# =============================================================================
@app.route("/api/admin/exec", methods=["POST"])
def admin_exec():
    # (0) 관리자 전용 엔드포인트이므로 인증/인가 검사가 선행되어야 한다.
    #     실제 구현에서는 세션 또는 토큰 기반 권한 확인으로 교체할 것.
    #     require_admin()

    cmd_key = request.form.get("cmd", "")

    # (1) 사용자 입력을 "명령 문자열"이 아니라 "사전에 정의된 키"로만 취급한다.
    #     입력값은 dict 조회에만 쓰이고, 실행 인자에는 절대 전달되지 않는다.
    #     → 사용자 데이터가 명령줄에 도달하는 경로 자체가 사라진다.
    argv_tail = ADMIN_COMMANDS.get(cmd_key)
    if argv_tail is None:
        logger.warning("unknown admin command: %r from %s", cmd_key, request.remote_addr)
        abort(400, description="지원하지 않는 명령입니다.")

    # (2) 실행 파일은 절대경로 고정 + 존재 여부 확인 (PATH 하이재킹 방지, CWE-426)
    if not shutil.which(ADMIN_TOOL_PATH):
        logger.error("admin-tool not found: %s", ADMIN_TOOL_PATH)
        abort(500)

    # (3) os.popen 제거 → 내부적으로 /bin/sh 를 호출하므로 근본적으로 위험하다.
    #     subprocess.run + shell=False 로 대체.
    try:
        result = subprocess.run(
            [ADMIN_TOOL_PATH, *argv_tail],
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504

    if result.returncode != 0:
        logger.error("admin-tool failed rc=%s stderr=%s", result.returncode, result.stderr)
        return jsonify({"error": "command failed"}), 500

    return jsonify({"command": cmd_key, "output": result.stdout})
