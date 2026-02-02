#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import socket
import sys
import time
import traceback
import uuid
import urllib.request
import urllib.error

# ================== 配置区 ==================
APP_ID = os.getenv("FEISHU_APP_ID", "")
APP_SECRET = os.getenv("FEISHU_APP_SECRET", "")
FEISHU_USER_ID = os.getenv("FEISHU_USER_ID", "")  # 你的 user_id

# Prefer the official Feishu OpenAPI host.
FEISHU_IM_API_URL = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=user_id"

DEFAULT_TIMEOUT_SECS = float(os.getenv("CODEX_NOTIFY_TIMEOUT", "10"))
DRY_RUN = os.getenv("CODEX_NOTIFY_DRY_RUN", "").lower() in {"1", "true", "yes", "on"}
DEBUG_DUMP_JSON = os.getenv("CODEX_NOTIFY_DUMP_JSON", "").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
# ==========================================


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("codex_notify")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    log_path = os.getenv("CODEX_NOTIFY_LOG", "").strip()
    if not log_path:
        # Default to ~/.codex/log/notify.log based on script location.
        log_path = str(Path(__file__).resolve().parent / "log" / "notify.log")

    log_file = Path(log_path).expanduser()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        log_file,
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)sZ %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logger.addHandler(handler)
    return logger


LOGGER = _setup_logger()


def _safe_env_flag(name: str) -> str:
    return "set" if os.getenv(name) else "unset"


def get_tenant_access_token(timeout: float = DEFAULT_TIMEOUT_SECS) -> str:
    """
    推荐用 app_id/app_secret 动态获取 tenant_access_token，
    避免手动填一个很容易过期的 token。
    """
    if not APP_ID or not APP_SECRET:
        raise RuntimeError("FEISHU_APP_ID / FEISHU_APP_SECRET 未配置")

    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    headers = {"Content-Type": "application/json; charset=utf-8"}
    data = json.dumps({"app_id": APP_ID, "app_secret": APP_SECRET}).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    if body.get("code") != 0:
        raise RuntimeError("get tenant_access_token failed: %s" % body)

    return body["tenant_access_token"]


def send_feishu_dm(
    title: str,
    message: str,
    thread_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECS,
) -> bool:
    """
    直接通过飞书 im/v1/messages 给“自己”发一条文本消息
    """
    if not FEISHU_USER_ID:
        LOGGER.error("missing FEISHU_USER_ID")
        print("❌ 缺少 FEISHU_USER_ID")
        return False

    if DRY_RUN:
        LOGGER.info("dry_run: would send dm title=%r thread_id=%r", title, thread_id)
        print("DRY_RUN: not sending (CODEX_NOTIFY_DRY_RUN=1)")
        return True

    token = get_tenant_access_token(timeout=timeout)

    parts = []
    if title:
        parts.append(title)
    if message:
        parts.append(message)
    if thread_id:
        parts.append("[thread_id: %s]" % thread_id)

    text = "\n\n".join(parts) if parts else "Codex 通知"

    body = {
        "receive_id": FEISHU_USER_ID,
        "msg_type": "text",
        "content": json.dumps({"text": text}, ensure_ascii=False),
        "uuid": str(uuid.uuid4()),
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer %s" % token,
    }

    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(FEISHU_IM_API_URL, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            resp_text = response.read().decode("utf-8")

        try:
            resp_json = json.loads(resp_text)
        except Exception:
            LOGGER.warning("non_json_response: %s", resp_text[:2000])
            print("⚠️ 返回不是 JSON：%s" % resp_text)
            return False

        code = resp_json.get("code", -1)
        msg = resp_json.get("msg", "")
        if code == 0:
            LOGGER.info("feishu_dm_sent thread_id=%s", thread_id)
            print("✅ Feishu DM sent. Thread:", thread_id)
            return True

        LOGGER.warning(
            "feishu_api_error code=%s msg=%s raw=%s", code, msg, resp_text[:2000]
        )
        print("⚠️ Feishu API error, code=%s, msg=%s" % (code, msg))
        return False
    except urllib.error.HTTPError as e:
        LOGGER.error("http_error code=%s reason=%s", e.code, e.reason)
        print("❌ HTTPError:", e.code, e.reason)
        try:
            body = e.read().decode("utf-8")
            LOGGER.error("http_error_body: %s", body[:2000])
            print(body)
        except Exception:
            pass
        return False
    except urllib.error.URLError as e:
        LOGGER.error("url_error: %r", e)
        print("❌ URLError:", e)
        return False


def _read_notification_json() -> str:
    if len(sys.argv) == 2:
        return sys.argv[1]
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _get_thread_id(notification: dict) -> str:
    return (
        notification.get("thread-id")
        or notification.get("thread_id")
        or notification.get("threadId")
        or notification.get("session_id")  # Claude Code hooks
        or ""
    )


def _get_last_assistant_message(notification: dict) -> str:
    # Codex: direct field
    msg = (
        notification.get("last-assistant-message")
        or notification.get("last_assistant_message")
    )
    if msg:
        LOGGER.info("last_assistant_from_direct len=%d", len(msg))
        return msg

    # Claude Code: read from transcript_path
    transcript_path = notification.get("transcript_path")
    LOGGER.info("transcript_path=%s", transcript_path)
    if transcript_path:
        msg = _read_last_assistant_from_transcript(transcript_path)
        if msg:
            return msg

    LOGGER.info("no_last_assistant_message")
    return ""


def _read_last_assistant_from_transcript(transcript_path: str) -> str:
    """
    Read all assistant text from the last conversation turn in Claude Code's transcript (JSONL format).

    A conversation turn starts with a user message (not tool_result) and includes all subsequent
    assistant messages until the next user message. We collect all text blocks from assistant
    messages in the last turn.

    Retries with increasing delay because Stop hook fires before transcript is fully written.
    """
    path = Path(transcript_path)
    if not path.exists():
        LOGGER.warning("transcript_not_found path=%s", transcript_path)
        return ""

    # Retry a few times with increasing delay
    for attempt in range(4):
        time.sleep(1.5 + attempt * 0.5)  # 1.5s, 2s, 2.5s, 3s

        try:
            result = _parse_transcript_for_last_turn(path, attempt + 1)
            if result:
                return result
        except Exception as e:
            LOGGER.warning("transcript_parse_error attempt=%d error=%r", attempt + 1, e)

    LOGGER.info("no_text_after_retries path=%s", transcript_path)
    return ""


def _parse_transcript_for_last_turn(path: Path, attempt: int) -> str:
    """Parse transcript and extract text from the last conversation turn.

    Strategy: Find the last real user message, then collect all assistant text after it.
    If no text found after the last user message, it means Stop hook fired before
    the final assistant message was written - in that case, search backwards for
    the most recent assistant text.
    """
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    LOGGER.info("transcript_read attempt=%d path=%s lines=%d", attempt, str(path), len(lines))

    # Find the last user message that's not a tool_result (start of last turn)
    last_user_idx = -1
    for i in range(len(lines) - 1, -1, -1):
        line = lines[i].strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if entry.get("type") == "user":
            message = entry.get("message", {})
            content = message.get("content", [])
            # Check if it's a real user message (not tool_result)
            if isinstance(content, str):
                last_user_idx = i
                break
            elif isinstance(content, list):
                # If first item is tool_result, skip this
                if content and isinstance(content[0], dict) and content[0].get("type") == "tool_result":
                    continue
                last_user_idx = i
                break

    if last_user_idx == -1:
        LOGGER.info("no_user_message_found path=%s", str(path))
        return ""

    # Collect all assistant text from last_user_idx to end
    all_text_parts = []
    for i in range(last_user_idx + 1, len(lines)):
        line = lines[i].strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if entry.get("type") == "assistant":
            message = entry.get("message", {})
            content = message.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "").strip()
                        if text:
                            all_text_parts.append(text)
                    elif isinstance(block, str):
                        if block.strip():
                            all_text_parts.append(block.strip())
            elif isinstance(content, str) and content.strip():
                all_text_parts.append(content.strip())

    # If no text found after user message, search backwards for any recent assistant text
    # This handles the case where Stop hook fires before final message is written
    if not all_text_parts:
        LOGGER.info("no_text_after_user_msg, searching backwards from_idx=%d", last_user_idx)
        for i in range(last_user_idx - 1, max(0, last_user_idx - 50), -1):
            line = lines[i].strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if entry.get("type") == "assistant":
                message = entry.get("message", {})
                content = message.get("content", [])
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            text = block.get("text", "").strip()
                            if text:
                                LOGGER.info("found_previous_assistant_text at_idx=%d len=%d", i, len(text))
                                return text

    if all_text_parts:
        result = "\n\n".join(all_text_parts)
        LOGGER.info("found_turn_text parts=%d len=%d preview=%r", len(all_text_parts), len(result), result[:100])
        return result

    LOGGER.info("no_text_in_turn path=%s from_idx=%d attempt=%d", str(path), last_user_idx, attempt)
    return ""


def _normalize_notification_type(notification: dict) -> str:
    """
    Normalize notification type from various sources:
    - Codex: type field (e.g., "agent-turn-complete", "agent_turn_complete")
    - Claude Code hooks: hook_event_name + notification_type
      - Stop event -> "stop" (similar to turn complete)
      - Notification event -> notification_type (e.g., "idle_prompt", "permission_prompt")
    """
    # Claude Code hooks: check hook_event_name first
    hook_event = notification.get("hook_event_name", "")
    if hook_event:
        # Stop event = Claude finished responding (like agent-turn-complete)
        if hook_event == "Stop":
            return "stop"
        # Notification event: use notification_type sub-field
        if hook_event == "Notification":
            notification_type = notification.get("notification_type", "")
            if notification_type:
                return notification_type.replace("_", "-")
            return "notification"
        # SubagentStop = subagent finished
        if hook_event == "SubagentStop":
            return "subagent-stop"
        # Other hook events
        return hook_event.lower().replace("_", "-")

    # Codex / OpenAI Codex: use type field
    notification_type = notification.get("type")
    if not notification_type:
        return ""
    return notification_type.replace("_", "-").replace(".", "-")


def _dump_json_if_requested(raw_json: str, thread_id: str) -> None:
    if not DEBUG_DUMP_JSON:
        return

    try:
        log_dir = Path(__file__).resolve().parent / "log" / "notify_payloads"
        log_dir.mkdir(parents=True, exist_ok=True)
        suffix = thread_id or "no-thread"
        dump_file = log_dir / f"payload-{suffix}.json"
        dump_file.write_text(raw_json, encoding="utf-8")
        LOGGER.info("dumped_payload path=%s bytes=%d", str(dump_file), len(raw_json))
    except Exception as e:
        LOGGER.warning("dump_payload_failed error=%r", e)


def main():
    # 1. 获取输入数据
    raw_json = _read_notification_json()

    if not raw_json:
        print("Usage: notify.py <JSON_STRING> (or pipe via stdin)")
        LOGGER.info("no_input argv=%r", sys.argv)
        return 1

    try:
        notification = json.loads(raw_json)
    except json.JSONDecodeError:
        LOGGER.error("invalid_json raw_prefix=%r", raw_json[:200])
        print("Error: Invalid JSON input")
        return 1

    # 2. 解析逻辑 — 用 if/else，而不是 match
    notification_type = notification.get("type")
    hook_event_name = notification.get("hook_event_name", "")
    normalized_type = _normalize_notification_type(notification)
    title = ""
    message = ""

    # Get context info for prefix
    username = os.getenv("USER", os.getenv("USERNAME", "unknown"))
    hostname = socket.gethostname()
    cwd = notification.get("cwd", os.getcwd())
    # Shorten home directory
    home = os.path.expanduser("~")
    if cwd.startswith(home):
        cwd = "~" + cwd[len(home):]
    context_prefix = "[%s@%s %s]" % (username, hostname, cwd)

    thread_id = _get_thread_id(notification)
    LOGGER.info(
        "notify_received type=%r hook_event=%r normalized=%r thread_id=%r env={APP_ID:%s,APP_SECRET:%s,USER_ID:%s} argv_len=%d raw_len=%d",
        notification_type,
        hook_event_name,
        normalized_type,
        thread_id,
        _safe_env_flag("FEISHU_APP_ID"),
        _safe_env_flag("FEISHU_APP_SECRET"),
        _safe_env_flag("FEISHU_USER_ID"),
        len(sys.argv),
        len(raw_json),
    )
    _dump_json_if_requested(raw_json, thread_id)

    # Prevent infinite loops for Claude Code Stop hook
    if notification.get("stop_hook_active"):
        LOGGER.info("skip_stop_hook_active to prevent infinite loop")
        return 0

    if normalized_type == "agent-turn-complete":
        # Codex: agent turn complete
        assistant_message = _get_last_assistant_message(notification)
        if assistant_message:
            short_msg = (
                assistant_message[:1500] + ".."
                if len(assistant_message) > 1500
                else assistant_message
            )
            title = "%s Codex:\n%s" % (context_prefix, short_msg)
        else:
            title = "%s Codex: Turn Complete!" % context_prefix

    elif normalized_type == "stop":
        # Claude Code: Stop hook (Claude finished responding)
        # Read last assistant message from transcript file
        assistant_message = _get_last_assistant_message(notification)
        if assistant_message:
            short_msg = (
                assistant_message[:1500] + ".."
                if len(assistant_message) > 1500
                else assistant_message
            )
            title = "%s Claude Code:\n%s" % (context_prefix, short_msg)
        else:
            title = "%s Claude Code: Turn Complete!" % context_prefix

    elif normalized_type == "subagent-stop":
        # Claude Code: SubagentStop hook
        title = "%s Claude Code: Subagent Complete!" % context_prefix
        assistant_message = _get_last_assistant_message(notification)
        if assistant_message:
            message = assistant_message[:1500]

    elif normalized_type in ("idle-prompt", "permission-prompt"):
        # Claude Code: Notification hook - needs user attention
        notif_title = notification.get("title", "")
        notif_message = notification.get("message", "")
        if normalized_type == "permission-prompt":
            title = "%s Claude Code: Permission Needed" % context_prefix
        else:
            title = "%s Claude Code: Waiting for Input" % context_prefix
        if notif_title:
            message = notif_title
        if notif_message:
            message = "%s\n%s" % (message, notif_message) if message else notif_message

    else:
        LOGGER.info("skip_notification type=%r hook_event=%r normalized=%r", notification_type, hook_event_name, normalized_type)
        print("Not sending a push notification for type:", notification_type or hook_event_name)
        return 0

    try:
        send_feishu_dm(title, message, thread_id)
    except Exception as e:
        LOGGER.error("send_failed error=%r\n%s", e, traceback.format_exc())
        print("❌ notify failed:", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
