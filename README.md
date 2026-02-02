# Claude Code Feishu Notify

Claude Code 完成任务后自动发送飞书通知。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/zhonglinxie/claude-codex-feishu-notify/main/install.sh | bash
```

## 配置环境变量

安装后需要配置飞书凭据，添加到 `~/.bashrc` 或 `~/.zshrc`：

```bash
export FEISHU_APP_ID="your_app_id"
export FEISHU_APP_SECRET="your_app_secret"
export FEISHU_USER_ID="your_user_id"
```

然后执行 `source ~/.bashrc`。

## 获取飞书凭据

### 1. 创建飞书应用
1. 访问 [飞书开放平台](https://open.feishu.cn/app)
2. 创建企业自建应用
3. 获取 `App ID` 和 `App Secret`

### 2. 配置应用权限
在应用的「权限管理」中开启：
- `im:message:send_as_bot` - 以应用身份发消息

### 3. 获取 User ID
1. 在应用中添加「通讯录」权限
2. 调用 API 或在飞书管理后台查看你的 `user_id`

## 测试

```bash
# 手动测试
echo '{"hook_event_name":"Stop","session_id":"test-123"}' | python3 ~/.codex/notify.py
```

## 功能

- **Stop Hook**: Claude 完成回复时发送通知（包含回复内容摘要）
- **Notification Hook**: 需要权限确认时发送通知（默认不推送“闲置输入提示”，可通过环境变量开启）

## 调试

| 环境变量 | 说明 |
|---------|------|
| `CODEX_NOTIFY_DRY_RUN=1` | 不发送，只打印日志 |
| `CODEX_NOTIFY_DUMP_JSON=1` | 保存收到的 JSON |
| `CODEX_NOTIFY_CLAUDE_IDLE_PROMPT=1` | 发送 Claude Code 的闲置输入提示通知（默认关闭） |
| `CODEX_NOTIFY_CLAUDE_EMPTY_STOP=1` | Stop 事件即使没有解析到回复文本也发送通知（默认关闭） |

日志位置：`~/.codex/log/notify.log`

## License

MIT
