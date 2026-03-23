#!/usr/bin/env bash
#
# 动态创建 Sub-Agent 执行任务
# 用法: ./spawn-agent.sh <task-type> [args]
#

set -e

AGENT_ID="${AGENT_ID:-cve-analyzer}"
TIMEOUT="${TIMEOUT:-300}"
WORKSPACE="${WORKSPACE:-$HOME/.openclaw/workspace/skills/cve-review}"

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

# 生成唯一的 session ID
generate_session_id() {
    local task_type="$1"
    echo "${AGENT_ID}-${task_type}-$(date +%s)-$$"
}

# 清理函数
cleanup() {
    if [[ -n "${SESSION_ID:-}" ]]; then
        log "清理 session: $SESSION_ID"
        # 可选：删除临时 session
    fi
}
trap cleanup EXIT

# 执行 CVE 分析任务
cmd_analyze() {
    local cve_id="$1"
    [[ -z "$cve_id" ]] && { echo "用法: $0 analyze <cve-id>"; exit 1; }
    
    SESSION_ID=$(generate_session_id "analyze-${cve_id}")
    log "创建 sub-agent session: $SESSION_ID"
    log "任务: 分析 $cve_id"
    
    cd "$WORKSPACE"
    
    # 动态创建 sub-agent 实例执行任务
    openclaw agent \
        --agent "$AGENT_ID" \
        --session-id "$SESSION_ID" \
        --message "执行 CVE Review SKILL，完整分析 $cve_id 漏洞。要求：1.查询CVE详情 2.检查代码 3.Kconfig检查 4.生成报告到 reports/ 目录" \
        --timeout "$TIMEOUT" \
        --thinking medium \
        --verbose on
    
    log "任务完成，session: $SESSION_ID"
}

# 批量分析任务
cmd_batch() {
    local since="$1"
    local limit="${2:-10}"
    [[ -z "$since" ]] && { echo "用法: $0 batch <since-date> [limit]"; exit 1; }
    
    SESSION_ID=$(generate_session_id "batch-${since}")
    log "创建 sub-agent session: $SESSION_ID"
    log "任务: 批量分析 $since 之后的 $limit 个 CVE"
    
    cd "$WORKSPACE"
    
    openclaw agent \
        --agent "$AGENT_ID" \
        --session-id "$SESSION_ID" \
        --message "执行 CVE Review SKILL，批量分析 $since 之后的前 $limit 个 CVE。步骤：1.同步CVE数据 2.逐一分析 3.生成汇总报告" \
        --timeout "$((TIMEOUT * 3))" \
        --thinking medium
    
    log "批量任务完成，session: $SESSION_ID"
}

# 监控任务（心跳模式）
cmd_monitor() {
    local interval="${1:-300}"  # 默认5分钟
    SESSION_ID=$(generate_session_id "monitor")
    
    log "创建监控 sub-agent: $SESSION_ID"
    log "监控间隔: ${interval}秒"
    
    while true; do
        openclaw agent \
            --agent "$AGENT_ID" \
            --session-id "$SESSION_ID" \
            --message "执行监控检查：检查是否有新的CVE需要分析，检查reports目录状态" \
            --timeout 60 \
            --thinking low
        
        log "等待 ${interval}秒后下次检查..."
        sleep "$interval"
    done
}

# 列出所有 sub-agent sessions
cmd_list() {
    log "列出所有 sessions:"
    openclaw sessions --agent "$AGENT_ID" --json | \
        python3 -c "import json,sys; data=json.load(sys.stdin); [print(f\"{s.get('id', 'N/A')}: {s.get('lastMessage', 'N/A')[:50]}...\") for s in data.get('sessions', [])]" 2>/dev/null || \
        openclaw sessions --agent "$AGENT_ID"
}

# 杀死指定 session
cmd_kill() {
    local target_session="$1"
    [[ -z "$target_session" ]] && { echo "用法: $0 kill <session-id>"; exit 1; }
    
    log "终止 session: $target_session"
    # 使用 subagents 工具或发送终止信号
    openclaw sessions send \
        --session-id "$target_session" \
        --message "SYSTEM: 收到终止命令，请立即退出" || true
    
    log "已发送终止信号"
}

# 主入口
case "${1:-help}" in
    analyze)
        shift
        cmd_analyze "$@"
        ;;
    batch)
        shift
        cmd_batch "$@"
        ;;
    monitor)
        shift
        cmd_monitor "$@"
        ;;
    list)
        cmd_list
        ;;
    kill)
        shift
        cmd_kill "$@"
        ;;
    help|-h|--help|*)
        cat << 'EOF'
动态 Sub-Agent 管理工具

用法:
    ./spawn-agent.sh <command> [args]

命令:
    analyze <cve-id>          创建 sub-agent 分析单个 CVE
    batch <since> [limit]    创建 sub-agent 批量分析
    monitor [interval]       创建监控 sub-agent（循环执行）
    list                     列出所有 sub-agent sessions
    kill <session-id>        终止指定 sub-agent

环境变量:
    AGENT_ID    使用的 agent ID (默认: cve-analyzer)
    TIMEOUT     超时时间秒数 (默认: 300)
    WORKSPACE   工作目录 (默认: ~/.openclaw/workspace/skills/cve-review)

示例:
    # 分析单个 CVE
    ./spawn-agent.sh analyze CVE-2025-40198

    # 批量分析
    ./spawn-agent.sh batch 2025-11-01 10

    # 创建监控 agent（每5分钟检查一次）
    ./spawn-agent.sh monitor 300

    # 列出所有 sessions
    ./spawn-agent.sh list

    # 终止指定 session
    ./spawn-agent.sh kill cve-analyzer-analyze-CVE-2025-40198-1234567890-1234
EOF
        exit 1
        ;;
esac
