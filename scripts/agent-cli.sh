#!/usr/bin/env bash
#
# OpenClaw Agent CLI 调用封装
# 用于自动化环境调用 SKILL
#

set -e

WORKSPACE="${WORKSPACE:-$HOME/.openclaw/workspace}"
SKILL="cve-review"

cmd_analyze_cve() {
    local cve_id="$1"
    [[ -z "$cve_id" ]] && { echo "用法: $0 analyze <cve-id>"; exit 1; }
    
    echo "[*] 调用 OpenClaw agent 分析 $cve_id..."
    
    # 使用 openclaw agent 调用（非 TUI）
    openclaw agent \
        --agent main \
        --message "执行 CVE Review SKILL，分析 $cve_id 漏洞，输出完整报告" \
        --timeout 120
}

cmd_batch_analyze() {
    local since="$1"
    local limit="${2:-10}"
    [[ -z "$since" ]] && { echo "用法: $0 batch <since-date> [limit]"; exit 1; }
    
    echo "[*] 批量分析 $since 之后的 $limit 个 CVE..."
    
    openclaw agent \
        --agent main \
        --message "执行 CVE Review SKILL，分析 $since 之后的前 $limit 个 CVE 漏洞，生成批量分析报告" \
        --timeout 300
}

case "${1:-}" in
    analyze)
        cmd_analyze_cve "$2"
        ;;
    batch)
        cmd_batch_analyze "$2" "$3"
        ;;
    *)
        echo "用法: $0 <analyze|batch> [args]"
        echo ""
        echo "示例:"
        echo "  $0 analyze CVE-2025-40198"
        echo "  $0 batch 2025-11-01 10"
        exit 1
        ;;
esac
