#!/usr/bin/env bash
# Đổi chế độ WAF và xem trạng thái — dùng khi demo.
#   ./scripts/waf-mode.sh detect     # DetectionOnly: chỉ phát hiện + ghi log
#   ./scripts/waf-mode.sh block      # On: chặn request vượt ngưỡng
#   ./scripts/waf-mode.sh status     # chế độ đang chạy thực tế trong container
#   ./scripts/waf-mode.sh clear-logs # xóa log cũ trước buổi demo
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"

set_mode() {
  sed -i '' "s/^WAF_MODE=.*/WAF_MODE=$1/" .env
  docker compose up -d waf >/dev/null 2>&1
  printf "Đang khởi động lại WAF"
  for _ in $(seq 1 30); do
    if [ "$(docker inspect -f '{{.State.Health.Status}}' waf-lab-waf 2>/dev/null)" = "healthy" ]; then
      echo " — xong."
      status
      return
    fi
    printf "."; sleep 1
  done
  echo; echo "WAF chưa healthy, kiểm tra: docker compose logs waf" >&2; exit 1
}

status() {
  mode=$(docker exec waf-lab-waf printenv MODSEC_RULE_ENGINE 2>/dev/null || echo "?")
  pl=$(docker exec waf-lab-waf printenv BLOCKING_PARANOIA 2>/dev/null || echo "?")
  th=$(docker exec waf-lab-waf printenv ANOMALY_INBOUND 2>/dev/null || echo "?")
  echo "Chế độ WAF: $mode | Paranoia Level: $pl | Ngưỡng inbound: $th"
}

case "${1:-status}" in
  detect)     set_mode DetectionOnly ;;
  block)      set_mode On ;;
  status)     status ;;
  clear-logs) : > logs/waf/modsec_audit.json; : > logs/waf/access.log; : > logs/waf/error.log
              echo "Đã xóa log trong logs/waf/" ;;
  *) echo "Cách dùng: $0 {detect|block|status|clear-logs}" >&2; exit 1 ;;
esac
