#!/usr/bin/env bash

set -uo pipefail

OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-gpt-oss:20b}"
OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-16384}"
OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-30m}"
CURL_TIMEOUT="${CURL_TIMEOUT:-120}"

passes=0
failures=0
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

pass() {
  printf 'PASS  %s\n' "$1"
  passes=$((passes + 1))
}

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'ERROR required command not found: %s\n' "$1" >&2
    exit 2
  fi
}

post_chat() {
  local payload_file="$1"
  local output_file="$2"

  curl --fail --silent --show-error \
    --connect-timeout 5 \
    --max-time "$CURL_TIMEOUT" \
    -H 'Content-Type: application/json' \
    --data-binary "@$payload_file" \
    "$OLLAMA_HOST/api/chat" >"$output_file"
}

require_command curl
require_command jq

printf 'Ollama smoke tests\n'
printf '  host:  %s\n' "$OLLAMA_HOST"
printf '  model: %s\n\n' "$OLLAMA_MODEL"

tags_file="$temp_dir/tags.json"
if curl --fail --silent --show-error \
  --connect-timeout 5 \
  --max-time 15 \
  "$OLLAMA_HOST/api/tags" >"$tags_file"; then
  pass 'Ollama endpoint is reachable'
else
  fail 'Ollama endpoint is not reachable'
  exit 1
fi

if jq -e --arg model "$OLLAMA_MODEL" \
  '.models[]? | select(.name == $model)' "$tags_file" >/dev/null; then
  pass "model $OLLAMA_MODEL is installed"
else
  fail "model $OLLAMA_MODEL is not installed"
fi

jq -n \
  --arg model "$OLLAMA_MODEL" \
  --arg keep_alive "$OLLAMA_KEEP_ALIVE" \
  --argjson num_ctx "$OLLAMA_CONTEXT_LENGTH" \
  '{
    model: $model,
    messages: [{role: "user", content: "Responda apenas WARM_OK"}],
    stream: false,
    think: false,
    keep_alive: $keep_alive,
    options: {temperature: 0, num_ctx: $num_ctx}
  }' >"$temp_dir/warm-request.json"

if post_chat "$temp_dir/warm-request.json" "$temp_dir/warm-first.json" && \
  post_chat "$temp_dir/warm-request.json" "$temp_dir/warm-second.json"; then
  first_load_ms="$(jq -r '(.load_duration // 0) / 1000000 | floor' "$temp_dir/warm-first.json")"
  second_load_ms="$(jq -r '(.load_duration // 0) / 1000000 | floor' "$temp_dir/warm-second.json")"
  second_total_ms="$(jq -r '(.total_duration // 0) / 1000000 | floor' "$temp_dir/warm-second.json")"
  if jq -e '.message.content | test("WARM_OK")' "$temp_dir/warm-second.json" >/dev/null; then
    pass "warm request succeeds (load ${first_load_ms}ms -> ${second_load_ms}ms, warm total ${second_total_ms}ms)"
  else
    fail 'warm request returned unexpected content'
  fi
else
  fail 'warm request failed'
fi

jq -n \
  --arg model "$OLLAMA_MODEL" \
  --arg keep_alive "$OLLAMA_KEEP_ALIVE" \
  --argjson num_ctx "$OLLAMA_CONTEXT_LENGTH" \
  '{
    model: $model,
    messages: [{
      role: "user",
      content: "Classifique o risco como low, medium ou high. Existem 12 tentativas de login com falha e um login de risco alto."
    }],
    format: {
      type: "object",
      properties: {
        risk: {type: "string", enum: ["low", "medium", "high"]},
        reason: {type: "string"}
      },
      required: ["risk", "reason"],
      additionalProperties: false
    },
    stream: false,
    think: "low",
    keep_alive: $keep_alive,
    options: {temperature: 0, num_ctx: $num_ctx}
  }' >"$temp_dir/structured-request.json"

if post_chat "$temp_dir/structured-request.json" "$temp_dir/structured-response.json"; then
  structured_content="$(jq -r '.message.content // empty' "$temp_dir/structured-response.json")"
  if jq -e '
    type == "object" and
    (.risk == "low" or .risk == "medium" or .risk == "high") and
    (.reason | type == "string" and length > 0) and
    (keys | sort == ["reason", "risk"])
  ' <<<"$structured_content" >/dev/null 2>&1; then
    pass "structured output matches schema (risk=$(jq -r '.risk' <<<"$structured_content"))"
  else
    fail 'structured output does not match the expected schema'
  fi
else
  fail 'structured output request failed'
fi

jq -n \
  --arg model "$OLLAMA_MODEL" \
  --arg keep_alive "$OLLAMA_KEEP_ALIVE" \
  --argjson num_ctx "$OLLAMA_CONTEXT_LENGTH" \
  '{
    model: $model,
    messages: [
      {role: "system", content: "Para investigar um usuario, chame investigate_user. Nao invente resultados."},
      {role: "user", content: "Investigue alice@contoso.com nos ultimos 7 dias."}
    ],
    tools: [{
      type: "function",
      function: {
        name: "investigate_user",
        description: "Obtem evidencias de seguranca de identidade para um usuario.",
        parameters: {
          type: "object",
          properties: {
            user_upn: {type: "string"},
            days_back: {type: "integer", minimum: 1, maximum: 30}
          },
          required: ["user_upn", "days_back"],
          additionalProperties: false
        }
      }
    }],
    stream: false,
    think: false,
    keep_alive: $keep_alive,
    options: {temperature: 0, num_ctx: $num_ctx}
  }' >"$temp_dir/tool-request.json"

if post_chat "$temp_dir/tool-request.json" "$temp_dir/tool-response.json"; then
  if jq -e '
    .message.tool_calls | length == 1 and
    .[0].function.name == "investigate_user" and
    .[0].function.arguments.user_upn == "alice@contoso.com" and
    .[0].function.arguments.days_back == 7 and
    (.[0].function.arguments | keys | sort == ["days_back", "user_upn"])
  ' "$temp_dir/tool-response.json" >/dev/null; then
    pass 'tool calling selects investigate_user with valid arguments'
  else
    fail 'tool calling returned an unexpected tool or arguments'
  fi
else
  fail 'tool calling request failed'
fi

jq -n \
  --arg model "$OLLAMA_MODEL" \
  --arg keep_alive "$OLLAMA_KEEP_ALIVE" \
  --argjson num_ctx "$OLLAMA_CONTEXT_LENGTH" \
  '{
    model: $model,
    messages: [
      {role: "system", content: "Use somente as evidencias fornecidas. Diferencie fatos de hipoteses. Nao invente IP, pais, dispositivo ou horario."},
      {role: "user", content: "Investigue alice@contoso.com nos ultimos 7 dias."},
      {
        role: "assistant",
        content: "",
        tool_calls: [{function: {name: "investigate_user", arguments: {user_upn: "alice@contoso.com", days_back: 7}}}]
      },
      {
        role: "tool",
        tool_name: "investigate_user",
        content: "{\"status\":\"success\",\"failed_signins\":12,\"high_risk_signins\":1,\"audit_events\":0}"
      }
    ],
    stream: false,
    think: false,
    keep_alive: $keep_alive,
    options: {temperature: 0, num_ctx: $num_ctx}
  }' >"$temp_dir/follow-up-request.json"

if post_chat "$temp_dir/follow-up-request.json" "$temp_dir/follow-up-response.json"; then
  follow_up="$(jq -r '.message.content // empty' "$temp_dir/follow-up-response.json")"
  if grep -Eq '12|doze' <<<"$follow_up" && \
    grep -Eq '1|um|alto risco' <<<"$follow_up" && \
    grep -Eq '0|nenhum|ausencia|não há|nao ha' <<<"$follow_up"; then
    pass 'tool result is incorporated into the final response'
  else
    fail 'final response omitted one or more supplied facts'
  fi
else
  fail 'tool result follow-up request failed'
fi

printf '\nSummary: %d passed, %d failed\n' "$passes" "$failures"

if ((failures > 0)); then
  exit 1
fi