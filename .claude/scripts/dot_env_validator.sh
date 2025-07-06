#!/bin/bash

# 標準入力からJSONを読み込む
input=$(cat)

# PreToolUse で渡されてくるJSONを確認し、ログへ出力する
echo "$input" | jq . > ./logs/"$(date +%Y_%m%d_%H%M%S)_log.txt"

# .envファイルかチェック
if echo "$input" | jq -e '.tool_input.file_path | test("/\\.env$")' > /dev/null; then
    # ブロックメッセージを出力
    echo '{"decision": "block", "reason": ".envファイルへの操作をブロックしました"}'
    exit 2
fi

# commandに.envが含まれるかチェック
if echo "$input" | jq -e '.tool_input.command | test("(^|\\s)\\.env($|\\s)")' > /dev/null 2>&1; then
    echo '{"decision": "block", "reason": ".envファイルへの操作をブロックしました（command）"}'
    exit 2
fi

# .envでない場合は何も出力せず正常終了
exit 0