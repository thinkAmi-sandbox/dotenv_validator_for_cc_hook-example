#!/usr/bin/env python3

import json
import sys
import re
import subprocess
import os
from datetime import datetime


def notify_block():
    """ブロックしたことを通知"""
    subprocess.run(['afplay', '/System/Library/Sounds/Sosumi.aiff'])

def contains_dangerous_patterns(cmd):
    """危険なパターンを含んでいるかチェック"""
    if not cmd:
        return False
    
    # 正規化：複数のスペースを1つに
    cmd_normalized = re.sub(r'\s+', ' ', cmd)
    
    # 検出パターン
    patterns = [
        # 直接的な.envアクセス
        r'(^|[^a-zA-Z0-9_])\.env($|[^a-zA-Z0-9_])',
        
        # ワイルドカード
        r'(\s|^|["\'])\.\*',
        
        # コマンド置換
        r'(\s|^|["\'])\.\$',
        
        # ブラケット表現
        r'\.\[[^\]]*[en][^\]]*\]',
        
        # 文字列結合・変数展開
        r'["\']\.e["\']\s*\+\s*["\']nv["\']',
        r'\$\{[^}]*\}.*env',
        r'\.e.*\$.*nv',
        
        # エンコードされた文字
        r'\\x2e.*env',
        r'\\056.*env',
        r'chr\(46\)',
        
        # 部分文字列マッチング
        r'\.e[^a-zA-Z0-9]{0,5}n[^a-zA-Z0-9]{0,5}v',
        
        # 危険なコマンドと.の組み合わせ
        r'(cat|head|tail|less|more|sed|awk|grep|python|perl|ruby|node).*\s+\.',
        
        # awk/sed/grep等での正規表現パターン
        r'(awk|sed|grep).*[/"\'].*\\\..*v.*[/"\']',  # \. と v を含む正規表現
        r'(awk|sed|grep).*[/"\'][^/"\']*(\.|\\\.).*[envENV]',  # . または \. と e,n,v を含む
        r'/\^.*\\\..*v\$/',  # /^...\....v$/ のようなパターン
        
        # findコマンドのパターン
        r'find.*\-name.*["\'].*\.',
        r'find.*\-regex.*["\'].*\.',
        
        # globパターン
        r'glob["\'\(].*\.',
        
        # xargsとの組み合わせ
        r'\|\s*xargs\s+(cat|head|tail|less|more)',
    ]
    
    # パターンチェック
    for pattern in patterns:
        if re.search(pattern, cmd, re.IGNORECASE):
            return True
    
    # 危険な文字列の組み合わせチェック
    dangerous_parts = [
        ('.e', 'nv'),
        ('.', 'env'),
        ('dot', 'env'),
        ('2e', '656e76'),
        ('\\.', 'v$'),  # awkパターン用
        ('\.', '*v'),   # 正規表現パターン
    ]
    
    cmd_lower = cmd.lower()
    for part1, part2 in dangerous_parts:
        if part1 in cmd_lower and part2 in cmd_lower:
            idx1 = cmd_lower.find(part1)
            idx2 = cmd_lower.find(part2)
            if 0 <= abs(idx2 - idx1) <= 50:
                return True
    
    # コマンドインジェクションの可能性
    if re.search(r'(eval|exec|os\.system|subprocess|\\`|`)', cmd, re.IGNORECASE):
        if re.search(r'(env|\.)', cmd, re.IGNORECASE):
            return True
    
    # パイプラインを使った複雑な処理の検出
    # ls/find等 → フィルタリング → cat/read等
    pipeline_pattern = r'(ls|find|dir).*\|.*\|.*(cat|head|tail|xargs\s+(cat|head|tail))'
    if re.search(pipeline_pattern, cmd, re.IGNORECASE):
        # パイプライン内に危険なパターンがあるか
        if re.search(r'(\.|env|\\\.)', cmd, re.IGNORECASE):
            return True

    # グロブパターンチェック
    glob_patterns = [
        r'\.\?+\*',      # .?*, .??*
        r'for\s+\w+\s+in\s+\.',  # for i in .
        r'\$\(.*\.\*.*\)',       # $(... .* ...)
    ]
    
    if any(re.search(p, cmd) for p in glob_patterns):
        return True
    
    # 複雑なパイプラインチェック
    if cmd.count('|') >= 2 and re.search(r'(head|tail|cat)', cmd):
        return True
    
    return False

def main():
    try:
        # 標準入力からJSONを読み込む
        input_raw = sys.stdin.read()
        
        try:
            input_data = json.loads(input_raw)
        except json.JSONDecodeError as e:
            # JSONパースエラーは攻撃の可能性があるため、ブロック
            error_data = {
                "error": "Invalid JSON input",
                "details": str(e),
                "input_preview": input_raw[:200]
            }
            notify_block()
            
            response = {
                "decision": "block",
                "reason": "不正な入力形式です（JSONパースエラー）"
            }
            print(json.dumps(response, ensure_ascii=False))
            sys.exit(2)
        
        # tool_inputが存在するかチェック
        tool_input = input_data.get('tool_input', {})
        
        # file_pathのチェック
        file_path = tool_input.get('file_path', '')
        if file_path and re.search(r'/\.env$', file_path):
            notify_block()

            response = {
                "decision": "block",
                "reason": ".envファイルへの操作をブロックしました"
            }
            print(json.dumps(response, ensure_ascii=False))
            sys.exit(2)
        
        # commandのチェック
        command = tool_input.get('command', '')
        if command and contains_dangerous_patterns(command):
            notify_block()

            response = {
                "decision": "block",
                "reason": "環境変数ファイルへのアクセスをブロックしました"
            }
            print(json.dumps(response, ensure_ascii=False))
            sys.exit(2)
        
        # 問題なければ正常終了（何も出力しない）
        sys.exit(0)
        
    except Exception as e:
        # 予期しないエラーは安全のためブロック（Fail-closed）
        error_data = {
            "error": str(e),
            "type": type(e).__name__,
            "timestamp": datetime.now().isoformat()
        }
        notify_block()
        
        response = {
            "decision": "block",
            "reason": "内部エラーが発生しました（安全のためブロック）"
        }
        print(json.dumps(response, ensure_ascii=False))
        sys.exit(2)


if __name__ == '__main__':
    main()