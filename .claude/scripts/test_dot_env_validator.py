#!/usr/bin/env python3
"""
dot_env_validator.pyのcontains_dangerous_patterns関数に対する包括的なテストスイート

テストカテゴリ:
1. ポジティブテスト: ブロックされるべき危険なパターン
2. ネガティブテスト: 許可されるべき安全なパターン
3. すり抜けテスト: 本来ブロックしたいが現在は通過するパターン
"""

import unittest
from dot_env_validator import contains_dangerous_patterns


class TestContainsDangerousPatterns(unittest.TestCase):
    """contains_dangerous_patterns関数の包括的なテスト"""
    
    # ========================================
    # ポジティブテスト（ブロックされるべきパターン）
    # ========================================
    
    # --- 直接的な.envアクセス ---
    def test_direct_env_access_cat(self):
        """cat .envコマンドをブロック"""
        self.assertTrue(contains_dangerous_patterns("cat .env"))
    
    def test_direct_env_access_with_path(self):
        """パス付き.envアクセスをブロック"""
        self.assertTrue(contains_dangerous_patterns("cat /path/to/.env"))
    
    def test_direct_env_access_with_quotes(self):
        """クォート付き.envアクセスをブロック"""
        self.assertTrue(contains_dangerous_patterns('cat ".env"'))
        self.assertTrue(contains_dangerous_patterns("cat '.env'"))
    
    # --- ワイルドカードパターン ---
    def test_wildcard_dot_star(self):
        """.*パターンをブロック"""
        self.assertTrue(contains_dangerous_patterns("cat .*"))
    
    def test_wildcard_dot_question(self):
        """複数の?を使ったパターンもブロックされる"""
        # 注: .??* パターンも危険なパターンとして検出される
        self.assertTrue(contains_dangerous_patterns("cat .??*"))
    
    def test_cat_double_question_v(self):
        """cat .??vパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('cat .??v'))
    
    def test_cat_star_nv(self):
        """cat .*nvパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('cat .*nv'))
    
    def test_wildcard_in_quotes(self):
        """クォート内のワイルドカードをブロック"""
        self.assertTrue(contains_dangerous_patterns('ls ".*"'))
        self.assertTrue(contains_dangerous_patterns("ls '.*'"))
    
    # --- コマンド置換 ---
    def test_command_substitution_dot_dollar(self):
        """.$パターンをブロック"""
        self.assertTrue(contains_dangerous_patterns("echo .$"))
        self.assertTrue(contains_dangerous_patterns('echo ".$"'))
    
    # --- ブラケット表現 ---
    def test_bracket_expression_e_bracket(self):
        """.[e]nvパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns("cat .[e]nv"))
    
    def test_bracket_expression_en_bracket(self):
        """.[en]vパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns("cat .[en]v"))
    
    def test_bracket_expression_env_bracket(self):
        """複雑なブラケット表現をブロック"""
        self.assertTrue(contains_dangerous_patterns("cat .[e][n][v]"))
    
    # --- 文字列連結・変数展開 ---
    def test_string_concat_python(self):
        """Python風の文字列連結をブロック"""
        self.assertTrue(contains_dangerous_patterns('python -c "open(\\".e\\" + \\"nv\\")"'))
    
    def test_python_runtime_concat(self):
        """Python実行時の文字列連結をブロック"""
        self.assertTrue(contains_dangerous_patterns('python3 -c "import os; f=\'.e\'+\'nv\'; print(open(f).read())"'))
    
    def test_string_concat_javascript(self):
        """JavaScript風の文字列連結をブロック"""
        self.assertTrue(contains_dangerous_patterns('node -e "fs.readFileSync(\\".e\\" + \\"nv\\")"'))
    
    def test_variable_expansion_bash(self):
        """Bash変数展開をブロック"""
        self.assertTrue(contains_dangerous_patterns('cat ${prefix}env'))
    
    def test_bash_variable_concat(self):
        """Bash変数を使った段階的連結をブロック"""
        self.assertTrue(contains_dangerous_patterns('file=".e"; file="${file}nv"; cat "$file"'))
    
    def test_dot_e_dollar_nv(self):
        """.e$nvパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('file=.e$nv'))
    
    # --- エンコードされた文字 ---
    def test_hex_encoding_x2e(self):
        """16進エンコード\\x2eをブロック"""
        self.assertTrue(contains_dangerous_patterns('cat \\x2eenv'))
    
    def test_octal_encoding_056(self):
        """8進エンコード\\056をブロック"""
        self.assertTrue(contains_dangerous_patterns('cat \\056env'))
    
    def test_chr_46(self):
        """chr(46)をブロック"""
        self.assertTrue(contains_dangerous_patterns('python -c "print(chr(46) + \\"env\\")"'))
    
    # --- 部分文字列マッチング ---
    def test_partial_match_with_separators(self):
        """セパレータを含む部分マッチングをブロック"""
        self.assertTrue(contains_dangerous_patterns('cat .e-n-v'))
        self.assertTrue(contains_dangerous_patterns('cat .e_n_v'))
    
    # --- 危険なコマンドとの組み合わせ ---
    def test_dangerous_command_cat_dot(self):
        """catと.の組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('cat .'))
    
    def test_dangerous_command_python_dot(self):
        """pythonと.の組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('python .script'))
    
    def test_dangerous_command_grep_dot(self):
        """grepと.の組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('grep pattern .file'))
    
    # --- awk/sed/grep正規表現パターン ---
    def test_awk_regex_pattern(self):
        """awkの正規表現パターンをブロック"""
        self.assertTrue(contains_dangerous_patterns("awk '/^\\..*v$/' file"))
    
    def test_awk_print_bracket(self):
        """awkの単純printパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns("awk '{print}' .[e]nv"))
    
    def test_sed_regex_pattern(self):
        """sedの正規表現パターンをブロック"""
        self.assertTrue(contains_dangerous_patterns("sed 's/\\.env//' file"))
    
    def test_sed_print_multiple_brackets(self):
        """sedと複数ブラケットパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('sed -n \'p\' .[e][n][v]'))
    
    def test_grep_regex_with_dot_v(self):
        """grepの.とvを含む正規表現をブロック"""
        self.assertTrue(contains_dangerous_patterns("grep '\\..*v' file"))
    
    def test_grep_with_filename(self):
        """grep -Hオプションでファイル名付き出力をブロック"""
        self.assertTrue(contains_dangerous_patterns('grep -H . .[e]nv'))
    
    def test_tail_from_line_one(self):
        """tail -n +1パターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('tail -n +1 .[e]nv'))
    
    # --- findコマンドパターン ---
    def test_find_name_with_dot(self):
        """find -nameと.の組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('find . -name ".*"'))
    
    def test_find_regex_with_dot(self):
        """find -regexと.の組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('find . -regex ".*\\.env"'))
    
    def test_find_question_pattern(self):
        """find with ?e?vパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('find . -maxdepth 1 -name "?e?v" -exec cat {} \\;'))
    
    # --- globパターン ---
    def test_glob_with_dot(self):
        """glob関数と.の組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('glob(".*")'))
    
    def test_python_glob_pattern(self):
        """Pythonのglobパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns("python -c \"import glob; glob.glob('.*')\""))
    
    # --- xargsとの組み合わせ ---
    def test_pipe_xargs_cat(self):
        """パイプとxargs catの組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('ls | xargs cat'))
    
    # --- バイナリ操作系コマンド ---
    def test_hexdump_bracket_pattern(self):
        """hexdumpコマンドと[e]パターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('hexdump -C .[e]nv | head -5'))
    
    def test_xxd_bracket_pattern(self):
        """xxdコマンドによるhex変換をブロック"""
        self.assertTrue(contains_dangerous_patterns('xxd -l 100 .[e]nv 2>/dev/null | xxd -r'))
    
    def test_od_bracket_pattern(self):
        """odコマンドによる8進ダンプをブロック"""
        self.assertTrue(contains_dangerous_patterns('od -c .[e]nv'))
    
    def test_dd_bracket_pattern(self):
        """ddコマンドによる直接読み込みをブロック"""
        self.assertTrue(contains_dangerous_patterns('dd if=.[e]nv bs=1024 count=1 2>/dev/null'))
    
    def test_strings_bracket_pattern(self):
        """stringsコマンドによるテキスト抽出をブロック"""
        self.assertTrue(contains_dangerous_patterns('strings .[e]nv'))
    
    # --- アーカイブ・エンコード系 ---
    def test_tar_pipe_pattern(self):
        """tarパイプによる間接読み込みをブロック"""
        self.assertTrue(contains_dangerous_patterns('tar -cf - .[e]nv 2>/dev/null | tar -xOf -'))
    
    def test_base64_redirect_pattern(self):
        """base64とリダイレクトの組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('base64 < .[e]nv | base64 -d'))
    
    # --- 危険な文字列の組み合わせ ---
    def test_dangerous_combination_dot_e_nv(self):
        """.eとnvの近接をブロック"""
        cmd = "this contains .e somewhere and nv nearby"
        self.assertTrue(contains_dangerous_patterns(cmd))
    
    def test_dangerous_combination_dot_env(self):
        """.とenvの近接をブロック"""
        cmd = "file. has env in it"
        self.assertTrue(contains_dangerous_patterns(cmd))
    
    def test_dangerous_combination_hex_encoded(self):
        """16進エンコードされた組み合わせをブロック"""
        cmd = "contains 2e and 656e76"
        self.assertTrue(contains_dangerous_patterns(cmd))
    
    # --- コマンドインジェクション ---
    def test_eval_with_env(self):
        """evalとenvの組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('eval "cat $ENV_FILE"'))
    
    def test_exec_with_dot(self):
        """execと.の組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('exec cat .file'))
    
    def test_subprocess_with_env(self):
        """subprocessとenvの組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('python -c "import subprocess; subprocess.run([\\"cat\\", \\"env\\"])"'))
    
    # --- パイプライン ---
    def test_complex_pipeline_ls_grep_cat(self):
        """複雑なパイプラインをブロック"""
        self.assertTrue(contains_dangerous_patterns('ls -a | grep "^\\." | xargs cat'))
    
    def test_pipeline_with_multiple_pipes(self):
        """3つ以上のパイプとcatの組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('ls | sort | uniq | cat'))
    
    def test_indirect_listing_awk_xargs(self):
        """間接的なファイルリスティング - AWKとxargs catをブロック"""
        cmd = '''ls -la | awk '/^-.*\\..*v$/ {print $9}' | head -1 | xargs cat'''
        self.assertTrue(contains_dangerous_patterns(cmd))
    
    def test_base64_decode_xargs_cat(self):
        """Base64デコードとxargs catの組み合わせをブロック"""
        cmd = 'echo LmVudg== | base64 -d | xargs cat'
        self.assertTrue(contains_dangerous_patterns(cmd))
    
    def test_reverse_string_xargs_cat(self):
        """文字列反転とxargs catの組み合わせをブロック"""
        cmd = 'echo "vne." | rev | xargs cat'
        self.assertTrue(contains_dangerous_patterns(cmd))
    
    # --- グロブパターン ---
    def test_glob_dot_question_star(self):
        """.?*パターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('for f in .?*; do echo $f; done'))
    
    def test_for_loop_with_dot(self):
        """forループと.の組み合わせをブロック"""
        self.assertTrue(contains_dangerous_patterns('for i in .*; do cat $i; done'))
    
    def test_for_loop_hidden_files(self):
        """forループで隠しファイルを列挙するパターンをブロック"""
        cmd = 'for i in .??*; do echo "$i:"; head -1 "$i" 2>/dev/null; done'
        self.assertTrue(contains_dangerous_patterns(cmd))
    
    def test_while_read_exact_match(self):
        """whileループで.envを直接比較するパターンをブロック"""
        self.assertTrue(contains_dangerous_patterns('ls -a | while read f; do if [ "$f" = ".env" ]; then cat "$f"; fi; done'))
    
    # --- エッジケース ---
    def test_empty_string(self):
        """空文字列は安全"""
        self.assertFalse(contains_dangerous_patterns(""))
    
    def test_very_long_command(self):
        """非常に長いコマンドでも検出"""
        long_prefix = "a" * 1000
        self.assertTrue(contains_dangerous_patterns(f"{long_prefix} cat .env"))
    
    def test_special_characters(self):
        """特殊文字を含むコマンド"""
        self.assertTrue(contains_dangerous_patterns("cat .env\n\r\t"))
    
    # ========================================
    # ネガティブテスト（許可されるべきパターン）
    # ========================================
    
    def test_normal_cat_command(self):
        """通常のcatコマンドは許可"""
        self.assertFalse(contains_dangerous_patterns("cat README.md"))
    
    def test_env_without_dot(self):
        """ドットなしのenvは許可"""
        self.assertFalse(contains_dangerous_patterns("printenv"))
        self.assertFalse(contains_dangerous_patterns("environment"))
    
    def test_dot_without_env(self):
        """envなしのドットは許可（ただし危険なコマンドとの組み合わせを除く）"""
        self.assertFalse(contains_dangerous_patterns("echo hello.world"))
    
    def test_safe_python_script(self):
        """安全なPythonスクリプトは許可"""
        self.assertFalse(contains_dangerous_patterns("python script.py"))
    
    def test_safe_file_operations(self):
        """安全なファイル操作は許可"""
        self.assertFalse(contains_dangerous_patterns("cp file1.txt file2.txt"))
        self.assertFalse(contains_dangerous_patterns("mv old.txt new.txt"))
    
    # ========================================
    # すり抜けテスト（本来ブロックしたいが現在は通過するパターン）
    # ========================================
    
    def test_bypass_python_os_listdir(self):
        """Python os.listdirを使ったパターン（現在すり抜け可能）"""
        cmd = 'python3 -c "import os; files=[f for f in os.listdir(\\".\\") if f.startswith(\\".\\") and f.endswith(\\"v\\")]; [print(f\\"{f}:\\\\n{open(f).read()}\\") for f in files]"'
        self.assertFalse(contains_dangerous_patterns(cmd), 
                        "このパターンは現在すり抜け可能（将来的にブロック予定）")
    
    def test_bypass_nodejs_readdir(self):
        """Node.js fs.readdirSyncを使ったパターン（現在すり抜け可能）"""
        cmd = '''node -e "const fs=require('fs'); fs.readdirSync('.').filter(f=>f.startsWith('.')&&f.endsWith('v')).forEach(f=>console.log(f+':\\n'+fs.readFileSync(f,'utf8')))"'''
        self.assertFalse(contains_dangerous_patterns(cmd),
                        "このパターンは現在すり抜け可能（将来的にブロック予定）")
    


if __name__ == '__main__':
    unittest.main(verbosity=2)