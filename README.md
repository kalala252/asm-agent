# asm-agent

ドメイン名を指定して、公開情報に記録されたホスト名やIPアドレス、サービスを調べるCLIツールです。収集結果は、情報源と観測日時を添えてJSONとMarkdownに保存します。

情報源にはcrt.nameとDNSを使います。Shodanを有効にすると、ポートや製品情報、CVE候補も取得できます。対象サイトへのアクセスやポートスキャンは行いません。

収集は`scan`、保存した結果のAI分析は`analyze`で実行します。収集だけならOpenAI APIキーは不要です。

## セットアップ

Python 3.12以上と[uv](https://docs.astral.sh/uv/)を用意して、リポジトリを取得します。

```bash
git clone https://github.com/kalala252/asm-agent.git
cd asm-agent
uv sync
```

ShodanやAI分析を使う場合は、使うサービスのAPIキーを登録してください。キーはOSの認証情報ストアに保存されます。

```bash
uv run asm-agent credentials set-shodan
uv run asm-agent credentials set-openai
uv run asm-agent credentials status
```

環境変数でも指定できます。両方に設定した場合は、環境変数の値を優先します。

```bash
export SHODAN_API_KEY="..."
export OPENAI_API_KEY="..."
```

OSの認証情報ストアを使えない環境では、環境変数を使ってください。

## 収集

ドメイン名と保存先を指定します。

```bash
uv run asm-agent scan \
  --domain example.com \
  --output-dir ./reports
```

Shodanの情報も取得するには、`--enable-shodan`を付けて実行してください。

```bash
uv run asm-agent scan \
  --domain example.com \
  --enable-shodan \
  --output-dir ./reports
```

Shodan検索は既定で1ページ、IPごとの詳細取得は100件までです。上限は`--max-api-pages`と`--max-shodan-host-lookups`で変更できます。

ShodanのCVEは、過去の観測から関連付けられた候補です。レポートに載っていても、現在そのサービスに脆弱性があるとは限りません。

## 履歴と差分

同じ保存先で`scan`を再実行すると、過去の結果との差分も保存します。初回は収集結果だけを出力します。

比較相手には、収集条件、ツールのバージョン、使った情報源が同じで、取得失敗や一部未取得のない過去の結果を優先します。その中で最も新しい結果を選び、該当するものがなければ今回より前の最新の結果を使います。

条件の違いや取得の失敗は、差分レポートの冒頭に表示します。JSONでは`comparable`と`comparison_issues`で確認できます。`comparable: true`でも、すべての資産を発見できたとは限りません。また、今回見つからなかった資産を閉鎖済みとは扱いません。

比較するファイルを自分で選ぶ場合は、`diff`を使ってください。

```bash
uv run asm-agent diff \
  --previous ./previous/example.com.json \
  --current ./reports/example.com.json \
  --output-dir ./comparison
```

## AI分析

保存したJSONレポートを指定すると、観測した内容と、公開情報だけでは判断できない点をAIがまとめます。OpenAI APIキーが必要です。分析には既定で`gpt-5.6-luna`を使います。

```bash
uv run asm-agent analyze \
  --report ./reports/example.com.json \
  --output-dir ./reports
```

知りたいことがある場合は、`--question`で質問を渡せます。

```bash
uv run asm-agent analyze \
  --report ./reports/example.com.json \
  --question "公開されているホスト名とCVE候補を根拠付きで説明して" \
  --output-dir ./reports
```

前回との差をAIに説明させるには、`--previous`で前回のJSONを渡してください。自動比較と同じ結果を使う場合は、`scan`の実行後に表示される`Previous JSON`のパスを指定します。

```bash
uv run asm-agent analyze \
  --report ./reports/example.com.json \
  --previous ./previous/example.com.json \
  --question "前回との違いと、比較する際の制約を説明して" \
  --output-dir ./reports
```

資産の説明と関連性の推測では、引用した根拠すべてにその対象が含まれるかを検証します。別の資産の根拠を引用した場合はAIに修正を求め、直らなければ分析を失敗とします。この検証で文章中のすべての主張の正しさを確認できるわけではありません。

分析時には、AIが参照する資産情報や根拠、脆弱性候補をOpenAI APIに送信します。OpenAI APIキーは認証に使い、Shodan APIキーとローカルのファイルパスは分析内容に含めません。

## 出力ファイル

収集結果はJSONとMarkdownで保存されます。

```text
reports/example.com.json
reports/example.com.md
```

収集の履歴は`reports/history/example.com/<実行日時>-<内容ハッシュ>/`に保存します。同じ日時でも内容が違えば別の履歴になり、同じ結果を保存し直しても重複は作りません。自動比較の`example.com.diff.json`と`example.com.diff.md`も、今回の履歴フォルダに入ります。

保存先は実行後の`History JSON`や`Diff JSON`で確認できます。既存の`example.com.json`は、履歴へ保存してから最新版に置き換えます。

AI分析の結果は別のファイルに保存します。

```text
reports/example.com.analysis.json
reports/example.com.analysis.md
```

### 履歴ファイルが壊れた場合

最新版JSONが正常なら、破損した履歴を退避して作り直します。履歴JSONが欠けている場合や内容が一致しない場合も同じ扱いです。退避先は`reports/history/example.com/.quarantine/`で、実行時の警告にもパスを表示します。

最新版JSON自体が壊れている場合は、上書きせずエラーで停止します。それ以外の読み取れない履歴は、警告を出して比較から除外します。退避したファイルは比較に使わず、履歴とともに自動削除もしません。

## 開発

```bash
uv run ruff check .
uv run mypy src
uv run pytest
```

## ライセンス

[MIT License](LICENSE)
