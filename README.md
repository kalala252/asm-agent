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

分析時には、AIが参照する資産情報や根拠、脆弱性候補をOpenAI APIに送信します。OpenAI APIキーは認証に使い、Shodan APIキーとローカルのファイルパスは分析内容に含めません。

## 出力ファイル

収集結果はJSONとMarkdownで保存されます。

```text
reports/example.com.json
reports/example.com.md
```

AI分析の結果は別のファイルに保存します。

```text
reports/example.com.analysis.json
reports/example.com.analysis.md
```

## 開発

```bash
uv run ruff check .
uv run mypy src
uv run pytest
```

## ライセンス

[MIT License](LICENSE)
