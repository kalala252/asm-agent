# asm-agent

`asm-agent`は、収集した公開情報を根拠付きで分析し、質問に応じて説明するAIエージェントです。

公開情報の収集は`scan`、AIエージェントによる分析は`analyze`で実行します。AIエージェントは収集済みレポートから必要な根拠をツールで参照し、確認できた事実と未確定事項を分けて説明します。

対象サイトへのアクセスやポートスキャンは行いません。

## できること

- 公開されているホスト名、IPアドレス、ポート、製品、CVE候補を調べます
- 情報源と観測日時を保存し、結果の根拠を追跡できるようにします
- 質問に応じて、AIエージェントが収集結果と根拠を読み分けて説明します
- `crt.name`、DNS、任意で有効にしたShodanを情報源として利用します

公開情報の収集だけでも利用できます。AIエージェントによる分析にはOpenAI APIキーが必要です。

## セットアップ

Python 3.12以上と[uv](https://docs.astral.sh/uv/)が必要です。

リポジトリを取得し、依存関係を準備します。

```bash
git clone https://github.com/kalala252/asm-agent.git
cd asm-agent
uv sync
```

ShodanとOpenAIを使う場合は、APIキーをOSの認証情報保管機能へ保存します。

```bash
uv run asm-agent credentials set-shodan
uv run asm-agent credentials set-openai
uv run asm-agent credentials status
```

環境変数も利用できます。環境変数が設定されている場合は、OSに保存した値より優先されます。

```bash
export SHODAN_API_KEY="..."
export OPENAI_API_KEY="..."
```

LinuxなどでOSの認証情報保管機能を利用できない場合は、環境変数を使用してください。

## 公開情報を収集する

`crt.name`とDNSから収集します。

```bash
uv run asm-agent scan \
  --domain example.com \
  --output-dir ./reports
```

Shodanも利用する場合は`--enable-shodan`を付けます。

```bash
uv run asm-agent scan \
  --domain example.com \
  --enable-shodan \
  --output-dir ./reports
```

Shodan検索は既定で1ページ、IPごとの詳細取得は最大100件です。変更する場合は`--max-api-pages`と`--max-shodan-host-lookups`を指定してください。

## AIエージェントで分析する

AIエージェントが収集済みのJSONレポートを読み、確認できた事実、根拠、未確定事項を整理します。既定モデルは`gpt-5.6-luna`です。

```bash
uv run asm-agent analyze \
  --report ./reports/example.com.json \
  --output-dir ./reports
```

質問を指定することもできます。

```bash
uv run asm-agent analyze \
  --report ./reports/example.com.json \
  --question "公開されているホスト名とCVE候補を根拠付きで説明して" \
  --output-dir ./reports
```

AI分析では、収集済みレポートからAIエージェントが参照した資産、根拠、脆弱性候補をOpenAI APIへ送信します。OpenAI APIキーはAPI認証にのみ使用し、Shodan APIキーとローカルのファイルパスは分析入力に含めません。

## 出力ファイル

収集結果は次の2ファイルへ保存されます。

```text
reports/example.com.json
reports/example.com.md
```

AI分析を実行すると、次のファイルが追加されます。

```text
reports/example.com.analysis.json
reports/example.com.analysis.md
```

ShodanのCVEは過去の観測に基づく候補であり、現在も脆弱であることを証明するものではありません。

## 開発

```bash
uv run ruff check .
uv run mypy src
uv run pytest
```

## ライセンス

[MIT License](LICENSE)
