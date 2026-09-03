# Mailday.org

秘密鍵をブラウザから出さない、Cloudflare Workers上の一時メールサービスです。

## Architecture

- Workers: Web/API、challenge認証、Email Routing ingress
- D1: Inbox公開鍵、暗号文の索引、期限付きchallenge/session
- R2: ブラウザの公開鍵向けに暗号化済みのraw MIME
- Browser/Web Worker crypto: P-256 ECDSA認証、X25519 + XChaCha20-Poly1305
- Strong mode: X-Wing（ML-KEM-768 + X25519）耐量子ハイブリッドKEM
- Recovery protection: Argon2id（64MiB）+ XChaCha20-Poly1305
- PostalMime + DOMPurify: 端末内MIME解析と安全なHTML表示

標準・強力モードでは、R2へ保存される前に受信したraw MIME全体をWorkerのメモリ上で暗号化します。秘密鍵と平文メールをサーバー側へ永続化しません。「暗号化なし」を明示的に選択したInboxは例外です。過去に作成したP-256/P-384 Inboxの復号互換性も維持しています。

## Local development

```sh
npm install
npm run build
npm run db:migrate:local
npm run dev
```

開発Worker起動後、`npm run test:integration`で全暗号モードの受信・復号・MIME解析を検証できます。

ローカルでEmail handlerをテストする場合は、Wranglerの`/cdn-cgi/handler/email`開発エンドポイントを使用します。

## Deployment

1. `wrangler d1 create mailday-db`でD1を作り、返されたIDを`wrangler.jsonc`へ設定します。
2. `wrangler r2 bucket create mailday-encrypted-mail`でR2を作ります。
3. `npm run db:migrate:remote`でmigrationを適用します。
4. `npm run deploy`を実行します。
5. Cloudflare Email Routingで対象ドメインのcatch-allをこのWorkerへ接続します。

Workers Logs/Observabilityは`wrangler.jsonc`で無効化しています。Cloudflare基盤自体が処理するネットワーク情報までゼロになるという意味ではありません。
