# JWTAPI
## Make and Verify JWT Server.

main.go と同じ階層に JWT の署名に使う秘密鍵(Private.key)とそれに対応する公開鍵(Public.key)を置いてください。

```
go run main.go
```
`GET localhost:8080/get` で JWT の取得が行なえます。
`Header['Authorization']` に JWT をセットして `GET localhost:8080/verify` をすると検証が行われます。
