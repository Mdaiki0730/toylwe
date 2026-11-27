# CTF：足りないコイン

Alice は toy を 80 ビット版に改造し、フラグを暗号化して公開した。秘密鍵 S はどこにも出ていない。

**公開鍵と暗号文だけから、フラグを復号せよ。**

- 配布ファイル：[`output.json`](output.json)（公開鍵と暗号文1つ）
- 問題コード：[`chall.go`](chall.go)

---

## 暗号方式

toy（[README](../README.md) 0章）との違いは、1回の暗号化で 80 ビット（10 バイト）を運ぶことだけ。秘密鍵 S を N×80 の行列にし、V を 80 個の数にする。

**パラメータ**：Q = 3329、N = 48、M = 40、L = 80、誤差は −2〜+2

**鍵生成**（Alice）

$$
S \leftarrow \mathbb{Z}_Q^{N\times L},\quad A \leftarrow \mathbb{Z}_Q^{M\times N},\quad E \leftarrow \{-2,\dots,2\}^{M\times L},\quad B = AS + E \bmod Q
$$

**暗号化**（Bob、80 ビットのメッセージ $`\mu \in \{0,1\}^{L}`$）

$$
r \leftarrow \{0,1\}^{M},\quad U = A^{\top} r \bmod Q,\quad V = B^{\top} r + \mu \left\lfloor \tfrac{Q}{2} \right\rfloor \bmod Q
$$

**復号**（Alice）：各 $`k`$ について $`w_k = V_k - \langle U, S_{\cdot k} \rangle`$ が Q/2 の近くならビット $`k`$ は 1。

**フラグの載せ方**：フラグ（10 バイト以下、足りない分は `0x00` で埋める）を先頭バイトの最上位ビットから順に並べ、$`k`$ 番目のビットを $`V_k`$ に載せる。暗号化は1回だけ。

---

## output.json の形

```json
{
  "public_key": { "A": [[...N 個...], ...M 行...], "B": [[...L 個...], ...M 行...] },
  "ciphertext": { "U": [...N 個...], "V": [...L 個...] }
}
```

---

## ヒント

<details>
<summary>ヒント 1</summary>

S を求める必要はない。B = AS + E は式が M = 40 本、未知数が 48×80 個。式が足りず、S は求まらない。

</details>

<details>
<summary>ヒント 2</summary>

狙うのは Bob のコイン r である。r がわかれば、$`V - B^{\top} r`$ は誤差なしでちょうど $`\mu \lfloor Q/2 \rfloor`$ になる。

</details>

<details>
<summary>ヒント 3</summary>

$`U = A^{\top} r`$ は、式が N = 48 本、未知数が M = 40 個の連立方程式である。

</details>

---

## 実行方法

リポジトリのルートで実行する。

```sh
go run ./ctf/solution ctf/output.json                                    # solve.go の Attack を実装して実行。フラグが表示される
go run ./ctf/gen -flag 'xxx' -sk ctf/gen/secret.json > ctf/output.json   # 問題ファイルと秘密鍵の再生成
go run ./ctf/decrypt ctf/output.json ctf/gen/secret.json                 # 秘密鍵での正規の復号（出題者の確認用）
```
