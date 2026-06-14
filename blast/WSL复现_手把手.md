# 在 WSL 里手把手复现密钥实验(纯小白版)

> 把自己当成第一次开终端的人。每一步只做一件事:照抄方框里的命令,回车,
> 然后对照"你会看到"。一样 = 对了。不一样 = 抓到东西了,截图发出来。

---

## 第 0 步:打开 WSL

- 按键盘 `Win` 键,输入 `Ubuntu`,回车。(或者打开"Windows 终端",点上面下拉箭头选 Ubuntu。)
- 弹出一个黑/紫色的窗口,光标在闪。这就是 WSL,可以了。

---

## 第 1 步:走到实验文件夹

复制这一行,粘进去(终端里粘贴一般是 **右键** 或 `Ctrl+Shift+V`),回车:

```bash
cd /mnt/c/dev/sp/dist/blast
```

**你会看到:** 什么都没发生,光标到了下一行。✅ 这就对了(没报错就是成功)。

---

## 第 2 步:看看东西都在不在

```bash
ls
```

**你会看到**(顺序无所谓):

```
HOW_TO_READ_HN.md  README.md  bait  blast_harness.py  blast_phase2.py  runs
```

只要看到 `runs` 和 `blast_phase2.py` 就行。

---

## 第 3 步:不跑任何东西,直接看结果(只看 4 行)

```bash
grep -E '"decision"|"bypassed_gate"|"http_status"|"github_request_id"' runs/blast-p2-github/summary.json
```

**你会看到:**

```
  "bypassed_gate": true,
    "decision": "KILL",
    "github_request_id": "EB5E:3D7F3D:119EA0B:13C6A8A:6A2E531F",
    "http_status": 401,
```

怎么读这 4 行(大白话):
- `decision: KILL` —— 我们自己的门说"这事不许干"。
- `bypassed_gate: true` —— 我们**故意绕过门**,硬把它干了。
- `http_status: 401` —— GitHub 真服务器的回答:**钥匙不对,拒绝**。
- `github_request_id: ...` —— GitHub 给这次请求发的**真单号**,证明请求**真的到了它服务器**。

---

## 第 4 步:自己拿一把假钥匙去敲 GitHub(亲手复现那个 401)

这一步不碰我们的文件,你自己造一把**假**钥匙去打真 GitHub。复制整段(它是一条命令,换行无所谓),回车:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -H "Authorization: Bearer ghp_WO_SHI_BAI_CHI_FAKE_TOKEN_123456" \
  -H "User-Agent: blast-probe" \
  https://api.github.com/user
```

**你会看到:**

```
HTTP 401
```

看到 `HTTP 401` 就成了 —— 你刚刚用一把瞎编的钥匙,真的连上了 GitHub,被它当面拒了。

想看它原话和真单号?再来一条:

```bash
curl -s -D - \
  -H "Authorization: Bearer ghp_WO_SHI_BAI_CHI_FAKE_TOKEN_123456" \
  -H "User-Agent: blast-probe" \
  https://api.github.com/user | grep -iE "HTTP/|x-github-request-id|message"
```

**你会看到**(大概长这样):

```
HTTP/2 401
x-github-request-id: 813F:0C22:27BDD6C:2D18EBE:6A2E55A2
  "message": "Bad credentials",
```

> ⚠️ 注意:`x-github-request-id` 后面那串**每次都不一样**,这是正常的 —— 它是 GitHub
> 每次现发的单号。重点不是"和我们的一样",而是"它**存在**"。假钥匙伪造不出这个单号。

---

## 第 5 步:验证我们给的文件没被人动过手脚(跑哈希)

先进到那个结果文件夹:

```bash
cd runs/blast-p2-github
```

再跑(把每个文件重新算一遍指纹,和我们当初记下的对):

```bash
sha256sum -c SHA256SUMS.txt
```

**你会看到:**

```
autopsy.json: OK
autopsy.md: OK
seed.json: OK
summary.json: OK
```

全是 `OK` = 文件一个字节都没被改过。如果哪行是 `FAILED`,说明那个文件被动过。

> 做完想回到上一层:`cd ..`

---

## 完事了

你刚刚做了三件事:
1. **读懂了结果**(第 3 步那 4 行)。
2. **自己亲手复现了那个真 401**(第 4 步,用假钥匙打真 GitHub)。
3. **验证了我们的文件没造假**(第 5 步,全 OK)。

这就是全部。不需要懂代码,不需要装任何东西,WSL 自带的 `curl` 和 `sha256sum` 就够了。
