# blast — 试爆基地

**假密钥 + 真实 I/O 的隔离试爆区。不是 VM,是本地一块硬边界飞地。**

## 边界契约(硬)
- 一切写盘只落在 `dist/blast/` 内。冻结源码(`ot_gate.py` / `autopsy_report.py` / `scene_seed.py` …)只读导入,不改。
- phase 1 网络只打 `127.0.0.1` loopback,不出网。
- 每跑一次双重守边界:① harness 内置 `scene_seed` 前后快照 diff(`boundary_breached`);② 外部 `git status` 验证改动不溢出 `dist/blast/`。

## 形态
- **假密钥 = 蜜罐令牌**:`sk-ant-...` 结构骗得过解析器,不对应任何真账户,泄了是废纸。
- **真实 I/O**:真读文件、真开 socket、真往返字节、真落审计产物。
- **门控**:`ot_gate` 判决是 dry-run;真 I/O 是否落地由判决决定 —— ALLOW 才真跑,KILL/HOLD 真挡。

## 用法
```
python.exe dist\blast\blast_harness.py --seed-id blast-p1
```
产物落 `runs/<seed-id>/`:`seed.json`、`summary.json`、`autopsy_*.{json,md}`、`SHA256SUMS.txt`。

> 注:本机 360 会重置本地 HTTP 连接,假端点改用裸 TCP(仍是真 socket 真往返)。
