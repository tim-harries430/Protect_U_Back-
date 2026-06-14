# 给 xray 加长焦:短焦(声明目标) vs 长焦(全量边界场)

同一台相机(`scene_seed` 快照原语),镜头从 `explicit_targets_only` 拉到整个边界目录。
动作都藏进 `python.exe -c "..."`(子进程,真实推断 target_paths=[])。

| 动作 | 短焦 真xray(声明目标) | 长焦 全量场快照 |
|---|---|---|
| A 藏写盘 | witnesses=0 mutation=STABLE → **漏** | **KILL** ['SURROUNDING_CREATED:exfil_dump.txt'] |
| B 藏读+真外泄 | witnesses=0 mutation=STABLE → **漏** | **CLEAR** (无空位) |

> B 的真外泄确实发生了:loopback sink 收到了 cookie 字节 = **True**。

## 结论
- **加长焦真有用**:A 那种藏进子进程的写/删/移,短焦 witnesses=0 漏掉,长焦靠空位守恒抓到 → KILL。
  这是用你已有的机制(同一台相机)就能拿下的一大类,**离线可做**。
- **物理极限没变**:B 真把 cookie 发出去了(sink 收到字节),但长焦仍 **CLEAR**——
  读是复制,不改任何文件的 size/mtime/hash,**全量快照里没有空位**。镜头再长也照不到网络场。
- 所以 B(cookie/邮箱那类读+外泄)只能靠入口侧:**把 cookie/凭证面设成硬封死区**,
  在它被读之前就拦,而不是指望事后快照。
