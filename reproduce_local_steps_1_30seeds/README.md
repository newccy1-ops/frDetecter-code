# local_steps = 1：30-seed 可复现子单元

本目录只对应此前结果图中的一个实验条件：`local_steps = 1`。它不运行
`2`、`5`、`10` 或 `full_epoch` 条件，也不修改任何训练、攻击、检测或阈值设置。

## 固定协议

- MNIST；Logistic Regression；50 clients（25 honest、25 low-resource attackers）
- IID partition；batch size 64；SGD；learning rate 0.10
- honest local steps 1；attack 从 paper round 5 开始
- reference round 6；validation round 8；probe 从保存的 `theta_(r+1)` 出发且只观察
- threshold 0.1（`DEMO_ASSUMPTION`）
- 30 个 seed：`20260915 + run_id`，`run_id = 0,...,29`

## 运行

在本目录中运行：

```powershell
python .\run_reproduction.py
```

默认复用项目根目录的 `..\data` MNIST 缓存。若该缓存不存在，MNIST loader 会下载数据。
可通过 `--data-root <path>` 指定数据目录；`--workers <n>` 只改变并行度，不改变算法。

输出写入 `results\reproduced\`：

- `per_run.csv`：30 个 seed 的逐 run 指标。
- `summary.json`：750 honest 与 750 attacker 判定的 pooled 统计。

## 已验证参考结果

`results\reference\` 保存从原始 `local_steps` sweep 中筛出的同一条件结果。
其 pooled confusion matrix 为 `TP=750, FP=1, TN=749, FN=0`，因此：

- DSR = 100%
- FPR = 0.133333...%
- F1 = 99.933377...%
- honest cosine mean = 0.4456918804
- attacker cosine mean = -0.0002673677（约 0）

`fedavg_mnist_demo.py` 和 `torch_runtime_compat.py` 是运行所需的核心实现与 Windows
PyTorch runtime 兼容层的本地副本。
