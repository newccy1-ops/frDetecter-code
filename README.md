# frDetecter: reproducible Stage-1 + single-client ZKP demos

本仓库只保留源码、依赖锁及说明，**不包含实验结果、模型、MNIST、proof、密钥、
witness、编译输出或node_modules**。运行会重新生成所需数据和证据，不依赖作者
电脑中的目录、已有results或历史证明。

## 1. 环境

已实际使用：Windows、Python **3.12.4**、PyTorch **2.12.1+cpu**、torchvision
**0.27.1+cpu**、NumPy **1.26.4**、Node.js **24.15.0**、npm **11.12.1**。
建议使用相同版本复现；其他平台/版本不保证浮点结果逐位相同。
Windows需可用的Microsoft VC++运行库；所带兼容层只预加载系统DLL，不替换系统/Conda文件。

```powershell
git clone https://github.com/newccy1-ops/frDetecter-code.git
cd frDetecter-code
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm --prefix stage2_zkp_single_client ci --no-audit --no-fund
```

不要安装未锁定的最新版库来追求结果一致。Python版本不符时先准备Python3.12；
Node/npm也应在PATH中。首次MNIST下载、Circom下载和约2.4GB公开CRS下载需要网络。
公开工具/CRS按固定SHA-256/BLAKE2b校验，校验失败即停止，绝不关闭TLS校验。

## 2. Stage 1：30个seed重新训练并计算检测结果

```powershell
python run_demo.py stage1
```

并行度只影响资源占用，可用 `--workers 1`。也可用
`--data-root "D:\MNIST-cache"` 指定缓存；没有缓存时自动下载，样本内容不改变。
30个seed为`20260915 + run_id`，run_id=0..29。

| 冻结设置 | 数值/规则 |
| --- | --- |
| 数据/模型 | MNIST，训练60000/测试10000；Linear(784,10)，共7850参数 |
| 客户端 | 50，IID无放回均分，每人1200样本；25honest+25固定随机选中的attackers |
| 参与和聚合 | 每轮50人全部参与；按本地样本数加权FedAvg，不排除attacker |
| 本地训练 | 每次1个minibatch，batch64，SGD，lr0.10 |
| 攻击 | 第5轮开始跳过攻击者本地训练；高斯随机方向归一化；范数为第4轮真实更新范数中位数 |
| 总通信轮 | 8（DEMO_ASSUMPTION，不是论文明确总轮数） |
| Reference/validation | 6/7；probe从第6轮聚合模型出发，在第7轮常规训练之前执行 |
| Stage-1规则 | cosine < 0.1 标记suspicious；等于0.1不标记 |

客户端划分、local steps/batch/optimizer/lr、seed、全参与、攻击分布和尺度、
数值零范数保护及训练长度均为工程假设，不伪装成原稿参数。0.1也是原稿最小Demo
中的工程阈值；此发布不声称已重现论文数值表格。

`observation-only` **仅表示probe不参与FedAvg、不改变主训练轨迹**，不表示Stage 2
不生成/验证证明。共享Stage-1模拟内部保留旧functional-helper，其结论不作为
真实ZKP、Stage-2结果或完整两阶段指标。

输出在`reproduce_local_steps_1_30seeds/results/validation_round_7/`：
`summary.json`、`per_run.csv`、`client_level.csv`、`run_audits.json`，均为新生成且gitignored。
每轮全数据集准确率评估被省略以降低成本，不改变训练、cosine或检测。

相同已测环境下的预期核对值（仅作复现验收，不作为计算输入）：

- 750次honest、750次attacker判定；TP=750、FP=3、TN=747、FN=0。
- Pooled DSR=100%，FPR=0.4%，Precision=99.6015936%，F1=99.8003992%。
- Honest cosine mean约0.4446133960；attacker约0.0013150833。
- Pooled与逐run指标平均分别输出，不能混用。

## 3. Stage 2：真实ZKP，不是transcript检查

默认证明首个自然误报案例：

```powershell
python run_demo.py stage2
```

重新运行三个已识别的honest误报案例（顺序执行，避免内存叠加）：

```powershell
python run_demo.py stage2 --all-cases
```

也可以单独运行一个：

```powershell
python run_demo.py stage2 --seed 20260925 --client-id 1
python run_demo.py stage2 --seed 20260938 --client-id 26
```

先跑Stage 1再跑这三个案例的一键命令：

```powershell
python run_demo.py all
```

以上“all”是**本仓库已实现的三个honest恢复案例**，不是全体753次suspicious判定。

| Seed | Client | 预期Stage-1 cosine | 预期Stage-2结论 |
| --- | --- | --- | --- |
| 20260923 | 30 | -0.050070902207898574 | 真实证明接受，恢复benign |
| 20260925 | 1 | 0.027141515101994963 | 同上 |
| 20260938 | 26 | 0.09136296941406738 | 同上 |

每个案例重新执行原Stage 1来捕获其实际batch/模型/更新，不是导入旧结果伪造证据。
无须先生成30-run结果也可以运行Stage 2；如果本机已有同协议summary，则额外核对。
如果选定客户端不再是自然误报，停止，不搜索seed、不调threshold、不放宽容差。

流程：登记batch承诺 -> 服务器KeyGen -> 服务器新鲜挑战 -> 客户端Compute/Prove
-> 服务器Verify -> 负例检查。服务器以自己保存的模型、原上传更新、承诺、挑战和VK
验收；验证不读取ground-truth角色或`training_executed`。

每次独立输出：`stage2_zkp_single_client/runs/paper_v2_seed..._client..._<id>/`。
其中`report.json`、`public/proof.json`、`public/verification.json`、
`public/negative_tests.json`保存真实运行证据；`client_private/`不可公开上传。
所有阶段成功、真实验证通过、负例通过、文件哈希一致后才写`report.json: PASS`。

首次每个案例需独立编译/密钥准备，已测环境约一小时/案例，非秒级实验。
单案例密钥阶段可能占约8-9GiB内存，并产生数GB临时文件；三个案例请顺序执行，
预留充足磁盘（例如40GB），避免系统休眠。实际耗时随硬件/内存压力变化。

## 4. 一致性的边界

- 固定ML seed控制划分、初始化、batch shuffle、攻击者IDs和伪造更新。
- Proof、salt、nonce和setup贡献使用新鲜密码学随机数；**proof/key文件、承诺、
  运行目录、耗时和文件大小不要求逐字节一致**。应核对Stage-1数值和ZKP接受/拒绝结论。
- 电路证明固定点近似训练关系，绑定原上传更新的全部7850个坐标，并有固定容差；
  不是PyTorch/IEEE-754逐位证明，工程误差界限不是论文参数。
- 本地只有一个已执行batch，随机抽查候选集只有一个；没有多batch抽查覆盖率证据。
- 承诺不证明远端数据来源/所有权，nonce不证明历史执行时间或禁止witness复用。
- 使用Circom/snarkjs/Groth16，不是论文声称的Java/jsnark/libsnark后端复现。
- 三个honest恢复案例不等于全部suspicious经过Stage 2；750次attacker判定尚无
  本仓库实验的全量ZKP证据。不得声称完整两阶段指标、消融或历史论文表格已复现。

详细数值关系与安全假设见`stage2_zkp_single_client/paper_aligned/README.md`。
协议单元测试：`python -m unittest discover -s tests -v`（不下载MNIST、不生成证明）。
