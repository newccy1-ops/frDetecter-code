# frDetecter: Stage 1 + Java/jsnark/libsnark Stage 2

源码发布：不包含实验结果、MNIST、模型、证明、密钥、witness、node_modules、
下载的第三方工具或构建产物。运行时在本机生成这些文件，Git 默认忽略。

默认 Stage 2 已切换到 **Java/jsnark + libsnark**；原有 Circom/snarkjs 版本保留
在 `stage2_zkp_single_client/`，不是新后端的证明生成/验证工具。

## 1. 安装

已使用环境：Windows，Python 3.12.4，PyTorch 2.12.1+cpu，torchvision 0.27.1+cpu，
NumPy 1.26.4，Node.js 24.15.0，npm 11.12.1，JDK 17。需要 Git 在 PATH 中。
其他硬件/平台/库版本不保证浮点结果逐位相同。Windows 需 Microsoft VC++ 运行库。

```powershell
git clone https://github.com/newccy1-ops/frDetecter-code.git
cd frDetecter-code
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm --prefix stage2_zkp_single_client ci --no-audit --no-fund
python stage2_jsnark_libsnark/bootstrap_sources.py
powershell -NoProfile -ExecutionPolicy Bypass -File stage2_jsnark_libsnark/bootstrap_msys2.ps1 -InstallPackages
```

Node 依赖沿用锁定的包，仅复用 Poseidon 编码/常量；新后端不调用 Circom/snarkjs
生成或验证证明，也不下载旧后端的公开 CRS。首次需要网络下载 MNIST 和固定工具源码。
不会关闭 TLS 验证。新版原生后端每次运行会自动检查依赖版本并构建。

Linux 需自行安装 GCC、CMake、GMP/OpenSSL 开发库、JDK、Git、Node 和 Python依赖，
省略 MSYS2 命令；Windows 是已测试平台。

## 2. Stage 1

30 个 seed，`seed = 20260915 + run_id`，run_id=0..29：

```powershell
python run_demo.py stage1 --workers 4
```

生成 `reproduce_local_steps_1_30seeds/results/validation_round_7/` 下的统计、
逐客户端结果和审计记录。可指定 `--data-root "D:\MNIST-cache"`；
没有缓存时自动下载。并行度只改变资源占用，不改变实验规则。

| 设置 | 冻结内容 |
| --- | --- |
| 数据集/模型 | MNIST，训练60000/测试10000；Linear(784,10)，7850参数 |
| 客户端 | 50；IID无放回均分，每客户端1200样本 |
| 身份 | 每个seed固定选择25个low-resource attackers，另25个honest |
| 训练/聚合 | 每轮50人全部参与；按本地样本数加权FedAvg，不剔除attacker |
| 本地训练 | local_steps=1，batch64，SGD，lr0.10 |
| 攻击 | 第5轮起跳过训练；归一化高斯随机方向；范数为第4轮真实更新范数中位数 |
| 轮次 | 总8轮，reference=6，validation=7 |
| Probe | 从保存的第6轮聚合模型出发，在第7轮常规训练前执行 |
| Stage 1 | cosine < 0.1 标记suspicious；严格小于 |

上述 IID、全参与、本地超参数、seed、随机攻击分布/尺度、总轮数、数值实现和阈值
均含 DEMO_ASSUMPTION，不伪称来自原稿。不以论文 Table V 为校准目标。
`observation-only` 仅表示 probe 不进入 FedAvg、不改变主训练轨迹，**不表示没有
Stage 2**。Stage-1 模拟中旧 functional-helper 的结论不计为真实 ZKP 结果。

## 3. Stage 2 与 Stage 1 串联

独立运行一个已识别的诚实误报案例；先执行其 Stage 1 捕获实际输入，再生成真实证明：

```powershell
python run_demo.py stage2 --seed 20260923 --client-id 30
```

另外两个案例为 `20260925 / client1` 和 `20260938 / client26`。
顺序运行三个案例，或从30-seed Stage 1开始一键串联：

```powershell
python run_demo.py stage2 --all-cases
python run_demo.py all --workers 4
```

`all` 是30-seed Stage 1 + 三个选定honest FP的 Stage 2，**不是全体suspicious**。
Stage 2 检查实际客户端是否suspicious；有当前Stage-1 summary时，还必须精确匹配
cosine和原始上传update的哈希。没有summary也可自行运行，不依赖仓库中的旧结果。

如需先保存一个 Stage 1 输入，之后 Stage 2 不再训练，使用：

```powershell
python run_demo.py stage1-case --seed 20260923 --client-id 30
# 将下面路径替换为上一条打印的 STAGE1_CASE_DIR
python run_demo.py stage2 --seed 20260923 --client-id 30 --case-dir "<STAGE1_CASE_DIR>"
```

`stage1-case` 实际运行该seed的50客户端完整协议，只捕获指定honest suspicious客户端。
它不生成ZKP。后续 `--case-dir` 只导入其模型、真实batch、原始upload和元数据，
校验字节/tensor哈希，重新生成密钥、挑战、witness和proof，不复用旧验证结论。
不支持通过调整阈值、搜索seed、修改upload或放宽容差让案例通过。

流程：batch承诺登记 → 服务器KeyGen/挑战 → 客户端Compute/Prove → 服务器Verify
→ 单次验收与负例审计。Verify仅使用服务器VK和预期公开输入，不读私有batch/witness
或ground-truth角色。完整前向/反向训练关系绑定原upload全部7850个坐标。

每次输出到 `stage2_jsnark_libsnark/runs/jsnark_seed..._client..._<uuid>/`。
`report.json: PASS` 须包括真实native证明、Verify、负例和哈希检查全部通过；
构建成功、functional transcript检查或旧证明不能冒充成功。该目录含敏感batch、
witness和大体积密钥，**不可上传**。

三个案例应顺序运行，避免内存叠加；建议至少16GB RAM、30GB空闲磁盘。
每例含独立KeyGen、Compute/Prove/Verify及负例检查，耗时依硬件变化。

## 4. 一致性与边界

- 同环境固定ML seed应得到相同Stage-1输入/数值和ZKP验收结论；证明、salt、nonce、
  keys使用新鲜密码学随机数，其文件内容、运行ID、耗时和文件大小不要求完全一致。
- Java/jsnark/libsnark工具链与论文描述对齐，不代表恢复了原作者源码/全部参数。
  Groth16/ALT_BN128、依赖版本、固定点Q=2^30、近似与误差界、承诺编码和本地trusted
  setup仍为工程选择；没有独立审计的多方setup。
- 电路证明固定点近似训练关系，不是PyTorch/IEEE-754逐位证明。数值约束与已验证版本
  保持不变；单个已执行batch使随机batch选择退化为单候选。
- 承诺/nonce不证明远端数据来源、历史执行时间或从未复用计算/witness。
- 三个honest误报恢复案例不等于750次attacker或全部suspicious已通过Stage 2，
  不构成完整两阶段指标、完整消融或历史论文表格执行证据。

更多说明见 [新Stage-2说明](stage2_jsnark_libsnark/README.md)。
保留旧后端可运行入口：`python stage2_zkp_single_client/run_paper_aligned.py --seed 20260923 --client-id 30`；
旧后端需要额外工具/CRS，见其说明。

不训练/不生成证明的检查：

```powershell
python -m unittest discover -s tests -v
python stage2_jsnark_libsnark/test_source_contract.py
```

只读核对新后端完成结果：`python stage2_jsnark_libsnark/verify_run.py "<NEW_RUN_DIRECTORY>"`。
