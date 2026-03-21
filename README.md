# code_audit

## 项目简介

code_audit 是一个基于 Joern + LLM 的半自动漏洞审计流水线，目标是把“源码导入、候选点发现、上下文补全、漏洞判断、结果落盘”串成可重复执行的流程。

当前核心能力：

1. 读取 YAML 配置，加载审计目标与规则开关。
2. 通过 Joern query-sync 接口导入代码并执行图查询。
3. 生成候选审计点（当前支持 CWE-78、CWE-259）。
4. 对候选点做多轮 LLM 审计与上下文追问。
5. 输出最终漏洞结果与 overall token 统计。

## 运行前提

1. Python 3.10+
2. 已安装并可执行 Joern
3. 可用的 LLM API Key（从配置中的 llm.api_key_env 对应环境变量读取）

## Python 依赖

推荐在虚拟环境中安装：

```bash
cd code_audit
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

如果你使用 conda：

```bash
conda activate code-audit
cd code_audit
pip install -r requirements.txt
```

## 一次完整运行

下面是推荐顺序。重点：运行两个脚本前，必须先启动 Joern server。

### 1. 后台启动 Joern server

在任意终端执行：

```bash
nohup joern --server > logs/joern_server.log 2>&1 &
echo $!
```

可选检查（确认 query-sync 可访问）：

```bash
curl -X POST http://127.0.0.1:8080/query-sync \
  -H "Content-Type: application/json" \
  -d '{"query":"cpg.method.name.l.take(3)"}'
```

### 2. 运行候选点构建脚本

```bash
cd code_audit
python -m scripts.build_candidates --config configs/config.yaml
```

该步骤会生成审计单元 JSON（默认在 outputs/context 下）。

### 3. 运行 LLM 审计脚本

```bash
cd code_audit
python -m scripts.run_audit --config configs/config.yaml
```

该步骤会读取上一步审计单元，并输出最终结果 JSON（默认在 outputs/results 下）。

### 4. 生成可阅读 Markdown 报告

推荐直接运行脚本文件（兼容性更好）：

```bash
cd code_audit
python scripts/render_results_md.py \
  --config configs/config.yaml \
  --input outputs/results/audit_results.json \
  --output outputs/results/audit_results.md \
  --context-lines 3
```

也可以使用模块方式运行：

```bash
cd code_audit
python -m scripts.render_results_md \
  --config configs/config.yaml \
  --input outputs/results/audit_results.json \
  --output outputs/results/audit_results.md \
  --context-lines 3
```

如果某些 file_path 在本地源码中无法定位，可开启 Joern 回退查询：

```bash
python scripts/render_results_md.py --joern-fallback
```

常用参数：

1. --context-lines: 每个 bug line 前后展示的源码行数，默认 3。
2. --input: 输入结果 JSON 路径，默认 outputs/results/audit_results.json。
3. --output: 输出 Markdown 路径，默认 outputs/results/audit_results.md。
4. --joern-fallback: 本地找不到源码时，尝试通过 Joern 查询函数源码作为补充。

输出内容会保留原结果字段，并在每个 bug line 下附带上下文源码片段。

### 5. 对已有结果做去重（可选）

如果你已经有 `outputs/results/audit_results.json`，可以单独执行去重脚本。  
去重键为：`file_path + function_start_line + function_end_line + bug_lines`（按升序去重后比较）。  
其中 `file_path` 会做路径归一化，`CWE259_Hard_Coded_Password/xxx.c` 与 `xxx.c`（当文件名以目录名开头）会被视为同一路径。

```bash
cd code_audit
python scripts/dedup_audit_results.py --dry-run
python scripts/dedup_audit_results.py
```

可选输出到新文件：

```bash
python scripts/dedup_audit_results.py \
  --input outputs/results/audit_results.json \
  --output outputs/results/audit_results_deduped.json
```

## 关键文件

1. configs/config.yaml: 主配置文件
2. scripts/build_candidates.py: 候选点与审计单元构建入口
3. scripts/run_audit.py: LLM 审计入口
4. scripts/render_results_md.py: 将结果 JSON 渲染为可读 Markdown
5. outputs/context/: 中间上下文与审计单元输出目录
6. outputs/results/: 最终审计结果输出目录

## 输出说明

最终结果文件默认为 outputs/results/audit_results.json。

主要结构：

1. task_info: 任务元数据与 overall token 统计
2. results: 仅保留命中漏洞的条目（yes）

results 中常见字段：

1. file_path
2. function_start_line
3. function_end_line
4. bug_lines
5. reason
6. token_usage

## 常见问题

1. 连接 Joern 失败

通常是 Joern server 未启动，或 configs/config.yaml 中 joern.server_url 与实际地址不一致。

2. 运行 run_audit 报 API Key 缺失

请检查 llm.api_key_env 指向的环境变量是否已导出。

3. 没有生成结果

先确认 build_candidates 是否成功生成审计单元，再检查规则开关与 audit.target 是否包含有效源码路径。
