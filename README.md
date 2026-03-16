# code_audit

## 当前实现内容

本项目当前已实现一条可运行的基础链路：

1. 从 YAML 配置读取审计输入与规则开关。
2. 通过 Joern `query-sync` 执行 `importCode("...")` 导入项目。
3. 执行候选点查询（当前支持 `CWE-78`、`CWE-259` 基础查询）。
4. 解析 Joern 返回结果并写入结构化 JSON。
5. 输出中的 `candidates[].file_path` 会尽量转换为相对 `input_targets` 的路径形式。

核心入口：

- `scripts/build_candidates.py`

核心模块：

- `src/config_loader.py`：配置读取与校验
- `src/joern_client.py`：Joern HTTP 客户端（`query-sync`）
- `src/project_builder.py`：按输入模式组织并导入目标
- `src/candidate_query_builder.py`：构造候选点查询语句
- `src/candidate_extractor.py`：执行查询与结果解析

## 目录与包结构

当前已改为包导入方式：

- `src/__init__.py`
- `scripts/__init__.py`

建议统一使用模块运行方式：

- `python -m scripts.build_candidates`

## 配置说明

默认配置文件：

- `configs/config.yaml`

关键字段：

- `joern.server_url`：Joern `query-sync` 地址
- `audit.target`：输入路径列表（可混合文件和目录）
- `rules.enable_cwe78`：是否启用 CWE-78 查询
- `rules.enable_cwe259`：是否启用 CWE-259 查询
- `output.candidate_json`：候选点输出 JSON 路径

`audit.target` 使用示例：

```yaml
audit:
	project_name: "code_audit_candidates"
	target:
		- "../juliet-test-suite-c/testcases/CWE78_OS_Command_Injection/s01"
		- "../juliet-test-suite-c/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_execl_61a.c"
```

说明：

- 目录会按递归方式导入（由 Joern `importCode` 处理）。
- 文件会按文件路径导入。
- 可以同时给目录和文件。

## 运行方式

默认使用现有 conda 环境：`code-audit`。

### 1) 启动 Joern server

确保本地 Joern server 已启动，且 `query-sync` 可访问。

示例检查：

```bash
curl -X POST http://127.0.0.1:8080/query-sync \
	-H "Content-Type: application/json" \
	-d '{"query":"cpg.method.name.l.take(3)"}'
```

### 2) 进入项目目录

```bash
conda activate code-audit
cd /home/jerry/code-audit/code_audit
```

### 3) 运行候选点构建

```bash
python -m scripts.build_candidates
```

可选：指定配置文件

```bash
python -m scripts.build_candidates --config configs/config.yaml
```

### 4) 依赖安装（如需）

如需补装 Python 依赖，请在同一个 conda 环境中执行：

```bash
conda activate code-audit
pip install requests pyyaml
```

## 输出结果

默认输出文件：

- `outputs/context/candidate_context.json`

JSON 顶层结构：

- `task_info`
- `input_targets`
- `rules`
- `candidates`

`candidates` 每项至少包含：

- `cwe`
- `rule_type`
- `function_name`
- `file_path`
- `line_number`
- `code`

## 当前默认测试用例

`configs/config.yaml` 默认 `audit.target` 包含 4 个 CWE-78 测试文件：

- `CWE78_OS_Command_Injection__char_connect_socket_execl_61a.c`
- `CWE78_OS_Command_Injection__char_connect_socket_execl_61b.c`
- `CWE78_OS_Command_Injection__char_connect_socket_execl_62a.cpp`
- `CWE78_OS_Command_Injection__char_connect_socket_execl_62b.cpp`

## 常见问题

1. Joern 服务未启动或 URL 不对

- 现象：构建阶段报连接失败。
- 处理：检查 `joern.server_url` 与 Joern server 状态。

2. 查询语法错误

- 现象：stdout/stderr 出现 `E008`、`Error:`、`Exception`。
- 处理：脚本会将其视为查询失败并中止，不会静默写空结果。

3. 编辑器提示导入错误

- 当前已切换为包结构导入，优先使用 `python -m scripts.build_candidates` 运行。