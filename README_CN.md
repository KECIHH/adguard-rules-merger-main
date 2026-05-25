# AdGuard 规则自动合并仓库

这个项目会通过 GitHub Actions 定时抓取多个 AdGuard / Adblock 规则源，合并去重后生成两份产物：

- `merged_all.txt`：完整规则
- `merged_lite.txt`：精简规则

这次整理后，项目补上了几件之前缺失但实际很重要的能力：

- `config.yml` 已真实接入，下载和精简参数不再写死在脚本里
- `logs/` 会自动生成，三个脚本分别输出独立日志
- 合并阶段不会再把 `failed_sources.txt`、`[Adblock Plus 2.0]` 之类的元数据误写进最终规则
- 精简阶段补上了空规则集、负数目标值等边界保护
- `tests/` 已补上回归测试，GitHub Actions 会先跑测试再发版

## 目录结构

```text
.
├── .github/workflows/update-rules.yml
├── config.yml
├── requirements.txt
├── sources/sources.txt
├── scripts/
│   ├── common.py
│   ├── fetch_rules.py
│   ├── merge_rules.py
│   └── optimize_rules.py
├── tests/
│   ├── test_fetch_rules.py
│   ├── test_merge_rules.py
│   └── test_optimize_rules.py
├── logs/                # 自动生成
└── rules/               # 自动生成，可额外放 rules/my_rules.txt
```

## 配置说明

`config.yml` 关键字段：

```yaml
download:
  timeout: 30
  connect_timeout: 10
  read_timeout: 30
  retries: 3
  min_success_rate: 0.8

workers:
  threads: 4

optimization:
  enable: true
  level: 2
  target_rules: 150000
  min_rules: 100000
  max_rules: 200000
```

说明：

- `download.timeout` 是兼容旧配置的简写；如果设置了 `read_timeout`，优先使用 `read_timeout`
- `download.min_success_rate` 是下载成功率保护；低于该比例时本次任务失败，`rules` 分支会保留上一版规则
- `optimization.enable=false` 时，`merged_lite.txt` 会直接复制 `merged_all.txt`
- `level` 是一个便捷预设；`target_rules / min_rules / max_rules` 会覆盖预设值
- 如果精简结果低于 `min_rules`，脚本会拒绝发布，避免把明显不完整的规则推给订阅端

## 本地运行

```bash
python -m pip install -r requirements.txt
python -m pip install pytest

python scripts/fetch_rules.py
python scripts/merge_rules.py
python scripts/optimize_rules.py
```

运行完成后可查看：

```bash
python -m pytest
```

输出文件：

- `rules/merged_all.txt`
- `rules/merged_lite.txt`
- `rules/merge_stats.txt`
- `rules/optimization_stats.txt`

日志文件：

- `logs/fetch_rules.log`
- `logs/merge_rules.log`
- `logs/optimize_rules.log`

## 自定义规则

如果你有想长期保留的本地规则，可以放到：

```text
rules/my_rules.txt
```

合并时会优先加载这个文件，再加载下载到 `temp/` 的规则源。

## GitHub 发布结果

工作流会把结果发布到 `rules` 分支，并保留：

- `latest/full/merged_all.txt`
- `latest/lite/merged_lite.txt`
- `archive/YYYY-MM-DD/...`

如果你要给 AdGuard Home 订阅，建议使用 `raw.githubusercontent.com` 地址，而不是 `github.com/.../blob/...` 页面地址。示例：

```text
https://raw.githubusercontent.com/<your-user>/<your-repo>/rules/latest/lite/merged_lite.txt
https://raw.githubusercontent.com/<your-user>/<your-repo>/rules/latest/full/merged_all.txt
```

## 注意事项

- 规则源失效时，下载失败列表会写入 `temp/failed_sources.log`，但不会混进最终规则文件
- 本项目只做规则聚合和筛选，不保证所有网站都 100% 正常或 100% 无误拦截
- 规则版权归各上游维护者所有

## 贡献

新增规则源、修复脚本或调整工作流前，建议先看 [CONTRIBUTING.md](./CONTRIBUTING.md)。
