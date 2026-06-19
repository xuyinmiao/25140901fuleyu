# 4.25-semgrep（Semgrep 实验小型应用）

## 复现扫描（仅自写规则，一条 `id`）

在本目录根目录执行：

```bash
semgrep --test semgrep-lab/rules --metrics=off
semgrep -c semgrep-lab/rules/sqli_dynamic_execute.yaml . --exclude "sqli_dynamic_execute.test.py" --metrics=off
```

勿使用 `p/`、`owasp-top-ten` 等现成规则包作为本实验配置。当前规则**仅**匹配 `%` 格式化 SQL 后 `cur.execute(变量)`（`sqli-exec-after-modulo-format`）。

## 课程材料

- `付乐宇-25140901-Semgrep实验.md`：实验主报告
- `semgrep-lab/report.md`：按讲义推荐目录补充的报告副本
- `付乐宇-25140901-Semgrep实验.pdf`：实验报告 PDF 版本
- `semgrep-lab/`：自写规则、测试、流程图与 `output/semgrep.txt` 运行记录

## 作者

付乐宇 · 学号 25140901
