#!/usr/bin/env python3
"""
SmartAttack CI/CD 扫描脚本
============================
在 GitHub Actions / CI 流水线中调用 SmartAttack API 执行扫描。

用法:
    python run_scan.py --endpoint http://localhost:8888 \
                       --url http://target:5000/api/swagger.json \
                       --output scan-result.json \
                       --timeout 600
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error


def main():
    parser = argparse.ArgumentParser(description="SmartAttack CI/CD 扫描脚本")
    parser.add_argument("--endpoint", default="http://localhost:8888",
                        help="SmartAttack 服务地址")
    parser.add_argument("--url", required=True,
                        help="待扫描的 Swagger/OpenAPI 文档 URL")
    parser.add_argument("--api-key", default="",
                        help="LLM API Key（也可通过 SMARTA_ATTACK_API_KEY 环境变量设置）")
    parser.add_argument("--model", default="deepseek-chat",
                        help="AI 模型名称")
    parser.add_argument("--output", default="scan-result.json",
                        help="结果输出文件路径")
    parser.add_argument("--timeout", type=int, default=600,
                        help="最大等待时间（秒）")
    parser.add_argument("--format", default="json",
                        help="输出格式: json | pdf")
    args = parser.parse_args()

    import os
    api_key = args.api_key or os.getenv("SMARTA_ATTACK_API_KEY", "")

    endpoint = args.endpoint.rstrip("/")
    target_url = args.url

    print(f"🛡️  SmartAttack CI/CD 扫描")
    print(f"   服务: {endpoint}")
    print(f"   目标: {target_url}")
    print(f"   模型: {args.model}")
    print()

    # ---- Step 1: 健康检查 ----
    print("1️⃣  检查服务状态…")
    try:
        with urllib.request.urlopen(f"{endpoint}/health", timeout=10) as resp:
            health = json.loads(resp.read())
            print(f"   ✅ 服务正常 (版本: {health.get('version', 'unknown')})")
    except Exception as e:
        print(f"   ❌ 服务不可达: {e}")
        sys.exit(1)

    # ---- Step 2: 提交扫描 ----
    print("2️⃣  提交扫描任务…")
    import os
    payload = json.dumps({
        "url": target_url,
        "mode": "async",
        "model_provider": "deepseek",
        "model_name": args.model,
    }).encode()

    req = urllib.request.Request(
        f"{endpoint}/start_scan",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            if not result.get("success"):
                print(f"   ❌ 提交失败: {result.get('error')}")
                sys.exit(1)
            scan_id = result["scan_id"]
            print(f"   ✅ 扫描已提交: {scan_id}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"   ❌ HTTP {e.code}: {body}")
        sys.exit(1)

    # ---- Step 3: 轮询等待 ----
    print("3️⃣  等待扫描完成…")
    start_time = time.time()
    dots = 0

    while True:
        elapsed = time.time() - start_time
        if elapsed > args.timeout:
            print(f"\n   ⚠️  超时 ({args.timeout}s)，将尝试获取部分结果")

        try:
            with urllib.request.urlopen(f"{endpoint}/scans/{scan_id}/status", timeout=5) as resp:
                status = json.loads(resp.read())
        except Exception:
            time.sleep(2)
            continue

        if status.get("status") == "completed":
            print(f"\n   ✅ 扫描完成 ({elapsed:.0f}s)")
            break
        elif status.get("status") == "failed":
            print(f"\n   ❌ 扫描失败: {status.get('message', '')}")
            sys.exit(1)

        # 进度打印
        progress = status.get("progress", 0)
        msg = status.get("message", "")
        dots = (dots + 1) % 4
        print(f"\r   ⏳ [{progress}%] {msg} {'.' * dots}   ", end="", flush=True)
        time.sleep(3)

    # ---- Step 4: 获取完整结果 ----
    print("4️⃣  获取扫描结果…")
    try:
        with urllib.request.urlopen(f"{endpoint}/scans/{scan_id}", timeout=15) as resp:
            scan_data = json.loads(resp.read())
    except Exception as e:
        print(f"   ❌ 获取结果失败: {e}")
        sys.exit(1)

    # ---- Step 5: 保存结果 ----
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(scan_data, fh, ensure_ascii=False, indent=2)
    print(f"   ✅ 结果已保存: {args.output}")

    # 也获取安全评分
    try:
        with urllib.request.urlopen(f"{endpoint}/scans/{scan_id}/score", timeout=10) as resp:
            score_data = json.loads(resp.read())
            if score_data.get("success"):
                score = score_data["score"]
                print(f"\n📊 SmartAttack Score: {score['score']}/100 ({score['grade']})")
                print(f"   漏洞总数: {score['vulnerability_summary']['total']}")
                print(f"   严重/高危: {score['vulnerability_summary']['critical'] + score['vulnerability_summary']['high']}")
    except Exception:
        pass

    print("\n🎉 CI/CD 扫描完成！")
    return 0


if __name__ == "__main__":
    sys.exit(main())
