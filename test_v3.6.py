#!/usr/bin/env python
"""
快速测试脚本 - 验证 v3.6 改进效果
"""

import requests
import time
import json

SCANNER_URL = "http://127.0.0.1:8888"
TARGET_URL = "http://127.0.0.1:5000/api/swagger.json"  # VAmPI Mock 靶场

def start_scan():
    """启动扫描"""
    print("🚀 启动扫描...")
    response = requests.post(f"{SCANNER_URL}/start_scan", json={
        "url": TARGET_URL,
        "mode": "async"
    })
    result = response.json()
    if not result.get("success"):
        print(f"❌ 启动失败: {result.get('error')}")
        return None

    scan_id = result["scan_id"]
    print(f"✅ 扫描已启动，scan_id: {scan_id}")
    return scan_id

def wait_for_completion(scan_id, timeout=300):
    """等待扫描完成"""
    print("⏳ 等待扫描完成...")
    start_time = time.time()

    while time.time() - start_time < timeout:
        response = requests.get(f"{SCANNER_URL}/scans/{scan_id}/status")
        status = response.json()

        if status.get("status") == "completed":
            print("✅ 扫描完成!")
            return True
        elif status.get("status") == "failed":
            print(f"❌ 扫描失败: {status.get('error')}")
            return False

        progress = status.get("progress", 0)
        phase = status.get("phase", "unknown")
        print(f"  进度: {progress}% | 阶段: {phase}")
        time.sleep(3)

    print("⏰ 超时!")
    return False

def get_results(scan_id):
    """获取扫描结果"""
    print("\n📊 获取扫描结果...")
    response = requests.get(f"{SCANNER_URL}/scans/{scan_id}")
    result = response.json()

    if not result.get("success"):
        print(f"❌ 获取失败: {result.get('error')}")
        return None

    scan = result["scan"]
    data = scan.get("data", {})

    # 提取关键信息
    security_assessment = data.get("security_assessment", {})
    vulns = security_assessment.get("vulnerabilities_found", [])
    stats = data.get("stats", {})

    print("\n" + "="*60)
    print("📈 扫描结果摘要")
    print("="*60)
    print(f"目标: {data.get('target_url', 'N/A')}")
    print(f"攻击方案数: {stats.get('phase1_plan_count', 0)}")
    print(f"执行攻击数: {stats.get('phase1_executed', 0)}")
    print(f"发现漏洞数: {len(vulns)}")
    print(f"二次验证: {'✅ 已执行' if security_assessment.get('verification_applied') else '❌ 未执行'}")
    print(f"验证前漏洞数: {security_assessment.get('original_count', 'N/A')}")
    print(f"验证后漏洞数: {security_assessment.get('verified_count', len(vulns))}")

    print("\n🔍 漏洞详情:")
    for i, vuln in enumerate(vulns, 1):
        print(f"\n  [{i}] {vuln.get('vulnerability_type', 'unknown').upper()}")
        print(f"      端点: {vuln.get('endpoint', 'N/A')}")
        print(f"      严重性: {vuln.get('severity', 'N/A')}")
        print(f"      置信度: {vuln.get('confidence', 0):.2f}")
        print(f"      发现: {vuln.get('finding', 'N/A')[:100]}...")

    print("\n" + "="*60)

    # 检查改进效果
    print("\n📋 改进效果检查:")
    if len(vulns) <= 10:
        print("  ✅ 漏洞数量合理 (<=10)")
    else:
        print(f"  ⚠️ 漏洞数量仍然较多 ({len(vulns)})")

    if security_assessment.get("verification_applied"):
        print("  ✅ 二次验证已执行")
    else:
        print("  ⚠️ 二次验证未执行")

    # 检查置信度阈值
    low_confidence = [v for v in vulns if v.get("confidence", 0) < 0.72]
    if not low_confidence:
        print("  ✅ 所有漏洞置信度 >= 0.72")
    else:
        print(f"  ⚠️ 有 {len(low_confidence)} 个漏洞置信度 < 0.72")

    return data

def main():
    """主函数"""
    print("="*60)
    print("SmartAttack v3.6 测试脚本")
    print("="*60)

    # 检查扫描器是否运行
    try:
        response = requests.get(f"{SCANNER_URL}/health", timeout=3)
        if response.status_code != 200:
            print("❌ 扫描器未运行或无法连接")
            print("请先启动: python -m smart_attacking.scanner")
            return
        print("✅ 扫描器已连接")
    except Exception as e:
        print(f"❌ 无法连接扫描器: {e}")
        print("请先启动: python -m smart_attacking.scanner")
        return

    # 启动扫描
    scan_id = start_scan()
    if not scan_id:
        return

    # 等待完成
    if not wait_for_completion(scan_id):
        return

    # 获取结果
    get_results(scan_id)

if __name__ == "__main__":
    main()
