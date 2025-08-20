#!/bin/bash
# 在Ubuntu下创建虚拟环境并安装依赖
set -e

# 确保在脚本所在目录执行
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
#pip config set global.index-url https://mirror.nju.edu.cn/pypi/web/simple
pip install --upgrade pip
pip install -r requirements.txt

echo "虚拟环境已创建并安装依赖完成。"
