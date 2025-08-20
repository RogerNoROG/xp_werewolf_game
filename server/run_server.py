import os
import platform
import subprocess
import sys

if platform.system().lower() == "linux":
    script_path = os.path.join(os.path.dirname(__file__), "setup_venv.sh")
    if os.path.exists(script_path):
        print("检测到Linux环境，自动创建虚拟环境并安装依赖...")
        result = subprocess.run(["bash", script_path], check=True)
        if result.returncode != 0:
            print("依赖安装失败，程序终止。"); sys.exit(1)
        else:
            print("依赖安装完成，继续启动服务...")
    else:
        print("未找到setup_venv.sh脚本，跳过虚拟环境创建。")
else:
    print("Windows环境，跳过虚拟环境自动创建。请手动安装依赖。")

# 激活虚拟环境（仅对Linux）
if platform.system().lower() == "linux":
    activate_this = os.path.join(os.path.dirname(__file__), "venv/bin/activate_this.py")
    if os.path.exists(activate_this):
        exec(open(activate_this).read(), dict(__file__=activate_this))

# 现在再导入并运行主服务
import server
