import os
import platform
import subprocess
import sys

# 检查是否已经在虚拟环境中
if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
    print("已在虚拟环境中，直接启动服务...")
    import server
else:
    # 不在虚拟环境中，需要创建并激活
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
        venv_python = os.path.join(os.path.dirname(__file__), "venv/bin/python")
        if os.path.exists(venv_python):
            print(f"使用虚拟环境Python: {venv_python}")
            # 重新启动进程，使用虚拟环境的Python
            os.execv(venv_python, [venv_python, __file__])
        else:
            print("虚拟环境Python未找到，使用系统Python")

    # 现在再导入并运行主服务
    import server
