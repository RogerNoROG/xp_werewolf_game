import os
import platform
import subprocess
import sys

# 检查是否已经在虚拟环境中
if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
    print("已在虚拟环境中，直接启动服务...")
    # 导入server模块
    import server
    
    # 直接调用server的启动逻辑
    print(f"服务器运行在端口 {server.PORT}")
    print(f"本地访问: http://localhost:{server.PORT}")
    print(f"网络访问: http://{server.HOST}:{server.PORT}")
    print("服务器启动中...")
    
    try:
        import uvicorn
        uvicorn.run(
            server.socket_app,
            host=server.HOST,
            port=server.PORT,
            log_level=server.SERVER_CONFIG["LOG_LEVEL"]
        )
    except KeyboardInterrupt:
        print("\n服务器关闭中...")
    finally:
        # 删除所有json文件，模拟数据库关闭
        for file_path in server.DATA_FILES.values():
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"删除文件: {file_path}")
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
    
    # 直接调用server的启动逻辑
    print(f"服务器运行在端口 {server.PORT}")
    print(f"本地访问: http://localhost:{server.PORT}")
    print(f"网络访问: http://{server.HOST}:{server.PORT}")
    print("服务器启动中...")
    
    try:
        import uvicorn
        uvicorn.run(
            server.socket_app,
            host=server.HOST,
            port=server.PORT,
            log_level=server.SERVER_CONFIG["LOG_LEVEL"]
        )
    except KeyboardInterrupt:
        print("\n服务器关闭中...")
    finally:
        # 删除所有json文件，模拟数据库关闭
        for file_path in server.DATA_FILES.values():
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"删除文件: {file_path}")
