# XP狼人杀 - Python服务器

本项目是狼人杀游戏的后端服务，基于 FastAPI + Socket.IO 实现，所有数据均以 JSON 文件存储，无需数据库。

## 主要特性
- 用户注册/登录/认证（JWT）
- 房间创建、加入、准备、离开
- 游戏流程、投票、讨论、XP提交
- 实时推送（Socket.IO）
- 所有数据均存储为 JSON 文件，便于迁移和备份

## 依赖安装

```bash
cd server
pip install -r requirements.txt
```

## 运行方法

```bash
python server.py
```

默认监听 0.0.0.0:12741，可通过 `config.py` 修改端口和参数。

## 主要API
- `/api/auth/register` 用户注册
- `/api/auth/login` 用户登录
- `/api/room/create` 创建房间
- `/api/room/join` 加入房间
- `/api/room/ready` 切换准备
- `/api/room/leave` 离开房间
- `/api/game/start` 开始游戏
- `/api/game/kill` 狼人夜晚投票
- `/api/game/submit-xp` XP提交
- `/api/game/submit-discussion` 讨论提交
- `/api/game/vote` 白天投票
- `/api/game/state` 获取游戏状态

## 数据存储方式
- 所有用户、房间、成员、游戏、投票、讨论等数据均存储在 `server/data/` 目录下的 json 文件中。
- 每类数据一个 json 文件（如 `users.json`、`rooms.json` 等）。

## 注意事项
- 适合本地或小型局域网娱乐，生产环境请加强安全性和并发处理。
- 启动/关闭服务器时会自动清理 json 数据文件（模拟数据库关闭）。
- 前端页面请见 `frontend/` 目录。

## License
MIT
