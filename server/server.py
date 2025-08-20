#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XP狼人杀 - Python服务器
替代Node.js实现，提供完整的游戏后端服务
"""

import json
import os
import uuid
import bcrypt
import asyncio
import signal
import sys
import random
import secrets
import time
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
import socketio
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import jwt
from pydantic import BaseModel
import threading

# 导入配置
from config import (
    SERVER_CONFIG, SECURITY_CONFIG, DATABASE_CONFIG, DIRECTORY_CONFIG, 
    GAME_CONFIG, CORS_CONFIG, SOCKETIO_CONFIG,
    PORT, HOST, JWT_SECRET, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES,
    PLAYERS_DIR, DATABASE_DIR, DATABASE_FILE,
    get_database_dir, get_database_path, get_players_dir, 
    get_frontend_file_path
)

# 初始化随机数生成器以确保更好的随机性
random.seed()
# 使用系统时间和随机数增强随机性
import time
random.seed(int(time.time() * 1000000) % (2**32))

# JSON数据文件路径
DATA_FILES = {
    'users': os.path.join(get_database_dir(), 'users.json'),
    'rooms': os.path.join(get_database_dir(), 'rooms.json'),
    'room_members': os.path.join(get_database_dir(), 'room_members.json'),
    'games': os.path.join(get_database_dir(), 'games.json'),
    'game_players': os.path.join(get_database_dir(), 'game_players.json'),
    'votes': os.path.join(get_database_dir(), 'votes.json'),
    'discussions': os.path.join(get_database_dir(), 'discussions.json'),
}

# 线程锁，保证多线程/协程下文件操作安全
DATA_LOCKS = {k: threading.Lock() for k in DATA_FILES}

def load_json_data(data_type):
    """加载某类数据的全部内容，返回list"""
    file_path = DATA_FILES[data_type]
    with DATA_LOCKS[data_type]:
        if not os.path.exists(file_path):
            return []
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except Exception:
                return []

def save_json_data(data_type, data_list):
    """保存某类数据的全部内容（list）"""
    file_path = DATA_FILES[data_type]
    with DATA_LOCKS[data_type]:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data_list, f, ensure_ascii=False, indent=2)

def append_json_data(data_type, item):
    """向某类数据追加一条记录"""
    data = load_json_data(data_type)
    data.append(item)
    save_json_data(data_type, data)

def update_json_data(data_type, item_id, item, id_field='id'):
    """根据id更新某类数据的一条记录"""
    data = load_json_data(data_type)
    for idx, d in enumerate(data):
        if d.get(id_field) == item_id:
            data[idx] = item
            break
    save_json_data(data_type, data)

def delete_json_data(data_type, item_id, id_field='id'):
    """根据id删除某类数据的一条记录"""
    data = load_json_data(data_type)
    data = [d for d in data if d.get(id_field) != item_id]
    save_json_data(data_type, data)

def get_json_data_by_field(data_type, field, value):
    """根据字段查找所有匹配的记录"""
    data = load_json_data(data_type)
    return [d for d in data if d.get(field) == value]

def get_json_data_one_by_field(data_type, field, value):
    """根据字段查找一条记录"""
    data = load_json_data(data_type)
    for d in data:
        if d.get(field) == value:
            return d
    return None

# 创建FastAPI应用
app = FastAPI(title="XP狼人杀服务器")

# CORS设置
app.add_middleware(
    CORSMiddleware,
    **CORS_CONFIG
)

# Socket.IO服务器
sio = socketio.AsyncServer(**SOCKETIO_CONFIG)
socket_app = socketio.ASGIApp(sio, app)

# 玩家数据管理
def ensure_players_dir():
    """确保players目录存在"""
    players_dir = get_players_dir()
    if not os.path.exists(players_dir):
        os.makedirs(players_dir)
    return players_dir

def get_player_file_path(username: str) -> str:
    """获取玩家数据文件路径"""
    return os.path.join(get_players_dir(), f"{username}.json")

def load_player(username: str) -> Optional[Dict]:
    """加载玩家数据"""
    try:
        file_path = get_player_file_path(username)
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None
    except Exception as e:
        print(f"Error loading player {username}: {e}")
        return None

def save_player(username: str, data: Dict) -> bool:
    """保存玩家数据"""
    try:
        players_dir = ensure_players_dir()
        file_path = get_player_file_path(username)
        
        # 确保数据包含必要字段
        default_data = {
            "username": username,
            "password": "",
            "total_games": 0,
            "wins": 0,
            "losses": 0,
            "created_at": datetime.now().isoformat(),
            "last_login": datetime.now().isoformat()
        }
        
        # 合并数据
        player_data = {**default_data, **data}
        player_data["last_login"] = datetime.now().isoformat()
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(player_data, f, ensure_ascii=False, indent=2)
        
        return True
    except Exception as e:
        print(f"Error saving player {username}: {e}")
        return False

def update_player_stats(username: str, won: bool = False) -> bool:
    """更新玩家统计数据"""
    try:
        player_data = load_player(username)
        if not player_data:
            print(f"无法加载玩家数据: {username}")
            return False
        
        # 增加总游戏局数
        old_total = player_data.get("total_games", 0)
        old_wins = player_data.get("wins", 0)
        old_losses = player_data.get("losses", 0)
        
        player_data["total_games"] = old_total + 1
        
        if won:
            player_data["wins"] = old_wins + 1
        else:
            player_data["losses"] = old_losses + 1
        
        print(f"玩家 {username} 统计更新: 总局数 {old_total} -> {player_data['total_games']}, 胜利 {old_wins} -> {player_data['wins']}, 失败 {old_losses} -> {player_data['losses']}")
        
        result = save_player(username, player_data)
        if result:
            print(f"玩家 {username} 统计保存成功")
        else:
            print(f"玩家 {username} 统计保存失败")
        return result
    except Exception as e:
        print(f"Error updating player stats {username}: {e}")
        return False

def list_players() -> List[Dict]:
    """列出所有玩家"""
    try:
        players_dir = ensure_players_dir()
        players = []
        for filename in os.listdir(players_dir):
            if filename.endswith('.json'):
                username = filename[:-5]  # 移除.json后缀
                player_data = load_player(username)
                if player_data:
                    players.append(player_data)
        return players
    except Exception as e:
        print(f"Error listing players: {e}")
        return []

# 认证相关
security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """验证JWT令牌"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="访问令牌已过期")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="访问令牌无效")

# 数据模型
class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class RoomReady(BaseModel):
    room_id: str

class RoomLeave(BaseModel):
    room_id: str

class RoomStart(BaseModel):
    room_id: str

class XPSubmit(BaseModel):
    game_id: str
    xp_content: str

class GameVote(BaseModel):
    game_id: str
    target_id: str

class GameExit(BaseModel):
    game_id: str

class DiscussionSubmit(BaseModel):
    game_id: str
    content: str

# 工具函数
def generate_room_code() -> str:
    """生成随机房间号"""
    return str(random.randint(1000, 9999))

def generate_xp_content() -> str:
    """生成狼人杀XP内容"""
    return random.choice(GAME_CONFIG["XP_CONTENTS"])

def shuffle_roles(player_count: int) -> List[bool]:
    """
    改进的角色分配函数，确保真正的随机性
    返回角色列表，True表示狼人，False表示村民
    """
    wolf_count = max(1, int(player_count * GAME_CONFIG["WOLF_RATIO"]))
    
    if GAME_CONFIG.get("DEBUG_ROLE_ASSIGNMENT", False):
        print(f"玩家总数: {player_count}, 狼人数: {wolf_count}, 村民数: {player_count - wolf_count}")
    
    # 创建角色列表
    roles = [True] * wolf_count + [False] * (player_count - wolf_count)
    
    # 多层随机化策略，确保极高的随机性
    import time
    import hashlib
    
    # 1. 使用高精度时间、进程ID和随机数创建随机种子
    current_microseconds = int(time.time() * 1000000)
    process_id = os.getpid()
    random_bytes = secrets.token_bytes(16)
    
    # 创建复合种子
    seed_string = f"{current_microseconds}_{process_id}_{random_bytes.hex()}_{player_count}"
    seed_hash = hashlib.sha256(seed_string.encode()).hexdigest()
    seed_value = int(seed_hash[:8], 16)  # 取前8个十六进制字符作为种子
    
    # 2. 重新初始化随机数生成器
    random.seed(seed_value)
    
    # 3. 使用 secrets 模块进行第一轮打乱
    for i in range(len(roles)):
        j = secrets.randbelow(len(roles))
        roles[i], roles[j] = roles[j], roles[i]
    
    # 4. 使用标准 random 进行多轮打乱
    for round_num in range(3):  # 进行3轮打乱
        random.shuffle(roles)
        
        # 每轮中再进行手动交换
        for _ in range(player_count * 2):  # 交换次数与玩家数成比例
            i = random.randint(0, len(roles) - 1)
            j = random.randint(0, len(roles) - 1)
            roles[i], roles[j] = roles[j], roles[i]
    
    # 5. 最后使用时间戳进行额外打乱
    final_time = int(time.time() * 1000000) % 1000
    for _ in range(final_time % 20 + 10):  # 10-29次额外交换
        i = secrets.randbelow(len(roles))
        j = secrets.randbelow(len(roles))
        roles[i], roles[j] = roles[j], roles[i]
    
    # 验证角色分配（仅在调试模式下显示）
    if GAME_CONFIG.get("DEBUG_ROLE_ASSIGNMENT", False):
        wolf_assigned = sum(roles)
        wolf_positions = [i for i, is_wolf in enumerate(roles) if is_wolf]
        print(f"角色分配完成: 狼人 {wolf_assigned} 人, 村民 {len(roles) - wolf_assigned} 人")
        print(f"狼人位置: {wolf_positions}")
        print(f"角色序列: {['狼人' if r else '村民' for r in roles]}")
        print(f"种子值: {seed_value} (基于时间: {current_microseconds})")
    
    return roles

# 健康检查和基础API
@app.get("/api/health")
async def health_check():
    """健康检查"""
    return {"status": "ok", "message": "服务器运行正常"}

@app.get("/api/status")
async def get_status():
    """获取服务器状态"""
    users = load_json_data('users')
    rooms = load_json_data('rooms')
    games = load_json_data('games')
    
    # 统计数据
    user_count = len(users)
    waiting_rooms = sum(1 for r in rooms if r.get('status') == 'waiting')
    active_games = sum(1 for g in games if g.get('status') != 'finished')
    
    return {
        "status": "running",
        "stats": {
            "total_users": user_count,
            "waiting_rooms": waiting_rooms,
            "active_games": active_games
        }
    }

# API路由

@app.post("/api/auth/register")
async def register(user_data: UserRegister):
    """用户注册"""
    if not user_data.username or not user_data.password:
        raise HTTPException(status_code=400, detail="用户名和密码不能为空")
    
    # 检查用户是否已存在
    existing_user = get_json_data_one_by_field('users', 'username', user_data.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 创建新用户
    user_id = str(uuid.uuid4())
    hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user_info = {
        "id": user_id,
        "username": user_data.username,
        "password": hashed_password,
        "total_games": 0,
        "wins": 0,
        "losses": 0
    }
    append_json_data('users', user_info)
    
    # 生成JWT令牌
    token = jwt.encode({"id": user_id, "username": user_data.username}, JWT_SECRET, algorithm="HS256")
    return {
        "token": token,
        "user": {"id": user_id, "username": user_data.username, "nickname": user_data.username}
    }

@app.post("/api/auth/login")
async def login(user_data: UserLogin):
    """用户登录"""
    if not user_data.username or not user_data.password:
        raise HTTPException(status_code=400, detail="用户名和密码不能为空")
    
    user = get_json_data_one_by_field('users', 'username', user_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="用户不存在")
    if not bcrypt.checkpw(user_data.password.encode('utf-8'), user['password'].encode('utf-8')):
        raise HTTPException(status_code=400, detail="密码错误")
    
    token = jwt.encode({"id": user['id'], "username": user['username']}, JWT_SECRET, algorithm="HS256")
    return {
        "token": token,
        "user": {"id": user['id'], "username": user['username'], "nickname": user['username']}
    }

@app.get("/api/user/profile")
async def get_profile(current_user: Dict = Depends(verify_token)):
    """获取用户信息"""
    user = load_player(current_user["username"])
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    return {
        "id": user["id"],
        "username": user["username"],
        "nickname": user["username"],
        "total_games": user.get("total_games", 0),
        "wins": user.get("wins", 0),
        "losses": user.get("losses", 0)
    }

@app.get("/api/user/stats")
async def get_stats(current_user: Dict = Depends(verify_token)):
    """获取所有玩家统计"""
    players = list_players()
    stats = []
    for player in players:
        total_games = player.get("total_games", 0)
        wins = player.get("wins", 0)
        win_rate = (wins / total_games * 100) if total_games > 0 else 0
        
        stats.append({
            "username": player["username"],
            "total_games": total_games,
            "wins": wins,
            "losses": player.get("losses", 0),
            "win_rate": f"{win_rate:.1f}"
        })
    
    # 按总游戏局数排序
    stats.sort(key=lambda x: x["total_games"], reverse=True)
    return stats

# 房间管理API
@app.get("/api/room/list")
async def list_rooms(current_user: Dict = Depends(verify_token)):
    """获取房间列表"""
    rooms = load_json_data('rooms')
    users = load_json_data('users')
    room_members = load_json_data('room_members')
    rooms_data = []
    for room in rooms:
        if room.get('status') == 'waiting':
            owner = next((u for u in users if u['id'] == room['owner_id']), None)
            member_count = sum(1 for m in room_members if m['room_id'] == room['id'])
        rooms_data.append({
                "id": room['id'],
                "code": room['code'],
                "name": room['name'],
                "owner_id": room['owner_id'],
                "status": room['status'],
                "max_players": room['max_players'],
                "created_at": room['created_at'],
                "owner_nickname": owner['username'] if owner else '',
                "member_count": member_count
            })
    return {"rooms": rooms_data}

@app.post("/api/room/create")
async def create_room(current_user: Dict = Depends(verify_token)):
    """创建房间"""
    room_id = str(uuid.uuid4())
    room_code = generate_room_code()
    room_name = f"{current_user['username']}的房间"
    room = {
        "id": room_id,
        "code": room_code,
        "name": room_name,
        "owner_id": current_user["id"],
        "status": "waiting",
        "max_players": 8,
        "created_at": datetime.now().isoformat()
    }
    append_json_data('rooms', room)
    # 房主自动加入房间
    member_id = str(uuid.uuid4())
    member = {
        "id": member_id,
        "room_id": room_id,
        "user_id": current_user["id"],
        "is_ready": True,
        "joined_at": datetime.now().isoformat()
    }
    append_json_data('room_members', member)
    return {"room_id": room_id, "room_code": room_code}

@app.post("/api/room/join")
async def join_room(code: str, current_user: Dict = Depends(verify_token)):
    """加入房间"""
    rooms = load_json_data('rooms')
    room = next((r for r in rooms if r['code'] == code and r['status'] == 'waiting'), None)
    if not room:
        raise HTTPException(status_code=404, detail="房间不存在或已开始")
    room_members = load_json_data('room_members')
    if any(m['room_id'] == room['id'] and m['user_id'] == current_user['id'] for m in room_members):
        raise HTTPException(status_code=400, detail="你已在房间中")
    member_id = str(uuid.uuid4())
    member = {
        "id": member_id,
        "room_id": room['id'],
        "user_id": current_user['id'],
        "is_ready": False,
        "joined_at": datetime.now().isoformat()
    }
    append_json_data('room_members', member)
    return {"room_id": room['id'], "room_code": room['code']}

@app.post("/api/room/ready")
async def toggle_ready(ready_data: RoomReady, current_user: Dict = Depends(verify_token)):
    """切换准备状态"""
    room_members = load_json_data('room_members')
    updated = False
    for m in room_members:
        if m['room_id'] == ready_data.room_id and m['user_id'] == current_user['id']:
            m['is_ready'] = not m.get('is_ready', False)
            updated = True
            break
    if not updated:
        raise HTTPException(status_code=404, detail="房间成员不存在")
    save_json_data('room_members', room_members)
    return {"room_id": ready_data.room_id, "user_id": current_user['id']}

@app.post("/api/room/leave")
async def leave_room(leave_data: RoomLeave, current_user: Dict = Depends(verify_token)):
    """离开房间"""
    room_members = load_json_data('room_members')
    new_members = [m for m in room_members if not (m['room_id'] == leave_data.room_id and m['user_id'] == current_user['id'])]
    if len(new_members) == len(room_members):
        raise HTTPException(status_code=404, detail="房间成员不存在")
    save_json_data('room_members', new_members)
    return {"room_id": leave_data.room_id, "user_id": current_user['id']}

@app.get("/api/room/info")
async def get_room_info(code: str, current_user: Dict = Depends(verify_token)):
    """获取房间详细信息"""
    rooms = load_json_data('rooms')
    users = load_json_data('users')
    room_members = load_json_data('room_members')
    room = next((r for r in rooms if r['code'] == code), None)
    if not room:
        raise HTTPException(status_code=404, detail="房间不存在")
    owner = next((u for u in users if u['id'] == room['owner_id']), None)
    members = [m for m in room_members if m['room_id'] == room['id']]
    member_infos = []
    for m in members:
        user = next((u for u in users if u['id'] == m['user_id']), None)
        member_infos.append({
            "id": m['id'],
            "user_id": m['user_id'],
            "username": user['username'] if user else '',
            "is_ready": m.get('is_ready', False),
            "joined_at": m.get('joined_at', '')
        })
    return {
        "room": {
            "id": room['id'],
            "code": room['code'],
            "name": room['name'],
            "owner_id": room['owner_id'],
            "owner_nickname": owner['username'] if owner else '',
            "status": room['status'],
            "max_players": room['max_players'],
            "created_at": room['created_at']
        },
        "members": member_infos
    }

@app.post("/api/game/start")
async def start_game(start_data: RoomStart, current_user: Dict = Depends(verify_token)):
    """开始游戏"""
    rooms = load_json_data('rooms')
    room = next((r for r in rooms if r['id'] == start_data.room_id and r['owner_id'] == current_user['id']), None)
    if not room:
        raise HTTPException(status_code=404, detail="房间不存在或无权限")
    room_members = load_json_data('room_members')
    members = [m for m in room_members if m['room_id'] == start_data.room_id]
    if len(members) < 4:
        raise HTTPException(status_code=400, detail="房间人数不足")
    # 更新房间状态
    for r in rooms:
        if r['id'] == start_data.room_id:
            r['status'] = 'playing'
            break
    save_json_data('rooms', rooms)
    # 创建游戏
    game_id = str(uuid.uuid4())
    game = {
        "id": game_id,
        "room_id": start_data.room_id,
        "status": "submitting_xp",
        "round": 1,
        "public_xp": None,
        "winner": None,
        "created_at": datetime.now().isoformat()
    }
    append_json_data('games', game)
    # 创建game_players
    game_players = []
    for m in members:
        game_players.append({
            "id": str(uuid.uuid4()),
            "game_id": game_id,
            "user_id": m['user_id'],
            "is_wolf": False,  # 角色分配逻辑可后续补充
            "is_alive": True,
            "xp_content": None,
            "death_reason": None
        })
    all_game_players = load_json_data('game_players')
    all_game_players.extend(game_players)
    save_json_data('game_players', all_game_players)
    return {"game_id": game_id}

# 游戏相关API
@app.get("/api/game/state")
async def get_game_state(game_id: str, current_user: Dict = Depends(verify_token)):
    """获取游戏状态"""
    games = load_json_data('games')
    game = next((g for g in games if g['id'] == game_id), None)
    if not game:
        raise HTTPException(status_code=404, detail="游戏不存在")
    game_players = load_json_data('game_players')
    players = [p for p in game_players if p['game_id'] == game_id]
    users = load_json_data('users')
    player_infos = []
    for p in players:
        user = next((u for u in users if u['id'] == p['user_id']), None)
        player_infos.append({
            "id": p['id'],
            "user_id": p['user_id'],
            "username": user['username'] if user else '',
            "is_wolf": p.get('is_wolf', False),
            "is_alive": p.get('is_alive', True),
            "xp_content": p.get('xp_content'),
            "death_reason": p.get('death_reason')
        })
    return {
        "game": game,
        "players": player_infos
    }

@app.post("/api/game/submit-discussion")
async def submit_discussion(discussion_data: DiscussionSubmit, current_user: Dict = Depends(verify_token)):
    """提交讨论内容"""
    if not discussion_data.content:
        raise HTTPException(status_code=400, detail="讨论内容不能为空")
    
    discussions = load_json_data('discussions')
    
    # 检查游戏状态
    game = next((g for g in load_json_data('games') if g['id'] == discussion_data.game_id), None)
    if not game or game.get('status') not in ['discussing', 'voting']:
        raise HTTPException(status_code=400, detail="当前不是讨论时间")
    
    # 检查玩家是否在游戏中且存活
    player = next((p for p in load_json_data('game_players') if p['game_id'] == discussion_data.game_id and p['user_id'] == current_user["id"]), None)
    if not player or not player.get('is_alive'):
        raise HTTPException(status_code=400, detail="您不在游戏中或已死亡")
    
    try:
        # 记录讨论内容
        discussion_id = str(uuid.uuid4())
        print(f"存储讨论内容: game_id={discussion_data.game_id}, user_id={current_user['id']}, content={discussion_data.content}, round={game['round']}")
        # 确保讨论内容以字符串形式存储
        content_str = str(discussion_data.content)
        discussions.append({
            "id": discussion_id,
            "game_id": discussion_data.game_id,
            "user_id": current_user["id"],
            "content": content_str,
            "round": game['round'],
            "created_at": datetime.now().isoformat()
        })
        save_json_data('discussions', discussions)
        
        # 验证数据是否正确存储
        saved_discussion = next((d for d in discussions if d['id'] == discussion_id), None)
        print(f"验证存储结果: {saved_discussion}")
        
        # 检查是否所有存活玩家都已提交讨论内容
        alive_players = [p for p in load_json_data('game_players') if p['game_id'] == discussion_data.game_id and p['is_alive']]
        discussed_count = sum(1 for d in discussions if d['game_id'] == discussion_data.game_id and d['round'] == game['round'])
        
        print(f"存活玩家数: {len(alive_players)}, 已提交讨论玩家数: {discussed_count}")
        
        # 如果所有存活玩家都已提交讨论内容，自动进入投票阶段
        if len(alive_players) > 0 and discussed_count >= len(alive_players):
            game['status'] = 'voting'
            save_json_data('games', load_json_data('games')) # 重新加载games以获取更新后的状态
            print(f"所有玩家已完成讨论，游戏 {discussion_data.game_id} 自动进入投票阶段")
            
            # 通知游戏状态更新
            await notify_game_update(discussion_data.game_id, 'phase_changed', {
                'status': 'voting',
                'reason': 'all_discussions_submitted'
            })
            
            return {"message": "讨论内容提交成功，所有玩家已完成讨论，游戏进入投票阶段"}
        
        # 通知游戏状态更新
        await notify_game_update(discussion_data.game_id, 'discussion_submitted', {
            'user_id': current_user["id"],
            'content': discussion_data.content
        })
        
        return {"message": "讨论内容提交成功"}
    
    except Exception as e:
        print(f"Error submitting discussion: {e}")
        raise HTTPException(status_code=500, detail="讨论内容提交失败")

@app.get("/api/game/discussions")
async def get_discussions(game_id: str, current_user: Dict = Depends(verify_token)):
    """获取游戏讨论内容"""
    discussions = load_json_data('discussions')
    result = [d for d in discussions if d['game_id'] == game_id]
    return {"discussions": result}

@app.post("/api/game/submit-xp")
async def submit_xp(xp_data: XPSubmit, current_user: Dict = Depends(verify_token)):
    """提交XP"""
    if not xp_data.xp_content:
        raise HTTPException(status_code=400, detail="XP内容不能为空")
    
    games = load_json_data('games')
    game = next((g for g in games if g['id'] == xp_data.game_id), None)
    if not game or game.get('status') != 'submitting_xp':
        raise HTTPException(status_code=400, detail="当前不是提交XP时间")
    
    game_players = load_json_data('game_players')
    player = next((p for p in game_players if p['game_id'] == xp_data.game_id and p['user_id'] == current_user["id"]), None)
    if not player:
        raise HTTPException(status_code=400, detail="您不在游戏中")
    
    try:
        # 更新玩家的XP内容
        player['xp_content'] = xp_data.xp_content
        save_json_data('game_players', game_players)
        
        # 检查是否所有玩家都已提交XP
        all_submitted = all(p.get('xp_content') and p.get('xp_content').strip() for p in game_players)
        
        if all_submitted:
            # 找到狼人玩家并公布其XP
            wolf_players = [p for p in game_players if p.get('is_wolf')]
            
            if wolf_players:
                # 如果有多个狼人，随机选择一个狼人的XP作为公开XP
                selected_wolf = random.choice(wolf_players)
                selected_xp = selected_wolf.get('xp_content')
                
                print(f"公开狼人XP: 狼人玩家 {selected_wolf['username']} 的XP: '{selected_xp}'")
                
                # 更新游戏状态为讨论阶段，并设置公开的XP
                game['status'] = 'discussing'
                game['public_xp'] = selected_xp
                save_json_data('games', games) # 重新加载games以获取更新后的状态
                message = "XP提交成功，游戏进入讨论阶段"
                
                # 通知游戏状态更新
                await notify_game_update(xp_data.game_id, 'xp_phase_complete', {
                    'status': 'discussing',
                    'public_xp': selected_xp
                })
            else:
                # 理论上不应该发生，但作为备用处理
                print("警告: 没有找到狼人玩家！")
                random_player = random.choice(game_players)
                game['status'] = 'voting'
                game['public_xp'] = random_player.get('xp_content')
                save_json_data('games', games) # 重新加载games以获取更新后的状态
                message = "XP提交成功，游戏进入投票阶段"
                
                # 通知游戏状态更新
                await notify_game_update(xp_data.game_id, 'xp_phase_complete', {
                    'status': 'voting',
                    'public_xp': random_player.get('xp_content')
                })
        else:
            message = "XP提交成功，等待其他玩家"
            
            # 通知XP提交进度
            await notify_game_update(xp_data.game_id, 'xp_submitted', {
                'submitted_count': len([p for p in game_players if p.get('xp_content') and p.get('xp_content').strip()]),
                'total_count': len(game_players)
            })
        
        return {"message": message}
    
    except Exception as e:
        print(f"Error submitting XP: {e}")
        raise HTTPException(status_code=500, detail="XP提交失败")

@app.post("/api/game/vote")
async def vote_player(vote_data: GameVote, current_user: Dict = Depends(verify_token)):
    """投票"""
    votes = load_json_data('votes')
    # 检查是否已投票
    for v in votes:
        if v['game_id'] == vote_data.game_id and v['voter_id'] == current_user['id'] and v['round'] == vote_data.round and v['vote_type'] == vote_data.vote_type:
            raise HTTPException(status_code=400, detail="你已投票")
    vote = {
        "id": str(uuid.uuid4()),
        "game_id": vote_data.game_id,
        "voter_id": current_user['id'],
        "target_id": vote_data.target_id,
        "round": vote_data.round,
        "vote_type": vote_data.vote_type,
        "created_at": datetime.now().isoformat()
    }
    append_json_data('votes', vote)
    return {"vote_id": vote['id']}

@app.post("/api/game/discussion")
async def submit_discussion(discussion_data: DiscussionSubmit, current_user: Dict = Depends(verify_token)):
    """提交讨论"""
    discussion = {
        "id": str(uuid.uuid4()),
        "game_id": discussion_data.game_id,
        "user_id": current_user['id'],
        "content": discussion_data.content,
        "round": discussion_data.round,
        "created_at": datetime.now().isoformat()
    }
    append_json_data('discussions', discussion)
    return {"discussion_id": discussion['id']}

@app.post("/api/game/kill")
async def kill_player(kill_data: GameVote, current_user: Dict = Depends(verify_token)):
    """狼人夜晚投票击杀"""
    games = load_json_data('games')
    game = next((g for g in games if g['id'] == kill_data.game_id), None)
    if not game or game.get('status') != 'night':
        raise HTTPException(status_code=400, detail="当前不是夜晚时间")
    game_players = load_json_data('game_players')
    player = next((p for p in game_players if p['game_id'] == kill_data.game_id and p['user_id'] == current_user["id"]), None)
    if not player or not player.get('is_wolf') or not player.get('is_alive'):
        raise HTTPException(status_code=400, detail="您不是狼人或已死亡")
    # 检查是否已投票
    for v in load_json_data('votes'):
        if v['game_id'] == kill_data.game_id and v['voter_id'] == current_user["id"] and v['round'] == game['round'] and v['vote_type'] == 'night':
            raise HTTPException(status_code=400, detail="您已经投过票了")
    try:
        votes = load_json_data('votes')
        vote_id = str(uuid.uuid4())
        votes.append({
            "id": vote_id,
            "game_id": kill_data.game_id,
            "voter_id": current_user["id"],
            "target_id": kill_data.target_id,
            "round": game['round'],
            "vote_type": 'night',
            "created_at": datetime.now().isoformat()
        })
        save_json_data('votes', votes)
        # 检查是否所有存活狼人都已投票
        alive_wolves = [p for p in game_players if p.get('is_wolf') and p.get('is_alive')]
        vote_count = sum(1 for v in votes if v['game_id'] == kill_data.game_id and v['round'] == game['round'] and v['vote_type'] == 'night')
        if vote_count >= len(alive_wolves):
            from collections import Counter
            vote_results = Counter(v['target_id'] for v in votes if v['game_id'] == kill_data.game_id and v['round'] == game['round'] and v['vote_type'] == 'night')
            if vote_results:
                max_votes = vote_results.most_common(1)[0][1]
                top_voted = [v for v in vote_results if vote_results[v] == max_votes]
                if len(top_voted) == 1:
                    killed_player_id = top_voted[0]
                    killed_player = next((p for p in game_players if p['user_id'] == killed_player_id), None)
                    if killed_player:
                        killed_player['is_alive'] = False
                        killed_player['death_reason'] = 'killed'
                        save_json_data('game_players', game_players)
                        message = await check_game_end(game_players, kill_data.game_id, current_user["username"])
                        if message:
                                save_json_data('games', games)
                                return {"message": message}
                        game['status'] = 'submitting_xp'
                        game['round'] += 1
                        save_json_data('games', games)
                        for p in game_players:
                            p['xp_content'] = None
                        save_json_data('game_players', game_players)
                        message = "击杀成功，进入新一轮"
                    else:
                        message = "击杀失败，目标玩家不存在"
                else:
                    save_json_data('votes', [v for v in votes if v['game_id'] != kill_data.game_id or v['round'] != game['round'] or v['vote_type'] != 'night'])
                    message = "击杀投票平局，请重新投票"
            else:
                message = "投票成功"
        else:
            message = "投票成功"
        save_json_data('games', games)
        return {"message": message}
    except Exception as e:
        print(f"Error voting: {e}")
        raise HTTPException(status_code=500, detail="投票失败")

@app.post("/api/game/exit")
async def exit_game(exit_data: GameExit, current_user: Dict = Depends(verify_token)):
    """退出游戏"""
    game_players = load_json_data('game_players')
    player_to_exit = next((p for p in game_players if p['game_id'] == exit_data.game_id and p['user_id'] == current_user["id"]), None)
    
    if not player_to_exit:
        raise HTTPException(status_code=404, detail="未找到游戏玩家")
    
    try:
        # 将玩家标记为死亡（退出）
        player_to_exit['is_alive'] = False
        player_to_exit['death_reason'] = 'exited'
        save_json_data('game_players', game_players)
        
        # 检查游戏是否应该结束
        message = await check_game_end(game_players, exit_data.game_id, current_user["username"])
        if message:
            save_json_data('games', load_json_data('games')) # 重新加载games以获取更新后的状态
            return {"message": "已退出游戏", "game_terminated": True, "winner": message.split("，")[1] if "，" in message else None}
        
        save_json_data('games', load_json_data('games')) # 重新加载games以获取更新后的状态
        return {"message": "已退出游戏", "game_terminated": False}
    
    except Exception as e:
        print(f"Error exiting game: {e}")
        raise HTTPException(status_code=500, detail="数据库错误")

async def check_game_end(game_players: List[Dict], game_id: str, current_username: str) -> Optional[str]:
    """检查游戏是否结束并更新统计"""
    alive_players = [p for p in game_players if p.get('is_alive')]
    
    alive_wolves = [p for p in alive_players if p.get('is_wolf')]
    alive_villagers = [p for p in alive_players if not p.get('is_wolf')]
    
    print(f"游戏结束检查: 总玩家{len(game_players)}, 存活玩家{len(alive_players)}, 存活狼人{len(alive_wolves)}, 存活村民{len(alive_villagers)}")
    
    winner = None
    if len(alive_wolves) == 0:
        winner = "villagers"
        print(f"判定村民胜利: 狼人全部死亡")
    elif len(alive_wolves) >= len(alive_villagers):
        winner = "wolves"
        print(f"判定狼人胜利: 狼人数({len(alive_wolves)}) >= 村民数({len(alive_villagers)})")
    
    if winner:
        # 更新游戏状态
        games = load_json_data('games')
        game = next((g for g in games if g['id'] == game_id), None)
        if game:
            game['status'] = 'finished'
            game['winner'] = winner
            save_json_data('games', games) # 重新加载games以获取更新后的状态
        
        # 更新所有玩家的统计数据
            users = load_json_data('users')
        for player in game_players:
                username = next((u['username'] for u in users if u['id'] == player['user_id']), player['user_id']) # 假设用户ID就是用户名
                is_wolf = bool(player.get('is_wolf'))
                # 修正胜负判定逻辑
                if winner == "wolves":
                    is_winner = is_wolf  # 狼人胜利时，狼人获胜
                else:  # winner == "villagers"
                    is_winner = not is_wolf  # 村民胜利时，村民获胜
                    
                print(f"更新玩家 {username} 统计: is_wolf={is_wolf}, is_winner={is_winner}")
                update_player_stats(username, is_winner)
        if winner == "villagers":
            return "游戏结束，村民胜利"
        else:
            return "游戏结束，狼人胜利"
    
    return None

# Socket.IO事件处理
@sio.event
async def connect(sid, environ):
    print(f'Socket.IO用户连接: {sid}')

@sio.event
async def disconnect(sid):
    print(f'Socket.IO用户断开连接: {sid}')

@sio.event
async def join_room(sid, data):
    """加入房间事件"""
    room_code = data.get('room_code')
    if room_code:
        await sio.enter_room(sid, f"room_{room_code}")
        print(f'Socket.IO用户 {sid} 加入房间 {room_code}')
        # 通知房间内其他用户
        await sio.emit('user_joined', {'sid': sid}, room=f"room_{room_code}", skip_sid=sid)

@sio.event
async def leave_room(sid, data):
    """离开房间事件"""
    room_code = data.get('room_code')
    if room_code:
        await sio.leave_room(sid, f"room_{room_code}")
        print(f'Socket.IO用户 {sid} 离开房间 {room_code}')
        # 通知房间内其他用户
        await sio.emit('user_left', {'sid': sid}, room=f"room_{room_code}")

@sio.event
async def join_game(sid, data):
    """加入游戏事件"""
    game_id = data.get('game_id')
    if game_id:
        await sio.enter_room(sid, f"game_{game_id}")
        print(f'Socket.IO用户 {sid} 加入游戏 {game_id}')

@sio.event
async def game_update(sid, data):
    """游戏状态更新事件"""
    game_id = data.get('game_id')
    if game_id:
        # 广播游戏状态更新
        await sio.emit('game_state_changed', data, room=f"game_{game_id}")

# 辅助函数：通知房间更新
async def notify_room_update(room_code: str, event_type: str = 'room_updated'):
    """通知房间状态更新"""
    await sio.emit(event_type, {'room_code': room_code}, room=f"room_{room_code}")

# 辅助函数：通知游戏更新
async def notify_game_update(game_id: str, event_type: str = 'game_updated', data: dict = None):
    """通知游戏状态更新"""
    emit_data = {'game_id': game_id}
    if data:
        emit_data.update(data)
    await sio.emit(event_type, emit_data, room=f"game_{game_id}")

# 静态文件服务
@app.get("/")
async def read_index():
    """返回主页"""
    return FileResponse(get_frontend_file_path('index.html'))

@app.get("/xpwerewolf.js")
async def get_js():
    """返回JS文件"""
    return FileResponse(get_frontend_file_path('xpwerewolf.js'))

@app.get("/style.css")
async def get_css():
    """返回CSS文件"""
    return FileResponse(get_frontend_file_path('style.css'))

@app.get("/favicon.ico")
async def get_favicon():
    """返回图标文件"""
    # 返回一个空的图标响应，避免404
    from fastapi.responses import Response
    return Response(content="", media_type="image/x-icon")

# 挂载静态文件（作为备用）
app.mount("/assets", StaticFiles(directory=get_frontend_file_path('')), name="assets")

if __name__ == "__main__":
    import platform
    if platform.system().lower() == "linux":
        import subprocess
        script_path = os.path.join(os.path.dirname(__file__), "setup_venv.sh")
        if os.path.exists(script_path):
            print("检测到Linux环境，自动创建虚拟环境并安装依赖...")
            subprocess.run(["bash", script_path], check=True)
        else:
            print("未找到setup_venv.sh脚本，跳过虚拟环境创建。")
    else:
        print("Windows环境，跳过虚拟环境自动创建。请手动安装依赖。")
    print(f"服务器运行在端口 {PORT}")
    print(f"本地访问: http://localhost:{PORT}")
    print(f"网络访问: http://{HOST}:{PORT}")
    print("服务器启动中...")
    
    # 优雅关闭处理
    def signal_handler(signum, frame):
        print("\n正在关闭服务器...")
        # 删除所有json文件，模拟数据库关闭
        for file_path in DATA_FILES.values():
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"删除文件: {file_path}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        uvicorn.run(
            socket_app,
            host=HOST,
            port=PORT,
            log_level=SERVER_CONFIG["LOG_LEVEL"]
        )
    except KeyboardInterrupt:
        print("\n服务器关闭中...")
        # 删除所有json文件，模拟数据库关闭
        for file_path in DATA_FILES.values():
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"删除文件: {file_path}")
    finally:
        # 删除所有json文件，模拟数据库关闭
        for file_path in DATA_FILES.values():
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"删除文件: {file_path}")
