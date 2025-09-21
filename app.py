import os
import json
import time
import random
import sqlite3
import hashlib
import base64
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from urllib.parse import quote, unquote
import asyncio
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import StreamingResponse, JSONResponse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import uvicorn

# 环境变量配置
BASE_URL = os.getenv("BASE_URL", "https://g4f.dev")
AUTH_TOKENS = os.getenv("AUTH_TOKENS", "sk-default,sk-false").split(",")
FILE_PROXY_URL = os.getenv("FILE_PROXY_URL", "https://proxy.mengze.vip/proxy/")
FILE_PROXY_ENCODE = os.getenv("FILE_PROXY_ENCODE", "false").lower() == "true"
MAX_KEYS = int(os.getenv("MAX_KEYS", "3"))
KEY_EXPIRE_MINUTES = int(os.getenv("KEY_EXPIRE_MINUTES", "60"))
MODEL_CACHE_DAYS = int(os.getenv("MODEL_CACHE_DAYS", "7"))
USE_SQLITE = os.getenv("USE_SQLITE", "true").lower() == "true"

# User-Agent配置
USER_AGENTS = {
    "chrome_windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "chrome_mac": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "firefox_windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "safari_mac": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "edge_windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
}

class AzureKeyManager:
    def __init__(self):
        self.keys = {}  # {key: {"ua_name": str, "created_at": datetime, "ua": str}}
        self.models_cache = None
        self.models_cache_time = None
        
        if USE_SQLITE:
            self.init_db()
    
    def init_db(self):
        """初始化SQLite数据库"""
        self.conn = sqlite3.connect("azure_keys.db", check_same_thread=False)
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS azure_keys (
                key TEXT PRIMARY KEY,
                ua_name TEXT,
                ua TEXT,
                created_at TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS models_cache (
                id INTEGER PRIMARY KEY,
                data TEXT,
                created_at TIMESTAMP
            )
        ''')
        self.conn.commit()
        self.load_keys_from_db()
    
    def load_keys_from_db(self):
        """从数据库加载密钥"""
        if not USE_SQLITE:
            return
        cursor = self.conn.cursor()
        cursor.execute("SELECT key, ua_name, ua, created_at FROM azure_keys")
        for row in cursor.fetchall():
            key, ua_name, ua, created_at = row
            self.keys[key] = {
                "ua_name": ua_name,
                "ua": ua,
                "created_at": datetime.fromisoformat(created_at)
            }
    
    def save_key_to_db(self, key: str, ua_name: str, ua: str):
        """保存密钥到数据库"""
        if not USE_SQLITE:
            return
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO azure_keys (key, ua_name, ua, created_at) VALUES (?, ?, ?, ?)",
            (key, ua_name, ua, datetime.now().isoformat())
        )
        self.conn.commit()
    
    def delete_key_from_db(self, key: str):
        """从数据库删除密钥"""
        if not USE_SQLITE:
            return
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM azure_keys WHERE key = ?", (key,))
        self.conn.commit()
    
    def clean_expired_keys(self):
        """清理过期的密钥"""
        now = datetime.now()
        expired_keys = []
        for key, info in self.keys.items():
            if now - info["created_at"] > timedelta(minutes=KEY_EXPIRE_MINUTES):
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.keys[key]
            self.delete_key_from_db(key)
    
    async def get_or_create_key(self) -> tuple[str, str]:
        """获取或创建Azure API密钥"""
        self.clean_expired_keys()
        
        # 如果有可用的密钥，随机返回一个
        if self.keys:
            key = random.choice(list(self.keys.keys()))
            return key, self.keys[key]["ua"]
        
        # 如果密钥数量不足，创建新的
        if len(self.keys) < MAX_KEYS:
            return await self.create_new_key()
        
        # 如果达到最大数量但都过期了，创建新的
        return await self.create_new_key()
    
    async def create_new_key(self) -> tuple[str, str]:
        """创建新的Azure API密钥"""
        ua_name = random.choice(list(USER_AGENTS.keys()))
        ua = USER_AGENTS[ua_name]
        
        async with httpx.AsyncClient() as client:
            # 获取公钥
            response = await client.post(
                f"{BASE_URL}/backend-api/v2/public-key",
                headers={"User-Agent": ua}
            )
            if response.status_code != 200:
                response = await client.get(
                    f"{BASE_URL}/backend-api/v2/public-key",
                    headers={"User-Agent": ua}
                )
            
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail="Failed to get public key")
            
            key_data = response.json()
            
            # 构造payload
            payload = {
                "data": key_data["data"],
                "user": key_data.get("user", "error"),
                "timestamp": int(time.time() * 1000),
                "user_agent": ua
            }
            
            # RSA加密
            public_key = serialization.load_pem_public_key(
                key_data["public_key"].encode(),
                backend=default_backend()
            )
            
            encrypted = public_key.encrypt(
                json.dumps(payload).encode(),
                padding.PKCS1v15()
            )
            
            azure_key = base64.b64encode(encrypted).decode()
            
            # 保存密钥
            self.keys[azure_key] = {
                "ua_name": ua_name,
                "ua": ua,
                "created_at": datetime.now()
            }
            self.save_key_to_db(azure_key, ua_name, ua)
            
            return azure_key, ua
    
    async def get_models(self) -> Dict:
        """获取模型列表"""
        # 检查缓存
        if self.models_cache and self.models_cache_time:
            if datetime.now() - self.models_cache_time < timedelta(days=MODEL_CACHE_DAYS):
                return self.models_cache
        
        # 获取新的模型列表
        azure_key, ua = await self.get_or_create_key()
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BASE_URL}/api/Azure/models",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {azure_key}",
                    "User-Agent": ua
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to get models")
            
            models_data = response.json()
            
            # 转换为OpenAI格式
            openai_models = {
                "object": "list",
                "data": []
            }
            
            for model in models_data.get("data", []):
                openai_model = {
                    "id": model["id"],
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "",
                    "image": model.get("image", False),
                    "vision": model.get("vision", False),
                    "audio": model.get("audio", False)
                }
                openai_models["data"].append(openai_model)
            
            # 缓存模型列表
            self.models_cache = openai_models
            self.models_cache_time = datetime.now()
            
            # 保存到数据库
            if USE_SQLITE:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM models_cache")
                cursor.execute(
                    "INSERT INTO models_cache (data, created_at) VALUES (?, ?)",
                    (json.dumps(openai_models), datetime.now().isoformat())
                )
                self.conn.commit()
            
            return openai_models

# 初始化
key_manager = AzureKeyManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时的操作
    yield
    # 关闭时的操作
    if USE_SQLITE and hasattr(key_manager, 'conn'):
        key_manager.conn.close()

app = FastAPI(lifespan=lifespan)

def verify_token(authorization: Optional[str] = Header(None)) -> bool:
    """验证授权令牌"""
    if not authorization:
        return False
    
    if not authorization.startswith("Bearer "):
        return False
    
    token = authorization.replace("Bearer ", "")
    return token in AUTH_TOKENS

def process_file_url(url: str) -> str:
    """处理文件URL，添加代理"""
    if not url:
        return url
    
    # 处理相对路径
    if url.startswith("/media/") or url.startswith("/thumbnail/"):
        url = f"{BASE_URL}{url}"
    
    # 添加代理
    if FILE_PROXY_ENCODE:
        return f"{FILE_PROXY_URL}{quote(url)}"
    else:
        return f"{FILE_PROXY_URL}{url}"

def process_content_for_media(content: str) -> str:
    """处理内容中的媒体链接"""
    # 处理 src="/media/ 和 src="/thumbnail/
    pattern = r'src="(/(?:media|thumbnail)/[^"]+)"'
    
    def replace_src(match):
        path = match.group(1)
        full_url = f"{BASE_URL}{path}"
        proxied_url = process_file_url(full_url)
        return f'src="{proxied_url}"'
    
    return re.sub(pattern, replace_src, content)

@app.get("/v1/models")
async def get_models(authorization: Optional[str] = Header(None)):
    """获取模型列表"""
    if not verify_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        models = await key_manager.get_models()
        return JSONResponse(content=models)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/chat/completions")
async def chat_completions(request: Request, authorization: Optional[str] = Header(None)):
    """处理聊天完成请求"""
    if not verify_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        body = await request.json()
        messages = body.get("messages", [])
        stream = body.get("stream", False)
        model = body.get("model", "")
        
        # 获取模型信息
        models = await key_manager.get_models()
        model_info = None
        for m in models["data"]:
            if m["id"] == model:
                model_info = m
                break
        
        if not model_info:
            raise HTTPException(status_code=400, detail=f"Model {model} not found")
        
        # 获取Azure密钥
        azure_key, ua = await key_manager.get_or_create_key()
        
        # 处理图片生成模型
        if model_info.get("image", False):
            return await handle_image_generation(messages, model, stream, azure_key, ua)
        
        # 处理音频模型
        if model_info.get("audio", False):
            return await handle_audio_chat(body, stream, azure_key, ua)
        
        # 处理普通聊天模型
        return await handle_normal_chat(body, stream, azure_key, ua)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def handle_image_generation(messages: List, model: str, stream: bool, azure_key: str, ua: str):
    """处理图片生成"""
    # 获取最后一个用户消息
    prompt = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            prompt = msg.get("content", "")
            break
    
    if not prompt:
        raise HTTPException(status_code=400, detail="No user prompt found")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/api/Azure/images/generations",
            json={"model": model, "prompt": prompt},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {azure_key}",
                "User-Agent": ua
            }
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
        
        result = response.json()
        
        # 格式化响应
        image_url = result["data"][0]["url"] if result.get("data") else ""
        proxied_url = process_file_url(image_url)
        
        formatted_content = f"""## 图片已生成成功
### 提示词如下：{prompt}
### 绘图模型：{model}
### 绘图结果如下：
![{prompt}]({proxied_url})"""
        
        # 构造OpenAI格式响应
        if stream:
            return StreamingResponse(
                generate_stream_response(formatted_content, model),
                media_type="text/event-stream"
            )
        else:
            return JSONResponse(content={
                "id": f"chatcmpl-{generate_id()}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": formatted_content
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0
                }
            })

async def handle_audio_chat(body: Dict, stream: bool, azure_key: str, ua: str):
    """处理音频聊天"""
    async with httpx.AsyncClient(timeout=60.0) as client:
        if stream:
            async with client.stream(
                "POST",
                f"{BASE_URL}/api/Azure/chat/completions",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {azure_key}",
                    "User-Agent": ua
                }
            ) as response:
                return StreamingResponse(
                    process_audio_stream(response),
                    media_type="text/event-stream"
                )
        else:
            response = await client.post(
                f"{BASE_URL}/api/Azure/chat/completions",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {azure_key}",
                    "User-Agent": ua
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            
            result = response.json()
            
            # 处理音频链接
            if result.get("choices") and result["choices"][0].get("message"):
                content = result["choices"][0]["message"].get("content", "")
                result["choices"][0]["message"]["content"] = process_content_for_media(content)
            
            return JSONResponse(content=result)

async def handle_normal_chat(body: Dict, stream: bool, azure_key: str, ua: str):
    """处理普通聊天"""
    async with httpx.AsyncClient(timeout=60.0) as client:
        if stream:
            async with client.stream(
                "POST",
                f"{BASE_URL}/api/Azure/chat/completions",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {azure_key}",
                    "User-Agent": ua
                }
            ) as response:
                return StreamingResponse(
                    forward_stream(response),
                    media_type="text/event-stream"
                )
        else:
            response = await client.post(
                f"{BASE_URL}/api/Azure/chat/completions",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {azure_key}",
                    "User-Agent": ua
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            
            return JSONResponse(content=response.json())

@app.post("/v1/images/generations")
async def images_generations(request: Request, authorization: Optional[str] = Header(None)):
    """处理图片生成请求"""
    if not verify_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        body = await request.json()
        model = body.get("model", "flux.1-kontext-pro")
        prompt = body.get("prompt", "")
        
        # 获取Azure密钥
        azure_key, ua = await key_manager.get_or_create_key()
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BASE_URL}/api/Azure/images/generations",
                json={"model": model, "prompt": prompt},
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {azure_key}",
                    "User-Agent": ua
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            
            result = response.json()
            
            # 处理图片URL
            if result.get("data"):
                for item in result["data"]:
                    if item.get("url"):
                        item["url"] = process_file_url(item["url"])
            
            return JSONResponse(content=result)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def forward_stream(response):
    """转发流式响应"""
    async for line in response.aiter_lines():
        if line:
            yield f"{line}\n\n"

async def process_audio_stream(response):
    """处理音频流式响应"""
    async for line in response.aiter_lines():
        if line:
            # 处理音频链接
            if 'src="' in line:
                line = process_content_for_media(line)
            yield f"{line}\n\n"

async def generate_stream_response(content: str, model: str):
    """生成流式响应"""
    completion_id = f"chatcmpl-{generate_id()}"
    
    # 发送内容
    chunk = {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": None
        }]
    }
    yield f"data: {json.dumps(chunk)}\n\n"
    
    # 发送结束
    chunk["choices"][0]["delta"]["content"] = ""
    chunk["choices"][0]["finish_reason"] = "stop"
    yield f"data: {json.dumps(chunk)}\n\n"
    yield "data: [DONE]\n\n"

def generate_id():
    """生成随机ID"""
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:16]

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
