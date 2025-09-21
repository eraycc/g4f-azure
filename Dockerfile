FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY app.py .

# 创建数据目录
RUN mkdir -p /app/data

# 设置环境变量
ENV BASE_URL=https://g4f.dev
ENV AUTH_TOKENS=sk-default,sk-false
ENV FILE_PROXY_URL=https://proxy.mengze.vip/proxy/
ENV FILE_PROXY_ENCODE=false
ENV MAX_KEYS=3
ENV KEY_EXPIRE_MINUTES=60
ENV MODEL_CACHE_DAYS=7
ENV USE_SQLITE=true
ENV PYTHONUNBUFFERED=1

# 暴露端口
EXPOSE 8000

# 启动应用
CMD ["python", "app.py"]
