# 使用官方 Node.js 镜像作为基础镜像
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 安装 sqlite3 编译所需的依赖
RUN apk add --no-cache python3 make g++

# 复制 package.json 和 package-lock.json（如果存在）
COPY package*.json ./

# 安装依赖
RUN npm ci --only=production

# 清理编译依赖以减小镜像大小
RUN apk del python3 make g++

# 复制应用程序代码
COPY app.js .

# 创建数据目录
RUN mkdir -p /app/data

# 设置环境变量默认值
ENV NODE_ENV=production \
    PORT=3000 \
    BASE_URL=https://g4f.dev \
    AUTH_TOKENS=sk-default,sk-false \
    PROXY_URL=https://proxy.mengze.vip/proxy/ \
    PROXY_ENCODE=false \
    MAX_KEYS=3 \
    KEY_EXPIRY_MINUTES=60 \
    MODEL_CACHE_DAYS=7 \
    USE_SQLITE=true

# 暴露端口
EXPOSE 3000

# 设置健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {r.statusCode === 200 ? process.exit(0) : process.exit(1)})"

# 运行应用
CMD ["node", "app.js"]
