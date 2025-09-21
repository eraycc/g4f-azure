# Azure API Proxy

一个用于代理和管理 Azure API 请求的 Node.js 服务。

## 功能特性

- 自动管理和轮换 Azure API Keys
- 支持 OpenAI 标准 API 格式
- 支持聊天、图片生成和音频模型
- 自动处理媒体文件代理
- 支持流式和非流式响应
- 内置认证机制
- SQLite 或内存存储

## 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| PORT | 3000 | 服务端口 |
| BASE_URL | https://g4f.dev | 目标 API 地址 |
| AUTH_TOKENS | sk-default,sk-false | 认证令牌，逗号分隔 |
| PROXY_URL | https://proxy.mengze.vip/proxy/ | 文件代理地址 |
| PROXY_ENCODE | false | 是否对文件URL进行编码 |
| MAX_KEYS | 3 | 最大保存的 API Key 数量 |
| KEY_EXPIRY_MINUTES | 60 | API Key 过期时间（分钟） |
| MODEL_CACHE_DAYS | 7 | 模型列表缓存时间（天） |
| USE_SQLITE | true | 是否使用 SQLite 存储 |

## 快速开始

### 使用 Docker

```bash
# 构建镜像
docker build -t azure-api-proxy .

# 运行容器
docker run -d \
  --name azure-api-proxy \
  -p 3000:3000 \
  -e AUTH_TOKENS=sk-your-token \
  -v $(pwd)/data:/app/data \
  azure-api-proxy
