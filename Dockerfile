# 使用轻量级 Python 3.8 镜像
FROM python:3.8-slim

# 设置工作目录
WORKDIR /app

# 1. 安装系统级依赖 (System Dependencies)
RUN apt-get update && apt-get install -y \
    bgpdump \
    nmap \
    build-essential \
    wget \
    git \
    zlib1g-dev \
    libbz2-dev \
    liblzma-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. 安装 Python 依赖 (Python Libraries)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    numpy \
    pandas \
    matplotlib \
    requests \
    ijson \
    beautifulsoup4 \
    python-dateutil \
    torch \
    altair \
    tqdm \
    scipy \
    ripe.atlas.cousteau \
    msgpack \
    py-radix \
    traceutils

# 3. 复制项目文件
# 将当前目录下所有文件复制到容器的 /app 目录
COPY . /app

# 4. 设置默认启动命令
CMD ["bash", "code/run_demo.sh"]
