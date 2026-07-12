FROM ghcr.io/astral-sh/uv:python3.13-trixie@sha256:c19cda33630429e3aa41fd919c240b167e4ef8abcbaf76f6c4405bedd66cd36c

COPY ./cairn/pyproject.toml /cairn/pyproject.toml
COPY ./cairn/uv.lock /cairn/uv.lock
WORKDIR /cairn
RUN uv sync --frozen --no-install-project -i https://mirrors.aliyun.com/pypi/simple/

COPY ./cairn /cairn
RUN uv sync --frozen -i https://mirrors.aliyun.com/pypi/simple/

ENV TZ=Asia/Shanghai
