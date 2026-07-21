# GuGu Xcore

GuGu Xcore 是 GuGu 生态使用的 Xray-core fork，主要用于 `gugu-agent` 的 embedded Xray-core 构建。普通 GuGu 用户通常不需要直接安装或运行本仓库。

当前 GuGu Xcore 发布：`v0.1`

## 仓库关系

| 仓库 | 作用 |
|------|------|
| [`xzyone/gugu`](https://github.com/xzyone/gugu) | 主控面板 |
| [`xzyone/gugu-agent`](https://github.com/xzyone/gugu-agent) | 远程服务器 Agent |
| [`xzyone/gugu-xcore`](https://github.com/xzyone/gugu-xcore) | Agent embedded 模式使用的 Xray-core fork |

## 这个仓库做什么

- 保留 Xray-core 上游能力和协议实现。
- 为 GuGu Agent embedded 模式提供可控的 Xray-core 依赖。
- 用独立 tag 配合 `gugu-agent` 发布流程构建远程节点二进制和镜像。
- 保留上游 MPL-2.0 许可和归属说明。

## 不做什么

- 不替代 GuGu 主控。
- 不提供 GuGu Web UI。
- 不单独负责远程服务器生命周期管理。
- 不接管主控入口的 Nginx / HTTPS / SSL。

如果你只是部署 GuGu，请从主控仓库开始：

```text
https://github.com/xzyone/gugu
```

## 与 Agent 的关系

`gugu-agent` 的 `go.mod` 使用相对路径引用本仓库：

```text
replace github.com/xtls/xray-core => ../gugu-xcore
```

因此本地构建 Agent 时建议保持如下目录结构：

```text
/home/xzy/apps
  ├── gugu-agent
  └── gugu-xcore
```

然后在 `gugu-agent` 中构建：

```bash
cd ../gugu-agent
go test ./...
go build -trimpath -ldflags="-s -w" -o build/gugu-agent ./cmd/gugu-agent
```

Docker 构建 Agent 时也会把本仓库作为额外 build context：

```bash
docker build \
  --build-context xray-core-fork=../gugu-xcore \
  -t gugu-agent:test ../gugu-agent
```

## 直接编译 Xray

如果需要单独构建 Xray binary：

```bash
CGO_ENABLED=0 go build \
  -o xray \
  -trimpath \
  -buildvcs=false \
  -ldflags="-s -w -buildid=" \
  -v ./main
```

可复现构建示例：

```bash
CGO_ENABLED=0 go build \
  -o xray \
  -trimpath \
  -buildvcs=false \
  -gcflags="all=-l=4" \
  -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" \
  -v ./main
```

## 上游同步

本仓库基于 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)。同步上游时应保留：

- 上游 license。
- 上游 copyright / attribution。
- GuGu 侧必要的 tag、构建说明和发布关系。

建议同步流程：

```bash
git remote add upstream https://github.com/XTLS/Xray-core.git
git fetch upstream
git merge upstream/main
go test ./...
```

如同步导致 Agent 编译或 embedded 模式行为变化，需要同时在 `gugu-agent` 验证。

## 发布

GuGu Xcore 使用独立 tag 发布，例如：

```bash
git tag v0.1
git push origin v0.1
```

发布后，`gugu-agent` 可在构建流程中固定对应的 Xcore ref，并生成新的 Agent Release。

## 给使用者的入口

大多数使用者只需要这些入口：

- 主控安装：[xzyone/gugu](https://github.com/xzyone/gugu)
- Agent 发布：[xzyone/gugu-agent/releases](https://github.com/xzyone/gugu-agent/releases)
- Xcore 发布：[xzyone/gugu-xcore/releases](https://github.com/xzyone/gugu-xcore/releases)
- Xray 上游文档：[XTLS/Xray-core](https://github.com/XTLS/Xray-core)

## 版本记录

### v0.1 (2026-07-19)

- 第一个 GuGu Xcore 独立发布。
- 作为 GuGu Agent embedded 模式的 Xray-core fork 发布入口。
- 保留上游 MPL-2.0 license 与 attribution。

## 上游归属

GuGu Xcore 基于 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)。Xray-core 由 XTLS 社区维护，原始项目、协议说明、安装方式和生态工具请参考上游仓库。

## 许可证

[Mozilla Public License Version 2.0](LICENSE)
