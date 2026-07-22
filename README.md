# schat.build

[Ireoo/Secret-Chat](https://github.com/Ireoo/Secret-Chat) 的独立 CI 仓库：GitHub Actions 在这里 clone 源仓库，把四个端各编译成独立应用包，并构建 Docker 镜像，产物统一发布到本仓库的 Releases。

## 产物

| 任务 | Runner | 产物 |
|---|---|---|
| iOS | macos-26（Liquid Glass / 部署目标 26.2 需 Xcode 26） | 未签名 IPA |
| Android | ubuntu | debug APK（可装）+ 未签名 release APK |
| Desktop（`build.yml` 调用 / `qt-desktop.yml` 独立派发） | macos-26 / windows / ubuntu | **mac = 原生 SwiftUI 客户端**(`desktop/macos`,arm64,Developer ID 真签+公证的 `.dmg` + 一键更新 `.zip`);**Windows/Linux = Qt6/QML**(`desktop/desktop-qt`,Win x64 NSIS 安装器、Linux x86_64+aarch64 的 `.deb` + AppImage) |
| Go server | ubuntu | `schat-server-linux-amd64` 单二进制 |
| Docker | ubuntu | `ghcr.io/integemjack/schat-server`（nodeServer 生产服务器镜像） |

## 触发

- 手动：Actions → **Build All**（含单架构 Qt 桌面端）或 **Qt Desktop**（全平台全架构桌面端打包）→ Run workflow，可填源分支
- 自动：push 到本仓库 `main`（即修改 workflow 本身）

`Build All` Release 标签格式：`<源分支>-b<run 编号>`，如 `v9.1-b3`。
`Qt Desktop` Release 标签格式：`qt-desktop-<源分支>-b<run 编号>`。

> 说明：桌面端取代已删除的 Electron 客户端。**mac 腿打的是原生 SwiftUI 客户端(`desktop/macos`)——
> 不再打 mac 的 Qt 版本**(Qt 的 macOS Universal2 腿已于 `9bc9989` 移除);流程 = 本地
> `scripts/{build-core,package-app}.sh` 原样上 CI,brew 装 openssl/opus/openh264/libsodium,
> 内嵌 dylib + 签名 + 公证。Windows 用 MSYS2 的 MinGW Qt6,Linux 在 Debian trixie 容器里用
> apt 的 Qt6 + pkg-config 链系统的 opus/openh264/libsodium。
> 旧的 `native-desktop.yml`(SwiftUI/WinUI3/GTK4 的 `desktop-native/` 线)引用已删路径,已移除。

## 必需 Secret

| 名称 | 用途 |
|---|---|
| `SRC_REPO_TOKEN` | 有 Ireoo/Secret-Chat 读权限的 PAT，供 actions/checkout clone 私有源仓库 |
| `RELEASE_SIGN_ED25519_KEY` | **官方更新分发签名私钥**（自建更新通道 Step 2）。base64url 无填充，32 字节 seed 或 64 字节完整 Ed25519 私钥均可。`release` job 用它对每个桌面/安卓资产按 `schat-release/1` 规范字节 Ed25519 签名。仅作 Actions secret 冷存，绝不入库；对应公钥 baked 进三端客户端 + chatserver 做上传时再验。 |
| `RELEASE_UPLOAD_TOKEN` | jiami.chat `POST /desktop/releases/upload` 的上传 Bearer 令牌，**必须等于** chatserver 的 `CHATSERVER_RELEASE_UPLOAD_TOKEN`。空 = 签名器只写 manifest 不上传。 |

Docker 推送用内置 `GITHUB_TOKEN`（`packages: write`），无需额外配置。

> **自建更新分发（Step 2）**：`build.yml` 的 `release` job 末尾追加了 4 个 `continue-on-error` 步骤——checkout 本仓库到 `_ci/`、装 Go、跑 `tools/release-signer`（对 `dist/**` 逐个资产签名 + POST 到 jiami.chat + 写出合并签名 manifest）、把 manifest 作为附加 release 资产上传（GitHub 兜底镜像仍是签名可验的）。签名器纯 Go 标准库、字节对齐 `docs/fixtures/update_distribution/vectors.json`；本地可 `cd tools/release-signer && go test ./...` 回归。**永不硬失败，绝不改 `qt-desktop.yml`。**
