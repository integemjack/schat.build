# schat.build

[Ireoo/Secret-Chat](https://github.com/Ireoo/Secret-Chat) 的独立 CI 仓库：GitHub Actions 在这里 clone 源仓库，把四个端各编译成独立应用包，并构建 Docker 镜像，产物统一发布到本仓库的 Releases。

## 产物

| 任务 | Runner | 产物 |
|---|---|---|
| iOS | macos-26（Liquid Glass / 部署目标 26.2 需 Xcode 26） | 未签名 IPA |
| Android | ubuntu | debug APK（可装）+ 未签名 release APK |
| Desktop | macos / ubuntu / windows 矩阵 | dmg / nsis exe / AppImage |
| Native Desktop | macos / ubuntu / windows 矩阵 | SwiftUI `.app.zip` / WinUI zip / GTK4 tar.gz |
| Go server | ubuntu | `schat-server-linux-amd64` 单二进制 |
| Docker | ubuntu | `ghcr.io/integemjack/schat-server`（nodeServer 生产服务器镜像） |

## 触发

- 手动：Actions → **Build All** 或 **Native Desktop** → Run workflow，可填源分支
- 自动：push 到本仓库 `main`（即修改 workflow 本身）

`Build All` Release 标签格式：`<源分支>-b<run 编号>`，如 `v9.1-b3`。
`Native Desktop` Release 标签格式：`native-desktop-<源分支>-b<run 编号>`。

## 必需 Secret

| 名称 | 用途 |
|---|---|
| `SRC_REPO_TOKEN` | 有 Ireoo/Secret-Chat 读权限的 PAT，供 actions/checkout clone 私有源仓库 |

Docker 推送用内置 `GITHUB_TOKEN`（`packages: write`），无需额外配置。
