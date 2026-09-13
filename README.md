# AIOps 实验平台

这是一个面向运维与 SRE 场景的 AIOps 项目。仓库自带一套秒杀订单服务，Agent 会围绕它查询指标、日志、Kubernetes 状态和发布变更。平台主要提供两类能力：

- 运维对话与固定巡检：用自然语言查询业务和集群状态。
- 告警分析与处置：把 Alertmanager 通知聚合为 Incident，持续补充调查证据；需要回滚或扩容时，先由人工审批，再执行变更并复查结果。

项目包含业务、监控和智能运维三个部分。业务侧使用网关、Redis 和 MySQL；监控侧使用 Prometheus、Alertmanager、Grafana、Loki 和 Promtail；智能运维侧包含 Web 工作台、Agent 执行器、巡检引擎、变更监听和知识库服务。

## 在线演示

[打开 AIOps Web 工作台](https://luhao0209.github.io/AIops-platform/)
这是一个很简陋的展示页面

演示页保存了一组脱敏的数据快照，可以查看健康指标、运维对话、工具调用记录、知识库和历史告警分析。它不连接真实 Kubernetes 集群，也不会执行回滚、扩容等变更操作。

## 推荐部署方式：一键安装包

如果只是想把项目运行起来，建议使用仓库中的一键安装包，不需要逐个研究外层源码目录里的 YAML。

安装包目录：

```text
一键部署/
├── aiops-installer-20260901.1-linux-amd64.run
├── deployment.env.example
├── images/
│   ├── image-bundle.json
│   ├── business-images.tar
│   └── agent-images.tar
├── docs/
├── 交付清单.json
└── SHA256SUMS
```

`.run` 安装器内已经包含项目源码、Ansible Playbook、Kubernetes 清单和验收逻辑；两个镜像归档包含当前版本的业务与 AIOps 应用镜像。部署时仍需联网下载系统包和 Prometheus、MySQL、Redis 等第三方基础镜像

### 1. 准备机器

准备一台 Linux 控制机和四台 Ubuntu 服务器。控制机也可以直接使用其中的 master 节点。

每台目标服务器建议至少满足：

- 2 vCPU、3.4 GiB 内存、根目录 15 GiB 可用空间；
- 节点私网互通，并可通过 SSH 登录；
- 使用全新服务器，或使用此前由同一安装器创建的集群；
- 使用云服务器时，提前开放所需的安全组端口。

不要直接在已有其他业务、来源不明或仍有重要数据的 Kubernetes 集群上运行安装器。

### 2. 下载完整交付包

请从项目的 [Releases 页面](../../releases) 下载“一键部署”完整交付包并解压。不要只下载 GitHub 自动生成的 `Source code` 压缩包，因为其中不包含体积较大的应用镜像

开始安装前，请确认 `aiops-installer-20260901.1-linux-amd64.run` 与 `images/` 位于同一目录，并且 `images/` 中包含以下文件：

```text
images/
├── image-bundle.json
├── business-images.tar
└── agent-images.tar
```

如果缺少上述文件，请重新下载交付包。缺少镜像归档时，安装器可能改为现场构建，部署会更慢，也更依赖网络环境。

### 3. 生成部署配置

在 Linux 控制机进入安装目录：

```bash
cd 一键部署
chmod +x aiops-installer-20260901.1-linux-amd64.run

./aiops-installer-20260901.1-linux-amd64.run --verify-only
./aiops-installer-20260901.1-linux-amd64.run --init-config
```

编辑生成的 `deployment.env`，至少填写：

- 四台服务器的公网 IP、私网 IP 和 SSH 登录信息；
- `MODEL_API_BASE`、`MODEL_API_KEY` 和 `MODEL_NAME`；
- Web 管理员用户名和密码；
- `CONFIRM_FRESH_SERVERS=YES`。

模型接口需要兼容 OpenAI Chat Completions，请只填写 API 前缀，不要在末尾添加 `/chat/completions`。配置文件含有密码和模型密钥，不要提交到 GitHub。

### 4. 预检并安装

```bash
chmod 600 deployment.env

./aiops-installer-20260901.1-linux-amd64.run --check-config
./aiops-installer-20260901.1-linux-amd64.run --preflight-only
./aiops-installer-20260901.1-linux-amd64.run
```

如果安装包就在 master 节点上运行，通常应让 master 通过私网地址连接各节点：

```bash
./aiops-installer-20260901.1-linux-amd64.run --preflight-only --ssh-private
./aiops-installer-20260901.1-linux-amd64.run --ssh-private
```

安装器会依次完成环境检查、Kubernetes 初始化、应用镜像导入、业务与监控组件部署、AIOps 服务部署以及接口验收。任一步失败都会停止，可以排除问题后使用相同配置继续运行；它不会自动执行 `kubeadm reset`，也不会自动删除已有 PVC 或数据库。

### 5. 访问服务

部署成功后，安装器会输出实际地址。默认 NodePort 对应为：

- AIOps Web：`http://<AGENT_PUBLIC_IP>:30900`
- 秒杀业务：`http://<BIZ_PUBLIC_IP>:30080`
- Grafana：`http://<MONITOR_PUBLIC_IP>:32000`

更完整的配置项、重跑规则和验收边界见 [一键部署交付说明](一键部署/docs/一键部署交付说明.md)。

## 源码目录

一键安装是推荐体验方式，外层源码用于阅读、二次开发和单组件调试：

```text
.
├── aiops-agent/                         # AIOps 平台源码
│   ├── server.py                        # Web 后端与平台 API
│   ├── web.html                         # 运维工作台前端
│   ├── aiops-agent-deploy.yaml          # Web 服务部署清单
│   ├── agent-executor/                  # Agent 执行器
│   │   ├── agent_app.py                 # 对话与告警分析入口
│   │   ├── alerting/                    # Incident、分析流程与复查调度
│   │   ├── tools/                       # 指标、日志、拓扑和变更工具
│   │   ├── memory/                      # 会话记忆与状态持久化
│   │   ├── guardrails/                  # 证据校验与安全约束
│   │   └── reliability/                 # SLI、SLO 与错误预算计算
│   ├── inspection-engine/               # 固定巡检任务
│   ├── change-watcher/                  # Kubernetes 变更监听
│   └── sop-service/                     # 运维知识库与检索服务
├── k8s-deploy/                          # Kubernetes、业务及监控配置
│   ├── aiops-biz/                       # 秒杀订单业务
│   │   ├── src/                         # 网关业务源码
│   │   ├── scripts/                     # 数据初始化与维护脚本
│   │   └── gateway-deploy.yaml          # 网关部署清单
│   ├── install_k8s.yaml                 # Kubernetes 安装 Playbook
│   ├── init_env.yaml                    # 节点环境初始化 Playbook
│   ├── prometheus.yml                   # Prometheus 采集配置
│   ├── rules.yaml                       # 告警规则
│   ├── alertmanager.yaml                # 告警通知配置
│   ├── monitor-native.yaml              # Prometheus 与 Grafana 部署
│   ├── loki-native.yaml                 # Loki 部署
│   ├── promtail-native.yaml             # 容器日志采集
│   ├── node-exporter.yaml               # 节点指标采集
│   ├── kube-state-metrics.yaml          # Kubernetes 对象指标采集
│   ├── mysql-native.yaml                # MySQL 部署
│   └── redis-native.yaml                # Redis 部署
└── 一键部署/                            # 推荐的一键交付包
```

源码目录中的清单用于开发调试。修改源码后，需要重新构建对应镜像并更新清单；只想运行项目时，直接使用一键安装包即可。

## 项目边界

这是一个用于学习和验证 AIOps 设计的实验平台，不是生产运维系统。部署前请更换所有密码与模型密钥，限制 NodePort 和 SSH 的访问范围，并在独立环境中验证资源占用和变更操作。
