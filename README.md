# 白皮书

# AuthBoot — 跨端全栈开发启动套件

> **Less Setup. More Building.**
> 
> 让开发者不必重复搭建基础设施，专注于产品本身和核心业务。

## 1. 产品概述

### 1.1 产品定位

AuthBoot 是一套面向个人开发者、独立开发者和小型开发团队的完整跨端全栈开发套件（Full-stack Starter Kit）。

提供开箱即用的服务端、Admin 管理平台，以及 Android、iOS、H5、微信小程序、抖音小程序、支付宝小程序等多端应用启动模板。

开发者可以根据项目需求直接启用对应模板，快速获得完整的应用基础架构和通用业务能力，无须每次从零开始搭建用户系统、登录认证、管理后台和客户端基础功能。

**AuthBoot 的核心目标：**

让开发者跳过重复的基础功能建设，直接进入产品开发阶段，只需关注具体业务本身。

### 1.2 目标用户

- 个人开发者、独立开发者。
- 2～10 人的小型开发团队。
- AI 工具及 AI Agent 产品开发者。
- APP、H5、Web、小程序开发者。
- SaaS 产品及创业团队。
- 需要快速交付项目的外包开发团队。

### 1.3 核心价值

| 价值 | 说明 |
| --- | --- |
| 开箱即用 | 提供可直接启动的服务端、管理后台和多端应用模板 |
| 减少重复开发 | 统一提供登录、注册、用户管理、权限等通用能力 |
| 多端支持 | 一套基础服务支持多个客户端 |
| 统一用户体系 | 不同客户端共享用户身份和用户数据 |
| 可扩展 | 支持二次开发，方便根据业务需求扩展 |
| 自主可控 | 支持源码级定制和私有化部署 |
| 专注业务 | 减少基础设施建设成本，把时间投入核心业务 |

---

## 2. 产品整体组成

AuthBoot 由三个核心部分组成：

1. Server：服务端基础能力。
2. Admin：Web 管理平台。
3. Client Starter Kits：多端应用启动模板。

### 2.1 Server（服务端）

基于 Go 构建的后端基础服务，为所有客户端提供统一的 API 和基础业务能力。

核心功能：

- 用户注册与登录。
- 用户身份认证与授权。
- Access Token / Refresh Token。
- Session 会话管理。
- 用户基础资料管理。
- 手机号、邮箱绑定。
- 第三方授权登录。
- 短信与邮件验证码。
- 产品与客户端管理。
- 用户状态管理。
- 管理员与 RBAC 权限管理。
- 内部 API。
- 登录日志与操作审计。

技术基础：

- Go
- MySQL
- Redis
- JWT
- RESTful API

### 2.2 Admin（管理平台）

提供统一的 Web 管理后台，用于管理产品、客户端、用户和系统配置。

核心功能：

| 模块 | 功能 |
| --- | --- |
| Dashboard | 系统概览 |
| Product Management | 产品管理 |
| Client Management | 客户端管理 |
| User Management | 用户列表、用户详情、状态管理 |
| Authentication | 登录方式配置 |
| Message Management | 短信模板、邮件模板 |
| Admin Management | 管理员管理 |
| Role Management | 角色与权限管理 |
| Session Management | 用户会话管理 |
| Audit Logs | 操作审计 |

Admin 同时提供可扩展的后台基础架构，开发者可以根据自身业务增加订单、会员、AI 任务等管理模块。

### 2.3 Client Starter Kits（多端应用模板）

AuthBoot 提供不同平台的应用启动模板，开发者可以根据目标平台直接启用。

| 平台 | 模板 | 主要用途 |
| --- | --- | --- |
| iOS | iOS Starter Kit | 原生 iOS APP |
| Android | Android Starter Kit | 原生 Android APP |
| H5 | H5 Starter Kit | 移动端 Web 应用 |
| 微信 | WeChat Mini Program | 微信小程序 |
| 抖音 | Douyin Mini Program | 抖音小程序 |
| 支付宝 | Alipay Mini Program | 支付宝小程序 |

各端模板统一对接 AuthBoot Server，使用相同的用户体系、认证规则和 API 规范。

---

## 3. APP Starter Kit（APP 启动套件）

APP Starter Kit 是 AuthBoot 的重要组成部分，主要解决 APP 开发过程中重复建设登录、注册、认证和个人中心的问题。

### 3.1 账号密码认证

| 功能 | 说明 |
| --- | --- |
| 邮箱注册 | 使用邮箱和密码注册 |
| 邮箱登录 | 使用邮箱和密码登录 |
| 用户名注册 | 使用用户名和密码注册 |
| 用户名登录 | 使用用户名和密码登录 |
| 手机号注册 | 使用手机号和密码注册 |
| 手机号登录 | 使用手机号和密码登录 |
| 密码重置 | 通过验证身份重置密码 |
| 修改密码 | 登录状态下修改密码 |

### 3.2 验证码认证

| 功能 | 说明 |
| --- | --- |
| 邮件验证码登录 | 使用邮箱验证码登录 |
| 邮件验证码注册 | 通过邮箱验证码完成注册 |
| 短信验证码登录 | 使用手机短信验证码登录 |
| 短信验证码注册 | 通过短信验证码完成注册 |
| 邮箱验证 | 验证邮箱有效性 |
| 手机号验证 | 验证手机号有效性 |

### 3.3 第三方授权登录

| 登录方式 | 说明 |
| --- | --- |
| Sign in with Apple | Apple 授权登录 |
| Google Login | Google 账号授权登录 |
| WeChat Login | 微信授权登录 |
| Facebook Login | Facebook 授权登录 |
| GitHub Login | GitHub 授权登录 |

第三方登录方式可以根据平台和目标市场进行选择和配置。

### 3.4 账号管理

- 多登录方式关联同一个用户。
- 第三方账号绑定与解绑。
- 邮箱绑定与解绑。
- 手机号绑定与解绑。
- 用户昵称和头像管理。
- 修改个人资料。
- 修改密码。
- 注销账号。
- 多设备登录管理。
- 退出登录。
- Token 自动刷新。
- Session 撤销与强制下线。

### 3.5 APP 基础页面模板

建议统一提供以下基础页面：

| 页面 | 功能 |
| --- | --- |
| Splash | APP 启动页 |
| Welcome | 欢迎页 |
| Login | 登录页 |
| Register | 注册页 |
| Forgot Password | 找回密码 |
| Verification | 邮箱/短信验证码 |
| OAuth Login | 第三方授权登录 |
| Home | 首页基础模板 |
| Profile | 个人中心 |
| Account Security | 账号安全 |
| Settings | 设置 |
| About | 关于应用 |

开发者可以在这些基础页面上直接扩展自己的业务 UI。

---

## 4. 统一用户体系

### 4.1 核心设计

AuthBoot 采用统一用户体系，一个 Product 可以拥有多个 Client。

```
                  AuthBoot
                      |
                  Product
                      |
          +-----------+-----------+
          |           |           |
        iOS          H5       微信小程序
          |           |           |
          +-----------+-----------+
                      |
                AuthBoot Server
                      |
                 User System
                      |
                   user_id
```

同一个 Product 下的不同客户端共享用户身份。

例如：

1. 用户在 iOS APP 注册，获得 user\_id = 10001。
2. 用户在 H5 登录，识别为同一个 user\_id。
3. 用户在微信小程序登录，仍然使用同一个 user\_id。

这样可以避免不同客户端分别维护用户表和登录体系。

### 4.2 身份与用户分离

用户身份与用户主体分开管理。

一个用户可以绑定多种登录身份：

- Username
- Email
- Mobile
- Apple
- Google
- WeChat
- GitHub

无论用户使用哪种方式登录，最终都映射到统一的 user\_id。

### 4.3 Token 与 Session

统一采用：

- Access Token：访问业务接口。
- Refresh Token：刷新访问令牌。
- Session：维护用户登录会话。
- JWT：承载用户身份信息。

业务系统可以使用 AuthBoot 签发的 user\_id 作为业务用户主键。

---

## 5. 产品架构

### 5.1 整体架构

```
                    Developer
                        |
                 AuthBoot Starter
                        |
        +---------------+----------------+
        |               |                |
      Server           Admin          Clients
        |               |                |
        |               |       +--------+--------+
        |               |       |        |        |
        |               |      iOS    Android     H5
        |               |       |
        |               |   Mini Programs
        |               |       |
        +---------------+-------+
                        |
                  AuthBoot API
                        |
              +---------+---------+
              |                   |
            MySQL               Redis
              |                   |
              +---------+---------+
                        |
                 Business Server
                        |
          +-------------+-------------+
          |             |             |
         AI           Payment       Business
        Tasks          Orders        Logic
```

### 5.2 业务边界

AuthBoot 负责通用基础能力：

- 用户身份。
- 登录认证。
- 用户资料。
- 客户端管理。
- Session 管理。
- 管理员权限。
- 基础管理后台。

具体业务由开发者自行实现：

- 会员与订阅。
- 商品与订单。
- 支付。
- 积分与权益。
- AI 模型调用。
- 图片生成。
- 文件处理。
- 业务数据与业务规则。

**AuthBoot 不限制开发者使用什么业务架构，也不要求业务逻辑必须写在 AuthBoot Server 中。**

---

## 6. 典型使用场景

### 6.1 AI 工具开发

开发者准备开发一个 AI 图片生成产品：

1. 启用 AuthBoot Server。
2. 启用 Admin。
3. 启用 iOS、Android 或 H5 模板。
4. 配置邮箱、Google 或 Apple 登录。
5. 开发 AI 图片生成接口。
6. 开发积分、会员和支付业务。

不需要重新实现用户注册、登录、Token 和个人中心。

### 6.2 APP 开发

开发者准备开发一个移动 APP：

1. 选择 iOS 或 Android 模板。
2. 配置 APP 基础信息。
3. 对接 AuthBoot Server。
4. 配置登录方式。
5. 开发首页及核心业务页面。

### 6.3 小程序开发

开发者准备开发微信小程序：

1. 启用微信小程序模板。
2. 配置微信 AppID 和 AppSecret。
3. 对接 AuthBoot Server。
4. 实现微信授权登录。
5. 直接开发小程序业务。

### 6.4 多端产品开发

一个产品同时拥有 APP、H5 和小程序：

- 多端共用一套服务端。
- 多端共用一套用户体系。
- 多端使用统一的认证 API。
- 多端使用统一的 user\_id。
- 不同客户端可以配置不同登录方式。

---

## 7. 技术设计原则

### 7.1 模块化

各部分尽量保持独立：

- Server 独立运行。
- Admin 独立部署。
- 各端 Client 独立构建。
- 业务服务独立扩展。

### 7.2 统一 API 规范

所有客户端使用统一的 API 设计规范。

包括：

- 统一请求格式。
- 统一响应格式。
- 统一错误码。
- 统一 Token 机制。
- 统一用户身份。
- 统一接口文档。

### 7.3 可扩展性

开发者可以：

- 修改源码。
- 增加业务模块。
- 扩展 API。
- 自定义页面。
- 替换第三方服务。
- 扩展登录方式。
- 增加新的客户端模板。

### 7.4 易部署

提供标准化部署方案：

- Docker Compose。
- MySQL 初始化。
- Redis 初始化。
- 环境变量配置。
- 服务启动脚本。
- 数据库迁移。
- 部署文档。

目标是尽量降低开发者从获取源码到成功运行的门槛。

---

## 8. 产品发展规划

### Phase 1：基础开发套件

目标：建立完整的基础开发能力。

- Go Server。
- Admin 管理后台。
- 用户注册与登录。
- 邮箱验证码登录。
- 短信验证码登录。
- 用户名密码登录。
- JWT / Refresh Token。
- Session 管理。
- RBAC 权限管理。
- 产品与客户端管理。
- 用户资料管理。
- 邮件和短信服务。

### Phase 2：跨端应用模板

目标：实现多平台快速启动。

- iOS Starter Kit。
- Android Starter Kit。
- H5 Starter Kit。
- 微信小程序 Starter Kit。
- 抖音小程序 Starter Kit。
- 支付宝小程序 Starter Kit。
- 统一登录与注册 UI。
- 统一用户资料 UI。
- 多端 Token 管理。

### Phase 3：第三方认证与生态

目标：完善国际化认证能力。

- Apple Login。
- Google Login。
- WeChat Login。
- GitHub Login。
- Facebook Login。
- 账号绑定与身份关联。
- Go SDK。
- TypeScript SDK。
- API 文档与接入示例。

### Phase 4：业务 Starter Kits

目标：从基础开发套件扩展到业务启动模板。

可探索的方向：

- Payment Starter Kit。
- Membership Starter Kit。
- AI Starter Kit。
- SaaS Starter Kit。
- File Storage Starter Kit。
- Notification Starter Kit。

这些属于后续可组合扩展的方向，不改变 AuthBoot 基础服务与业务服务解耦的原则。

---

## 9. 产品定位总结

AuthBoot 不是一个单纯的用户管理系统，也不是一个普通的 Admin 后台模板。

它是一套完整的跨端全栈开发启动套件。

它为开发者提前准备好：

- 服务端基础架构。
- Web 管理后台。
- APP 启动模板。
- H5 启动模板。
- 多平台小程序模板。
- 统一用户认证体系。
- 通用基础功能。

开发者只需要选择需要的平台和模板，配置基础信息，启动项目，然后专注于自己的核心业务。

> **AuthBoot — Less Setup. More Building.**
> 
> 不重复造基础设施，把时间留给真正有价值的产品和业务。
