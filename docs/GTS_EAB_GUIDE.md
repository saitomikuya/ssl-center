# Google Trust Services (GTS) EAB 凭据获取教程

Google Trust Services（简称 **GTS**）提供免费、稳定且支持多 SAN 与泛域名（`*.example.com`）的 ACME SSL 证书。首次向 GTS 注册 ACME 账户时，需要通过 Google Cloud 获取一次性的 **External Account Binding (EAB)** 凭据，即 **`keyId`（`eab_kid`）** 与 **`b64MacKey`（`eab_mac_key`）**。

> [!NOTE]
> 在 **ssl-center** 中，EAB 凭据仅在首次注册 ACME 账户时于内存中使用一次，注册成功后会立即销毁并仅加密保存生成的 `acme.key` 与 `account_uri`。后续签发、续期或跨节点迁移均不再需要 EAB。

---

## 获取步骤

### 第一步：打开 Google Cloud Shell

1. 登录 [Google Cloud Console](https://console.cloud.google.com/)。
2. 在顶部选择或新建一个项目（免费账户即可，无需启用付费账单即可使用 Public CA 配额，若提示需绑定结算账户请按控制台引导完成）。
3. 点击右上角的 **激活 Cloud Shell** 图标（`>_`），等待终端初始化完成。

### 第二步：指定项目并启用 Public CA API

在 Cloud Shell 中执行以下命令（将 `<你的PROJECT_ID>` 替换为实际项目 ID）：

```bash
gcloud config set project <你的PROJECT_ID>
gcloud services enable publicca.googleapis.com
```

### 第三步：生成 EAB Key ID 与 HMAC Key

- **生产环境（Production，签发正式受信任证书，推荐）**：

  ```bash
  gcloud publicca external-account-keys create
  ```

- **测试环境（Staging，仅用于测试，可选）**：

  ```bash
  gcloud beta publicca external-account-keys create \
    --endpoint-override=https://staging-publicca.googleapis.com/
  ```

### 第四步：填入 ssl-center 表单

执行上述命令后，终端会输出类似如下内容：

```yaml
Created an external account key
[b64MacKey: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
keyId: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy]
```

请按以下对应关系填入 **ssl-center →「凭据管理」→「添加 CA 账户」→「Google Trust Services (GTS)」→「EAB 首次注册」**：

| Cloud Shell 输出字段 | 对应 ssl-center 表单项 |
| --- | --- |
| `keyId` | **`EAB Key ID (eab_kid)`** |
| `b64MacKey` | **`EAB HMAC Key (eab_mac_key)`** |

同时在「环境」下拉框中选择与第三步一致的 **Production (正式证书)** 或 **Staging (测试环境)**，并填写真实可用域名的邮箱（请勿使用 `example.com` 等保留域名）。

---

## 常见问题与注意事项

1. **有效期与一次性限制**：通过 `gcloud` 创建的 EAB 凭据有效期为 **7 天**，且只能用于绑定 **1 个** ACME 账户；注册完成后即失效，如需再次新注册需重新执行 `create` 命令。
2. **备份与免 EAB 迁移**：注册成功后，建议在「凭据管理」点击该 GTS 账户的 **导出密钥** 备份 `acme.key` PEM。后续重建面板或迁移到新服务器时，只需选择 **「导入已有 acme.key (PEM)」** 即可在线校验并恢复同一 GTS 账户，无需重新申请 EAB。
3. **API 权限报错**：若执行 `gcloud publicca external-account-keys create` 提示权限不足，请确认当前账号拥有该项目的 `Public CA External Account Key Creator`（或 `Owner` / `Editor`）角色。
