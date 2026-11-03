# superagent-test

## DES 加密工具类

`src/utils/des.js` 提供基于 Node.js `crypto` 的 DES 加解密工具，支持 CBC/ECB 模式、PKCS#7 填充以及 Base64/Hex 编码。

> **安全提示**：DES 密钥只有 56 位，已不再安全，仅建议用于兼容仍要求 DES 的旧系统。新项目请使用 AES。
>
> 出于环境兼容性考虑，实现内部使用 Node.js 内置的 3DES，并以三个相同的 8 字节密钥调用；这在数学上等价于单 DES（`E_K(D_K(E_K(P))) === E_K(P)`），已通过标准 DES 测试向量验证。

### 使用

```js
const { DesUtil } = require('./src/utils/des');

const key = '12345678'; // 必须是 8 字节
const iv = '87654321'; // CBC 模式需要 8 字节 IV

const encrypted = DesUtil.encrypt('你好，DES', key, { iv });
const decrypted = DesUtil.decrypt(encrypted, key, { iv });
```

### API

- `DesUtil.encrypt(plaintext, key, options?)` → Base64/Hex 字符串
  - `plaintext`：`string`（UTF-8）或 `Buffer`
  - `key`：8 字节 `string` 或 `Buffer`
  - `options.mode`：`'cbc'`（默认）或 `'ecb'`
  - `options.iv`：CBC 模式必填，8 字节 `string` 或 `Buffer`
  - `options.padding`：`'pkcs7'`（默认）或 `'none'`
  - `options.outputEncoding`：`'base64'`（默认）或 `'hex'`
- `DesUtil.decrypt(ciphertext, key, options?)` → UTF-8 字符串
  - `ciphertext`：Base64/Hex 字符串或 `Buffer`
  - `options.inputEncoding`：`'base64'`（默认）或 `'hex'`
  - 其余参数与 `encrypt` 相同

模块同时导出 `encrypt` 和 `decrypt` 两个便捷函数：

```js
const { encrypt, decrypt } = require('./src/utils/des');
```

### 测试

```bash
npm test
```
