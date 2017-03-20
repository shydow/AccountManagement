# AccountManagement
fast and simple account Management service for multi-tenant application

# 架构选择
1. Spring Boot：事实的标准，默认大于配置的方式更易于开发
2. JPA：改用JPA而非MyBatis的原因主要是因为懒

# 核心处理逻辑
### 签名和验签
签名和验签采用RSA的公私钥，使用私钥签名，使用公钥验签。设置am的公私钥对、tenant的公私钥对（平台仅负责生成，不保存tenant私钥）
todo: 考虑后期增加对EC、HMAC等的支持。

### 加密
加密采用AES的对称加密算法，由平台生成加密密钥，在传输过程中使用该加密密钥进行加密处理
todo：考虑增加对RSA的支持

### 签名和验签
签名和验签采取RSA的公私钥，使用私钥签名，使用公钥验签。tenant之间可以通过平台查询对方的公钥。

### 密钥交换
使用DH算法执行密钥交换过程中的密钥生成逻辑，确保平台与租户之间以及租户之间的加密密钥的安全性