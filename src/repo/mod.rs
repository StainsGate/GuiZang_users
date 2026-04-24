/// 用户凭证（密码哈希、登录失败计数等）数据访问层。
pub mod credentials;
/// 幂等记录数据访问层。
pub mod idempotency;
/// 权限相关数据访问层。
pub mod permissions;
/// 刷新令牌数据访问层。
pub mod refresh_tokens;
/// 角色与关联关系数据访问层。
pub mod roles;
/// 用户主体数据访问层。
pub mod users;
