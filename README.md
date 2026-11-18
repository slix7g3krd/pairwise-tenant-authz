# pairwise-tenant-authz

SaaS 多租户开放子账号后，越权就从单个接口扩散到整条链路：对象 id 直接查库，不校验 tenant；角色判断只看 `role=admin`，不看所属租户；父资源鉴权通过后，子资源默认继承权限；批量接口逐个 id 查询，没有统一租户过滤；分页和导出能跨租户捞数据；缓存 key 不含 tenant，A 租户读到 B 租户结果；软删除对象还能被 id 访问；邀请链接不绑定租户，能加入任意 workspace；服务间调用只验签名不验租户；错误信息泄露对象是否存在。security/tenant_authz.py 是核心，tests/test_tenant_authz.py 15个红。要修的是：对象级租户校验；角色与租户联合判断；子资源继承收紧；批量统一过滤；分页与导出隔离；缓存 key 含租户；软删除拒绝；邀请绑定；服务间租户透传；错误统一。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
