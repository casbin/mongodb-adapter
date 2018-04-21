[request_definition]
r = tenant, sub, obj, act, service

[policy_definition]
p =tenant, sub, obj, act, service, eft

[role_definition]
g = _, _

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = r.tenant == p.tenant && g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*") && (r.service == p.service || p.service == "*")
