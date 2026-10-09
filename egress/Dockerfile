FROM node:22.22.2-alpine
COPY egress.mjs allowlist /etc/egress/
# 和 relogin 同一个 uid，才能读属主 10790、权限 0400 的令牌文件
USER 10790
CMD ["node", "/etc/egress/egress.mjs"]
