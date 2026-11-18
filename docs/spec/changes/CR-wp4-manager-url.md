# CR-wp4-manager-url: `MANAGER_URL` var and `settings.manager_url`

**From:** WP-4 **Affects:** WP-7 (deploy docs), WP-5 (settings page may show it) **Status:** informational

`dashboard.config.auth.sso.manager_url` must be the manager's own https origin. `05-manager.md` §1 lists no var
for it. The Worker therefore accepts an optional `MANAGER_URL` var (filled by `deploy.sh`) and otherwise records
the origin of the first authenticated admin request in `settings.manager_url`. Until known, dashboards are
compiled without `auth.sso` (and a warning). No contract change; `05-manager.md` §1 could list the var.
