# (DWang) Cloud Service Provider must ensure that all the permissions need
# to be protected are listed here.
# If a permission is not found in this dict, it is in the charge of the
# enforcer and the enforcer will deny requests of that permission by default.
class SystemRules(object):
    def __init__(self, conf):
        self.sys_rules = {
        'keystone': {
        "csp_domain": ("domain_id:"+conf.oslo_policy.CSP_domain_id),
        'cru_check': 'rule:csp_domain',
        # service
        "list_services": "scope:domain",
        "get_service": "scope:domain",
        "create_service": "rule:csp_domain",
        "update_service": "rule:csp_domain",
        "delete_service": "rule:csp_domain",
        # endpoint
        "get_endpoint": "scope:domain",
        "list_endpoints": "scope:domain",
        "create_endpoint": "rule:csp_domain",
        "update_endpoint": "rule:csp_domain",
        "delete_endpoint": "rule:csp_domain",
        # domain
        "list_domains": "rule:csp_domain",
        "create_domain": "rule:csp_domain",
        "delete_domain": "rule:csp_domain",
        "get_domain": "domain_id:%(obj.domain.id)s",
        "update_domain": "domain_id:%(obj.domain.id)s",
        # project
        "list_projects": "domain_id:%(qStr.domain_id)s",
        "list_user_projects": "domain_id:%(qStr.domain_id)s",
        "create_project": "domain_id:%(reqBody.project.domain_id)s",
        "get_project": "domain_id:%(obj.project.domain_id)s",
        "update_project": "domain_id:%(obj.project.domain_id)s",
        "delete_project": "domain_id:%(obj.project.domain_id)s",
        # user    
        "list_users": "domain_id:%(qStr.domain_id)s",
        "create_user": "domain_id:%(reqBody.user.domain_id)s",
        "get_user": "domain_id:%(obj.user.domain_id)s",
        "update_user": "domain_id:%(obj.user.domain_id)s",
        "delete_user": "domain_id:%(obj.user.domain_id)s",
        "change_password": "domain_id:%(obj.user.domain_id)s",
        # group
        "get_group": "domain_id:%(obj.group.domain_id)s",
        "list_groups": "domain_id:%(qStr.domain_id)s",
        "list_groups_for_user": "domain_id:%(obj.user.domain_id)s",
        "create_group": "domain_id:%(reqBody.group.domain_id)s",
        "update_group": "domain_id:%(obj.group.domain_id)s",
        "delete_group": "domain_id:%(obj.group.domain_id)s",
        "remove_user_from_group": "domain_id:%(obj.group.domain_id)s",
        "check_user_in_group": "domain_id:%(obj.group.domain_id)s",
        "add_user_to_group": "domain_id:%(obj.group.domain_id)s",
        "list_users_in_group": "domain_id:%(obj.group.domain_id)s",
        "list_projects_for_groups": "",
        "list_domains_for_groups": "",
        # grant
        "check_grant": "domain_id:%(obj.domain.id)s or domain_id:%(obj.project.domain_id)s",
        "list_grants": "domain_id:%(obj.domain.id)s or domain_id:%(obj.project.domain_id)s",
        "create_grant": "domain_id:%(obj.domain.id)s or domain_id:%(obj.project.domain_id)s",
        "revoke_grant": "domain_id:%(obj.domain.id)s or domain_id:%(obj.project.domain_id)s",
        # system grant 
        "check_sys_grant": "rule:csp_domain",
        "list_sys_grants": "rule:csp_domain",
        "create_sys_grant": "rule:csp_domain",
        "revoke_sys_grant": "rule:csp_domain",
        # role assignment
        "list_role_assignments": "user_id:%(user.id)s or domain_id:%(qStr.domain_id)s or scope_project_id:%(qStr.project_id)s",
        # role
        "get_role": "domain_id:%(obj.role.domain_id)s",
        "list_roles": "domain_id:%(qStr.domain_id)s",
        "create_role": "domain_id:%(reqBody.role.domain_id)s",
        "update_role": "domain_id:%(obj.role.domain_id)s",
        "delete_role": "domain_id:%(obj.role.domain_id)s",
        # system role
        "get_sys_role": "rule:csp_domain",
        "list_sys_roles": "rule:csp_domain",
        "create_sys_role": "rule:csp_domain",
        "update_sys_role": "rule:csp_domain",
        "delete_sys_role": "rule:csp_domain",
        # policy
        "get_policy": "domain_id:%(obj.policy.domain_id)s",
        "list_policies": "domain_id:%(qStr.domain_id)s",
        "create_policy": "domain_id:%(reqBody.policy.domain_id)s",
        "update_policy": "domain_id:%(obj.policy.domain_id)s",
        "delete_policy": "domain_id:%(obj.policy.domain_id)s",
        # rule
        "get_rule": "domain_id:%(obj.policy.domain_id)s",
        "list_rules": "domain_id:%(qStr.domain_id)s",
        "create_rule": "domain_id:%(obj.policy.domain_id)s",
        "update_rule": "domain_id:%(obj.policy.domain_id)s",
        "delete_rule": "domain_id:%(obj.policy.domain_id)s",
        # token
        "check_token": "@",
        "validate_token": "@",
        "revocation_list": "@",
        "revoke_token": "@",
        # other
        "get_auth_catalog": "@",
        "get_auth_projects": "@",
        "get_auth_domains": "@",
        "list_revoke_events": "@"
        },
        # Glance Related
        'glance': {
        "csp_domain": ("domain_id:"+conf.oslo_policy.CSP_domain_id),
        "context_is_admin": "rule:csp_domain",
        "add_image": "@",
        "delete_image": "domain_id:%(obj.image.domain_id)s",
        "get_image": "domain_id:%(obj.image.domain_id)s",
        "get_images": "domain_id:%(qStr.domain_id)s",
        "modify_image": "domain_id:%(obj.image.domain_id)s",
        "publicize_image": "domain_id:%(obj.image.domain_id)s",
        "download_image": "domain_id:%(obj.image.domain_id)s",
        "upload_image": "domain_id:%(obj.image.domain_id)s"}
        }
