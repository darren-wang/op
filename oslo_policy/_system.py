# This dict is unusable due to following reasons:
# 1. It's just my expectation to have isolation in this way, the attributes used
# in this dict are not tested, every operation needs to be tested in the official
# release to verify if the attributes used here are available.
# 2. Even the attributes are available, the rules defined here may not be enough
# to provide desirable domain(tenant) isolation.
class SystemRules(object):
    def __init__(self, conf):
        self.sys_rules = {
        # generic
            # The Syetem developer must ensure that: All the actions need
            # to be isolated are listed here.
            # so if an action isn't found in this dict, it is in the charge
            # of RBAC enforcer.
        'keystone': {
            "csp_domain": ("scope:domain and scope_domain_id:" + conf.
                             oslo_policy.CSP_domain_id),
        # region
            "list_regions": "rule:csp_domain",
            "get_region": "rule:csp_domain",
            "create_region": "rule:csp_domain",
            "update_region": "rule:csp_domain",
            "delete_region": "rule:csp_domain",
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
            "get_domain": "rule:csp_domain or (scope:domain and scope_domain_id:%(obj.domain.id)s)",
            "update_domain": "rule:csp_domain or (scope:domain and scope_domain_id:%(obj.domain.id)s)",
        # project
            "list_projects": "scope_domain_id:%(qStr.domain_id)s",
            "list_user_projects": "scope_domain_id:%(qStr.domain_id)s",
            "create_project": "scope:domain and scope_domain_id:%(reqBody.project.domain_id)s",
            "get_project": "scope_domain_id:%(obj.project.domain_id)s",
            "update_project": "(scope:domain and scope_domain_id:%(obj.project.domain_id)s) or scope_project_id:%(obj.project.id)s",
            "delete_project": "scope:domain and scope_domain_id:%(obj.project.domain_id)s",
        # user    
            "list_users": "scope_domain_id:%(qStr.domain_id)s",
            "create_user": "scope:domain and scope_domain_id:%(reqBody.user.domain_id)s",
            "get_user": "scope_domain_id:%(obj.user.domain_id)s",
            "update_user": "user_id:%(obj.user.id)s or (scope:domain and scope_domain_id:%(obj.user.domain_id)s)",
            "delete_user": "scope:domain and scope_domain_id:%(obj.user.domain_id)s",
        # group
            "get_group": "scope_domain_id:%(obj.group.domain_id)s",
            "list_groups": "scope_domain_id:%(qStr.domain_id)s",
            "list_groups_for_user": "scope_domain_id:%(obj.user.domain_id)s",
            "create_group": "scope:domain and scope_domain_id:%(reqBody.group.domain_id)s",
            "update_group": "scope:domain and scope_domain_id:%(obj.group.domain_id)s",
            "delete_group": "scope:domain and scope_domain_id:%(obj.group.domain_id)s",
            "remove_user_from_group": "scope:domain and scope_domain_id:%(obj.group.domain_id)s",
            "check_user_in_group": "scope_domain_id:%(obj.group.domain_id)s",
            "add_user_to_group": "scope:domain and scope_domain_id:%(obj.group.domain_id)s",
            "list_users_in_group": "scope_domain_id:%(obj.group.domain_id)s",
            "list_projects_for_groups": "",
            "list_domains_for_groups": "",
        # grant(it's very loose)
            "check_grant": "(scope_project_id:%(url.project_id)s) or (scope:domain and (scope_domain_id:%(obj.domain.id)s or scope_domain_id:%(obj.project.domain_id)s))",
            "list_grants": "(scope_project_id:%(url.project_id)s) or (scope:domain and (scope_domain_id:%(obj.domain.id)s or scope_domain_id:%(obj.project.domain_id)s))",
            "create_grant": "(scope_project_id:%(url.project_id)s) or (scope:domain and (scope_domain_id:%(obj.domain.id)s or scope_domain_id:%(obj.project.domain_id)s))",
            "revoke_grant": "(scope_project_id:%(url.project_id)s) or (scope:domain and (scope_domain_id:%(obj.domain.id)s or scope_domain_id:%(obj.project.domain_id)s))",
        # role assignment
            "list_role_assignments": "user_id:%(user.id)s or scope_domain_id:%(qStr.domain_id)s or scope_project_id:%(qStr.project_id)s",
        # token
            "change_password": "user_id:%(obj.user.id)s or (scope:domain and scope_domain_id:%(obj.user.domain_id)s)",
            "check_token": "",
            "validate_token": "",
            "revocation_list": "",
            "revoke_token": "",
        # role
            "get_role": "scope_domain_id:%(obj.role.domain_id)s",
            "list_roles": "scope_domain_id:%(qStr.domain_id)s",
            "create_role": "scope:domain and scope_domain_id:%(reqBody.role.domain_id)s",
            "update_role": "scope:domain and scope_domain_id:%(obj.role.domain_id)s",
            "delete_role": "scope:domain and scope_domain_id:%(obj.role.domain_id)s",
        # policy
            "get_policy": "scope:domain and scope_domain_id:%(obj.policy.domain_id)s",
            "list_policies": "scope:domain and scope_domain_id:%(qStr.domain_id)s",
            "create_policy": "scope:domain and scope_domain_id:%(reqBody.policy.domain_id)s",
            "update_policy": "scope:domain and scope_domain_id:%(obj.policy.domain_id)s",
            "delete_policy": "scope:domain and scope_domain_id:%(obj.policy.domain_id)s",
        # rule
            "get_rule": "@",
            "list_rules": "@",
            "create_rule": "@",
            "update_rule": "@",
            "delete_rule": "@",
        # other
            "get_auth_catalog": "",
            "get_auth_projects": "",
            "get_auth_domains": "",
            "list_revoke_events": ""
            },
        'glance': {
        # Glance Related
            "add_image": "scope:project",
            "delete_image": "scope_domain_id:%(obj.image.domain_id)s",
            "get_image": "scope_domain_id:%(obj.image.domain_id)s",
            "get_images": "scope_project_id:%(qStr.project_id)s or (scope:domain and scope_domain_id:%(qStr.domain_id)s)",
            "modify_image": "",
            "publicize_image": "",
            "download_image": "scope_domain_id:%(obj.image.domain_id)s",
            "upload_image": "scope_domain_id:%(obj.image.domain_id)s",
            "add_member": "",
            "delete_member": "",
            "get_member": "",
            "get_members": "",
            "modify_member": "",
            "manage_image_cache": ""
            }
        }
