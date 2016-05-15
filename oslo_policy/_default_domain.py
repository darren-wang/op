# (DWang) Cloud Service Provider must ensure that all the permissions need
# to be protected are listed here.
# If a permission is not found in this dict, it is in the charge of the
# enforcer and the enforcer will deny requests of that permission by default.
class DefaultRules(object):
    def __init__(self):
        self.dflt_rules = {
        'keystone': { 
        'cru_check': 'role:cloud_admin',
        # service
        "list_services": "role:domain_admin",
        "get_service": "role:domain_admin",
        "create_service": "role:domain_admin",
        "update_service": "role:domain_admin",
        "delete_service": "role:domain_admin",
        # endpoint
        "get_endpoint": "role:domain_admin",
        "list_endpoints": "role:domain_admin",
        "create_endpoint": "role:domain_admin",
        "update_endpoint": "role:domain_admin",
        "delete_endpoint": "role:domain_admin",
        # domain
        "list_domains": "role:domain_admin",
        "create_domain": "role:domain_admin",
        "delete_domain": "role:domain_admin",
        "get_domain": "role:domain_admin",
        "update_domain": "role:domain_admin",
        # project
        "list_projects": "role:domain_admin or role:project_admin",
        "list_user_projects": "role:domain_admin or user_id:%(obj.user.id)s",
        "create_project": "role:domain_admin",
        "get_project": "role:domain_admin or role:project_admin",
        "update_project": "role:domain_admin or role:project_admin",
        "delete_project": "role:domain_admin",
        # user    
        "list_users": "@",
        "get_user": "@",
        "create_user": "role:domain_admin",
        "update_user": "role:domain_admin or user_id:%(obj.user.id)s",
        "delete_user": "role:domain_admin",
        "change_password": "role:domain_admin or user_id:%(obj.user.id)s",
        # group
        "get_group": "role:domain_admin or role:project_admin",
        "list_groups": "role:domain_admin or role:project_admin",
        "list_groups_for_user": "role:domain_admin or role:project_admin or user_id:%(obj.user.id)s",
        "create_group": "role:domain_admin",
        "update_group": "role:domain_admin",
        "delete_group": "role:domain_admin",
        "remove_user_from_group": "role:domain_admin or role:project_admin",
        "check_user_in_group": "role:domain_admin or role:project_admin",
        "add_user_to_group": "role:domain_admin or role:project_admin",
        "list_users_in_group": "role:domain_admin or role:project_admin",
        "list_projects_for_groups": "@",
        "list_domains_for_groups": "@",
        # grant
        "check_grant": "role:domain_admin or role:project_admin",
        "list_grants": "role:domain_admin or role:project_admin",
        "create_grant": "role:domain_admin or role:project_admin",
        "revoke_grant": "role:domain_admin or role:project_admin",
        # system grant
        "check_sys_grant": "role:domain_admin",
        "list_sys_grants": "role:domain_admin",
        "create_sys_grant": "role:domain_admin",
        "revoke_sys_grant": "role:domain_admin",
        # role assignment
        "list_role_assignments": "role:domain_admin or role:project_admin",
        # role
        "get_role": "role:domain_admin or role:project_admin",
        "list_roles": "role:domain_admin or role:project_admin",
        "create_role": "role:domain_admin",
        "update_role": "role:domain_admin",
        "delete_role": "role:domain_admin",
        # system role
        "get_sys_role": "role:domain_admin",
        "list_sys_roles": "role:domain_admin",
        "create_sys_role": "role:domain_admin",
        "update_sys_role": "role:domain_admin",
        "delete_sys_role": "role:domain_admin",
        # policy
        "get_policy": "role:domain_admin",
        "list_policies": "role:domain_admin",
        "create_policy": "role:domain_admin",
        "update_policy": "role:domain_admin",
        "delete_policy": "role:domain_admin",
        # rule
        "get_rule": "role:domain_admin",
        "list_rules": "role:domain_admin",
        "create_rule": "role:domain_admin",
        "update_rule": "role:domain_admin",
        "delete_rule": "role:domain_admin",
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
        # Glance related
        'glance': {
        "add_image": "role:domain_admin",
        "delete_image": "role:domain_admin",
        "get_image": "role:domain_admin",
        "get_images": "role:domain_admin",
        "modify_image": "role:domain_admin",
        "publicize_image": "role:domain_admin",
        "download_image": "role:domain_admin",
        "upload_image": "role:domain_admin",
        "context_is_admin": "role:domain_admin"
        }
    }
