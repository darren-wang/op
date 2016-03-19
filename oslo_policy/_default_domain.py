# This dict is unusable due to following reasons:
# 1. It's just my expectation to have isolation in this way, the attributes used
# in this dict are not tested, every operation needs to be tested in the official
# release to verify if the attributes used here are available.
# 2. Even the attributes are available, the rules defined here may not be enough
# to provide desirable domain(tenant) isolation.
class DefaultRules(object):
    def __init__(self):
        self.dflt_rules = {
        # generic
            # The Syetem developer must ensure that: All the actions need
            # to be isolated are listed here.
            # so if an action isn't found in this dict, it is in the charge
            # of RBAC enforcer.
        'keystone': { 
        # region
            "list_regions": "role:domain_admin",
            "get_region": "role:domain_admin",
            "create_region": "role:domain_admin",
            "update_region": "role:domain_admin",
            "delete_region": "role:domain_admin",
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
            "list_users": "",
            "create_user": "role:domain_admin",
            "get_user": "",
            "update_user": "role:domain_admin or user_id:%(obj.user.id)s",
            "delete_user": "role:domain_admin",
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
            "list_projects_for_groups": "",
            "list_domains_for_groups": "",
        # grant(it's very loose)
            "check_grant": "role:domain_admin or role:project_admin",
            "list_grants": "role:domain_admin or role:project_admin",
            "create_grant": "role:domain_admin or role:project_admin",
            "revoke_grant": "role:domain_admin or role:project_admin",
        # role assignment
            "list_role_assignments": "role:domain_admin or role:project_admin",
        # token
            "change_password": "role:domain_admin or user_id:%(obj.user.id)s",
            "check_token": "",
            "validate_token": "",
            "revocation_list": "",
            "revoke_token": "",
        # role
            "get_role": "role:domain_admin or role:project_admin",
            "list_roles": "role:domain_admin or role:project_admin",
            "create_role": "role:domain_admin",
            "update_role": "role:domain_admin",
            "delete_role": "role:domain_admin",
        # policy
            "get_policy": "role:domain_admin",
            "list_policies": "role:domain_admin",
            "create_policy": "role:domain_admin",
            "update_policy": "role:domain_admin",
            "delete_policy": "role:domain_admin",
        # other
            "get_auth_catalog": "",
            "get_auth_projects": "",
            "get_auth_domains": "",
            "list_revoke_events": ""
            },
        'glance': {
        # Glance Related
            "add_image": "role:project_admin",
            "delete_image": "role:domain_admin or role:project_admin",
            "get_image": "@",
            "get_images": "@",
            "modify_image": "",
            "publicize_image": "",
            "download_image": "@",
            "upload_image": "scope:project and role:project_admin",
            "add_member": "",
            "delete_member": "",
            "get_member": "",
            "get_members": "",
            "modify_member": "",
            "manage_image_cache": ""
            }
        }