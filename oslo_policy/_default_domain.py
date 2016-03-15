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
            "default": "@",  
            "admin_domain": "",
        # region
            "list_regions": "",
            "get_region": "",
            "create_region": "",
            "update_region": "",
            "delete_region": "",
        # service
            "list_services": "",
            "get_service": "",
            "create_service": "",
            "update_service": "",
            "delete_service": "",
        # endpoint
            "get_endpoint": "",
            "list_endpoints": "",
            "create_endpoint": "",
            "update_endpoint": "",
            "delete_endpoint": "",
        # domain
            "list_domains": "",
            "create_domain": "",
            "delete_domain": "",
            "get_domain": "",
            "update_domain": "",
        # project
            "list_projects": "",
            "list_user_projects": "",
            "create_project": "",
            "get_project": "",
            "update_project": "",
            "delete_project": "",
        # user    
            "list_users": "",
            "create_user": "",
            "get_user": "",
            "update_user": "",
            "delete_user": "",
        # group
            "get_group": "",
            "list_groups": "",
            "list_groups_for_user": "",
            "create_group": "",
            "update_group": "",
            "delete_group": "",
            "remove_user_from_group": "",
            "check_user_in_group": "",
            "add_user_to_group": "",
            "list_users_in_group": "",
            "list_projects_for_groups": "",
            "list_domains_for_groups": "",
        # grant(it's very loose)
            "check_grant": "",
            "list_grants": "",
            "create_grant": "",
            "revoke_grant": "",
        # role assignment
            "list_role_assignments": "",
        # token
            "change_password": "",
            "check_token": "",
            "validate_token": "",
            "revocation_list": "",
            "revoke_token": "",
        # role
            "get_role": "",
            "list_roles": "",
            "create_role": "",
            "update_role": "",
            "delete_role": "",
        # policy
            "get_policy": "",
            "list_policies": "",
            "create_policy": "",
            "update_policy": "",
            "delete_policy": "",
        # other
            "get_auth_catalog": "",
            "get_auth_projects": "",
            "get_auth_domains": "",
            "list_revoke_events": ""
            },
        'glance': {
        # Glance Related
            "add_image": "",
            "delete_image": "",
            "get_image": "",
            "get_images": "",
            "modify_image": "",
            "publicize_image": "",
            "copy_from": "",
            "download_image": "",
            "upload_image": "",
            "set_image_location": "",
            "get_image_location": "",
            "delete_image_location": "",
            "add_member": "",
            "delete_member": "",
            "get_member": "",
            "get_members": "",
            "modify_member": "",
            "manage_image_cache": ""
            }
        }