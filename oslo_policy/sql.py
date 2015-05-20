# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_policy.common import sql
from oslo_policy import exception
from oslo_log import log


LOG = log.getLogger(__name__)


class Policy(sql.ModelBase, sql.DictBase):
    __tablename__ = 'policy'
    attributes = ['id', 'blob', 'name', 'enabled',
                  'description', 'domain_id']
    id = sql.Column(sql.String(64), primary_key=True)
    blob = sql.Column(sql.JsonBlob(), nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    enabled = sql.Column(sql.Boolean, default=False, nullable=False)
    description = sql.Column(sql.Text())
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})

class Domain(sql.ModelBase, sql.DictBase):
    __tablename__ = 'domain'
    attributes = ['id', 'name', 'enabled', 'description']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    enabled = sql.Column(sql.Boolean, default=True, nullable=False)
    description = sql.Column(sql.Text(), nullable=True)
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint('name'), {})


class Project(sql.ModelBase, sql.DictBase):
    __tablename__ = 'project'
    attributes = ['id', 'name', 'domain_id', 'description', 'enabled',
                  'parent_id']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    description = sql.Column(sql.Text())
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    parent_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'))
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class Backend(object):

    def __init__(self, conf):
        self.conf = conf

    def enabled_policies_in_domain(self, domain_id):
        try:
            self.get_domain(domain_id)
        except exception.DomainNotFound:
            raise
        return self._enabled_policies_in_domain(domain_id)
    
    def _enabled_policies_in_domain(self, domain_id):
        with sql.transaction(self.conf) as session:
            query = session.query(Policy)
            policy_refs = query.filter_by(domain_id=domain_id,
                                          enabled=True)
            return [policy_ref.to_dict() for policy_ref in policy_refs]

    def get_policy(self, policy_id):
        with sql.transaction(self.conf) as session:
            policy_ref = session.query(Policy).get(policy_id)
            if not policy_ref:
                raise exception.PolicyNotFound(policy_id=policy_id)
        return policy_ref.to_dict()

    def get_project(self, project_id):
        with sql.transaction(self.conf) as session:
            project_ref = session.query(Project).get(project_id)
            if project_ref is None:
                raise exception.ProjectNotFound(project_id=project_id)
            return project_ref.to_dict()

    def get_project_by_name(self, project_name, domain_id):
        with sql.transaction(self.conf) as session:
            query = session.query(Project)
            query = query.filter_by(name=project_name)
            query = query.filter_by(domain_id=domain_id)
            try:
                project_ref = query.one()
            except sql.NotFound:
                raise exception.ProjectNotFound(project_id=project_name)
            return project_ref.to_dict()

    def get_domain(self, domain_id):
        with sql.transaction(self.conf) as session:
            domain_ref = session.query(Domain).get(domain_id)
            if domain_ref is None:
                raise exception.DomainNotFound(domain_id=domain_id)
            return domain_ref.to_dict()

    def get_domain_by_name(self, domain_name):
        with sql.transaction(self.conf) as session:
            try:
                domain_ref = (session.query(Domain).
                       filter_by(name=domain_name).one())
            except sql.NotFound:
                raise exception.DomainNotFound(domain_id=domain_name)
            return domain_ref.to_dict()
