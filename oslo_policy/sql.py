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
from openstackclient.tests.identity.v3.fakes import domain_id


LOG = log.getLogger(__name__)


class Policy(sql.ModelBase, sql.DictBase):
    __tablename__ = 'policy'
    attributes = ['description', 'domain_id', 'enabled', 'id', 'name']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('domain.id'),
                           nullable=False)
    enabled = sql.Column(sql.Boolean, default=False, nullable=False)
    description = sql.Column(sql.Text(), nullable=True)
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'), {})


class Rule(sql.ModelBase, sql.DictBase):
    __tablename__ = 'rule'
    attributes = ['id', 'policy_id', 'service', 'permission', 'condition']
    id = sql.Column(sql.String(64), primary_key=True)
    policy_id = sql.Column(sql.String(64), sql.ForeignKey('policy.id'),
                           nullable=False)
    service = sql.Column(sql.String(64), nullable=False)
    permission = sql.Column(sql.String(64), nullable=False)
    condition = sql.Column(sql.JsonBlob(), nullable=True)
    __table_args__ = (sql.UniqueConstraint('policy_id', 'service',
                                           'permission'), {})


class Domain(sql.ModelBase, sql.DictBase):
    __tablename__ = 'domain'
    attributes = ['id', 'name', 'enabled', 'description']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    enabled = sql.Column(sql.Boolean, default=True, nullable=False)
    description = sql.Column(sql.Text(), nullable=True)
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint('name'), {})


class Backend(object):

    def __init__(self, conf):
        self.conf = conf

    def _get_domain(self, domain_id):
        with sql.transaction(self.conf) as session:
            domain_ref = session.query(Domain).get(domain_id)
            if domain_ref is None:
                raise exception.DomainNotFound(domain_id=domain_id)
            return domain_ref.to_dict()

    def _list_policies_in_domain(self, domain_id):
        self._get_domain(domain_id)
        with sql.transaction(self.conf) as session:
            query = session.query(Policy)
            policy_refs = query.filter_by(domain_id=domain_id)
            return [policy_ref.to_dict() for policy_ref in policy_refs]

    def get_enabled_policy_in_domain(self, domain_id):
        policies_ref = self._list_policies_in_domain(domain_id)
        if policies_ref:
            for policy_ref in policies_ref:
                if policy_ref['enabled']:
                    return policy_ref

    def get_rule(self, policy_id, serv, perm):
        """
        :param policy_id: ID of the policy in which we are searching for rule
        :param serv: target service, e.g. 'keystone'. 
        :param perm: target permission, e.g. 'create_domain'
        :return: dict of target rule if it exists, or raise RuleNotFound.
        """ 
        with sql.transaction(self.conf) as session:
            rule_ref = (session.query(Rule).filter_by(policy_id=policy_id,
                                        service=serv,permission=perm).one())
            if not rule_ref:
                raise exception.RuleNotFound(p_id=p_id, serv=serv, perm=perm)
        return rule_ref.to_dict()
