# Copyright 2012 OpenStack Foundation
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

"""SQL backends for the various services.

Before using this module, call initialize(). This has to be done before
CONF() because it sets up configuration options.

"""
import contextlib

from oslo_db.sqlalchemy import models
from oslo_db.sqlalchemy import session as db_session
from oslo_log import log
from oslo_serialization import jsonutils
import six
import sqlalchemy as sql
from sqlalchemy.ext import declarative
from sqlalchemy import types as sql_types

from oslo_policy import exception


LOG = log.getLogger(__name__)

ModelBase = declarative.declarative_base()


# For exporting to other modules
Column = sql.Column
String = sql.String
ForeignKey = sql.ForeignKey
NotFound = sql.orm.exc.NoResultFound
Boolean = sql.Boolean
Text = sql.Text
UniqueConstraint = sql.UniqueConstraint


def initialize(conf):
    """Initialize the module."""
    
    connection="sqlite:///keystone.db"
    conf.set_default('policy_conn', connection, group='oslo_policy')


def initialize_decorator(init):
    """Ensure that the length of string field do not exceed the limit.

    This decorator check the initialize arguments, to make sure the
    length of string field do not exceed the length limit, or raise a
    'StringLengthExceeded' exception.

    Use decorator instead of inheritance, because the metaclass will
    check the __tablename__, primary key columns, etc. at the class
    definition.

    """
    def initialize(self, *args, **kwargs):
        cls = type(self)
        for k, v in kwargs.items():
            if hasattr(cls, k):
                attr = getattr(cls, k)
                if isinstance(attr, InstrumentedAttribute):
                    column = attr.property.columns[0]
                    if isinstance(column.type, String):
                        if not isinstance(v, six.text_type):
                            v = six.text_type(v)
                        if column.type.length and column.type.length < len(v):
                            raise exception.StringLengthExceeded(
                                string=v, type=k, length=column.type.length)

        init(self, *args, **kwargs)
    return initialize

ModelBase.__init__ = initialize_decorator(ModelBase.__init__)


# Special Fields
class JsonBlob(sql_types.TypeDecorator):

    impl = sql.Text

    def process_bind_param(self, value, dialect):
        return jsonutils.dumps(value)

    def process_result_value(self, value, dialect):
        return jsonutils.loads(value)


class DictBase(models.ModelBase):
    attributes = []

    @classmethod
    def from_dict(cls, d):
        new_d = d.copy()

        new_d['extra'] = {k: new_d.pop(k) for k in six.iterkeys(d)
                          if k not in cls.attributes and k != 'extra'}

        return cls(**new_d)

    def to_dict(self, include_extra_dict=False):
        """Returns the model's attributes as a dictionary.

        If include_extra_dict is True, 'extra' attributes are literally
        included in the resulting dictionary twice, for backwards-compatibility
        with a broken implementation.

        """
        d = self.extra.copy()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)

        if include_extra_dict:
            d['extra'] = self.extra.copy()

        return d

    def __getitem__(self, key):
        if key in self.extra:
            return self.extra[key]
        return getattr(self, key)


_engine_facade = None


def _get_engine_facade(conf):
    global _engine_facade

    if not _engine_facade:
        _engine_facade = db_session.EngineFacade(conf.oslo_policy.policy_conn)

    return _engine_facade


def cleanup():
    global _engine_facade

    _engine_facade = None


def get_engine(conf):
    return _get_engine_facade(conf).get_engine()


def get_session(conf, expire_on_commit=False):
    return _get_engine_facade(conf).get_session(expire_on_commit=expire_on_commit)


@contextlib.contextmanager
def transaction(conf, expire_on_commit=False):
    """Return a SQLAlchemy session in a scoped transaction."""
    session = get_session(conf, expire_on_commit=expire_on_commit)
    with session.begin():
        yield session
