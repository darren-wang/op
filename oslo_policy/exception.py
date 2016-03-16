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

from oslo_log import log
from oslo_utils import encodeutils
import six

from oslo_policy._i18n import _, _LW


LOG = log.getLogger(__name__)

# Tests use this to make exception message format errors fatal
_FATAL_EXCEPTION_FORMAT_ERRORS = False


class Error(Exception):
    """Base error class.

    Child classes should define an HTTP status code, title, and a
    message_format.

    """
    code = None
    title = None
    message_format = None

    def __init__(self, message=None, **kwargs):
        try:
            message = self._build_message(message, **kwargs)
        except KeyError:
            # if you see this warning in your logs, please raise a bug report
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise
            else:
                LOG.warning(_LW('missing exception kwargs (programmer error)'))
                message = self.message_format

        super(Error, self).__init__(message)

    def _build_message(self, message, **kwargs):
        """Builds and returns an exception message.

        :raises: KeyError given insufficient kwargs

        """
        if not message:
            try:
                message = self.message_format % kwargs
            except UnicodeDecodeError:
                try:
                    kwargs = {k: encodeutils.safe_decode(v)
                              for k, v in six.iteritems(kwargs)}
                except UnicodeDecodeError:
                    # NOTE(jamielennox): This is the complete failure case
                    # at least by showing the template we have some idea
                    # of where the error is coming from
                    message = self.message_format
                else:
                    message = self.message_format % kwargs

        return message


class ValidationError(Error):
    message_format = _("Expecting to find %(attribute)s in %(target)s -"
                       " the server could not comply with the request"
                       " since it is either malformed or otherwise"
                       " incorrect. The client is assumed to be in error.")
    code = 400
    title = 'Bad Request'


class StringLengthExceeded(ValidationError):
    message_format = _("String length exceeded.The length of"
                       " string '%(string)s' exceeded the limit"
                       " of column %(type)s(CHAR(%(length)d)).")


class SecurityError(Error):
    """Avoids exposing details of security failures, unless in debug mode."""
    amendment = _('(Disable debug mode to suppress these details.)')

    def _build_message(self, message, **kwargs):
        """Only returns detailed messages in debug mode."""
        if CONF.debug:
            return _('%(message)s %(amendment)s') % {
                'message': message or self.message_format % kwargs,
                'amendment': self.amendment}
        else:
            return self.message_format % kwargs


class NotFound(Error):
    message_format = _("Could not find: %(target)s")
    code = 404
    title = 'Not Found'


class PolicyNotFound(NotFound):
    message_format = _("Could not find policy: %(policy_id)s")


class RuleNotFound(NotFound):
    message_format = _("Could not find rule: policy(%(p_id)s),"
        "service(%(serv)s), permission(%(perm)s)")


class RoleNotFound(NotFound):
    message_format = _("Could not find role: %(role_id)s")


class RoleAssignmentNotFound(NotFound):
    message_format = _("Could not find role assignment with role: "
                       "%(role_id)s, user or group: %(actor_id)s, "
                       "project or domain: %(target_id)s")


class DomainNotFound(NotFound):
    message_format = _("Could not find domain: %(domain_id)s")


class Conflict(Error):
    message_format = _("Conflict occurred attempting to store %(type)s -"
                       " %(details)s")
    code = 409
    title = 'Conflict'


class UnexpectedError(SecurityError):
    """Avoids exposing details of failures, unless in debug mode."""
    _message_format = _("An unexpected error prevented the server "
                        "from fulfilling your request.")

    debug_message_format = _("An unexpected error prevented the server "
                             "from fulfilling your request: %(exception)s")

    @property
    def message_format(self):
        """Return the generic message format string unless debug is enabled."""
        if CONF.debug:
            return self.debug_message_format
        return self._message_format

    def _build_message(self, message, **kwargs):
        if CONF.debug and 'exception' not in kwargs:
            # Ensure that exception has a value to be extra defensive for
            # substitutions and make sure the exception doesn't raise an
            # exception.
            kwargs['exception'] = ''
        return super(UnexpectedError, self)._build_message(message, **kwargs)

    code = 500
    title = 'Internal Server Error'
