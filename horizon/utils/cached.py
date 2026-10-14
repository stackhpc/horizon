# Copyright 2026 stackxperts GmbH
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Cross-request, scope-aware caching for openstack_dashboard.api list calls.

Why this exists
---------------
``horizon.utils.memoized.memoized`` keeps a process-local OrderedDict in a
closure. Most horizon API helpers take ``request`` as the first positional
argument; ``request`` is wrapped in a weakref and becomes part of the key, so
when the request is garbage collected the entry is auto-evicted. Net effect:
``@memoized`` on ``api.glance.image_list_detailed`` etc. is per-request only,
even though kolla deployments ship a perfectly good shared memcached.

This module fills that gap with a Django-cache-backed decorator
``@cached_api`` that:

* Builds a key scoped to (function, scope ids, hashed args/kwargs, and a
  tuple of "version counters")
* Reads/writes ``django.core.cache.caches['default']`` (memcached in kolla)
* Is invalidated on user-driven writes via ``bump_versions()``, which simply
  ``INCR`` s the matching counters and orphans every key that referenced the
  old version
* Falls back to direct function call on any cache layer exception, so
  memcached down does not break horizon

Storage format
--------------
Values are pickled by this module, zlib-compressed above 16 KiB and stored
as raw bytes behind a small header (magic, codec, length, digest). Payloads
above ``HORIZONX_CACHE_CHUNK_BYTES`` (default 900 KiB) are split over
several keys, because memcached refuses items above its ``item_size_max``
(1 MiB by default) and Django's backend swallows that error. A clouds-worth
image list (1300+ images, ~1.7 MB pickled) is the case that needs this.

Security boundary
-----------------
* Every key hashes its scope ids. The ``token`` scope isolates per auth
  token. The ``authz`` scope shares an entry between tokens that are scoped
  to the same project with the same role set; use it only for calls whose
  result is fully decided by (project, roles), such as the glance image list.
* Token rotation (default 1h) bounds staleness for revoked roles/quotas on
  token-scoped entries; TTLs bound it for ``authz`` entries.
* Per-resource version counters propagate writes (image upload, network
  create, fip allocate, ...) to all readers in the same scope within one
  request cycle.
* Pickle is used for the payload. The cache is written and read by horizon
  workers in the same trust domain; memcached must not be reachable from
  untrusted networks (the same requirement Django's own cache backends and
  cache-backed sessions have).
"""

import copy
import functools
import hashlib
import logging
import pickle
import struct
import threading
import time
import zlib

from django.conf import settings
from django.core.cache import caches

LOG = logging.getLogger(__name__)

# Key prefix is intentionally short -- memcached has a 250-byte key limit
# and Django's cache framework adds its own KEY_PREFIX:VERSION:USER_KEY
# wrapping on top.
_KEY_PREFIX = 'h2c:'
# Namespace of response keys. Bump it whenever the stored format changes, so
# workers running different builds during a rolling upgrade never read each
# other's entries. ('r:' was the fast1-fast4 pickled-tuple format.)
_RESPONSE_NS = 'r2:'
_HASH_LEN = 32

# Version-counter keys are stored with no expiry (timeout=None -> backend
# default, which for pymemcache is the configured slab max ~30 days). They
# get refreshed implicitly each time we INCR a hot resource.
_VERSION_KEY_TIMEOUT = None

# Sentinel for distinguishing a real cache miss from a cached None.
_MISS = object()

# Stored value: header + inline payload (or header only, when chunked).
#   magic | codec | flags | chunk count | payload length | created | digest
_MAGIC = b'h2c2'
_HEADER = struct.Struct('!4scBIQQ16s')
_CODEC_PICKLE = b'p'
_CODEC_ZLIB = b'z'
_FLAG_REBIND = 0x01

_COMPRESS_MIN_BYTES = 16 * 1024
_DEFAULT_CHUNK_BYTES = 900 * 1024
_DEFAULT_MAX_BYTES = 64 * 1024 * 1024
# Chunks outlive their header a little, so a reader that found the header
# also finds the chunks.
_CHUNK_GRACE_SECONDS = 60

# How long a function stays uncached in this worker after its result could
# not be frozen or serialised. Time-limited so one odd response does not
# disable caching until the next restart.
_BYPASS_SECONDS = 600

# Attribute set on frozen wrappers that held the live ``request``; the
# current request is re-attached on every cache hit.
_REBIND_ATTR = '_h2c_rebind_request'

# Attributes of openstack-client Resources that are plumbing, not data.
_RESOURCE_INTERNALS = frozenset(('manager',))

# Per-key process-local lock. Suppresses intra-worker dogpile on cold-cache
# population. Cross-worker dogpile is bounded at N_workers. Entries are
# dropped after the fill so the dict does not grow with every token.
_locks_lock = threading.Lock()
_locks: dict = {}

# qualname -> time.monotonic() deadline of a temporary bypass.
_bypass_until: dict = {}

# qualnames whose serialised payload has been round-trip checked once in
# this worker.
_validated: set = set()


def _setting(name, default):
    return getattr(settings, name, default)


def _get_lock(key):
    with _locks_lock:
        lock = _locks.get(key)
        if lock is None:
            lock = _locks[key] = threading.Lock()
        return lock


def _drop_lock(key):
    with _locks_lock:
        _locks.pop(key, None)


def _bypassed(qualname):
    until = _bypass_until.get(qualname)
    if until is None:
        return False
    if until > time.monotonic():
        return True
    _bypass_until.pop(qualname, None)
    return False


def _bypass(qualname, reason):
    _bypass_until[qualname] = time.monotonic() + _BYPASS_SECONDS
    LOG.warning("cached_api: not caching %s for %d s in this worker: %s",
                qualname, _BYPASS_SECONDS, reason)


def _own_attrs(obj):
    """Instance ``__dict__`` without triggering any ``__getattr__`` hook.

    openstack-client Resources lazy-load missing attributes with an API call
    from ``__getattr__``; ``hasattr`` on them is not free.
    """
    try:
        return vars(obj)
    except TypeError:
        return {}


def _thaw_resource(cls, state):
    """Rebuild an openstack-client Resource from its frozen ``__dict__``.

    The instance is created without running ``__init__`` and marked loaded,
    so the client's lazy-loading ``__getattr__`` never calls the API (and
    never recurses on a half-built object, which is what default pickling of
    a Resource runs into). ``manager`` is ``None``: data access, properties
    such as ``Flavor.is_public`` and ``to_dict()`` work, methods that talk to
    the API do not. Cached results are read-only by design.
    """
    obj = cls.__new__(cls)
    obj.__dict__.update(state)
    obj.__dict__['manager'] = None
    obj.__dict__['_loaded'] = True
    return obj


class _FrozenResource:
    """Pickle carrier for an openstack-client Resource (novaclient,
    cinderclient, keystoneclient). Unpickles as a real instance of the
    original class via ``_thaw_resource``."""

    def __init__(self, cls, state):
        self.cls = cls
        self.state = state

    def __reduce__(self):
        return (_thaw_resource, (self.cls, self.state))


class _FrozenInner:
    """Picklable stand-in for a glance image (a warlock model).

    glanceclient builds its image class at runtime from the API schema, so
    the class cannot be pickled by reference. Horizon's ``glance.Image``
    wrapper delegates attribute access to the model through
    ``_apiresource``; ``_FrozenInner`` mimics the attribute and mapping
    access of the model on top of a plain dict.

    Note: ``__slots__`` is intentionally NOT set. Some horizon views
    decorate the objects they receive (``image.tenant_name = ...``); slots
    would block those writes with an unhelpful ``AttributeError``. Each
    request unpickles fresh instances so cross-request decoration leak is
    not a concern.
    """

    def __init__(self, info, extras=None):
        self._info = dict(info) if info else {}
        if extras:
            self.__dict__.update(extras)

    def __getattr__(self, name):
        # Called only when the attribute is missing from instance __dict__
        # (so view-set decorations like t.domain_name take precedence).
        # Avoid infinite recursion if _info itself is missing, e.g. during
        # ``__setstate__`` partial restore.
        if name == '_info':
            raise AttributeError(name)
        try:
            return self.__dict__['_info'][name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, key):
        return self._info[key]

    def __contains__(self, key):
        return key in self._info

    def keys(self):
        return self._info.keys()

    def items(self):
        return self._info.items()

    def __iter__(self):
        return iter(self._info)

    def __len__(self):
        return len(self._info)

    def __repr__(self):
        return '_FrozenInner(%r)' % (self._info,)

    def to_dict(self):
        return copy.deepcopy(self._info)

    def is_loaded(self):
        return True

    def __reduce__(self):
        extras = {k: v for k, v in self.__dict__.items() if k != '_info'}
        return (_FrozenInner, (self._info, extras))


class _Freezer:
    """Replace OpenStack Resource objects in a value with picklable
    equivalents. Walks lists/tuples/dicts recursively. Non-Resource values
    are returned unchanged.

    Why this exists: openstack-client Resources do not survive pickling (see
    ``_FrozenInner``). Freezing the value before it is stored keeps the
    cached copy plain data. Caller still receives the live value; only the
    cached copy is frozen.
    """

    def __init__(self):
        # Set when a frozen wrapper needs the current request re-attached
        # on read (e.g. ``nova.Server`` keeps ``self.request``).
        self.rebind = False

    def freeze(self, value):
        if value is None or isinstance(value, (str, bytes, int, float, bool)):
            return value
        # Containers come back as the original object when nothing inside
        # changed, so pickle's memo keeps shared sub-objects shared (a client
        # Resource holds every payload value twice: in ``_info`` and as an
        # attribute). Dict subclasses are always copied: glance's warlock
        # models are dict subclasses whose class cannot be pickled.
        if isinstance(value, dict):
            out = {k: self.freeze(v) for k, v in value.items()}
            if type(value) is dict and all(
                    out[k] is v for k, v in value.items()):
                return value
            return out
        if isinstance(value, list):
            out = [self.freeze(v) for v in value]
            if type(value) is list and all(
                    a is b for a, b in zip(out, value)):
                return value
            return out
        if isinstance(value, tuple):
            out = [self.freeze(v) for v in value]
            if all(a is b for a, b in zip(out, value)):
                return value
            if hasattr(value, '_make'):
                return type(value)._make(out)
            return tuple(out)

        attrs = _own_attrs(value)

        # Horizon's APIResourceWrapper subclasses (e.g.
        # openstack_dashboard.api.cinder.Volume) delegate whitelisted
        # attribute access to the underlying client Resource through
        # ``_apiresource``. Freeze the inner and keep whatever else the
        # wrapper carries (``volume.transfer``, ``group.volume_type_names``).
        if attrs.get('_apiresource') is not None:
            return self._freeze_wrapper(value, attrs)

        # Bare openstack-client Resource. Has ``_info`` populated from the
        # JSON API response plus one attribute per payload key, and anything
        # horizon set afterwards (``flavor.extras``).
        if isinstance(attrs.get('_info'), dict):
            state = {k: self.freeze(v) for k, v in attrs.items()
                     if k not in _RESOURCE_INTERNALS}
            return _FrozenResource(type(value), state)

        # Glance warlock-generated images iterate as dicts but are not
        # plain dicts. Detect by quack and snapshot.
        if hasattr(value, 'items') and hasattr(value, '__contains__'):
            try:
                return _FrozenInner(
                    self.freeze({k: value[k] for k in value}))
            except Exception:
                pass

        return value

    def _freeze_wrapper(self, value, attrs):
        cls = type(value)
        shell = cls.__new__(cls)
        state = dict(attrs)
        inner = state.pop('_apiresource')
        if state.pop('request', None) is not None:
            shell.__dict__[_REBIND_ATTR] = True
            self.rebind = True
        if isinstance(inner, dict) and type(inner) is not dict:
            # glance warlock model: keep attribute access working.
            frozen_inner = _FrozenInner(
                self.freeze({k: inner[k] for k in inner}))
        else:
            frozen_inner = self.freeze(inner)
        shell.__dict__['_apiresource'] = frozen_inner
        for name, val in state.items():
            shell.__dict__[name] = self.freeze(val)
        return shell


def _freeze_value(value):
    return _Freezer().freeze(value)


def _rebind_requests(value, request, depth=0):
    """Re-attach the current request to frozen wrappers that held one."""
    if depth > 4:
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _rebind_requests(item, request, depth + 1)
    elif isinstance(value, dict):
        for item in value.values():
            _rebind_requests(item, request, depth + 1)
    else:
        attrs = _own_attrs(value)
        if attrs.pop(_REBIND_ATTR, False):
            attrs['request'] = request


class _TooLarge(Exception):
    pass


def _chunk_key(key, digest, index):
    return '%s:%s:%d' % (key, digest.hex()[:12], index)


def _store(cache, key, frozen, ttl, rebind, validate):
    blob = pickle.dumps(frozen, pickle.HIGHEST_PROTOCOL)
    if validate:
        # One local round trip per function and worker. Catches payloads
        # that pickle but cannot be rebuilt (the fast1 RecursionError case)
        # before they reach memcached.
        pickle.loads(blob)
    codec = _CODEC_PICKLE
    if len(blob) >= _COMPRESS_MIN_BYTES:
        blob = zlib.compress(blob, 1)
        codec = _CODEC_ZLIB
    if len(blob) > _setting('HORIZONX_CACHE_MAX_BYTES', _DEFAULT_MAX_BYTES):
        raise _TooLarge('%d bytes after compression' % len(blob))
    chunk = _setting('HORIZONX_CACHE_CHUNK_BYTES', _DEFAULT_CHUNK_BYTES)
    digest = hashlib.sha256(blob).digest()[:16]
    flags = _FLAG_REBIND if rebind else 0
    created = int(time.time())
    if len(blob) <= chunk:
        header = _HEADER.pack(_MAGIC, codec, flags, 0, len(blob), created,
                              digest)
        cache.set(key, header + blob, timeout=ttl)
        return
    parts = [blob[i:i + chunk] for i in range(0, len(blob), chunk)]
    failed = cache.set_many(
        {_chunk_key(key, digest, i): part for i, part in enumerate(parts)},
        timeout=ttl + _CHUNK_GRACE_SECONDS)
    if failed:
        LOG.debug("cached_api: %d of %d chunks not stored for %s",
                  len(failed), len(parts), key)
        return
    header = _HEADER.pack(_MAGIC, codec, flags, len(parts), len(blob),
                          created, digest)
    cache.set(key, header, timeout=ttl)


def _load(cache, key):
    """Return ``(value, needs_rebind)`` or ``(_MISS, False)``."""
    raw = cache.get(key)
    if not isinstance(raw, bytes) or len(raw) < _HEADER.size:
        return _MISS, False
    magic, codec, flags, chunks, length, _created, digest = (
        _HEADER.unpack_from(raw))
    if magic != _MAGIC:
        return _MISS, False
    if chunks == 0:
        blob = raw[_HEADER.size:]
    else:
        keys = [_chunk_key(key, digest, i) for i in range(chunks)]
        got = cache.get_many(keys)
        if len(got) != chunks:
            return _MISS, False
        blob = b''.join(got[k] for k in keys)
    if (len(blob) != length or
            hashlib.sha256(blob).digest()[:16] != digest):
        return _MISS, False
    if codec == _CODEC_ZLIB:
        blob = zlib.decompress(blob)
    elif codec != _CODEC_PICKLE:
        return _MISS, False
    return pickle.loads(blob), bool(flags & _FLAG_REBIND)


def _scope_id(request, scope):
    """Resolve a scope name to a stable id string for the current request."""
    user = getattr(request, 'user', None)
    if scope == 'token':
        token = getattr(user, 'token', None)
        return getattr(token, 'id', '') or ''
    if scope == 'project':
        return getattr(user, 'project_id', '') or ''
    if scope == 'user':
        return getattr(user, 'id', '') or ''
    if scope == 'domain':
        return (getattr(user, 'user_domain_id', '') or
                getattr(user, 'domain_id', '') or '')
    if scope == 'authz':
        # What decides the result of a project-scoped list call: the project
        # the token is scoped to and the roles it carries there. Tokens
        # without a project (domain/system scope) stay isolated per token.
        project = getattr(user, 'project_id', '') or ''
        if not project:
            token = getattr(user, 'token', None)
            return 'token:' + (getattr(token, 'id', '') or '')
        roles = sorted({r.get('name', '') for r in
                        (getattr(user, 'roles', None) or [])
                        if isinstance(r, dict)})
        return 'project:%s|roles:%s' % (project, ','.join(roles))
    raise ValueError("unknown cached_api scope %r" % scope)


def _version_key(scope_value, resource):
    return '{prefix}vk:{resource}:{scope}'.format(
        prefix=_KEY_PREFIX, resource=resource, scope=scope_value)


def _hash_args(args, kwargs):
    # Drop the request object (always the first positional arg in horizon
    # API helpers). Sort kwargs for determinism.
    safe_args = args[1:] if args else ()
    try:
        payload = pickle.dumps(
            (safe_args, sorted(kwargs.items())),
            pickle.HIGHEST_PROTOCOL)
    except Exception:
        # Fallback for unpicklable args: stable repr. Less collision-safe
        # but better than blowing up.
        payload = repr((safe_args, sorted(kwargs.items()))).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()[:_HASH_LEN]


def _resolve_versions(request, version_specs):
    """Fetch current values of all named version counters in one round trip."""
    if not version_specs:
        return ()
    keys = []
    for spec in version_specs:
        resource, scope = spec.split(':', 1)
        if scope == 'global':
            keys.append(_version_key('global', resource))
        else:
            sval = _scope_id(request, scope)
            keys.append(_version_key(sval, resource))
    try:
        got = caches['default'].get_many(keys)
    except Exception:
        LOG.debug("cached_api: version get_many failed", exc_info=True)
        return tuple(0 for _ in keys)
    return tuple(got.get(k, 0) for k in keys)


def _build_key(func, scope_tuple, version_values, request, args, kwargs):
    parts = [func.__module__, func.__qualname__]
    for s in scope_tuple:
        parts.append('%s=%s' % (s, _scope_id(request, s)))
    if version_values:
        parts.append('v=' + ','.join(str(v) for v in version_values))
    parts.append('a=' + _hash_args(args, kwargs))
    raw = '|'.join(parts)
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    return _KEY_PREFIX + _RESPONSE_NS + digest


def cached_api(ttl, scope=('token',), versions=()):
    """Cache the return value of an openstack_dashboard.api list helper.

    The decorated function MUST take ``request`` as its first positional arg.

    :param ttl: time-to-live in seconds. Should be <= keystone token
        lifetime; once a token is revoked the user cannot read token-scoped
        entries regardless of TTL. ``HORIZONX_CACHE_TTLS`` in the settings
        (``{'<module>.<qualname>': seconds}``) overrides it per function.
    :param scope: tuple of scope names. Each is one of ``'token'``,
        ``'project'``, ``'user'``, ``'domain'`` or ``'authz'`` (project plus
        role set, shared between tokens).
    :param versions: tuple of version-counter names of the form
        ``'<resource>:<scope>'``. ``<scope>`` is one of ``'project'``,
        ``'user'``, ``'domain'``, or ``'global'``. Bumping any of these
        counters orphans matching cache entries.
    """
    if isinstance(scope, str):
        scope = (scope,)
    scope_tuple = tuple(scope)
    version_tuple = tuple(versions)

    def decorate(func):
        qualname = func.__qualname__
        ttl_name = '%s.%s' % (func.__module__, qualname)

        def _read(cache, key, request):
            try:
                value, rebind = _load(cache, key)
            except Exception:
                LOG.debug("cached_api: read failed for %s; treating as miss",
                          qualname, exc_info=True)
                return _MISS
            if value is not _MISS and rebind:
                _rebind_requests(value, request)
            return value

        def _write(cache, key, value):
            freezer = _Freezer()
            try:
                frozen = freezer.freeze(value)
            except Exception as e:
                _bypass(qualname, 'freeze failed (%s)' % e)
                return
            ttl_now = _setting('HORIZONX_CACHE_TTLS', {}).get(ttl_name, ttl)
            try:
                _store(cache, key, frozen, ttl_now, freezer.rebind,
                       validate=qualname not in _validated)
                _validated.add(qualname)
            except _TooLarge as e:
                _bypass(qualname, 'result too large (%s)' % e)
            except (pickle.PicklingError, pickle.UnpicklingError, TypeError,
                    AttributeError, RecursionError) as e:
                _bypass(qualname, 'result is not serialisable (%s)' % e)
            except Exception:
                LOG.debug("cached_api: set failed for %s", qualname,
                          exc_info=True)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            request = args[0] if args else kwargs.get('request')
            if request is None or _bypassed(qualname):
                return func(*args, **kwargs)

            # Per-request hard bypass for views that need a fresh read
            # (used after create/delete redirects on shared resources).
            try:
                if request.GET.get('cache_bust'):
                    return func(*args, **kwargs)
            except Exception:
                pass

            cache = caches['default']
            try:
                versions_now = _resolve_versions(request, version_tuple)
                key = _build_key(func, scope_tuple, versions_now,
                                 request, args, kwargs)
            except Exception:
                LOG.debug("cached_api: key build failed for %s; bypassing",
                          qualname, exc_info=True)
                return func(*args, **kwargs)

            value = _read(cache, key, request)
            if value is not _MISS:
                return value

            lock = _get_lock(key)
            try:
                with lock:
                    value = _read(cache, key, request)
                    if value is not _MISS:
                        return value
                    value = func(*args, **kwargs)
                    _write(cache, key, value)
                    return value
            finally:
                _drop_lock(key)

        wrapper._cached_api = True
        wrapper._cached_api_ttl = ttl
        wrapper._cached_api_scope = scope_tuple
        wrapper._cached_api_versions = version_tuple
        return wrapper

    return decorate


class ProcessTTLCache:
    """Per-process cache for values that only change on upgrades, such as
    API version ranges and extension lists, keyed by endpoint URL.

    Horizon otherwise asks for them again on every request (several round
    trips per page). Values must not be ``None``; ``get`` returns ``None``
    on a miss.
    """

    def __init__(self, ttl):
        self.ttl = ttl
        self._data = {}

    def get(self, key):
        hit = self._data.get(key)
        if hit is not None and hit[0] > time.monotonic():
            return hit[1]
        return None

    def set(self, key, value):
        self._data[key] = (time.monotonic() + self.ttl, value)


def bump_versions(request, version_specs):
    """Increment the named version counter(s).

    Each affected counter's INCR orphans every cache entry that referenced
    its prior value. Subsequent reads see a fresh result. Call from inside
    create/update/delete API helpers in ``openstack_dashboard.api.*``.

    Cheap-on-failure: a missing counter is initialised to 1 via ``add()``;
    a backend exception is swallowed and logged at debug level.
    """
    if not version_specs:
        return
    cache = caches['default']
    for spec in version_specs:
        try:
            resource, scope = spec.split(':', 1)
            if scope == 'global':
                key = _version_key('global', resource)
            else:
                sval = _scope_id(request, scope)
                if not sval:
                    continue
                key = _version_key(sval, resource)
            try:
                cache.incr(key)
            except ValueError:
                # Counter does not exist yet. add() is set-if-absent, so a
                # racing worker that beat us to it will not be clobbered.
                cache.add(key, 1, timeout=_VERSION_KEY_TIMEOUT)
        except Exception:
            LOG.debug("cached_api: version bump failed for %s",
                      spec, exc_info=True)
