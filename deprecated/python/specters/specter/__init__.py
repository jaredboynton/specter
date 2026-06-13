import warnings as _warnings

from warpsock import *  # noqa: F401,F403
from warpsock import __all__ as _warpsock_all
from warpsock import __version__ as _warpsock_version

_warnings.warn(
    "The specter module was renamed to warpsock. Install warpsock and import warpsock instead.",
    FutureWarning,
    stacklevel=2,
)

__version__ = _warpsock_version
__all__ = list(_warpsock_all)
