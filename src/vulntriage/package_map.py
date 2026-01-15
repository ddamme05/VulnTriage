"""Package name mapping - maps PyPI names to importable module names."""

import re


def canonicalize_package_name(name: str) -> str:
    """Canonicalize a package name for consistent internal lookup.

    Normalizes casing and punctuation: all runs of [-_.] become underscores,
    and the name is lowercased. This ensures consistent matching between
    Trivy package names and our internal package map.

    Note: This is NOT strict PEP 503 (which uses hyphens). This is internal
    canonicalization for lookup consistency.

    Examples:
        - "PyYAML" -> "pyyaml"
        - "scikit-learn" -> "scikit_learn"
        - "Pillow" -> "pillow"
    """
    return re.sub(r"[-_.]+", "_", name.lower())


def build_package_map() -> dict[str, list[str]]:
    """Build a mapping from canonicalized PyPI package names to importable module names.

    For example:
        - "pyyaml" -> ["yaml", "_yaml"]
        - "pillow" -> ["PIL"]
        - "beautifulsoup4" -> ["bs4"]

    Returns:
        Dictionary mapping canonicalized package names to lists of module names.
    """
    # TODO: Implement package mapping
    # - Introspect installed packages from environment
    # - Use importlib.metadata to get top-level names
    # - Merge with PACKAGE_OVERRIDES

    # For now, return the overrides with canonicalized keys
    result: dict[str, list[str]] = {}
    for pkg_name, modules in PACKAGE_OVERRIDES.items():
        canonical = canonicalize_package_name(pkg_name)
        result[canonical] = modules
    return result


# Common manual overrides for packages where metadata is unreliable
# Keys are NOT canonicalized here - canonicalization happens in build_package_map()
PACKAGE_OVERRIDES: dict[str, list[str]] = {
    "PyYAML": ["yaml", "_yaml"],
    "Pillow": ["PIL"],
    "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "python-dateutil": ["dateutil"],
    "typing-extensions": ["typing_extensions"],
    "charset-normalizer": ["charset_normalizer"],
    "google-auth": ["google.auth"],
    "protobuf": ["google.protobuf"],
}
