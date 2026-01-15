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
        Unknown packages will NOT be in this dict — callers should treat
        missing keys as "unmapped" and classify as needs_review.
    """
    # TODO: Implement full package mapping using importlib.metadata
    # - Introspect installed packages from environment
    # - Use importlib.metadata to get top-level names
    # - Merge with PACKAGE_OVERRIDES

    result: dict[str, list[str]] = {}

    # Add overrides with canonicalized keys
    for pkg_name, modules in PACKAGE_OVERRIDES.items():
        canonical = canonicalize_package_name(pkg_name)
        result[canonical] = modules

    # Also add common packages where package name = module name
    # These are KNOWN to match, not guesses
    for common_pkg in COMMON_MATCHING_PACKAGES:
        canonical = canonicalize_package_name(common_pkg)
        if canonical not in result:
            result[canonical] = [common_pkg.lower().replace("-", "_")]

    return result


# Packages where package name == module name (verified, not guessed)
# This is an allowlist of KNOWN matches, not a fallback
COMMON_MATCHING_PACKAGES: list[str] = [
    "requests",
    "urllib3",
    "flask",
    "django",
    "numpy",
    "pandas",
    "boto3",
    "botocore",
    "certifi",
    "click",
    "jinja2",
    "markupsafe",
    "packaging",
    "setuptools",
    "wheel",
    "pip",
    "idna",
    "chardet",
    "six",
    "pytz",
    "cryptography",
    "pycparser",
    "cffi",
    "attrs",
    "jsonschema",
    "httpx",
    "httpcore",
    "toml",
    "tomli",
]


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
    "pydantic": ["pydantic"],
    "typer": ["typer"],
    "rich": ["rich"],
}
