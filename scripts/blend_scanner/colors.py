"""Terminal color definitions for output formatting."""


class Colors:
    """ANSI color codes for terminal output."""

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[0;36m"
    MAGENTA = "\033[0;35m"
    BOLD = "\033[1m"
    NC = "\033[0m"  # No Color (reset)

    @classmethod
    def red(cls, text: str) -> str:
        """Wrap text in red color."""
        return f"{cls.RED}{text}{cls.NC}"

    @classmethod
    def green(cls, text: str) -> str:
        """Wrap text in green color."""
        return f"{cls.GREEN}{text}{cls.NC}"

    @classmethod
    def yellow(cls, text: str) -> str:
        """Wrap text in yellow color."""
        return f"{cls.YELLOW}{text}{cls.NC}"

    @classmethod
    def cyan(cls, text: str) -> str:
        """Wrap text in cyan color."""
        return f"{cls.CYAN}{text}{cls.NC}"

    @classmethod
    def magenta(cls, text: str) -> str:
        """Wrap text in magenta color."""
        return f"{cls.MAGENTA}{text}{cls.NC}"

    @classmethod
    def bold(cls, text: str) -> str:
        """Wrap text in bold."""
        return f"{cls.BOLD}{text}{cls.NC}"
