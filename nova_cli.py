import argparse
import sys

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich import box

from nova.core.requester import Requester
from nova.core.engine import NovaEngine

from nova.discovery.path import PathDiscovery
from nova.discovery.parameter import ParameterDiscovery
from nova.discovery.subdomain import SubdomainDiscovery
from nova.discovery.post_parameter import PostParameterDiscovery
from nova.discovery.json_parameter import JSONParameterDiscovery
from nova.discovery.recursive import RecursiveDiscovery
from nova.discovery.payload import PayloadDiscovery
from nova.discovery.xxe import XXEDiscovery

from nova.utils.wordlist import Wordlist


console = Console()


# ═════════════════════════════════════════════════════
# NOVA COLORS
# ═════════════════════════════════════════════════════

COLORS = {
    "primary": "cyan",
    "secondary": "blue",
    "accent": "magenta",
    "text": "white",
    "muted": "grey70",
    "success": "green",
    "warning": "yellow",
    "error": "red",
    "border": "grey37",
}


# ═════════════════════════════════════════════════════
# BANNER
# ═════════════════════════════════════════════════════

def banner():

    logo = Text()

    lines = [
        "███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ",
        "████╗  ██║██╔═══██╗██║   ██║██╔══██╗",
        "██╔██╗ ██║██║   ██║██║   ██║███████║",
        "██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║",
        "██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║",
        "╚═╝  ╚═══╝ ╚═════╝   ╚════╝  ╚═╝  ╚═╝",
    ]

    colors = [
        "bright_cyan",
        "cyan",
        "bright_blue",
        "blue",
        "bright_magenta",
        "magenta",
    ]

    for line, color in zip(lines, colors):
        logo.append(
            line + "\n",
            style=f"bold {color}",
        )

    subtitle = Text()

    subtitle.append("\n")

    subtitle.append(
        "N O V A",
        style="bold white",
    )

    subtitle.append(
        "  /  ",
        style="grey50",
    )

    subtitle.append(
        "WEB SECURITY FUZZING FRAMEWORK",
        style="bold cyan",
    )

    subtitle.append("\n")

    subtitle.append(
        "DISCOVER  •  FUZZ  •  ANALYZE  •  DETECT",
        style="grey62",
    )

    content = Text()

    content.append("\n")

    content.append(
        "  VERSION   ",
        style="grey62",
    )

    content.append(
        "6.0.0",
        style="bold cyan",
    )

    content.append(
        "        ENGINE   ",
        style="grey62",
    )

    content.append(
        "NOVA",
        style="bold magenta",
    )

    content.append("\n")

    content.append(
        "  STATUS    ",
        style="grey62",
    )

    content.append(
        "● READY",
        style="bold green",
    )

    console.print(
        Panel(
            logo + subtitle + content,
            border_style="blue",
            box=box.ROUNDED,
            padding=(1, 3),
            title="[bold magenta] N O V A [/bold magenta]",
            subtitle="[grey62]security research toolkit[/grey62]",
        )
    )


# ═════════════════════════════════════════════════════
# UI HELPERS
# ═════════════════════════════════════════════════════

def section(title):

    console.print()

    console.rule(
        f"[bold cyan] {title} [/bold cyan]",
        style="grey37",
    )


def info(label, value):

    console.print(
        f"[grey62]  {label:<12}[/grey62] "
        f"[cyan]{value}[/cyan]"
    )


def success(message):

    console.print(
        f"[green]  ✓[/green] {message}"
    )


def error(message):

    console.print(
        f"[red]  ✗[/red] {message}"
    )


def warning(message):

    console.print(
        f"[yellow]  ![/yellow] {message}"
    )


def muted(message):

    console.print(
        f"[grey62]  {message}[/grey62]"
    )


# ═════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═════════════════════════════════════════════════════

def build_parser():

    parser = argparse.ArgumentParser(
        prog="nova",
        description="Nova Web Security Fuzzing Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        required=False,
        help="Wordlist path",
    )

    parser.add_argument(
        "-m",
        "--mode",
        required=True,
        choices=[
            "path",
            "param",
            "post",
            "json",
            "subdomain",
            "recursive",
            "payload",
            "xxe",
        ],
        help="Discovery mode",
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum pages to crawl",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout (default: 10)",
    )

    parser.add_argument(
        "--rate",
        type=float,
        default=0,
        help="Request rate limit",
    )

    parser.add_argument(
        "--value",
        default="nova",
        help="Value used for parameter testing",
    )

    parser.add_argument(
        "-t",
        "--type",
        dest="payload_type",
        choices=[
            "xss",
            "sqli",
            "ssti",
            "lfi",
            "ssrf",
            "xxe",
            "command",
            "generic",
        ],
        default="generic",
        help="Payload category",
    )

    parser.add_argument(
        "-p",
        "--parameter",
        default="q",
        help="Parameter to inject payload into",
    )

    return parser


# ═════════════════════════════════════════════════════
# SAFE RICH TEXT
# ═════════════════════════════════════════════════════

def safe_text(value, style=None):

    """
    Convert any value to Rich Text.

    Important:
    Do NOT use markup=True here.

    This prevents payloads such as:

        [/al/.source+/ert/.source]

    from being interpreted as Rich markup.
    """

    return Text(
        str(value),
        style=style,
    )


# ═════════════════════════════════════════════════════
# RESULTS
# ═════════════════════════════════════════════════════

def display_results(results, engine):

    section("FINDINGS")

    if not results:

        warning(
            "No interesting findings detected"
        )

    else:

        table = Table(
            box=box.ROUNDED,
            border_style="grey37",
            header_style="bold cyan",
            row_styles=[
                "",
                "dim",
            ],
            expand=True,
        )

        table.add_column(
            "CONFIDENCE",
            justify="center",
            no_wrap=True,
        )

        table.add_column(
            "TYPE",
            no_wrap=True,
        )

        table.add_column(
            "VALUE",
            overflow="fold",
        )

        table.add_column(
            "STATUS",
            justify="center",
            no_wrap=True,
        )

        table.add_column(
            "SCORE",
            justify="center",
            no_wrap=True,
        )

        for result in results:

            confidence = str(
                getattr(
                    result,
                    "confidence",
                    "LOW",
                )
            )

            confidence_lower = (
                confidence.lower()
            )

            if confidence_lower in (
                "high",
                "critical",
            ):

                confidence_style = (
                    "bold red"
                )

            elif confidence_lower == "medium":

                confidence_style = (
                    "bold yellow"
                )

            else:

                confidence_style = (
                    "green"
                )

            result_type = getattr(
                result,
                "type",
                "unknown",
            )

            result_value = getattr(
                result,
                "value",
                "",
            )

            result_status = getattr(
                result,
                "status",
                "",
            )

            result_score = getattr(
                result,
                "score",
                0,
            )

            table.add_row(

                # SAFE: Text does not parse
                # Rich markup.
                safe_text(
                    confidence,
                    confidence_style,
                ),

                # SAFE
                safe_text(
                    result_type
                ),

                # VERY IMPORTANT:
                # Payloads are displayed as
                # plain text.
                safe_text(
                    result_value
                ),

                safe_text(
                    result_status
                ),

                safe_text(
                    result_score
                ),
            )

        console.print(table)

    section("SCAN SUMMARY")

    summary = Table(
        box=box.SIMPLE,
        show_header=False,
        border_style="grey37",
    )

    summary.add_column(
        style="grey62"
    )

    summary.add_column(
        style="cyan"
    )

    summary.add_row(
        "Findings",
        str(len(results)),
    )

    try:

        summary.add_row(
            "Requests",
            str(engine.request_count),
        )

    except AttributeError:

        pass

    console.print(summary)


# ═════════════════════════════════════════════════════
# SUBDOMAIN
# ═════════════════════════════════════════════════════

def scanner_subdomain(
    requester,
    target,
    wordlist,
    timeout,
):

    scanner = SubdomainDiscovery(
        wordlist=wordlist,
        timeout=timeout,
    )

    return scanner.scan(
        target
    )


def display_subdomain_results(results):

    if not results:

        warning(
            "No subdomains found"
        )

        return

    table = Table(
        box=box.ROUNDED,
        border_style="grey37",
        header_style="bold cyan",
    )

    table.add_column(
        "HOSTNAME",
        style="cyan",
    )

    table.add_column(
        "ADDRESSES",
        style="white",
    )

    for result in results:

        hostname = result.get(
            "hostname",
            "",
        )

        addresses = result.get(
            "addresses",
            "",
        )

        table.add_row(
            safe_text(hostname),
            safe_text(addresses),
        )

    console.print(table)


# ═════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════

def main():

    banner()

    parser = build_parser()

    args = parser.parse_args()

    # ═════════════════════════════════════════════════
    # WORDLIST VALIDATION
    # ═════════════════════════════════════════════════

    if args.mode != "xxe" and not args.wordlist:

        parser.error(
            f"the following arguments are required "
            f"for mode '{args.mode}': "
            f"-w/--wordlist"
        )

    # ═════════════════════════════════════════════════
    # CONFIGURATION
    # ═════════════════════════════════════════════════

    section("SCAN CONFIGURATION")

    info(
        "Target",
        args.url,
    )

    info(
        "Mode",
        args.mode,
    )

    info(
        "Wordlist",
        (
            args.wordlist
            if args.wordlist
            else "Not required"
        ),
    )

    info(
        "Timeout",
        f"{args.timeout}s",
    )

    info(
        "Rate",
        (
            args.rate
            if args.rate
            else "Unlimited"
        ),
    )

    if args.mode == "recursive":

        info(
            "Max Pages",
            args.max_pages,
        )

    # ═════════════════════════════════════════════════
    # WORDLIST
    # ═════════════════════════════════════════════════

    words = []

    if args.mode != "xxe":

        section("WORDLIST")

        try:

            words = Wordlist.load(
                args.wordlist
            )

        except OSError as exc:

            error(
                str(exc)
            )

            return 1

        if not words:

            error(
                "Wordlist is empty"
            )

            return 1

        success(
            f"Loaded {len(words)} words"
        )

    else:

        section("WORDLIST")

        muted(
            "Not required for XXE detection"
        )

    # ═════════════════════════════════════════════════
    # REQUESTER
    # ═════════════════════════════════════════════════

    requester = Requester(
        timeout=args.timeout,
        rate=args.rate,
    )

    # ═════════════════════════════════════════════════
    # SUBDOMAIN
    # ═════════════════════════════════════════════════

    if args.mode == "subdomain":

        section(
            "SUBDOMAIN DISCOVERY"
        )

        muted(
            "Starting discovery..."
        )

        results = scanner_subdomain(
            requester=requester,
            target=args.url,
            wordlist=words,
            timeout=args.timeout,
        )

        display_subdomain_results(
            results
        )

        section(
            "SCAN SUMMARY"
        )

        success(
            f"Found: {len(results)}"
        )

        return 0

    # ═════════════════════════════════════════════════
    # ENGINE
    # ═════════════════════════════════════════════════

    engine = NovaEngine(
        requester=requester,
        target=args.url,
    )

    # ═════════════════════════════════════════════════
    # XXE
    # ═════════════════════════════════════════════════

    if args.mode == "xxe":

        section(
            "XXE DETECTION"
        )

        muted(
            "Running safe XML entity detection..."
        )

        scanner = XXEDiscovery(
            requester=requester,
            engine=engine,
        )

        try:

            results = scanner.scan(
                target=args.url,
            )

        except Exception as exc:

            error(
                f"XXE scan failed: {exc}"
            )

            return 1

        if results:

            success(
                "Potential XXE evidence detected"
            )

        else:

            muted(
                "No XXE evidence detected"
            )

    else:

        # ═════════════════════════════════════════════
        # CALIBRATION
        # ═════════════════════════════════════════════

        section(
            "ENGINE CALIBRATION"
        )

        muted(
            "Calibrating target baseline..."
        )

        try:

            baseline = engine.calibrate()

        except Exception as exc:

            error(
                f"Calibration failed: {exc}"
            )

            return 1

        if baseline.error:

            error(
                f"Calibration failed: "
                f"{baseline.error}"
            )

            return 1

        success(
            "Baseline established"
        )

        info(
            "Status",
            baseline.status,
        )

        info(
            "Size",
            f"{baseline.content_length} bytes",
        )

        # ═════════════════════════════════════════════
        # PATH
        # ═════════════════════════════════════════════

        if args.mode == "path":

            section(
                "PATH DISCOVERY"
            )

            scanner = PathDiscovery(
                requester=requester,
                engine=engine,
                wordlist=words,
            )

            results = scanner.scan(
                args.url
            )

        # ═════════════════════════════════════════════
        # PARAM
        # ═════════════════════════════════════════════

        elif args.mode == "param":

            section(
                "PARAMETER DISCOVERY"
            )

            scanner = ParameterDiscovery(
                requester=requester,
                engine=engine,
                wordlist=words,
            )

            results = scanner.scan(
                target=args.url,
                value=args.value,
            )

        # ═════════════════════════════════════════════
        # POST
        # ═════════════════════════════════════════════

        elif args.mode == "post":

            section(
                "POST PARAMETER DISCOVERY"
            )

            scanner = PostParameterDiscovery(
                requester=requester,
                engine=engine,
                wordlist=words,
            )

            results = scanner.scan(
                target=args.url,
                value=args.value,
            )

        # ═════════════════════════════════════════════
        # JSON
        # ═════════════════════════════════════════════

        elif args.mode == "json":

            section(
                "JSON PARAMETER DISCOVERY"
            )

            scanner = JSONParameterDiscovery(
                requester=requester,
                engine=engine,
                wordlist=words,
            )

            results = scanner.scan(
                target=args.url,
                value=args.value,
            )

        # ═════════════════════════════════════════════
        # PAYLOAD
        # ═════════════════════════════════════════════

        elif args.mode == "payload":

            section(
                f"{args.payload_type.upper()} "
                "PAYLOAD FUZZING"
            )

            info(
                "Parameter",
                args.parameter,
            )

            info(
                "Payload Type",
                args.payload_type,
            )

            scanner = PayloadDiscovery(
                requester=requester,
                engine=engine,
                wordlist=words,
            )

            results = scanner.scan(
                target=args.url,
                parameter=args.parameter,
                payload_type=args.payload_type,
            )

        # ═════════════════════════════════════════════
        # RECURSIVE
        # ═════════════════════════════════════════════

        elif args.mode == "recursive":

            section(
                "RECURSIVE DISCOVERY"
            )

            scanner = RecursiveDiscovery(
                requester=requester,
                engine=engine,
                wordlist=words,
                max_pages=args.max_pages,
            )

            recursive_results = scanner.scan(
                args.url
            )

            results = recursive_results[
                "findings"
            ]

            success(
                "Recursive discovery completed"
            )

            info(
                "Crawled Pages",
                len(
                    recursive_results[
                        "pages"
                    ]
                ),
            )

        else:

            parser.error(
                "Unsupported mode"
            )

            return 1

    # ═════════════════════════════════════════════════
    # SORT
    # ═════════════════════════════════════════════════

    try:

        engine.results.sort()

    except AttributeError:

        pass

    # ═════════════════════════════════════════════════
    # DISPLAY
    # ═════════════════════════════════════════════════

    display_results(
        results,
        engine,
    )

    # ═════════════════════════════════════════════════
    # COMPLETE
    # ═════════════════════════════════════════════════

    console.print()

    console.print(
        Text(
            "nova",
            style="bold magenta",
        ),
        end="",
    )

    console.print(
        Text(
            " > scan complete",
            style="grey62",
        )
    )

    console.print()

    return 0




if __name__ == "__main__":

    sys.exit(
        main()
    )