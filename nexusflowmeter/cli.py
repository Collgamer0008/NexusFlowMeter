import sys
import logging
import argparse
import multiprocessing
from pathlib import Path

# Import your PCAPToFlowConverter class
from nexusflowmeter.converter import PCAPToFlowConverter


def main():
    """Main function to handle command line arguments and run the flow analyzer."""
    parser = argparse.ArgumentParser(
        description="Convert PCAP files to flow-based analysis (CSV, JSON, Excel)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s capture.pcap flows.csv\n"
            "  %(prog)s capture.pcap flows.json --output-format json\n"
            "  %(prog)s capture.pcap flows --split-by-protocol\n"
            "  %(prog)s capture.pcap flows.csv --quick-preview 5\n"
            "  %(prog)s capture.pcap tcp_flows.xlsx --output-format xlsx --protocols tcp"
        ),
    )

    parser.add_argument("pcap_file", help="Input PCAP file path")
    parser.add_argument(
        "output_file", help="Output file path (extension will be adjusted based on format)"
    )
    parser.add_argument(
        "--protocols",
        help="Comma-separated list of protocols to include (tcp,udp,icmp,arp,dns,all)",
        default="all",
    )
    parser.add_argument("--max-flows", type=int, help="Maximum number of flows to analyze")
    parser.add_argument(
        "--output-format",
        "-of",
        choices=["csv", "json", "xlsx"],
        default="csv",
        help="Output file format (default: csv)",
    )
    parser.add_argument(
        "--quick-preview", type=int, default=0, help="Show first N flows before conversion"
    )
    parser.add_argument(
        "--split-by-protocol",
        action="store_true",
        help="Create separate files for each protocol",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Use streaming mode (PcapReader) instead of loading the whole file into memory",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1024,
        help="Chunk size in MB for large files (default: 1024MB = 1GB)",
    )
    parser.add_argument(
        "--flow-timeout",
        type=int,
        default=60,
        help="Flow timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=min(multiprocessing.cpu_count(), 4),
        help=f"Maximum parallel workers for chunk processing "
             f"(default: {min(multiprocessing.cpu_count(), 4)})",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    # Validate input file
    if not Path(args.pcap_file).exists():
        print(f"Error: Input file '{args.pcap_file}' does not exist")
        sys.exit(1)

    # Parse protocols
    protocols = None
    if args.protocols and args.protocols.lower() != "all":
        protocols = [p.strip().lower() for p in args.protocols.split(",")]

        # Validate protocols
        converter = PCAPToFlowConverter()
        invalid_protocols = [p for p in protocols if p not in converter.supported_protocols]
        if invalid_protocols:
            print(f"Error: Unsupported protocols: {', '.join(invalid_protocols)}")
            print(f"Supported protocols: {', '.join(converter.supported_protocols)}")
            sys.exit(1)

    # Adjust output file extension if needed
    output_path = Path(args.output_file)
    if not args.split_by_protocol:
        if args.output_format == "json" and output_path.suffix != ".json":
            output_path = output_path.with_suffix(".json")
        elif args.output_format == "xlsx" and output_path.suffix != ".xlsx":
            output_path = output_path.with_suffix(".xlsx")
        elif args.output_format == "csv" and output_path.suffix != ".csv":
            output_path = output_path.with_suffix(".csv")

    # Create output directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert PCAP to flows
    converter = PCAPToFlowConverter()
    converter.chunk_size_mb = args.chunk_size
    converter.flow_timeout = args.flow_timeout
    converter.max_workers = args.max_workers

    print("*) Starting PCAP flow analysis...")
    print(f"-> Input: {args.pcap_file}")
    print(f"-> Output: {output_path} ({args.output_format.upper()})")

    converter.convert(
        args.pcap_file,
        str(output_path),
        protocols,
        args.max_flows,
        args.output_format,
        args.quick_preview,
        args.split_by_protocol,
        stream=args.stream,
    )

    print("\nFlow analysis completed successfully!")


if __name__ == "__main__":
    main()
