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
        epilog="""
Examples:
  Single file conversion:
    %(prog)s capture.pcap flows.csv
    %(prog)s capture.pcap flows.json --output-format json
    %(prog)s capture.pcap flows --split-by-protocol
    %(prog)s capture.pcap flows.csv --quick-preview 5
    %(prog)s capture.pcap tcp_flows.xlsx --output-format xlsx --protocols tcp

  Directory processing:
    %(prog)s -d ./pcaps/ -c ./out/                    # Convert each PCAP to separate CSV
    %(prog)s -d ./pcaps/ -c ./out/ --merge            # Merge all PCAPs into one CSV
    %(prog)s -d ./pcaps/ -c ./out/ --output-format json  # Convert to JSON format
        """
    )
    
    # Mutually exclusive group for single file vs directory processing
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        'pcap_file',
        nargs='?',
        help='Input PCAP file path (for single file processing)'
    )
    input_group.add_argument(
        '-d', '--directory',
        help='Input directory containing PCAP files (for batch processing)'
    )
    
    # Output argument - required for single file, optional flag for directory
    parser.add_argument(
        'output_file',
        nargs='?',
        help='Output file path (for single file processing)'
    )
    
    parser.add_argument(
        '-c', '--output-dir',
        help='Output directory (for batch processing)'
    )
    
    parser.add_argument(
        '--merge',
        action='store_true',
        help='Merge all PCAP files into single output (directory processing only)'
    )
    
    parser.add_argument(
        '--protocols',
        help='Comma-separated list of protocols to include (tcp,udp,icmp,arp,dns,all)',
        default='all'
    )
    
    parser.add_argument(
        '--max-flows',
        type=int,
        help='Maximum number of flows to analyze'
    )
    
    parser.add_argument(
        '--output-format', '-of',
        choices=['csv', 'json', 'xlsx'],
        default='csv',
        help='Output file format (default: csv)'
    )
    
    parser.add_argument(
        '--quick-preview',
        type=int,
        default=0,
        help='Show first N flows before conversion (single file only)'
    )
    
    parser.add_argument(
        '--split-by-protocol',
        action='store_true',
        help='Create separate files for each protocol (single file only)'
    )

    parser.add_argument(
        '--stream',
        action='store_true',
        help='Use streaming mode (PcapReader) instead of loading the whole file into memory'
    )

    parser.add_argument(
        '--chunk-size',
        type=int,
        default=1024,
        help='Chunk size in MB for large files (default: 1024MB = 1GB)'
    )
    
    parser.add_argument(
        '--flow-timeout',
        type=int,
        default=60,
        help='Flow timeout in seconds (default: 60)'
    )
    
    parser.add_argument(
        '--max-workers',
        type=int,
        default=min(multiprocessing.cpu_count(), 4),
        help=f'Maximum parallel workers for chunk processing (default: {min(multiprocessing.cpu_count(), 4)})'
    )

    parser.add_argument(
        '--report-dir',
        help='Directory to save analysis reports (default: same as output file)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set up logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.WARNING)
    
    # Validate arguments based on processing mode
    if args.directory:
        # Directory processing mode
        if not args.output_dir:
            print("Error: --output-dir (-c) is required when processing a directory")
            sys.exit(1)
        
        if not Path(args.directory).exists():
            print(f"Error: Input directory '{args.directory}' does not exist")
            sys.exit(1)
        
        if not Path(args.directory).is_dir():
            print(f"Error: '{args.directory}' is not a directory")
            sys.exit(1)
            
        # Some options don't make sense for directory processing
        if args.quick_preview > 0:
            print("Warning: --quick-preview is not supported in directory processing mode")
            args.quick_preview = 0
            
        if args.split_by_protocol:
            print("Warning: --split-by-protocol is not supported in directory processing mode")
            args.split_by_protocol = False
            
    else:
        # Single file processing mode
        if not args.pcap_file or not args.output_file:
            print("Error: Both pcap_file and output_file are required for single file processing")
            sys.exit(1)
            
        if not Path(args.pcap_file).exists():
            print(f"Error: Input file '{args.pcap_file}' does not exist")
            sys.exit(1)
        
        if args.merge:
            print("Warning: --merge option is only applicable to directory processing")
    
    # Parse protocols
    protocols = None
    if args.protocols and args.protocols.lower() != 'all':
        protocols = [p.strip().lower() for p in args.protocols.split(',')]
        
        # Validate protocols
        converter = PCAPToFlowConverter()
        invalid_protocols = [p for p in protocols if p not in converter.supported_protocols]
        if invalid_protocols:
            print(f"Error: Unsupported protocols: {', '.join(invalid_protocols)}")
            print(f"Supported protocols: {', '.join(converter.supported_protocols)}")
            sys.exit(1)
    
    # Set up converter
    converter = PCAPToFlowConverter()
    converter.chunk_size_mb = args.chunk_size
    converter.flow_timeout = args.flow_timeout
    converter.max_workers = args.max_workers
    
    # Execute based on processing mode
    if args.directory:
        # Directory processing
        print(f"*) Starting batch PCAP flow analysis...")
        print(f"-> Input directory: {args.directory}")
        print(f"-> Output directory: {args.output_dir}")
        print(f"-> Format: {args.output_format.upper()}")
        print(f"-> Mode: {'Merged' if args.merge else 'Separate files'}")
        
        if args.merge:
            converter.process_directory_merged(
                args.directory,
                args.output_dir,
                protocols,
                args.max_flows,
                args.output_format,
                args.stream,
                report_dir=args.report_dir
            )
        else:
            converter.process_directory_separate(
                args.directory,
                args.output_dir,
                protocols,
                args.max_flows,
                args.output_format,
                args.stream,
                report_dir=args.report_dir
            )
    else:
        # Single file processing
        # Adjust output file extension if needed
        output_path = Path(args.output_file)
        if not args.split_by_protocol:
            # Ensure correct extension for output format
            if args.output_format == 'json' and not output_path.suffix == '.json':
                output_path = output_path.with_suffix('.json')
            elif args.output_format == 'xlsx' and not output_path.suffix == '.xlsx':
                output_path = output_path.with_suffix('.xlsx')
            elif args.output_format == 'csv' and not output_path.suffix == '.csv':
                output_path = output_path.with_suffix('.csv')
        
        # Create output directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"*) Starting PCAP flow analysis...")
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
            report_dir=args.report_dir
        )
    
    print(f"\n Flow analysis completed successfully!")


if __name__ == "__main__":
    main()