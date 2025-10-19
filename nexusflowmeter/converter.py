#!/usr/bin/env python3
"""
PCAP to Flow Analyzer Tool

This tool converts packet capture (PCAP) files to flow-based analysis in multiple formats.
Analyzes network flows instead of individual packets for better traffic insights.

Dependencies:
- scapy: pip install scapy
- pandas: pip install pandas
- openpyxl: pip install openpyxl (for Excel output)

Usage:
    python pcap_to_flows.py input.pcap output.csv
    python pcap_to_flows.py input.pcap output.json --output-format json
    python pcap_to_flows.py input.pcap output --split-by-protocol
    python pcap_to_flows.py input.pcap output.csv --quick-preview 10
"""

# import argparse
# import csv
import sys
import os
# import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import logging
# import math
# from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import pandas as pd


try:
    from scapy.all import PcapReader, rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, wrpcap
    import pandas as pd
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Please install required packages:")
    print("pip install scapy pandas")
    sys.exit(1)


class FlowKey:
    """Represents a unique network flow identifier."""
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # Normalize flow to be bidirectional (smaller IP:port first)
        if (src_ip, src_port) < (dst_ip, dst_port):
            self.ip1, self.port1 = src_ip, src_port
            self.ip2, self.port2 = dst_ip, dst_port
            self.direction = "forward"
        else:
            self.ip1, self.port1 = dst_ip, dst_port
            self.ip2, self.port2 = src_ip, src_port
            self.direction = "reverse"
            
        self.protocol = protocol
        
    def __hash__(self):
        return hash((self.ip1, self.port1, self.ip2, self.port2, self.protocol))
        
    def __eq__(self, other):
        return (self.ip1, self.port1, self.ip2, self.port2, self.protocol) == \
               (other.ip1, other.port1, other.ip2, other.port2, other.protocol)
               
    def __str__(self):
        if self.port1 and self.port2:
            return f"{self.ip1}:{self.port1} <-> {self.ip2}:{self.port2} ({self.protocol})"
        else:
            return f"{self.ip1} <-> {self.ip2} ({self.protocol})"


class NetworkFlow:
    """Represents a network flow with all its characteristics."""
    
    def __init__(self, flow_key):
        self.flow_key = flow_key
        self.packets = []
        self.start_time = None
        self.end_time = None
        
        # Flow statistics
        self.forward_packets = 0
        self.backward_packets = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.forward_payload_bytes = 0
        self.backward_payload_bytes = 0
        
        # TCP-specific
        self.tcp_flags = set()
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.ack_count = 0
        
        # Timing statistics
        self.inter_arrival_times = []
        self.packet_sizes = []
        
    def add_packet(self, packet, timestamp, is_forward):
        """Add a packet to this flow."""
        self.packets.append((packet, timestamp, is_forward))
        
        if self.start_time is None:
            self.start_time = timestamp
        self.end_time = timestamp
        
        # Update statistics
        packet_size = len(packet)
        self.packet_sizes.append(packet_size)
        
        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += packet_size
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                payload_size = len(packet.payload.payload) if hasattr(packet.payload, 'payload') else 0
                self.forward_payload_bytes += payload_size
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_size
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                payload_size = len(packet.payload.payload) if hasattr(packet.payload, 'payload') else 0
                self.backward_payload_bytes += payload_size
        
        # TCP flag analysis
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flags = str(tcp_layer.flags)
            self.tcp_flags.add(flags)
            
            if 'S' in flags and 'A' not in flags:  # SYN
                self.syn_count += 1
            if 'F' in flags:  # FIN
                self.fin_count += 1
            if 'R' in flags:  # RST
                self.rst_count += 1
            if 'A' in flags:  # ACK
                self.ack_count += 1
        
        # Calculate inter-arrival times
        if len(self.packets) > 1:
            prev_time = self.packets[-2][1]
            inter_arrival = (timestamp - prev_time).total_seconds() * 1000  # in ms
            self.inter_arrival_times.append(inter_arrival)
    
    def get_flow_stats(self, source_file=None):
        """Calculate comprehensive flow statistics."""
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time != self.start_time else 0
        total_packets = len(self.packets)
        total_bytes = self.forward_bytes + self.backward_bytes
        total_payload_bytes = self.forward_payload_bytes + self.backward_payload_bytes
        
        # Flow rates
        packets_per_second = total_packets / duration if duration > 0 else 0
        bytes_per_second = total_bytes / duration if duration > 0 else 0
        
        # Packet size statistics
        min_packet_size = min(self.packet_sizes) if self.packet_sizes else 0
        max_packet_size = max(self.packet_sizes) if self.packet_sizes else 0
        avg_packet_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
        
        # Inter-arrival time statistics
        avg_inter_arrival = sum(self.inter_arrival_times) / len(self.inter_arrival_times) if self.inter_arrival_times else 0
        min_inter_arrival = min(self.inter_arrival_times) if self.inter_arrival_times else 0
        max_inter_arrival = max(self.inter_arrival_times) if self.inter_arrival_times else 0
        
        # Flow characteristics
        is_bidirectional = self.forward_packets > 0 and self.backward_packets > 0
        forward_backward_ratio = self.forward_packets / self.backward_packets if self.backward_packets > 0 else float('inf')
        
        # Connection state (for TCP)
        connection_state = "Unknown"
        if self.flow_key.protocol == "TCP":
            if self.syn_count > 0 and self.fin_count == 0 and self.rst_count == 0:
                connection_state = "Established"
            elif self.syn_count > 0 and self.fin_count > 0:
                connection_state = "Closed"
            elif self.rst_count > 0:
                connection_state = "Reset"
            elif self.syn_count == 0:
                connection_state = "Ongoing"
        
        stats = {
            'flow_id': str(self.flow_key),
            'src_ip': self.flow_key.ip1,
            'dst_ip': self.flow_key.ip2,
            'src_port': self.flow_key.port1 if self.flow_key.port1 else '',
            'dst_port': self.flow_key.port2 if self.flow_key.port2 else '',
            'protocol': self.flow_key.protocol,
            
            # Timing
            'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'end_time': self.end_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'duration_seconds': duration,
            
            # Packet counts
            'total_packets': total_packets,
            'forward_packets': self.forward_packets,
            'backward_packets': self.backward_packets,
            'is_bidirectional': is_bidirectional,
            'forward_backward_ratio': forward_backward_ratio,
            
            # Byte counts
            'total_bytes': total_bytes,
            'forward_bytes': self.forward_bytes,
            'backward_bytes': self.backward_bytes,
            'total_payload_bytes': total_payload_bytes,
            'forward_payload_bytes': self.forward_payload_bytes,
            'backward_payload_bytes': self.backward_payload_bytes,
            
            # Flow rates
            'packets_per_second': packets_per_second,
            'bytes_per_second': bytes_per_second,
            
            # Packet size statistics
            'min_packet_size': min_packet_size,
            'max_packet_size': max_packet_size,
            'avg_packet_size': avg_packet_size,
            
            # Inter-arrival times (in milliseconds)
            'avg_inter_arrival_ms': avg_inter_arrival,
            'min_inter_arrival_ms': min_inter_arrival,
            'max_inter_arrival_ms': max_inter_arrival,
            
            # TCP-specific
            'tcp_flags': ','.join(sorted(self.tcp_flags)) if self.tcp_flags else '',
            'syn_count': self.syn_count,
            'fin_count': self.fin_count,
            'rst_count': self.rst_count,
            'ack_count': self.ack_count,
            'connection_state': connection_state
        }
        
        # Add source file information if provided
        if source_file:
            stats['source_file'] = os.path.basename(source_file)
            
        return stats


def process_chunk_worker(chunk_file, protocols, max_flows, stream):
    """
    Worker used by ProcessPoolExecutor.
    Must be at module/top-level so it is picklable for multiprocessing.
    Returns: dict {FlowKey: NetworkFlow}
    """
    try:
        converter = PCAPToFlowConverter()
        # For chunk files we can use non-streaming (rdpcap), chunks are expected smaller:
        if stream:
            flows = converter.convert_chunk_to_flows_streaming(chunk_file, protocols, max_flows)
        else:
            flows = converter.convert_chunk_to_flows_nonstreaming(chunk_file, protocols, max_flows)
        return flows
    except Exception as e:
        print(f"Worker error for {chunk_file}: {e}")
        return {}


class PCAPToFlowConverter:
    """Converts PCAP files to flow-based analysis in multiple formats."""
    
    def __init__(self):
        self.supported_protocols = ['tcp', 'udp', 'icmp', 'arp', 'dns', 'all']
        self.supported_formats = ['csv', 'json', 'xlsx']
        self.chunk_size_mb = 1024  # Split files larger than 1GB (increased from 100MB)
        self.flow_timeout = 60  # Flow timeout in seconds
        self.max_workers = min(multiprocessing.cpu_count(), 4)  # Parallel processing workers
        
    def find_pcap_files(self, directory):
        """Find all PCAP files in a directory."""
        pcap_files = []
        directory = Path(directory)
        
        # Common PCAP file extensions
        pcap_extensions = ['*.pcap', '*.pcapng', '*.cap', '*.dmp']
        
        for ext in pcap_extensions:
            pcap_files.extend(directory.glob(ext))
            # Also search case insensitive
            pcap_files.extend(directory.glob(ext.upper()))
        
        # Remove duplicates and sort
        pcap_files = sorted(list(set(pcap_files)))
        
        print(f"Found {len(pcap_files)} PCAP files in {directory}")
        for pcap_file in pcap_files:
            file_size = pcap_file.stat().st_size / (1024 * 1024)  # MB
            print(f"  - {pcap_file.name} ({file_size:.1f} MB)")
        
        return pcap_files
    
    def process_directory_separate(self, input_dir, output_dir, protocols=None, max_flows=None, 
                                 output_format='csv', stream=False, report_dir=None):
        """Process each PCAP file in directory separately."""
        pcap_files = self.find_pcap_files(input_dir)
        
        if not pcap_files:
            print(f"No PCAP files found in {input_dir}")
            return
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        successful_conversions = 0
        failed_conversions = []
        
        print(f"\nProcessing {len(pcap_files)} PCAP files separately...")
        
        for i, pcap_file in enumerate(pcap_files, 1):
            try:
                print(f"\n[{i}/{len(pcap_files)}] Processing {pcap_file.name}...")
                
                # Generate output filename
                output_filename = f"{pcap_file.stem}_flows.{output_format}"
                output_file = output_path / output_filename
                
                # Convert this PCAP file
                self.convert(
                    str(pcap_file), 
                    str(output_file), 
                    protocols, 
                    max_flows,
                    output_format,
                    quick_preview_count=0,
                    split_by_protocol=False,
                    stream=stream,
                    suppress_output=True,  # Suppress detailed output for batch processing
                    report_dir=report_dir
                )
                
                successful_conversions += 1
                print(f"  -> Saved to {output_file}")
                
            except Exception as e:
                print(f"  -> ERROR: Failed to process {pcap_file.name}: {e}")
                failed_conversions.append(pcap_file.name)
                continue
        
        # Summary
        print(f"\n{'='*50}")
        print(f"Batch Processing Summary:")
        print(f"  Successful: {successful_conversions}/{len(pcap_files)} files")
        print(f"  Failed: {len(failed_conversions)} files")
        if failed_conversions:
            print(f"  Failed files: {', '.join(failed_conversions)}")
        print(f"  Output directory: {output_path}")
        
    def process_directory_merged(self, input_dir, output_dir, protocols=None, max_flows=None, 
                               output_format='csv', stream=False, report_dir=None):
        """Process all PCAP files in directory and merge into single output."""
        pcap_files = self.find_pcap_files(input_dir)
        
        if not pcap_files:
            print(f"No PCAP files found in {input_dir}")
            return
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate merged output filename
        output_filename = f"merged_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{output_format}"
        output_file = output_path / output_filename
        
        print(f"\nProcessing {len(pcap_files)} PCAP files for merging...")
        
        all_flows = {}
        all_dataframes = []
        successful_files = 0
        failed_files = []
        
        for i, pcap_file in enumerate(pcap_files, 1):
            try:
                print(f"\n[{i}/{len(pcap_files)}] Analyzing {pcap_file.name}...")
                
                # Process this PCAP file to get flows
                file_flows = self.convert_pcap_to_flows_only(
                    str(pcap_file), 
                    protocols, 
                    max_flows, 
                    stream,
                    source_file=str(pcap_file)
                )
                
                if file_flows:
                    # Convert flows to DataFrame with source file info
                    flow_data = []
                    for flow_key, flow in file_flows.items():
                        flow_stats = flow.get_flow_stats(source_file=str(pcap_file))
                        flow_data.append(flow_stats)
                    
                    if flow_data:
                        df = pd.DataFrame(flow_data)
                        all_dataframes.append(df)
                        successful_files += 1
                        print(f"  -> Found {len(flow_data)} flows")
                    
                    # Also merge into global flows dictionary for overall statistics
                    for flow_key, flow in file_flows.items():
                        if flow_key in all_flows:
                            # Merge flows with same key from different files
                            existing_flow = all_flows[flow_key]
                            existing_flow.packets.extend(flow.packets)
                            existing_flow.forward_packets += flow.forward_packets
                            existing_flow.backward_packets += flow.backward_packets
                            existing_flow.forward_bytes += flow.forward_bytes
                            existing_flow.backward_bytes += flow.backward_bytes
                            existing_flow.forward_payload_bytes += flow.forward_payload_bytes
                            existing_flow.backward_payload_bytes += flow.backward_payload_bytes
                            
                            # Update time range
                            if flow.start_time < existing_flow.start_time:
                                existing_flow.start_time = flow.start_time
                            if flow.end_time > existing_flow.end_time:
                                existing_flow.end_time = flow.end_time
                            
                            # Merge TCP statistics
                            existing_flow.tcp_flags.update(flow.tcp_flags)
                            existing_flow.syn_count += flow.syn_count
                            existing_flow.fin_count += flow.fin_count
                            existing_flow.rst_count += flow.rst_count
                            existing_flow.ack_count += flow.ack_count
                            
                            # Merge packet statistics
                            existing_flow.inter_arrival_times.extend(flow.inter_arrival_times)
                            existing_flow.packet_sizes.extend(flow.packet_sizes)
                        else:
                            all_flows[flow_key] = flow
                
            except Exception as e:
                print(f"  -> ERROR: Failed to process {pcap_file.name}: {e}")
                failed_files.append(pcap_file.name)
                continue
        
        if not all_dataframes:
            print("No flows found in any PCAP files!")
            return
        
        # Merge all DataFrames
        print(f"\nMerging flows from {successful_files} files...")
        merged_df = pd.concat(all_dataframes, ignore_index=True)
        
        # Sort by total bytes (most active flows first)
        merged_df = merged_df.sort_values('total_bytes', ascending=False).reset_index(drop=True)
        
        # Save merged results
        self.save_as_format(merged_df, output_file, output_format)
        print(f"-> Merged flows saved to: {output_file}")
        
        # Display summary
        print(f"\n{'='*20} Merged Flow Analysis Summary {'='*20}")
        print(f"*) Source files processed: {successful_files}/{len(pcap_files)}")
        print(f"*) Total flows in merged file: {len(merged_df)}")
        print(f"*) Unique flows across all files: {len(all_flows)}")
        
        if failed_files:
            print(f"*) Failed files: {', '.join(failed_files)}")
        
        # Show protocol distribution
        if len(merged_df) > 0:
            protocol_counts = merged_df['protocol'].value_counts()
            print(f"\n*) Protocol distribution:")
            for protocol, count in protocol_counts.items():
                percentage = (count / len(merged_df)) * 100
                print(f"  {protocol:<8}: {count:>6} flows ({percentage:>5.1f}%)")
        
        # Show source file distribution
        if 'source_file' in merged_df.columns:
            print(f"\n*) Flows by source file:")
            source_counts = merged_df['source_file'].value_counts()
            for source, count in source_counts.items():
                percentage = (count / len(merged_df)) * 100
                print(f"  {os.path.basename(source):<20}: {count:>6} flows ({percentage:>5.1f}%)")
        
        # Save detailed report
        if report_dir:
            report_path = Path(report_dir)
            report_path.mkdir(parents=True, exist_ok=True)
            report_file = report_path / f"merged_flows_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        else:
            report_file = output_path / f"merged_flows_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.save_merged_report(merged_df, report_file, pcap_files, successful_files, failed_files)
    
    def convert_pcap_to_flows_only(self, pcap_file, protocols=None, max_flows=None, stream=False, source_file=None):
        """Convert PCAP to flows without saving - for internal use in batch processing."""
        try:
            # Check if we need to split the PCAP file
            chunk_files = self.split_pcap_streaming(pcap_file, self.chunk_size_mb)
            is_chunked = len(chunk_files) > 1
            all_flows = {}
            
            if is_chunked and self.max_workers > 1:
                # Use parallel processing
                all_flows = self.process_chunks_parallel(chunk_files, stream, protocols, max_flows)
            else:
                # Sequential processing
                for chunk_file in chunk_files:
                    if stream:
                        chunk_flows = self.convert_chunk_to_flows_streaming(chunk_file, protocols, max_flows)
                    else:
                        chunk_flows = self.convert_chunk_to_flows_nonstreaming(chunk_file, protocols, max_flows)
                    
                    # Merge flows
                    for flow_key, flow in chunk_flows.items():
                        if flow_key in all_flows:
                            existing_flow = all_flows[flow_key]
                            # Merge logic (same as in convert method)
                            existing_flow.packets.extend(flow.packets)
                            existing_flow.forward_packets += flow.forward_packets
                            existing_flow.backward_packets += flow.backward_packets
                            existing_flow.forward_bytes += flow.forward_bytes
                            existing_flow.backward_bytes += flow.backward_bytes
                            existing_flow.forward_payload_bytes += flow.forward_payload_bytes
                            existing_flow.backward_payload_bytes += flow.backward_payload_bytes
                            
                            if flow.start_time < existing_flow.start_time:
                                existing_flow.start_time = flow.start_time
                            if flow.end_time > existing_flow.end_time:
                                existing_flow.end_time = flow.end_time
                            
                            existing_flow.tcp_flags.update(flow.tcp_flags)
                            existing_flow.syn_count += flow.syn_count
                            existing_flow.fin_count += flow.fin_count
                            existing_flow.rst_count += flow.rst_count
                            existing_flow.ack_count += flow.ack_count
                            
                            existing_flow.inter_arrival_times.extend(flow.inter_arrival_times)
                            existing_flow.packet_sizes.extend(flow.packet_sizes)
                        else:
                            all_flows[flow_key] = flow
            
            # Clean up temporary files
            if is_chunked:
                for chunk_file in chunk_files:
                    if chunk_file != pcap_file:
                        try:
                            os.remove(chunk_file)
                        except:
                            pass
                temp_dir = os.path.dirname(chunk_files[0])
                try:
                    os.rmdir(temp_dir)
                except:
                    pass
            
            return all_flows
            
        except Exception as e:
            print(f"Error processing {pcap_file}: {e}")
            return {}
    
    def save_merged_report(self, df, report_file, pcap_files, successful_files, failed_files):
        """Save a detailed report for merged processing."""
        with open(report_file, 'w') as f:
            f.write("PCAP Merged Flow Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total PCAP files found: {len(pcap_files)}\n")
            f.write(f"Successfully processed: {successful_files}\n")
            f.write(f"Failed to process: {len(failed_files)}\n")
            f.write(f"Total flows in merged output: {len(df)}\n\n")
            
            if failed_files:
                f.write("Failed files:\n")
                for failed_file in failed_files:
                    f.write(f"  - {failed_file}\n")
                f.write("\n")
            
            f.write("Successfully processed files:\n")
            for pcap_file in pcap_files:
                if pcap_file.name not in failed_files:
                    f.write(f"  - {pcap_file.name}\n")
            f.write("\n")
            
            # Protocol distribution
            if len(df) > 0:
                f.write("Protocol Distribution:\n")
                f.write("-" * 30 + "\n")
                for protocol, count in df['protocol'].value_counts().items():
                    percentage = (count / len(df)) * 100
                    f.write(f"  {protocol:<8}: {count:>6} flows ({percentage:>5.1f}%)\n")
                
                # Source file distribution
                if 'source_file' in df.columns:
                    f.write(f"\nFlows by Source File:\n")
                    f.write("-" * 40 + "\n")
                    for source, count in df['source_file'].value_counts().items():
                        percentage = (count / len(df)) * 100
                        source_name = os.path.basename(source)
                        f.write(f"  {source_name:<25}: {count:>6} flows ({percentage:>5.1f}%)\n")
        
        print(f"-> Merged analysis report saved to: {report_file}")

    def get_file_size_mb(self, file_path):
        """Get file size in MB."""
        return os.path.getsize(file_path) / (1024 * 1024)
        
    def split_pcap_streaming(self, pcap_file, chunk_size_mb=1024):
        """Split large PCAP files into smaller chunks using streaming approach."""
        file_size_mb = self.get_file_size_mb(pcap_file)
        
        if file_size_mb <= chunk_size_mb:
            return [pcap_file]
            
        print(f"Large PCAP detected ({file_size_mb:.1f} MB). Splitting into {chunk_size_mb}MB chunks...")
        
        chunk_files = []
        temp_dir = tempfile.mkdtemp()
        current_chunk = []
        current_chunk_size = 0
        chunk_num = 1
        target_chunk_size_bytes = chunk_size_mb * 1024 * 1024
        
        try:
            with PcapReader(pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    packet_size = len(packet)
                    current_chunk.append(packet)
                    current_chunk_size += packet_size
                    
                    # Check if chunk is large enough
                    if current_chunk_size >= target_chunk_size_bytes:
                        # Save current chunk
                        chunk_file = os.path.join(temp_dir, f"chunk_{chunk_num}.pcap")
                        wrpcap(chunk_file, current_chunk)
                        chunk_files.append(chunk_file)
                        
                        # Reset for next chunk
                        current_chunk = []
                        current_chunk_size = 0
                        chunk_num += 1
                
                # Save remaining packets if any
                if current_chunk:
                    chunk_file = os.path.join(temp_dir, f"chunk_{chunk_num}.pcap")
                    wrpcap(chunk_file, current_chunk)
                    chunk_files.append(chunk_file)
                    
        except Exception as e:
            print(f"Error during PCAP splitting: {e}")
            # Cleanup on error
            for chunk_file in chunk_files:
                try:
                    os.remove(chunk_file)
                except:
                    pass
            try:
                os.rmdir(temp_dir)
            except:
                pass
            raise
            
        return chunk_files
        
    def merge_dataframes(self, dataframes):
        """Merge multiple dataframes."""
        if not dataframes:
            return pd.DataFrame()
            
        merged_df = pd.concat(dataframes, ignore_index=True)
        return merged_df
        
    def quick_preview_flows(self, flows, num_flows=5):
        """Display a quick preview of flows."""
        print(f"\n=== Flow Preview (First {min(num_flows, len(flows))} flows) ===")
        print(f"{'#':<3} {'Flow':<40} {'Packets':<8} {'Bytes':<8} {'Duration':<10} {'Rate':<10}")
        print("-" * 90)
        
        for i, (flow_key, flow) in enumerate(list(flows.items())[:num_flows], 1):
            stats = flow.get_flow_stats()
            duration_str = f"{stats['duration_seconds']:.1f}s"
            rate_str = f"{stats['packets_per_second']:.1f} pps"
            flow_str = f"{stats['src_ip']}:{stats['src_port']} <-> {stats['dst_ip']}:{stats['dst_port']}"
            if len(flow_str) > 38:
                flow_str = flow_str[:35] + "..."
            
            print(f"{i:<3} {flow_str:<40} {stats['total_packets']:<8} {stats['total_bytes']:<8} {duration_str:<10} {rate_str:<10}")
        
        print("-" * 90)
        
    def extract_flow_key(self, packet):
        """Extract flow key from packet."""
        src_ip = dst_ip = ""
        src_port = dst_port = 0
        protocol = "Unknown"
        
        # Extract IP information
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
        elif packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            src_ip = ipv6_layer.src
            dst_ip = ipv6_layer.dst
        
        # Extract port and protocol information
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol = "TCP"
            
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol = "UDP"
            
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            
        elif packet.haslayer(ARP):
            arp_layer = packet[ARP]
            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            protocol = "ARP"
        
        if src_ip and dst_ip:
            return FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
        return None
    
    def save_as_format(self, df, filepath, format_type):
        """Save DataFrame in specified format."""
        filepath = str(filepath)  # Ensure string path
        
        if format_type == 'csv':
            df.to_csv(filepath, index=False)
        elif format_type == 'json':
            # Convert DataFrame to JSON with proper formatting
            df.to_json(filepath, orient='records', indent=2, date_format='iso')
        elif format_type == 'xlsx':
            try:
                df.to_excel(filepath, index=False, engine='openpyxl')
            except ImportError:
                print("Warning: openpyxl not installed. Installing...")
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install", "openpyxl"])
                df.to_excel(filepath, index=False, engine='openpyxl')
        
    def save_report(self, df, report_file, pcap_file, protocols, processing_time):
        """Save a detailed processing report."""
        with open(report_file, 'w') as f:
            f.write("PCAP Flow Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Source file: {pcap_file}\n")
            f.write(f"Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Processing duration: {processing_time:.2f} seconds\n")
            f.write(f"Total flows analyzed: {len(df)}\n\n")
            
            if protocols:
                f.write(f"Protocol filter applied: {', '.join(protocols)}\n")
                
            f.write("Protocol Distribution:\n")
            f.write("-" * 30 + "\n")
            for protocol, count in df['protocol'].value_counts().items():
                percentage = (count / len(df)) * 100
                f.write(f"  {protocol:<8}: {count:>6} flows ({percentage:>5.1f}%)\n")
            
            # Flow duration statistics
            f.write(f"\nFlow Duration Statistics:\n")
            f.write("-" * 30 + "\n")
            f.write(f"  Average: {df['duration_seconds'].mean():>8.2f} seconds\n")
            f.write(f"  Median:  {df['duration_seconds'].median():>8.2f} seconds\n")
            f.write(f"  Max:     {df['duration_seconds'].max():>8.2f} seconds\n")
            
            # Flow size statistics
            f.write(f"\nFlow Size Statistics:\n")
            f.write("-" * 25 + "\n")
            f.write(f"  Avg packets/flow: {df['total_packets'].mean():>6.1f}\n")
            f.write(f"  Avg bytes/flow:   {df['total_bytes'].mean():>6.1f}\n")
            f.write(f"  Max packets/flow: {df['total_packets'].max():>6}\n")
            f.write(f"  Max bytes/flow:   {df['total_bytes'].max():>6}\n")
            
            # Top flows by packet count
            top_flows = df.nlargest(5, 'total_packets')
            f.write(f"\nTop 5 Flows by Packet Count:\n")
            f.write("-" * 40 + "\n")
            for _, flow in top_flows.iterrows():
                f.write(f"  {flow['src_ip']}:{flow['src_port']} <-> {flow['dst_ip']}:{flow['dst_port']} "
                       f"({flow['protocol']}): {flow['total_packets']} packets\n")
            
            # Bidirectional flows
            bidirectional = df['is_bidirectional'].sum()
            f.write(f"\nFlow Characteristics:\n")
            f.write("-" * 25 + "\n")
            f.write(f"  Bidirectional flows: {bidirectional} ({bidirectional/len(df)*100:.1f}%)\n")
            f.write(f"  Unidirectional flows: {len(df)-bidirectional} ({(len(df)-bidirectional)/len(df)*100:.1f}%)\n")
        
        print(f"\n-> Flow analysis report saved to: {report_file}")
    
    def filter_by_protocol(self, flows, protocols):
        """Filter flows by specified protocols."""
        if not protocols or 'all' in protocols:
            return flows
            
        filtered_flows = {}
        for flow_key, flow in flows.items():
            if flow_key.protocol.lower() in protocols:
                filtered_flows[flow_key] = flow
                
        return filtered_flows

    def process_chunks_parallel(self, chunk_files, stream, protocols=None, max_flows=None):
        """Process multiple chunks in parallel and merge results."""
        all_flows = {}

        # Prepare arguments for parallel processing
        worker_args = [(chunk_file, protocols, max_flows) for chunk_file in chunk_files]

        # Process chunks in parallel
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            print(f"Submitting {len(chunk_files)} chunks to {self.max_workers} workers...")

            # Correctly submit each worker with unpacked args
            future_to_chunk = {}
            for (chunk_file, prot, mflows) in worker_args:
                future = executor.submit(process_chunk_worker, chunk_file, prot, mflows, stream)
                future_to_chunk[future] = chunk_file

            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_chunk):
                chunk_file = future_to_chunk[future]
                chunk_name = os.path.basename(chunk_file)

                try:
                    chunk_flows = future.result()
                    completed += 1

                    print(f"Completed {completed}/{len(chunk_files)} chunks - {chunk_name}: {len(chunk_flows)} flows")

                    # Merge flows (same flow key from different chunks)
                    for flow_key, flow in chunk_flows.items():
                        if flow_key in all_flows:
                            existing_flow = all_flows[flow_key]
                            existing_flow.packets.extend(flow.packets)
                            existing_flow.forward_packets += flow.forward_packets
                            existing_flow.backward_packets += flow.backward_packets
                            existing_flow.forward_bytes += flow.forward_bytes
                            existing_flow.backward_bytes += flow.backward_bytes
                            existing_flow.forward_payload_bytes += flow.forward_payload_bytes
                            existing_flow.backward_payload_bytes += flow.backward_payload_bytes

                            # Update time range
                            if flow.start_time < existing_flow.start_time:
                                existing_flow.start_time = flow.start_time
                            if flow.end_time > existing_flow.end_time:
                                existing_flow.end_time = flow.end_time

                            # Merge TCP flags and counts
                            existing_flow.tcp_flags.update(flow.tcp_flags)
                            existing_flow.syn_count += flow.syn_count
                            existing_flow.fin_count += flow.fin_count
                            existing_flow.rst_count += flow.rst_count
                            existing_flow.ack_count += flow.ack_count

                            # Merge packet statistics
                            existing_flow.inter_arrival_times.extend(flow.inter_arrival_times)
                            existing_flow.packet_sizes.extend(flow.packet_sizes)
                        else:
                            all_flows[flow_key] = flow

                except Exception as e:
                    print(f"Error processing chunk {chunk_name}: {e}")
                    continue

        return all_flows
    
    def convert_chunk_to_flows_streaming(self, pcap_file, protocols=None, max_flows=None):
        """Convert a single PCAP file/chunk to flows using streaming approach."""
        flows = {}
        processed_packets = 0
        
        try:
            with PcapReader(pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    processed_packets += 1
                    if processed_packets % 1000 == 0:  # Reduced frequency for batch processing
                        print(f"    Processed {processed_packets} packets, identified {len(flows)} flows")
                    
                    try:
                        flow_key = self.extract_flow_key(packet)
                        if flow_key is None:
                            continue
                            
                        timestamp = datetime.fromtimestamp(float(packet.time))
                        
                        # Create or get existing flow
                        if flow_key not in flows:
                            flows[flow_key] = NetworkFlow(flow_key)
                        
                        # Determine if this packet is forward or backward
                        if packet.haslayer(IP):
                            src_ip = packet[IP].src
                            is_forward = (src_ip == flow_key.ip1)
                        elif packet.haslayer(IPv6):
                            src_ip = packet[IPv6].src
                            is_forward = (src_ip == flow_key.ip1)
                        else:
                            is_forward = True  # Default for non-IP packets
                        
                        flows[flow_key].add_packet(packet, timestamp, is_forward)
                        
                    except Exception as e:
                        logging.warning(f"Error processing packet {processed_packets}: {e}")
                        continue
                        
        except Exception as e:
            print(f"Error reading PCAP file {pcap_file}: {e}")
            return {}
        
        # Filter by protocols if specified
        if protocols:
            flows = self.filter_by_protocol(flows, protocols)
        
        # Limit flows if specified
        if max_flows and len(flows) > max_flows:
            # Sort by total packets and take top flows
            sorted_flows = sorted(flows.items(), key=lambda x: x[1].forward_packets + x[1].backward_packets, reverse=True)
            flows = dict(sorted_flows[:max_flows])
        
        return flows
    
    def convert_chunk_to_flows_nonstreaming(self, pcap_file, protocols=None, max_flows=None):
        """Convert a single PCAP file/chunk to flows using non-streaming approach (rdpcap)."""
        flows = {}
        processed_packets = 0

        try:
            packets = rdpcap(pcap_file)  # loads all packets into memory
            for packet in packets:
                processed_packets += 1
                if processed_packets % 10000 == 0:  # Reduced frequency for batch processing
                    print(f"    Processed {processed_packets} packets, identified {len(flows)} flows")

                try:
                    flow_key = self.extract_flow_key(packet)
                    if flow_key is None:
                        continue

                    timestamp = datetime.fromtimestamp(float(packet.time))

                    if flow_key not in flows:
                        flows[flow_key] = NetworkFlow(flow_key)

                    if packet.haslayer(IP):
                        src_ip = packet[IP].src
                        is_forward = (src_ip == flow_key.ip1)
                    elif packet.haslayer(IPv6):
                        src_ip = packet[IPv6].src
                        is_forward = (src_ip == flow_key.ip1)
                    else:
                        is_forward = True

                    flows[flow_key].add_packet(packet, timestamp, is_forward)

                except Exception as e:
                    logging.warning(f"Error processing packet {processed_packets}: {e}")
                    continue

        except Exception as e:
            print(f"Error reading PCAP file {pcap_file}: {e}")
            return {}

        # Apply filters (same as streaming)
        if protocols:
            flows = self.filter_by_protocol(flows, protocols)

        if max_flows and len(flows) > max_flows:
            sorted_flows = sorted(flows.items(), key=lambda x: x[1].forward_packets + x[1].backward_packets, reverse=True)
            flows = dict(sorted_flows[:max_flows])

        return flows
    
    def convert(self, pcap_file, output_file, protocols=None, max_flows=None, 
                output_format='csv', quick_preview_count=0, split_by_protocol=False, 
                stream=False, suppress_output=False, report_dir=None):
        """Convert PCAP file to flow-based analysis."""
        start_time = datetime.now()
        
        try:
            # Check if we need to split the PCAP file
            chunk_files = self.split_pcap_streaming(pcap_file, self.chunk_size_mb)
            is_chunked = len(chunk_files) > 1
            all_flows = {}

            if is_chunked and self.max_workers > 1:
                # Use the parallel path that leverages ProcessPoolExecutor
                if not suppress_output:
                    print(f"Running parallel flow conversion with {self.max_workers} workers...")
                all_flows = self.process_chunks_parallel(chunk_files, stream, protocols, max_flows)
            
            else:
                # Sequential path (existing behavior)
                if not suppress_output:
                    print("Running sequential flow conversion...")
                for i, chunk_file in enumerate(chunk_files, 1):
                    if is_chunked and not suppress_output:
                        print(f"\nAnalyzing flows in chunk {i}/{len(chunk_files)}...")

                    if stream:
                        chunk_flows = self.convert_chunk_to_flows_streaming(chunk_file, protocols, max_flows)
                    else:
                        chunk_flows = self.convert_chunk_to_flows_nonstreaming(chunk_file, protocols, max_flows)

                    # Merge flows (same flow key from different chunks)
                    for flow_key, flow in chunk_flows.items():
                        if flow_key in all_flows:
                            existing_flow = all_flows[flow_key]
                            existing_flow.packets.extend(flow.packets)
                            existing_flow.forward_packets += flow.forward_packets
                            existing_flow.backward_packets += flow.backward_packets
                            existing_flow.forward_bytes += flow.forward_bytes
                            existing_flow.backward_bytes += flow.backward_bytes
                            existing_flow.forward_payload_bytes += flow.forward_payload_bytes
                            existing_flow.backward_payload_bytes += flow.backward_payload_bytes

                            # Update time range
                            if flow.start_time < existing_flow.start_time:
                                existing_flow.start_time = flow.start_time
                            if flow.end_time > existing_flow.end_time:
                                existing_flow.end_time = flow.end_time

                            # Merge TCP flags and counts
                            existing_flow.tcp_flags.update(flow.tcp_flags)
                            existing_flow.syn_count += flow.syn_count
                            existing_flow.fin_count += flow.fin_count
                            existing_flow.rst_count += flow.rst_count
                            existing_flow.ack_count += flow.ack_count

                            # Merge packet statistics
                            existing_flow.inter_arrival_times.extend(flow.inter_arrival_times)
                            existing_flow.packet_sizes.extend(flow.packet_sizes)
                        else:
                            all_flows[flow_key] = flow

                    if not suppress_output:
                        print(f"Found {len(chunk_flows)} flows in chunk {i}")
                
            if not suppress_output:
                print(f"\n*) Total unique flows identified: {len(all_flows)}")
            
            # Clean up temporary files
            if is_chunked:
                for chunk_file in chunk_files:
                    if chunk_file != pcap_file:  # Don't delete original file
                        try:
                            os.remove(chunk_file)
                        except:
                            pass
                # Remove temp directory
                temp_dir = os.path.dirname(chunk_files[0])
                try:
                    os.rmdir(temp_dir)
                except:
                    pass
            
            # Quick preview if requested
            if quick_preview_count > 0:
                self.quick_preview_flows(all_flows, quick_preview_count)
                response = input("\nContinue with conversion? (y/n): ").lower().strip()
                if response != 'y':
                    print("Conversion cancelled.")
                    return
            
            # Convert flows to DataFrame
            flow_data = []
            for flow_key, flow in all_flows.items():
                flow_stats = flow.get_flow_stats()
                flow_data.append(flow_stats)
            
            final_df = pd.DataFrame(flow_data)
            
            # Sort by total bytes (most active flows first)
            final_df = final_df.sort_values('total_bytes', ascending=False).reset_index(drop=True)
            
            # Handle split by protocol
            if split_by_protocol and len(final_df) > 0:
                self.save_split_by_protocol(final_df, output_file, output_format)
            else:
                # Save single file
                self.save_as_format(final_df, output_file, output_format)
                if not suppress_output:
                    print(f"-> Flow analysis saved to: {output_file}")
            
            # Display summary statistics
            if not suppress_output:
                self.display_summary(final_df)
            
            # Save processing report
            if not suppress_output:
                processing_time = (datetime.now() - start_time).total_seconds()
                if report_dir:
                    report_path = Path(report_dir)
                    report_path.mkdir(parents=True, exist_ok=True)
                    report_file = report_path / f"{Path(output_file).stem}_flow_report.txt"
                else:
                    report_file = Path(output_file).parent / f"{Path(output_file).stem}_flow_report.txt"
    
                self.save_report(final_df, report_file, pcap_file, protocols, processing_time)
            
        except FileNotFoundError:
            print(f" Error: PCAP file '{pcap_file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f" Error converting PCAP to flows: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    def save_split_by_protocol(self, df, base_output_file, output_format):
        """Save separate files for each protocol."""
        protocols_found = df['protocol'].unique()
        base_path = Path(base_output_file).parent
        base_name = Path(base_output_file).stem
        
        print(f"\n-> Splitting flows by protocol...")
        
        for protocol in protocols_found:
            protocol_df = df[df['protocol'] == protocol]
            if len(protocol_df) > 0:
                protocol_file = base_path / f"{base_name}_{protocol.lower()}_flows.{output_format}"
                self.save_as_format(protocol_df, protocol_file, output_format)
                print(f"  {protocol}: {len(protocol_df)} flows → {protocol_file}")
    
    def display_summary(self, df):
        """Display summary statistics of the flow analysis."""
        print(f"\n{'='*20} Flow Analysis Summary {'='*20}")
        print(f"*) Total flows: {len(df)}")
        
        if len(df) > 0:
            protocol_counts = df['protocol'].value_counts()
            print(f"\n*) Protocol distribution:")
            for protocol, count in protocol_counts.items():
                percentage = (count / len(df)) * 100
                print(f"  {protocol:<8}: {count:>6} flows ({percentage:>5.1f}%)")
            
            # Flow characteristics
            bidirectional = df['is_bidirectional'].sum()
            print(f"\n*) Flow characteristics:")
            print(f"  Bidirectional:   {bidirectional:>6} flows ({bidirectional/len(df)*100:>5.1f}%)")
            print(f"  Unidirectional:  {len(df)-bidirectional:>6} flows ({(len(df)-bidirectional)/len(df)*100:>5.1f}%)")
            
            print(f"\n*)  Flow duration statistics:")
            print(f"  Average: {df['duration_seconds'].mean():>8.2f} seconds")
            print(f"  Median:  {df['duration_seconds'].median():>8.2f} seconds")
            print(f"  Max:     {df['duration_seconds'].max():>8.2f} seconds")
            
            print(f"\n*) Flow size statistics:")
            print(f"  Avg packets/flow: {df['total_packets'].mean():>6.1f}")
            print(f"  Avg bytes/flow:   {df['total_bytes'].mean():>6.1f}")
            print(f"  Max packets/flow: {df['total_packets'].max():>6}")
            print(f"  Max bytes/flow:   {df['total_bytes'].max():>6}")
            
            print(f"\n*) Flow rate statistics:")
            print(f"  Avg packets/sec:  {df['packets_per_second'].mean():>6.1f}")
            print(f"  Avg bytes/sec:    {df['bytes_per_second'].mean():>6.1f}")
