#!/usr/bin/env python3
"""
NetFlow MCP Server - Natural Language Interface for Network Flow Analysis

This MCP (Model Context Protocol) server provides intelligent analysis of NetFlow data
stored in Elasticsearch, enabling natural language queries for network monitoring,
bottleneck detection, anomaly identification, and traffic investigation.

Author: NetFlow Intelligence System
Version: 1.0.0
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from elasticsearch import AsyncElasticsearch
from dotenv import load_dotenv
import warnings

# Suppress SSL warnings for internal network connections
warnings.filterwarnings('ignore')

# Load environment variables from .env file
load_dotenv()


class NetflowMCPServer:
    """
    MCP Server for NetFlow data analysis.

    Provides natural language interface to analyze network traffic patterns,
    detect bottlenecks, identify anomalies, and investigate specific hosts.
    """

    # Common service port mappings
    SERVICE_PORTS = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
        80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
        161: 'SNMP', 162: 'SNMP-Trap', 443: 'HTTPS', 445: 'SMB',
        514: 'Syslog', 636: 'LDAPS', 989: 'FTPS', 990: 'FTPS',
        1433: 'MSSQL', 1521: 'Oracle', 2055: 'NetFlow', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5601: 'Kibana', 5984: 'CouchDB',
        6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
        9300: 'Elasticsearch', 27017: 'MongoDB'
    }

    def __init__(self):
        """Initialize the NetFlow MCP Server."""
        self.server = Server("netflow-intelligence")
        self.es: Optional[AsyncElasticsearch] = None

        # Network interface configuration
        # TODO: Load from configuration file in production
        self.interfaces = {
            1: {"name": "WAN-1", "capacity_mbps": 10000},
            2: {"name": "LAN-1", "capacity_mbps": 10000},
            3: {"name": "DMZ-1", "capacity_mbps": 1000},
            4: {"name": "Internet-1", "capacity_mbps": 1000}
        }

        self._setup_handlers()

    async def _initialize_elasticsearch(self) -> None:
        """
        Initialize connection to Elasticsearch cluster.

        Reads connection parameters from environment variables:
        - ES_HOST: Elasticsearch host
        - ES_PORT: Elasticsearch port
        - ES_USERNAME: Authentication username
        - ES_PASSWORD: Authentication password
        """
        self.es = AsyncElasticsearch(
            [f"https://{os.getenv('ES_HOST')}:{os.getenv('ES_PORT')}"],
            basic_auth=(os.getenv('ES_USERNAME'), os.getenv('ES_PASSWORD')),
            verify_certs=False  # For internal network; enable in production
        )

    def _setup_handlers(self) -> None:
        """Register MCP protocol handlers for tools and calls."""

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """Define available analysis tools."""
            return [
                Tool(
                    name="analyze_traffic",
                    description="Analyze network traffic patterns, bandwidth usage, top talkers, and services",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "time_range": {
                                "type": "string",
                                "description": "Time range for analysis (e.g., 'now-1h', 'now-15m')",
                                "default": "now-15m"
                            },
                            "focus": {
                                "type": "string",
                                "description": "Analysis focus: 'summary', 'top_talkers', 'services', 'geographic'",
                                "default": "summary"
                            }
                        }
                    }
                ),
                Tool(
                    name="detect_bottlenecks",
                    description="Identify network bottlenecks and interface utilization issues",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "time_range": {
                                "type": "string",
                                "description": "Time range for analysis (e.g., 'now-1h')",
                                "default": "now-1h"
                            },
                            "threshold_percent": {
                                "type": "number",
                                "description": "Utilization threshold percentage (0-100)",
                                "default": 30
                            }
                        }
                    }
                ),
                Tool(
                    name="find_anomalies",
                    description="Detect network anomalies like port scans, traffic spikes, or unusual patterns",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "anomaly_type": {
                                "type": "string",
                                "description": "Type: 'all', 'port_scan', 'traffic_spike', 'rare_ports'",
                                "default": "all"
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Time range for anomaly detection",
                                "default": "now-15m"
                            }
                        }
                    }
                ),
                Tool(
                    name="investigate_host",
                    description="Investigate traffic patterns for a specific IP address",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ip_address": {
                                "type": "string",
                                "description": "IP address to investigate"
                            },
                            "direction": {
                                "type": "string",
                                "description": "Traffic direction: 'source', 'destination', or 'both'",
                                "default": "both"
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Time range for investigation",
                                "default": "now-1h"
                            }
                        },
                        "required": ["ip_address"]
                    }
                ),
                Tool(
                    name="get_recommendations",
                    description="Get intelligent recommendations based on current network state",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "include_analysis": {
                                "type": "boolean",
                                "description": "Include full analysis before recommendations",
                                "default": True
                            }
                        }
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> List[TextContent]:
            """
            Handle tool invocations from the MCP client.

            Args:
                name: Name of the tool to invoke
                arguments: Tool-specific arguments

            Returns:
                List containing the tool's JSON response
            """
            # Initialize Elasticsearch connection if needed
            if not self.es:
                await self._initialize_elasticsearch()

            # Route to appropriate handler
            handlers = {
                "analyze_traffic": self._handle_analyze_traffic,
                "detect_bottlenecks": self._handle_detect_bottlenecks,
                "find_anomalies": self._handle_find_anomalies,
                "investigate_host": self._handle_investigate_host,
                "get_recommendations": self._handle_get_recommendations
            }

            handler = handlers.get(name)
            if not handler:
                result = {"error": f"Unknown tool: {name}"}
            else:
                result = await handler(arguments)

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

    async def _handle_analyze_traffic(self, args: dict) -> Dict[str, Any]:
        """Handle traffic analysis requests."""
        return await self.analyze_traffic(
            time_range=args.get("time_range", "now-15m"),
            focus=args.get("focus", "summary")
        )

    async def _handle_detect_bottlenecks(self, args: dict) -> Dict[str, Any]:
        """Handle bottleneck detection requests."""
        return await self.detect_bottlenecks(
            time_range=args.get("time_range", "now-1h"),
            threshold_percent=args.get("threshold_percent", 30)
        )

    async def _handle_find_anomalies(self, args: dict) -> Dict[str, Any]:
        """Handle anomaly detection requests."""
        return await self.find_anomalies(
            anomaly_type=args.get("anomaly_type", "all"),
            time_range=args.get("time_range", "now-15m")
        )

    async def _handle_investigate_host(self, args: dict) -> Dict[str, Any]:
        """Handle host investigation requests."""
        return await self.investigate_host(
            ip_address=args["ip_address"],
            direction=args.get("direction", "both"),
            time_range=args.get("time_range", "now-1h")
        )

    async def _handle_get_recommendations(self, args: dict) -> Dict[str, Any]:
        """Handle recommendation requests."""
        return await self.get_recommendations(
            include_analysis=args.get("include_analysis", True)
        )

    async def analyze_traffic(self, time_range: str, focus: str) -> Dict[str, Any]:
        """
        Analyze network traffic patterns and statistics.

        Args:
            time_range: Elasticsearch time range (e.g., 'now-1h')
            focus: Analysis focus area ('summary', 'top_talkers', 'services', 'geographic')

        Returns:
            Traffic analysis results including bandwidth, top talkers, and services
        """
        query = self._build_traffic_analysis_query(time_range)
        result = await self.es.search(index="logs-netflow*", body=query)

        return self._process_traffic_analysis(result, time_range, focus)

    def _build_traffic_analysis_query(self, time_range: str) -> Dict[str, Any]:
        """Build Elasticsearch query for traffic analysis."""
        return {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": time_range}}},
            "aggs": {
                "total_bytes": {"sum": {"field": "network.bytes"}},
                "total_packets": {"sum": {"field": "network.packets"}},
                "unique_sources": {"cardinality": {"field": "source.ip"}},
                "unique_destinations": {"cardinality": {"field": "destination.ip"}},
                "top_sources": {
                    "terms": {"field": "source.ip", "size": 10},
                    "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                },
                "top_destinations": {
                    "terms": {"field": "destination.ip", "size": 10},
                    "aggs": {
                        "bytes": {"sum": {"field": "network.bytes"}},
                        "geo": {
                            "top_hits": {
                                "size": 1,
                                "_source": [
                                    "destination.geo.country_name",
                                    "destination.as.organization.name"
                                ]
                            }
                        }
                    }
                },
                "top_ports": {
                    "terms": {"field": "destination.port", "size": 10},
                    "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                },
                "traffic_trend": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "5m"
                    },
                    "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                }
            }
        }

    def _process_traffic_analysis(self, result: Dict, time_range: str, focus: str) -> Dict[str, Any]:
        """Process Elasticsearch results into traffic analysis."""
        aggs = result['aggregations']

        analysis = {
            "time_range": time_range,
            "summary": {
                "total_traffic_mb": round(aggs['total_bytes']['value'] / 1_000_000, 2),
                "total_packets": int(aggs['total_packets']['value']),
                "unique_sources": aggs['unique_sources']['value'],
                "unique_destinations": aggs['unique_destinations']['value']
            }
        }

        # Add focus-specific details
        if focus in ['summary', 'top_talkers']:
            self._add_top_talkers(analysis, aggs)

        if focus in ['summary', 'services']:
            self._add_top_services(analysis, aggs)

        if focus == 'summary':
            self._add_traffic_trend(analysis, aggs)

        return analysis

    def _add_top_talkers(self, analysis: Dict, aggs: Dict) -> None:
        """Add top talkers to analysis results."""
        analysis["top_sources"] = [
            {
                "ip": s['key'],
                "traffic_mb": round(s['bytes']['value'] / 1_000_000, 2)
            }
            for s in aggs['top_sources']['buckets'][:5]
        ]

        analysis["top_destinations"] = [
            {
                "ip": d['key'],
                "traffic_mb": round(d['bytes']['value'] / 1_000_000, 2),
                "country": self._extract_geo_field(d, 'country_name'),
                "organization": self._extract_geo_field(d, 'organization', 'name')
            }
            for d in aggs['top_destinations']['buckets'][:5]
        ]

    def _add_top_services(self, analysis: Dict, aggs: Dict) -> None:
        """Add top services to analysis results."""
        analysis["top_services"] = [
            {
                "port": p['key'],
                "service": self._get_service_name(p['key']),
                "traffic_mb": round(p['bytes']['value'] / 1_000_000, 2)
            }
            for p in aggs['top_ports']['buckets'][:10]
        ]

    def _add_traffic_trend(self, analysis: Dict, aggs: Dict) -> None:
        """Add traffic trend to analysis results."""
        trend = aggs['traffic_trend']['buckets']
        if trend:
            analysis["traffic_trend"] = {
                "latest_5min_mb": round(trend[-1]['bytes']['value'] / 1_000_000, 2),
                "average_5min_mb": round(
                    sum(t['bytes']['value'] for t in trend) / len(trend) / 1_000_000, 2
                )
            }

    def _extract_geo_field(self, bucket: Dict, *field_path: str) -> str:
        """Safely extract geographic field from aggregation bucket."""
        try:
            if bucket['geo']['hits']['hits']:
                data = bucket['geo']['hits']['hits'][0]['_source']
                for field in ['destination'] + list(field_path[:-1]):
                    data = data.get(field, {})
                return data.get(field_path[-1], 'Unknown')
        except (KeyError, IndexError):
            pass
        return 'Unknown'

    async def detect_bottlenecks(self, time_range: str, threshold_percent: float) -> Dict[str, Any]:
        """
        Detect network interface bottlenecks.

        Args:
            time_range: Time period to analyze
            threshold_percent: Utilization threshold to flag as bottleneck

        Returns:
            List of interfaces exceeding threshold with utilization details
        """
        query = self._build_bottleneck_query(time_range)
        result = await self.es.search(index="logs-netflow*", body=query)

        return self._process_bottleneck_results(result, time_range, threshold_percent)

    def _build_bottleneck_query(self, time_range: str) -> Dict[str, Any]:
        """Build query for bottleneck detection."""
        return {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": time_range}}},
            "aggs": {
                "by_ingress": {
                    "terms": {"field": "netflow.ingress_interface", "size": 10},
                    "aggs": {
                        "bytes": {"sum": {"field": "network.bytes"}},
                        "packets": {"sum": {"field": "network.packets"}},
                        "top_sources": {
                            "terms": {"field": "source.ip", "size": 5},
                            "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                        }
                    }
                },
                "by_egress": {
                    "terms": {"field": "netflow.egress_interface", "size": 10},
                    "aggs": {
                        "bytes": {"sum": {"field": "network.bytes"}},
                        "packets": {"sum": {"field": "network.packets"}}
                    }
                }
            }
        }

    def _process_bottleneck_results(
        self, result: Dict, time_range: str, threshold_percent: float
    ) -> Dict[str, Any]:
        """Process bottleneck detection results."""
        bottlenecks = []
        duration_minutes = self._parse_time_range_minutes(time_range)

        for bucket in result['aggregations']['by_ingress']['buckets']:
            bottleneck = self._analyze_interface_bottleneck(
                bucket, duration_minutes, threshold_percent, "ingress"
            )
            if bottleneck:
                bottlenecks.append(bottleneck)

        return {
            "bottlenecks_found": len(bottlenecks),
            "threshold_used": threshold_percent,
            "time_range": time_range,
            "bottlenecks": bottlenecks
        }

    def _analyze_interface_bottleneck(
        self, bucket: Dict, duration_minutes: int, threshold_percent: float, direction: str
    ) -> Optional[Dict[str, Any]]:
        """Analyze single interface for bottleneck conditions."""
        interface_id = bucket['key']
        interface_info = self.interfaces.get(
            interface_id,
            {"name": f"Interface-{interface_id}", "capacity_mbps": 1000}
        )

        bytes_total = bucket['bytes']['value']
        bandwidth_used_mbps = (bytes_total * 8) / (duration_minutes * 60 * 1_000_000)
        capacity_mbps = interface_info['capacity_mbps']
        utilization = (bandwidth_used_mbps / capacity_mbps) * 100

        if utilization < threshold_percent:
            return None

        return {
            "interface": interface_info['name'],
            "interface_id": interface_id,
            "direction": direction,
            "utilization_percent": round(utilization, 2),
            "bandwidth_mbps": round(bandwidth_used_mbps, 2),
            "capacity_mbps": capacity_mbps,
            "total_traffic_mb": round(bytes_total / 1_000_000, 2),
            "top_talkers": self._extract_top_talkers(bucket, bytes_total),
            "severity": self._determine_severity(utilization)
        }

    def _extract_top_talkers(self, bucket: Dict, total_bytes: float) -> List[Dict[str, Any]]:
        """Extract top talkers from interface statistics."""
        if 'top_sources' not in bucket:
            return []

        return [
            {
                "ip": s['key'],
                "traffic_mb": round(s['bytes']['value'] / 1_000_000, 2),
                "percent_of_interface": round(
                    (s['bytes']['value'] / total_bytes) * 100, 1
                ) if total_bytes > 0 else 0
            }
            for s in bucket['top_sources']['buckets']
        ]

    def _determine_severity(self, utilization: float) -> str:
        """Determine severity level based on utilization percentage."""
        if utilization > 90:
            return "CRITICAL"
        elif utilization > 70:
            return "WARNING"
        else:
            return "INFO"

    async def find_anomalies(
        self, anomaly_type: str, time_range: str = "now-15m"
    ) -> Dict[str, Any]:
        """
        Detect network anomalies.

        Args:
            anomaly_type: Type of anomaly to detect ('all', 'port_scan', 'traffic_spike')
            time_range: Time range for anomaly detection

        Returns:
            List of detected anomalies with details and severity
        """
        anomalies = []

        if anomaly_type in ["all", "port_scan"]:
            port_scan_anomaly = await self._detect_port_scanning(time_range)
            if port_scan_anomaly:
                anomalies.append(port_scan_anomaly)

        if anomaly_type in ["all", "traffic_spike"]:
            traffic_anomaly = await self._detect_traffic_anomaly(time_range)
            if traffic_anomaly:
                anomalies.append(traffic_anomaly)

        return {
            "anomalies_found": len(anomalies),
            "time_range": time_range,
            "anomalies": anomalies
        }

    async def _detect_port_scanning(self, time_range: str) -> Optional[Dict[str, Any]]:
        """Detect potential port scanning activity."""
        query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": time_range}}},
            "aggs": {
                "unique_ports": {"cardinality": {"field": "destination.port"}},
                "port_distribution": {
                    "terms": {
                        "field": "destination.port",
                        "size": 100,
                        "order": {"_count": "asc"}
                    }
                },
                "scanning_sources": {
                    "terms": {
                        "field": "source.ip",
                        "size": 10,
                        "order": {"unique_ports": "desc"}
                    },
                    "aggs": {
                        "unique_ports": {"cardinality": {"field": "destination.port"}}
                    }
                }
            }
        }

        result = await self.es.search(index="logs-netflow*", body=query)
        unique_ports = result['aggregations']['unique_ports']['value']

        if unique_ports > 50:
            suspicious_sources = [
                {
                    "ip": s['key'],
                    "ports_accessed": s['unique_ports']['value']
                }
                for s in result['aggregations']['scanning_sources']['buckets']
                if s['unique_ports']['value'] > 20
            ]

            return {
                "type": "port_scan",
                "severity": "HIGH" if unique_ports > 100 else "MEDIUM",
                "description": f"Possible port scan - {unique_ports} unique ports in {time_range}",
                "details": {
                    "unique_ports_total": unique_ports,
                    "suspicious_sources": suspicious_sources[:5],
                    "rare_ports": [
                        p['key'] for p in result['aggregations']['port_distribution']['buckets'][:10]
                    ]
                }
            }

        return None

    async def _detect_traffic_anomaly(self, time_range: str) -> Optional[Dict[str, Any]]:
        """Detect traffic spikes or drops."""
        # Get baseline from previous hour
        baseline_query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": "now-1h", "lt": time_range}}},
            "aggs": {
                "bytes_per_5min": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "5m"
                    },
                    "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                }
            }
        }

        # Get current traffic
        current_query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": time_range}}},
            "aggs": {
                "current_bytes": {"sum": {"field": "network.bytes"}},
                "current_packets": {"sum": {"field": "network.packets"}}
            }
        }

        baseline_result = await self.es.search(index="logs-netflow*", body=baseline_query)
        current_result = await self.es.search(index="logs-netflow*", body=current_query)

        baseline_buckets = baseline_result['aggregations']['bytes_per_5min']['buckets']
        if not baseline_buckets:
            return None

        baseline_avg = sum(b['bytes']['value'] for b in baseline_buckets) / len(baseline_buckets)
        current_bytes = current_result['aggregations']['current_bytes']['value']

        if baseline_avg == 0:
            return None

        change_percent = ((current_bytes - baseline_avg) / baseline_avg) * 100

        if abs(change_percent) > 50:
            return {
                "type": "traffic_anomaly",
                "severity": "HIGH" if abs(change_percent) > 200 else "MEDIUM",
                "description": f"Traffic {'spike' if change_percent > 0 else 'drop'} - {abs(change_percent):.1f}% change",
                "details": {
                    "current_traffic_mb": round(current_bytes / 1_000_000, 2),
                    "baseline_traffic_mb": round(baseline_avg / 1_000_000, 2),
                    "change_percent": round(change_percent, 1)
                }
            }

        return None

    async def investigate_host(
        self, ip_address: str, direction: str, time_range: str
    ) -> Dict[str, Any]:
        """
        Investigate traffic patterns for a specific host.

        Args:
            ip_address: IP address to investigate
            direction: Traffic direction ('source', 'destination', 'both')
            time_range: Time period to analyze

        Returns:
            Detailed traffic analysis for the specified host
        """
        query = self._build_host_investigation_query(ip_address, direction, time_range)
        result = await self.es.search(index="logs-netflow*", body=query)

        return self._process_host_investigation(result, ip_address, direction, time_range)

    def _build_host_investigation_query(
        self, ip_address: str, direction: str, time_range: str
    ) -> Dict[str, Any]:
        """Build query for host investigation."""
        must_clauses = [{"range": {"@timestamp": {"gte": time_range}}}]

        if direction == "source":
            must_clauses.append({"term": {"source.ip": ip_address}})
        elif direction == "destination":
            must_clauses.append({"term": {"destination.ip": ip_address}})
        else:  # both
            must_clauses.append({
                "bool": {
                    "should": [
                        {"term": {"source.ip": ip_address}},
                        {"term": {"destination.ip": ip_address}}
                    ]
                }
            })

        return {
            "size": 0,
            "query": {"bool": {"must": must_clauses}},
            "aggs": {
                "total_bytes": {"sum": {"field": "network.bytes"}},
                "total_packets": {"sum": {"field": "network.packets"}},
                "as_source": {
                    "filter": {"term": {"source.ip": ip_address}},
                    "aggs": {
                        "bytes_sent": {"sum": {"field": "network.bytes"}},
                        "top_destinations": {
                            "terms": {"field": "destination.ip", "size": 10},
                            "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                        },
                        "top_dest_ports": {
                            "terms": {"field": "destination.port", "size": 10},
                            "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                        }
                    }
                },
                "as_destination": {
                    "filter": {"term": {"destination.ip": ip_address}},
                    "aggs": {
                        "bytes_received": {"sum": {"field": "network.bytes"}},
                        "top_sources": {
                            "terms": {"field": "source.ip", "size": 10},
                            "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                        },
                        "ports_accessed": {
                            "terms": {"field": "destination.port", "size": 10},
                            "aggs": {"bytes": {"sum": {"field": "network.bytes"}}}
                        }
                    }
                },
                "traffic_timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "5m"
                    },
                    "aggs": {
                        "bytes": {"sum": {"field": "network.bytes"}},
                        "packets": {"sum": {"field": "network.packets"}}
                    }
                }
            }
        }

    def _process_host_investigation(
        self, result: Dict, ip_address: str, direction: str, time_range: str
    ) -> Dict[str, Any]:
        """Process host investigation results."""
        aggs = result['aggregations']

        investigation = {
            "host": ip_address,
            "time_range": time_range,
            "direction_analyzed": direction,
            "summary": {
                "total_traffic_mb": round(aggs['total_bytes']['value'] / 1_000_000, 2),
                "total_packets": int(aggs['total_packets']['value'])
            }
        }

        # Add source traffic analysis
        if aggs['as_source']['bytes_sent']['value'] > 0:
            investigation["as_source"] = self._process_source_traffic(aggs['as_source'])

        # Add destination traffic analysis
        if aggs['as_destination']['bytes_received']['value'] > 0:
            investigation["as_destination"] = self._process_destination_traffic(aggs['as_destination'])

        # Add traffic pattern
        timeline = aggs['traffic_timeline']['buckets']
        if timeline:
            investigation["traffic_pattern"] = self._process_traffic_pattern(timeline)

        return investigation

    def _process_source_traffic(self, source_aggs: Dict) -> Dict[str, Any]:
        """Process source traffic aggregations."""
        return {
            "bytes_sent_mb": round(source_aggs['bytes_sent']['value'] / 1_000_000, 2),
            "top_destinations": [
                {
                    "ip": d['key'],
                    "traffic_mb": round(d['bytes']['value'] / 1_000_000, 2)
                }
                for d in source_aggs['top_destinations']['buckets'][:5]
            ],
            "top_services_used": [
                {
                    "port": p['key'],
                    "service": self._get_service_name(p['key']),
                    "traffic_mb": round(p['bytes']['value'] / 1_000_000, 2)
                }
                for p in source_aggs['top_dest_ports']['buckets'][:5]
            ]
        }

    def _process_destination_traffic(self, dest_aggs: Dict) -> Dict[str, Any]:
        """Process destination traffic aggregations."""
        return {
            "bytes_received_mb": round(dest_aggs['bytes_received']['value'] / 1_000_000, 2),
            "top_sources": [
                {
                    "ip": s['key'],
                    "traffic_mb": round(s['bytes']['value'] / 1_000_000, 2)
                }
                for s in dest_aggs['top_sources']['buckets'][:5]
            ],
            "services_accessed": [
                {
                    "port": p['key'],
                    "service": self._get_service_name(p['key']),
                    "traffic_mb": round(p['bytes']['value'] / 1_000_000, 2)
                }
                for p in dest_aggs['ports_accessed']['buckets'][:5]
            ]
        }

    def _process_traffic_pattern(self, timeline: List[Dict]) -> Dict[str, Any]:
        """Process traffic timeline into pattern analysis."""
        bytes_values = [t['bytes']['value'] for t in timeline]
        return {
            "peak_5min_mb": round(max(bytes_values) / 1_000_000, 2),
            "average_5min_mb": round(sum(bytes_values) / len(bytes_values) / 1_000_000, 2),
            "periods_active": len([v for v in bytes_values if v > 0])
        }

    async def get_recommendations(self, include_analysis: bool = True) -> Dict[str, Any]:
        """
        Generate intelligent recommendations based on network state.

        Args:
            include_analysis: Whether to run full analysis before generating recommendations

        Returns:
            Prioritized list of recommended actions
        """
        recommendations = []

        if include_analysis:
            # Run analysis to generate recommendations
            bottlenecks = await self.detect_bottlenecks("now-1h", 50)
            anomalies = await self.find_anomalies("all", "now-15m")

            # Generate recommendations from findings
            recommendations.extend(self._generate_bottleneck_recommendations(bottlenecks))
            recommendations.extend(self._generate_anomaly_recommendations(anomalies))

        # Add default recommendation if none found
        if not recommendations:
            recommendations.append({
                "priority": "LOW",
                "category": "General",
                "issue": "No significant issues detected",
                "actions": [
                    "Continue normal monitoring",
                    "Review historical trends weekly",
                    "Maintain current security policies"
                ]
            })

        return {
            "recommendations_count": len(recommendations),
            "recommendations": recommendations,
            "generated_at": datetime.now().isoformat()
        }

    def _generate_bottleneck_recommendations(self, bottlenecks: Dict) -> List[Dict[str, Any]]:
        """Generate recommendations from bottleneck analysis."""
        recommendations = []

        for bottleneck in bottlenecks.get('bottlenecks', []):
            if bottleneck['severity'] == 'CRITICAL':
                recommendations.append({
                    "priority": "HIGH",
                    "category": "Performance",
                    "issue": f"{bottleneck['interface']} at critical utilization ({bottleneck['utilization_percent']}%)",
                    "actions": [
                        "Immediately investigate top talkers for abnormal traffic",
                        "Consider emergency traffic shaping or rate limiting",
                        "Plan immediate capacity upgrade if legitimate traffic"
                    ]
                })
            elif bottleneck['severity'] == 'WARNING':
                recommendations.append({
                    "priority": "MEDIUM",
                    "category": "Performance",
                    "issue": f"{bottleneck['interface']} approaching capacity ({bottleneck['utilization_percent']}%)",
                    "actions": [
                        "Monitor trend over next few hours",
                        "Review QoS policies for optimization",
                        "Schedule capacity planning review"
                    ]
                })

        return recommendations

    def _generate_anomaly_recommendations(self, anomalies: Dict) -> List[Dict[str, Any]]:
        """Generate recommendations from anomaly detection."""
        recommendations = []

        for anomaly in anomalies.get('anomalies', []):
            if anomaly['type'] == 'port_scan':
                recommendations.append({
                    "priority": "HIGH",
                    "category": "Security",
                    "issue": anomaly['description'],
                    "actions": [
                        "Review firewall logs for blocked attempts",
                        "Investigate suspicious source IPs",
                        "Enable IDS/IPS rules if not already active",
                        "Check for compromised internal hosts"
                    ]
                })
            elif anomaly['type'] == 'traffic_anomaly':
                recommendations.append({
                    "priority": "MEDIUM",
                    "category": "Operations",
                    "issue": anomaly['description'],
                    "actions": [
                        "Identify source of traffic change",
                        "Check for scheduled backups or transfers",
                        "Verify no ongoing attacks or data exfiltration",
                        "Document if legitimate for future baseline"
                    ]
                })

        return recommendations

    def _parse_time_range_minutes(self, time_range: str) -> int:
        """Parse Elasticsearch time range string to minutes."""
        if "h" in time_range:
            return int(time_range.replace("now-", "").replace("h", "")) * 60
        elif "m" in time_range:
            return int(time_range.replace("now-", "").replace("m", ""))
        else:
            return 60

    def _get_service_name(self, port: int) -> str:
        """Map port number to service name."""
        return self.SERVICE_PORTS.get(port, f'Port-{port}')


async def main():
    """Main entry point for the NetFlow MCP Server."""
    server = NetflowMCPServer()

    # Run the server using stdio transport
    async with stdio_server() as (read_stream, write_stream):
        await server.server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="netflow-intelligence",
                server_version="1.0.0",
                capabilities=server.server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())