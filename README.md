# NetFlow MCP Server

A Model Context Protocol (MCP) server that provides natural language interface for analyzing NetFlow data stored in Elasticsearch. Query your network traffic patterns, detect bottlenecks, identify anomalies, and get intelligent recommendations using simple conversational queries.

## Features

- **Traffic Analysis**: Real-time bandwidth monitoring, top talkers identification, and service usage statistics
- **Bottleneck Detection**: Interface utilization monitoring with configurable thresholds
- **Anomaly Detection**: Port scan detection, traffic spike/drop alerts, and unusual pattern identification
- **Host Investigation**: Deep-dive into specific IP addresses' traffic patterns
- **Intelligent Recommendations**: Prioritized actions based on current network state

## Prerequisites

- Python 3.8 or higher
- Elasticsearch cluster with NetFlow data (indices: `logs-netflow*`)
- MCP-compatible client (e.g., Claude Desktop)

## Installation

### macOS Setup

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/netflow-mcp-server.git
cd netflow-mcp-server
```

2. **Create and activate virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**:
```bash
pip install mcp elasticsearch python-dotenv
```

4. **Configure environment variables**:
```bash
cp .env.example .env
# Edit .env with your Elasticsearch credentials
nano .env
```

5. **Configure Claude Desktop**:

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "netflow": {
      "command": "/usr/bin/python3",
      "args": ["/path/to/netflow-mcp-server/netflow_mcp_server.py"],
      "env": {
        "PYTHONPATH": "/path/to/netflow-mcp-server"
      }
    }
  }
}
```

6. **Restart Claude Desktop** to load the MCP server.

### Linux Setup

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/netflow-mcp-server.git
cd netflow-mcp-server
```

2. **Create and activate virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**:
```bash
pip install mcp elasticsearch python-dotenv
```

4. **Configure environment variables**:
```bash
cp .env.example .env
# Edit .env with your Elasticsearch credentials
vim .env
```

5. **Configure Claude Desktop** (if using AppImage):

Add to `~/.config/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "netflow": {
      "command": "/usr/bin/python3",
      "args": ["/path/to/netflow-mcp-server/netflow_mcp_server.py"],
      "env": {
        "PYTHONPATH": "/path/to/netflow-mcp-server"
      }
    }
  }
}
```

Or if installed via package manager, check the appropriate config directory for your distribution.

6. **Restart Claude Desktop** to load the MCP server.

## Environment Configuration

Create a `.env` file with your Elasticsearch connection details:

```env
# Elasticsearch Configuration
ES_HOST=your-elasticsearch-host
ES_PORT=9200
ES_USERNAME=your-username
ES_PASSWORD=your-password
```

## Usage Examples

Once configured, you can ask Claude natural language questions about your network traffic:

### Traffic Analysis
- "What's the current network traffic like?"
- "Show me the top bandwidth consumers in the last hour"
- "Which services are using the most bandwidth?"

### Bottleneck Detection
- "Are there any network bottlenecks?"
- "Which interfaces are overutilized?"
- "Show me interfaces above 70% utilization"

### Security & Anomalies
- "Are there any security concerns right now?"
- "Is anyone port scanning our network?"
- "Detect any unusual traffic patterns"

### Host Investigation
- "What's 192.168.1.100 doing on the network?"
- "Show me all traffic from 10.0.0.50"
- "Which services is 192.168.1.25 accessing?"

### Recommendations
- "What should I focus on right now?"
- "Give me network recommendations"
- "Are there any critical issues I should address?"

## Architecture

The MCP server connects to your Elasticsearch cluster and provides five main tools:

1. **analyze_traffic**: Traffic patterns, bandwidth usage, top talkers
2. **detect_bottlenecks**: Interface utilization and capacity issues
3. **find_anomalies**: Port scans, traffic spikes, unusual patterns
4. **investigate_host**: Detailed analysis of specific IP addresses
5. **get_recommendations**: Intelligent, prioritized action items

## Data Requirements

The server expects NetFlow data in Elasticsearch with the following fields:
- `@timestamp`: Flow timestamp
- `network.bytes`: Bytes transferred
- `network.packets`: Packet count
- `source.ip`: Source IP address
- `destination.ip`: Destination IP address
- `destination.port`: Destination port
- `netflow.ingress_interface`: Ingress interface ID
- `netflow.egress_interface`: Egress interface ID

## Customization

### Interface Configuration

Edit the interface mappings in `netflow_mcp_server.py`:

```python
self.interfaces = {
    1: {"name": "WAN-1", "capacity_mbps": 10000},
    2: {"name": "LAN-1", "capacity_mbps": 10000},
    3: {"name": "DMZ-1", "capacity_mbps": 1000},
    4: {"name": "Internet-1", "capacity_mbps": 1000}
}
```

### Service Port Mappings

Additional service ports can be added to the `SERVICE_PORTS` dictionary in the server class.

## Troubleshooting

### Server Not Loading
- Check Claude Desktop logs for connection errors
- Verify Python path and script location in config
- Ensure all dependencies are installed

### Connection Issues
- Verify Elasticsearch is accessible from your machine
- Check credentials in `.env` file
- Test connection with: `curl -u username:password https://es-host:9200`

### No Data Returned
- Verify NetFlow indices exist: `logs-netflow*`
- Check time ranges in your queries
- Ensure NetFlow data is being ingested

