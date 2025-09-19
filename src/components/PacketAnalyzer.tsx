import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  Network, 
  Eye, 
  FileText,
  Zap,
  Target,
  TrendingUp,
  WifiOff
} from "lucide-react";

interface NetworkPacket {
  id: string;
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  size: number;
  threatLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  payload: string;
  headers: Record<string, string>;
  anomaly?: string;
}

interface ThreatAlert {
  id: string;
  timestamp: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  source: string;
  action: string;
}

const PacketAnalyzer = () => {
  const [packets, setPackets] = useState<NetworkPacket[]>([]);
  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<NetworkPacket | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [stats, setStats] = useState({
    totalPackets: 0,
    threatsDetected: 0,
    anomalies: 0,
    throughput: 0
  });

  // Simulate real-time packet capture
  useEffect(() => {
    if (!isMonitoring) return;

    const interval = setInterval(() => {
      const newPacket = generateMockPacket();
      setPackets(prev => [newPacket, ...prev.slice(0, 99)]); // Keep last 100 packets
      
      if (newPacket.threatLevel !== 'safe') {
        const threat = generateThreatAlert(newPacket);
        setThreats(prev => [threat, ...prev.slice(0, 49)]);
      }

      setStats(prev => ({
        totalPackets: prev.totalPackets + 1,
        threatsDetected: prev.threatsDetected + (newPacket.threatLevel !== 'safe' ? 1 : 0),
        anomalies: prev.anomalies + (newPacket.anomaly ? 1 : 0),
        throughput: Math.random() * 1000 + 500
      }));
    }, Math.random() * 2000 + 1000);

    return () => clearInterval(interval);
  }, [isMonitoring]);

  const generateMockPacket = (): NetworkPacket => {
    const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP', 'DNS'];
    const threatLevels: ('safe' | 'low' | 'medium' | 'high' | 'critical')[] = ['safe', 'safe', 'safe', 'safe', 'low', 'medium', 'high', 'critical'];
    const sources = ['192.168.1.100', '10.0.0.15', '172.16.0.5', '203.0.113.45', '198.51.100.20'];
    const destinations = ['192.168.1.1', '8.8.8.8', '1.1.1.1', '172.217.12.142', '151.101.193.140'];
    
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];
    const threatLevel = threatLevels[Math.floor(Math.random() * threatLevels.length)];
    
    return {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      source: sources[Math.floor(Math.random() * sources.length)],
      destination: destinations[Math.floor(Math.random() * destinations.length)],
      protocol,
      size: Math.floor(Math.random() * 1500) + 64,
      threatLevel,
      payload: generatePayload(protocol, threatLevel),
      headers: generateHeaders(protocol),
      anomaly: threatLevel !== 'safe' ? generateAnomaly() : undefined
    };
  };

  const generatePayload = (protocol: string, threatLevel: string) => {
    const normalPayloads = [
      "GET /api/users HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0",
      "POST /login HTTP/1.1\nContent-Type: application/json\n{\"username\":\"user\",\"password\":\"***\"}",
      "DNS Query: example.com A",
      "ICMP Echo Request",
      "TCP SYN to port 443"
    ];

    const maliciousPayloads = [
      "GET /admin/../../etc/passwd HTTP/1.1",
      "POST /search HTTP/1.1\nContent: <script>alert('xss')</script>",
      "TCP port scan detected on ports 22,23,80,443,3389",
      "Suspicious SQL injection attempt: ' OR 1=1--",
      "Potential buffer overflow: " + "A".repeat(1000)
    ];

    return threatLevel === 'safe' 
      ? normalPayloads[Math.floor(Math.random() * normalPayloads.length)]
      : maliciousPayloads[Math.floor(Math.random() * maliciousPayloads.length)];
  };

  const generateHeaders = (protocol: string) => {
    const base = {
      'Version': protocol === 'TCP' ? '4' : '1.1',
      'Length': Math.floor(Math.random() * 1500).toString(),
      'TTL': (Math.floor(Math.random() * 64) + 64).toString(),
    };

    if (protocol === 'HTTP' || protocol === 'HTTPS') {
      return {
        ...base,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Accept': 'text/html,application/xhtml+xml',
        'Content-Type': 'application/json'
      };
    }

    return base;
  };

  const generateAnomaly = () => {
    const anomalies = [
      "Unusual packet size detected",
      "Suspicious payload pattern",
      "Port scanning behavior",
      "SQL injection attempt",
      "XSS payload detected",
      "DDoS pattern identified",
      "Malformed packet structure",
      "Unauthorized access attempt"
    ];
    return anomalies[Math.floor(Math.random() * anomalies.length)];
  };

  const generateThreatAlert = (packet: NetworkPacket): ThreatAlert => {
    const types = ["Intrusion Attempt", "Malware Communication", "Data Exfiltration", "Port Scan", "SQL Injection"];
    const actions = ["Blocked", "Quarantined", "Logged", "Investigating"];
    
    return {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: packet.timestamp,
      type: types[Math.floor(Math.random() * types.length)],
      severity: packet.threatLevel as 'low' | 'medium' | 'high' | 'critical',
      description: packet.anomaly || "Suspicious network activity detected",
      source: packet.source,
      action: actions[Math.floor(Math.random() * actions.length)]
    };
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-threat-critical';
      case 'high': return 'bg-threat-high';
      case 'medium': return 'bg-threat-medium';
      case 'low': return 'bg-threat-low';
      default: return 'bg-safe';
    }
  };

  const getProtocolColor = (protocol: string) => {
    switch (protocol.toLowerCase()) {
      case 'tcp': return 'text-network-tcp';
      case 'udp': return 'text-network-udp';
      case 'http': return 'text-network-http';
      case 'https': return 'text-network-https';
      default: return 'text-primary';
    }
  };

  return (
    <div className="min-h-screen bg-background p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-3xl font-bold">NetSecure Analyzer</h1>
              <p className="text-muted-foreground">Advanced Network Packet Analysis & Threat Detection</p>
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-4">
          <div className={`flex items-center space-x-2 px-3 py-2 rounded-lg ${isMonitoring ? 'bg-safe/20' : 'bg-muted'}`}>
            <div className={`h-2 w-2 rounded-full ${isMonitoring ? 'bg-safe animate-pulse' : 'bg-muted-foreground'}`} />
            <span className="text-sm font-medium">{isMonitoring ? 'Live Monitoring' : 'Paused'}</span>
          </div>
          <Button
            variant={isMonitoring ? "secondary" : "default"}
            onClick={() => setIsMonitoring(!isMonitoring)}
            className="space-x-2"
          >
            {isMonitoring ? <WifiOff className="h-4 w-4" /> : <Activity className="h-4 w-4" />}
            <span>{isMonitoring ? 'Stop' : 'Start'} Monitoring</span>
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-border/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Packets</CardTitle>
            <Network className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalPackets.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">
              <TrendingUp className="inline h-3 w-3 mr-1" />
              +12.5% from last hour
            </p>
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Threats Detected</CardTitle>
            <AlertTriangle className="h-4 w-4 text-threat-high" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-threat-high">{stats.threatsDetected}</div>
            <p className="text-xs text-muted-foreground">
              {stats.threatsDetected > 0 ? 'Immediate attention required' : 'All clear'}
            </p>
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Anomalies</CardTitle>
            <Target className="h-4 w-4 text-threat-medium" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-threat-medium">{stats.anomalies}</div>
            <p className="text-xs text-muted-foreground">
              Pattern analysis active
            </p>
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Throughput</CardTitle>
            <Zap className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{Math.round(stats.throughput)} KB/s</div>
            <Progress value={(stats.throughput / 1500) * 100} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Traffic Feed */}
        <div className="lg:col-span-2">
          <Tabs defaultValue="packets" className="space-y-4">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="packets" className="space-x-2">
                <Activity className="h-4 w-4" />
                <span>Live Packets</span>
              </TabsTrigger>
              <TabsTrigger value="threats" className="space-x-2">
                <AlertTriangle className="h-4 w-4" />
                <span>Threat Alerts</span>
              </TabsTrigger>
              <TabsTrigger value="reports" className="space-x-2">
                <FileText className="h-4 w-4" />
                <span>Reports</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="packets">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Eye className="h-5 w-5" />
                    <span>Network Traffic Analysis</span>
                  </CardTitle>
                  <CardDescription>Real-time packet inspection and monitoring</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-96">
                    <div className="space-y-2">
                      {packets.map((packet) => (
                        <div
                          key={packet.id}
                          className={`p-3 rounded-lg border cursor-pointer transition-colors hover:bg-muted/50 ${
                            selectedPacket?.id === packet.id ? 'bg-muted border-primary' : 'border-border/50'
                          }`}
                          onClick={() => setSelectedPacket(packet)}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-4">
                              <Badge 
                                variant="outline"
                                className={`${getThreatColor(packet.threatLevel)} text-background border-none`}
                              >
                                {packet.threatLevel.toUpperCase()}
                              </Badge>
                              <span className={`font-mono text-sm ${getProtocolColor(packet.protocol)}`}>
                                {packet.protocol}
                              </span>
                              <span className="text-sm font-mono">
                                {packet.source} → {packet.destination}
                              </span>
                            </div>
                            <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                              <span>{packet.size}B</span>
                              <span>{new Date(packet.timestamp).toLocaleTimeString()}</span>
                            </div>
                          </div>
                          {packet.anomaly && (
                            <div className="mt-2 text-sm text-threat-medium">
                              ⚠ {packet.anomaly}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="threats">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2 text-threat-high">
                    <AlertTriangle className="h-5 w-5" />
                    <span>Security Threat Alerts</span>
                  </CardTitle>
                  <CardDescription>Identified security threats and anomalies</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-96">
                    <div className="space-y-3">
                      {threats.map((threat) => (
                        <Alert key={threat.id} className={`border-l-4 ${
                          threat.severity === 'critical' ? 'border-l-threat-critical' :
                          threat.severity === 'high' ? 'border-l-threat-high' :
                          threat.severity === 'medium' ? 'border-l-threat-medium' :
                          'border-l-threat-low'
                        }`}>
                          <AlertTriangle className="h-4 w-4" />
                          <AlertTitle className="flex items-center justify-between">
                            <span>{threat.type}</span>
                            <Badge variant="outline" className={getThreatColor(threat.severity)}>
                              {threat.severity.toUpperCase()}
                            </Badge>
                          </AlertTitle>
                          <AlertDescription className="mt-2 space-y-1">
                            <p>{threat.description}</p>
                            <div className="flex items-center justify-between text-xs">
                              <span>Source: {threat.source}</span>
                              <span>Action: {threat.action}</span>
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {new Date(threat.timestamp).toLocaleString()}
                            </div>
                          </AlertDescription>
                        </Alert>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="reports">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <FileText className="h-5 w-5" />
                    <span>Security Analysis Report</span>
                  </CardTitle>
                  <CardDescription>Comprehensive security assessment and findings</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="prose prose-invert max-w-none">
                    <h3 className="text-lg font-semibold text-foreground">Executive Summary</h3>
                    <p className="text-muted-foreground">
                      Network monitoring session analysis reveals {stats.threatsDetected} security threats 
                      and {stats.anomalies} anomalies detected across {stats.totalPackets} analyzed packets.
                    </p>
                    
                    <h4 className="text-md font-semibold text-foreground mt-4">Key Findings:</h4>
                    <ul className="text-muted-foreground space-y-2">
                      <li>• Multiple SQL injection attempts detected from external sources</li>
                      <li>• Port scanning activity identified targeting internal infrastructure</li>
                      <li>• Suspicious payload patterns in HTTP traffic</li>
                      <li>• DDoS-like behavior patterns observed</li>
                    </ul>

                    <h4 className="text-md font-semibold text-foreground mt-4">Recommendations:</h4>
                    <ul className="text-muted-foreground space-y-2">
                      <li>• Implement additional input validation on web applications</li>
                      <li>• Configure firewall rules to block identified malicious IPs</li>
                      <li>• Update intrusion detection signatures</li>
                      <li>• Schedule security team review of flagged activities</li>
                    </ul>
                  </div>

                  <div className="flex space-x-2 pt-4">
                    <Button variant="outline">
                      <FileText className="h-4 w-4 mr-2" />
                      Export Report
                    </Button>
                    <Button variant="outline">
                      <Shield className="h-4 w-4 mr-2" />
                      Schedule Scan
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        {/* Packet Inspector */}
        <div>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Eye className="h-5 w-5" />
                <span>Packet Inspector</span>
              </CardTitle>
              <CardDescription>
                {selectedPacket ? 'Detailed packet analysis' : 'Select a packet to inspect'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {selectedPacket ? (
                <ScrollArea className="h-96">
                  <div className="space-y-4 font-mono text-sm">
                    <div>
                      <h4 className="font-semibold text-primary mb-2">Packet Information</h4>
                      <div className="space-y-1 text-xs">
                        <div>ID: {selectedPacket.id}</div>
                        <div>Timestamp: {new Date(selectedPacket.timestamp).toLocaleString()}</div>
                        <div>Size: {selectedPacket.size} bytes</div>
                        <div className="flex items-center space-x-2">
                          <span>Threat Level:</span>
                          <Badge className={getThreatColor(selectedPacket.threatLevel)}>
                            {selectedPacket.threatLevel.toUpperCase()}
                          </Badge>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold text-primary mb-2">Network Headers</h4>
                      <div className="bg-muted/50 p-2 rounded text-xs space-y-1">
                        <div>Source: {selectedPacket.source}</div>
                        <div>Destination: {selectedPacket.destination}</div>
                        <div>Protocol: {selectedPacket.protocol}</div>
                        {Object.entries(selectedPacket.headers).map(([key, value]) => (
                          <div key={key}>{key}: {value}</div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold text-primary mb-2">Payload Analysis</h4>
                      <div className="bg-muted/50 p-2 rounded text-xs whitespace-pre-wrap">
                        {selectedPacket.payload}
                      </div>
                    </div>

                    {selectedPacket.anomaly && (
                      <div>
                        <h4 className="font-semibold text-threat-high mb-2">Security Alert</h4>
                        <Alert className="border-threat-high">
                          <AlertTriangle className="h-4 w-4" />
                          <AlertDescription className="text-xs">
                            {selectedPacket.anomaly}
                          </AlertDescription>
                        </Alert>
                      </div>
                    )}
                  </div>
                </ScrollArea>
              ) : (
                <div className="h-96 flex items-center justify-center text-center">
                  <div className="space-y-2">
                    <Eye className="h-12 w-12 text-muted-foreground mx-auto" />
                    <p className="text-muted-foreground">Select a packet from the traffic feed to view detailed analysis</p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default PacketAnalyzer;