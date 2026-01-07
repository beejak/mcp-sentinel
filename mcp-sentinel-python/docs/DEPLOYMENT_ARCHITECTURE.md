# Deployment Architecture Guide

## Overview

This document provides comprehensive deployment architecture guidance for the MCP Sentinel Python project, covering containerization, cloud deployment, scaling strategies, security considerations, and operational best practices.

## Table of Contents

1. [Container Architecture](#container-architecture)
2. [Deployment Patterns](#deployment-patterns)
3. [Cloud Platform Integration](#cloud-platform-integration)
4. [Scaling Strategies](#scaling-strategies)
5. [Security Architecture](#security-architecture)
6. [Monitoring and Observability](#monitoring-and-observability)
7. [Configuration Management](#configuration-management)
8. [Backup and Recovery](#backup-and-recovery)
9. [Performance Optimization](#performance-optimization)
10. [Operational Procedures](#operational-procedures)

---

## Container Architecture

### Multi-Stage Docker Build

```dockerfile
# Build stage
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install Poetry
RUN pip install poetry

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction --no-ansi

# Runtime stage
FROM python:3.11-slim as runtime

# Create non-root user
RUN groupadd -r mcp-sentinel && useradd -r -g mcp-sentinel mcp-sentinel

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=mcp-sentinel:mcp-sentinel . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/config \
    && chown -R mcp-sentinel:mcp-sentinel /app

# Switch to non-root user
USER mcp-sentinel

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import mcp_sentinel; print('OK')" || exit 1

# Default command
CMD ["mcp-sentinel", "--help"]
```

### Container Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  mcp-sentinel:
    build:
      context: .
      dockerfile: Dockerfile
    image: mcp-sentinel:latest
    container_name: mcp-sentinel-app
    restart: unless-stopped
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
    
    # Environment variables
    environment:
      - MCP_SENTINEL_LOG_LEVEL=INFO
      - MCP_SENTINEL_CONFIG_PATH=/app/config/config.yaml
      - MCP_SENTINEL_DATA_PATH=/app/data
      - MCP_SENTINEL_MAX_WORKERS=4
      - MCP_SENTINEL_TIMEOUT=300
    
    # Volume mounts
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
      - ./logs:/app/logs
      - ./reports:/app/reports
    
    # Network configuration
    networks:
      - mcp-sentinel-network
    
    # Security options
    security_opt:
      - no-new-privileges:true
    
    # Read-only root filesystem
    read_only: true
    
    # Temporary filesystem
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    
    # Logging configuration
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service=mcp-sentinel"

  # Redis for caching (optional)
  redis:
    image: redis:7-alpine
    container_name: mcp-sentinel-redis
    restart: unless-stopped
    
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
    
    volumes:
      - redis-data:/data
    
    networks:
      - mcp-sentinel-network
    
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru

  # PostgreSQL for metadata (optional)
  postgres:
    image: postgres:15-alpine
    container_name: mcp-sentinel-postgres
    restart: unless-stopped
    
    environment:
      - POSTGRES_DB=mcp_sentinel
      - POSTGRES_USER=mcp_sentinel
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-changeme}
    
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    
    networks:
      - mcp-sentinel-network
    
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G

networks:
  mcp-sentinel-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

volumes:
  redis-data:
  postgres-data:
```

---

## Deployment Patterns

### Kubernetes Deployment

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: mcp-sentinel
  labels:
    name: mcp-sentinel
    environment: production
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-sentinel-config
  namespace: mcp-sentinel
data:
  config.yaml: |
    app:
      name: "MCP Sentinel"
      version: "1.0.0"
      environment: "production"
    
    scanner:
      max_workers: 8
      timeout: 300
      chunk_size: 8192
      cache_enabled: true
      cache_ttl: 3600
    
    logging:
      level: "INFO"
      format: "json"
      file: "/app/logs/app.log"
    
    monitoring:
      enabled: true
      metrics_port: 8080
      health_check_port: 8081
---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: mcp-sentinel-secrets
  namespace: mcp-sentinel
type: Opaque
data:
  # Base64 encoded values
  database_password: <base64-encoded-password>
  api_key: <base64-encoded-api-key>
  jwt_secret: <base64-encoded-jwt-secret>
---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-sentinel
  namespace: mcp-sentinel
  labels:
    app: mcp-sentinel
    version: v1
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: mcp-sentinel
  template:
    metadata:
      labels:
        app: mcp-sentinel
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: mcp-sentinel
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: mcp-sentinel
        image: mcp-sentinel:latest
        imagePullPolicy: Always
        
        ports:
        - containerPort: 8080
          name: metrics
          protocol: TCP
        - containerPort: 8081
          name: health
          protocol: TCP
        
        env:
        - name: MCP_SENTINEL_CONFIG_PATH
          value: "/app/config/config.yaml"
        - name: MCP_SENTINEL_LOG_LEVEL
          value: "INFO"
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mcp-sentinel-secrets
              key: database_password
        
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: data
          mountPath: /app/data
        - name: logs
          mountPath: /app/logs
        
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 2000m
            memory: 2Gi
        
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /ready
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      
      volumes:
      - name: config
        configMap:
          name: mcp-sentinel-config
      - name: data
        persistentVolumeClaim:
          claimName: mcp-sentinel-data
      - name: logs
        emptyDir: {}
      
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - mcp-sentinel
              topologyKey: kubernetes.io/hostname
---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: mcp-sentinel-service
  namespace: mcp-sentinel
  labels:
    app: mcp-sentinel
spec:
  selector:
    app: mcp-sentinel
  ports:
  - name: metrics
    port: 8080
    targetPort: 8080
    protocol: TCP
  - name: health
    port: 8081
    targetPort: 8081
    protocol: TCP
  type: ClusterIP
---
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mcp-sentinel-hpa
  namespace: mcp-sentinel
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mcp-sentinel
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

### Serverless Deployment (AWS Lambda)

```python
# lambda_function.py
import json
import os
import asyncio
from typing import Dict, Any
from mcp_sentinel import MCPSentinel
from mcp_sentinel.config import Config

# Initialize once for Lambda container reuse
config = Config()
sentinel = MCPSentinel(config)

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for MCP Sentinel."""
    
    try:
        # Parse event
        scan_path = event.get('scan_path', '/tmp')
        scan_type = event.get('scan_type', 'full')
        output_format = event.get('output_format', 'json')
        
        # Run scan
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(
            sentinel.scan_directory(scan_path, scan_type)
        )
        
        # Format results
        if output_format == 'json':
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({
                    'scan_id': context.request_id,
                    'results': results.to_dict(),
                    'scan_duration': context.get_remaining_time_in_millis()
                })
            }
        else:
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/plain'
                },
                'body': results.to_summary()
            }
    
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'error': str(e),
                'scan_id': context.request_id
            })
        }

# Lambda layer configuration
# layer/requirements.txt
mcp-sentinel==1.0.0
pydantic>=2.0.0
aiofiles>=23.0.0
rich>=13.0.0
```

---

## Cloud Platform Integration

### AWS Deployment

```yaml
# aws/cloudformation.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'MCP Sentinel AWS Deployment'

Parameters:
  Environment:
    Type: String
    Default: production
    AllowedValues: [development, staging, production]
  
  InstanceType:
    Type: String
    Default: t3.medium
    AllowedValues: [t3.micro, t3.small, t3.medium, t3.large]
  
  KeyPair:
    Type: AWS::EC2::KeyPair::KeyName
  
  VpcId:
    Type: AWS::EC2::VPC::Id
  
  SubnetIds:
    Type: List<AWS::EC2::Subnet::Id>

Resources:
  # ECS Cluster
  ECSCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Sub "mcp-sentinel-${Environment}"
      CapacityProviders:
        - FARGATE
        - FARGATE_SPOT
      DefaultCapacityProviderStrategy:
        - CapacityProvider: FARGATE
          Weight: 1
        - CapacityProvider: FARGATE_SPOT
          Weight: 2
  
  # Task Definition
  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: mcp-sentinel
      NetworkMode: awsvpc
      RequiresCompatibilities:
        - FARGATE
      Cpu: 1024
      Memory: 2048
      ExecutionRoleArn: !Ref ExecutionRole
      TaskRoleArn: !Ref TaskRole
      ContainerDefinitions:
        - Name: mcp-sentinel
          Image: !Sub "${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/mcp-sentinel:latest"
          Essential: true
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: !Ref LogGroup
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: mcp-sentinel
          Environment:
            - Name: ENVIRONMENT
              Value: !Ref Environment
            - Name: AWS_REGION
              Value: !Ref AWS::Region
          Secrets:
            - Name: DATABASE_PASSWORD
              ValueFrom: !Sub "${SecretArn}:database_password::"
  
  # Application Load Balancer
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: !Sub "mcp-sentinel-alb-${Environment}"
      Type: application
      Scheme: internal
      Subnets: !Ref SubnetIds
      SecurityGroups:
        - !Ref ALBSecurityGroup
  
  # Auto Scaling
  AutoScalingTarget:
    Type: AWS::ApplicationAutoScaling::ScalableTarget
    Properties:
      ServiceNamespace: ecs
      ResourceId: !Sub "service/${ECSCluster}/${ECSService}"
      ScalableDimension: ecs:service:DesiredCount
      MinCapacity: 2
      MaxCapacity: 10
      RoleARN: !Sub "arn:aws:iam::${AWS::AccountId}:role/aws-service-role/ecs.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_ECSService"
  
  # CloudWatch Alarms
  HighErrorRateAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub "mcp-sentinel-high-error-rate-${Environment}"
      MetricName: ErrorRate
      Namespace: MCP_Sentinel
      Statistic: Average
      Period: 300
      EvaluationPeriods: 2
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SNSTopic

Outputs:
  ClusterName:
    Description: 'ECS Cluster Name'
    Value: !Ref ECSCluster
    Export:
      Name: !Sub "${AWS::StackName}-cluster"
  
  LoadBalancerDNS:
    Description: 'Load Balancer DNS Name'
    Value: !GetAtt ApplicationLoadBalancer.DNSName
    Export:
      Name: !Sub "${AWS::StackName}-alb-dns"
```

### Azure Container Instances

```yaml
# azure/arm-template.json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "containerGroupName": {
      "type": "string",
      "defaultValue": "mcp-sentinel-cg",
      "metadata": {
        "description": "Name for the container group"
      }
    },
    "location": {
      "type": "string",
      "defaultValue": "[resourceGroup().location]",
      "metadata": {
        "description": "Location for all resources"
      }
    },
    "imageRepository": {
      "type": "string",
      "defaultValue": "mcpregistry.azurecr.io/mcp-sentinel",
      "metadata": {
        "description": "Container image repository"
      }
    },
    "imageTag": {
      "type": "string",
      "defaultValue": "latest",
      "metadata": {
        "description": "Container image tag"
      }
    }
  },
  "resources": [
    {
      "type": "Microsoft.ContainerInstance/containerGroups",
      "apiVersion": "2021-09-01",
      "name": "[parameters('containerGroupName')]",
      "location": "[parameters('location')]",
      "properties": {
        "containers": [
          {
            "name": "mcp-sentinel",
            "properties": {
              "image": "[concat(parameters('imageRepository'), ':', parameters('imageTag'))]",
              "resources": {
                "requests": {
                  "cpu": 1,
                  "memoryInGB": 2
                }
              },
              "environmentVariables": [
                {
                  "name": "ENVIRONMENT",
                  "value": "production"
                },
                {
                  "name": "LOG_LEVEL",
                  "value": "INFO"
                }
              ],
              "volumeMounts": [
                {
                  "name": "config",
                  "mountPath": "/app/config"
                },
                {
                  "name": "data",
                  "mountPath": "/app/data"
                }
              ]
            }
          }
        ],
        "osType": "Linux",
        "restartPolicy": "Always",
        "volumes": [
          {
            "name": "config",
            "azureFile": {
              "shareName": "mcp-sentinel-config",
              "storageAccountName": "[variables('storageAccountName')]",
              "storageAccountKey": "[listKeys(variables('storageAccountId'), '2019-06-01').keys[0].value]"
            }
          },
          {
            "name": "data",
            "azureFile": {
              "shareName": "mcp-sentinel-data",
              "storageAccountName": "[variables('storageAccountName')]",
              "storageAccountKey": "[listKeys(variables('storageAccountId'), '2019-06-01').keys[0].value]"
            }
          }
        ]
      }
    }
  ]
}
```

---

## Scaling Strategies

### Horizontal Scaling Configuration

```python
# scaling/autoscaler.py
from typing import Dict, List, Optional
import asyncio
import aiohttp
from dataclasses import dataclass

@dataclass
class ScalingMetrics:
    """Metrics for scaling decisions."""
    cpu_utilization: float
    memory_utilization: float
    queue_length: int
    error_rate: float
    response_time: float

class AutoScaler:
    """Intelligent auto-scaling for MCP Sentinel."""
    
    def __init__(self, 
                 min_instances: int = 2,
                 max_instances: int = 20,
                 scale_up_threshold: float = 0.8,
                 scale_down_threshold: float = 0.3,
                 cooldown_period: int = 300):
        self.min_instances = min_instances
        self.max_instances = max_instances
        self.scale_up_threshold = scale_up_threshold
        self.scale_down_threshold = scale_down_threshold
        self.cooldown_period = cooldown_period
        self.current_instances = min_instances
        self.last_scale_time = 0
    
    async def evaluate_scaling(self, metrics: ScalingMetrics) -> Optional[int]:
        """Evaluate if scaling is needed."""
        
        current_time = asyncio.get_event_loop().time()
        
        # Check cooldown period
        if current_time - self.last_scale_time < self.cooldown_period:
            return None
        
        # Calculate scaling score
        scale_score = self._calculate_scale_score(metrics)
        
        # Determine scaling action
        if scale_score > self.scale_up_threshold:
            new_instances = min(self.current_instances + 2, self.max_instances)
            if new_instances > self.current_instances:
                self.last_scale_time = current_time
                return new_instances
        
        elif scale_score < self.scale_down_threshold:
            new_instances = max(self.current_instances - 1, self.min_instances)
            if new_instances < self.current_instances:
                self.last_scale_time = current_time
                return new_instances
        
        return None
    
    def _calculate_scale_score(self, metrics: ScalingMetrics) -> float:
        """Calculate composite scaling score."""
        
        # Weighted scoring
        cpu_weight = 0.3
        memory_weight = 0.2
        queue_weight = 0.3
        response_time_weight = 0.2
        
        # Normalize response time (assuming target < 5 seconds)
        normalized_response_time = min(metrics.response_time / 5000, 1.0)
        
        score = (
            cpu_weight * metrics.cpu_utilization +
            memory_weight * metrics.memory_utilization +
            queue_weight * min(metrics.queue_length / 100, 1.0) +
            response_time_weight * normalized_response_time
        )
        
        return score

# Queue-based scaling
class QueueManager:
    """Manages scan queues for distributed processing."""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.scan_queue = "mcp-sentinel:scan-queue"
        self.result_queue = "mcp-sentinel:result-queue"
    
    async def enqueue_scan(self, scan_request: Dict) -> str:
        """Add scan request to queue."""
        import redis.asyncio as redis
        
        r = redis.from_url(self.redis_url)
        scan_id = scan_request.get('scan_id', self._generate_scan_id())
        
        await r.lpush(self.scan_queue, json.dumps(scan_request))
        return scan_id
    
    async def dequeue_scan(self) -> Optional[Dict]:
        """Get next scan request from queue."""
        import redis.asyncio as redis
        
        r = redis.from_url(self.redis_url)
        result = await r.brpop(self.scan_queue, timeout=1)
        
        if result:
            return json.loads(result[1])
        return None
    
    async def publish_result(self, scan_id: str, result: Dict) -> None:
        """Publish scan result."""
        import redis.asyncio as redis
        
        r = redis.from_url(self.redis_url)
        result_data = {
            'scan_id': scan_id,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        
        await r.publish(f"scan-result:{scan_id}", json.dumps(result_data))
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        import uuid
        return str(uuid.uuid4())
```

### Load Balancing Strategy

```yaml
# nginx/nginx.conf
upstream mcp_sentinel_backend {
    least_conn;
    server mcp-sentinel-1:8080 weight=3 max_fails=3 fail_timeout=30s;
    server mcp-sentinel-2:8080 weight=3 max_fails=3 fail_timeout=30s;
    server mcp-sentinel-3:8080 weight=3 max_fails=3 fail_timeout=30s;
    
    keepalive 32;
    keepalive_requests 100;
    keepalive_timeout 60s;
}

server {
    listen 80;
    server_name mcp-sentinel.example.com;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    # Timeouts
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
    
    # Buffer settings
    proxy_buffer_size 4k;
    proxy_buffers 8 4k;
    proxy_busy_buffers_size 8k;
    
    location / {
        proxy_pass http://mcp_sentinel_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
    }
    
    location /health {
        access_log off;
        proxy_pass http://mcp_sentinel_backend/health;
    }
    
    location /metrics {
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        
        proxy_pass http://mcp_sentinel_backend/metrics;
    }
}
```

---

## Security Architecture

### Container Security

```yaml
# security/pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: mcp-sentinel-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  allowedCapabilities:
    - NET_BIND_SERVICE
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
  seLinux:
    rule: 'RunAsAny'
---
# security/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcp-sentinel-network-policy
  namespace: mcp-sentinel
spec:
  podSelector:
    matchLabels:
      app: mcp-sentinel
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 8081
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS
    - protocol: TCP
      port: 80   # HTTP
```

### Secrets Management

```python
# security/secrets_manager.py
import os
from typing import Dict, Optional
from cryptography.fernet import Fernet
import boto3
from azure.keyvault import SecretClient
from google.cloud import secretmanager

class SecretsManager:
    """Unified secrets management across cloud providers."""
    
    def __init__(self, provider: str, config: Dict):
        self.provider = provider
        self.config = config
        self._client = None
        self._encryption_key = None
    
    @property
    def client(self):
        """Get cloud-specific secrets client."""
        if not self._client:
            if self.provider == 'aws':
                self._client = boto3.client('secretsmanager')
            elif self.provider == 'azure':
                from azure.identity import DefaultAzureCredential
                credential = DefaultAzureCredential()
                self._client = SecretClient(
                    vault_url=self.config['vault_url'],
                    credential=credential
                )
            elif self.provider == 'gcp':
                self._client = secretmanager.SecretManagerServiceClient()
        return self._client
    
    def get_secret(self, secret_name: str) -> str:
        """Retrieve secret from cloud provider."""
        try:
            if self.provider == 'aws':
                response = self.client.get_secret_value(SecretId=secret_name)
                return response['SecretString']
            elif self.provider == 'azure':
                secret = self.client.get_secret(secret_name)
                return secret.value
            elif self.provider == 'gcp':
                name = f"projects/{self.config['project_id']}/secrets/{secret_name}/versions/latest"
                response = self.client.access_secret_version(name=name)
                return response.payload.data.decode('UTF-8')
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        except Exception as e:
            raise RuntimeError(f"Failed to retrieve secret {secret_name}: {e}")
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data at rest."""
        if not self._encryption_key:
            key_path = self.config.get('encryption_key_path')
            if key_path and os.path.exists(key_path):
                with open(key_path, 'rb') as f:
                    self._encryption_key = f.read()
            else:
                self._encryption_key = Fernet.generate_key()
                if key_path:
                    os.makedirs(os.path.dirname(key_path), exist_ok=True)
                    with open(key_path, 'wb') as f:
                        f.write(self._encryption_key)
        
        f = Fernet(self._encryption_key)
        encrypted = f.encrypt(data.encode())
        return encrypted.decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        if not self._encryption_key:
            raise RuntimeError("Encryption key not available")
        
        f = Fernet(self._encryption_key)
        decrypted = f.decrypt(encrypted_data.encode())
        return decrypted.decode()

# Usage example
secrets_config = {
    'aws': {
        'region': 'us-west-2'
    },
    'azure': {
        'vault_url': 'https://mcp-sentinel-vault.vault.azure.net/'
    },
    'gcp': {
        'project_id': 'mcp-sentinel-project'
    }
}

# Initialize secrets manager
secrets_manager = SecretsManager(
    provider=os.getenv('CLOUD_PROVIDER', 'aws'),
    config=secrets_config.get(os.getenv('CLOUD_PROVIDER', 'aws'), {})
)

# Retrieve database password
db_password = secrets_manager.get_secret('mcp-sentinel/database-password')
```

---

## Monitoring and Observability

### Prometheus Metrics Collection

```python
# monitoring/metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from typing import Dict, Any
import time
import functools

# Application metrics
SCAN_REQUESTS_TOTAL = Counter(
    'mcp_sentinel_scan_requests_total',
    'Total number of scan requests',
    ['scan_type', 'status']
)

SCAN_DURATION_SECONDS = Histogram(
    'mcp_sentinel_scan_duration_seconds',
    'Time spent processing scans',
    ['scan_type'],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600]
)

ACTIVE_SCANS = Gauge(
    'mcp_sentinel_active_scans',
    'Number of currently active scans'
)

VULNERABILITIES_FOUND = Counter(
    'mcp_sentinel_vulnerabilities_found_total',
    'Total number of vulnerabilities found',
    ['severity', 'detector_type']
)

MEMORY_USAGE_BYTES = Gauge(
    'mcp_sentinel_memory_usage_bytes',
    'Current memory usage in bytes'
)

CPU_USAGE_PERCENT = Gauge(
    'mcp_sentinel_cpu_usage_percent',
    'Current CPU usage percentage'
)

ERROR_RATE = Counter(
    'mcp_sentinel_errors_total',
    'Total number of errors',
    ['error_type', 'component']
)

def track_scan_metrics(scan_type: str):
    """Decorator to track scan metrics."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            ACTIVE_SCANS.inc()
            
            try:
                result = await func(*args, **kwargs)
                SCAN_REQUESTS_TOTAL.labels(scan_type=scan_type, status='success').inc()
                return result
            except Exception as e:
                SCAN_REQUESTS_TOTAL.labels(scan_type=scan_type, status='error').inc()
                ERROR_RATE.labels(error_type=type(e).__name__, component='scanner').inc()
                raise
            finally:
                scan_duration = time.time() - start_time
                SCAN_DURATION_SECONDS.labels(scan_type=scan_type).observe(scan_duration)
                ACTIVE_SCANS.dec()
        
        return wrapper
    return decorator

def update_system_metrics():
    """Update system resource metrics."""
    import psutil
    
    MEMORY_USAGE_BYTES.set(psutil.virtual_memory().used)
    CPU_USAGE_PERCENT.set(psutil.cpu_percent(interval=1))

class MetricsCollector:
    """Collects and exposes application metrics."""
    
    def __init__(self):
        self.start_time = time.time()
    
    def get_metrics(self) -> str:
        """Get current metrics in Prometheus format."""
        update_system_metrics()
        return generate_latest().decode('utf-8')
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get application health status."""
        uptime = time.time() - self.start_time
        
        return {
            'status': 'healthy',
            'uptime_seconds': uptime,
            'active_scans': ACTIVE_SCANS._value.get(),
            'total_scans': sum(
                sum(metric.values()) for metric in SCAN_REQUESTS_TOTAL._metrics.values()
            ),
            'memory_usage_mb': MEMORY_USAGE_BYTES._value.get() / (1024 * 1024),
            'cpu_usage_percent': CPU_USAGE_PERCENT._value.get()
        }

# Usage example
@track_scan_metrics('full_scan')
async def perform_full_scan(scan_path: str) -> Dict[str, Any]:
    """Perform a full scan with metrics tracking."""
    # Scan implementation
    pass
```

### Distributed Tracing with OpenTelemetry

```python
# monitoring/tracing.py
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
from opentelemetry.instrumentation.asyncio import AsyncioInstrumentor
import functools

class DistributedTracer:
    """Distributed tracing configuration."""
    
    def __init__(self, service_name: str, otlp_endpoint: str):
        self.service_name = service_name
        self.otlp_endpoint = otlp_endpoint
        self.tracer = None
        self._setup_tracing()
    
    def _setup_tracing(self):
        """Setup OpenTelemetry tracing."""
        # Set up tracer provider
        trace.set_tracer_provider(TracerProvider())
        
        # Create OTLP exporter
        otlp_exporter = OTLPSpanExporter(
            endpoint=self.otlp_endpoint,
            insecure=True
        )
        
        # Add span processor
        span_processor = BatchSpanProcessor(otlp_exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)
        
        # Get tracer
        self.tracer = trace.get_tracer(self.service_name)
        
        # Instrument libraries
        AioHttpClientInstrumentor().instrument()
        AsyncioInstrumentor().instrument()
    
    def trace_async_operation(self, operation_name: str):
        """Decorator for tracing async operations."""
        def decorator(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                with self.tracer.start_as_current_span(operation_name):
                    return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def trace_sync_operation(self, operation_name: str):
        """Decorator for tracing sync operations."""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                with self.tracer.start_as_current_span(operation_name):
                    return func(*args, **kwargs)
            return wrapper
        return decorator

# Usage example
tracer = DistributedTracer(
    service_name='mcp-sentinel',
    otlp_endpoint='otel-collector:4317'
)

@tracer.trace_async_operation('scan_directory')
async def scan_directory(path: str) -> Dict[str, Any]:
    """Scan directory with distributed tracing."""
    # Add custom span attributes
    current_span = trace.get_current_span()
    current_span.set_attribute('scan.path', path)
    current_span.set_attribute('scan.type', 'directory')
    
    # Scan implementation
    pass
```

---

## Configuration Management

### Environment-Based Configuration

```python
# config/deployment_config.py
from pydantic import BaseSettings, Field
from typing import Optional, List, Dict
import os

class DeploymentConfig(BaseSettings):
    """Deployment-specific configuration."""
    
    # Application settings
    app_name: str = Field(default="MCP Sentinel", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    
    # Server settings
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8080, env="PORT")
    workers: int = Field(default=4, env="WORKERS")
    
    # Database settings
    database_url: Optional[str] = Field(default=None, env="DATABASE_URL")
    database_pool_size: int = Field(default=10, env="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=20, env="DATABASE_MAX_OVERFLOW")
    
    # Redis settings
    redis_url: Optional[str] = Field(default=None, env="REDIS_URL")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    
    # Security settings
    secret_key: str = Field(env="SECRET_KEY")
    jwt_secret: str = Field(env="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_expiration: int = Field(default=3600, env="JWT_EXPIRATION")
    
    # Monitoring settings
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    metrics_port: int = Field(default=8080, env="METRICS_PORT")
    tracing_enabled: bool = Field(default=True, env="TRACING_ENABLED")
    tracing_endpoint: Optional[str] = Field(default=None, env="TRACING_ENDPOINT")
    
    # Scaling settings
    scaling_enabled: bool = Field(default=True, env="SCALING_ENABLED")
    min_instances: int = Field(default=2, env="MIN_INSTANCES")
    max_instances: int = Field(default=10, env="MAX_INSTANCES")
    
    # Feature flags
    feature_cache_enabled: bool = Field(default=True, env="FEATURE_CACHE_ENABLED")
    feature_async_processing: bool = Field(default=True, env="FEATURE_ASYNC_PROCESSING")
    feature_distributed_scanning: bool = Field(default=False, env="FEATURE_DISTRIBUTED_SCANNING")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Environment-specific configurations
class ProductionConfig(DeploymentConfig):
    """Production environment configuration."""
    
    environment: str = "production"
    log_level: str = "INFO"
    metrics_enabled: bool = True
    tracing_enabled: bool = True
    scaling_enabled: bool = True
    
    # Override with stricter settings
    workers: int = 8
    min_instances: int = 3
    max_instances: int = 20

class StagingConfig(DeploymentConfig):
    """Staging environment configuration."""
    
    environment: str = "staging"
    log_level: str = "DEBUG"
    metrics_enabled: bool = True
    tracing_enabled: bool = True
    scaling_enabled: bool = True

class DevelopmentConfig(DeploymentConfig):
    """Development environment configuration."""
    
    environment: str = "development"
    log_level: str = "DEBUG"
    metrics_enabled: bool = False
    tracing_enabled: bool = False
    scaling_enabled: bool = False
    workers: int = 2

# Configuration factory
def get_deployment_config(environment: str = None) -> DeploymentConfig:
    """Get deployment configuration for environment."""
    
    if environment is None:
        environment = os.getenv("ENVIRONMENT", "development")
    
    config_classes = {
        "production": ProductionConfig,
        "staging": StagingConfig,
        "development": DevelopmentConfig
    }
    
    config_class = config_classes.get(environment, DevelopmentConfig)
    return config_class()

# Usage
config = get_deployment_config()
```

### Configuration Validation

```python
# config/validation.py
from pydantic import validator, ValidationError
from typing import Optional
import re

class ValidatedDeploymentConfig(DeploymentConfig):
    """Deployment configuration with validation."""
    
    @validator('environment')
    def validate_environment(cls, v):
        allowed_environments = ['development', 'staging', 'production']
        if v not in allowed_environments:
            raise ValueError(f'Environment must be one of {allowed_environments}')
        return v
    
    @validator('port')
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v
    
    @validator('workers')
    def validate_workers(cls, v):
        if v < 1:
            raise ValueError('Workers must be at least 1')
        return v
    
    @validator('database_url')
    def validate_database_url(cls, v):
        if v and not re.match(r'^postgresql://.*$', v):
            raise ValueError('Database URL must be a valid PostgreSQL connection string')
        return v
    
    @validator('redis_url')
    def validate_redis_url(cls, v):
        if v and not re.match(r'^redis://.*$', v):
            raise ValueError('Redis URL must be a valid Redis connection string')
        return v
    
    @validator('secret_key', 'jwt_secret')
    def validate_secret_length(cls, v):
        if len(v) < 32:
            raise ValueError('Secret keys must be at least 32 characters long')
        return v
```

---

## Backup and Recovery

### Automated Backup Strategy

```python
# backup/backup_manager.py
import asyncio
import shutil
import tarfile
from datetime import datetime, timedelta
from typing import List, Optional
import boto3
from pathlib import Path

class BackupManager:
    """Manages automated backups for MCP Sentinel."""
    
    def __init__(self, 
                 backup_dir: str,
                 retention_days: int = 30,
                 cloud_provider: str = 'aws'):
        self.backup_dir = Path(backup_dir)
        self.retention_days = retention_days
        self.cloud_provider = cloud_provider
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    async def create_backup(self, 
                          data_paths: List[str],
                          backup_name: str = None) -> str:
        """Create compressed backup of specified paths."""
        
        if backup_name is None:
            backup_name = f"mcp-sentinel-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        backup_path = self.backup_dir / f"{backup_name}.tar.gz"
        
        try:
            # Create tar archive
            with tarfile.open(backup_path, 'w:gz') as tar:
                for data_path in data_paths:
                    path = Path(data_path)
                    if path.exists():
                        tar.add(path, arcname=path.name)
            
            # Upload to cloud storage
            cloud_url = await self._upload_to_cloud(backup_path, backup_name)
            
            # Clean up old backups
            await self._cleanup_old_backups()
            
            return cloud_url or str(backup_path)
        
        except Exception as e:
            # Clean up failed backup
            if backup_path.exists():
                backup_path.unlink()
            raise RuntimeError(f"Backup failed: {e}")
    
    async def restore_backup(self, backup_source: str, restore_dir: str) -> None:
        """Restore from backup."""
        
        restore_path = Path(restore_dir)
        restore_path.mkdir(parents=True, exist_ok=True)
        
        try:
            # Download from cloud if necessary
            if backup_source.startswith(('s3://', 'gs://', 'azure://')):
                backup_file = await self._download_from_cloud(backup_source)
            else:
                backup_file = Path(backup_source)
            
            # Extract backup
            with tarfile.open(backup_file, 'r:gz') as tar:
                tar.extractall(restore_path)
            
            print(f"Backup restored to {restore_path}")
        
        except Exception as e:
            raise RuntimeError(f"Restore failed: {e}")
    
    async def _upload_to_cloud(self, local_file: Path, backup_name: str) -> Optional[str]:
        """Upload backup to cloud storage."""
        
        if self.cloud_provider == 'aws':
            return await self._upload_to_s3(local_file, backup_name)
        elif self.cloud_provider == 'gcp':
            return await self._upload_to_gcs(local_file, backup_name)
        elif self.cloud_provider == 'azure':
            return await self._upload_to_azure(local_file, backup_name)
        
        return None
    
    async def _upload_to_s3(self, local_file: Path, backup_name: str) -> str:
        """Upload to AWS S3."""
        
        s3_client = boto3.client('s3')
        bucket_name = f"mcp-sentinel-backups-{datetime.now().strftime('%Y%m')}"
        
        # Create bucket if it doesn't exist
        try:
            s3_client.create_bucket(Bucket=bucket_name)
        except:
            pass  # Bucket already exists
        
        # Upload file
        s3_key = f"backups/{backup_name}.tar.gz"
        s3_client.upload_file(str(local_file), bucket_name, s3_key)
        
        return f"s3://{bucket_name}/{s3_key}"
    
    async def _cleanup_old_backups(self) -> None:
        """Remove backups older than retention period."""
        
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        # Clean local backups
        for backup_file in self.backup_dir.glob("*.tar.gz"):
            file_time = datetime.fromtimestamp(backup_file.stat().st_mtime)
            if file_time < cutoff_date:
                backup_file.unlink()
                print(f"Removed old backup: {backup_file}")
        
        # Clean cloud backups (implementation depends on provider)
        await self._cleanup_cloud_backups(cutoff_date)
    
    async def _cleanup_cloud_backups(self, cutoff_date: datetime) -> None:
        """Clean up old cloud backups."""
        
        if self.cloud_provider == 'aws':
            await self._cleanup_s3_backups(cutoff_date)
        # Add other providers as needed
    
    async def _cleanup_s3_backups(self, cutoff_date: datetime) -> None:
        """Clean up old S3 backups."""
        
        s3_client = boto3.client('s3')
        
        # List buckets
        response = s3_client.list_buckets()
        
        for bucket in response['Buckets']:
            if bucket['Name'].startswith('mcp-sentinel-backups-'):
                # List objects in bucket
                objects = s3_client.list_objects_v2(Bucket=bucket['Name'])
                
                for obj in objects.get('Contents', []):
                    if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                        s3_client.delete_object(Bucket=bucket['Name'], Key=obj['Key'])
                        print(f"Deleted old S3 backup: {obj['Key']}")

# Database backup
class DatabaseBackupManager:
    """Specialized backup manager for databases."""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
    
    async def backup_database(self, backup_path: str) -> str:
        """Create database backup using pg_dump."""
        
        import subprocess
        
        backup_file = f"{backup_path}/database-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.sql"
        
        try:
            # Use pg_dump for PostgreSQL
            cmd = [
                'pg_dump',
                '--dbname', self.database_url,
                '--file', backup_file,
                '--verbose',
                '--format', 'plain'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"Database backup failed: {result.stderr}")
            
            return backup_file
        
        except FileNotFoundError:
            raise RuntimeError("pg_dump not found. Please install PostgreSQL client tools.")
    
    async def restore_database(self, backup_file: str) -> None:
        """Restore database from backup."""
        
        import subprocess
        
        try:
            # Use psql for PostgreSQL restore
            cmd = [
                'psql',
                '--dbname', self.database_url,
                '--file', backup_file,
                '--verbose'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"Database restore failed: {result.stderr}")
            
            print(f"Database restored from {backup_file}")
        
        except FileNotFoundError:
            raise RuntimeError("psql not found. Please install PostgreSQL client tools.")

# Usage example
async def main():
    # Initialize backup manager
    backup_manager = BackupManager(
        backup_dir="/app/backups",
        retention_days=30,
        cloud_provider="aws"
    )
    
    # Create backup
    data_paths = ["/app/data", "/app/config", "/app/logs"]
    backup_url = await backup_manager.create_backup(data_paths)
    print(f"Backup created: {backup_url}")
    
    # Database backup
    db_backup_manager = DatabaseBackupManager(
        database_url="postgresql://user:password@localhost:5432/mcp_sentinel"
    )
    db_backup_file = await db_backup_manager.backup_database("/app/backups")
    print(f"Database backup created: {db_backup_file}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Performance Optimization

### Container Optimization

```dockerfile
# Optimized Dockerfile
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy dependency files first (for better caching)
COPY pyproject.toml poetry.lock ./

# Install Poetry and dependencies
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-dev --no-interaction --no-ansi && \
    pip uninstall -y poetry

# Runtime stage
FROM python:3.11-slim as runtime

# Create non-root user
RUN groupadd -r mcp-sentinel && useradd -r -g mcp-sentinel -s /bin/false mcp-sentinel

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=mcp-sentinel:mcp-sentinel . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/tmp && \
    chown -R mcp-sentinel:mcp-sentinel /app

# Pre-compile Python files
RUN python -m compileall /app

# Switch to non-root user
USER mcp-sentinel

# Set Python optimization flags
ENV PYTHONOPTIMIZE=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import mcp_sentinel; print('healthy')" || exit 1

# Use dumb-init for proper signal handling
RUN apt-get update && apt-get install -y --no-install-recommends dumb-init && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["dumb-init", "--"]
CMD ["python", "-m", "mcp_sentinel", "server"]
```

### Runtime Performance Tuning

```python
# performance/tuning.py
import os
import multiprocessing
from typing import Dict, Any

class PerformanceTuner:
    """Runtime performance optimization for MCP Sentinel."""
    
    def __init__(self):
        self.cpu_count = multiprocessing.cpu_count()
        self.memory_gb = self._get_memory_gb()
    
    def _get_memory_gb(self) -> float:
        """Get available memory in GB."""
        try:
            import psutil
            return psutil.virtual_memory().total / (1024 ** 3)
        except ImportError:
            return 4.0  # Default assumption
    
    def get_optimal_worker_count(self) -> int:
        """Calculate optimal worker count based on system resources."""
        # For I/O bound operations, use 2-4x CPU cores
        # For CPU bound operations, use CPU cores + 1
        # MCP Sentinel is I/O bound due to file scanning
        optimal_workers = min(self.cpu_count * 2, 16)  # Cap at 16
        return max(optimal_workers, 2)  # Minimum 2 workers
    
    def get_optimal_chunk_size(self, file_size_mb: int) -> int:
        """Calculate optimal chunk size for file processing."""
        # Larger files get larger chunks
        if file_size_mb < 1:
            return 4096  # 4KB
        elif file_size_mb < 10:
            return 16384  # 16KB
        elif file_size_mb < 100:
            return 65536  # 64KB
        else:
            return 262144  # 256KB
    
    def get_connection_pool_size(self) -> int:
        """Calculate optimal connection pool size."""
        # Pool size should be proportional to worker count
        return self.get_optimal_worker_count() * 2
    
    def apply_optimizations(self) -> Dict[str, Any]:
        """Apply runtime optimizations."""
        optimizations = {
            'workers': self.get_optimal_worker_count(),
            'connection_pool_size': self.get_connection_pool_size(),
            'chunk_size': self.get_optimal_chunk_size(10),  # Default assumption
            'memory_limit_mb': int(self.memory_gb * 1024 * 0.8),  # 80% of available memory
        }
        
        # Set environment variables for subprocesses
        os.environ['MCP_SENTINEL_WORKERS'] = str(optimizations['workers'])
        os.environ['MCP_SENTINEL_CONNECTION_POOL_SIZE'] = str(optimizations['connection_pool_size'])
        
        return optimizations

# Memory optimization
class MemoryOptimizer:
    """Memory usage optimization strategies."""
    
    def __init__(self, max_memory_mb: int):
        self.max_memory_mb = max_memory_mb
        self.current_usage_mb = 0
    
    def optimize_file_processing(self, file_count: int) -> Dict[str, Any]:
        """Optimize file processing for memory constraints."""
        # Calculate safe concurrent file limit
        memory_per_file_mb = 50  # Conservative estimate
        max_concurrent = min(
            int(self.max_memory_mb / memory_per_file_mb),
            file_count,
            100  # Hard cap to prevent excessive concurrency
        )
        
        return {
            'max_concurrent_files': max(1, max_concurrent),
            'use_streaming': file_count > max_concurrent,
            'chunk_size': 8192 if file_count > 1000 else 16384
        }
    
    def optimize_detector_loading(self, detector_count: int) -> Dict[str, Any]:
        """Optimize detector loading strategy."""
        # Load detectors in batches if memory is constrained
        if detector_count > 20:
            return {
                'load_strategy': 'lazy',
                'batch_size': 10,
                'cache_detectors': False
            }
        else:
            return {
                'load_strategy': 'eager',
                'batch_size': detector_count,
                'cache_detectors': True
            }

# Usage example
tuner = PerformanceTuner()
optimizations = tuner.apply_optimizations()
print(f"Applied optimizations: {optimizations}")

memory_optimizer = MemoryOptimizer(max_memory_mb=1024)
file_optimization = memory_optimizer.optimize_file_processing(file_count=500)
print(f"File processing optimization: {file_optimization}")
```

---

## Operational Procedures

### Deployment Checklist

```markdown
# Deployment Checklist

## Pre-Deployment
- [ ] All tests pass (unit, integration, security)
- [ ] Code review completed
- [ ] Documentation updated
- [ ] Configuration validated for target environment
- [ ] Secrets and credentials configured
- [ ] Database migrations applied (if applicable)
- [ ] Backup strategy verified

## Deployment
- [ ] Deploy to staging environment first
- [ ] Run smoke tests in staging
- [ ] Monitor application health
- [ ] Verify metrics and logging
- [ ] Check resource utilization
- [ ] Validate security configurations
- [ ] Test failover scenarios

## Post-Deployment
- [ ] Monitor application performance
- [ ] Verify all services are healthy
- [ ] Check error rates and response times
- [ ] Validate scaling behavior
- [ ] Review security logs
- [ ] Update runbooks and documentation
- [ ] Notify stakeholders of completion

## Rollback Plan
- [ ] Previous version available and tested
- [ ] Database rollback procedures ready
- [ ] Configuration rollback verified
- [ ] Communication plan activated
- [ ] Monitoring alerts configured for rollback
```

### Health Check Implementation

```python
# health/health_check.py
from typing import Dict, Any, List
import asyncio
import time
import aiohttp
from dataclasses import dataclass

@dataclass
class HealthStatus:
    """Health check status."""
    component: str
    status: str  # 'healthy', 'degraded', 'unhealthy'
    message: str
    response_time_ms: float
    timestamp: float

class HealthChecker:
    """Comprehensive health checking for MCP Sentinel."""
    
    def __init__(self):
        self.checks = {
            'application': self._check_application,
            'database': self._check_database,
            'redis': self._check_redis,
            'filesystem': self._check_filesystem,
            'memory': self._check_memory,
            'external_services': self._check_external_services
        }
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status."""
        
        start_time = time.time()
        
        # Run all health checks concurrently
        health_tasks = [
            self._run_check(name, check_func)
            for name, check_func in self.checks.items()
        ]
        
        health_results = await asyncio.gather(*health_tasks, return_exceptions=True)
        
        # Process results
        health_status = {}
        overall_status = 'healthy'
        
        for i, (name, _) in enumerate(self.checks.items()):
            result = health_results[i]
            
            if isinstance(result, Exception):
                health_status[name] = HealthStatus(
                    component=name,
                    status='unhealthy',
                    message=f"Check failed: {str(result)}",
                    response_time_ms=0,
                    timestamp=time.time()
                )
                overall_status = 'unhealthy'
            else:
                health_status[name] = result
                if result.status == 'unhealthy':
                    overall_status = 'unhealthy'
                elif result.status == 'degraded' and overall_status == 'healthy':
                    overall_status = 'degraded'
        
        total_response_time = (time.time() - start_time) * 1000
        
        return {
            'status': overall_status,
            'timestamp': time.time(),
            'response_time_ms': total_response_time,
            'checks': {
                name: {
                    'status': status.status,
                    'message': status.message,
                    'response_time_ms': status.response_time_ms,
                    'timestamp': status.timestamp
                }
                for name, status in health_status.items()
            }
        }
    
    async def _run_check(self, name: str, check_func) -> HealthStatus:
        """Run individual health check."""
        
        start_time = time.time()
        
        try:
            result = await check_func()
            response_time = (time.time() - start_time) * 1000
            
            return HealthStatus(
                component=name,
                status=result.get('status', 'healthy'),
                message=result.get('message', 'OK'),
                response_time_ms=response_time,
                timestamp=time.time()
            )
        
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            
            return HealthStatus(
                component=name,
                status='unhealthy',
                message=f"Exception: {str(e)}",
                response_time_ms=response_time,
                timestamp=time.time()
            )
    
    async def _check_application(self) -> Dict[str, Any]:
        """Check application health."""
        
        # Check if application is responsive
        try:
            # This would check actual application state
            # For now, return healthy
            return {
                'status': 'healthy',
                'message': 'Application is running normally',
                'uptime_seconds': time.time() - self.start_time if hasattr(self, 'start_time') else 0
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Application error: {str(e)}'
            }
    
    async def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity."""
        
        try:
            # This would check actual database connectivity
            # For demonstration, simulate a check
            return {
                'status': 'healthy',
                'message': 'Database connection successful',
                'connection_pool_size': 10,
                'active_connections': 3
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Database connection failed: {str(e)}'
            }
    
    async def _check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity."""
        
        try:
            # Simulate Redis check
            return {
                'status': 'healthy',
                'message': 'Redis connection successful',
                'memory_usage_mb': 128,
                'connected_clients': 5
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Redis connection failed: {str(e)}'
            }
    
    async def _check_filesystem(self) -> Dict[str, Any]:
        """Check filesystem health."""
        
        try:
            import shutil
            
            # Check disk space
            disk_usage = shutil.disk_usage('/')
            free_percent = (disk_usage.free / disk_usage.total) * 100
            
            if free_percent < 10:
                status = 'degraded'
                message = f'Low disk space: {free_percent:.1f}% free'
            elif free_percent < 20:
                status = 'healthy'
                message = f'Disk space warning: {free_percent:.1f}% free'
            else:
                status = 'healthy'
                message = f'Disk space OK: {free_percent:.1f}% free'
            
            return {
                'status': status,
                'message': message,
                'free_space_gb': disk_usage.free / (1024**3),
                'total_space_gb': disk_usage.total / (1024**3)
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Filesystem check failed: {str(e)}'
            }
    
    async def _check_memory(self) -> Dict[str, Any]:
        """Check memory usage."""
        
        try:
            import psutil
            
            memory = psutil.virtual_memory()
            
            if memory.percent > 90:
                status = 'degraded'
                message = f'High memory usage: {memory.percent}%'
            elif memory.percent > 80:
                status = 'healthy'
                message = f'Memory usage warning: {memory.percent}%'
            else:
                status = 'healthy'
                message = f'Memory usage OK: {memory.percent}%'
            
            return {
                'status': status,
                'message': message,
                'memory_usage_percent': memory.percent,
                'available_memory_gb': memory.available / (1024**3)
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Memory check failed: {str(e)}'
            }
    
    async def _check_external_services(self) -> Dict[str, Any]:
        """Check external service dependencies."""
        
        try:
            # Check external APIs or services
            # This would check actual external dependencies
            return {
                'status': 'healthy',
                'message': 'All external services available',
                'services_checked': ['api-1', 'api-2']
            }
        except Exception as e:
            return {
                'status': 'degraded',
                'message': f'External service check failed: {str(e)}'
            }

# Usage example
async def health_check_example():
    """Example health check usage."""
    
    health_checker = HealthChecker()
    health_checker.start_time = time.time()  # Initialize start time
    
    # Get health status
    health_status = await health_checker.get_health_status()
    
    print(f"Overall status: {health_status['status']}")
    print(f"Response time: {health_status['response_time_ms']:.2f}ms")
    
    for component, status in health_status['checks'].items():
        print(f"{component}: {status['status']} - {status['message']}")

# FastAPI health endpoint
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

app = FastAPI()
health_checker = HealthChecker()

@app.get("/health")
async def health_endpoint():
    """Health check endpoint."""
    
    health_status = await health_checker.get_health_status()
    
    # Set HTTP status based on overall health
    if health_status['status'] == 'healthy':
        status_code = 200
    elif health_status['status'] == 'degraded':
        status_code = 200  # Still functional
    else:  # unhealthy
        status_code = 503  # Service Unavailable
    
    return JSONResponse(
        content=health_status,
        status_code=status_code,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )

@app.get("/ready")
async def readiness_endpoint():
    """Readiness check endpoint."""
    
    # Check if application is ready to serve requests
    try:
        # This would check actual readiness
        return JSONResponse(
            content={"status": "ready"},
            status_code=200
        )
    except Exception as e:
        return JSONResponse(
            content={"status": "not_ready", "error": str(e)},
            status_code=503
        )
```

---

## Summary

This comprehensive deployment architecture guide provides:

1. **Container Architecture**: Multi-stage Docker builds with security best practices
2. **Deployment Patterns**: Kubernetes, serverless, and traditional deployment options
3. **Cloud Platform Integration**: AWS, Azure, and GCP deployment templates
4. **Scaling Strategies**: Auto-scaling, load balancing, and queue management
5. **Security Architecture**: Container security, network policies, and secrets management
6. **Monitoring and Observability**: Metrics collection, distributed tracing, and health checks
7. **Configuration Management**: Environment-based configuration with validation
8. **Backup and Recovery**: Automated backup strategies and disaster recovery
9. **Performance Optimization**: Container optimization and runtime tuning
10. **Operational Procedures**: Deployment checklists and health check implementations

This architecture ensures that MCP Sentinel can be deployed reliably, scaled efficiently, and operated securely across different environments and cloud platforms.

**Status**: Review Ready

**Document Version**: 1.0  
**Last Updated**: January 2026