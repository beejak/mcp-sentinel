# Tally - Implementation Plan

**Version**: 1.0.0  
**Status**: Ready for Development  
**Purpose**: Phase-by-phase implementation roadmap for Tally transaction classifier  

---

## 🎯 Executive Summary

This document provides a comprehensive implementation plan for building Tally, an independent transaction classification rule engine with AI assistance. The plan is structured in phases, each building upon the previous, with clear deliverables, timelines, and success criteria.

---

## 📋 Table of Contents

1. [Phase 1: Foundation & Core Engine](#phase-1-foundation--core-engine)
2. [Phase 2: AI Integration & Intelligence](#phase-2-ai-integration--intelligence)
3. [Phase 3: Multi-Language Implementation](#phase-3-multi-language-implementation)
4. [Phase 4: Production & Deployment](#phase-4-production--deployment)
5. [Phase 5: Advanced Features & Optimization](#phase-5-advanced-features--optimization)
6. [Testing Strategy](#testing-strategy)
7. [Documentation Plan](#documentation-plan)
8. [Risk Assessment](#risk-assessment)
9. [Success Criteria](#success-criteria)

---

## Phase 1: Foundation & Core Engine

**Duration**: 2 weeks  
**Goal**: Establish solid foundation with working rule engine  

### Week 1: Project Setup & Data Models

#### Day 1-2: Repository Structure & Development Environment
```
tally/
├── docs/                      # Documentation
├── src/                       # Source code
│   ├── python/               # Python implementation
│   ├── rust/                  # Rust implementation (placeholder)
│   ├── go/                    # Go implementation (placeholder)
│   └── typescript/            # TypeScript implementation (placeholder)
├── tests/                     # Test suites
├── examples/                  # Usage examples
├── configs/                   # Configuration files
├── scripts/                   # Build and deployment scripts
└── benchmarks/               # Performance benchmarks
```

**Deliverables**:
- Git repository initialized with proper structure
- Development environment setup scripts
- CI/CD pipeline configuration
- Code quality tools (linting, formatting)

#### Day 3-4: Core Data Models (Python)

```python
# tally/src/python/tally/models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum

class Operator(Enum):
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    EQUALS = "equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    RANGE = "range"
    REGEX = "regex"

@dataclass
class Condition:
    field: str
    operator: Operator
    value: Any = None
    min_value: Any = None
    max_value: Any = None
    case_sensitive: bool = False

@dataclass
class Rule:
    id: str
    name: str
    description: str
    category: str
    conditions: List[Condition]
    confidence: float = 1.0
    priority: int = 0
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class Transaction:
    id: str
    merchant: str
    amount: float
    date: datetime
    description: Optional[str] = None
    category: Optional[str] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Classification:
    category: str
    confidence: float
    rule_matched: Optional[str] = None
    ai_suggested: bool = False
    reasoning: Optional[str] = None
```

#### Day 5: Configuration Management

```python
# tally/src/python/tally/config.py
from dataclasses import dataclass
from typing import Optional, List
import yaml

@dataclass
class AIConfig:
    enabled: bool = False
    api_key: Optional[str] = None
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 150
    temperature: float = 0.1
    system_prompt: str = "You are a financial transaction classification expert."

@dataclass
class EngineConfig:
    max_rules_per_category: int = 1000
    confidence_threshold: float = 0.7
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    parallel_processing: bool = True
    max_workers: int = 4

@dataclass
class TallyConfig:
    ai: AIConfig = field(default_factory=AIConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    categories: List[str] = field(default_factory=lambda: [
        "Groceries", "Dining", "Transportation", "Entertainment",
        "Shopping", "Utilities", "Healthcare", "Other"
    ])

class ConfigManager:
    @staticmethod
    def load_config(config_path: str) -> TallyConfig:
        with open(config_path, 'r') as file:
            data = yaml.safe_load(file)
        return TallyConfig(**data)
    
    @staticmethod
    def save_config(config: TallyConfig, config_path: str):
        with open(config_path, 'w') as file:
            yaml.dump(config.__dict__, file, default_flow_style=False)
```

### Week 2: Rule Engine Implementation

#### Day 1-3: Core Rule Engine

```python
# tally/src/python/tally/engine.py
import re
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor
import asyncio
from .models import Transaction, Rule, Classification, Condition, Operator

class RuleEngine:
    def __init__(self, rules: List[Rule] = None):
        self.rules = rules or []
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._rules_by_category: Dict[str, List[Rule]] = {}
        self._compile_rules()
    
    def add_rule(self, rule: Rule):
        self.rules.append(rule)
        self._compile_rule(rule)
        self._index_rule(rule)
    
    def remove_rule(self, rule_id: str):
        self.rules = [r for r in self.rules if r.id != rule_id]
        self._rebuild_indices()
    
    def classify(self, transaction: Transaction) -> Classification:
        applicable_rules = self._get_applicable_rules(transaction)
        
        if not applicable_rules:
            return Classification(
                category="Uncategorized",
                confidence=0.0,
                reasoning="No matching rules found"
            )
        
        best_rule = max(applicable_rules, key=lambda r: (r.priority, r.confidence))
        
        return Classification(
            category=best_rule.category,
            confidence=best_rule.confidence,
            rule_matched=best_rule.id,
            ai_suggested=False,
            reasoning=f"Matched rule: {best_rule.name}"
        )
    
    def _get_applicable_rules(self, transaction: Transaction) -> List[Rule]:
        applicable = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if self._evaluate_rule(transaction, rule):
                applicable.append(rule)
        return applicable
    
    def _evaluate_rule(self, transaction: Transaction, rule: Rule) -> bool:
        for condition in rule.conditions:
            if not self._evaluate_condition(transaction, condition):
                return False
        return True
    
    def _evaluate_condition(self, transaction: Transaction, condition: Condition) -> bool:
        field_value = self._get_field_value(transaction, condition.field)
        
        if condition.operator == Operator.CONTAINS:
            if not condition.case_sensitive:
                return condition.value.lower() in str(field_value).lower()
            return condition.value in str(field_value)
        
        elif condition.operator == Operator.EQUALS:
            if not condition.case_sensitive:
                return str(field_value).lower() == str(condition.value).lower()
            return field_value == condition.value
        
        elif condition.operator == Operator.GREATER_THAN:
            return float(field_value) > float(condition.value)
        
        elif condition.operator == Operator.LESS_THAN:
            return float(field_value) < float(condition.value)
        
        elif condition.operator == Operator.RANGE:
            return (condition.min_value <= float(field_value) <= condition.max_value)
        
        elif condition.operator == Operator.REGEX:
            pattern = self._get_compiled_pattern(condition.value)
            return bool(pattern.match(str(field_value)))
        
        return False
    
    def _get_field_value(self, transaction: Transaction, field: str) -> any:
        if field == "merchant":
            return transaction.merchant
        elif field == "amount":
            return transaction.amount
        elif field == "description":
            return transaction.description or ""
        elif field == "date":
            return transaction.date
        else:
            return transaction.metadata.get(field, "")
    
    def _compile_rules(self):
        for rule in self.rules:
            self._compile_rule(rule)
            self._index_rule(rule)
    
    def _compile_rule(self, rule: Rule):
        for condition in rule.conditions:
            if condition.operator == Operator.REGEX:
                self._compiled_patterns[condition.value] = re.compile(condition.value)
    
    def _get_compiled_pattern(self, pattern: str) -> re.Pattern:
        if pattern not in self._compiled_patterns:
            self._compiled_patterns[pattern] = re.compile(pattern)
        return self._compiled_patterns[pattern]
    
    def _index_rule(self, rule: Rule):
        if rule.category not in self._rules_by_category:
            self._rules_by_category[rule.category] = []
        self._rules_by_category[rule.category].append(rule)
    
    def _rebuild_indices(self):
        self._compiled_patterns.clear()
        self._rules_by_category.clear()
        self._compile_rules()
```

#### Day 4-5: Rule Management & YAML Integration

```python
# tally/src/python/tally/rule_manager.py
import yaml
from typing import List, Dict
from pathlib import Path
from .models import Rule, Condition, Operator

class RuleManager:
    def __init__(self, rules_dir: str = "configs/rules"):
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.rules: Dict[str, Rule] = {}
    
    def load_rules_from_yaml(self, yaml_path: str) -> List[Rule]:
        with open(yaml_path, 'r') as file:
            data = yaml.safe_load(file)
        
        rules = []
        for rule_data in data.get('rules', []):
            conditions = []
            for cond_data in rule_data.get('conditions', []):
                condition = Condition(
                    field=cond_data['field'],
                    operator=Operator(cond_data['operator']),
                    value=cond_data.get('value'),
                    min_value=cond_data.get('min_value'),
                    max_value=cond_data.get('max_value'),
                    case_sensitive=cond_data.get('case_sensitive', False)
                )
                conditions.append(condition)
            
            rule = Rule(
                id=rule_data['id'],
                name=rule_data['name'],
                description=rule_data.get('description', ''),
                category=rule_data['category'],
                conditions=conditions,
                confidence=rule_data.get('confidence', 1.0),
                priority=rule_data.get('priority', 0),
                enabled=rule_data.get('enabled', True)
            )
            rules.append(rule)
        
        return rules
    
    def save_rules_to_yaml(self, rules: List[Rule], yaml_path: str):
        data = {'rules': []}
        for rule in rules:
            rule_data = {
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'category': rule.category,
                'confidence': rule.confidence,
                'priority': rule.priority,
                'enabled': rule.enabled,
                'conditions': []
            }
            
            for condition in rule.conditions:
                cond_data = {
                    'field': condition.field,
                    'operator': condition.operator.value
                }
                if condition.value is not None:
                    cond_data['value'] = condition.value
                if condition.min_value is not None:
                    cond_data['min_value'] = condition.min_value
                if condition.max_value is not None:
                    cond_data['max_value'] = condition.max_value
                if condition.case_sensitive:
                    cond_data['case_sensitive'] = condition.case_sensitive
                
                rule_data['conditions'].append(cond_data)
            
            data['rules'].append(rule_data)
        
        with open(yaml_path, 'w') as file:
            yaml.dump(data, file, default_flow_style=False, sort_keys=False)
```

---

## Phase 2: AI Integration & Intelligence

**Duration**: 2 weeks  
**Goal**: Integrate AI assistant for enhanced classification  

### Week 3: AI Assistant Implementation

#### Day 1-2: OpenAI Integration

```python
# tally/src/python/tally/ai_assistant.py
import openai
from typing import Optional
from .models import Transaction, Classification
from .config import AIConfig

class AIAssistant:
    def __init__(self, config: AIConfig):
        self.config = config
        if config.enabled and config.api_key:
            openai.api_key = config.api_key
    
    async def classify_transaction(self, transaction: Transaction) -> Optional[Classification]:
        if not self.config.enabled or not self.config.api_key:
            return None
        
        try:
            prompt = self._build_classification_prompt(transaction)
            
            response = await openai.ChatCompletion.acreate(
                model=self.config.model,
                messages=[
                    {"role": "system", "content": self.config.system_prompt},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature
            )
            
            ai_response = response.choices[0].message.content.strip()
            return self._parse_classification_response(ai_response)
            
        except Exception as e:
            print(f"AI classification failed: {e}")
            return None
    
    def _build_classification_prompt(self, transaction: Transaction) -> str:
        return f"""
Analyze this financial transaction and classify it into the most appropriate category.

Transaction Details:
- Merchant: {transaction.merchant}
- Amount: ${transaction.amount:.2f}
- Date: {transaction.date.strftime('%Y-%m-%d')}
- Description: {transaction.description or 'No description'}

Available Categories:
- Groceries
- Dining
- Transportation
- Entertainment
- Shopping
- Utilities
- Healthcare
- Other

Please respond in this exact format:
CATEGORY: [category name]
CONFIDENCE: [0.0-1.0]
REASONING: [brief explanation]
"""
    
    def _parse_classification_response(self, ai_response: str) -> Classification:
        lines = ai_response.strip().split('\n')
        category = None
        confidence = 0.0
        reasoning = ""
        
        for line in lines:
            line = line.strip()
            if line.startswith('CATEGORY:'):
                category = line.replace('CATEGORY:', '').strip()
            elif line.startswith('CONFIDENCE:'):
                try:
                    confidence = float(line.replace('CONFIDENCE:', '').strip())
                except ValueError:
                    confidence = 0.5
            elif line.startswith('REASONING:'):
                reasoning = line.replace('REASONING:', '').strip()
        
        if category:
            return Classification(
                category=category,
                confidence=confidence,
                rule_matched=None,
                ai_suggested=True,
                reasoning=f"AI suggested: {reasoning}"
            )
        
        return None
```

#### Day 3-4: Enhanced Classification Orchestrator

```python
# tally/src/python/tally/classifier.py
from typing import Optional, List
from .models import Transaction, Classification
from .engine import RuleEngine
from .ai_assistant import AIAssistant
from .config import TallyConfig

class TransactionClassifier:
    def __init__(self, config: TallyConfig, rules: List[Rule] = None):
        self.config = config
        self.rule_engine = RuleEngine(rules or [])
        self.ai_assistant = AIAssistant(config.ai)
    
    async def classify(self, transaction: Transaction) -> Classification:
        # First, try rule-based classification
        rule_classification = self.rule_engine.classify(transaction)
        
        # If rule-based classification has high confidence, use it
        if rule_classification.confidence >= self.config.engine.confidence_threshold:
            return rule_classification
        
        # Otherwise, try AI classification
        ai_classification = await self.ai_assistant.classify_transaction(transaction)
        
        # If AI provides better classification, use it
        if ai_classification and ai_classification.confidence > rule_classification.confidence:
            return ai_classification
        
        # Return the better of the two classifications
        return rule_classification if rule_classification.confidence >= (ai_classification.confidence if ai_classification else 0) else ai_classification
    
    def add_rule(self, rule: Rule):
        self.rule_engine.add_rule(rule)
    
    def remove_rule(self, rule_id: str):
        self.rule_engine.remove_rule(rule_id)
    
    def get_rules(self) -> List[Rule]:
        return self.rule_engine.rules
```

#### Day 5: Confidence Scoring & Result Aggregation

```python
# tally/src/python/tally/scoring.py
from typing import List, Optional
from .models import Classification, Transaction

class ConfidenceAggregator:
    def __init__(self, weights=None):
        self.weights = weights or {
            'rule': 1.0,
            'ai': 0.8,
            'historical': 0.6,
            'pattern': 0.4
        }
    
    def aggregate_classifications(self, classifications: List[Classification], transaction: Transaction) -> Classification:
        if not classifications:
            return Classification(
                category="Uncategorized",
                confidence=0.0,
                reasoning="No classifications available"
            )
        
        # Group by category
        category_scores = {}
        for classification in classifications:
            category = classification.category
            if category not in category_scores:
                category_scores[category] = []
            category_scores[category].append(classification.confidence)
        
        # Calculate weighted scores
        best_category = None
        best_score = -1
        
        for category, scores in category_scores.items():
            # Use average confidence for now, can be enhanced
            avg_confidence = sum(scores) / len(scores)
            if avg_confidence > best_score:
                best_score = avg_confidence
                best_category = category
        
        # Find the classification with the best category
        best_classification = next(c for c in classifications if c.category == best_category)
        
        return Classification(
            category=best_category,
            confidence=min(best_score, 0.95),  # Cap at 0.95 for aggregated results
            rule_matched=best_classification.rule_matched,
            ai_suggested=best_classification.ai_suggested,
            reasoning=f"Aggregated from {len(classifications)} sources"
        )
    
    def calculate_confidence_boost(self, transaction: Transaction, classification: Classification) -> float:
        """Calculate confidence boost based on transaction patterns"""
        boost = 0.0
        
        # Boost confidence for well-known merchants
        well_known_merchants = {
            "WHOLEFDS": 0.1,
            "UBER": 0.15,
            "AMAZON": 0.1,
            "STARBUCKS": 0.12
        }
        
        for merchant, confidence_boost in well_known_merchants.items():
            if merchant in transaction.merchant.upper():
                boost += confidence_boost
                break
        
        # Boost confidence for round amounts in certain categories
        if transaction.amount == round(transaction.amount):
            if classification.category in ["Groceries", "Dining", "Entertainment"]:
                boost += 0.05
        
        # Cap the boost
        return min(boost, 0.2)  # Maximum 20% boost
```

### Week 4: CLI Interface & Testing

#### Day 1-3: Command-Line Interface

```python
# tally/src/python/tally/cli.py
import argparse
import asyncio
import csv
import json
from pathlib import Path
from typing import List
from .classifier import TransactionClassifier
from .config import TallyConfig, ConfigManager
from .rule_manager import RuleManager
from .models import Transaction
from datetime import datetime

class TallyCLI:
    def __init__(self):
        self.config = TallyConfig()
        self.classifier = None
        self.rule_manager = RuleManager()
    
    async def classify_csv(self, csv_path: str, output_path: str = None):
        """Classify transactions from CSV file"""
        transactions = self._load_transactions_from_csv(csv_path)
        
        results = []
        for transaction in transactions:
            classification = await self.classifier.classify(transaction)
            results.append({
                'transaction': transaction,
                'classification': classification
            })
        
        self._save_results(results, output_path or f"classified_{Path(csv_path).stem}.json")
        
        # Print summary
        self._print_classification_summary(results)
    
    def _load_transactions_from_csv(self, csv_path: str) -> List[Transaction]:
        transactions = []
        with open(csv_path, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                transaction = Transaction(
                    id=row.get('id', str(len(transactions) + 1)),
                    merchant=row['merchant'],
                    amount=float(row['amount']),
                    date=datetime.fromisoformat(row['date']),
                    description=row.get('description'),
                    metadata={k: v for k, v in row.items() if k not in ['id', 'merchant', 'amount', 'date', 'description']}
                )
                transactions.append(transaction)
        return transactions
    
    def _save_results(self, results: List[dict], output_path: str):
        with open(output_path, 'w') as file:
            json.dump([{
                'transaction': {
                    'id': r['transaction'].id,
                    'merchant': r['transaction'].merchant,
                    'amount': r['transaction'].amount,
                    'date': r['transaction'].date.isoformat(),
                    'description': r['transaction'].description
                },
                'classification': {
                    'category': r['classification'].category,
                    'confidence': r['classification'].confidence,
                    'rule_matched': r['classification'].rule_matched,
                    'ai_suggested': r['classification'].ai_suggested,
                    'reasoning': r['classification'].reasoning
                }
            } for r in results], file, indent=2)
    
    def _print_classification_summary(self, results: List[dict]):
        total = len(results)
        categorized = len([r for r in results if r['classification'].category != "Uncategorized"])
        ai_suggested = len([r for r in results if r['classification'].ai_suggested])
        
        print(f"\nClassification Summary:")
        print(f"Total transactions: {total}")
        print(f"Categorized: {categorized} ({categorized/total*100:.1f}%)")
        print(f"AI suggestions: {ai_suggested}")
        print(f"Average confidence: {sum(r['classification'].confidence for r in results)/total:.2f}")
        
        # Category breakdown
        categories = {}
        for result in results:
            category = result['classification'].category
            categories[category] = categories.get(category, 0) + 1
        
        print("\nCategory breakdown:")
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  {category}: {count}")

def main():
    parser = argparse.ArgumentParser(description='Tally - Transaction Classification Engine')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Classify command
    classify_parser = subparsers.add_parser('classify', help='Classify transactions')
    classify_parser.add_argument('input', help='Input CSV file')
    classify_parser.add_argument('--output', help='Output JSON file')
    classify_parser.add_argument('--config', help='Configuration file')
    classify_parser.add_argument('--rules', help='Rules YAML file')
    
    # Rules management
    rules_parser = subparsers.add_parser('rules', help='Manage rules')
    rules_subparsers = rules_parser.add_subparsers(dest='rules_command')
    
    add_rule_parser = rules_subparsers.add_parser('add', help='Add a rule')
    add_rule_parser.add_argument('--file', help='YAML file with rules')
    
    list_rules_parser = rules_subparsers.add_parser('list', help='List rules')
    
    args = parser.parse_args()
    
    if args.command == 'classify':
        asyncio.run(classify_command(args))
    elif args.command == 'rules':
        rules_command(args)

async def classify_command(args):
    cli = TallyCLI()
    
    # Load configuration
    if args.config:
        cli.config = ConfigManager.load_config(args.config)
    
    # Load rules
    if args.rules:
        rules = cli.rule_manager.load_rules_from_yaml(args.rules)
        cli.classifier = TransactionClassifier(cli.config, rules)
    else:
        cli.classifier = TransactionClassifier(cli.config)
    
    await cli.classify_csv(args.input, args.output)

def rules_command(args):
    cli = TallyCLI()
    
    if args.rules_command == 'add':
        if args.file:
            rules = cli.rule_manager.load_rules_from_yaml(args.file)
            print(f"Added {len(rules)} rules")
    elif args.rules_command == 'list':
        # Implementation for listing rules
        pass

if __name__ == '__main__':
    main()
```

#### Day 4-5: Unit Testing Framework

```python
# tally/tests/test_engine.py
import pytest
from datetime import datetime
from tally.models import Transaction, Rule, Classification, Condition, Operator
from tally.engine import RuleEngine

class TestRuleEngine:
    @pytest.fixture
    def sample_rules(self):
        return [
            Rule(
                id="grocery_001",
                name="Whole Foods Market",
                description="Classify Whole Foods as Groceries",
                category="Groceries",
                conditions=[
                    Condition(field="merchant", operator=Operator.CONTAINS, value="WHOLEFDS")
                ],
                confidence=0.95,
                priority=10
            ),
            Rule(
                id="dining_001",
                name="Restaurant Classification",
                description="Classify restaurants as Dining",
                category="Dining",
                conditions=[
                    Condition(field="merchant", operator=Operator.CONTAINS, value="RESTAURANT")
                ],
                confidence=0.90,
                priority=5
            ),
            Rule(
                id="transport_001",
                name="Uber Transportation",
                description="Classify Uber as Transportation",
                category="Transportation",
                conditions=[
                    Condition(field="merchant", operator=Operator.CONTAINS, value="UBER")
                ],
                confidence=0.98,
                priority=15
            )
        ]
    
    @pytest.fixture
    def engine(self, sample_rules):
        return RuleEngine(sample_rules)
    
    def test_grocery_classification(self, engine):
        transaction = Transaction(
            id="1",
            merchant="WHOLEFDS SM 1234",
            amount=45.67,
            date=datetime.now()
        )
        
        classification = engine.classify(transaction)
        
        assert classification.category == "Groceries"
        assert classification.confidence == 0.95
        assert classification.rule_matched == "grocery_001"
    
    def test_transport_classification(self, engine):
        transaction = Transaction(
            id="2",
            merchant="UBER TRIP",
            amount=12.34,
            date=datetime.now()
        )
        
        classification = engine.classify(transaction)
        
        assert classification.category == "Transportation"
        assert classification.confidence == 0.98
        assert classification.rule_matched == "transport_001"
    
    def test_no_match_classification(self, engine):
        transaction = Transaction(
            id="3",
            merchant="UNKNOWN MERCHANT",
            amount=100.00,
            date=datetime.now()
        )
        
        classification = engine.classify(transaction)
        
        assert classification.category == "Uncategorized"
        assert classification.confidence == 0.0
    
    def test_rule_priority_ordering(self, engine):
        # Add a lower priority rule that would also match
        low_priority_rule = Rule(
            id="test_low",
            name="Low Priority Test",
            description="Lower priority rule",
            category="Test",
            conditions=[
                Condition(field="merchant", operator=Operator.CONTAINS, value="WHOLEFDS")
            ],
            confidence=0.99,
            priority=1  # Lower priority
        )
        engine.add_rule(low_priority_rule)
        
        transaction = Transaction(
            id="4",
            merchant="WHOLEFDS SM 5678",
            amount=23.45,
            date=datetime.now()
        )
        
        classification = engine.classify(transaction)
        
        # Should match the higher priority rule (grocery_001)
        assert classification.rule_matched == "grocery_001"
```

---

## Phase 3: Multi-Language Implementation

**Duration**: 4 weeks  
**Goal**: Implement the same functionality in Rust, Go, and TypeScript  

### Week 5-6: Rust Implementation

#### Core Structure

```rust
// tally/src/rust/tally/src/models.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operator {
    Contains,
    StartsWith,
    EndsWith,
    Equals,
    GreaterThan,
    LessThan,
    Range,
    Regex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub operator: Operator,
    pub value: Option<String>,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub conditions: Vec<Condition>,
    pub confidence: f64,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub merchant: String,
    pub amount: f64,
    pub date: DateTime<Utc>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub confidence: f64,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub category: String,
    pub confidence: f64,
    pub rule_matched: Option<String>,
    pub ai_suggested: bool,
    pub reasoning: Option<String>,
}
```

#### Rule Engine Implementation

```rust
// tally/src/rust/tally/src/engine.rs
use regex::Regex;
use std::collections::HashMap;
use crate::models::{Transaction, Rule, Classification, Condition, Operator};

pub struct RuleEngine {
    rules: Vec<Rule>,
    compiled_patterns: HashMap<String, Regex>,
    rules_by_category: HashMap<String, Vec<Rule>>,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut engine = RuleEngine {
            rules,
            compiled_patterns: HashMap::new(),
            rules_by_category: HashMap::new(),
        };
        engine.compile_rules();
        engine
    }
    
    pub fn classify(&self, transaction: &Transaction) -> Classification {
        let applicable_rules = self.get_applicable_rules(transaction);
        
        if applicable_rules.is_empty() {
            return Classification {
                category: "Uncategorized".to_string(),
                confidence: 0.0,
                rule_matched: None,
                ai_suggested: false,
                reasoning: Some("No matching rules found".to_string()),
            };
        }
        
        let best_rule = applicable_rules
            .iter()
            .max_by(|a, b| {
                a.priority.cmp(&b.priority)
                    .then(a.confidence.partial_cmp(&b.confidence).unwrap())
            })
            .unwrap();
        
        Classification {
            category: best_rule.category.clone(),
            confidence: best_rule.confidence,
            rule_matched: Some(best_rule.id.clone()),
            ai_suggested: false,
            reasoning: Some(format!("Matched rule: {}", best_rule.name)),
        }
    }
    
    fn get_applicable_rules(&self, transaction: &Transaction) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|rule| rule.enabled)
            .filter(|rule| self.evaluate_rule(transaction, rule))
            .collect()
    }
    
    fn evaluate_rule(&self, transaction: &Transaction, rule: &Rule) -> bool {
        rule.conditions.iter().all(|condition| self.evaluate_condition(transaction, condition))
    }
    
    fn evaluate_condition(&self, transaction: &Transaction, condition: &Condition) -> bool {
        let field_value = self.get_field_value(transaction, &condition.field);
        
        match condition.operator {
            Operator::Contains => {
                let value = field_value.to_lowercase();
                let pattern = condition.value.as_ref().unwrap().to_lowercase();
                value.contains(&pattern)
            },
            Operator::Equals => {
                let value = field_value.to_lowercase();
                let pattern = condition.value.as_ref().unwrap().to_lowercase();
                value == pattern
            },
            Operator::GreaterThan => {
                let value: f64 = field_value.parse().unwrap_or(0.0);
                let pattern: f64 = condition.value.as_ref().unwrap().parse().unwrap_or(0.0);
                value > pattern
            },
            Operator::LessThan => {
                let value: f64 = field_value.parse().unwrap_or(0.0);
                let pattern: f64 = condition.value.as_ref().unwrap().parse().unwrap_or(0.0);
                value < pattern
            },
            Operator::Range => {
                let value: f64 = field_value.parse().unwrap_or(0.0);
                let min = condition.min_value.unwrap_or(f64::MIN);
                let max = condition.max_value.unwrap_or(f64::MAX);
                value >= min && value <= max
            },
            Operator::Regex => {
                let pattern = condition.value.as_ref().unwrap();
                let regex = self.get_compiled_pattern(pattern);
                regex.is_match(&field_value)
            },
            _ => false,
        }
    }
    
    fn get_field_value(&self, transaction: &Transaction, field: &str) -> String {
        match field {
            "merchant" => transaction.merchant.clone(),
            "amount" => transaction.amount.to_string(),
            "description" => transaction.description.clone().unwrap_or_default(),
            "date" => transaction.date.to_rfc3339(),
            _ => transaction.metadata.get(field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }
    }
    
    fn compile_rules(&mut self) {
        for rule in &self.rules {
            self.compile_rule(rule);
            self.index_rule(rule);
        }
    }
    
    fn compile_rule(&mut self, rule: &Rule) {
        for condition in &rule.conditions {
            if let Operator::Regex = condition.operator {
                if let Some(pattern) = &condition.value {
                    let regex = Regex::new(pattern).expect("Invalid regex pattern");
                    self.compiled_patterns.insert(pattern.clone(), regex);
                }
            }
        }
    }
    
    fn get_compiled_pattern(&self, pattern: &str) -> &Regex {
        self.compiled_patterns.get(pattern)
            .expect("Pattern should be pre-compiled")
    }
    
    fn index_rule(&mut self, rule: &Rule) {
        self.rules_by_category
            .entry(rule.category.clone())
            .or_insert_with(Vec::new)
            .push(rule.clone());
    }
}
```

### Week 7-8: Go & TypeScript Implementations

Similar implementations for Go and TypeScript would follow the same pattern with language-specific optimizations.

---

## Phase 4: Production & Deployment

**Duration**: 4 weeks  
**Goal**: Production-ready deployment with monitoring and scaling  

### Week 9-10: REST API Development

#### FastAPI Implementation (Python)

```python
# tally/src/python/tally/api/main.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import asyncio
from ..classifier import TransactionClassifier
from ..models import Transaction, Classification, Rule
from ..config import TallyConfig

app = FastAPI(title="Tally API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response models
class ClassificationRequest(BaseModel):
    transactions: List[Transaction]
    use_ai: bool = True
    confidence_threshold: float = 0.7

class ClassificationResponse(BaseModel):
    results: List[Classification]
    summary: dict

class RuleRequest(BaseModel):
    rule: Rule

# Dependency injection
class TallyService:
    def __init__(self):
        self.config = TallyConfig()
        self.classifier = TransactionClassifier(self.config)
    
    async def classify_transactions(self, transactions: List[Transaction], use_ai: bool = True) -> List[Classification]:
        results = []
        for transaction in transactions:
            classification = await self.classifier.classify(transaction)
            results.append(classification)
        return results

tally_service = TallyService()

@app.post("/classify", response_model=ClassificationResponse)
async def classify_transactions(request: ClassificationRequest):
    try:
        results = await tally_service.classify_transactions(
            request.transactions, 
            request.use_ai
        )
        
        summary = {
            "total": len(results),
            "categorized": len([r for r in results if r.category != "Uncategorized"]),
            "ai_suggested": len([r for r in results if r.ai_suggested]),
            "average_confidence": sum(r.confidence for r in results) / len(results) if results else 0
        }
        
        return ClassificationResponse(results=results, summary=summary)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

@app.get("/rules")
async def get_rules():
    return tally_service.classifier.get_rules()

@app.post("/rules")
async def add_rule(request: RuleRequest):
    tally_service.classifier.add_rule(request.rule)
    return {"message": "Rule added successfully"}

@app.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    tally_service.classifier.remove_rule(rule_id)
    return {"message": "Rule deleted successfully"}
```

### Week 11-12: Containerization & Deployment

#### Multi-stage Dockerfile

```dockerfile
# tally/Dockerfile
# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Copy source code
COPY src/python/tally ./tally
COPY configs ./configs

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN useradd --create-home --shell /bin/bash tally

# Copy installed packages from builder
COPY --from=builder /root/.local /home/tally/.local

# Copy application code
COPY --from=builder /app .

# Set ownership and switch to non-root user
RUN chown -R tally:tally /app
USER tally

# Environment variables
ENV PATH=/home/tally/.local/bin:$PATH
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health').raise_for_status()"

# Expose port
EXPOSE 8000

# Default command
CMD ["uvicorn", "tally.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### Docker Compose Configuration

```yaml
# tally/docker-compose.yml
version: '3.8'

services:
  tally:
    build: .
    ports:
      - "8000:8000"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - TALLY_CONFIG_PATH=/app/configs/production.yaml
    volumes:
      - ./configs:/app/configs
      - ./rules:/app/rules
    depends_on:
      - redis
      - postgres
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=tally
      - POSTGRES_USER=tally
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - tally
    restart: unless-stopped

volumes:
  postgres_data:
```

---

## Phase 5: Advanced Features & Optimization

**Duration**: 4 weeks  
**Goal**: Advanced features and performance optimization  

### Advanced Features

1. **Machine Learning Integration**
   - Custom model training on user data
   - Feature engineering for transaction patterns
   - Online learning capabilities

2. **Plugin Architecture**
   - Custom classification plugins
   - Third-party integrations
   - Extensible rule conditions

3. **Advanced Analytics**
   - Spending pattern analysis
   - Anomaly detection
   - Predictive categorization

4. **Performance Optimizations**
   - Rule compilation caching
   - Parallel processing improvements
   - Memory usage optimization

### Performance Benchmarks

```python
# tally/benchmarks/performance_test.py
import time
import asyncio
from tally.classifier import TransactionClassifier
from tally.models import Transaction
from datetime import datetime

async def benchmark_classification():
    # Generate test data
    transactions = []
    for i in range(10000):
        transaction = Transaction(
            id=f"test_{i}",
            merchant=f"TEST MERCHANT {i % 100}",
            amount=float(i * 10.5),
            date=datetime.now()
        )
        transactions.append(transaction)
    
    # Benchmark classification
    classifier = TransactionClassifier(TallyConfig())
    
    start_time = time.time()
    results = []
    
    # Process in batches
    batch_size = 100
    for i in range(0, len(transactions), batch_size):
        batch = transactions[i:i + batch_size]
        batch_results = await asyncio.gather(*[
            classifier.classify(tx) for tx in batch
        ])
        results.extend(batch_results)
    
    end_time = time.time()
    
    duration = end_time - start_time
    throughput = len(transactions) / duration
    
    print(f"Processed {len(transactions)} transactions in {duration:.2f} seconds")
    print(f"Throughput: {throughput:.2f} transactions/second")
    print(f"Average time per transaction: {(duration / len(transactions)) * 1000:.2f}ms")

if __name__ == "__main__":
    asyncio.run(benchmark_classification())
```

---

## Testing Strategy

### Test Coverage Requirements

- **Unit Tests**: > 90% code coverage
- **Integration Tests**: All API endpoints
- **Performance Tests**: Benchmarks for all operations
- **Security Tests**: Penetration testing
- **Load Tests**: 10,000+ concurrent requests

### Test Categories

1. **Functional Tests**
   - Rule matching accuracy
   - AI classification quality
   - Data validation
   - Error handling

2. **Performance Tests**
   - Classification speed
   - Memory usage
   - Concurrent processing
   - Scalability limits

3. **Security Tests**
   - Input validation
   - Authentication
   - Authorization
   - Data encryption

4. **Compatibility Tests**
   - Multi-language consistency
   - Platform compatibility
   - Database compatibility
   - API versioning

---

## Documentation Plan

### Documentation Structure

```
docs/
├── api/                    # API documentation
│   ├── openapi.yaml       # OpenAPI specification
│   └── examples/          # API examples
├── deployment/            # Deployment guides
│   ├── docker.md         # Docker deployment
│   ├── kubernetes.md     # Kubernetes deployment
│   └── cloud.md          # Cloud deployment
├── development/           # Development guides
│   ├── setup.md          # Development setup
│   ├── architecture.md   # Architecture overview
│   └── contributing.md   # Contributing guidelines
├── user/                  # User documentation
│   ├── quickstart.md     # Quick start guide
│   ├── rules.md          # Rule configuration
│   └── troubleshooting.md # Troubleshooting
└── README.md             # Main documentation
```

### Documentation Requirements

- **API Documentation**: 100% coverage with examples
- **User Documentation**: Step-by-step guides
- **Developer Documentation**: Architecture and setup
- **Deployment Documentation**: All deployment methods
- **Video Tutorials**: Key features and workflows

---

## Risk Assessment

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|---------|------------|
| AI API rate limits | Medium | High | Implement caching and fallback mechanisms |
| Performance degradation | Low | High | Comprehensive benchmarking and optimization |
| Memory leaks | Low | Medium | Memory profiling and testing |
| Security vulnerabilities | Medium | High | Security audits and penetration testing |

### Business Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|---------|------------|
| Competition from established players | High | Medium | Focus on unique AI features and performance |
| User adoption challenges | Medium | High | Excellent documentation and user experience |
| Scaling costs | Medium | Medium | Efficient architecture and cost optimization |

---

## Success Criteria

### Technical Success Criteria

- ✅ **Performance**: Process 1000+ transactions/second
- ✅ **Accuracy**: > 95% correct classifications
- ✅ **Latency**: < 10ms per transaction
- ✅ **Availability**: 99.9% uptime
- ✅ **Scalability**: Handle 1M+ transactions/day

### Business Success Criteria

- ✅ **User Satisfaction**: > 4.5/5 rating
- ✅ **Documentation Quality**: Complete and clear
- ✅ **Community Adoption**: Open source contributions
- ✅ **Enterprise Ready**: Security and compliance
- ✅ **Cost Effective**: Competitive pricing model

### Milestone Deliverables

1. **Phase 1**: Working Python implementation with tests
2. **Phase 2**: AI integration with confidence scoring
3. **Phase 3**: Multi-language implementations
4. **Phase 4**: Production deployment with monitoring
5. **Phase 5**: Advanced features and optimization

---

## Conclusion

This implementation plan provides a structured approach to building Tally as an independent, production-ready transaction classification system. The phased approach ensures steady progress with measurable deliverables at each stage, while the comprehensive testing and documentation strategy ensures a high-quality final product.

The plan emphasizes performance, scalability, and user experience, making Tally competitive with existing solutions while offering unique AI-enhanced capabilities and multi-language flexibility.