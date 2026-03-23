// MCP Sentinel — Jenkins Declarative Pipeline
// Requires: Jenkins with Pipeline plugin, Python 3.9+ on agent
//
// Quick start:
//   1. Create a new Pipeline job in Jenkins
//   2. Set "Pipeline script from SCM", point to this repository
//   3. Jenkins will automatically pick up this Jenkinsfile
//
// Optional Jenkins plugins for enhanced output:
//   - junit        : renders test results in the Jenkins UI
//   - warnings-ng  : renders SARIF/static analysis results
//   - cobertura    : renders coverage reports

pipeline {
    agent any

    options {
        timeout(time: 15, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    environment {
        // Pin the Python interpreter. Override per-agent via Jenkins node properties
        // if your agent uses a different path (e.g. /usr/bin/python3).
        PYTHON = 'python3'
        PIP    = 'pip3'
    }

    stages {

        // ------------------------------------------------------------------ //
        // Stage 1: install dependencies into a virtualenv
        // ------------------------------------------------------------------ //
        stage('Install') {
            steps {
                sh """
                    ${PYTHON} -m venv .venv
                    . .venv/bin/activate
                    ${PIP} install --upgrade pip
                    ${PIP} install -e ".[dev]"
                """
            }
        }

        // ------------------------------------------------------------------ //
        // Stage 2: lint (ruff) + type check (mypy) — non-blocking by default
        // ------------------------------------------------------------------ //
        stage('Lint') {
            steps {
                sh """
                    . .venv/bin/activate
                    ruff check src/ --output-format=github || true
                    mypy src/mcp_sentinel --ignore-missing-imports || true
                """
            }
        }

        // ------------------------------------------------------------------ //
        // Stage 3: run the full test suite with JUnit XML + coverage output
        // ------------------------------------------------------------------ //
        stage('Test') {
            steps {
                sh """
                    . .venv/bin/activate
                    python -m pytest tests/ \
                        -v \
                        --tb=short \
                        --junitxml=reports/junit.xml \
                        --cov=src/mcp_sentinel \
                        --cov-report=xml:reports/coverage.xml \
                        --cov-report=term
                """
            }
            post {
                always {
                    // Publish JUnit test results (requires JUnit plugin)
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        // ------------------------------------------------------------------ //
        // Stage 4: run MCP Sentinel on the project's own source code
        // (dogfood scan — catches regressions in the tool itself)
        // ------------------------------------------------------------------ //
        stage('Security Scan') {
            steps {
                sh """
                    . .venv/bin/activate
                    mkdir -p reports
                    mcp-sentinel scan src/ \
                        --output sarif \
                        --json-file reports/sentinel.sarif \
                        --no-progress \
                        || true
                    mcp-sentinel scan src/ \
                        --output json \
                        --json-file reports/sentinel.json \
                        --no-progress \
                        || true
                """
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/sentinel.sarif, reports/sentinel.json',
                                     allowEmptyArchive: true
                    // Publish with warnings-ng plugin (optional):
                    // recordIssues tools: [sarif(pattern: 'reports/sentinel.sarif')]
                }
            }
        }

    }

    // ---------------------------------------------------------------------- //
    // Post-pipeline: publish all reports and notify on failure
    // ---------------------------------------------------------------------- //
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure {
            echo 'Pipeline failed. Check the test and scan stages above.'
        }
        success {
            echo 'All stages passed.'
        }
    }
}
