use anyhow::Result;
use clap::{Parser, Subcommand};
use std::process::ExitCode;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use mcp_sentinel::cli;

#[derive(Parser)]
#[command(
    name = "mcp-sentinel",
    version,
    about = "🛡️  The Ultimate Security Scanner for MCP Servers",
    long_about = "MCP Sentinel combines static analysis, runtime monitoring, and AI-powered detection \
                  to provide comprehensive security scanning for Model Context Protocol servers."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan MCP server or configuration for vulnerabilities
    ///
    /// Exit codes:
    ///   0 - No issues found (or below --fail-on threshold)
    ///   1 - Vulnerabilities found at or above --fail-on level
    ///   2 - Scan error (target not found, invalid config, etc.)
    ///   3 - Usage error (invalid arguments)
    #[command(visible_alias = "s")]
    Scan {
        /// Path to MCP server directory, GitHub URL, or config file
        #[arg(value_name = "TARGET")]
        target: String,

        /// Scanning mode
        #[arg(long, value_enum, default_value = "quick")]
        mode: ScanMode,

        /// LLM provider for deep mode
        #[arg(long, value_enum)]
        llm_provider: Option<LlmProvider>,

        /// Specific model name
        #[arg(long)]
        llm_model: Option<String>,

        /// API key (or use env var)
        #[arg(long, env = "MCP_SENTINEL_API_KEY")]
        llm_api_key: Option<String>,

        /// Output format
        #[arg(short, long, value_enum, default_value = "terminal")]
        output: OutputFormat,

        /// Save report to file
        #[arg(long, value_name = "PATH")]
        output_file: Option<String>,

        /// Minimum severity to report
        #[arg(long, value_enum, default_value = "low")]
        severity: SeverityLevel,

        /// Exit with code 1 if vulnerabilities >= level found
        #[arg(long, value_enum)]
        fail_on: Option<SeverityLevel>,

        /// Custom configuration file
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Run as transparent MCP proxy for runtime monitoring
    Proxy {
        /// MCP configuration file to proxy
        #[arg(short, long)]
        config: Option<String>,

        /// Proxy listen port
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Custom guardrails rules file (YAML)
        #[arg(short, long)]
        guardrails: Option<String>,

        /// Save all MCP traffic to log file
        #[arg(long)]
        log_traffic: bool,

        /// Traffic log destination
        #[arg(long)]
        log_file: Option<String>,

        /// Block requests >= risk level
        #[arg(long, value_enum)]
        block_on_risk: Option<SeverityLevel>,

        /// Send alerts to webhook URL
        #[arg(long)]
        alert_webhook: Option<String>,

        /// Launch web dashboard
        #[arg(short, long)]
        dashboard: bool,
    },

    /// Continuous scanning with file watching
    Monitor {
        /// Path to MCP server directory
        #[arg(value_name = "TARGET")]
        target: String,

        /// Rescan interval in seconds
        #[arg(long, default_value = "300")]
        interval: u64,

        /// Watch for file changes and rescan immediately
        #[arg(short, long)]
        watch: bool,

        /// Run as background daemon
        #[arg(short, long)]
        daemon: bool,

        /// Daemon PID file location
        #[arg(long)]
        pid_file: Option<String>,

        /// Alert on vulnerabilities >= level
        #[arg(long, value_enum)]
        alert_on: Option<SeverityLevel>,
    },

    /// Comprehensive security audit (all engines)
    Audit {
        /// Path to MCP server directory
        #[arg(value_name = "TARGET")]
        target: String,

        /// Include runtime analysis (temporary proxy)
        #[arg(long)]
        include_proxy: bool,

        /// Proxy duration for runtime analysis in seconds
        #[arg(long, default_value = "300")]
        duration: u64,

        /// Maximum depth analysis (slower)
        #[arg(short, long)]
        comprehensive: bool,

        // Inherit scan options
        #[arg(long, value_enum)]
        llm_provider: Option<LlmProvider>,

        #[arg(long)]
        llm_model: Option<String>,

        #[arg(long, env = "MCP_SENTINEL_API_KEY")]
        llm_api_key: Option<String>,

        #[arg(short, long, value_enum, default_value = "terminal")]
        output: OutputFormat,

        #[arg(long)]
        output_file: Option<String>,
    },

    /// Initialize configuration
    Init {
        /// Config file location
        #[arg(long, default_value = "~/.mcp-sentinel/config.yaml")]
        config_path: String,
    },

    /// Manage whitelisted tools and servers
    Whitelist {
        #[command(subcommand)]
        command: WhitelistCommands,
    },

    /// Manage guardrails rules
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ScanMode {
    Quick,
    Deep,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum LlmProvider {
    Openai,
    Anthropic,
    Local,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum OutputFormat {
    Terminal,
    Json,
    Html,
    Pdf,
    Sarif,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Subcommand)]
enum WhitelistCommands {
    /// Add tool/server to whitelist
    Add {
        #[arg(value_name = "TYPE")]
        item_type: String,
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(value_name = "HASH")]
        hash: String,
    },
    /// Remove from whitelist
    Remove {
        #[arg(value_name = "HASH")]
        hash: String,
    },
    /// Show all whitelisted items
    List,
    /// Export whitelist to JSON
    Export {
        #[arg(value_name = "PATH")]
        path: String,
    },
    /// Import whitelist from JSON
    Import {
        #[arg(value_name = "PATH")]
        path: String,
    },
}

#[derive(Subcommand)]
enum RulesCommands {
    /// Validate guardrails syntax
    Validate {
        #[arg(value_name = "PATH")]
        path: String,
    },
    /// List available rule templates
    List,
    /// Test rules against sample traffic
    Test {
        #[arg(value_name = "RULES")]
        rules: String,
        #[arg(value_name = "TRAFFIC")]
        traffic: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose {
        "mcp_sentinel=debug,info"
    } else {
        "mcp_sentinel=info,warn"
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Set color preference
    if cli.no_color {
        std::env::set_var("NO_COLOR", "1");
    }

    info!("🛡️  MCP Sentinel v{}", env!("CARGO_PKG_VERSION"));

    // Execute command and handle exit codes
    let result = match cli.command {
        Commands::Scan {
            target,
            mode,
            llm_provider,
            llm_model,
            llm_api_key,
            output,
            output_file,
            severity,
            fail_on,
            config,
        } => {
            match cli::scan::execute(
                target,
                mode,
                llm_provider,
                llm_model,
                llm_api_key,
                output,
                output_file,
                severity,
                fail_on,
                config,
            )
            .await
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(cli::SentinelError::VulnerabilitiesFound { message }) => {
                    eprintln!("❌ {}", message);
                    ExitCode::from(1)
                }
                Err(cli::SentinelError::ScanError { message }) => {
                    eprintln!("❌ {}", message);
                    ExitCode::from(2)
                }
                Err(cli::SentinelError::UsageError { message }) => {
                    eprintln!("❌ {}", message);
                    ExitCode::from(3)
                }
                Err(cli::SentinelError::Success) => ExitCode::SUCCESS,
            }
        }
        Commands::Proxy {
            config,
            port,
            guardrails,
            log_traffic,
            log_file,
            block_on_risk,
            alert_webhook,
            dashboard,
        } => {
            match cli::proxy::execute(
                config,
                port,
                guardrails,
                log_traffic,
                log_file,
                block_on_risk,
                alert_webhook,
                dashboard,
            )
            .await
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    ExitCode::from(2)
                }
            }
        }
        Commands::Monitor {
            target,
            interval,
            watch,
            daemon,
            pid_file,
            alert_on,
        } => {
            match cli::monitor::execute(target, interval, watch, daemon, pid_file, alert_on).await
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    ExitCode::from(2)
                }
            }
        }
        Commands::Audit {
            target,
            include_proxy,
            duration,
            comprehensive,
            llm_provider,
            llm_model,
            llm_api_key,
            output,
            output_file,
        } => {
            match cli::audit::execute(
                target,
                include_proxy,
                duration,
                comprehensive,
                llm_provider,
                llm_model,
                llm_api_key,
                output,
                output_file,
            )
            .await
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    ExitCode::from(2)
                }
            }
        }
        Commands::Init { config_path } => match cli::init::execute(config_path).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("❌ Error: {}", e);
                ExitCode::from(2)
            }
        },
        Commands::Whitelist { command } => {
            let result = match command {
                WhitelistCommands::Add {
                    item_type,
                    name,
                    hash,
                } => cli::whitelist::add(item_type, name, hash).await,
                WhitelistCommands::Remove { hash } => cli::whitelist::remove(hash).await,
                WhitelistCommands::List => cli::whitelist::list().await,
                WhitelistCommands::Export { path } => cli::whitelist::export(path).await,
                WhitelistCommands::Import { path } => cli::whitelist::import(path).await,
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    ExitCode::from(2)
                }
            }
        }
        Commands::Rules { command } => {
            let result = match command {
                RulesCommands::Validate { path } => cli::rules::validate(path).await,
                RulesCommands::List => cli::rules::list().await,
                RulesCommands::Test { rules, traffic } => cli::rules::test(rules, traffic).await,
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    ExitCode::from(2)
                }
            }
        }
    };

    result
}
