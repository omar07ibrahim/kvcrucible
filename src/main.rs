use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use kvcrucible::Contract;

#[derive(Debug, Parser)]
#[command(
    name = "kvcrucible",
    version,
    about = "Offline conformance lab for unreliable LLM KV-cache event streams"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the versioned v0.1 scope and its explicit non-goals.
    Contract {
        /// Select human-readable text or stable JSON output.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum OutputFormat {
    Json,
    #[default]
    Text,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Contract { format } => print_contract(format),
    }
}

fn print_contract(format: OutputFormat) -> ExitCode {
    let contract = Contract::v0_1();

    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&contract) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("failed to serialize contract: {error}");
                return ExitCode::FAILURE;
            }
        },
        OutputFormat::Text => {
            println!("{}", contract.project);
            println!("status: {}", contract.status);
            println!("trace format: {}", contract.trace_format);
            println!("\nguarantees:");
            for guarantee in contract.guarantees {
                println!("  - {guarantee}");
            }
            println!("\nnon-goals:");
            for non_goal in contract.non_goals {
                println!("  - {non_goal}");
            }
        }
    }

    ExitCode::SUCCESS
}
