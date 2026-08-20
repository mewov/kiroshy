use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Inspect {
        #[arg(short, long)]
        addr: String,
        #[arg(short, long)]
        public: String,
    },
}

mod quic;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    match args.command {
        Command::Inspect { addr, public } => {}
    }
}
