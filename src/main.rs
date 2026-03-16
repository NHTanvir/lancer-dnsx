//! lancer-dnsx
//! Rust clone of dnsx. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-dnsx", version, about = "Rust clone of dnsx")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-dnsx - scaffold ready. Implement per plan.md.");
    Ok(())
}
