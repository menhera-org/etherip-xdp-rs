use clap::Parser;

use etherip_xdp::{run, Opt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opt = Opt::parse();
    run(opt).await
}
