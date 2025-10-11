#[cfg(feature = "clap")]
mod bin {
    use clap::Parser;
    use etherip_xdp::{run, Opt};

    #[allow(dead_code)]
    #[tokio::main]
    pub(crate) async fn main() -> anyhow::Result<()> {
        env_logger::init();

        let opt = Opt::parse();
        run(opt).await
    }
}

#[cfg(feature = "clap")]
use bin::main;

#[cfg(not(feature = "clap"))]
fn main() {
    compile_error!("To build a binary, 'clap' feature is needed.");
}
