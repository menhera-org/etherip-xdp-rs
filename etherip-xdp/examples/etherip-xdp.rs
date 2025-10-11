#[cfg(feature = "serde")]
mod bin {
    use std::path::PathBuf;

    use clap::Parser;
    use etherip_xdp::{run, EtheripConfigOld};
    use tracing_log::LogTracer;

    #[derive(Parser)]
    #[command(version, about, long_about = None)]
    struct Cli {
        #[arg(short = 'c', long, default_value = "/etc/etherip-xdp.toml")]
        config: PathBuf,

        #[arg(short = 'v', long, action = clap::ArgAction::Count)]
        verbose: u8,
    }

    #[allow(dead_code)]
    #[tokio::main]
    pub(crate) async fn main() -> anyhow::Result<()> {
        let cli = Cli::parse();

        let level = match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            3.. => "trace",
        };

        init_tracing(level)?;
        LogTracer::init()?;

        let opt = EtheripConfigOld::parse();
        run(opt).await
    }


    fn init_tracing(level: &str) -> anyhow::Result<()> {
        use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

        let env_filter = if let Ok(value) = std::env::var(EnvFilter::DEFAULT_ENV) {
            EnvFilter::new(value)
        } else {
            EnvFilter::new(level)
        };

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer())
            .init();
        Ok(())
    }
}

#[cfg(feature = "serde")]
use bin::main;

#[cfg(not(feature = "serde"))]
fn main() {
    compile_error!("To build an example binary, 'serde' feature is needed.");
}
