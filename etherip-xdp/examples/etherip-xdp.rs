#[cfg(all(feature = "serde", feature = "build-lib"))]
mod bin {
    use std::path::PathBuf;

    use clap::Parser;
    use etherip_xdp::EtheripConfig;
    //use tracing_log::LogTracer;

    #[derive(Parser)]
    #[command(version, about, long_about = None)]
    struct Cli {
        #[arg(short = 'c', long, default_value = "/etc/etherip-xdp.toml")]
        config: PathBuf,

        #[arg(short = 'v', long, action = clap::ArgAction::Count)]
        verbose: u8,
    }

    #[allow(dead_code)]
    pub(crate) fn main() -> anyhow::Result<()> {
        let cli = Cli::parse();

        let level = match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            3.. => "trace",
        };

        init_tracing(level)?;
        //LogTracer::init()?;

        let string = std::fs::read_to_string(&cli.config)?;
        let config = toml::from_str::<EtheripConfig>(&string)?;

        config.run()?;

        loop {
            std::thread::park();
        }
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

#[cfg(all(feature = "serde", feature = "build-lib"))]
use bin::main;

#[cfg(any(not(feature = "serde"), not(feature = "build-lib")))]
fn main() {
    compile_error!("To build an example binary, 'serde' and 'build-lib' features are needed.");
}
