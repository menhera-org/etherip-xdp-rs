#[cfg(feature = "clap")]
mod bin {
    use clap::Parser;
    use etherip_xdp::{run, EtherIpConfig};
    use tracing_log::LogTracer;

    #[allow(dead_code)]
    #[tokio::main]
    pub(crate) async fn main() -> anyhow::Result<()> {
        init_tracing("info")?;
        LogTracer::init()?;

        let opt = EtherIpConfig::parse();
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

#[cfg(feature = "clap")]
use bin::main;

#[cfg(not(feature = "clap"))]
fn main() {
    compile_error!("To build a binary, 'clap' feature is needed.");
}
