#[cfg(feature = "build-ebpf")]
use anyhow::{anyhow, Context as _};

#[cfg(feature = "build-ebpf")]
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "build-ebpf")]
    {
        let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context("MetadataCommand::exec")?;
        let ebpf_package = packages
            .into_iter()
            .find(|cargo_metadata::Package { name, .. }| name == "etherip-xdp-ebpf")
            .ok_or_else(|| anyhow!("etherip-xdp-ebpf package not found"))?;
        aya_build::build_ebpf([ebpf_package])
    }

    #[cfg(not(feature = "build-ebpf"))]
    Ok(())
}
