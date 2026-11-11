//! `webdesserts-mesh` standalone binary; see [`webdesserts_mesh::cli`].

fn main() -> anyhow::Result<()> {
    webdesserts_mesh::cli::run_from_os_args(std::env::args_os().collect())
}
