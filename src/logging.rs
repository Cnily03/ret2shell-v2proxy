use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_logger() {
    let env_filter_directive = std::env::var("RUST_LOG").unwrap_or("info".to_string());
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_ansi(true),
        )
        .with(EnvFilter::new(&env_filter_directive))
        .init();
}
