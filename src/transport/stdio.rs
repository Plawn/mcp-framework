use rmcp::{ServerHandler, ServiceExt};

/// Run the MCP server with stdio transport (for Claude Desktop)
pub async fn run_stdio<S>(server: S) -> anyhow::Result<()>
where
    S: ServerHandler,
{
    // Create stdio transport
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    eprintln!("MCP server running in stdio mode");

    // Run the server with Ctrl+C handling
    let service = server.serve((stdin, stdout)).await?;

    tokio::select! {
        result = service.waiting() => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("Shutting down stdio server");
        }
    }

    Ok(())
}
