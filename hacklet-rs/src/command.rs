use clap::ArgAction;
use clap::Args;
use clap::Parser;
use clap::Subcommand;

use clap_num::maybe_hex;

#[derive(Parser)]
#[command(arg_required_else_help = true)]
pub struct Command {
    #[command(subcommand)]
    pub command: Option<Subcommands>,

    /// Enable debug messages (add this twice for trace level)
    #[arg(short, long, global=true, action = ArgAction::Count)]
    pub debug: u8,
}

#[derive(Subcommand)]
pub enum Subcommands {
    /// Turn on the specified socket
    On(SocketArgs),

    /// Turn off the specified socket
    Off(SocketArgs),

    /// Read all available samples from the specified socket
    Read(SocketArgs),

    /// Add a new device to the network
    Commission,
}

#[derive(Args)]
pub struct SocketArgs {
    /// The network ID, (e.g. 0x215a)
    #[arg(short, long, value_parser = maybe_hex::<u16>)]
    pub network: u16,

    /// The socket number, either 0 or 1 for top or bottom outlet
    #[arg(short, long, value_parser = clap::value_parser!(u8).range(0..2))]
    pub socket: u8,
}