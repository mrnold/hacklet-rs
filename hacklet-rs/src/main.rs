use clap::Parser;
use log::info;

mod command;
use command::{Command, Subcommands};
use hacklet::dongle::{Dongle, DongleError, SwitchState, CommissionStatus};

fn main() -> Result<(), DongleError> {
    let run = Command::parse();

    match run.debug {
        1 => simple_logger::init_with_level(log::Level::Debug).unwrap(),
        2 => simple_logger::init_with_level(log::Level::Trace).unwrap(),
        _ => simple_logger::init_with_level(log::Level::Info).unwrap(),
    }

    match &run.command {
        Some(Subcommands::On(args)) => {
            info!("Turning on channel {:?} on network 0x{:x?}", args.socket, args.network);
            let mut dongle = Dongle::open()?;
            dongle.switch(args.network, args.socket, SwitchState::AlwaysOn)?;
        },
        Some(Subcommands::Off(args)) => {
            info!("Turning off channel {:?} on network 0x{:x?}", args.socket, args.network);
            let mut dongle = Dongle::open()?;
            dongle.switch(args.network, args.socket, SwitchState::AlwaysOff)?;
        },
        Some(Subcommands::Read(args)) => {
            info!("Reading power samples from device...");
            let mut dongle = Dongle::open()?;
            let response = dongle.request_samples(args.network, args.socket as u16)?;
            info!("Samples: {:x?}", response);
        },
        Some(Subcommands::Commission) => {
            info!("Listening for new device network...");
            let mut dongle = Dongle::open()?;
            let response = dongle.commission()?;
            if let CommissionStatus::Commissioned(id) = response {
                info!("Found device 0x{:x?} on network 0x{:x?}", id.device, id.network);
            }
        },
        _ => {}
    };

    Ok(())
}
