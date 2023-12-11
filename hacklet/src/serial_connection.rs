use log::{debug, error, trace};
use std::time::Duration;

use libftd2xx::BitMode;
use libftd2xx::Ftdi;
use libftd2xx::FtStatus;
use libftd2xx::FtdiCommon;

pub struct SerialConnection {
    pub connection: Ftdi,
}

impl SerialConnection {
    pub fn new() -> Result<SerialConnection, FtStatus> {
        let mut ftd = SerialConnection::usb_open(0x0403, 0x8c81)?;
        ftd.set_bit_mode(0x00, BitMode::Reset)?;
        ftd.set_baud_rate(115200)?;
        ftd.set_flow_control_none()?;
        ftd.set_dtr()?;
        ftd.set_rts()?;
        ftd.set_timeouts(Duration::from_secs(30), Duration::from_secs(5))?;
        
        let rx_bytes = ftd.queue_status()?;
        if rx_bytes != 0 {
            let _ = ftd.purge_rx();
        }

        Ok(SerialConnection {
            connection: ftd,
        })
    }

    pub fn close(&mut self) {
        debug!("Closing serial connection");
        let _ = self.connection.close();
    }

    pub fn transmit(&mut self, command: &[u8]) -> Result<usize, FtStatus> {
        trace!("TX: {:x?}", command);
        self.connection.write(command)
    }

    pub fn receive(&mut self, expected_bytes: usize) -> Result<Vec<u8>, FtStatus> {
        let mut bytes = vec![0u8; expected_bytes];
        let mut bytes_read: usize = 0;
        loop {
            let rx_bytes = self.connection.queue_status()?;
            if rx_bytes >= 1 {
                let bytes_to_read = std::cmp::min(rx_bytes, expected_bytes-bytes_read);
                bytes_read += self.connection.read( &mut bytes[bytes_read..bytes_read+bytes_to_read])?;
                if bytes_read == expected_bytes {
                    trace!("RX: {:x?}", bytes);
                    return Ok(bytes);
                }
            }
        }
    }

    fn usb_open(vendor: u16, product: u16) -> Result<Ftdi, FtStatus> {
        debug!("Opening USB device");
        libftd2xx::set_vid_pid(0x0403u16,0x8c81u16)?;
        trace!("Successfully set FTDI VID/PID");

        let devices = match libftd2xx::list_devices() {
            Ok(list) => list,
            Err(err) => {
                error!("Failed to list FTDI devices! {:?}", err);
                return Err(err);
            }
        };

        debug!("Device count: {:?}", devices.len());
        if devices.len() == 1 {
            return Ftdi::with_index(0);
        }

        for device in devices {
            debug!("Found device: {:?}", device);
            if device.vendor_id == vendor && device.product_id == product {
                match Ftdi::with_serial_number(&device.serial_number) {
                    Ok(ft) => {
                        trace!("Opened FTDI device");
                        return Ok(ft);
                    },
                    Err(err) => {
                        error!("Failed to open Modlet FTDI device: {:?}", err);
                        return Err(err);
                    }
                };
            }
        }

        Err(FtStatus::DEVICE_NOT_FOUND)
    }
}

impl Drop for SerialConnection {
    fn drop(&mut self) {
        debug!("Dropping serial connection");
        self.close();
    }
}