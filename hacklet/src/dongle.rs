use log::debug;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use crate::messages::*;
use crate::serial_connection;

// TODO: more helpful errors
#[derive(Debug)]
pub enum DongleError {
    MessageFailure,
    SerialConnectionError,
}

impl From<binrw::Error> for DongleError {
    fn from(_: binrw::Error) -> Self {
        DongleError::MessageFailure
    }
}

// TODO: more helpful d2xx error conversions
impl From<libftd2xx::FtStatus> for DongleError {
    fn from(status: libftd2xx::FtStatus) -> Self {
        match status {
            libftd2xx::FtStatus::INVALID_HANDLE => Self::SerialConnectionError,
            libftd2xx::FtStatus::DEVICE_NOT_FOUND => Self::SerialConnectionError,
            libftd2xx::FtStatus::DEVICE_NOT_OPENED => Self::SerialConnectionError,
            libftd2xx::FtStatus::IO_ERROR => Self::SerialConnectionError,
            libftd2xx::FtStatus::INSUFFICIENT_RESOURCES => Self::SerialConnectionError,
            libftd2xx::FtStatus::INVALID_PARAMETER => Self::SerialConnectionError,
            libftd2xx::FtStatus::INVALID_BAUD_RATE => Self::SerialConnectionError,
            libftd2xx::FtStatus::DEVICE_NOT_OPENED_FOR_ERASE => Self::SerialConnectionError,
            libftd2xx::FtStatus::DEVICE_NOT_OPENED_FOR_WRITE => Self::SerialConnectionError,
            libftd2xx::FtStatus::FAILED_TO_WRITE_DEVICE => Self::SerialConnectionError,
            libftd2xx::FtStatus::EEPROM_READ_FAILED => Self::SerialConnectionError,
            libftd2xx::FtStatus::EEPROM_WRITE_FAILED => Self::SerialConnectionError,
            libftd2xx::FtStatus::EEPROM_ERASE_FAILED => Self::SerialConnectionError,
            libftd2xx::FtStatus::EEPROM_NOT_PRESENT => Self::SerialConnectionError,
            libftd2xx::FtStatus::EEPROM_NOT_PROGRAMMED => Self::SerialConnectionError,
            libftd2xx::FtStatus::INVALID_ARGS => Self::SerialConnectionError,
            libftd2xx::FtStatus::NOT_SUPPORTED => Self::SerialConnectionError,
            libftd2xx::FtStatus::OTHER_ERROR => Self::SerialConnectionError,
            libftd2xx::FtStatus::DEVICE_LIST_NOT_READY => Self::SerialConnectionError,
        }
    }
}

pub struct DongleId {
    pub device: u64,
    pub network: u16,
}
pub enum CommissionStatus {
    Commissioned(DongleId),
    NotCommissioned,
    Unknown,
}

pub enum SwitchState {
    AlwaysOn,
    AlwaysOff,
}

pub struct Dongle {
    pub serial: serial_connection::SerialConnection,
}

impl Dongle {
    pub fn open() -> Result<Dongle, DongleError> {
        let serial = serial_connection::SerialConnection::new()?;
        let mut dongle = Dongle { serial: serial };
        dongle.boot()?;
        dongle.boot_confirm()?;
        Ok(dongle)
    }

    pub fn commission(&mut self) -> Result<CommissionStatus, DongleError> {
        debug!("Listening for devices...");

        self.unlock_network()?;

        let timeout = Duration::from_secs(30);
        let until = Instant::now() + timeout;

        loop {
            if Instant::now() > until {
                break;
            }
            debug!("Waiting for broadcast...");

            let header_buf = self.serial.receive(4)?;
            let remaining_bytes = (header_buf[3] + 1) as usize;
            let payload_buf = self.serial.receive(remaining_bytes)?;
            let total_len = header_buf.len() + payload_buf.len();
            let mut buf = vec![0u8; total_len];
            buf[..4].copy_from_slice(&header_buf);
            buf[4..].copy_from_slice(&payload_buf);
            if buf[1] != 0xa0 {
                continue;
            }
            let response = read_message_from_buf::<BroadcastResponse>(&buf)?;
            debug!("Found device {:?} on network {:?}", response.device_id, response.network_id);

            let current_time = SystemTime::now();
            let since_epoch = current_time.duration_since(SystemTime::UNIX_EPOCH);
            match since_epoch {
                Ok(time) => {
                    let timestamp = time.as_secs() as u32; // Warning: u64->u32 conversion loss
                    self.update_time(response.network_id, timestamp)?;
                },
                Err(_) => (),
            };

            self.lock_network()?;

            let dongle_id = DongleId {
                device: response.device_id,
                network: response.network_id,
            };
            return Ok(CommissionStatus::Commissioned(dongle_id))
        }


        Ok(CommissionStatus::Unknown)
    }

    pub fn select_network(&mut self, network_id: u16) -> Result<HandshakeResponse, DongleError> {
        debug!("Selecting network {:?}", network_id);
        let request = HandshakeRequest{network_id};
        let data = create_message_buf(&request)?;
        self.serial.transmit(&data)?;

        let returned = self.serial.receive(6)?;
        let response = read_message_from_buf::<HandshakeResponse>(&returned)?;
        Ok(response)
    }

    pub fn request_samples(&mut self, network_id: u16, channel_id: u16) -> Result<Vec<u16>, DongleError> {
        debug!("Requesting samples {:?}/{:?}", network_id, channel_id);
        let request = SamplesRequest{network_id, channel_id};
        let data = create_message_buf(&request)?;
        self.serial.transmit(&data)?;

        let returned = self.serial.receive(6)?;
        let _ = read_message_from_buf::<AckResponse>(&returned)?;

        let header_buf = self.serial.receive(4)?;
        let remaining_bytes = (header_buf[3] + 1) as usize;
        let payload_buf = self.serial.receive(remaining_bytes)?;
        let total_len = header_buf.len() + payload_buf.len();
        let mut buf = vec![0u8; total_len];
        buf[..4].copy_from_slice(&header_buf);
        buf[4..].copy_from_slice(&payload_buf);

        let response = read_message_from_buf::<SamplesResponse>(&buf)?;

        Ok(response.samples)
    }

    pub fn switch(&mut self, network_id: u16, channel_id: u8, state: SwitchState) -> Result<ScheduleResponse, DongleError> {
        let schedule: [u8; 56] = match state {
            SwitchState::AlwaysOff => {
                debug!("Turning off channel {:?} on network {:?}", channel_id, network_id);
                let mut bitmap = [0x7f; 56];
                bitmap[5] = 0x25;
                bitmap
            }
            SwitchState::AlwaysOn => {
                debug!("Turning on channel {:?} on network {:?}", channel_id, network_id);
                let mut bitmap = [0xff; 56];
                bitmap[5] = 0xa5;
                bitmap
            }
        };
        let schedule_request = ScheduleRequest {
            network_id,
            channel_id,
            schedule,
        };

        let mut data = create_message_buf(&schedule_request)?;
        let size = self.serial.transmit(&mut data)?;
        debug!("Wrote {:?} bytes", size);

        let returned = self.serial.receive(6)?;
        let response = read_message_from_buf::<ScheduleResponse>(&returned)?;
        Ok(response)
    }

    pub fn unlock_network(&mut self) -> Result<LockResponse, DongleError> {
        debug!("Unlocking network");
        let request = UnlockRequest{};
        let mut data = create_message_buf(&request)?;
        let size = self.serial.transmit(&mut data)?;
        debug!("Wrote {:?} bytes", size);

        let returned = self.serial.receive(6)?;
        let response = read_message_from_buf::<LockResponse>(&returned)?;
        debug!("Unlock complete");
        Ok(response)
    }

    pub fn lock_network(&mut self) -> Result<LockResponse, DongleError> {
        debug!("Locking network");
        let request = LockRequest{};
        let mut data = create_message_buf(&request)?;
        let size = self.serial.transmit(&mut data)?;
        debug!("Wrote {:?} bytes", size);

        let returned = self.serial.receive(6)?;
        let response = read_message_from_buf::<LockResponse>(&returned)?;
        debug!("Lock complete");
        Ok(response)

    }

    fn boot(&mut self) -> Result<BootResponse, DongleError> {
        debug!("Sending boot request...");
        let request = BootRequest{};
        let mut data = create_message_buf(&request)?;
        let size = self.serial.transmit(&mut data)?;
        debug!("Wrote {:?} bytes", size);

        let returned = self.serial.receive(27)?;
        let response = read_message_from_buf::<BootResponse>(&returned)?;
        Ok(response)
    }

    fn boot_confirm(&mut self) -> Result<BootConfirmResponse, DongleError> {
        debug!("Sending boot confirmation request...");
        let request = BootConfirmRequest{};
        let data = create_message_buf(&request)?;
        let size = self.serial.transmit(&data)?;
        debug!("Wrote {:?} bytes", size);

        let returned = self.serial.receive(6)?;
        let response = read_message_from_buf::<BootConfirmResponse>(&returned)?;
        Ok(response)
    }

    fn update_time(&mut self, network_id: u16, time: u32) -> Result<UpdateTimeResponse, DongleError> {
        debug!("Updating time...");
        let request = UpdateTimeRequest {
            network_id,
            time,
        };
        let data = create_message_buf(&request)?;
        self.serial.transmit(&data)?;

        let ackreturned = self.serial.receive(6)?;
        read_message_from_buf::<UpdateTimeAckResponse>(&ackreturned)?;

        let returned = self.serial.receive(8)?;
        let response = read_message_from_buf::<UpdateTimeResponse>(&returned)?;
        Ok(response)
    }

    pub fn drop(&mut self) {
        self.serial.close()
    }
}
