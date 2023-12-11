use binrw::binrw;
use binrw::BinRead;
use binrw::BinWrite;
use binrw::io::Read;
use binrw::io::Seek;
use binrw::io::SeekFrom;
use binrw::io::Write;
use binrw::meta::ReadEndian;
use binrw::meta::WriteEndian;

pub fn create_message_buf<T>(message: &T) -> Result<Vec<u8>, binrw::Error>
where
    T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian + PartialEq
{
    let mut data = binrw::io::Cursor::new(vec![]);
    match message.write(&mut data) {
        Ok(()) => Ok(data.into_inner()),
        Err(err) => Err(err),
    }
}

pub fn read_message_from_buf<T>(buf: &[u8]) -> Result<T, binrw::Error>
where
    T: for<'a> BinRead<Args<'a> = ()> + ReadEndian + PartialEq
{
    let mut data = binrw::io::Cursor::new(buf);
    T::read(&mut data)
}

// Checksum everything but the first and last bytes (header and checksum fields).
// The checksum is just a running XOR of every byte. The header is ignored by
// virtue of being marked as a binrw magic number, so it is not included in the
// stream. The checksum field is ignored by keeping the current checksum and
// the previous checksum, and returning only the previous checksum on reads.
pub struct MessageChecksum<T> {
    wrapped_stream: T,
    previous_checksum: u8,
    checksum: u8,
}

impl<T> MessageChecksum<T> {
    fn new(stream: T) -> Self {
        Self {
            wrapped_stream: stream,
            previous_checksum: 0,
            checksum: 0,
        }
    }
}

impl<T: Read> Read for MessageChecksum<T> {
    fn read(&mut self, buf: &mut [u8]) -> binrw::io::Result<usize> {
        let size = match self.wrapped_stream.read(buf) {
            Ok(size) => size,
            Err(error) => return Err(error),
        };

        for byte in &buf[0..size] {
            self.checksum = self.previous_checksum;
            self.previous_checksum = self.previous_checksum ^ byte;
        }

        Ok(size)
    }
}

impl<T: Seek> Seek for MessageChecksum<T> {
    fn seek(&mut self, pos: SeekFrom) -> binrw::io::Result<u64> {
        self.wrapped_stream.seek(pos)
    }
}

impl<T: Write> Write for MessageChecksum<T> {
    fn write(&mut self, buf: &[u8]) -> binrw::io::Result<usize> {
        let size = match self.wrapped_stream.write(buf) {
            Ok(size) => size,
            Err(error) => return Err(error),
        };

        for byte in &buf[0..size] {
            self.checksum = self.checksum ^ byte;
        }

        Ok(size)
    }

    fn flush(&mut self) -> binrw::io::Result<()> {
        self.wrapped_stream.flush()
    }
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4084))]
#[br(assert(payload_length == 0x16))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct BootResponse {
    #[bw(calc(0x4084))] command: u16,
    #[bw(calc(0x16))] payload_length: u8,
    pub data: [u8; 12],
    pub device_id: u64,
    pub data2: u16,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4080))]
#[br(assert(payload_length == 0x01))]
#[br(assert(data == 0x10))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct BootConfirmResponse {
    #[bw(calc(0x4080))] command: u16,
    #[bw(calc(0x01))] payload_length: u8,
    #[bw(calc(0x10))] data: u8,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0xa013))]
#[br(assert(payload_length == 0x0b))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct BroadcastResponse {
    #[bw(calc(0xa013))] command: u16,
    #[bw(calc(0x0b))] payload_length: u8,
    pub network_id: u16, 
    pub device_id: u64,
    pub data: u8,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0xa0f9))]
#[br(assert(payload_length == 0x01))]
#[br(assert(data == 0x00))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct LockResponse {
    #[bw(calc(0xa0f9))] command: u16,
    #[bw(calc(0x01))] payload_length: u8,
    #[bw(calc(0x00))] data: u8,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4022))]
#[br(assert(payload_length == 0x01))]
#[br(assert(data == 0x00))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct UpdateTimeAckResponse {
    #[bw(calc(0x4022))] command: u16,
    #[bw(calc(0x01))] payload_length: u8,
    #[bw(calc(0x00))] data: u8,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x40a2))]
#[br(assert(payload_length == 0x03))]
#[br(assert(data == 0x00))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct UpdateTimeResponse {
    #[bw(calc(0x40a2))] command: u16,
    #[bw(calc(0x03))] payload_length: u8,
    pub network_id: u16,
    #[bw(calc(0x00))] data: u8,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4003))]
#[br(assert(payload_length == 0x01))]
#[br(assert(data == 0x00))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct HandshakeResponse {
    #[bw(calc(0x4003))] command: u16,
    #[bw(calc(0x01))] payload_length: u8,
    #[bw(calc(0x00))] data: u8,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4024))]
#[br(assert(payload_length == 0x01))]
#[br(assert(data == 0x00))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct AckResponse {
    #[bw(calc(0x4024))] command: u16,
    #[bw(calc(0x01))] payload_length: u8,
    #[bw(calc(0x00))] data: u8,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x40a4))]
#[br(assert(payload_length == 14+2*sample_count))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct SamplesResponse {
    #[bw(calc(0x40a4))] command: u16,
    #[bw(calc(14+2*sample_count))] payload_length: u8,
    pub network_id: u16,
    pub channel_id: u16,
    pub data: u16,
    #[brw(little)] pub time: u32,
    pub sample_count: u8,
    pub stored_sample_count: [u8; 3],
    #[br(little, args { count: sample_count as usize})] pub samples: Vec<u16>,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = s, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4023))]
#[br(assert(payload_length == 0x01))]
#[br(assert(data == 0x00))]
#[br(assert(checksum == s.checksum))]
#[derive(Debug, PartialEq)]
pub struct ScheduleResponse {
    #[bw(calc(0x4023))] command: u16,
    #[bw(calc(0x01))] payload_length: u8,
    #[bw(calc(0x00))] data: u8,
    #[bw(calc(s.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = w, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4004))]
#[br(assert(payload_length == 0x00))]
#[br(assert(checksum == w.checksum))]
#[derive(Debug, PartialEq)]
pub struct BootRequest {
    #[bw(calc(0x4004))] command: u16,
    #[bw(calc(0x00))] payload_length: u8,
    #[bw(calc(w.checksum))] checksum: u8
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = w, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4000))]
#[br(assert(payload_length == 0x00))]
#[br(assert(checksum == w.checksum))]
#[derive(Debug, PartialEq)]
pub struct BootConfirmRequest {
    #[bw(calc(0x4000))] command: u16,
    #[bw(calc(0x00))] payload_length: u8,
    #[bw(calc(w.checksum))] checksum: u8
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = w, map_stream = MessageChecksum::new)]
#[br(assert(command == 0xa236))]
#[br(assert(payload_length == 0x04))]
#[br(assert(data == 0xfcff9001))]
#[br(assert(checksum == w.checksum))]
#[derive(Debug, PartialEq)]
pub struct UnlockRequest {
    #[bw(calc(0xa236))] command: u16,
    #[bw(calc(0x04))] payload_length: u8,
    #[bw(calc(0xfcff9001))] data: u32,
    #[bw(calc(w.checksum))] checksum: u8
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = w, map_stream = MessageChecksum::new)]
#[br(assert(command == 0xa236))]
#[br(assert(payload_length == 0x04))]
#[br(assert(data == 0xfcff0001))]
#[br(assert(checksum == w.checksum))]
#[derive(Debug, PartialEq)]
pub struct LockRequest {
    #[bw(calc(0xa236))] command: u16,
    #[bw(calc(0x04))] payload_length: u8,
    #[bw(calc(0xfcff0001))] data: u32,
    #[bw(calc(w.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = w, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4022))]
#[br(assert(payload_length == 0x06))]
#[br(assert(checksum == w.checksum))]
#[derive(Debug, PartialEq)]
pub struct UpdateTimeRequest {
    #[bw(calc(0x4022))] command: u16,
    #[bw(calc(0x06))] payload_length: u8,
    pub network_id: u16,
    #[bw(little)]
    pub time: u32,
    #[bw(calc(w.checksum))] pub checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = w, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4003))]
#[br(assert(payload_length == 0x04))]
#[br(assert(data == 0x0500))]
#[br(assert(checksum == w.checksum))]
#[derive(Debug, PartialEq)]
pub struct HandshakeRequest {
    #[bw(calc(0x4003))] command: u16,
    #[bw(calc(0x04))] payload_length: u8,
    pub network_id: u16,
    #[bw(calc(0x0500))] data: u16,
    #[bw(calc(w.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = w, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4024))]
#[br(assert(payload_length == 0x06))]
#[br(assert(data == 0x0a00))]
#[br(assert(checksum == w.checksum))]
#[derive(Debug, PartialEq)]
pub struct SamplesRequest {
    #[bw(calc(0x4024))] command: u16,
    #[bw(calc(0x06))] payload_length: u8,
    pub network_id: u16,
    pub channel_id: u16,
    #[bw(calc(0x0a00))] data: u16,
    #[bw(calc(w.checksum))] checksum: u8,
}

#[binrw]
#[brw(big, magic = 0x02u8)]
#[brw(stream = w, map_stream = MessageChecksum::new)]
#[br(assert(command == 0x4023))]
#[br(assert(payload_length == 0x3b))]
#[br(assert(checksum == w.checksum))]
#[derive(Debug, PartialEq)]
pub struct ScheduleRequest {
    #[bw(calc(0x4023))] command: u16,
    #[bw(calc(0x3b))] payload_length: u8,
    pub network_id: u16,
    pub channel_id: u8,
    pub schedule: [u8; 56],
    #[bw(calc(w.checksum))] checksum: u8,
}

// Test checksum calculations for all messages.
#[cfg(test)]
mod test_message_checksums {
    use super::*;

    use binrw::BinRead;
    use binrw::BinWrite;
    use binrw::meta::ReadEndian;
    use binrw::meta::WriteEndian;

    use std::fmt::Debug;

    fn test_data_with_known_good_message<T>(known_good: &T, test_data: &[u8])
    where
        T: for<'a> BinRead<Args<'a> = ()> + ReadEndian +
           for<'b> BinWrite<Args<'b> = ()> + WriteEndian +
           PartialEq + Debug 
    {
        // Make sure a good message struct is read out of the test data,
        // meaning all the public fields match.
        let test_message = read_message_from_buf::<T>(test_data).unwrap();
        assert_eq!(known_good, &test_message);

        // Make sure every byte is equal between constructed and known good
        // message structures.
        let expected_bytes = create_message_buf(known_good).unwrap();
        let extracted_bytes = create_message_buf(&test_message).unwrap();
        assert_eq!(expected_bytes, extracted_bytes);
    }

    fn get_test_data_copy(test_data: &[u8]) -> Vec<u8> {
        let mut copied_data = vec![0; test_data.len()];
        copied_data.copy_from_slice(test_data);
        return copied_data;
    }

    fn test_bad_data_checksum_failure<T>(test_data: &[u8])
    where
        T: for<'a> BinRead<Args<'a> = ()> + ReadEndian +
           for<'b> BinWrite<Args<'b> = ()> + WriteEndian +
           PartialEq + Debug 
    {
        let mut poison_data = get_test_data_copy(test_data);
        let checksum = poison_data.last_mut().expect("Expected test data to not be empty");
        *checksum = checksum.wrapping_add(1);

        let test_message_result = read_message_from_buf::<T>(&poison_data);
        assert!(test_message_result.is_err_and(|err| err.to_string().contains("checksum")));
    }

    fn test_bad_command_header_failure<T>(test_data: &[u8])
    where
        T: for<'a> BinRead<Args<'a> = ()> + ReadEndian +
           for<'b> BinWrite<Args<'b> = ()> + WriteEndian +
           PartialEq + Debug 
    {
        let mut poison_data = get_test_data_copy(test_data);
        assert!(poison_data.len() > 2, "Test data is too short for this test.");

        poison_data[1] = poison_data[1].wrapping_add(1);
        poison_data[2] = poison_data[2].wrapping_add(1);
        let command = [poison_data[1], poison_data[2]];

        let checksum = poison_data.last_mut().expect("Expected test data to not be empty");
        *checksum = *checksum ^ command[0];
        *checksum = *checksum ^ command[1];

        let test_message_result = read_message_from_buf::<T>(&poison_data);
        assert!(test_message_result.is_err_and(|err| err.to_string().contains("command")));
    }

    #[test]
    fn test_boot_response() {
        let test_data: [u8; 27] = [0x02, 0x40, 0x84, 0x16, 0x01, 0x00, 0x00, 0x87, 0x03,
                                   0x00, 0x30, 0x00, 0x33, 0x83, 0x69, 0x9a, 0x0b, 0x2f,
                                   0x00, 0x00, 0x00, 0x58, 0x4f, 0x80, 0x0a, 0x1c, 0x81];

        let boot_response = BootResponse {
            data: [0x01, 0x00, 0x00, 0x87, 0x03, 0x00, 0x30, 0x00, 0x33, 0x83, 0x69, 0x9a],
            device_id: 0x0b2f000000584f80,
            data2: 0x0a1c,
        };

        test_data_with_known_good_message(&boot_response, &test_data.clone());
        test_bad_data_checksum_failure::<BootResponse>(&test_data);
        test_bad_command_header_failure::<BootResponse>(&test_data);
    }

    #[test]
    fn test_boot_confirm_response() {
        let test_data: [u8; 6]= [0x02, 0x40, 0x80, 0x01, 0x10, 0xd1];
        let boot_confirm_response= BootConfirmResponse{};
        test_data_with_known_good_message(&boot_confirm_response, &test_data);
        test_bad_data_checksum_failure::<BootConfirmResponse>(&test_data);
        test_bad_command_header_failure::<BootConfirmResponse>(&test_data);
    }

    #[test]
    fn test_broadcast_response() {
        let test_data: [u8; 16] = [0x02, 0xa0, 0x13, 0x0b, 0x01, 0x02, 0x01, 0x02,
                                   0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0xb2];
        let broadcast_response = BroadcastResponse {
            network_id: 0x0102,
            device_id: 0x0102030405060708,
            data: 0x01,
        };

        test_data_with_known_good_message(&broadcast_response, &test_data);
        test_bad_data_checksum_failure::<BroadcastResponse>(&test_data);
        test_bad_command_header_failure::<BroadcastResponse>(&test_data);
    }

    #[test]
    fn test_lock_response() {
        let test_data: [u8; 6] = [0x02, 0xa0, 0xf9, 0x01, 0x00, 0x58];
        let lock_response = LockResponse{};
        test_data_with_known_good_message(&lock_response, &test_data);
        test_bad_data_checksum_failure::<LockResponse>(&test_data);
        test_bad_command_header_failure::<LockResponse>(&test_data);
    }

    #[test]
    fn test_update_time_ack_response() {
        let test_data: [u8; 6] = [0x02, 0x40, 0x22, 0x01, 0x00, 0x63];
        let update_time_ack_response = UpdateTimeAckResponse{};
        test_data_with_known_good_message(&update_time_ack_response, &test_data);
        test_bad_data_checksum_failure::<UpdateTimeAckResponse>(&test_data);
        test_bad_command_header_failure::<UpdateTimeAckResponse>(&test_data);
    }

    #[test]
    fn test_update_time_response() {
        let test_data: [u8; 8] = [0x02, 0x40, 0xa2, 0x03, 0x01, 0x02, 0x00, 0xe2];
        let update_time_response = UpdateTimeResponse {
            network_id: 0x0102,
        };
        test_data_with_known_good_message(&update_time_response, &test_data);
        test_bad_data_checksum_failure::<UpdateTimeResponse>(&test_data);
        test_bad_command_header_failure::<UpdateTimeResponse>(&test_data);
    }

    #[test]
    fn test_handshake_response() {
        let test_data: [u8; 6] = [0x02, 0x40, 0x03, 0x01, 0x00, 0x42];
        let handshake_response = HandshakeResponse{};
        test_data_with_known_good_message(&handshake_response, &test_data);
        test_bad_data_checksum_failure::<HandshakeResponse>(&test_data);
        test_bad_command_header_failure::<HandshakeResponse>(&test_data);
    }

    #[test]
    fn test_ack_response() {
        let test_data: [u8; 6] = [0x02, 0x40, 0x24, 0x01, 0x00, 0x65];
        let ack_response = AckResponse{};
        test_data_with_known_good_message(&ack_response, &test_data);
        test_bad_data_checksum_failure::<AckResponse>(&test_data);
        test_bad_command_header_failure::<AckResponse>(&test_data);
    }

    #[test]
    fn test_samples_response() {
        let test_data: [u8; 23] = [0x02, 0x40, 0xa4, 0x12, 0x01, 0x02,
                                   0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
                                   0x03, 0x04, 0x02, 0x02, 0x00, 0x00,
                                   0x01, 0x00, 0x02, 0x00, 0xf2];
        let samples_response = SamplesResponse {
            network_id: 0x0102,
            channel_id: 0x0102,
            data: 0x0102,
            time: 0x04030201,
            sample_count: 0x02,
            stored_sample_count: [0x02, 0x00, 0x00],
            samples: vec![0x0001, 0x0002],
        };
        assert!(samples_response.sample_count as usize == samples_response.samples.len());
        test_data_with_known_good_message(&samples_response, &test_data);
        test_bad_data_checksum_failure::<SamplesResponse>(&test_data);
        test_bad_command_header_failure::<SamplesResponse>(&test_data);
    }

    #[test]
    fn test_schedule_response() {
        let test_data: [u8; 6] = [0x02, 0x40, 0x23, 0x01, 0x00, 0x62];
        let schedule_response = ScheduleResponse{};
        test_data_with_known_good_message(&schedule_response, &test_data);
        test_bad_data_checksum_failure::<ScheduleResponse>(&test_data);
        test_bad_command_header_failure::<ScheduleResponse>(&test_data);
    }

    #[test]
    fn test_boot_request() {
        let test_data: [u8; 5] = [0x02, 0x40, 0x04, 0x00, 0x44];
        let boot_request = BootRequest{};
        test_data_with_known_good_message(&boot_request, &test_data);
        test_bad_data_checksum_failure::<BootRequest>(&test_data);
        test_bad_command_header_failure::<BootRequest>(&test_data);
    }

    #[test]
    fn test_boot_confirm_request() {
        let test_data: [u8; 5] = [0x02, 0x40, 0x00, 0x00, 0x40];
        let boot_confirm_request = BootConfirmRequest{};
        test_data_with_known_good_message(&boot_confirm_request, &test_data);
        test_bad_data_checksum_failure::<BootConfirmRequest>(&test_data);
        test_bad_command_header_failure::<BootConfirmRequest>(&test_data);
    }

    #[test]
    fn test_unlock_request() {
        let test_data: [u8; 9] = [0x02, 0xa2, 0x36, 0x04, 0xfc, 0xff, 0x90, 0x01, 0x02];
        let unlock_request = UnlockRequest{};
        test_data_with_known_good_message(&unlock_request, &test_data);
        test_bad_data_checksum_failure::<UnlockRequest>(&test_data);
        test_bad_command_header_failure::<UnlockRequest>(&test_data);
    }

    #[test]
    fn test_lock_request() {
        let test_data: [u8; 9] = [0x02, 0xa2, 0x36, 0x04, 0xfc, 0xff, 0x00, 0x01, 0x92];
        let lock_request = LockRequest{};
        test_data_with_known_good_message(&lock_request, &test_data);
        test_bad_data_checksum_failure::<LockRequest>(&test_data);
        test_bad_command_header_failure::<LockRequest>(&test_data);
    }

    #[test]
    fn test_update_time_request() {
        let test_data: [u8; 11] = [0x02, 0x40, 0x22, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x65];
        let update_time_request = UpdateTimeRequest {
            network_id: 0x0001,
            time: 0x00000000,
        };
        test_data_with_known_good_message(&update_time_request, &test_data);
        test_bad_data_checksum_failure::<UpdateTimeRequest>(&test_data);
        test_bad_command_header_failure::<UpdateTimeRequest>(&test_data);
    }

    #[test]
    fn test_handshake_request() {
        let test_data: [u8; 9] = [0x02, 0x40, 0x03, 0x04, 0x00, 0x01, 0x05, 0x00, 0x43];
        let handshake_request = HandshakeRequest {
            network_id: 0x0001,
        };
        test_data_with_known_good_message(&handshake_request, &test_data);
        test_bad_data_checksum_failure::<HandshakeRequest>(&test_data);
        test_bad_command_header_failure::<HandshakeRequest>(&test_data);
    }

    #[test]
    fn test_samples_request() {
        let test_data: [u8; 11] = [0x02, 0x40, 0x24, 0x06, 0x00, 0x02, 0x00, 0x01, 0x0a, 0x00, 0x6b];
        let samples_request = SamplesRequest {
            network_id: 0x0002,
            channel_id: 0x0001,
        };
        test_data_with_known_good_message(&samples_request, &test_data);
        test_bad_data_checksum_failure::<SamplesRequest>(&test_data);
        test_bad_command_header_failure::<SamplesRequest>(&test_data);
    }

    #[test]
    fn test_schedule_request() {
        let test_data: [u8; 64] = [0x02, 0x40, 0x23, 0x3b, 0x00, 0x02, 0x01, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b];
        let schedule: [u8; 56] = [0; 56];
        let schedule_request = ScheduleRequest {
            network_id: 0x0002,
            channel_id: 0x01,
            schedule,
        };
        test_data_with_known_good_message(&schedule_request, &test_data);
        test_bad_data_checksum_failure::<ScheduleRequest>(&test_data);
        test_bad_command_header_failure::<ScheduleRequest>(&test_data);
    }
}
