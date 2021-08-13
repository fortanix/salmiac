use pcap::{
    Active,
    Error,
    Capture,
    Device
};

const SNAP_LEN : i32 = 5000;

pub fn open_packet_capture(port : u32, device_name : &str) -> Result<Capture<Active>, String> {
    let main_device = Device::list()
        .and_then(|devices|{ find_device(devices, device_name) })
        .map_err(|err| format!("Failed to create device {:?}", err));

    let capture = main_device.and_then(|device| {
        println!("Capturing with device: {}", device.name);
        Capture::from_device(device).map_err(|err| format!("Cannot create capture {:?}", err))
    });

    capture.and_then(|capture| {
        let result = capture.promisc(true)
            .immediate_mode(true)
            .snaplen(SNAP_LEN)
            .open();

        result.map(|c| add_port_filter(c, port))
            .map_err(|err| format!("Cannot open capture {:?}", err))
    })
}

fn find_device(devices: Vec<Device>, device_name : &str) -> Result<Device, Error> {
    devices.into_iter()
        .find(|e| e.name == device_name)
        .ok_or(Error::PcapError(format!("Can't find {:?} device", device_name)))
}

fn add_port_filter(mut capture : Capture<Active>, port : u32) -> Capture<Active> {
    capture.filter(&*format!("port {}", port)).expect("Cannot set pcap port filter.");
    capture
}