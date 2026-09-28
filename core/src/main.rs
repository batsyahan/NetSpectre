fn main() {
    let devices = pcap::Device::list().expect("could not list devices");
    for d in devices {
        println!("interface: {}", d.name);
    }
}