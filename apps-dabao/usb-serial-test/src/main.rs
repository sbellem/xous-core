fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("usb-serial-test: PID is {}", xous::process::id());

    let tt = ticktimer::Ticktimer::new().unwrap();
    tt.sleep_ms(2000).ok();

    log::info!("usb-serial-test: hooking USB serial mirror...");
    let usb = usb_bao1x::UsbHid::new();
    usb.serial_console_input_injection();
    log::info!("usb-serial-test: USB serial mirror hooked!");

    println!("Hello from USB serial!");

    let mut i = 0u32;
    loop {
        tt.sleep_ms(1000).ok();
        println!("tick {}", i);
        i += 1;
    }
}
