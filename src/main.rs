// TODO Error handling
// TODO Handle windows and linux paths

use std::{
    str,
    process,
    path::Path,
    fs::{self, File}, 
    collections::{HashMap, HashSet},
};


use anyhow::anyhow;
use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305,
};
use serde_json;
use show_image::{create_window, event};

// Custom imports
mod utils;
use utils::{
    DB, 
    MetaData, 
    USB_ID_FILE,
    INDEX_CHAR, 
    IMAGES_PREFIX, 
    KEY,
    NONCE,
    get_usb_id
};

fn decrypt_mode(usb_id: &String) -> Result<(), anyhow::Error>{

    let paths = fs::read_dir(".\\Files")?;
    let cipher = XChaCha20Poly1305::new(&KEY.into());

    // Read db.json
    let db_data_encrypted = fs::read("db.json").expect("db.json not found, make sure to run encrypt mode");
    let db_data_decrypted = cipher
        .decrypt(&NONCE.into(), db_data_encrypted.as_ref())
        .map_err(|err| anyhow!("Decrypting db: {}", err))?;
    let db_data_decoded = match str::from_utf8(&db_data_decrypted) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    let mut db_data: DB = serde_json::from_str(db_data_decoded).unwrap();

    // Confirm usb_id
    let current_usb_id = get_usb_id();
    if db_data.usb_id != current_usb_id{
        println!("pdf-secure can only run on the same usb device. {} != {}", db_data.usb_id, current_usb_id);
        process::exit(0);
    }

    // read files in db.json
    loop{

        // Show files to user
        let mut selected_file = String::new();
        let mut available_inputs: HashSet<String> = db_data.data
            .iter()
            .enumerate()
            .map(|(i, _)| (i+1).to_string())
            .collect();

        println!("\n\nWhich file do you want to view? Type q to exit\n");
        let mut filenames: HashMap<String, String> = HashMap::new();
        for (index, (key, _)) in db_data.data.iter().enumerate(){
            let index_display = index + 1;
            let filename_display =  key.split('\\').last().unwrap();
            println!("{}-  {}", index_display,filename_display);
            let index_str = index_display.to_string();
            filenames.insert(index_str, key.clone());
        }

        std::io::stdin().read_line(&mut selected_file).unwrap();
        let selected_file = selected_file.trim();
        // Check if the input is "q"
        if selected_file == "q" {
            break;
        }

        // Check if the input is in available_inputs
        if available_inputs.contains(selected_file) {
            let filename = filenames.get(selected_file).unwrap();
            let filename_display =  filename.split('\\').last().unwrap();
            let mut file_metadata: &MetaData = db_data.data.get(filename).unwrap();

            // Check if file is allowed to be opened
            if file_metadata.file_open_count > file_metadata.max_files_open_count{
                println!("{} can't be opened anymore", filename_display);
                continue;
            }
            
            // view file
            let mut index: usize = 0;
            let current_image = read_image(filename, index, file_metadata).unwrap();
            let max_pages = file_metadata.number_of_images;

            // view image
            let window = create_window("Secure PDF Viewer", Default::default())
                .expect("Failed to create window");
            window.set_image(format!("Page {}/{}", index+1, max_pages), current_image)
                .expect("Failed to set image");
    
            for event in window.event_channel()? {
                if let event::WindowEvent::KeyboardInput(event) = event {
                    if event.input.key_code == Some(event::VirtualKeyCode::Escape) 
                        && event.input.state.is_pressed() {
                        break;
                    }
                    if event.input.key_code == Some(event::VirtualKeyCode::Right) 
                        && event.input.state.is_pressed() 
                        && index+1 < max_pages as usize{
                            index+=1;
                            let current_image = read_image(filename, index, file_metadata)
                                .unwrap();
                            window.set_image(format!("Page {}/{}", index+1, max_pages),current_image)
                                .expect("Failed to set image");
                    }
                    if event.input.key_code == Some(event::VirtualKeyCode::Left) 
                        && event.input.state.is_pressed() && index > 0{
                            index-=1;
                            let current_image = read_image(filename, index, file_metadata).unwrap();
                            window.set_image(format!("Page {}/{}", index+1, max_pages), current_image)
                                .expect("Failed to set image");
                    }
                }
            }
            // Update, save db.json
            db_data.update_file_open_count(filename, file_metadata.file_open_count+1);
            let mut db_file = File::create("db.json").expect("Failed to create db.json");
            let db = serde_json::to_string(&db_data).unwrap();
            let encrypted_db = cipher
                .encrypt(&NONCE.into(), db.as_ref())
                .map_err(|err| anyhow!("Ecrypting db: {}", err))?;
            fs::write("db.json", encrypted_db)?;  
        } else {
            println!("Please pick a valid file from the options, try again !");
            continue;
        }
    }

    Ok(())
}


fn read_image(filename: &str, index: usize, file_metadata: &MetaData) -> Result<image::DynamicImage, anyhow::Error>{
    

    let cipher = XChaCha20Poly1305::new(&KEY.into());
    let prefix_image = IMAGES_PREFIX.replace(INDEX_CHAR, index.to_string().as_str());
    let data_encrypted= fs::read(format!("{}{}", filename, prefix_image)).expect("Couldn't read pdf file");
    let rgba_data: Vec<u8> = cipher
        .decrypt(&NONCE.into(), data_encrypted.as_ref())
        .map_err(|err| anyhow!("Decrypting pdf: {}", err))?;
   

    let (x,y) = file_metadata.renders_config.get(&index).unwrap();
    let image_buffer: image::RgbImage = image::RgbImage::new(*x, *y);
    let mut pixel_data  = image_buffer.into_raw();

    for i in 0..rgba_data.len() / 4 {
        let r = rgba_data[i * 4];
        let g = rgba_data[i * 4 + 1];
        let b = rgba_data[i * 4 + 2];
        pixel_data[i * 3] = r;
        pixel_data[i * 3 + 1] = g;
        pixel_data[i * 3 + 2] = b;
    }


    let image_buffer =  image::RgbImage::from_raw(*x, *y, pixel_data).unwrap();
    let dynamic_image = image::DynamicImage::ImageRgb8(image_buffer);
    
    Ok(dynamic_image)
}

#[show_image::main]
fn main() {
    // Initial setup
    println!("Welcome to pdf-secure, a tool to secure your pdf files");
    
    // Check if program runs on a USB stick
    if Path::new(USB_ID_FILE).exists() {
        println!("USB device detected");   
    } else {
        println!("pdf-secure runs only on a USB device, Exiting");
        process::exit(0);
    }
    let usb_id: String = get_usb_id();
    let result = decrypt_mode(&usb_id).unwrap();
}
