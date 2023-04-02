// TODO Error handling
// TODO Handle windows and linux paths

use std::{
    str,
    process,
    path::Path,
    fs, 
    collections::HashMap,
};

use anyhow::anyhow;
use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305,
};
use serde_json;
use pdfium_render::prelude::*;

// Custom imports
mod utils;
use utils::{
    DB, 
    MetaData, 
    BIN_PATH, 
    FILES_PATH, 
    USB_ID_FILE,
    INDEX_CHAR, 
    IMAGES_PREFIX, 
    get_usb_id,
    KEY,
    NONCE
};

fn export_pdf_to_jpegs(path: &str, password: Option<&str>) -> Result<(HashMap<usize, (u32, u32)>, i32), PdfiumError> {
    // Renders each page in the PDF file at the given path to a separate JPEG file.

    // Bind to a Pdfium library in the same directory as our Rust executable;
    // failing that, fall back to using a Pdfium library provided by the operating system.
    println!("Creating pdf obj");
    let pdfium = Pdfium::new(
        Pdfium::bind_to_library(Pdfium::pdfium_platform_library_name_at_path(BIN_PATH))
        .or_else(|_| Pdfium::bind_to_system_library())?,
        );

    // Load the document from the given path...
    println!("Loading pdf document from {}", path);
    let document = pdfium.load_pdf_from_file(path, password).expect("Can't open pdf file");

    // ... set rendering options that will be applied to all pages...
    println!("Rendering pdf");
    let render_config = PdfRenderConfig::new()
        .set_target_width(2000)
        .set_maximum_height(2000)
        .rotate_if_landscape(PdfBitmapRotation::Degrees90, true);
    
    let cipher = XChaCha20Poly1305::new(&KEY.into());

    // ... then render each page to a bitmap image, saving each image to a JPEG file.
    let mut render_config_data = HashMap::new();
    let mut pages_num: i32 = 0;
    for (index, page) in document.pages().iter().enumerate() {
        let temp = page
            .render_with_config(&render_config)
            .unwrap()
            .as_image()
            .as_rgba8()
            .unwrap()
            .clone();

        let (x, y) = temp.dimensions();
        render_config_data.insert(index, (x,y));
        println!("{}:{}", x, y);
        println!("Encrypting {}", index);
        let encrypted_data = cipher
            .encrypt(&NONCE.into(), temp.into_raw().as_ref())
            .unwrap();
        let prefix_image = IMAGES_PREFIX.replace(INDEX_CHAR, index.to_string().as_str());
        let _check = fs::write(format!("{}{}", path, prefix_image), encrypted_data);
        pages_num+=1;
    }

    Ok((render_config_data, pages_num))
}

fn encrypt_mode(usb_id: &String) -> Result<(), anyhow::Error>{
   
    let paths = fs::read_dir(FILES_PATH)?;
    let cipher = XChaCha20Poly1305::new(&KEY.into());
    
    // Main encrypt loop
    let mut db = DB::new(usb_id); 

    for path in paths{
        
        // Encrypt pdf files
        let p = path.unwrap().path().into_os_string().into_string().unwrap();
        let filename = p.clone(); 
        // skip if file isn't pdf
        if ! p.ends_with(".pdf"){continue;};
       
        println!("Converting {} to jpegs", filename); 
        let (renders_config, pages_num) = export_pdf_to_jpegs(&filename, None).unwrap();
        fs::remove_file(p)?; // remove pdf
    
        // Ask user for number of times for file
        println!("\n\nWhat's the maximum number of time is {} allowed to be opened ?\n", filename);
        let mut max_number_open = String::new();
        std::io::stdin().read_line(&mut max_number_open).expect("Failed to read line");
        let max_number_open: i8 = max_number_open.trim().parse().expect("Please enter a positive number");        
        
        // Save to db 
        let db_data = MetaData{
            file_open_count: 1,
            max_files_open_count: max_number_open,
            renders_config: renders_config,
            glob_pattern: format!("{}{}", filename, IMAGES_PREFIX),
            number_of_images: pages_num,
        };
        db.join(&filename, db_data);         
    

    // Save db.json
    let db = serde_json::to_string(&db).unwrap();
    let encrypted_db = cipher
        .encrypt(&NONCE.into(), db.as_ref())
        .map_err(|err| anyhow!("Ecrypting db: {}", err))?;
    fs::write("db.json", encrypted_db)?;  

    }

    Ok(())
}

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
    encrypt_mode(&usb_id).unwrap();
}
