// TODO Error handling
// TODO Handle windows and linux paths
// TODO security on all saved files

use std::{
    str,
    process,
    path::Path,
    fs::{self, File, read_to_string}, 
    collections::HashMap,
};

use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead},
    XChaCha20Poly1305,
};
use serde::{Serialize, Deserialize};
use serde_json;
use cocoon::*;
use pdfium_render::prelude::*;

// Constansts
const BIN_PATH: &str = ".\\bin\\";
const FILES_PATH: &str = ".\\Files";
const USB_ID_FILE: &str = "./System Volume Information/IndexerVolumeGuid";
const KEY: [u8; 32] = [201, 246, 255, 188, 110, 230, 
                    94, 198, 192, 77, 164, 20, 5, 122, 
                    116, 209, 113, 208, 241, 175, 251, 
                    52, 138, 202, 197, 204, 234, 230, 
                    120, 164, 160, 52];
const NONCE: [u8; 24] =  [213, 85, 53, 54, 40, 196, 
                        219, 239, 120, 62, 63, 205, 
                        43, 146, 64, 252, 128, 242, 
                        103, 225, 59, 7, 43, 130];


#[derive(Serialize, Deserialize, Debug)]
struct MetaData {
    file_open_count: i8, // number of times file is opened
    max_files_open_count: i8, // maximum number of times a file is allowed to be opened
}

#[derive(Serialize, Deserialize, Debug)]
struct DB {
    usb_id: String, 
    data: HashMap<String, MetaData>
}

impl DB {
    fn new(usb_id: &String) -> DB {
        DB {
            usb_id: usb_id.to_string(),
            data: HashMap::new(),
        }
    }

    // Used to add new data
    fn join(
        &mut self,
        key: &str,
        value: MetaData,
        ){
            self.data.insert(key.to_string(), value);
    }
}


fn get_usb_id() -> String{ 
   let content = match read_to_string(USB_ID_FILE){
    Result::Ok(value) => value,
    Result::Err(error) => panic!("Couldn't open {} due to {}", USB_ID_FILE, error)
   };

   return content;
}

fn export_pdf_to_jpegs(path: &str, password: Option<&str>) -> Result<(), PdfiumError> {
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

    // ... then render each page to a bitmap image, saving each image to a JPEG file.
    let cipher = XChaCha20Poly1305::new(&KEY.into());
    for (index, page) in document.pages().iter().enumerate() {
        let temp = page.render_with_config(&render_config)
                    .unwrap()
                    .as_image()
                    .as_rgba8()
                    .unwrap()
                    .clone();

        
        
        println!("Encrypting {}", index);
        let encrypted_data = cipher
            .encrypt(&NONCE.into(), temp.into_raw().as_ref())
            .unwrap(); 
        fs::write(format!("{}_{}.bin", path, index), encrypted_data);

    }

    Ok(())
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
       
        let file_data = fs::read(&p)?;
        println!("Converting {} to jpegs", filename); 
        let pdf_done = export_pdf_to_jpegs(&filename, None).unwrap();
        fs::remove_file(p)?; // remove pdf
    
        // Ask user for number of times for file
        println!("What's the maximum number of time is {} allowed to be opened", filename);
        let mut max_number_open = String::new();
        std::io::stdin().read_line(&mut max_number_open).expect("Failed to read line");
        let max_number_open: i8 = max_number_open.trim().parse().expect("Please enter a positive number");        
        
        // Save to db 
        let db_data = MetaData{
            file_open_count: 1,
            max_files_open_count: max_number_open,
        };
        db.join(&filename, db_data);         
    

    // Save db.json
    let mut db_file = File::create("db.json").expect("Failed to create db.json");
    let db = serde_json::to_string(&db).unwrap();
    let encrypted_db = cipher
        .encrypt(&NONCE.into(), db.as_ref())
        .map_err(|err| anyhow!("Ecrypting db: {}", err))?;
    fs::write("db.json", encrypted_db)?;  

    }

    Ok(())
}


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
    let db_data: DB = serde_json::from_str(db_data_decoded).unwrap();

    // Confirm usb_id
    let current_usb_id = get_usb_id();
    if db_data.usb_id != current_usb_id{
        println!("pdf-secure can only run on the same usb device. {} != {}", db_data.usb_id, current_usb_id);
        process::exit(0);
    }

    // Ask user which file to view


    // View file
    let temp_filename = "test.bin"; // TODO replace by file picker
   
    let full_path = format!("{}\\{}", FILES_PATH, temp_filename);
    let pdf_data_encrypted= fs::read(full_path).expect("Couldn't read pdf file");
    let pdf_data_decrypted: Vec<u8> = cipher
        .decrypt(&NONCE.into(), pdf_data_encrypted.as_ref())
        .map_err(|err| anyhow!("Decrypting pdf: {}", err))?;
    
    
    fs::write("test.pdf", pdf_data_decrypted)?;

    Ok(())
}
fn main() {
    println!("Welcome to pdf-secure, a tool to secure your pdf files");
    
    // Check if program runs on a USB stick
    if Path::new(USB_ID_FILE).exists() {
        println!("USB device detected");        
    } else {
        println!("pdf-secure runs only on a USB device, Exiting");
        process::exit(0);
    }

    let usb_id: String = get_usb_id();


    println!("Which mode do you want to select?");
    println!("1. Encrypt");
    println!("2. Decrypt");
    
    // Select mode
    let mut mode = String::new();
    std::io::stdin().read_line(&mut mode).expect("Failed to read line");

    let mode: u8 = mode.trim().parse().expect("Please type a number!");
    
    if mode == 1 {
        println!("Encrypt mode selected");
        let result = encrypt_mode(&usb_id).unwrap();
    } else if mode == 2 {
        println!("Decrypt mode selected");
        let result = decrypt_mode(&usb_id).unwrap();
    } else {
        println!("Invalid mode selected");
    }
}
