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

// Constansts
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

fn encrypt_mode(usb_id: &String) -> Result<(), anyhow::Error>{
   
    let paths = fs::read_dir(".\\Files")?;
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
        let encrypted_file = cipher
            .encrypt(&NONCE.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Encrypting file: {}", err))?;
        let out_file = p.replace(".pdf", ".bin");
        fs::write(out_file, encrypted_file)?; // save encrypted file
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
    let db_file = File::create("db.json").expect("Failed to create db.json");
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
    let db_data = fs::read("db.json").expect("db.json not found, make sure to run encrypt mode");

    let db_file = cipher
        .decrypt(&NONCE.into(), db_data.as_ref())
        .map_err(|err| anyhow!("Decrypting db: {}", err))?;
    
    let decoded_db_file = match str::from_utf8(&db_file) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    let db_data: DB = serde_json::from_str(decoded_db_file).unwrap();

    // Confirm usb_id
    let current_usb_id = get_usb_id();
    if db_data.usb_id != current_usb_id{
        println!("pdf-secure can only run on the same usb device. {} != {}", db_data.usb_id, current_usb_id);
        process::exit(0);
    }

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
